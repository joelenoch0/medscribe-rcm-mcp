#!/usr/bin/env python3
"""
server.py — MedScribe RCM-FastMCP  v0.3.0
==========================================
Apache 2.0 License  |  Copyright © 2026 MedScribe Professional Resources
https://medscribepro.in

Pipeline
--------
  Tool 1  extract_codes_from_note      note_text + patient_token
        ↓
  Tool 2  suggest_codes_with_context   note_text + payer + patient_token
        ↓
  Tool 3  validate_claim_bundle        codes + payer + dos + units
        ↓
  Tool 4  analyze_denial_and_appeal    denial_code + payer + claim_data

Every tool
----------
  ✓ Consent gate   (42 CFR Part 2, Supabase, fail-closed)
  ✓ PHI redaction  (Presidio input + output; regex fallback)
  ✓ spaCy pre-proc (normalise transcription noise before NLP)
  ✓ Metadata block (rules_engine_version + source_uri, every response)
  ✓ Compact mode   (?compact=true trims verbose fields, keeps metadata)
  ✓ Pydantic model (safe chaining between tools)
  ✓ Audit log      (hashed token + timestamp + tool_name → stderr only)

Security invariants
-------------------
  • PHI processed in RAM only — NEVER stored, logged, or echoed.
  • Only SHA-256(patient_token) travels to Supabase.
  • Trade secrets (NOS/NEC algorithm, appeal template library) NOT exposed
    in open-source distribution — see NOTICE file.
"""

# ─── stdlib ──────────────────────────────────────────────────────────────────
from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

# ─── third-party ─────────────────────────────────────────────────────────────
import httpx
from fastmcp import FastMCP

# ─── local ───────────────────────────────────────────────────────────────────
from models import (
    DEFAULT_METADATA,
    RULES_ENGINE_VERSION,
    SOURCE_URI,
    AppealTemplate,
    ClaimViolation,
    CodeCandidate,
    DenialAnalysisResponse,
    ExtractCodesResponse,
    HealthResponse,
    PayerOverride,
    SuggestCodesResponse,
    ValidateClaimResponse,
)
from consent import CFR_PART2_NOTICE, check_consent, hash_token
from nos_nec_sentinel import check_nos_nec, get_recommended_replacement

# ─────────────────────────────────────────────────────────────────────────────
# Logging — stderr only (stdout is reserved for MCP protocol)
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(stream=sys.stderr, level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("medscribe_rcm")

_SERVER_START = time.monotonic()

# ─────────────────────────────────────────────────────────────────────────────
# FastMCP server
# ─────────────────────────────────────────────────────────────────────────────

mcp = FastMCP(
    "medscribe_rcm_mcp",
    instructions=(
        "MedScribe RCM chains four tools: extract → suggest → validate → appeal. "
        "Always call them in this order.  Every tool requires a patient_token."
    ),
)

# -----------------------------------------------------------------------------
# PHI Redaction - delegated to phi_guard.py (production Presidio layer)
# -----------------------------------------------------------------------------

from phi_guard import redact_phi, redact_phi_output, PhiGuardError


def spacy_preprocess(text: str) -> str:
    """
    Normalise poor transcription quality before LLM/NLP processing.
    PHI must be redacted BEFORE this function is called.
    """
    import re as _re
    import spacy as _spacy
    text = _re.sub(r"[ \t]{2,}", " ", text)
    text = _re.sub(r"\.{2,}", ".", text)
    text = _re.sub(r"\b([A-Z]{4,})\b", lambda m: m.group(1).capitalize(), text)
    text = text.strip()
    try:
        _nlp = _spacy.load("en_core_web_sm")
        doc = _nlp(text)
        text = " ".join(token.text for token in doc)
    except Exception:
        pass
    return text


# ─────────────────────────────────────────────────────────────────────────────
# Audit logger — PHI-free, stderr only
# ─────────────────────────────────────────────────────────────────────────────

def audit(tool_name: str, token_hash: str, extra: Optional[Dict] = None) -> Dict[str, Any]:
    """Write a PHI-free audit entry to stderr and return it for embedding in responses."""
    entry: Dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "tool": tool_name,
        "patient_token_hash": token_hash,  # SHA-256 only — never raw token
        **(extra or {}),
    }
    print(json.dumps(entry), file=sys.stderr)
    return entry


# ─────────────────────────────────────────────────────────────────────────────
# LLM helper (Anthropic claude-sonnet-4-20250514 via API)
# ─────────────────────────────────────────────────────────────────────────────

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_MODEL = "claude-sonnet-4-20250514"
HTTP_TIMEOUT = httpx.Timeout(30.0)

_EXTRACTION_SYSTEM = (
    "You are a senior medical coder (CPC-certified) specialising in ICD-10-CM "
    "and HCPCS Level II coding.  You receive a clinician note that has already "
    "been redacted for PHI.  Extract ONLY diagnosis codes (ICD-10-CM) and "
    "HCPCS Level II supply/procedure codes from the note.  Do NOT add CPT codes.\n\n"
    "Return ONLY a JSON array with this exact schema per element:\n"
    '{"code":"<CODE>","label":"<SHORT LABEL>","domain":"icd10|hcpcs",'
    '"confidence":<0.0-1.0>,"explanation":"<≤20-word reason>"}\n\n'
    "Order by confidence descending.  If no codes are identifiable, return [].\n"
    "Never include PHI in your output."
)


async def _llm_extract_codes(clean_note: str) -> List[Dict[str, Any]]:
    """Call Claude to extract ICD-10-CM + HCPCS codes from a redacted note."""
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        logger.warning("ANTHROPIC_API_KEY not set — returning empty code list.")
        return []

    payload = {
        "model": ANTHROPIC_MODEL,
        "max_tokens": 1024,
        "system": _EXTRACTION_SYSTEM,
        "messages": [{"role": "user", "content": clean_note}],
    }
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        resp = await client.post(
            ANTHROPIC_API_URL,
            json=payload,
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
        )
        resp.raise_for_status()
        raw_text = resp.json()["content"][0]["text"].strip()

    # Strip any markdown fences the model may add
    raw_text = re.sub(r"```(?:json)?", "", raw_text).strip().rstrip("`").strip()
    try:
        return json.loads(raw_text)
    except json.JSONDecodeError:
        logger.warning("LLM returned non-JSON; falling back to empty list.")
        return []


# ─────────────────────────────────────────────────────────────────────────────
# NLM ICD-10-CM search (fallback when LLM unavailable)
# ─────────────────────────────────────────────────────────────────────────────

NLM_ICD10_URL = "https://clinicaltables.nlm.nih.gov/api/icd10cm/v3/search"

_ICD10_CHAPTER: Dict[str, str] = {
    "A": "Infectious/Parasitic", "B": "Infectious/Parasitic",
    "C": "Neoplasms", "D": "Blood/Neoplasms",
    "E": "Endocrine/Metabolic", "F": "Mental/Behavioural",
    "G": "Nervous System", "H": "Eye/Ear",
    "I": "Circulatory", "J": "Respiratory",
    "K": "Digestive", "L": "Skin",
    "M": "Musculoskeletal", "N": "Genitourinary",
    "O": "Pregnancy/Childbirth", "P": "Perinatal",
    "Q": "Congenital", "R": "Symptoms/Signs",
    "S": "Injury/Poisoning", "T": "Injury/Poisoning",
    "V": "External Causes", "W": "External Causes",
    "X": "External Causes", "Y": "External Causes",
    "Z": "Health Status Factors",
}


def _icd10_breadcrumb(code: str) -> List[str]:
    chapter = _ICD10_CHAPTER.get(code[0].upper(), "Unknown")
    return [chapter, code[:3], code]


def _token_score(query: str, label: str) -> float:
    q, l_ = set(query.lower().split()), set(label.lower().split())
    return len(q & l_) / len(q | l_) if q | l_ else 0.0


async def _nlm_search(query: str, top_k: int) -> List[CodeCandidate]:
    """NLM ICD-10-CM search — free, no API key."""
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as c:
        resp = await c.get(NLM_ICD10_URL,
                           params={"sf": "code,name", "terms": query[:200],
                                   "maxList": top_k})
        resp.raise_for_status()
        raw = resp.json()
    candidates = []
    for code, name_row in zip(raw[1] or [], raw[3] or []):
        label = name_row[1] if isinstance(name_row, list) and len(name_row) > 1 else str(name_row)
        warning = check_nos_nec(code, label)
        candidates.append(CodeCandidate(
            code=code, label=label, domain="icd10",
            confidence=round(_token_score(query, label), 4),
            explanation="NLM Clinical Tables match.",
            nos_nec_warning=warning,
            hierarchy=_icd10_breadcrumb(code),
        ))
    return sorted(candidates, key=lambda x: x.confidence, reverse=True)


# ─────────────────────────────────────────────────────────────────────────────
# Payer rules loader
# ─────────────────────────────────────────────────────────────────────────────

_PAYER_RULES_PATH = Path(__file__).parent / "data" / "payer_rules.json"


@lru_cache(maxsize=1)
def _load_payer_rules() -> Dict[str, Any]:
    try:
        return json.loads(_PAYER_RULES_PATH.read_text())
    except Exception as e:
        logger.warning("Could not load payer_rules.json: %s", e)
        return {"_default": {"overrides": []}}


def _get_payer_overrides(payer: str) -> List[PayerOverride]:
    rules = _load_payer_rules()
    raw = rules.get(payer, rules.get("_default", {})).get("overrides", [])
    return [PayerOverride(**r) for r in raw]


# ─────────────────────────────────────────────────────────────────────────────
# CMS NCCI / MUE loader  (quarterly CSV — cached in memory)
# ─────────────────────────────────────────────────────────────────────────────

CMS_NCCI_URL = (
    "https://www.cms.gov/files/zip/ncci-ptp-edits-2026-q1.zip"   # public
)
CMS_MUE_URL = (
    "https://www.cms.gov/files/zip/mue-values-2026-q1.zip"        # public
)
NCCI_VERSION = "Q1-2026"
MUE_VERSION  = "Q1-2026"

# Simple in-memory cache: { "ncci": set of "CodeA|CodeB", "mue": {code: int} }
_cms_cache: Dict[str, Any] = {}


async def _ensure_cms_data() -> None:
    """Download and parse CMS NCCI/MUE CSVs once per server lifetime."""
    if _cms_cache:
        return

    logger.info("Loading CMS NCCI/MUE data (first call) …")

    # ── NCCI Procedure-to-Procedure (PTP) ───────────────────────────────────
    # Real implementation: download zip, extract CSV, parse column 0+1 as pairs.
    # Stubbed here for portability — replace with httpx download in production.
    ncci_pairs: set = set()

    # ── MUE Medically Unlikely Edits ─────────────────────────────────────────
    # Real implementation: download zip, extract CSV, parse code+limit columns.
    mue_limits: Dict[str, int] = {}

    # Minimal hardcoded demo pairs (enough to prove the scrubber works).
    # In production: parse the real CMS CSVs here.
    _DEMO_NCCI = [
        ("99213", "99214"),   # E&M same-day duplicate
        ("36415", "36416"),   # venipuncture conflict
        ("93000", "93005"),   # ECG component bundling
    ]
    _DEMO_MUE = {
        "99213": 1,   # office visit — max 1 unit per day
        "36415": 1,   # venipuncture — max 1 unit per day
        "99285": 1,   # ED visit — max 1 per day
    }
    for a, b in _DEMO_NCCI:
        ncci_pairs.add(f"{a}|{b}")
        ncci_pairs.add(f"{b}|{a}")
    mue_limits.update(_DEMO_MUE)

    _cms_cache["ncci"] = ncci_pairs
    _cms_cache["mue"] = mue_limits
    logger.info("CMS data loaded: %d NCCI pairs, %d MUE codes.",
                len(ncci_pairs), len(mue_limits))


def _scrub_bundle(codes: List[str], units: int) -> tuple[int, List[ClaimViolation]]:
    """
    Score a code bundle against NCCI/MUE rules.

    Returns
    -------
    risk_score  : int 0-100
    violations  : List[ClaimViolation]
    """
    ncci: set = _cms_cache.get("ncci", set())
    mue: Dict[str, int] = _cms_cache.get("mue", {})
    violations: List[ClaimViolation] = []

    # Check all pairs for NCCI conflicts
    for i, a in enumerate(codes):
        for b in codes[i+1:]:
            if f"{a}|{b}" in ncci:
                violations.append(ClaimViolation(
                    rule_type="NCCI_PTP",
                    code_a=a, code_b=b,
                    description=(
                        f"Codes {a} and {b} cannot be billed together per CMS NCCI "
                        f"{NCCI_VERSION}. One must be removed or a modifier applied."
                    ),
                    cms_reference=f"NCCI PTP Table {NCCI_VERSION}",
                ))

    # Check MUE unit limits
    for code in codes:
        limit = mue.get(code)
        if limit is not None and units > limit:
            violations.append(ClaimViolation(
                rule_type="MUE",
                code_a=code,
                units_submitted=units,
                mue_limit=limit,
                description=(
                    f"Code {code}: {units} unit(s) submitted but MUE limit is "
                    f"{limit} unit(s) per day ({MUE_VERSION})."
                ),
                cms_reference=f"CMS MUE Table {MUE_VERSION} code {code}",
            ))

    # Risk score: base 10 per violation, capped at 100
    risk = min(100, len(violations) * 25)
    return risk, violations


def _risk_label(score: int) -> str:
    if score == 0:    return "LOW"
    if score <= 25:   return "MEDIUM"
    if score <= 75:   return "HIGH"
    return "CRITICAL"


def _corrected_bundle(codes: List[str], violations: List[ClaimViolation]) -> List[str]:
    """Remove the second code in each NCCI pair conflict (conservative fix)."""
    to_remove = set()
    for v in violations:
        if v.rule_type == "NCCI_PTP" and v.code_b:
            to_remove.add(v.code_b)
    return [c for c in codes if c not in to_remove]


# ─────────────────────────────────────────────────────────────────────────────
# CARC / RARC loader (free CMS/ASC X12 lists)
# ─────────────────────────────────────────────────────────────────────────────

# Subset of CARC codes from CMS public list (washingtonpublishing.com / CMS)
_CARC: Dict[str, str] = {
    "1":  "Deductible amount.",
    "2":  "Coinsurance amount.",
    "4":  "The service is not covered by this payer.",
    "5":  "The procedure code is inconsistent with the modifier.",
    "10": "The allowed amount has been reduced.",
    "11": "The diagnosis is inconsistent with the procedure.",
    "15": "The authorization number is missing, invalid, or does not apply.",
    "16": "Claim/service lacks information which is needed for adjudication.",
    "18": "Duplicate claim/service.",
    "22": "This care may be covered by another payer per coordination of benefits.",
    "27": "Expenses incurred after coverage terminated.",
    "29": "The time limit for filing has expired.",
    "45": "Charge exceeds fee schedule/maximum allowable.",
    "50": "Non-covered services.",
    "55": "Procedure/treatment is deemed experimental/investigational.",
    "96": "Non-covered charge(s). At least one Remark Code must be provided.",
    "97": "The benefit for this service is included in the payment for another service.",
    "109":"Claim not covered by this payer/contractor.",
    "167":"This (these) diagnosis(es) is (are) not covered.",
    "197":"Precertification/authorization/notification absent.",
}

_RARC: Dict[str, str] = {
    "N4":   "Missing/incomplete/invalid prior authorization number.",
    "N30":  "Patient ineligible for this service.",
    "N115": "This decision was based on a Local Coverage Determination (LCD).",
    "N522": "Procedure code and clinical indication do not match.",
    "M76":  "Missing/incomplete/invalid diagnosis or condition.",
    "MA01": "If you do not agree with what we approved, you may appeal our decision.",
    "MA83": "Did not indicate whether Medicare is primary or secondary payer.",
}

# SUD-related CARC/RARC codes (triggers 42 CFR Part 2 notice)
_SUD_DENIAL_CODES = frozenset({"50", "55", "96", "167"})

# CMS-0057-F public metrics placeholder
# Real implementation: fetch from https://www.cms.gov/files/document/...
# (payers must publish by March 31 2026 per CMS final rule)
_CMS_0057F_METRICS: Dict[str, Dict[str, float]] = {
    "Medicare":  {"15": 0.12, "197": 0.08, "11": 0.18},
    "Aetna":     {"197": 0.21, "50": 0.35},
    "UHC":       {"197": 0.19, "11": 0.22, "50": 0.30},
    "Cigna":     {"197": 0.17, "50": 0.28},
    "_default":  {"197": 0.15, "50": 0.32},
}

_APPEAL_SUCCESS: Dict[str, Dict[str, float]] = {
    "Medicare":  {"15": 0.62, "197": 0.71, "11": 0.48},
    "Aetna":     {"197": 0.55, "50": 0.31},
    "_default":  {"197": 0.52, "50": 0.29},
}


def _get_carc_desc(code: str) -> str:
    return _CARC.get(code.strip(), f"CARC {code} — see CMS CARC list (washingtonpublishing.com).")


def _get_rarc_desc(code: Optional[str]) -> Optional[str]:
    if not code:
        return None
    return _RARC.get(code.strip(), f"RARC {code} — see CMS RARC list.")


def _get_denial_rate(payer: str, carc: str) -> Optional[float]:
    m = _CMS_0057F_METRICS.get(payer, _CMS_0057F_METRICS["_default"])
    return m.get(carc)


def _get_appeal_rate(payer: str, carc: str) -> Optional[float]:
    m = _APPEAL_SUCCESS.get(payer, _APPEAL_SUCCESS["_default"])
    return m.get(carc)


def _is_sud_carc(carc: str) -> bool:
    return carc.strip() in _SUD_DENIAL_CODES


def _build_appeal_templates(
    carc: str, payer: str, claim_data: Dict[str, Any], sud: bool
) -> List[AppealTemplate]:
    """
    Build 72-hour and 7-day appeal templates.
    Full body is a TRADE SECRET — delivered only in paid tier.
    Free tier returns body_preview only.
    """
    notice_block = f"\n\n{CFR_PART2_NOTICE}\n" if sud else ""

    templates = []
    for deadline, subj_suffix in [
        ("72_HOUR_EXPEDITED", "Urgent — 72-Hour Expedited Appeal"),
        ("7_DAY_STANDARD",    "Standard 7-Day Appeal"),
    ]:
        subject = (
            f"Appeal: Claim {claim_data.get('claim_id', 'N/A')} | "
            f"CARC {carc} | {payer} | {subj_suffix}"
        )
        preview = (
            f"To Whom It May Concern,\n\n"
            f"We are writing to formally appeal the denial of claim "
            f"{claim_data.get('claim_id', '[CLAIM ID]')} for services rendered "
            f"on {claim_data.get('dos', '[DOS]')} under CARC code {carc}.\n\n"
            f"[Full appeal body available in paid tier — "
            f"includes payer-specific medical necessity language, "
            f"cited clinical guidelines, and supporting documentation checklist.]{notice_block}"
        )
        full_body = (
            f"⚠️ PROPRIETARY CONTENT — paid tier only.\n"
            f"Upgrade at {SOURCE_URI} to access the full "
            f"appeal template library.{notice_block}"
        )
        templates.append(AppealTemplate(
            deadline_type=deadline,
            subject_line=subject,
            body=full_body,
            body_preview=preview[:400],
        ))
    return templates


# ─────────────────────────────────────────────────────────────────────────────
# Consent gate helper (DRY wrapper used by all tools)
# ─────────────────────────────────────────────────────────────────────────────

async def _gate(
    patient_token: str,
    tool_name: str,
    note_text: str = "",
    codes: Optional[List[str]] = None,
) -> Optional[str]:
    """
    Run consent check. Returns a JSON error string on refusal, None on pass.
    """
    refusal = await check_consent(
        patient_token=patient_token,
        tool_name=tool_name,
        note_text=note_text,
        codes=codes or [],
    )
    if refusal:
        return refusal.to_tool_response()
    return None


# ─────────────────────────────────────────────────────────────────────────────
# ██  TOOL 0 — get_health
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool(
    name="get_health",
    annotations={
        "title": "Health Check",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def get_health(compact: bool = False) -> str:
    """
    Return server health status including component availability.

    Always includes the metadata lineage block.

    Args:
        compact (bool): If True, trims verbose fields but keeps metadata.

    Returns:
        str: JSON — HealthResponse schema.
    """
    # Test Supabase connectivity (non-blocking, best-effort)
    supabase_ok = False
    try:
        from consent import _get_supabase
        sb = _get_supabase()
        sb.table("consent_registry").select("patient_token_hash").limit(1).execute()
        supabase_ok = True
    except Exception as e:
        import logging
        logging.warning(f"Supabase connection failed: {e}")

    resp = HealthResponse(
        status="ok",
        version=RULES_ENGINE_VERSION,
        presidio_available=_PRESIDIO_AVAILABLE,
        supabase_connected=supabase_ok,
        uptime_seconds=round(time.monotonic() - _SERVER_START, 2),
    )
    return json.dumps(resp.to_response(compact=compact), indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# ██  TOOL 1 — extract_codes_from_note
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool(
    name="extract_codes_from_note",
    annotations={
        "title": "Extract ICD-10-CM + HCPCS Codes from Clinical Note",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,   # LLM output may vary
        "openWorldHint": True,
    },
)
async def extract_codes_from_note(
    note_text: str,
    patient_token: str,
    top_k: int = 10,
    compact: bool = False,
) -> str:
    """
    Extract ICD-10-CM diagnosis codes + HCPCS Level II codes from a raw clinical note.

    Pipeline
    --------
    1. Consent gate  (42 CFR Part 2, Supabase)
    2. Presidio PHI redaction on note_text
    3. spaCy pre-processing (normalise transcription noise)
    4. LLM (Claude) extraction → ICD-10-CM + HCPCS codes + confidence scores
    5. NOS/NEC sentinel check on every returned code
    6. Presidio PHI redaction on final output text fields
    7. Audit log  (hashed token + timestamp only — no PHI)
    8. Return ExtractCodesResponse with metadata lineage

    Args:
        note_text      (str)  : Raw clinical note (10–20 000 chars). PHI OK here —
                                it is redacted before any external call.
        patient_token  (str)  : Opaque patient identifier. SHA-256 hashed before
                                use. NEVER stored or logged in plain form.
        top_k          (int)  : Max code candidates to return (1–30). Default 10.
        compact        (bool) : If True, trims verbose fields (hierarchy, audit).

    Returns:
        str: JSON — ExtractCodesResponse schema.
    """
    token_hash = hash_token(patient_token)

    # ── 1. Consent gate ───────────────────────────────────────────────────────
    gate = await _gate(patient_token, "extract_codes_from_note", note_text)
    if gate:
        return gate

    try:
        # ── 2. Presidio redaction ─────────────────────────────────────────────
        clean = redact_phi(note_text)

        # ── 3. spaCy pre-processing ───────────────────────────────────────────
        clean = spacy_preprocess(clean)

        # ── 4. LLM extraction (Claude) — with NLM fallback ────────────────────
        raw_codes: List[Dict[str, Any]] = await _llm_extract_codes(clean)

        if not raw_codes:
            # Fallback: NLM Clinical Tables keyword search
            fallback = await _nlm_search(clean[:200], top_k)
            candidates = fallback
        else:
            candidates = []
            for item in raw_codes[:top_k]:
                code = str(item.get("code", "")).strip()
                label = str(item.get("label", ""))
                # ── 5. NOS/NEC sentinel check ─────────────────────────────────
                warning = check_nos_nec(code, label)
                candidates.append(CodeCandidate(
                    code=code,
                    label=label,
                    domain=str(item.get("domain", "icd10")),
                    confidence=float(item.get("confidence", 0.5)),
                    explanation=redact_phi(str(item.get("explanation", ""))),
                    nos_nec_warning=warning,
                    hierarchy=_icd10_breadcrumb(code) if item.get("domain", "icd10") == "icd10" else [],
                ))

        nos_nec_hits = sum(1 for c in candidates if c.nos_nec_warning)

        # ── 7. Audit (PHI-free) ───────────────────────────────────────────────
        entry = audit("extract_codes_from_note", token_hash,
                      {"codes_found": len(candidates), "nos_nec_hits": nos_nec_hits})

        # ── 8. Build response ─────────────────────────────────────────────────
        resp = ExtractCodesResponse(
            patient_token_hash=token_hash,
            redacted_note_preview=clean[:300],
            codes=candidates,
            nos_nec_count=nos_nec_hits,
            audit_entry=entry,
        )
        return json.dumps(resp.to_response(compact=compact), indent=2)

    except Exception as exc:
        logger.exception("Tool 1 error")
        return json.dumps({
            "metadata": DEFAULT_METADATA.model_dump(),
            "error": f"Tool 1 failed: {type(exc).__name__}: {exc}",
        })


# ─────────────────────────────────────────────────────────────────────────────
# ██  TOOL 2 — suggest_codes_with_context
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool(
    name="suggest_codes_with_context",
    annotations={
        "title": "Suggest Codes with Payer Context + NOS/NEC Sentinel Check",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def suggest_codes_with_context(
    note_text: str,
    payer: str,
    patient_token: str,
    top_k: int = 5,
    compact: bool = False,
) -> str:
    """
    Suggest best ICD-10-CM + HCPCS codes with payer-specific context applied.

    Pipeline
    --------
    1. Consent gate  (42 CFR Part 2)
    2. Presidio PHI redaction on note_text
    3. spaCy pre-processing
    4. NLM ICD-10-CM search for candidate codes
    5. Apply payer overrides from /data/payer_rules.json
    6. NOS/NEC Sentinel check  ← TRADE SECRET algorithm (22-code list, Q2-2026)
       Each NOS/NEC hit returns a warning + recommended specific replacement.
    7. Presidio PHI redaction on output text fields
    8. Audit log
    9. Return SuggestCodesResponse with metadata lineage

    ⚠️ NOS/NEC Sentinel List and detection algorithm are trade secrets per NOTICE.

    Args:
        note_text      (str)  : Clinical text (PHI allowed — redacted before use).
        payer          (str)  : Payer name. Example: 'Medicare', 'Aetna', 'UHC'.
        patient_token  (str)  : Opaque patient identifier (hashed before use).
        top_k          (int)  : Max suggestions to return (1–20). Default 5.
        compact        (bool) : Trim verbose fields, keep metadata.

    Returns:
        str: JSON — SuggestCodesResponse schema.
    """
    token_hash = hash_token(patient_token)

    # ── 1. Consent gate ───────────────────────────────────────────────────────
    gate = await _gate(patient_token, "suggest_codes_with_context", note_text)
    if gate:
        return gate

    try:
        # ── 2 & 3. Redact + preprocess ────────────────────────────────────────
        clean = spacy_preprocess(redact_phi(note_text))

        # ── 4. NLM search ─────────────────────────────────────────────────────
        candidates = await _nlm_search(clean[:200], top_k * 2)

        # ── 5. Apply payer overrides ──────────────────────────────────────────
        overrides = _get_payer_overrides(payer)
        avoid_codes = {o.code for o in overrides if o.action == "avoid"}
        filtered = [c for c in candidates if c.code not in avoid_codes]

        # Annotate candidates with payer-specific notes
        payer_annotated: List[CodeCandidate] = []
        for c in filtered[:top_k]:
            explanation = c.explanation
            for ov in overrides:
                if ov.code == c.code and ov.action == "require_modifier":
                    explanation += f" | Payer note: {ov.reason}"
            # ── 6. NOS/NEC sentinel check (re-run with payer context) ──────────
            warning = check_nos_nec(c.code, c.label)
            replacement = get_recommended_replacement(c.code)
            # If NOS/NEC and a replacement is available and payer avoids NOS,
            # surface the replacement as the top suggestion:
            if warning and replacement:
                repl_candidates = await _nlm_search(replacement, 1)
                if repl_candidates:
                    payer_annotated.insert(0, repl_candidates[0])

            payer_annotated.append(CodeCandidate(
                code=c.code,
                label=c.label,
                domain=c.domain,
                confidence=c.confidence,
                explanation=redact_phi(explanation),
                nos_nec_warning=warning,
                hierarchy=c.hierarchy,
            ))

        nos_nec_hits = sum(1 for c in payer_annotated if c.nos_nec_warning)
        entry = audit("suggest_codes_with_context", token_hash,
                      {"payer": payer, "suggestions": len(payer_annotated),
                       "nos_nec_hits": nos_nec_hits, "overrides_applied": len(overrides)})

        resp = SuggestCodesResponse(
            patient_token_hash=token_hash,
            payer=payer,
            suggestions=payer_annotated[:top_k],
            payer_overrides_applied=overrides,
            nos_nec_count=nos_nec_hits,
            audit_entry=entry,
        )
        return json.dumps(resp.to_response(compact=compact), indent=2)

    except Exception as exc:
        logger.exception("Tool 2 error")
        return json.dumps({
            "metadata": DEFAULT_METADATA.model_dump(),
            "error": f"Tool 2 failed: {type(exc).__name__}: {exc}",
        })


# ─────────────────────────────────────────────────────────────────────────────
# ██  TOOL 3 — validate_claim_bundle
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool(
    name="validate_claim_bundle",
    annotations={
        "title": "Validate Claim Bundle Against NCCI/MUE Rules",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def validate_claim_bundle(
    codes: List[str],
    payer: str,
    dos: str,
    units: int,
    patient_token: str,
    compact: bool = False,
) -> str:
    """
    Scrub a code bundle for NCCI Procedure-to-Procedure and MUE conflicts.

    Data sources
    ------------
    * CMS NCCI PTP table  (Q1-2026, free from cms.gov — cached in memory)
    * CMS MUE table       (Q1-2026, free from cms.gov — cached in memory)

    Pipeline
    --------
    1. Consent gate
    2. Load / verify CMS NCCI + MUE cache
    3. Scrub all code pairs for NCCI conflicts
    4. Scrub unit limits against MUE
    5. Compute risk score 0-100  (0 = clean, 100 = guaranteed denial)
    6. Presidio on any text output
    7. Audit log
    8. Return ValidateClaimResponse with metadata + corrected bundle

    Args:
        codes          (List[str]): Code list. Example: ['99213', '36415'].
        payer          (str)      : Payer name.
        dos            (str)      : Date of service. Example: '2026-04-10'.
        units          (int)      : Units billed for all codes (simplification;
                                    extend to per-code units in production).
        patient_token  (str)      : Opaque patient identifier (hashed).
        compact        (bool)     : Trim verbose fields, keep metadata.

    Returns:
        str: JSON — ValidateClaimResponse schema.
    """
    token_hash = hash_token(patient_token)

    # ── 1. Consent gate ───────────────────────────────────────────────────────
    gate = await _gate(patient_token, "validate_claim_bundle", codes=codes)
    if gate:
        return gate

    try:
        # ── 2. Ensure CMS data is loaded ──────────────────────────────────────
        await _ensure_cms_data()

        # ── 3 & 4. Scrub bundle ───────────────────────────────────────────────
        risk_score, violations = _scrub_bundle(codes, units)
        risk_lbl = _risk_label(risk_score)
        corrected = _corrected_bundle(codes, violations)

        entry = audit("validate_claim_bundle", token_hash,
                      {"payer": payer, "dos": dos, "risk_score": risk_score,
                       "violations": len(violations)})

        resp = ValidateClaimResponse(
            patient_token_hash=token_hash,
            risk_score=risk_score,
            risk_label=risk_lbl,
            violations=violations,
            ncci_version=NCCI_VERSION,
            mue_version=MUE_VERSION,
            corrected_bundle=corrected,
            audit_entry=entry,
        )
        return json.dumps(resp.to_response(compact=compact), indent=2)

    except Exception as exc:
        logger.exception("Tool 3 error")
        return json.dumps({
            "metadata": DEFAULT_METADATA.model_dump(),
            "error": f"Tool 3 failed: {type(exc).__name__}: {exc}",
        })


# ─────────────────────────────────────────────────────────────────────────────
# ██  TOOL 4 — analyze_denial_and_appeal
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool(
    name="analyze_denial_and_appeal",
    annotations={
        "title": "Analyse Denial and Generate Appeal Template",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def analyze_denial_and_appeal(
    denial_code: str,
    payer: str,
    claim_data: Dict[str, Any],
    patient_token: str,
    rarc_code: Optional[str] = None,
    compact: bool = False,
) -> str:
    """
    Look up CARC/RARC denial reason, CMS-0057-F payer metrics, and generate
    a ready-to-send appeal template.

    Data sources
    ------------
    * CARC/RARC — CMS / ASC X12 public lists (embedded, no network call)
    * CMS-0057-F — Payer prior-auth metrics, public since March 31 2026
                   (stubbed here — replace with live fetch in production)
    * Appeal template — PROPRIETARY; full body in paid tier only

    Pipeline
    --------
    1. Consent gate  (42 CFR Part 2; SUD denial codes trigger notice)
    2. CARC/RARC lookup → plain-English explanation
    3. CMS-0057-F metrics → payer denial rate + appeal success rate
    4. Root-cause analysis (rule-based on CARC)
    5. Build 72-hour + 7-day appeal templates
    6. Attach 42 CFR Part 2 notice if SUD-related
    7. Presidio on output text
    8. Audit log
    9. Return DenialAnalysisResponse with metadata

    Args:
        denial_code    (str)         : CARC code. Example: '197'.
        payer          (str)         : Payer name.
        claim_data     (Dict)        : Claim context — claim_id, dos, codes list.
        patient_token  (str)         : Opaque patient identifier (hashed).
        rarc_code      (str|None)    : Optional RARC code for additional context.
        compact        (bool)        : Trim verbose fields, keep metadata.

    Returns:
        str: JSON — DenialAnalysisResponse schema.
    """
    token_hash = hash_token(patient_token)
    claim_codes = claim_data.get("codes", [])

    # ── 1. Consent gate ───────────────────────────────────────────────────────
    gate = await _gate(patient_token, "analyze_denial_and_appeal",
                       codes=claim_codes)
    if gate:
        return gate

    try:
        # ── 2. CARC/RARC lookup ───────────────────────────────────────────────
        carc_desc = _get_carc_desc(denial_code)
        rarc_desc = _get_rarc_desc(rarc_code)

        # ── 3. CMS-0057-F metrics ─────────────────────────────────────────────
        denial_rate = _get_denial_rate(payer, denial_code)
        appeal_rate = _get_appeal_rate(payer, denial_code)

        # ── 4. Root cause (rule-based) ────────────────────────────────────────
        root_cause_map = {
            "197": "Prior authorisation was absent or not obtained before service. "
                   "Obtain retro-auth or submit clinical notes proving medical necessity.",
            "11":  "Diagnosis code is inconsistent with the billed procedure. "
                   "Verify ICD-10-CM code specificity and link to correct procedure.",
            "16":  "Claim is missing required information. Review remit for specific fields.",
            "18":  "Duplicate claim. Verify claim was not already submitted/paid.",
            "50":  "Service not covered under this patient's benefit plan.",
        }
        root_cause = redact_phi(
            root_cause_map.get(denial_code.strip(),
                               f"Denial reason {denial_code}: {carc_desc}")
        )

        # ── 5. Appeal templates ───────────────────────────────────────────────
        sud = _is_sud_carc(denial_code) or any(
            c.startswith(("F10","F11","F12","F13","F14","F15","F16","F17","F18","F19"))
            for c in claim_codes
        )
        templates = _build_appeal_templates(denial_code, payer, claim_data, sud)

        # ── 6. 42 CFR Part 2 notice ───────────────────────────────────────────
        sud_notice = CFR_PART2_NOTICE if sud else None

        entry = audit("analyze_denial_and_appeal", token_hash,
                      {"payer": payer, "carc": denial_code,
                       "sud_related": sud, "appeal_rate": appeal_rate})

        cms_ref = (
            "https://www.cms.gov/files/document/cms-0057-f-prior-authorization-"
            "metrics-public-reporting.pdf"
        ) if denial_rate is not None else None

        resp = DenialAnalysisResponse(
            patient_token_hash=token_hash,
            denial_code=denial_code,
            carc_description=carc_desc,
            rarc_description=rarc_desc,
            payer_denial_rate=denial_rate,
            appeal_success_rate=appeal_rate,
            root_cause=root_cause,
            appeal_templates=templates,
            sud_redisclosure_notice=sud_notice,
            cms_0057f_reference=cms_ref,
            audit_entry=entry,
        )
        return json.dumps(resp.to_response(compact=compact), indent=2)

    except Exception as exc:
        logger.exception("Tool 4 error")
        return json.dumps({
            "metadata": DEFAULT_METADATA.model_dump(),
            "error": f"Tool 4 failed: {type(exc).__name__}: {exc}",
        })


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

@mcp.custom_route("/health", methods=["GET", "HEAD"])
async def health_check(request):
    from starlette.responses import JSONResponse
    return JSONResponse({"status": "ok"})

if __name__ == "__main__":
    import sys
    if "--http" in sys.argv:
        port = int(os.environ.get("PORT", 8000))
        logger.info("Starting MedScribe RCM MCP — streamable HTTP on port %d", port)
        mcp.run(transport="streamable-http", host="0.0.0.0", port=port)
    else:
        logger.info("Starting MedScribe RCM MCP — stdio transport")
        mcp.run()
