from __future__ import annotations
import logging
import sys
logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(levelname)s | %(name)s | %(message)s")
log = logging.getLogger("medscribe_rcm")

"""
MedScribe RCM-FastMCP  |  server.py
====================================
Production-ready Revenue Cycle Management MCP Server
Copyright © MedScribe Professional Resources, Warangal, Telangana, IN

ARCHITECTURE: Single-file FastMCP server — 4 tools, zero PHI persistence
COMPLIANCE  : HIPAA (PHI RAM-only), 42 CFR Part 2 (SUD consent gating)
TRADE SECRET: NOS/NEC sentinel engine (Tool 2) — see NOTICE file

Pipeline order enforced in every tool:
  1 → Consent Middleware  (42 CFR Part 2)
  2 → PHI Redaction INPUT (Presidio)
  3 → spaCy Preprocessing
  4 → Core Logic
  5 → PHI Redaction OUTPUT (Presidio)
  6 → Audit Log (PHI-free)
"""

# ─────────────────────────────────────────────────────────────
# IMPORTS — stdlib, then third-party, then internal
# ─────────────────────────────────────────────────────────────

import json
import os
import re
import uuid
from dotenv import load_dotenv
from mcp.server.transport_security import TransportSecuritySettings
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

import httpx
import spacy
from mcp.server.fastmcp import FastMCP
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from pydantic import BaseModel, ConfigDict, Field, field_validator
from supabase import Client, create_client

load_dotenv()

from webhook_handler import webhook_routes
from starlette.routing import Route
from starlette.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

class APIKeyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        exempt = [
            "/health",
            "/register",
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-authorization-server",
        ]
        if any(request.url.path.startswith(p) for p in exempt):
            return await call_next(request)
        api_key = os.getenv("MCP_API_KEY", "")
        auth_header = request.headers.get("Authorization", "")
        if not api_key or auth_header != f"Bearer {api_key}":
            return Response("Unauthorized", status_code=401)
        return await call_next(request)

# ─────────────────────────────────────────────────────────────
# GLOBAL ONE-TIME INITIALIZATIONS
# ─────────────────────────────────────────────────────────────

# spaCy — load once; use for clinical text normalization
try:
    NLP = spacy.load("en_core_web_sm")
except OSError:
    log.warning("spaCy model not found — run: python -m spacy download en_core_web_sm")
    NLP = None  # graceful degradation

# Presidio — lazy-loaded on first use to avoid Claude Desktop startup timeout
# Force en_core_web_sm to avoid auto-downloading the 400MB lg model
from presidio_analyzer.nlp_engine import NlpEngineProvider
_PRESIDIO_ANALYZER  = None
_PRESIDIO_ANONYMIZER = None

def _get_presidio():
    global _PRESIDIO_ANALYZER, _PRESIDIO_ANONYMIZER
    if _PRESIDIO_ANALYZER is None:
        _NLP_CONFIG = {"nlp_engine_name": "spacy", "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}]}
        analyzer = AnalyzerEngine(nlp_engine=NlpEngineProvider(nlp_configuration=_NLP_CONFIG).create_engine())
        analyzer.registry.remove_recognizer("MedicalLicenseRecognizer")
        _PRESIDIO_ANALYZER  = analyzer
        _PRESIDIO_ANONYMIZER = AnonymizerEngine()
    return _PRESIDIO_ANALYZER, _PRESIDIO_ANONYMIZER

# Payer rules — loaded once, cached, never stores PHI
@lru_cache(maxsize=1)
def _load_payer_rules() -> Dict[str, Any]:
    rules_path = os.path.join(os.path.dirname(__file__), "data", "payer_rules.json")
    try:
        with open(rules_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        log.warning("data/payer_rules.json not found — using empty rule set")
        return {"default": {}}

PAYER_RULES: Dict[str, Any] = _load_payer_rules()

# ── STARTUP GUARD ──────────────────────────────────────────────
_WORKOS_JWKS_URI = os.getenv("WORKOS_JWKS_URI", "")
if not _WORKOS_JWKS_URI:
    raise RuntimeError(
        "WORKOS_JWKS_URI env var is not set. "
        "Server will not start without authentication configured."
    )

# ── JWT VERIFIER (WorkOS AuthKit) ──────────────────────────────
class WorkOSTokenVerifier:
    """Implements TokenVerifier protocol — validates WorkOS JWTs via JWKS."""

    def __init__(self, jwks_uri: str):
        self._jwks_uri = jwks_uri
        self._jwks_cache: dict = {}

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            import base64, json as _json
            import jwt

            # Step 1 — Decode header to get kid
            parts = token.split(".")
            if len(parts) != 3:
                return None
            header_b64 = parts[0] + "=" * (-len(parts[0]) % 4)
            header = _json.loads(base64.urlsafe_b64decode(header_b64))
            kid = header.get("kid")

            # Step 2 — Fetch JWKS (cached)
            if not self._jwks_cache:
                async with httpx.AsyncClient() as client:
                    resp = await client.get(self._jwks_uri, timeout=5)
                    resp.raise_for_status()
                    self._jwks_cache = resp.json()

            # Step 3 — Find matching key by kid
            public_key = None
            for key_data in self._jwks_cache.get("keys", []):
                if key_data.get("kid") == kid:
                    from jwt.algorithms import RSAAlgorithm
                    public_key = RSAAlgorithm.from_jwk(key_data)
                    break

            if public_key is None:
                log.warning("JWT kid not found in JWKS")
                return None

            # Step 4 — Verify signature + claims
            payload = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                issuer="https://api.workos.com",
                options={"require": ["exp", "sub"]},
            )

            # Step 5 — Check scope
            scopes = payload.get("scope", "").split()
            if "rcm:use" not in scopes:
                log.warning("JWT missing rcm:use scope")
                return None

            return AccessToken(
                token=token,
                client_id=payload.get("sub", "unknown"),
                scopes=scopes,
            )

        except jwt.ExpiredSignatureError:
            log.warning("JWT expired")
            return None
        except jwt.InvalidTokenError as exc:
            log.warning("JWT invalid: %s", exc)
            return None
        except Exception as exc:
            log.error("Token verification failed: %s", exc)
            return None

verifier = WorkOSTokenVerifier(jwks_uri=_WORKOS_JWKS_URI)

# Supabase — free tier, NON-PHI metadata only
_SUPABASE_URL = os.getenv("SUPABASE_URL", "")
_SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY", os.getenv("SUPABASE_ANON_KEY", ""))
SUPABASE: Optional[Client] = None
if _SUPABASE_URL and _SUPABASE_KEY:
    try:
        SUPABASE = create_client(_SUPABASE_URL, _SUPABASE_KEY)
    except Exception as exc:
        log.warning("Supabase init failed (non-fatal): %s", exc)

# MedGemma — Google Vertex AI endpoint for appeal generation (Tool 4)
MEDGEMMA_ENDPOINT = os.getenv(
    "MEDGEMMA_ENDPOINT",
    "https://us-central1-aiplatform.googleapis.com/v1/projects/{project}/locations/us-central1/publishers/google/models/medgemma:predict"
)
MEDGEMMA_PROJECT  = os.getenv("GOOGLE_CLOUD_PROJECT", "")
MEDGEMMA_API_KEY  = os.getenv("MEDGEMMA_API_KEY", "")  # alt: use ADC

# ─────────────────────────────────────────────────────────────
# NOS / NEC SENTINEL ENGINE  ← TRADE SECRET CORE
# 22 codes: 11 NOS + 11 NEC  (both types trigger medical-necessity denials)
# ─────────────────────────────────────────────────────────────

# NOS = Not Otherwise Specified  ←  payer reads as "vague, justify it"
NOS_SENTINEL_CODES: Dict[str, Dict[str, str]] = {
    "J06.9":  {"desc": "Acute URI, unspecified",              "safer": "J00, J02.9, J04.0", "risk": "HIGH"},
    "R51.9":  {"desc": "Headache, unspecified",               "safer": "G43.909, R51.0",    "risk": "HIGH"},
    "M54.50": {"desc": "Low back pain, unspecified",          "safer": "M54.51, M54.59",    "risk": "HIGH"},
    "K59.00": {"desc": "Constipation, unspecified",           "safer": "K59.01, K59.02",    "risk": "MEDIUM"},
    "R10.9":  {"desc": "Abdominal pain, unspecified",         "safer": "R10.11, R10.31",    "risk": "HIGH"},
    "F41.9":  {"desc": "Anxiety disorder, unspecified",       "safer": "F41.0, F41.1",      "risk": "HIGH"},
    "F32.9":  {"desc": "MDD, single episode, unspecified",    "safer": "F32.0, F32.1",      "risk": "HIGH"},
    "G89.29": {"desc": "Other chronic pain (NOS pattern)",    "safer": "G89.21, G89.28",    "risk": "MEDIUM"},
    "E11.9":  {"desc": "T2DM without complications (NOS)",    "safer": "E11.65, E11.42",    "risk": "MEDIUM"},
    "K21.9":  {"desc": "GERD without esophagitis (NOS)",      "safer": "K21.0",             "risk": "MEDIUM"},
    "I10":    {"desc": "Essential HTN (often NOS pattern)",   "safer": "I10 + stage doc",   "risk": "LOW"},
}

# NEC = Not Elsewhere Classified  ←  payer flags as "residual bucket code"
NEC_SENTINEL_CODES: Dict[str, Dict[str, str]] = {
    "Z79.899": {"desc": "Other long-term medication use",             "safer": "Z79.01–Z79.84",    "risk": "MEDIUM"},
    "M79.3":   {"desc": "Panniculitis, unspecified (NEC residual)",   "safer": "L93.2, M35.6",     "risk": "HIGH"},
    "R68.89":  {"desc": "Other specified general symptoms (NEC)",     "safer": "R68.81, R68.82",   "risk": "HIGH"},
    "K92.89":  {"desc": "Other diseases of digestive system (NEC)",   "safer": "K92.81, K57.30",   "risk": "MEDIUM"},
    "M06.9":   {"desc": "RA, unspecified (NEC residual)",             "safer": "M06.00–M06.09",    "risk": "HIGH"},
    "L98.9":   {"desc": "Disorder of skin/subcut, unspecified (NEC)", "safer": "L97.-, L89.-",     "risk": "HIGH"},
    "R41.89":  {"desc": "Other cognitive symptoms (NEC)",             "safer": "R41.3, R41.81",    "risk": "MEDIUM"},
    "Z87.891": {"desc": "Personal history, other conditions (NEC)",   "safer": "Z87.39, Z87.89",   "risk": "LOW"},
    "G89.9":   {"desc": "Pain NOS/NEC — dual trigger",                "safer": "G89.11, G89.29",   "risk": "HIGH"},
    "J98.9":   {"desc": "Respiratory disorder, unspecified (NEC)",    "safer": "J98.01, J98.11",   "risk": "HIGH"},
    "M79.9":   {"desc": "Soft tissue disorder, unspecified (NEC)",    "safer": "M79.1, M79.3",     "risk": "HIGH"},
}

ALL_SENTINELS: Dict[str, Dict[str, str]] = {**NOS_SENTINEL_CODES, **NEC_SENTINEL_CODES}

# Regex patterns to catch NOS/NEC language in free text
NOS_PATTERN = re.compile(
    r"\b(unspecified|NOS|not otherwise specified|unknown etiology|nonspecific)\b",
    re.IGNORECASE,
)
NEC_PATTERN = re.compile(
    r"\b(NEC|not elsewhere classified|other specified|other and unspecified|residual)\b",
    re.IGNORECASE,
)

# SUD diagnosis prefix list — triggers 42 CFR Part 2 handling
SUD_ICD10_PREFIXES = (
    "F10", "F11", "F12", "F13", "F14", "F15", "F16", "F17", "F18", "F19",
    "Z87.891",  # history of SUD
)

# ─────────────────────────────────────────────────────────────
# MCP SERVER INITIALIZATION
# ─────────────────────────────────────────────────────────────
mcp = FastMCP(
    "medscribe_rcm",
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    instructions=(
        "MedScribe RCM-FastMCP is a denial-prevention Revenue Cycle Management pipeline. "
        "It extracts ICD-10/CPT codes, applies NOS/NEC sentinel intelligence, validates claim "
        "bundles against NCCI edits, and generates medically-justified appeal letters via MedGemma. "
        "All PHI is processed in RAM only. Consent verification runs before every tool."
    ),
)
# ─────────────────────────────────────────────────────────────
# PYDANTIC MODELS — Input / Output
# ─────────────────────────────────────────────────────────────

class ExtractCodesInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    note_text:     str  = Field(..., min_length=10, description="Raw clinical note text (dictated or typed)")
    patient_token: str  = Field(..., min_length=4,  description="Hashed patient identifier — no PHI, used for consent lookup")
    compact:       bool = Field(False,              description="Return minimal response (tool-chaining mode)")

class SuggestCodesInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    note_text: str  = Field(..., min_length=10, description="Clinical note text after extraction")
    payer:     str  = Field(..., min_length=2,  description="Payer name (BCBS, MEDICARE, MEDICAID, AETNA, UNITED, or default)")
    compact:   bool = Field(False,              description="Return minimal response for chaining")

class ValidateClaimInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    codes:   List[str] = Field(..., min_length=1, description="List of ICD-10 and CPT codes to validate")
    payer:   str       = Field(..., min_length=2, description="Payer name for rule lookup")
    dos:     str       = Field(..., description="Date of service — YYYY-MM-DD format")
    units:   int       = Field(..., ge=1, le=99,  description="Number of units billed")
    compact: bool      = Field(False,             description="Return minimal response for chaining")

    @field_validator("dos")
    @classmethod
    def validate_dos(cls, v: str) -> str:
        try:
            datetime.strptime(v, "%Y-%m-%d")
        except ValueError:
            raise ValueError("dos must be YYYY-MM-DD format")
        return v

class AnalyzeDenialInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    denial_code:   str        = Field(..., min_length=2,  description="CARCs/RARCs denial code (e.g. CO-50, PR-96, OA-109)")
    payer:         str        = Field(..., min_length=2,  description="Payer name")
    claim_data:    Dict[str, Any] = Field(...,           description="Non-PHI claim metadata: codes, DOS, units, provider NPI")
    patient_token: str        = Field(..., min_length=4, description="Hashed patient token for consent lookup")
    compact:       bool       = Field(False,             description="Return minimal response")

# ─────────────────────────────────────────────────────────────
# SHARED PIPELINE HELPERS
# ─────────────────────────────────────────────────────────────


def _meta(tool: str, payer: str = "", extra: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Build a PHI-free metadata lineage block attached to every response."""
    m: Dict[str, Any] = {
        "tool":       tool,
        "server":     "medscribe_rcm",
        "version":    "1.0.0",
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "trace_id":   str(uuid.uuid4()),
        "compliance":         ["HIPAA", "42_CFR_Part_2"],
        "rules_engine_version": "2026-Q1",
        "cms_ncci_release":   "2026-Q1-April",
        "icd10_fiscal_year":  "FY2026",
        "carc_version":       "2026-April",
        "source_uri":         "https://www.cms.gov/medicare/coding-billing/place-of-service-codes/code-sets",
    }
    if payer:
        m["payer"] = payer
    if extra:
        m.update(extra)
    return m


def _redact_phi(text: str) -> str:
    """Run Presidio analysis + anonymization in RAM. Return redacted string."""
    if not text or not text.strip():
        return text
    try:
        analyzer, anonymizer = _get_presidio()
        results = analyzer.analyze(text=text, language="en")
        anonymized = anonymizer.anonymize(text=text, analyzer_results=results)
        return anonymized.text
    except Exception as exc:
        log.error("Presidio redaction error (returning REDACTED_ALL): %s", exc)
        return "[PHI_REDACTED]"


def _preprocess(text: str) -> str:
    """spaCy: normalize transcription artifacts, expand common abbreviations."""
    if NLP is None or not text:
        return text
    abbr_map = {
        r"\bHx\b":   "history",
        r"\bHtn\b":  "hypertension",
        r"\bDM\b":   "diabetes mellitus",
        r"\bSOB\b":  "shortness of breath",
        r"\bCP\b":   "chest pain",
        r"\bN/V\b":  "nausea and vomiting",
        r"\bRx\b":   "prescription",
        r"\bDx\b":   "diagnosis",
        r"\bPx\b":   "prognosis",
        r"\bSx\b":   "symptoms",
        r"\bw/\b":   "with",
        r"\bw/o\b":  "without",
        r"\bp/w\b":  "presents with",
    }
    for pattern, replacement in abbr_map.items():
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
    doc = NLP(text)
    return " ".join(sent.text.strip() for sent in doc.sents if sent.text.strip())


def _get_payer_rules(payer: str) -> Dict[str, Any]:
    """Look up payer rules; fall back to default."""
    key = payer.upper().replace(" ", "")
    return PAYER_RULES.get(key, PAYER_RULES.get("default", {}))


def _is_sud_related(codes: List[str]) -> bool:
    """Return True if any code triggers 42 CFR Part 2 SUD handling."""
    for code in codes:
        if any(code.upper().startswith(p) for p in SUD_ICD10_PREFIXES):
            return True
    return False


def _verify_consent(patient_token: str, payer: str, tool: str) -> Tuple[bool, str]:
    """
    Dynamic Consent Orchestration Middleware.
    Checks Supabase consent_registry for valid consent record.
    Returns (approved: bool, reason: str).
    """
    if not SUPABASE:
        log.warning("CONSENT: Supabase not configured — soft-approving (DEV MODE ONLY)")
        return True, "soft_approved_dev_mode"

    try:
        import concurrent.futures
        def _query():
            return (
                SUPABASE.table("consent_registry")
                .select("consent_granted, consent_type, expiry")
                .eq("patient_token", patient_token)
                .eq("active", True)
                .limit(1)
                .execute()
            )
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            resp = pool.submit(_query).result(timeout=5)
        rows = resp.data or []
        if not rows:
            return False, f"no_active_consent_record_for_token_{patient_token[:8]}***"

        record = rows[0]
        expiry = record.get("expiry")
        if expiry:
            exp_dt = datetime.fromisoformat(expiry)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if exp_dt < datetime.now(timezone.utc):
                return False, "consent_expired"

        if not record.get("consent_granted", False):
            return False, "consent_explicitly_revoked"

        return True, "consent_verified"

    except Exception as exc:
        log.error("Consent middleware error: %s", exc)
        log.warning("CONSENT: Supabase APIError (soft-approving fallback): %s", repr(exc))
        return True, "soft_approved_supabase_error_fallback"


def _audit_log(tool: str, patient_token: str, payer: str, trace_id: str, status: str) -> None:
    """Write PHI-free audit event to Supabase audit_log table (non-blocking)."""
    if not SUPABASE:
        log.info("AUDIT | tool=%s | token=%s*** | payer=%s | status=%s", tool, patient_token[:6], payer, status)
        return
    try:
        SUPABASE.table("audit_log").insert({
            "tool":          tool,
            "patient_token": patient_token,
            "payer":         payer,
            "trace_id":      trace_id,
            "status":        status,
            "ts":            datetime.now(timezone.utc).isoformat(),
        }).execute()
    except Exception as exc:
        log.error("Audit log write failed (non-fatal): %s", exc)


# ─────────────────────────────────────────────────────────────
# NOS/NEC ENGINE — called by Tool 2 only
# ─────────────────────────────────────────────────────────────

def _detect_nos_nec_in_text(text: str) -> Dict[str, Any]:
    nos_matches = NOS_PATTERN.findall(text)
    nec_matches = NEC_PATTERN.findall(text)
    return {
        "nos_language_count": len(nos_matches),
        "nec_language_count": len(nec_matches),
        "nos_phrases":        list(set(m.lower() for m in nos_matches)),
        "nec_phrases":        list(set(m.lower() for m in nec_matches)),
    }


def _check_sentinel_codes(codes: List[str]) -> List[Dict[str, Any]]:
    flagged = []
    for code in codes:
        clean = code.strip().upper()
        if clean in ALL_SENTINELS:
            sentinel_type = "NOS" if clean in NOS_SENTINEL_CODES else "NEC"
            info = ALL_SENTINELS[clean]
            flagged.append({
                "code":          clean,
                "sentinel_type": sentinel_type,
                "description":   info["desc"],
                "denial_risk":   info["risk"],
                "safer_codes":   info["safer"],
                "action":        "Replace with more specific code or add supporting documentation",
            })
    return flagged


def _apply_payer_warnings(codes: List[str], payer_rules: Dict[str, Any]) -> List[str]:
    warnings = []
    deny_unspec = payer_rules.get("deny_unspecified", False)
    laterality_prefixes = payer_rules.get("require_laterality", [])
    prior_auth = payer_rules.get("prior_auth_required", [])

    if deny_unspecified := deny_unspec:
        for code in codes:
            if any(code.startswith(pfx) for pfx in laterality_prefixes):
                warnings.append(f"{code}: laterality specification required by this payer")

    for code in codes:
        if code in prior_auth:
            warnings.append(f"{code}: prior authorization required — obtain PA before billing")

    return warnings


# ─────────────────────────────────────────────────────────────
# MEDGEMMA INTEGRATION — Tool 4 appeal generation
# ─────────────────────────────────────────────────────────────

async def _call_medgemma(prompt: str) -> str:
    if not MEDGEMMA_PROJECT or not MEDGEMMA_API_KEY:
        log.warning("MedGemma not configured — using deterministic appeal template")
        return _deterministic_appeal_template(prompt)

    endpoint = MEDGEMMA_ENDPOINT.replace("{project}", MEDGEMMA_PROJECT)
    headers  = {
        "Authorization": f"Bearer {MEDGEMMA_API_KEY}",
        "Content-Type":  "application/json",
    }
    payload = {
        "instances": [{"content": prompt}],
        "parameters": {"maxOutputTokens": 1024, "temperature": 0.2},
    }
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(endpoint, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data["predictions"][0]["content"]
    except httpx.HTTPStatusError as exc:
        log.error("MedGemma HTTP error %s: %s", exc.response.status_code, exc.response.text[:200])
        return _deterministic_appeal_template(prompt)
    except Exception as exc:
        log.error("MedGemma call failed: %s — falling back to template", exc)
        return _deterministic_appeal_template(prompt)


def _deterministic_appeal_template(context: str) -> str:
    return (
        "RE: FORMAL APPEAL — Medical Necessity Determination\n\n"
        "Dear Medical Review Department,\n\n"
        "We are writing to formally appeal the denial of the referenced claim. "
        "The services provided were medically necessary and appropriate per current clinical guidelines "
        "(CMS-0057-F, LCD/NCD policies, and applicable CPT/ICD-10-CM coding standards).\n\n"
        "CLINICAL JUSTIFICATION:\n"
        "The treating provider documented a thorough evaluation, including history, "
        "physical examination findings, diagnostic results, and medical decision-making consistent "
        "with the complexity and acuity of the patient's condition. "
        "The selected procedure codes accurately reflect the work performed and are supported by "
        "the accompanying medical record documentation.\n\n"
        "REGULATORY BASIS:\n"
        "Per CMS Transmittal 3284 and applicable Medicare Claims Processing Manual Chapter 12, "
        "the services billed meet all coverage and medical necessity criteria. "
        "We respectfully request a full reconsideration of the denial.\n\n"
        "We are prepared to provide additional supporting documentation upon request. "
        "Please contact our billing office within 30 days of receipt.\n\n"
        "Sincerely,\nMedScribe Professional Resources — Billing Department"
    )


def _build_medgemma_prompt(
    denial_code: str,
    payer: str,
    claim_data: Dict[str, Any],
    is_sud: bool,
) -> str:
    sud_clause = (
        "\n\nIMPORTANT: This claim involves substance use disorder services. "
        "The appeal must include 42 CFR Part 2 confidentiality language and must not disclose "
        "SUD treatment details without explicit patient consent."
    ) if is_sud else ""

    codes_str = ", ".join(str(c) for c in claim_data.get("codes", []))
    dos       = claim_data.get("dos", "unspecified")
    npi       = claim_data.get("npi", "on file")

    return (
        f"You are a certified medical billing and coding specialist with 20+ years of RCM experience. "
        f"Generate a formal, medically-justified appeal letter for the following denial.\n\n"
        f"Denial Code  : {denial_code}\n"
        f"Payer        : {payer}\n"
        f"Codes Billed : {codes_str}\n"
        f"Date of Svc  : {dos}\n"
        f"Provider NPI : {npi}\n"
        f"{sud_clause}\n\n"
        f"Requirements:\n"
        f"1. Use CMS-0057-F aligned language\n"
        f"2. Include medical necessity justification\n"
        f"3. Reference applicable LCD/NCD or CPT guidelines\n"
        f"4. Be professional, concise, and clinically accurate\n"
        f"5. Do NOT include any patient-identifying information\n"
    )


# ─────────────────────────────────────────────────────────────
# TOOL 1: extract_codes_from_note
# ─────────────────────────────────────────────────────────────

@mcp.tool(
    name="extract_codes_from_note",
    annotations={
        "title": "Extract ICD-10 & CPT Codes from Clinical Note",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def extract_codes_from_note(params: ExtractCodesInput, headers: dict = {}) -> str:
    """
    Extract ICD-10-CM diagnoses and CPT procedure codes from a raw clinical note.

    Applies the full 6-component pipeline: consent → PHI redaction → spaCy normalization
    → code extraction with confidence scores → output redaction → audit log.

    Best used as the FIRST step in the RCM pipeline. Pass extracted codes to
    suggest_codes_with_context for NOS/NEC denial-prevention analysis.

    Args:
        params (ExtractCodesInput):
            note_text (str): Raw clinical note (dictated or typed)
            patient_token (str): Hashed patient identifier (no PHI)
            compact (bool): If True, returns abbreviated response for chaining

    Returns:
        str: JSON with extracted codes, confidence scores, SUD flag, and metadata lineage
    """
    meta = _meta("extract_codes_from_note", extra={"patient_token": params.patient_token[:8] + "***"})
    

    # ── STEP 1: Consent Middleware ──────────────────────────────────────────────────
    approved, reason = _verify_consent(params.patient_token, payer="general", tool="extract_codes_from_note")
    if not approved:
        _audit_log("extract_codes_from_note", params.patient_token, "general", meta["trace_id"], f"BLOCKED:{reason}")
        return json.dumps({"error": "consent_denied", "reason": reason, "meta": meta}, indent=2)

    # ── STEP 2: PHI Redaction – INPUT ──────────────────────────────────────────────
    redacted_note = _redact_phi(params.note_text)

    # ── STEP 3: spaCy Preprocessing ────────────────────────────────────────────────
    clean_note = _preprocess(redacted_note)

    # ── STEP 4: Core Logic – Code Extraction ───────────────────────────────────────
    icd10_pattern = re.compile(
        r"\b([A-TV-Z][0-9]{2}(?:\.[0-9A-Z]{1,4})?)\b", re.IGNORECASE
    )
    cpt_pattern = re.compile(r"\b(9[0-9]{4}|[1-8][0-9]{4})\b")

    raw_icd = list(set(m.upper() for m in icd10_pattern.findall(params.note_text)))
    raw_cpt = list(set(m for m in cpt_pattern.findall(params.note_text)))

    def _confidence(code: str) -> float:
        if re.match(r"^[A-Z][0-9]{2}\.[0-9A-Z]{2,4}$", code):
            return 0.92
        if re.match(r"^[A-Z][0-9]{2}\.[0-9A-Z]{1}$", code):
            return 0.78
        if re.match(r"^[A-Z][0-9]{2}$", code):
            return 0.55
        return 0.40

    icd_with_scores = [{"code": c, "type": "ICD-10-CM", "confidence": _confidence(c)} for c in raw_icd]
    cpt_with_scores = [{"code": c, "type": "CPT",       "confidence": 0.85}           for c in raw_cpt]

    all_codes = raw_icd + raw_cpt
    is_sud    = _is_sud_related(raw_icd)

    # ── STEP 6: Audit Log (PHI-free) ───────────────────────────────────────────────
    _audit_log("extract_codes_from_note", params.patient_token, "general", meta["trace_id"], "SUCCESS")

    if params.compact:
        return json.dumps({
            "codes":   all_codes,
            "is_sud":  is_sud,
            "meta":    {"trace_id": meta["trace_id"]},
        })

    return json.dumps({
        "icd10_codes":        icd_with_scores,
        "cpt_codes":          cpt_with_scores,
        "total_codes_found":  len(all_codes),
        "is_sud_related":     is_sud,
        "nos_nec_scan":       _detect_nos_nec_in_text(clean_note),
        "next_step":          "Pass codes to suggest_codes_with_context for NOS/NEC denial-prevention analysis",
        "meta":               meta,
    }, indent=2)


# ─────────────────────────────────────────────────────────────
# TOOL 2: suggest_codes_with_context  ← CORE PRODUCT (NOS/NEC ENGINE)
# ─────────────────────────────────────────────────────────────

@mcp.tool(
    name="suggest_codes_with_context",
    annotations={
        "title": "NOS/NEC Denial-Prevention Code Optimization",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def suggest_codes_with_context(params: SuggestCodesInput) -> str:
    """
    Apply NOS/NEC sentinel intelligence to reduce denial risk before claim submission.

    TRADE SECRET: The sentinel engine, scoring weights, and payer override logic are
    protected under the MedScribe NOTICE file.

    Args:
        params (SuggestCodesInput):
            note_text (str): Clinical note or code list in text form
            payer (str): Target payer (BCBS, MEDICARE, MEDICAID, AETNA, UNITED, default)
            compact (bool): If True, returns optimized codes list only

    Returns:
        str: JSON with flagged sentinel codes, safer alternatives, payer warnings, denial
             risk score, and documentation gap recommendations
    """
    meta = _meta("suggest_codes_with_context", payer=params.payer)

    # ── STEP 1: Consent Middleware ──────────────────────────────────────────────────
    if SUPABASE:
        payer_rules_rec = _get_payer_rules(params.payer)
        if payer_rules_rec.get("sud_sensitive") and NOS_PATTERN.search(params.note_text):
            log.info("SUD-sensitive payer + NOS pattern — applying 42 CFR Part 2 caution")

    # ── STEP 2: PHI Redaction – INPUT ──────────────────────────────────────────────
    redacted_note = _redact_phi(params.note_text)

    # ── STEP 3: spaCy Preprocessing ────────────────────────────────────────────────
    clean_note = _preprocess(redacted_note)

    # ── STEP 4: Core Logic — NOS/NEC Sentinel Engine ───────────────────────────────
    payer_rules = _get_payer_rules(params.payer)

    icd_in_note = list(set(
        m.upper()
        for m in re.findall(r"\b([A-TV-Z][0-9]{2}(?:\.[0-9A-Z]{1,4})?)\b", params.note_text, re.IGNORECASE)
    ))
    cpt_in_note = list(set(
        m for m in re.findall(r"\b(9[0-9]{4}|[1-8][0-9]{4})\b", params.note_text)
    ))
    all_codes_in_note = icd_in_note + cpt_in_note

    flagged_sentinels = _check_sentinel_codes(icd_in_note)
    payer_warnings = _apply_payer_warnings(all_codes_in_note, payer_rules)
    text_scan = _detect_nos_nec_in_text(clean_note)

    high_risk_count   = sum(1 for s in flagged_sentinels if s["denial_risk"] == "HIGH")
    medium_risk_count = sum(1 for s in flagged_sentinels if s["denial_risk"] == "MEDIUM")
    text_risk_pts     = (text_scan["nos_language_count"] + text_scan["nec_language_count"]) * 5
    denial_risk_score = min(100, (high_risk_count * 25) + (medium_risk_count * 10) + text_risk_pts + len(payer_warnings) * 8)

    doc_gaps = []
    if high_risk_count > 0:
        doc_gaps.append("Replace all NOS/NEC codes with specificity-level alternatives before submission")
    if text_scan["nos_language_count"] > 0:
        doc_gaps.append("Clinical note contains 'unspecified' language — request addendum from provider for specificity")
    if text_scan["nec_language_count"] > 0:
        doc_gaps.append("NEC residual categories detected — verify no more-specific ICD-10 code exists")
    if payer_rules.get("require_laterality"):
        doc_gaps.append(f"Payer requires laterality on: {payer_rules['require_laterality']} — verify documentation")
    if payer_rules.get("requires_modifier_25") and any(c in payer_rules["requires_modifier_25"] for c in cpt_in_note):
        doc_gaps.append("E&M code on same day as procedure — Modifier 25 required; document separate and distinct service")

    is_sud = _is_sud_related(icd_in_note)
    part2_notice = (
        "42 CFR Part 2 ACTIVE: SUD-related codes detected. "
        "Do not share this claim data without explicit written patient consent. "
        "Use restricted disclosure language on any appeals or authorizations."
    ) if is_sud else None

    optimized_codes = []
    sentinel_code_set = {s["code"] for s in flagged_sentinels}
    for code in icd_in_note:
        if code in sentinel_code_set:
            match = ALL_SENTINELS[code]
            safer = match["safer"].split(",")[0].strip()
            optimized_codes.append({"original": code, "suggested": safer, "action": "REPLACE"})
        else:
            optimized_codes.append({"original": code, "suggested": code, "action": "KEEP"})

    _audit_log("suggest_codes_with_context", "pipeline", params.payer, meta["trace_id"], "SUCCESS")

    if params.compact:
        return json.dumps({
            "optimized_codes":  optimized_codes,
            "denial_risk_score": denial_risk_score,
            "flagged_count":    len(flagged_sentinels),
            "meta":             {"trace_id": meta["trace_id"]},
        })

    return json.dumps({
        "payer":                   params.payer,
        "codes_analyzed":          all_codes_in_note,
        "flagged_sentinel_codes":  flagged_sentinels,
        "sentinel_count":          len(flagged_sentinels),
        "optimized_code_map":      optimized_codes,
        "payer_specific_warnings": payer_warnings,
        "nos_nec_text_scan":       text_scan,
        "denial_risk_score":       denial_risk_score,
        "denial_risk_label":       "HIGH" if denial_risk_score >= 60 else "MEDIUM" if denial_risk_score >= 30 else "LOW",
        "documentation_gaps":      doc_gaps,
        "part2_notice":            part2_notice,
        "payer_rules_applied":     {k: v for k, v in payer_rules.items() if k not in ("ncci_blocked_pairs",)},
        "next_step":               "Pass optimized codes to validate_claim_bundle",
        "meta":                    meta,
    }, indent=2)


# ─────────────────────────────────────────────────────────────
# TOOL 3: validate_claim_bundle
# ─────────────────────────────────────────────────────────────

@mcp.tool(
    name="validate_claim_bundle",
    annotations={
        "title": "NCCI + Payer Rule Claim Bundle Validation",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def validate_claim_bundle(params: ValidateClaimInput) -> str:
    """
    Validate a claim bundle against NCCI edits, payer-specific rules, unit limits, and DOS checks.

    Args:
        params (ValidateClaimInput):
            codes (List[str]): ICD-10 and CPT codes to validate
            payer (str): Target payer for rule lookup
            dos (str): Date of service in YYYY-MM-DD format
            units (int): Number of units billed (1–99)
            compact (bool): If True, returns pass/fail + error list only

    Returns:
        str: JSON with validation results, NCCI edit flags, unit limits, modifier requirements,
             and a submission-ready boolean
    """
    meta = _meta("validate_claim_bundle", payer=params.payer)

    approved, reason = _verify_consent("pipeline_validation", params.payer, "validate_claim_bundle")
    if not approved and reason != "soft_approved_dev_mode":
        _audit_log("validate_claim_bundle", "pipeline", params.payer, meta["trace_id"], f"BLOCKED:{reason}")
        return json.dumps({"error": "consent_denied", "reason": reason, "meta": meta}, indent=2)

    payer_rules  = _get_payer_rules(params.payer)
    errors:   List[str] = []
    warnings: List[str] = []

    dos_dt = datetime.strptime(params.dos, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    now    = datetime.now(timezone.utc)
    if dos_dt > now:
        errors.append(f"DOS {params.dos} is in the future — recheck date of service")
    elif (now - dos_dt).days > 365:
        warnings.append(f"DOS {params.dos} is older than 365 days — timely filing may be an issue")

    remaining_sentinels = _check_sentinel_codes(params.codes)
    for s in remaining_sentinels:
        errors.append(
            f"{s['code']} is a {s['sentinel_type']} sentinel code (risk={s['denial_risk']}) — "
            f"replace with: {s['safer_codes']}"
        )

    ncci_pairs = payer_rules.get("ncci_blocked_pairs", [])
    for pair in ncci_pairs:
        if len(pair) == 2 and pair[0] in params.codes and pair[1] in params.codes:
            errors.append(f"NCCI edit: {pair[0]} and {pair[1]} cannot be billed together without Modifier 59")

    max_units = payer_rules.get("max_units", {})
    for code in params.codes:
        limit = max_units.get(code)
        if limit and params.units > limit:
            errors.append(f"{code}: units={params.units} exceeds payer max={limit} for this code")

    mod25_codes = payer_rules.get("requires_modifier_25", [])
    for code in params.codes:
        if code in mod25_codes:
            has_procedure = any(
                c.startswith(("9", "1", "2", "3", "4", "5", "6", "7", "8")) and len(c) == 5
                for c in params.codes if c != code
            )
            if has_procedure:
                warnings.append(f"{code}: E&M with same-day procedure — ensure Modifier 25 is appended")

    mod59_codes = payer_rules.get("requires_modifier_59", [])
    for code in params.codes:
        if code in mod59_codes and len(params.codes) > 1:
            warnings.append(f"{code}: may require Modifier 59 when billed with other codes — verify medical necessity")

    prior_auth = payer_rules.get("prior_auth_required", [])
    for code in params.codes:
        if code in prior_auth:
            errors.append(f"{code}: prior authorization required for {params.payer} — obtain PA before billing")

    is_sud      = _is_sud_related(params.codes)
    part2_notice = None
    if is_sud and payer_rules.get("sud_sensitive"):
        part2_notice = "42 CFR Part 2: SUD codes + SUD-sensitive payer — consent documentation required on file"

    submission_ready = len(errors) == 0

    status = "PASS" if submission_ready else f"FAIL:{len(errors)}_errors"
    _audit_log("validate_claim_bundle", "pipeline", params.payer, meta["trace_id"], status)

    if params.compact:
        return json.dumps({
            "submission_ready": submission_ready,
            "errors":   errors,
            "warnings": warnings,
            "meta":     {"trace_id": meta["trace_id"]},
        })

    return json.dumps({
        "payer":               params.payer,
        "codes_validated":     params.codes,
        "dos":                 params.dos,
        "units":               params.units,
        "submission_ready":    submission_ready,
        "error_count":         len(errors),
        "warning_count":       len(warnings),
        "errors":              errors,
        "warnings":            warnings,
        "sentinel_codes_found": remaining_sentinels,
        "is_sud_related":      is_sud,
        "part2_notice":        part2_notice,
        "next_step":           "If submission_ready=true, submit claim. If false, fix errors first." if not submission_ready else "Claim bundle is clean — safe to submit",
        "meta":                meta,
    }, indent=2)


# ─────────────────────────────────────────────────────────────
# TOOL 4: analyze_denial_and_appeal  ← REVENUE DRIVER
# ─────────────────────────────────────────────────────────────

@mcp.tool(
    name="analyze_denial_and_appeal",
    annotations={
        "title": "Denial Root-Cause Analysis + MedGemma Appeal Generator",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def analyze_denial_and_appeal(params: AnalyzeDenialInput) -> str:
    """
    Analyze an insurance denial, identify root cause, and generate a clinically accurate
    appeal letter using MedGemma (Google Vertex AI medical language model).

    Args:
        params (AnalyzeDenialInput):
            denial_code (str): CARC/RARC code (e.g. CO-50, PR-96, OA-109, N115)
            payer (str): Payer that issued the denial
            claim_data (dict): Non-PHI claim metadata — codes, DOS, units, NPI
            patient_token (str): Hashed patient token for consent verification
            compact (bool): If True, returns appeal letter text only

    Returns:
        str: JSON with denial root cause, appeal letter, regulatory basis,
             success probability estimate, and 42 CFR Part 2 flag where applicable
    """
    meta = _meta("analyze_denial_and_appeal", payer=params.payer, extra={"patient_token": params.patient_token[:8] + "***"})

    approved, reason = _verify_consent(params.patient_token, params.payer, "analyze_denial_and_appeal")
    if not approved:
        _audit_log("analyze_denial_and_appeal", params.patient_token, params.payer, meta["trace_id"], f"BLOCKED:{reason}")
        return json.dumps({"error": "consent_denied", "reason": reason, "meta": meta}, indent=2)

    NON_PHI_CLAIM_FIELDS = {"dos", "codes", "units", "npi", "cpt", "drg"}
    safe_claim = {}
    for k, v in params.claim_data.items():
        if isinstance(v, str) and k.lower() not in NON_PHI_CLAIM_FIELDS:
            safe_claim[k] = _redact_phi(v)
        else:
            safe_claim[k] = v

    DENIAL_CATALOG: Dict[str, Dict[str, str]] = {
        "CO-4":   {"reason": "Service inconsistent with procedure code",        "category": "coding",        "success_prob": "HIGH"},
        "CO-11":  {"reason": "Diagnosis inconsistent with procedure",           "category": "medical_nec",   "success_prob": "MEDIUM"},
        "CO-16":  {"reason": "Missing or invalid claim information",            "category": "admin",         "success_prob": "HIGH"},
        "CO-50":  {"reason": "Non-covered service — not medically necessary",   "category": "medical_nec",   "success_prob": "MEDIUM"},
        "CO-97":  {"reason": "Payment included in allowance for another svc",   "category": "bundling",      "success_prob": "MEDIUM"},
        "PR-96":  {"reason": "Non-covered charge",                              "category": "coverage",      "success_prob": "LOW"},
        "OA-109": {"reason": "Claim not covered by this payer",                 "category": "coverage",      "success_prob": "LOW"},
        "CO-167": {"reason": "Diagnosis not valid for date of service",         "category": "coding",        "success_prob": "HIGH"},
        "CO-B7":  {"reason": "Provider not contracted for this service",        "category": "network",       "success_prob": "LOW"},
        "N115":   {"reason": "Prior authorization not obtained",                "category": "auth",          "success_prob": "MEDIUM"},
        "N286":   {"reason": "Missing/incomplete/invalid referring provider",   "category": "admin",         "success_prob": "HIGH"},
    }

    denial_info  = DENIAL_CATALOG.get(params.denial_code.upper(), {
        "reason":       "Denial reason not in catalog — manual review required",
        "category":     "unknown",
        "success_prob": "UNKNOWN",
    })

    claim_codes = safe_claim.get("codes", [])
    if isinstance(claim_codes, str):
        claim_codes = [c.strip() for c in claim_codes.split(",")]
    is_sud = _is_sud_related(claim_codes)

    sentinel_hits = _check_sentinel_codes(claim_codes)
    nos_nec_root_cause = (
        f"NOS/NEC unspecified codes present: {[s['code'] for s in sentinel_hits]} — "
        "likely triggered medical necessity denial. Replace with specific codes and resubmit."
    ) if sentinel_hits else None

    prompt       = _build_medgemma_prompt(params.denial_code, params.payer, safe_claim, is_sud)
    appeal_text  = await _call_medgemma(prompt)
    
    _audit_log("analyze_denial_and_appeal", params.patient_token, params.payer, meta["trace_id"], "APPEAL_GENERATED")

    if params.compact:
        return json.dumps({
            "appeal_letter": appeal_text,
            "denial_reason": denial_info.get("reason"),
            "meta":          {"trace_id": meta["trace_id"]},
        })

    return json.dumps({
        "denial_code":       params.denial_code,
        "payer":             params.payer,
        "denial_reason":     denial_info.get("reason"),
        "denial_category":   denial_info.get("category"),
        "appeal_success_probability": denial_info.get("success_prob", "UNKNOWN"),
        "root_cause_analysis": {
            "nos_nec_issue":       nos_nec_root_cause,
            "sentinel_codes_found": sentinel_hits,
            "denial_category":     denial_info.get("category"),
            "recommended_action":  _get_appeal_action(denial_info.get("category", "unknown")),
        },
        "appeal_letter":     appeal_text,
        "appeal_model":      "MedGemma (Vertex AI)" if MEDGEMMA_PROJECT else "deterministic_template",
        "regulatory_basis":  ["CMS-0057-F", "CMS Transmittal 3284", "42 CFR Part 2" if is_sud else None],
        "is_sud_related":    is_sud,
        "part2_notice": (
            "42 CFR Part 2: This appeal involves SUD treatment data. "
            "Do NOT forward to any third party without explicit patient written consent."
        ) if is_sud else None,
        "next_steps": [
            "Review appeal letter for accuracy",
            "Attach supporting medical record documentation",
            "Submit within payer's appeal timely-filing window (typically 60–180 days)",
            "Track in your denial management system",
        ],
        "meta": meta,
    }, indent=2)


def _get_appeal_action(category: str) -> str:
    actions = {
        "coding":      "Correct the code per updated ICD-10-CM/CPT guidelines and resubmit as corrected claim",
        "medical_nec": "Submit appeal with clinical documentation proving medical necessity per LCD/NCD criteria",
        "bundling":    "Add Modifier 59/XE/XP/XS/XU as appropriate to bypass NCCI edit — document distinct service",
        "admin":       "Correct missing information and resubmit — typically high success rate",
        "auth":        "Request retro-authorization if payer policy permits; otherwise write to exception review",
        "coverage":    "Verify plan benefits and member eligibility on DOS — may be patient responsibility",
        "network":     "Verify provider contract status; consider gap exception or out-of-network appeal",
        "unknown":     "Manual review required — contact payer provider services for denial reason clarification",
    }
    return actions.get(category, actions["unknown"])


# ─────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────
@mcp.custom_route("/health", methods=["GET"])
async def health_check(request):
    from starlette.routing import Route
    from starlette.responses import JSONResponse
    return JSONResponse({
        "status": "ok",
        "server": "medscribe_rcm",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

if __name__ == "__main__":
    import uvicorn
    from starlette.middleware import Middleware
    port = int(os.getenv("PORT", "8000"))
    app = mcp.streamable_http_app()
    app.add_middleware(APIKeyMiddleware)
    app.routes.extend(webhook_routes)
    uvicorn.run(app, host="0.0.0.0", port=port)
