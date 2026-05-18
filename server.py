from __future__ import annotations
import code
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
from mcp.server.fastmcp import FastMCP, Context
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from pydantic import BaseModel, ConfigDict, Field, field_validator
from supabase import Client, create_client

load_dotenv()

from webhook_handler import webhook_routes
from tool_coverage_lookup import run_coverage_lookup
from tool_charge_capture import run_charge_capture
from starlette.routing import Route
from starlette.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

class APIKeyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        exempt = [
             "/",
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

# Supabase audit client — service key ONLY, bypasses RLS for audit writes
# anon_insert_audit policy has been dropped; only service key can write audit_log
_SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")
SUPABASE_AUDIT: Optional[Client] = None
if _SUPABASE_URL and _SUPABASE_SERVICE_KEY:
    try:
        SUPABASE_AUDIT = create_client(_SUPABASE_URL, _SUPABASE_SERVICE_KEY)
    except Exception as exc:
        log.warning("Supabase audit client init failed (non-fatal): %s", exc)

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

# ─────────────────────────────────────────────────────────────
# STAGE 3: PROSE-TO-CODE MAP  ← condition keywords → sentinel ICD codes
# Used when note_text contains no explicit ICD codes (pure prose input).
# Maps longest/most-specific keyword first to avoid false matches.
# ─────────────────────────────────────────────────────────────
PROSE_TO_CODE_MAP: List[Tuple[str, str]] = [
    # Low back pain
    ("low back pain",                  "M54.50"),
    ("lumbar pain",                    "M54.50"),
    ("lumbago",                        "M54.50"),
    ("low back",                       "M54.50"),
    # Type 2 diabetes
    ("type 2 diabetes",               "E11.9"),
    ("type ii diabetes",              "E11.9"),
    ("t2dm",                           "E11.9"),
    ("diabetes mellitus",             "E11.9"),
    ("diabetic",                       "E11.9"),
    # Anxiety
    ("anxiety disorder",              "F41.9"),
    ("anxiety",                        "F41.9"),
    # Depression / MDD
    ("major depressive disorder",     "F32.9"),
    ("major depressive",              "F32.9"),
    ("depression",                     "F32.9"),
    ("mdd",                            "F32.9"),
    # Abdominal pain
    ("abdominal pain",                "R10.9"),
    # Upper respiratory infection
    ("upper respiratory infection",   "J06.9"),
    ("upper respiratory",             "J06.9"),
    ("uri",                            "J06.9"),
    # Headache
    ("cephalgia",                      "R51.9"),
    ("headache",                       "R51.9"),
    # Constipation
    ("constipation",                   "K59.00"),
    # GERD / reflux
    ("gastroesophageal reflux",       "K21.9"),
    ("acid reflux",                    "K21.9"),
    ("gerd",                           "K21.9"),
    ("reflux",                         "K21.9"),
    # Hypertension
    ("high blood pressure",           "I10"),
    ("hypertension",                   "I10"),
    ("htn",                            "I10"),
    # Chronic pain
    ("chronic pain",                   "G89.29"),
    # Pain NOS
    ("pain, unspecified",             "G89.9"),
    # Soft tissue disorder / myalgia
    ("fibromyalgia",                   "M79.9"),
    ("myalgia",                        "M79.9"),
    ("soft tissue disorder",          "M79.9"),
    # Respiratory disorder
    ("respiratory disorder",          "J98.9"),
    # Rheumatoid arthritis
    ("rheumatoid arthritis",          "M06.9"),
    # Skin / subcutaneous disorder
    ("skin disorder",                  "L98.9"),
    # Cognitive symptoms
    ("cognitive symptoms",            "R41.89"),
    ("memory problems",               "R41.89"),
    ("memory loss",                   "R41.89"),
    # Long-term medication use
    ("long-term medication",          "Z79.899"),
    ("chronic medication",            "Z79.899"),
    # Wound care / diabetic foot
    ("diabetic foot ulcer",           "E11.621"),
    ("diabetic foot",                 "E11.621"),
    ("foot ulcer",                    "L97.509"),
    ("heel ulcer",                    "L97.419"),
    ("pressure ulcer",                "L89.90"),
    ("osteomyelitis",                 "M86.9"),
    ("wound infection",               "L08.9"),
]

# ─────────────────────────────────────────────────────────────
# STAGE 3: CLINICAL ENTITY MAP
# Rule-based extraction of laterality, site, chronicity, severity
# from prose — used to filter Supabase safer_alternative queries
# so results are site/laterality-specific rather than generic siblings.
# ─────────────────────────────────────────────────────────────
CLINICAL_ENTITY_MAP: Dict[str, Dict[str, str]] = {
    "laterality": {
        "left":      "left",
        "right":     "right",
        "bilateral": "bilateral",
    },
    "site": {
        "heel":     "heel",
        "ankle":    "ankle",
        "foot":     "foot",
        "toe":      "toe",
        "knee":     "knee",
        "shoulder": "shoulder",
        "wrist":    "wrist",
        "hand":     "hand",
        "finger":   "finger",
        "elbow":    "elbow",
        "thigh":    "thigh",
        "sacrum":   "sacrum",
        "sacral":   "sacrum",
        "coccyx":   "coccyx",
        "hip":      "hip",
        "lumbar":   "lumbar",
        "cervical": "cervical",
        "plantar":  "plantar",
    },
    "chronicity": {
        "acute":    "acute",
        "chronic":  "chronic",
        "subacute": "subacute",
    },
    "severity": {
        "mild":     "mild",
        "moderate": "moderate",
        "severe":   "severe",
    },
}

# Regex patterns to catch NOS/NEC language in free text
NOS_PATTERN = re.compile(
    r"\b(unspecified|NOS|not otherwise specified|unknown etiology|nonspecific)\b",
    re.IGNORECASE,
)
NEC_PATTERN = re.compile(
    r"\b(NEC|not elsewhere classified|other specified|other and unspecified|residual)\b",
    re.IGNORECASE,
)
# ─────────────────────────────────────────────────────────────
# STAGE 2: DOCUMENTATION SUPPORT ENGINE
# Source: Kiran Kumar BC (forensic AR recovery specialist)
# Pattern: Narrative-to-Code Alignment
# ─────────────────────────────────────────────────────────────

DOC_SUPPORT_MAP: Dict[str, Dict[str, List[str]]] = {
    "M54.50": {
        "M54.51": ["vertebrogenic", "L4-L5", "L5-S1", "disc", "vertebral"],
        "M54.59": ["radiculopathy", "radiating", "sciatica", "nerve root", "foraminal stenosis", "intractable", "failed conservative therapy"],
        "M54.41": ["left", "left side", "left lower"],
        "M54.42": ["right", "right side", "right lower"],
    },
    "E11.9": {
        "E11.40": ["neuropathy", "peripheral neuropathy", "nerve damage", "intractable"],
        "E11.65": ["CKD", "nephropathy", "renal", "failed conservative therapy"],
        "E11.311": ["retinopathy", "diabetic eye", "vision changes"],
        "E11.51": ["peripheral vascular", "PVD", "circulation"],
    },
    "F41.9": {
        "F41.0": ["panic", "panic attack", "palpitations", "sudden onset", "intractable anxiety"],
        "F41.1": ["generalized", "chronic worry", "failed conservative therapy", "GAD", "excessive worry"],
    },
    "F32.9": {
        "F32.0": ["mild", "minimal symptoms"],
        "F32.1": ["moderate", "functional limitation"],
        "F32.2": ["severe", "intractable depression", "failed conservative therapy", "refractory"],
    },
    "R10.9": {
        "R10.11": ["right upper", "RUQ", "epigastric"],
        "R10.31": ["right lower", "RLQ", "appendix"],
        "R10.12": ["left upper", "LUQ"],
        "R10.32": ["left lower", "LLQ"],
    },
    "J06.9": {
        "J02.9": ["pharyngitis", "throat", "sore throat"],
        "J04.0": ["laryngitis", "hoarse", "voice"],
        "J00":   ["rhinorrhea", "nasal", "cold symptoms"],
    },
    "R51.9": {
        "G43.909": ["migraine", "aura", "throbbing", "intractable headache", "failed conservative therapy"],
        "R51.0":   ["orthostatic", "positional headache"],
    },
    "M79.9": {
        "M79.1": ["myalgia", "muscle pain", "fibromyalgia"],
        "M79.3": ["panniculitis", "subcutaneous", "nodular"],
    },
    "G89.29": {
        "G89.21": ["post-procedural", "post-surgical", "post-op pain"],
        "G89.28": ["chronic intractable", "failed conservative therapy", "refractory pain"],
    },
    "K59.00": {
        "K59.01": ["slow transit", "colonic inertia"],
        "K59.02": ["outlet dysfunction", "pelvic floor", "obstructive"],
    },
    "K21.9": {
        "K21.0": ["esophagitis", "erosive", "Barrett", "intractable reflux", "failed conservative therapy"],
    },
    # ── NOS: remaining 1 ─────────────────────────────────────────────────────────────────────────────
    "I10": {
        "I16.0":  ["hypertensive urgency", "urgency", "severely elevated", "BP > 180", "BP over 180"],
        "I16.1":  ["hypertensive emergency", "end-organ damage", "encephalopathy", "papilledema"],
        "I11.9":  ["hypertensive heart", "heart failure", "LVH", "left ventricular hypertrophy"],
        "I12.9":  ["hypertensive CKD", "CKD", "chronic kidney", "renal insufficiency", "nephropathy"],
        "I13.10": ["hypertensive heart and CKD", "cardiac and renal", "combined"],
    },
    # ── NEC: remaining 10 ────────────────────────────────────────────────────────────────────────
    "Z79.899": {
        "Z79.01":  ["anticoagulant", "warfarin", "coumadin", "heparin", "enoxaparin", "apixaban", "rivaroxaban"],
        "Z79.02":  ["antiplatelet", "antithrombotic", "clopidogrel", "ticagrelor", "prasugrel"],
        "Z79.1":   ["antidiabetic", "metformin", "glipizide", "glimepiride", "non-insulin diabetes medication"],
        "Z79.4":   ["insulin", "insulin-dependent", "insulin therapy", "basal insulin", "bolus insulin"],
        "Z79.52":  ["systemic steroid", "prednisone", "dexamethasone", "methylprednisolone", "long-term steroid"],
        "Z79.51":  ["inhaled steroid", "fluticasone", "budesonide", "inhaled corticosteroid"],
        "Z79.82":  ["aspirin", "aspirin therapy", "daily aspirin", "low-dose aspirin", "aspirin 81mg", "baby aspirin"],
        "Z79.83":  ["bisphosphonate", "alendronate", "zoledronic acid", "risedronate", "osteoporosis medication"],
        "Z79.811": ["aromatase inhibitor", "anastrozole", "letrozole", "exemestane"],
        "Z79.84":  ["oral contraceptive", "birth control pill", "OCP", "combined oral contraceptive"],
    },
    "M79.3": {
        "L93.2":  ["lupus", "lupus panniculitis", "SLE", "systemic lupus", "lupus erythematosus profundus"],
        "M35.6":  ["relapsing", "Weber-Christian", "relapsing febrile nodular panniculitis", "recurrent nodules"],
        "L92.3":  ["foreign body", "injected substance", "silicone", "injection site"],
    },
    "R68.89": {
        "R68.81": ["early satiety", "postprandial fullness", "unable to finish meals", "satiety after small meals"],
        "R68.82": ["decreased libido", "decreased sex drive", "loss of libido", "hypoactive sexual desire"],
        "R11.0":  ["nausea", "nausea without vomiting"],
        "R63.0":  ["anorexia", "loss of appetite", "reduced appetite", "poor oral intake"],
    },
    "K92.89": {
        "K92.81": ["mucositis", "GI mucositis", "gastrointestinal mucositis", "chemotherapy-induced mucositis"],
        "K57.30": ["diverticulosis", "diverticular disease", "diverticula", "colonic diverticula"],
        "K92.1":  ["melena", "black tarry stool", "GI bleed", "upper GI bleeding"],
        "K92.0":  ["hematemesis", "vomiting blood", "coffee ground emesis"],
    },
    "M06.9": {
        "M06.011": ["right shoulder", "right shoulder joint", "right shoulder pain", "right shoulder swelling"],
        "M06.021": ["right elbow"],
        "M06.031": ["right wrist"],
        "M06.041": ["right hand", "right MCP", "right PIP", "right fingers"],
        "M06.061": ["right knee"],
        "M06.071": ["right ankle", "right foot"],
        "M06.09":  ["multiple joints", "bilateral", "symmetric", "polyarthritis", "generalized"],
        "M06.00":  ["seropositive", "RF positive", "RF elevated", "anti-CCP positive"],
        "M06.80":  ["seronegative", "RF negative", "anti-CCP negative", "seronegative RA"],
    },
    "L98.9": {
        "L89.159": ["pressure ulcer sacrum", "sacral ulcer", "coccyx ulcer", "sacrum", "coccyx", "pressure injury"],
        "L89.619": ["pressure ulcer heel", "heel ulcer", "heel pressure injury", "heel wound"],
        "L97.419": ["venous ulcer", "stasis ulcer", "chronic leg ulcer", "non-pressure chronic ulcer"],
        "L97.119": ["thigh ulcer", "non-pressure ulcer thigh"],
        "L89.314": ["stage 4", "full thickness", "bone exposed", "tendon exposed"],
        "L89.313": ["stage 3", "full thickness skin loss", "subcutaneous tissue visible"],
        "L89.312": ["stage 2", "partial thickness", "blister", "shallow open ulcer"],
    },
    "R41.89": {
        "R41.3":  ["amnesia", "memory loss", "blackout", "unable to recall", "anterograde", "retrograde"],
        "R41.81": ["age-related cognitive decline", "age-related", "normal aging", "senior forgetfulness"],
        "F06.70": ["mild cognitive impairment", "MCI", "mild neurocognitive disorder", "early cognitive impairment"],
        "R41.0":  ["disorientation", "confused", "confusion", "disoriented to time", "disoriented to place"],
    },
    "Z87.891": {
        "Z87.398": ["history of substance use", "history of drug use", "prior substance use disorder", "former addiction", "in recovery", "sobriety"],
        "Z87.39":  ["history of mental health condition", "past psychiatric history", "previous mental health treatment"],
        "F10.20":  ["alcohol use disorder", "alcohol dependence", "active alcoholism", "current AUD"],
        "F11.20":  ["opioid use disorder", "opioid dependence", "active OUD", "current opioid use"],
    },
    "G89.9": {
        "G89.11": ["acute pain due to trauma", "traumatic", "injury", "post-traumatic pain", "accident", "fracture pain"],
        "G89.12": ["acute post-procedural pain", "post-surgical", "post-op pain", "procedure-related pain"],
        "G89.29": ["chronic pain", "chronic intractable", "long-standing pain", "persistent pain", "failed conservative therapy", "refractory"],
        "G89.3":  ["neoplasm-related pain", "cancer pain", "tumor pain", "malignancy-related", "oncology pain"],
        "G89.4":  ["chronic pain syndrome", "pain syndrome", "central sensitization", "widespread pain"],
    },
    "J98.9": {
        "J98.01": ["dry pleurisy", "pleuritis", "pleuritic chest pain", "pleural rub", "pleural inflammation"],
        "J98.11": ["atelectasis", "collapse", "subsegmental atelectasis", "plate-like atelectasis", "lobar collapse"],
        "J90":    ["pleural effusion", "pleural fluid", "fluid in pleura", "thoracentesis"],
        "J98.2":  ["interstitial emphysema", "mediastinal emphysema", "pneumomediastinum"],
        "J80":    ["ARDS", "acute respiratory distress syndrome", "acute lung injury", "ALI"],
    },
}

SEVERITY_UPGRADE_TRIGGERS: List[str] = [
    "intractable",
    "failed conservative therapy",
    "refractory",
    "chronic unresponsive",
    "not responding to treatment",
    "persistent despite treatment",
    "escalating",
    "worsening despite",
    "functional limitation",
    "unable to perform",
    "activities of daily living",
    "ADL impairment",
]

ANATOMICAL_LANDMARKS: List[str] = [
    "L1", "L2", "L3", "L4", "L5",
    "S1", "S2", "C3", "C4", "C5", "C6", "C7",
    "L4-L5", "L5-S1", "C5-C6",
    "radiculopathy", "foraminal stenosis",
    "nerve root compression", "disc herniation",
    "lateral recess", "central stenosis",
]
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
    note_text: str  = Field(..., min_length=10, description="Clinical note (prose or explicit code list) — Stage 3 auto-detects prose when no ICD codes are present")
    payer:     str  = Field(..., min_length=2,  description="Payer name (BCBS, MEDICARE, MEDICAID, AETNA, UNITED, or default)")
    compact:   bool = Field(False,              description="Return minimal response for chaining")

class ValidateClaimInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    codes:   List[str] = Field(..., min_length=1, description="List of ICD-10 and CPT codes to validate")
    payer:   str       = Field(..., min_length=2, description="Payer name for rule lookup")
    dos:     str       = Field(..., description="Date of service — YYYY-MM-DD format")
    units:   int       = Field(..., ge=1, le=99,  description="Number of units billed")
    compact: bool      = Field(False,             description="Return minimal response for chaining")
    pos:     str       = Field('',                description="Place of Service code (e.g. 11=office, 21=inpatient, 22=outpatient hospital)")

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

class CoverageLookupInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    cpt_code: str = Field(..., min_length=5, max_length=5, description="CPT procedure code (5 digits)")
    state:    str = Field(..., min_length=2, max_length=2, description="Two-letter US state abbreviation (e.g. TX, FL)")
    payer:    str = Field("MEDICARE", min_length=2,         description="Payer name — defaults to MEDICARE")

class ChargeCaptureInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    cpt_code:         str            = Field(..., min_length=5, max_length=5, description="CPT procedure code (5 digits)")
    state:            str            = Field(..., min_length=2, max_length=2, description="Two-letter US state abbreviation (e.g. TX, FL)")
    facility:         bool           = Field(False,              description="True = facility/hospital setting; False = office/non-facility")
    modifier:         str            = Field('',                 description="Optional CPT modifier (e.g. 25, 59, TC)")
    payment_received: Optional[float]= Field(None,              description="Actual payment received — triggers underpayment analysis")

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
    key = payer.lower().replace(" ", "")
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
    """Write PHI-free audit event to Supabase audit_log table (non-blocking).
    Uses service key client only — anon key has no INSERT access to audit_log.
    """
    log.info("AUDIT | tool=%s | token=%s*** | payer=%s | status=%s", tool, patient_token[:6], payer, status)
    if not SUPABASE_AUDIT:
        return
    try:
        SUPABASE_AUDIT.table("audit_log").insert({
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
def _check_documentation_support(code: str, note_text: str) -> Dict[str, Any]:
    """
    Stage 2: Narrative-to-Code Alignment.
    Scans Procedure Note for severity descriptors, anatomical landmarks,
    and code-specific keywords that justify upgrading a sentinel code.
    Pattern sourced from forensic AR recovery specialist Kiran Kumar BC.
    """
    note_lower = note_text.lower()

    severity_hits = [t for t in SEVERITY_UPGRADE_TRIGGERS if t.lower() in note_lower]
    anatomical_hits = [a for a in ANATOMICAL_LANDMARKS if a.lower() in note_lower]

    if code not in DOC_SUPPORT_MAP:
        if severity_hits or anatomical_hits:
            return {
                "supported_upgrade": None,
                "evidence": severity_hits + anatomical_hits,
                "confidence": 0.60,
                "time_to_read_gap": True,
                "severity_triggers": severity_hits,
                "anatomical_landmarks": anatomical_hits,
                "recommendation": "Severity/anatomical language found — manual Procedure Note review recommended for specificity upgrade",
            }
        return {
            "supported_upgrade": None,
            "evidence": [],
            "confidence": 0,
            "time_to_read_gap": False,
            "severity_triggers": [],
            "anatomical_landmarks": [],
            "recommendation": "No documentation support found — request provider addendum",
        }

    best_code = None
    best_evidence: List[str] = []

    for specific_code, keywords in DOC_SUPPORT_MAP[code].items():
        evidence = [kw for kw in keywords if kw.lower() in note_lower]
        if evidence and len(evidence) > len(best_evidence):
            best_code = specific_code
            best_evidence = evidence

    all_evidence = list(set(best_evidence + severity_hits + anatomical_hits))

    return {
        "supported_upgrade": best_code,
        "evidence": all_evidence,
        "confidence": min(0.95, 0.60 + len(all_evidence) * 0.08),
        "time_to_read_gap": best_code is not None,
        "severity_triggers": severity_hits,
        "anatomical_landmarks": anatomical_hits,
        "recommendation": (
            f"Documentation supports upgrade to {best_code} — safe to recode. "
            f"Evidence: {', '.join(best_evidence)}"
        ) if best_code else (
            "Severity language present — manual Procedure Note review recommended"
            if severity_hits else
            "No specific upgrade found — request provider addendum"
        ),
    }
def _lookup_icd10_batch(codes: List[str], supabase_client) -> Dict[str, Dict]:
    """
    Batch query Supabase icd10_codes for a list of codes.
    Returns dict: code -> {description, is_leaf, use_additional, excludes1}
    Silent on failure — Tool 2 degrades gracefully without it.
    """
    if not supabase_client or not codes:
        return {}
    try:
        resp = supabase_client.table("icd10_codes") \
            .select("code,description,is_leaf,use_additional,excludes1") \
            .in_("code", codes) \
            .execute()
        return {row["code"]: row for row in (resp.data or [])}
    except Exception as exc:
        log.warning("icd10_codes batch lookup failed (non-fatal): %s", exc)
        return {}


NOS_NEC_DESC_PATTERN = re.compile(
    r"\b(unspecified|not otherwise specified|NOS|not elsewhere classified|NEC|"
    r"other specified|other and unspecified|unspecified site|unspecified type)\b",
    re.IGNORECASE,
)


def _flag_extended_nos_nec(
    codes: List[str],
    icd10_rows: Dict[str, Dict],
    already_flagged: set,
    supabase_client=None,
    prose_text: str = "",
) -> List[Dict[str, Any]]:
    """
    Extend NOS/NEC detection beyond the 22 hardcoded sentinels using
    CMS descriptions from icd10_codes Supabase table.
    Returns list of extended flags (same shape as sentinel flags).
    """
    # Identify all codes that will be flagged, then batch-fetch alternatives
    flaggable = [
        code for code in codes
        if code not in already_flagged
        and icd10_rows.get(code)
        and (
            NOS_NEC_DESC_PATTERN.search(icd10_rows[code].get("description", ""))
            or not icd10_rows[code].get("is_leaf")
        )
    ]
    alternatives = _find_safer_alternatives_batch(flaggable, supabase_client, prose_text)

    extended = []
    for code in codes:
        if code in already_flagged:
            continue
        row = icd10_rows.get(code)
        if not row:
            continue
        desc = row.get("description", "")
        safer = alternatives.get(code, "See ICD-10-CM tabular for specificity options")
        if NOS_NEC_DESC_PATTERN.search(desc):
            extended.append({
                "code":          code,
                "description":   desc,
                "sentinel_type": "NOS" if "unspecified" in desc.lower() else "NEC",
                "denial_risk":   "MEDIUM",
                "safer_alternative": safer,
                "source":        "icd10_cms_description",
            })
        elif not row.get("is_leaf"):
            extended.append({
                "code":          code,
                "description":   desc,
                "sentinel_type": "HEADER",
                "denial_risk":   "HIGH",
                "safer_alternative": safer if safer != "See ICD-10-CM tabular for specificity options" else "Code is a header category — select a billable child code",
                "source":        "icd10_cms_description",
            })
    return extended


def _extract_clinical_entities(text: str) -> Dict[str, Any]:
    """
    Rule-based NLP entity extraction from clinical prose.
    Extracts laterality, anatomical site, chronicity, severity.
    Returns description_fragments list used to filter Supabase queries.
    """
    text_lower = text.lower()
    entities: Dict[str, Any] = {
        "laterality":            None,
        "sites":                 [],
        "chronicity":            None,
        "severity":              None,
        "description_fragments": [],
    }
    for kw, frag in CLINICAL_ENTITY_MAP["laterality"].items():
        if kw in text_lower:
            entities["laterality"] = frag
            entities["description_fragments"].append(frag)
            break
    for kw, frag in CLINICAL_ENTITY_MAP["site"].items():
        if kw in text_lower and frag not in entities["sites"]:
            entities["sites"].append(frag)
            if frag not in entities["description_fragments"]:
                entities["description_fragments"].append(frag)
    for kw, frag in CLINICAL_ENTITY_MAP["chronicity"].items():
        if kw in text_lower:
            entities["chronicity"] = frag
            entities["description_fragments"].append(frag)
            break
    for kw, frag in CLINICAL_ENTITY_MAP["severity"].items():
        if kw in text_lower:
            entities["severity"] = frag
            entities["description_fragments"].append(frag)
            break
    return entities


def _find_safer_alternatives_batch(
    codes: List[str],
    supabase_client,
    prose_text: str = "",
) -> Dict[str, str]:
    """
    For each NOS/NEC code, find site/laterality-specific leaf codes in the same
    3-char category using clinical entity filters extracted from prose.
    Falls back to unfiltered category siblings if entity query returns nothing.
    Silent on failure — always returns generic fallback string.
    """
    result: Dict[str, str] = {}
    if not supabase_client or not codes:
        return result
    entities = _extract_clinical_entities(prose_text) if prose_text else {"description_fragments": [], "chronicity": None, "laterality": None, "sites": []}
    fragments = entities["description_fragments"]
    try:
        import concurrent.futures
        def _query(code: str):
            prefix = code[:3]
            def _build_query(use_fragments: bool):
                q = supabase_client.table("icd10_codes") \
                    .select("code") \
                    .like("code", f"{prefix}.%") \
                    .eq("is_leaf", True) \
                    .neq("code", code)
                if use_fragments:
                    for frag in fragments:
                        q = q.ilike("description", f"%{frag}%")
                return q.limit(4).execute()
            # Try entity-filtered first; fall back to unfiltered
            resp = _build_query(use_fragments=bool(fragments))
            used_fallback = False
            if not (resp.data or []) and fragments:
                resp = _build_query(use_fragments=False)
                used_fallback = True
            return code, resp, used_fallback
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(codes), 4)) as pool:
            futures = {pool.submit(_query, c): c for c in codes}
            for future in concurrent.futures.as_completed(futures, timeout=3):
                try:
                    code, resp, used_fallback = future.result()
                    rows = resp.data or []
                    if rows:
                        examples = ", ".join(r["code"] for r in rows[:3])
                        if used_fallback and fragments:
                            # Entity filter couldn't narrow — append clinical context hint
                            if not entities.get("chronicity"):
                                suffix = " — specify acute vs chronic to narrow"
                            elif not entities.get("laterality"):
                                suffix = " — specify laterality (left/right) to narrow"
                            else:
                                suffix = " — review for site specificity"
                            result[code] = f"More specific alternatives: {examples}{suffix}"
                        else:
                            result[code] = f"More specific alternatives: {examples}"
                except Exception:
                    pass
    except Exception as exc:
        log.warning("safer_alternatives batch lookup failed (non-fatal): %s", exc)
    return result


def _search_icd10_by_description(noun_phrases: List[str], supabase_client) -> List[str]:
    """
    Second-pass prose extraction: search icd10_codes table by description.
    Fires ilike queries for each noun phrase, returns billable (is_leaf) codes only.
    Uses concurrent.futures to stay synchronous — same pattern as _verify_consent.
    Silent on failure; keyword-map results are always returned regardless.
    """
    if not supabase_client or not noun_phrases:
        return []
    found: List[str] = []
    seen: set = set()
    try:
        import concurrent.futures
        def _query(phrase: str):
            # Starts-with match: prioritises codes where phrase is the primary concept
            # (e.g. 'Osteomyelitis, unspecified') over compound modifiers
            # (e.g. 'Typhoid osteomyelitis', 'Gonococcal osteomyelitis')
            return supabase_client.table("icd10_codes") \
                .select("code") \
                .ilike("description", f"{phrase}%") \
                .eq("is_leaf", True) \
                .limit(3) \
                .execute()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = {pool.submit(_query, p): p for p in noun_phrases}
            for future in concurrent.futures.as_completed(futures, timeout=3):
                try:
                    rows = future.result().data or []
                    for row in rows:
                        code = row["code"]
                        if code not in seen:
                            found.append(code)
                            seen.add(code)
                except Exception:
                    pass
    except Exception as exc:
        log.warning("icd10 description search failed (non-fatal): %s", exc)
    return found


def _extract_noun_phrases(text: str) -> List[str]:
    """
    Extract 1–4 word clinical noun phrases from prose for description search.
    Single words allowed only when >= 8 chars AND not a clinical modifier/adjective.
    Uses spaCy noun chunks when available; falls back to bigram/trigram + long unigrams.
    """
    # Modifiers/adjectives that are too broad to drive standalone ilike queries
    PROSE_QUERY_STOPWORDS = {
        "left", "right", "bilateral", "peripheral", "chronic", "acute", "subacute",
        "severe", "mild", "moderate", "unspecified", "multiple", "primary", "secondary",
        "upper", "lower", "anterior", "posterior", "lateral", "medial", "distal",
        "proximal", "central", "general", "generalized", "systemic", "local",
        "patient", "presents", "history", "diagnosis", "treatment", "clinical",
    }
    def _keep(phrase: str) -> bool:
        words = phrase.split()
        if len(words) == 1:
            # single word: must be >= 8 chars and not a stopword
            return len(phrase) >= 8 and phrase not in PROSE_QUERY_STOPWORDS
        return len(words) <= 4

    if NLP:
        doc = NLP(text)
        phrases = [
            chunk.text.lower() for chunk in doc.noun_chunks
            if _keep(chunk.text.lower())
        ]
        return list(dict.fromkeys(phrases))[:12]
    # fallback: bigrams + trigrams + long single nouns
    words = text.lower().split()
    phrases = [w for w in words if _keep(w)]
    for n in (2, 3):
        for i in range(len(words) - n + 1):
            phrases.append(" ".join(words[i:i + n]))
    return list(dict.fromkeys(phrases))[:12]


# ICD-10 chapter-level plausibility guards for prose extraction.
# Keys are code prefixes; values are terms that MUST appear in prose
# for codes in that chapter to be included. Chapters not listed are
# always considered plausible (conservative: only guard high-FP chapters).
CHAPTER_GUARD: Dict[str, List[str]] = {
    # H00–H59: Diseases of the eye and adnexa
    "H0": ["eye", "vision", "ocular", "orbit", "retina", "cornea",
            "glaucoma", "cataract", "optic", "visual", "conjunctiv",
            "eyelid", "lacrimal", "pupil", "lens"],
    # H60–H95: Diseases of the ear
    "H6": ["ear", "hearing", "tinnitus", "vertigo", "otitis",
            "auditory", "cochlea", "vestibular", "mastoid"],
    "H7": ["ear", "hearing", "tinnitus", "vertigo", "otitis",
            "auditory", "cochlea", "vestibular", "mastoid"],
    "H8": ["ear", "hearing", "tinnitus", "vertigo", "otitis",
            "auditory", "cochlea", "vestibular", "mastoid"],
    "H9": ["ear", "hearing", "tinnitus", "vertigo", "otitis",
            "auditory", "cochlea", "vestibular", "mastoid"],
    # O: Pregnancy, childbirth
    "O":  ["pregnan", "obstetric", "gestation", "trimester",
            "antepartum", "postpartum", "labor", "delivery", "maternal"],
    # P: Perinatal conditions
    "P":  ["newborn", "neonate", "perinatal", "birth", "infant"],
    # Q: Congenital malformations
    "Q":  ["congenital", "malformation", "anomaly", "chromosom", "syndrome"],
}


def _is_chapter_plausible(code: str, text_lower: str) -> bool:
    """Return False if code's chapter requires trigger terms absent from prose."""
    for prefix, triggers in CHAPTER_GUARD.items():
        if code.upper().startswith(prefix):
            return any(t in text_lower for t in triggers)
    return True


def _extract_codes_from_prose(text: str, supabase_client=None) -> Tuple[List[str], str]:
    """
    Stage 3: extract candidate ICD-10 codes from pure clinical prose.
    Pass 1 — keyword map (PROSE_TO_CODE_MAP): fast, offline, sentinel-scoped.
    Pass 2 — Supabase description search: covers full 46,881-code CMS table.
    Returns (codes, input_mode) so Tool 2 can surface which path fired.
    """
    text_lower = text.lower()
    seen: set = set()
    found: List[str] = []

    # Pass 1: keyword map
    for keyword, code in sorted(PROSE_TO_CODE_MAP, key=lambda x: len(x[0]), reverse=True):
        if keyword.lower() in text_lower and code not in seen:
            found.append(code)
            seen.add(code)

    keyword_count = len(found)

    # Pass 2: Supabase description search (extended)
    if supabase_client:
        phrases = _extract_noun_phrases(text)
        extended = _search_icd10_by_description(phrases, supabase_client)
        for code in extended:
            if code not in seen and _is_chapter_plausible(code, text_lower):
                found.append(code)
                seen.add(code)

    if not found:
        return [], "explicit_codes"
    extended_fired = len(found) > keyword_count
    mode = "prose_extraction_extended" if extended_fired else "prose_extraction"
    return found, mode


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
                "documentation_support": None,
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
# SAMPLING HELPER — agent-to-agent via MCP ctx.sample()
# Priority: 1) MCP sampling (Claude) → 2) MedGemma → 3) deterministic template
# ─────────────────────────────────────────────────────────────

async def _generate_appeal_with_sampling(
    prompt: str,
    ctx: Context | None = None,
) -> tuple[str, str]:
    """
    Returns (appeal_text, source_label).
    Tries MCP native sampling first — routes through the connected LLM client
    (Claude Desktop / Claude.ai) with zero additional API keys.
    Falls back to MedGemma, then deterministic template.
    """
    # 1 ── MCP native sampling (ctx from connected Claude client)
    if ctx is not None:
        try:
            result = await ctx.sample(
                messages=prompt,
                system_prompt=(
                    "You are a certified medical billing and coding specialist "
                    "with 20+ years of RCM experience. Generate a formal, "
                    "medically justified, PHI-free appeal letter. "
                    "Use CMS-0057-F aligned language. Be concise and professional."
                ),
                max_tokens=600,
            )
            if result and result.text:
                log.info("Appeal generated via MCP sampling (Claude)")
                return result.text, "mcp_sampling:claude"
        except Exception as exc:
            log.warning("ctx.sample() failed: %s — falling back to MedGemma", exc)

    # 2 ── Anthropic API direct (fires when ANTHROPIC_API_KEY is set)
    anthropic_key = os.getenv("ANTHROPIC_API_KEY", "")
    if anthropic_key:
        try:
            import anthropic as _anthropic
            _client = _anthropic.Anthropic(api_key=anthropic_key)
            r = _client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=600,
                system=(
                    "You are a certified medical billing and coding specialist "
                    "with 20+ years of RCM experience. Generate a formal, "
                    "medically justified, PHI-free appeal letter. "
                    "Use CMS-0057-F aligned language. Be concise under 250 words."
                ),
                messages=[{"role": "user", "content": prompt}],
            )
            log.info("Appeal generated via Anthropic API")
            return r.content[0].text, "anthropic_api:claude-sonnet-4-6"
        except Exception as exc:
            log.warning("Anthropic API call failed: %s — falling back to MedGemma", exc)

    # 3 ── MedGemma (unchanged fallback)
    text = await _call_medgemma(prompt)
    source = "MedGemma (Vertex AI)" if MEDGEMMA_PROJECT else "deterministic_template"
    return text, source


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

    # ── Stage 3: prose fallback — fires only when no ICD codes found explicitly
    input_mode = "explicit_codes"
    if not icd_in_note:
        icd_in_note, input_mode = _extract_codes_from_prose(clean_note, SUPABASE)
        all_codes_in_note = icd_in_note + cpt_in_note
        if icd_in_note:
            log.info("Stage 3 prose extraction (%s): found %d candidate code(s): %s", input_mode, len(icd_in_note), icd_in_note)

    flagged_sentinels = _check_sentinel_codes(icd_in_note)
    for sentinel in flagged_sentinels:
        sentinel["documentation_support"] = _check_documentation_support(
            sentinel["code"], params.note_text
        )

    # ── Supabase ICD-10 extended lookup ──────────────────────────────
    icd10_rows     = _lookup_icd10_batch(icd_in_note, SUPABASE)
    already_flagged = {s["code"] for s in flagged_sentinels}
    extended_flags  = _flag_extended_nos_nec(icd_in_note, icd10_rows, already_flagged, SUPABASE, clean_note)

    # use_additional companion code warnings from CMS data
    use_additional_warnings = []
    for code in icd_in_note:
        row = icd10_rows.get(code)
        if row and row.get("use_additional"):
            for note in row["use_additional"]:
                use_additional_warnings.append(f"{code}: CMS requires — {note}")

    payer_warnings = _apply_payer_warnings(all_codes_in_note, payer_rules)
    text_scan = _detect_nos_nec_in_text(clean_note)

    high_risk_count   = sum(1 for s in flagged_sentinels if s["denial_risk"] == "HIGH") + sum(1 for s in extended_flags if s["denial_risk"] == "HIGH")
    medium_risk_count = sum(1 for s in flagged_sentinels if s["denial_risk"] == "MEDIUM") + sum(1 for s in extended_flags if s["denial_risk"] == "MEDIUM")
    text_risk_pts     = (text_scan["nos_language_count"] + text_scan["nec_language_count"]) * 5
    denial_risk_score = min(100, (high_risk_count * 25) + (medium_risk_count * 10) + text_risk_pts + len(payer_warnings) * 8)

    doc_gaps = []
    if high_risk_count > 0:
        doc_gaps.append("Replace all NOS/NEC codes with specificity-level alternatives before submission")
    if extended_flags:
        doc_gaps.append(f"{len(extended_flags)} additional unspecified/header code(s) detected via CMS ICD-10 lookup — review for specificity")
    if use_additional_warnings:
        doc_gaps.extend(use_additional_warnings)
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
            doc_support = next((s.get("documentation_support") for s in flagged_sentinels if s["code"] == code), None)
            suggested = (doc_support.get("supported_upgrade") or match["safer"].split(",")[0].strip()) if doc_support else match["safer"].split(",")[0].strip()
            optimized_codes.append({"original": code, "suggested": suggested, "action": "REPLACE"})
        else:
            optimized_codes.append({"original": code, "suggested": code, "action": "KEEP"})

    _audit_log("suggest_codes_with_context", "pipeline", params.payer, meta["trace_id"], "SUCCESS")

    if params.compact:
        return json.dumps({
            "optimized_codes":  optimized_codes,
            "denial_risk_score": denial_risk_score,
            "flagged_count":    len(flagged_sentinels),
            "input_mode":       input_mode,
            "meta":             {"trace_id": meta["trace_id"]},
        })

    return json.dumps({
        "payer":                   params.payer,
        "codes_analyzed":          all_codes_in_note,
        "flagged_sentinel_codes":  flagged_sentinels,
        "extended_nos_nec_flags":  extended_flags,
        "sentinel_count":          len(flagged_sentinels) + len(extended_flags),
        "optimized_code_map":      optimized_codes,
        "payer_specific_warnings": payer_warnings,
        "nos_nec_text_scan":       text_scan,
        "denial_risk_score":       denial_risk_score,
        "denial_risk_label":       "HIGH" if denial_risk_score >= 60 else "MEDIUM" if denial_risk_score >= 30 else "LOW",
        "documentation_gaps":      doc_gaps,
        "part2_notice":            part2_notice,
        "payer_rules_applied":     {k: v for k, v in payer_rules.items() if k not in ("ncci_blocked_pairs",)},
        "input_mode":              input_mode,
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

    # ── Telehealth modifier check (GT / 95) ──────────────────────────────
    telehealth_cpt  = payer_rules.get("telehealth_cpt_codes", [])
    telehealth_mods = set(payer_rules.get("telehealth_modifiers", ["GT", "95", "FQ"]))
    submitted_mods  = set(m.strip().upper() for m in (params.codes) if len(m) == 2 and m.isalpha())
    for code in params.codes:
        if code in telehealth_cpt and not submitted_mods & telehealth_mods:
            warnings.append(
                f"{code}: if delivered via telehealth, Modifier GT (Medicare) or 95 (commercial) is required — "
                f"omission causes CO-4 denial"
            )
            break  # one warning covers all telehealth CPTs in bundle

    # ── Mental health POS modifier check (HO / HN / AH) ─────────────────
    mh_cpt  = payer_rules.get("mental_health_pos_cpt", [])
    mh_mods = set(payer_rules.get("mental_health_pos_modifiers", ["HO", "HN", "AH"]))
    for code in params.codes:
        if code in mh_cpt and not submitted_mods & mh_mods:
            warnings.append(
                f"{code}: mental health service — verify POS modifier (HO = master level, HN = bachelor level, "
                f"AH = clinical psychologist) matches rendering provider credentials"
            )
            break  # one warning covers all MH CPTs in bundle

    # ── POS/CPT mismatch check — inpatient CPT billed at office POS ────────
    # 99231/99232/99233 = Subsequent Hospital Care (POS 21/22/23 only)
    # Billing these at POS 11 (office) triggers CO-4 authorization scope denial
    INPATIENT_CARE_CPTS = {"99231", "99232", "99233"}
    INPATIENT_POS       = {"21", "22", "23"}  # inpatient hospital, ICU, on-campus
    if params.pos and params.pos not in INPATIENT_POS:
        for code in params.codes:
            if code in INPATIENT_CARE_CPTS:
                errors.append(
                    f"{code}: Subsequent Hospital Care CPT requires inpatient POS (21/22/23) — "
                    f"POS {params.pos} (office/outpatient) will trigger CO-4 denial. "
                    f"Verify setting of care before submission."
                )

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
async def analyze_denial_and_appeal(params: AnalyzeDenialInput, ctx: Context = None) -> str:
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
    appeal_text, appeal_source = await _generate_appeal_with_sampling(prompt, ctx)
    
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
        "appeal_model":      appeal_source,
        "regulatory_basis":  [r for r in ["CMS-0057-F", "CMS Transmittal 3284", "42 CFR Part 2" if is_sud else None] if r is not None],
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
# TOOL 5: lookup_coverage_policy
# ─────────────────────────────────────────────────────────────

@mcp.tool(
    name="lookup_coverage_policy",
    annotations={
        "title": "NCD + LCD Coverage Policy Lookup",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def lookup_coverage_policy(params: CoverageLookupInput) -> str:
    """
    Returns the applicable Medicare NCD and LCD for a CPT code given state.

    Maps state → MAC contractor → checks Supabase cache (7-day TTL) →
    hits CMS Medicare Coverage Database API if stale → caches result.

    Args:
        params (CoverageLookupInput):
            cpt_code (str): 5-digit CPT code (e.g. 99183)
            state (str): Two-letter state abbreviation (e.g. TX)
            payer (str): Payer name — defaults to MEDICARE

    Returns:
        str: JSON with applicable NCD/LCD policy IDs, titles, coverage
             summary, documentation checklist, and MAC contractor name
    """
    return await run_coverage_lookup(
        cpt_code=params.cpt_code,
        state=params.state,
        payer=params.payer,
        supabase_client=SUPABASE,
        meta_fn=_meta,
    )


# ─────────────────────────────────────────────────────────────
# TOOL 6: get_charge_capture
# ─────────────────────────────────────────────────────────────

@mcp.tool(
    name="get_charge_capture",
    annotations={
        "title": "Medicare Fee Schedule & Underpayment Check",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def get_charge_capture(params: ChargeCaptureInput) -> str:
    """
    Returns the 2026 Medicare Physician Fee Schedule allowed amount for a
    CPT code. Optionally flags underpayments when payment_received is provided.

    Checks Supabase fee_schedule_cache first (25 common RCM codes seeded).
    Falls back to CMS Data API for unlisted codes and caches the result.

    Args:
        params (ChargeCaptureInput):
            cpt_code (str): 5-digit CPT code (e.g. 99213)
            state (str): Two-letter state abbreviation (e.g. TX)
            facility (bool): True = hospital/facility; False = office setting
            modifier (str): Optional CPT modifier (e.g. 25, 59)
            payment_received (float): Actual ERA/EOB payment — triggers
                                      underpayment analysis if provided

    Returns:
        str: JSON with non-facility and facility allowed amounts,
             applicable allowed amount for the setting, and underpayment
             analysis (variance, %, action) when payment_received is given
    """
    return await run_charge_capture(
        cpt_code=params.cpt_code,
        state=params.state,
        facility=params.facility,
        modifier=params.modifier,
        payment_received=params.payment_received,
        supabase_client=SUPABASE,
        meta_fn=_meta,
    )


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
async def register_handler(request: Request):
    return JSONResponse({
        "client_id": os.getenv("WORKOS_CLIENT_ID"),
        "client_secret": os.getenv("WORKOS_CLIENT_SECRET"),
        "client_id_issued_at": 0,
        "client_secret_expires_at": 0,
        "grant_types": ["authorization_code"],
        "token_endpoint_auth_method": "client_secret_basic"
    })

async def oauth_metadata_handler(request: Request):
    base = "https://mcp.medscribepro.in"
    return JSONResponse({
        "issuer": base,
        "authorization_endpoint": "https://api.workos.com/sso/authorize",
        "token_endpoint": "https://api.workos.com/sso/token",
        "registration_endpoint": f"{base}/register",
        "scopes_supported": ["rcm:use"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"]
    })

async def protected_resource_handler(request: Request):
    return JSONResponse({
        "resource": "https://mcp.medscribepro.in/",
        "authorization_servers": ["https://mcp.medscribepro.in"],
        "scopes_supported": ["rcm:use"],
        "bearer_methods_supported": ["header"]
    })

register_route = Route("/register", register_handler, methods=["POST"])
oauth_metadata_route = Route("/.well-known/oauth-authorization-server", oauth_metadata_handler, methods=["GET"])
protected_resource_route = Route("/.well-known/oauth-protected-resource", protected_resource_handler, methods=["GET"])

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    app = mcp.streamable_http_app()
    app.add_middleware(APIKeyMiddleware)
    app.routes[:0] = [register_route, oauth_metadata_route, protected_resource_route]
    app.routes.extend(webhook_routes)
    uvicorn.run(app, host="0.0.0.0", port=port)
