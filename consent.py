"""
consent.py — Dynamic Consent Orchestration Middleware
=======================================================
Enforces 42 CFR Part 2 (updated February 16 2026, OCR enforcement active)
before ANY tool in the RCM pipeline executes.

Rules enforced
--------------
1. A valid consent record MUST exist in Supabase `consent_registry` for the
   hashed patient_token before any tool runs.
2. If the note or claim data contains SUD-related codes / keywords, the
   consent record MUST include sud_consent=True (single TPO patient consent).
3. On refusal: return a structured ConsentRefusalResponse that includes the
   mandatory 42 CFR Part 2 redisclosure prohibition notice.
4. PHI is NEVER stored or logged — only the SHA-256 hashed token travels
   to Supabase; the raw patient_token never leaves RAM.

Supabase schema (free tier, single table)
-----------------------------------------
Table: consent_registry
  patient_token_hash  TEXT  PRIMARY KEY   -- SHA-256(patient_token)
  consent_granted     BOOL  NOT NULL
  sud_consent         BOOL  NOT NULL DEFAULT FALSE
  consent_timestamp   TIMESTAMPTZ NOT NULL
  expiry_timestamp    TIMESTAMPTZ           -- NULL = no expiry
  consented_by        TEXT                  -- staff ID, never patient name
"""

from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field
from supabase import create_client, Client

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# 42 CFR Part 2 Mandatory Redisclosure Notice (verbatim)
# ─────────────────────────────────────────────────────────────────────────────

CFR_PART2_NOTICE: str = (
    "⚠️  42 CFR PART 2 REDISCLOSURE PROHIBITION NOTICE\n"
    "This information has been disclosed to you from records protected under "
    "the Federal Confidentiality of Substance Use Disorder Patient Records "
    "regulations (42 CFR Part 2), as updated February 16, 2026.  "
    "Federal rules prohibit you from making any further disclosure of this "
    "information unless further disclosure is expressly permitted by the "
    "written consent of the person to whom it pertains, or as otherwise "
    "permitted by 42 CFR Part 2.  A general authorisation for the release "
    "of medical or other information is NOT sufficient for this purpose.  "
    "Federal rules restrict any use of this information to criminally "
    "investigate or prosecute any alcohol or drug abuse patient."
)

# SUD keyword / code markers (conservative list — expand as needed)
_SUD_KEYWORDS = frozenset({
    "sud", "substance use disorder", "opioid", "opioid use disorder",
    "heroin", "methadone", "buprenorphine", "naloxone", "suboxone",
    "alcohol use disorder", "aud", "detox", "detoxification",
    "withdrawal", "mat", "medication assisted",
    # ICD-10-CM F1x chapter codes
    "f10", "f11", "f12", "f13", "f14", "f15", "f16", "f17", "f18", "f19",
})


# ─────────────────────────────────────────────────────────────────────────────
# Supabase client (lazy singleton)
# ─────────────────────────────────────────────────────────────────────────────

_supabase_client: Optional[Client] = None


def _get_supabase() -> Client:
    global _supabase_client
    if _supabase_client is None:
        url = os.environ.get("SUPABASE_URL", "")
        key = os.environ.get("SUPABASE_ANON_KEY", "")
        if not url or not key:
            raise EnvironmentError(
                "SUPABASE_URL and SUPABASE_ANON_KEY must be set. "
                "See README — free Supabase project is sufficient."
            )
        _supabase_client = create_client(url, key)
    return _supabase_client


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def hash_token(patient_token: str) -> str:
    """One-way SHA-256 hash of the patient token.  Only this hash is stored."""
    return hashlib.sha256(patient_token.encode("utf-8")).hexdigest()


def _is_sud_related(text: str, codes: Optional[list] = None) -> bool:
    """Return True if the content appears SUD-related."""
    lower = text.lower()
    if any(kw in lower for kw in _SUD_KEYWORDS):
        return True
    if codes:
        for code in codes:
            if any(code.lower().startswith(f) for f in ("f10", "f11", "f12",
                   "f13", "f14", "f15", "f16", "f17", "f18", "f19")):
                return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Consent lookup (pure async, no PHI stored)
# ─────────────────────────────────────────────────────────────────────────────

class ConsentRecord(BaseModel):
    """In-memory representation of a Supabase consent_registry row."""

    patient_token_hash: str
    consent_granted: bool
    sud_consent: bool
    consent_timestamp: datetime
    expiry_timestamp: Optional[datetime] = None


class ConsentRefusal(BaseModel):
    """Returned to the tool caller when consent check fails."""

    refused: bool = True
    reason: str
    redisclosure_notice: Optional[str] = None
    patient_token_hash: str
    tool_name: str
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_tool_response(self) -> str:
        """Serialise to the string a FastMCP tool must return on refusal."""
        import json
        return json.dumps(self.model_dump(), indent=2)


async def check_consent(
    patient_token: str,
    tool_name: str,
    note_text: str = "",
    codes: Optional[list] = None,
) -> Optional[ConsentRefusal]:
    """
    Core consent gate — call this at the top of every tool.

    Returns
    -------
    None                if consent is valid and tool may proceed.
    ConsentRefusal      if the tool call must be blocked.
    """
    token_hash = hash_token(patient_token)
    sud_related = _is_sud_related(note_text, codes)

    try:
        sb = _get_supabase()
        result = (
            sb.table("consent_registry")
            .select("*")
            .eq("patient_token_hash", token_hash)
            .single()
            .execute()
        )
        row = result.data
    except Exception as exc:
        logger.error("Supabase consent lookup failed: %s", exc)
        # Fail-closed: if we cannot verify consent, refuse the call
        return ConsentRefusal(
            reason=(
                "Consent registry unreachable. Tool call refused under fail-closed policy. "
                "Verify SUPABASE_URL and SUPABASE_ANON_KEY, then retry."
            ),
            patient_token_hash=token_hash,
            tool_name=tool_name,
        )

    if not row:
        return ConsentRefusal(
            reason=(
                "No consent record found for this patient token. "
                "A valid consent must be recorded in the consent_registry before "
                "any RCM tool can process this patient's data."
            ),
            patient_token_hash=token_hash,
            tool_name=tool_name,
        )

    record = ConsentRecord(**row)

    # Check expiry
    if record.expiry_timestamp and record.expiry_timestamp < datetime.now(timezone.utc):
        return ConsentRefusal(
            reason=(
                f"Consent for this patient expired at "
                f"{record.expiry_timestamp.isoformat()}. "
                "Obtain fresh consent before retrying."
            ),
            patient_token_hash=token_hash,
            tool_name=tool_name,
        )

    # Check general consent
    if not record.consent_granted:
        return ConsentRefusal(
            reason=(
                "Patient consent is recorded as NOT granted. "
                "Tool call refused. Update consent_registry if consent has since been obtained."
            ),
            patient_token_hash=token_hash,
            tool_name=tool_name,
        )

    # 42 CFR Part 2 — SUD single TPO consent gate
    if sud_related and not record.sud_consent:
        return ConsentRefusal(
            reason=(
                "This request involves Substance Use Disorder (SUD) records. "
                "Under 42 CFR Part 2 (updated February 16, 2026), a specific, "
                "single-purpose Treatment-Payment-Operations (TPO) patient consent "
                "for SUD data is required and has NOT been recorded. "
                "Obtain SUD-specific consent (sud_consent=True in consent_registry) "
                "before retrying."
            ),
            redisclosure_notice=CFR_PART2_NOTICE,
            patient_token_hash=token_hash,
            tool_name=tool_name,
        )

    # Consent valid
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Decorator — wraps any async tool function
# ─────────────────────────────────────────────────────────────────────────────

def require_consent(tool_name: str):
    """
    Decorator for FastMCP tool functions.

    The wrapped function MUST accept `patient_token: str` as its first
    positional argument (after self if a class method).

    Usage
    -----
        @mcp.tool(name="extract_codes_from_note", ...)
        @require_consent("extract_codes_from_note")
        async def extract_codes_from_note(note_text: str, patient_token: str, ...) -> str:
            ...
    """
    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            # FastMCP passes a Pydantic model as the first positional arg
            # when using input models, or keyword args for flat signatures.
            patient_token = kwargs.get("patient_token") or (
                getattr(args[0], "patient_token", None) if args else None
            )
            note_text = kwargs.get("note_text", "") or (
                getattr(args[0], "note_text", "") if args else ""
            )
            codes = kwargs.get("codes") or (
                getattr(args[0], "codes", None) if args else None
            )

            if not patient_token:
                from models import BaseRCMResponse, DEFAULT_METADATA
                import json
                return json.dumps({
                    "metadata": DEFAULT_METADATA.model_dump(),
                    "error": "patient_token is required for consent verification.",
                })

            refusal = await check_consent(
                patient_token=patient_token,
                tool_name=tool_name,
                note_text=str(note_text),
                codes=list(codes) if codes else [],
            )
            if refusal:
                return refusal.to_tool_response()

            return await fn(*args, **kwargs)
        return wrapper
    return decorator
