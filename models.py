"""
models.py — MedScribe RCM-FastMCP
==================================
Single source of truth for every Pydantic model used across Tools 1-4
and the health endpoint.

Key design decisions
--------------------
* RULES_ENGINE_VERSION + SOURCE_URI live here — one line to update for
  the whole server on a quarterly CMS release.
* BaseRCMResponse forces metadata into EVERY response at the type level;
  no tool can accidentally omit it.
* compact=True trims verbose fields but keeps metadata intact —
  downstream agents rely on metadata for version-gating.
* PHI is NEVER stored or logged.  All text fields here contain either
  redacted text or non-PHI codes/tokens.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

# ─────────────────────────────────────────────────────────────────────────────
# ①  Central version constants — update these ONLY; every model picks them up
# ─────────────────────────────────────────────────────────────────────────────

RULES_ENGINE_VERSION: str = "2026-Q2"   # ← bump quarterly after CMS release
SOURCE_URI: str = "https://medscribepro.in"


# ─────────────────────────────────────────────────────────────────────────────
# ②  Shared metadata block (frozen so agents can hash it for integrity checks)
# ─────────────────────────────────────────────────────────────────────────────

class RCMMetadata(BaseModel):
    """Lineage block injected at the top level of every tool response."""

    model_config = ConfigDict(frozen=True)

    rules_engine_version: str = Field(
        default=RULES_ENGINE_VERSION,
        description="Quarterly CMS rules snapshot this response was generated against.",
        examples=["2026-Q2"],
    )
    source_uri: str = Field(
        default=SOURCE_URI,
        description="Canonical service URI for audit and provenance.",
        examples=["https://medscribepro.in"],
    )


# Singleton — imported and reused everywhere
DEFAULT_METADATA = RCMMetadata()


# ─────────────────────────────────────────────────────────────────────────────
# ③  Base class — all tool responses extend this
# ─────────────────────────────────────────────────────────────────────────────

class BaseRCMResponse(BaseModel):
    """
    Parent for every tool output model.

    Guarantees that `metadata` is always the first key in JSON output and
    that `compact` suppression is applied uniformly via .to_response().
    """

    model_config = ConfigDict(
        populate_by_name=True,
        str_strip_whitespace=True,
    )

    metadata: RCMMetadata = Field(
        default_factory=RCMMetadata,
        description="Lineage block — always present regardless of compact mode.",
    )

    def to_response(self, compact: bool = False) -> Dict[str, Any]:
        """
        Serialise to dict.  compact=True keeps metadata intact but drops
        fields annotated with json_schema_extra={'compact_hide': True}.
        """
        full = self.model_dump(mode="python")
        if not compact:
            return full
        # Walk the model fields and strip compact_hide fields
        for field_name, field_info in self.model_fields.items():
            extra = field_info.json_schema_extra or {}
            if extra.get("compact_hide") and field_name in full:
                del full[field_name]
        return full


# ─────────────────────────────────────────────────────────────────────────────
# ④  Shared sub-models (reused across tools)
# ─────────────────────────────────────────────────────────────────────────────

class CodeCandidate(BaseModel):
    """A single extracted or suggested medical code."""

    code: str = Field(..., description="The billing/diagnosis code. e.g. 'E11.9'.")
    label: str = Field(..., description="Human-readable code description.")
    domain: str = Field(..., description="Coding vocabulary: icd10 | hcpcs | cpt.")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Model confidence 0-1.")
    explanation: str = Field(..., description="Short plain-English rationale.")
    nos_nec_warning: Optional[str] = Field(
        default=None,
        description=(
            "Non-null when this code is on the NOS/NEC Sentinel List. "
            "Contains the recommended specific replacement code + reason."
        ),
    )
    hierarchy: List[str] = Field(
        default_factory=list,
        description="Breadcrumb from root chapter → this code.",
        json_schema_extra={"compact_hide": True},
    )


class ClaimViolation(BaseModel):
    """A single NCCI or MUE rule violation found in a claim bundle."""

    rule_type: str = Field(..., description="'NCCI_PTP' | 'MUE' | 'BUNDLING'.")
    code_a: str = Field(..., description="First code in the conflict pair.")
    code_b: Optional[str] = Field(default=None, description="Second code (if pair conflict).")
    units_submitted: Optional[int] = Field(default=None)
    mue_limit: Optional[int] = Field(default=None)
    description: str = Field(..., description="Plain-English explanation of the violation.")
    cms_reference: str = Field(
        ...,
        description="CMS document / table reference e.g. 'NCCI PTP Table Q1-2026 row 4721'.",
        json_schema_extra={"compact_hide": True},
    )


# ─────────────────────────────────────────────────────────────────────────────
# ⑤  Health response
# ─────────────────────────────────────────────────────────────────────────────

class HealthResponse(BaseRCMResponse):
    """Response model for the get_health tool."""

    status: str = Field(default="ok")
    version: str = Field(default=RULES_ENGINE_VERSION)
    presidio_available: bool = Field(
        default=False,
        description="True when Microsoft Presidio is loaded and ready.",
    )
    supabase_connected: bool = Field(
        default=False,
        description="True when Supabase consent registry is reachable.",
    )
    uptime_seconds: Optional[float] = Field(
        default=None,
        json_schema_extra={"compact_hide": True},
    )


# ─────────────────────────────────────────────────────────────────────────────
# ⑥  Tool 1 — extract_codes_from_note
# ─────────────────────────────────────────────────────────────────────────────

class ExtractCodesResponse(BaseRCMResponse):
    """Output model for Tool 1."""

    patient_token_hash: str = Field(
        ...,
        description="SHA-256 of the patient_token — the ONLY patient identifier stored.",
    )
    redacted_note_preview: str = Field(
        ...,
        description="First 300 chars of Presidio-redacted note (no PHI).",
        json_schema_extra={"compact_hide": True},
    )
    codes: List[CodeCandidate] = Field(
        ...,
        description="Extracted ICD-10-CM + HCPCS candidates, ranked by confidence.",
    )
    nos_nec_count: int = Field(
        default=0,
        description="Number of NOS/NEC sentinel hits requiring review.",
    )
    audit_entry: Dict[str, Any] = Field(
        ...,
        description="PHI-free audit log entry: hashed token + timestamp + tool_name.",
        json_schema_extra={"compact_hide": True},
    )


# ─────────────────────────────────────────────────────────────────────────────
# ⑦  Tool 2 — suggest_codes_with_context
# ─────────────────────────────────────────────────────────────────────────────

class PayerOverride(BaseModel):
    """A single payer-specific coding rule override."""

    code: str
    action: str = Field(..., description="'prefer' | 'avoid' | 'require_modifier'.")
    reason: str
    effective_date: str


class SuggestCodesResponse(BaseRCMResponse):
    """Output model for Tool 2."""

    patient_token_hash: str
    payer: str
    suggestions: List[CodeCandidate] = Field(
        ...,
        description="Ranked codes with payer context applied.",
    )
    payer_overrides_applied: List[PayerOverride] = Field(
        default_factory=list,
        description="Payer-specific rules that altered suggestions.",
        json_schema_extra={"compact_hide": True},
    )
    nos_nec_count: int = Field(default=0)
    audit_entry: Dict[str, Any] = Field(
        ..., json_schema_extra={"compact_hide": True}
    )


# ─────────────────────────────────────────────────────────────────────────────
# ⑧  Tool 3 — validate_claim_bundle
# ─────────────────────────────────────────────────────────────────────────────

class ValidateClaimResponse(BaseRCMResponse):
    """Output model for Tool 3."""

    patient_token_hash: str
    risk_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="0 = clean claim, 100 = guaranteed denial.",
    )
    risk_label: str = Field(
        ...,
        description="'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'.",
    )
    violations: List[ClaimViolation] = Field(
        ...,
        description="NCCI/MUE rule conflicts found in the submitted bundle.",
    )
    ncci_version: str = Field(
        ...,
        description="CMS NCCI table version used. e.g. 'Q1-2026'.",
    )
    mue_version: str = Field(
        ...,
        description="CMS MUE table version used. e.g. 'Q1-2026'.",
    )
    corrected_bundle: Optional[List[str]] = Field(
        default=None,
        description="Suggested corrected code list after removing conflicts.",
        json_schema_extra={"compact_hide": True},
    )
    audit_entry: Dict[str, Any] = Field(
        ..., json_schema_extra={"compact_hide": True}
    )


# ─────────────────────────────────────────────────────────────────────────────
# ⑨  Tool 4 — analyze_denial_and_appeal
# ─────────────────────────────────────────────────────────────────────────────

class AppealTemplate(BaseModel):
    """A ready-to-send appeal letter template."""

    deadline_type: str = Field(
        ..., description="'72_HOUR_EXPEDITED' | '7_DAY_STANDARD'."
    )
    subject_line: str
    body: str = Field(
        ...,
        description="Full appeal letter body.  PROPRIETARY — only in paid tier.",
        json_schema_extra={"compact_hide": True},
    )
    body_preview: str = Field(
        ...,
        description="First 400 chars of body (always returned, even in free tier).",
    )


class DenialAnalysisResponse(BaseRCMResponse):
    """Output model for Tool 4."""

    patient_token_hash: str
    denial_code: str
    carc_description: str = Field(..., description="Plain-English CARC meaning.")
    rarc_description: Optional[str] = Field(
        default=None, description="Plain-English RARC meaning (if present)."
    )
    payer_denial_rate: Optional[float] = Field(
        default=None,
        description=(
            "Payer's denial rate for this code from CMS-0057-F public metrics (0-1)."
        ),
    )
    appeal_success_rate: Optional[float] = Field(
        default=None,
        description="Historical appeal overturn rate for this payer+CARC combo (0-1).",
    )
    root_cause: str = Field(..., description="Plain-English root cause explanation.")
    appeal_templates: List[AppealTemplate] = Field(
        ..., description="72-hour and 7-day templates (body_preview always present)."
    )
    sud_redisclosure_notice: Optional[str] = Field(
        default=None,
        description=(
            "Non-null for any SUD-related denial. Mandatory 42 CFR Part 2 notice."
        ),
    )
    cms_0057f_reference: Optional[str] = Field(
        default=None,
        description="CMS-0057-F public metric source URL.",
        json_schema_extra={"compact_hide": True},
    )
    audit_entry: Dict[str, Any] = Field(
        ..., json_schema_extra={"compact_hide": True}
    )
