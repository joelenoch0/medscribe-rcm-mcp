import re
from pydantic import BaseModel, Field, ConfigDict
from typing import List
from phi_guard import redact_phi
from consent_middleware import ConsentMiddleware
from audit_log import AuditLogger

RULES_ENGINE_VERSION = "2026.Q2.1"
SOURCE_URI = "https://github.com/medscribepro/medscribe-rcm-mcp"

ICD10_PATTERN = re.compile(r'\b[A-Z][0-9]{2}\.?[0-9A-Z]{0,4}\b')
HCPCS_PATTERN = re.compile(r'\b[A-Z][0-9]{4}\b')

consent = ConsentMiddleware()
audit   = AuditLogger()

# --- Input model ---
class ExtractCodesInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra='forbid')
    note_text:     str = Field(..., description="Raw clinical note text", min_length=10)
    patient_token: str = Field(..., description="Non-PHI UUID token for this patient", min_length=8)

# --- Output model ---
class ExtractCodesOutput(BaseModel):
    patient_token:        str
    redacted_note:        str
    icd10_codes:          List[str]
    hcpcs_codes:          List[str]
    extraction_note:      str
    rules_engine_version: str
    source_uri:           str

async def extract_codes_from_note(params: ExtractCodesInput) -> ExtractCodesOutput:
    await consent.before_request({"consent": True})
    redacted    = redact_phi(params.note_text)
    icd10_codes = sorted(set(ICD10_PATTERN.findall(redacted)))
    hcpcs_codes = sorted(set(HCPCS_PATTERN.findall(redacted)))
    audit.log(
        action="extract_codes_from_note",
        user_id=params.patient_token,
        metadata={"icd10_count": len(icd10_codes), "hcpcs_count": len(hcpcs_codes)}
    )
    return ExtractCodesOutput(
        patient_token=params.patient_token,
        redacted_note=redacted,
        icd10_codes=icd10_codes,
        hcpcs_codes=hcpcs_codes,
        extraction_note="Pattern-based extraction. Validate with clinical context.",
        rules_engine_version=RULES_ENGINE_VERSION,
        source_uri=SOURCE_URI
    )