import os
from fastmcp import FastMCP
from fastmcp.server.auth import JWTVerifier
from tool_extract import extract_codes_from_note, ExtractCodesInput

JWKS_URI = os.getenv("WORKOS_JWKS_URI")
if not JWKS_URI:
    raise RuntimeError("WORKOS_JWKS_URI not set. Refusing to start.")

verifier = JWTVerifier(
    jwks_uri=JWKS_URI,
    issuer="https://api.workos.com",
    audience="medscribe-rcm"
)

app = FastMCP("medscribe_rcm_mcp", auth=verifier)

@app.tool(
    name="extract_codes_from_note",
    annotations={
        "title": "Extract ICD-10 and HCPCS Codes from Clinical Note",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False
    }
)
async def _extract(note_text: str, patient_token: str) -> dict:
    """Redacts PHI using Presidio, then extracts ICD-10-CM and HCPCS codes.
    
    Args:
        note_text: Raw clinical note (min 10 chars)
        patient_token: Non-PHI UUID for audit trail
    
    Returns:
        dict with redacted_note, icd10_codes, hcpcs_codes, rules_engine_version
    """
    params = ExtractCodesInput(note_text=note_text, patient_token=patient_token)
    result = await extract_codes_from_note(params)
    return result.model_dump()

if __name__ == "__main__":
    app.run()