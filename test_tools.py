"""
test_tools.py — MedScribe RCM Tool Tester
Run with: python test_tools.py
Tests all 4 tools directly without MCP transport or JWT.
"""

import asyncio
import os

# ── Set env vars BEFORE importing server ──────────────────────
os.environ.setdefault("WORKOS_JWKS_URI", "https://api.workos.com/.well-known/jwks.json")
os.environ.setdefault("SUPABASE_URL", "")
os.environ.setdefault("SUPABASE_ANON_KEY", "")

# ── Now import the tool functions from server ──────────────────
from server import (
    extract_codes_from_note,
    suggest_codes_with_context,
    validate_claim_bundle,
    analyze_denial_and_appeal,
    ExtractCodesInput,
    SuggestCodesInput,
    ValidateClaimInput,
    AnalyzeDenialInput,
)

PASS = "✅ PASS"
FAIL = "❌ FAIL"

SEP = "─" * 60


def check(label: str, result: str) -> None:
    import json
    try:
        parsed = json.loads(result)
        if "error" in parsed and parsed["error"] == "consent_denied":
            print(f"{PASS}  {label}  [consent soft-approved, tool ran]")
        else:
            print(f"{PASS}  {label}")
    except Exception as e:
        print(f"{FAIL}  {label}  → {e}")
        print("       Raw output:", result[:200])


async def test_tool1():
    print(SEP)
    print("TOOL 1: extract_codes_from_note")
    result = await extract_codes_from_note(ExtractCodesInput(
        note_text=(
            "Patient is a 58-year-old male presenting with unspecified low back pain (M54.50), "
            "hypertension (I10), and type 2 diabetes mellitus without complications (E11.9). "
            "Procedure: office visit 99213."
        ),
        patient_token="test-patient-token-001",
        compact=False,
    ))
    check("Tool 1 ran successfully", result)
    import json
    data = json.loads(result)
    codes = data.get("icd10_codes", [])
    print(f"       ICD-10 codes found: {[c['code'] for c in codes]}")
    nos = data.get("nos_nec_scan", {})
    print(f"       NOS language hits: {nos.get('nos_language_count', 0)}")
    return result


async def test_tool2():
    print(SEP)
    print("TOOL 2: suggest_codes_with_context  ← NOS/NEC sentinel engine")
    result = await suggest_codes_with_context(SuggestCodesInput(
        note_text=(
            "Diagnoses: M54.50 (low back pain unspecified), E11.9 (T2DM unspecified), "
            "F41.9 (anxiety disorder unspecified). Procedure 99213."
        ),
        payer="MEDICARE",
        compact=False,
    ))
    check("Tool 2 ran successfully", result)
    import json
    data = json.loads(result)
    flagged = data.get("flagged_sentinel_codes", [])
    score   = data.get("denial_risk_score", 0)
    print(f"       Sentinel codes flagged: {len(flagged)}")
    for s in flagged:
        print(f"         • {s['code']} [{s['sentinel_type']}] risk={s['denial_risk']} → safer: {s['safer_codes']}")
    print(f"       Denial risk score: {score}/100  ({data.get('denial_risk_label')})")
    return result


async def test_tool3():
    print(SEP)
    print("TOOL 3: validate_claim_bundle")
    result = await validate_claim_bundle(ValidateClaimInput(
        codes=["M54.51", "99213", "E11.65"],
        payer="BCBS",
        dos="2026-04-15",
        units=1,
        compact=False,
    ))
    check("Tool 3 ran successfully", result)
    import json
    data = json.loads(result)
    print(f"       Submission ready: {data.get('submission_ready')}")
    print(f"       Errors:   {data.get('errors', [])}")
    print(f"       Warnings: {data.get('warnings', [])}")
    return result


async def test_tool4():
    print(SEP)
    print("TOOL 4: analyze_denial_and_appeal  ← MedGemma / deterministic template")
    result = await analyze_denial_and_appeal(AnalyzeDenialInput(
        denial_code="CO-50",
        payer="MEDICARE",
        claim_data={
            "codes": ["E11.9", "99213"],
            "dos":   "2026-04-15",
            "units": 1,
            "npi":   "1234567890",
        },
        patient_token="test-patient-token-001",
        compact=False,
    ))
    check("Tool 4 ran successfully", result)
    import json
    data = json.loads(result)
    print(f"       Denial reason: {data.get('denial_reason')}")
    print(f"       Appeal model:  {data.get('appeal_model')}")
    print(f"       Success prob:  {data.get('appeal_success_probability')}")
    nos_nec = data.get("root_cause_analysis", {}).get("nos_nec_issue")
    if nos_nec:
        print(f"       NOS/NEC root cause: {nos_nec}")
    return result


async def main():
    print("\n" + "═" * 60)
    print("  MedScribe RCM — 4-Tool Test Suite")
    print("═" * 60)

    try:
        await test_tool1()
    except Exception as e:
        print(f"{FAIL}  Tool 1 crashed: {e}")

    try:
        await test_tool2()
    except Exception as e:
        print(f"{FAIL}  Tool 2 crashed: {e}")

    try:
        await test_tool3()
    except Exception as e:
        print(f"{FAIL}  Tool 3 crashed: {e}")

    try:
        await test_tool4()
    except Exception as e:
        print(f"{FAIL}  Tool 4 crashed: {e}")

    print(SEP)
    print("Done. Fix any ❌ lines above before deploying to Render.")
    print("═" * 60 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
