"""
tool_charge_capture.py
======================
Tool 6: get_charge_capture
Returns the 2026 Medicare Physician Fee Schedule allowed amount for a CPT
code given state and place of service.

Pipeline:
  1. Check Supabase fee_schedule_cache (national rate, TTL = 1 year)
  2. If missing → attempt CMS Data API lookup → cache result
  3. If payment_received provided → flag underpayment
  4. Return allowed amounts, underpayment flag, and action

No PHI involved. All amounts are public CMS data.
Data source: CMS Medicare Physician Fee Schedule 2026
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx

log = logging.getLogger("medscribe_rcm")

# CMS Data API — Medicare Physician Fee Schedule dataset
# Dataset ID for PFS: 9d9e5924-e0e1-432d-800a-3e4d3a1d8c54
CMS_PFS_API = (
    "https://data.cms.gov/data-api/v1/dataset"
    "/9d9e5924-e0e1-432d-800a-3e4d3a1d8c54/data"
)


async def _fetch_cms_pfs(cpt_code: str) -> Optional[Dict[str, Any]]:
    """
    Query CMS Data API for PFS allowed amounts by HCPCS code.
    Returns first matching row or None.
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                CMS_PFS_API,
                params={"filter[HCPCS_CD]": cpt_code, "size": 1},
            )
            resp.raise_for_status()
            rows = resp.json()
            if rows and isinstance(rows, list):
                return rows[0]
    except Exception as exc:
        log.warning("CMS PFS API fetch failed for %s: %s", cpt_code, exc)
    return None


def _read_cache(supabase_client, cpt_code: str, modifier: str) -> Optional[Dict]:
    """Return cached fee schedule row if present (no TTL — PFS is annual)."""
    if not supabase_client:
        return None
    try:
        resp = (
            supabase_client.table("fee_schedule_cache")
            .select("*")
            .eq("cpt_code", cpt_code)
            .eq("modifier", modifier)
            .eq("locality_code", "0000")   # national rate
            .limit(1)
            .execute()
        )
        rows = resp.data or []
        return rows[0] if rows else None
    except Exception as exc:
        log.warning("fee_schedule_cache read failed: %s", exc)
        return None


def _write_cache(supabase_client, record: Dict) -> None:
    """Upsert a fee schedule row into Supabase."""
    if not supabase_client:
        return
    try:
        supabase_client.table("fee_schedule_cache").upsert(
            record,
            on_conflict="cpt_code,modifier,locality_code",
        ).execute()
    except Exception as exc:
        log.warning("fee_schedule_cache write failed (non-fatal): %s", exc)


def _underpayment_flag(
    allowed: float,
    received: Optional[float],
) -> Dict[str, Any]:
    """Return underpayment analysis if payment_received is provided."""
    if received is None:
        return {"checked": False}
    diff = round(allowed - received, 2)
    pct  = round((diff / allowed) * 100, 1) if allowed else 0
    return {
        "checked":          True,
        "allowed_amount":   allowed,
        "received_amount":  received,
        "variance":         diff,
        "variance_pct":     pct,
        "underpayment":     diff > 0,
        "action": (
            "Flag for underpayment review — post-payment audit recommended"
            if diff > 0
            else "Payment at or above Medicare allowed — no action needed"
        ),
    }


async def run_charge_capture(
    cpt_code: str,
    state: str,
    facility: bool,
    modifier: str,
    payment_received: Optional[float],
    supabase_client,
    meta_fn,
) -> str:
    """
    Core logic for get_charge_capture tool. Called from server.py wrapper.
    """
    meta    = meta_fn("get_charge_capture")
    mod     = modifier.strip().upper() if modifier else ""
    setting = "facility" if facility else "non_facility"

    # 1 — Supabase cache
    cached = _read_cache(supabase_client, cpt_code, mod)

    if not cached:
        # 2 — CMS Data API
        log.info("fee_schedule_cache: MISS — querying CMS PFS API for %s", cpt_code)
        cms_row = await _fetch_cms_pfs(cpt_code)
        if cms_row:
            # CMS API field names vary by dataset version; map defensively
            non_fac = float(cms_row.get("NON_FAC_PE_TOTAL", cms_row.get("non_fac_total", 0)) or 0)
            fac     = float(cms_row.get("FAC_PE_TOTAL",     cms_row.get("fac_total", 0)) or 0)
            record  = {
                "cpt_code":            cpt_code,
                "modifier":            mod,
                "locality_code":       "0000",
                "state":               state.upper(),
                "non_facility_amount": non_fac,
                "facility_amount":     fac,
                "pfs_year":            2026,
                "fetched_at":          datetime.now(timezone.utc).isoformat(),
            }
            _write_cache(supabase_client, record)
            cached = record

    if not cached:
        return json.dumps({
            "cpt_code":  cpt_code,
            "found":     False,
            "message":   f"CPT {cpt_code} not found in fee schedule cache or CMS API. "
                         f"Verify code is valid and billable under Medicare PFS.",
            "meta":      meta,
        }, indent=2)

    non_fac_amt = float(cached.get("non_facility_amount") or 0)
    fac_amt     = float(cached.get("facility_amount") or 0)
    allowed     = fac_amt if facility else non_fac_amt

    return json.dumps({
        "cpt_code":             cpt_code,
        "modifier":             mod or None,
        "state":                state.upper(),
        "place_of_service":     setting,
        "found":                True,
        "pfs_year":             cached.get("pfs_year", 2026),
        "source":               "supabase_cache" if cached else "cms_api",
        "non_facility_allowed": non_fac_amt,
        "facility_allowed":     fac_amt,
        "applicable_allowed":   allowed,
        "underpayment_analysis": _underpayment_flag(allowed, payment_received),
        "note": (
            "National rate (locality 0000). Actual payment may vary by "
            "geographic adjustment factor (GPCI). Confirm with MAC remittance."
        ),
        "meta": meta,
    }, indent=2)
