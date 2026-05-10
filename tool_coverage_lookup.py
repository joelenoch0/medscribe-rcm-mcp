"""
tool_coverage_lookup.py
=======================
Tool 5: lookup_coverage_policy
Looks up the applicable NCD and LCD for a CPT code + payer + state.

Pipeline:
  1. Map state → MAC contractor name
  2. Check Supabase cache (fetched within 7 days)
  3. If stale or missing → hit CMS MCD API → cache in Supabase → return
  4. Return policy_id, title, coverage criteria, doc checklist

No PHI involved. RLS: anon read, service role write.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import httpx

log = logging.getLogger("medscribe_rcm")

# ─────────────────────────────────────────────────────────────
# STATE → MAC CONTRACTOR MAPPING
# Source: CMS Medicare Administrative Contractors directory
# ─────────────────────────────────────────────────────────────
STATE_TO_MAC: Dict[str, str] = {
    # Jurisdiction E — Novitas Solutions
    "DC": "Novitas Solutions", "DE": "Novitas Solutions", "MD": "Novitas Solutions",
    "NJ": "Novitas Solutions", "PA": "Novitas Solutions",
    # Jurisdiction H — Novitas Solutions
    "AR": "Novitas Solutions", "CO": "Novitas Solutions", "LA": "Novitas Solutions",
    "MS": "Novitas Solutions", "NM": "Novitas Solutions", "OK": "Novitas Solutions",
    "TX": "Novitas Solutions",
    # Jurisdiction J6 — CGS Administrators
    "KY": "CGS Administrators", "OH": "CGS Administrators",
    # Jurisdiction J15 — CGS Administrators
    "TN": "CGS Administrators", "IN": "CGS Administrators",  # partial
    # Jurisdiction 5 — Wisconsin Physicians Service (WPS)
    "IA": "WPS Government Health Administrators", "KS": "WPS Government Health Administrators",
    "MO": "WPS Government Health Administrators", "NE": "WPS Government Health Administrators",
    # Jurisdiction 8 — WPS
    "IL": "WPS Government Health Administrators", "MI": "WPS Government Health Administrators",
    "MN": "WPS Government Health Administrators", "WI": "WPS Government Health Administrators",
    # Jurisdiction F — Palmetto GBA
    "SC": "Palmetto GBA", "NC": "Palmetto GBA", "VA": "Palmetto GBA",
    "WV": "Palmetto GBA",
    # Jurisdiction J — Palmetto GBA
    "AL": "Palmetto GBA", "GA": "Palmetto GBA", "TN": "Palmetto GBA",
    # Jurisdiction L — Palmetto GBA (Part A only; use for general mapping)
    # Jurisdiction M — First Coast Service Options
    "FL": "First Coast Service Options", "PR": "First Coast Service Options",
    "VI": "First Coast Service Options",
    # Jurisdiction N — First Coast Service Options
    "ME": "First Coast Service Options", "NH": "First Coast Service Options",
    "VT": "First Coast Service Options", "MA": "First Coast Service Options",
    "RI": "First Coast Service Options", "CT": "First Coast Service Options",
    "NY": "First Coast Service Options",
    # Jurisdiction 1 — CGS Administrators (Part A MAC)
    # Jurisdiction 2/3 — National Government Services (NGS)
    "AK": "Noridian Healthcare Solutions", "AZ": "Noridian Healthcare Solutions",
    "CA": "Noridian Healthcare Solutions", "HI": "Noridian Healthcare Solutions",
    "ID": "Noridian Healthcare Solutions", "MT": "Noridian Healthcare Solutions",
    "ND": "Noridian Healthcare Solutions", "NV": "Noridian Healthcare Solutions",
    "OR": "Noridian Healthcare Solutions", "SD": "Noridian Healthcare Solutions",
    "UT": "Noridian Healthcare Solutions", "WA": "Noridian Healthcare Solutions",
    "WY": "Noridian Healthcare Solutions",
    # Jurisdiction K — NGS
    "CT": "National Government Services",
    # India / non-US fallback
    "IN": "Palmetto GBA",  # Indiana
}

# ─────────────────────────────────────────────────────────────
# CMS MCD (Medicare Coverage Database) API
# Public REST API — no key required
# ─────────────────────────────────────────────────────────────
CMS_MCD_BASE = "https://www.cms.gov/medicare-coverage-database/api"
CACHE_TTL_DAYS = 7


async def _fetch_cms_policy(keyword: str, policy_type: str) -> List[Dict[str, Any]]:
    """
    Hit CMS MCD API for NCD or LCD by keyword.
    Returns a list of raw policy dicts.
    """
    endpoint = f"{CMS_MCD_BASE}/{'ncd' if policy_type == 'NCD' else 'lcd'}"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(endpoint, params={"keyword": keyword, "fmt": "json"})
            resp.raise_for_status()
            data = resp.json()
            # CMS API returns different shapes; normalise to list
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return data.get("items", data.get("results", [data]))
    except Exception as exc:
        log.warning("CMS MCD API fetch failed (%s %s): %s", policy_type, keyword, exc)
    return []


def _cache_policy(supabase_client, record: Dict[str, Any]) -> None:
    """Upsert a policy record into the coverage_policy Supabase table."""
    if not supabase_client:
        return
    try:
        supabase_client.table("coverage_policy").upsert(
            record,
            on_conflict="policy_id,mac_name",
        ).execute()
    except Exception as exc:
        log.warning("coverage_policy cache write failed (non-fatal): %s", exc)


def _get_cached_policy(
    supabase_client, cpt_code: str, mac_name: str
) -> Optional[List[Dict[str, Any]]]:
    """
    Return cached rows for this CPT + MAC if fetched within TTL.
    Returns None if cache is stale or empty.
    """
    if not supabase_client:
        return None
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=CACHE_TTL_DAYS)).isoformat()
        resp = (
            supabase_client.table("coverage_policy")
            .select("*")
            .contains("cpt_codes", [cpt_code])
            .gte("fetched_at", cutoff)
            .execute()
        )
        rows = resp.data or []
        # Filter by MAC (NCD rows have mac_name=None, LCD rows have MAC)
        return [r for r in rows if r.get("mac_name") in (mac_name, None)] or None
    except Exception as exc:
        log.warning("coverage_policy cache read failed: %s", exc)
        return None


# ─────────────────────────────────────────────────────────────
# KNOWN POLICY SEED  (fallback when CMS API is unavailable)
# Covers the most common HBOT / wound care / RCM scenarios.
# ─────────────────────────────────────────────────────────────
KNOWN_POLICIES: Dict[str, Dict[str, Any]] = {
    "NCD-20.29": {
        "policy_type": "NCD",
        "policy_id": "NCD-20.29",
        "cpt_codes": ["99183", "99185", "99186"],
        "mac_name": None,   # national — no MAC
        "states": [],
        "title": "Hyperbaric Oxygen Therapy (NCD 20.29)",
        "coverage_summary": (
            "Medicare covers HBOT for 14 approved conditions including diabetic "
            "lower extremity wounds (Wagner Grade III+) with 30-day failure of "
            "standard wound care."
        ),
        "doc_checklist": [
            "Confirmed Wagner Grade III or higher with wound measurement",
            "30-day wound care log showing <50% area reduction",
            "Type 1 or Type 2 diabetes diagnosis confirmed",
            "Osteomyelitis confirmed via MRI, bone biopsy, or X-ray",
            "Attending physician order for HBOT with clinical justification",
            "Optimization of nutritional status documented",
            "Debridement of necrotic tissue documented",
            "Glycemic control optimization documented",
        ],
        "effective_date": "1986-01-01",
    },
    "LCD-L33761": {
        "policy_type": "LCD",
        "policy_id": "LCD-L33761",
        "cpt_codes": ["99183"],
        "mac_name": None,   # multi-MAC LCD — apply to all
        "states": [],
        "title": "Hyperbaric Oxygen Therapy (LCD L33761)",
        "coverage_summary": (
            "Contractor-level LCD supplementing NCD 20.29. Specifies documentation "
            "requirements, session frequency limits (30 sessions standard; 31-40 "
            "require re-documentation), and coding guidance for HBOT billing."
        ),
        "doc_checklist": [
            "All NCD 20.29 documentation criteria met",
            "Sessions 1-30: standard documentation per treating physician",
            "Sessions 31-40: renewed medical necessity documentation required",
            "Sessions beyond 40: individual consideration only",
            "ICD-10 code must directly link to covered HBOT indication",
            "Place of Service 22 (hospital outpatient) or 11/19 (wound center)",
        ],
        "effective_date": "2015-10-01",
    },
}


async def run_coverage_lookup(
    cpt_code: str,
    state: str,
    payer: str,
    supabase_client,
    meta_fn,
) -> str:
    """
    Core logic for lookup_coverage_policy tool.
    Called from server.py @mcp.tool wrapper.
    """
    meta = meta_fn("lookup_coverage_policy", payer=payer)
    state_upper = state.upper().strip()
    mac_name = STATE_TO_MAC.get(state_upper, "Unknown MAC — verify at cms.gov/medicare/macs")

    # 1 — Check Supabase cache
    cached = _get_cached_policy(supabase_client, cpt_code, mac_name)
    if cached:
        log.info("coverage_policy: cache HIT for %s / %s", cpt_code, mac_name)
        return json.dumps({
            "cpt_code": cpt_code,
            "state": state_upper,
            "mac_name": mac_name,
            "policies": cached,
            "source": "supabase_cache",
            "next_step": "Review doc_checklist before billing",
            "meta": meta,
        }, indent=2, default=str)

    # 2 — Try CMS API
    log.info("coverage_policy: cache MISS — querying CMS MCD API for %s", cpt_code)
    cms_results = await _fetch_cms_policy(cpt_code, "NCD")
    cms_results += await _fetch_cms_policy(cpt_code, "LCD")

    policies_to_return: List[Dict[str, Any]] = []

    if cms_results:
        for item in cms_results[:5]:   # cap at 5 results
            record = {
                "policy_type": "NCD" if item.get("type", "").upper() == "NCD" else "LCD",
                "policy_id": item.get("id", item.get("ncdId", item.get("lcdId", "UNKNOWN"))),
                "cpt_codes": [cpt_code],
                "mac_name": mac_name if "LCD" in str(item.get("type", "")) else None,
                "states": [state_upper],
                "title": item.get("title", item.get("name", "Untitled Policy")),
                "coverage_summary": item.get("summary", item.get("description", "")),
                "doc_checklist": [],
                "effective_date": item.get("effectiveDate"),
                "fetched_at": datetime.now(timezone.utc).isoformat(),
            }
            _cache_policy(supabase_client, record)
            policies_to_return.append(record)
    else:
        # 3 — Seed fallback: return known policies matching this CPT
        log.info("coverage_policy: CMS API unavailable — using known policy seed")
        for pid, policy in KNOWN_POLICIES.items():
            if cpt_code in policy.get("cpt_codes", []):
                record = {**policy, "fetched_at": datetime.now(timezone.utc).isoformat()}
                _cache_policy(supabase_client, record)
                policies_to_return.append(record)

    return json.dumps({
        "cpt_code": cpt_code,
        "state": state_upper,
        "mac_name": mac_name,
        "payer": payer,
        "policies": policies_to_return,
        "source": "cms_api" if cms_results else "known_policy_seed",
        "next_step": "Review doc_checklist for each policy before billing",
        "meta": meta,
    }, indent=2, default=str)
