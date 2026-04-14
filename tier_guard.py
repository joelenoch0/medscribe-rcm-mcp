"""
tier_guard.py — MedScribe RCM tier-based feature gating
=========================================================
Free tier    : ICD-10-CM + HCPCS Level II only. CPT codes blocked.
               20 calls/day (enforced by rate_limiter.py).
Paid tier    : Full CPT access + unlimited calls. $29/month via Gumroad.
Enterprise   : White-label config + unlimited + CPT. $499/month.

CPT codes are property of the American Medical Association (AMA).
Distributing CPT in the open-source layer would violate AMA licensing.
CPT is therefore ONLY available to paid/enterprise tier users.

This file never stores PHI. It works on code strings only.
"""

import logging
import re
from typing import List, Optional

logger = logging.getLogger("medscribe.tier_guard")

# ---------------------------------------------------------------------------
# CPT code pattern — 5 digits, optionally followed by F/T/U modifier suffix
# HCPCS Level II pattern — letter A-V followed by 4 digits
# ICD-10-CM pattern — letter followed by digits and optional decimal
# ---------------------------------------------------------------------------

_CPT_PATTERN    = re.compile(r"^\d{5}[FTU]?$")
_HCPCS_PATTERN  = re.compile(r"^[A-VXYZ]\d{4}$", re.IGNORECASE)
_ICD10_PATTERN  = re.compile(r"^[A-Z]\d{2}\.?\w*$", re.IGNORECASE)

# CPT code ranges that are NOT covered by AMA licensing concerns:
# These are HCPCS Level II codes that start with letters — always free.
# True CPT codes are purely numeric 5-digit strings.

# Specific HCPCS Level II prefixes (always allowed on free tier)
_FREE_HCPCS_PREFIXES = tuple("ABCDEGHIJKLMNPQRSTV")


def is_cpt_code(code: str) -> bool:
    """
    Returns True if the code is a CPT code (AMA-licensed, paid tier only).
    CPT codes are purely 5-digit numeric strings (e.g. 99213, 36415, 27447).
    HCPCS Level II codes start with a letter — those are always free.
    """
    code = code.strip().upper()
    if _CPT_PATTERN.match(code):
        return True
    return False


def is_hcpcs_code(code: str) -> bool:
    """Returns True if the code is a HCPCS Level II code (free tier allowed)."""
    code = code.strip().upper()
    return bool(_HCPCS_PATTERN.match(code))


def is_icd10_code(code: str) -> bool:
    """Returns True if the code looks like an ICD-10-CM code (free tier allowed)."""
    code = code.strip().upper()
    return bool(_ICD10_PATTERN.match(code)) and not is_cpt_code(code)


def classify_code(code: str) -> str:
    """Returns 'cpt', 'hcpcs', 'icd10', or 'unknown'."""
    code = code.strip().upper()
    if is_cpt_code(code):
        return "cpt"
    if is_hcpcs_code(code):
        return "hcpcs"
    if is_icd10_code(code):
        return "icd10"
    return "unknown"


# ---------------------------------------------------------------------------
# Main guard functions
# ---------------------------------------------------------------------------

class TierAccessDenied(Exception):
    """Raised when a free-tier user requests a paid-only feature."""
    pass


def enforce_code_access(codes: List[str], plan_tier: str) -> List[str]:
    """
    Filter a list of codes based on the user's plan tier.

    Free tier  : Returns only ICD-10-CM and HCPCS codes. CPT codes removed.
    Paid tier  : Returns all codes unchanged.
    Enterprise : Returns all codes unchanged.

    Parameters
    ----------
    codes     : List of code strings to filter.
    plan_tier : 'free', 'paid', or 'enterprise'

    Returns
    -------
    Filtered list of codes allowed for the tier.
    Also logs how many CPT codes were stripped on free tier.
    """
    if plan_tier in ("paid", "enterprise"):
        return codes

    # Free tier — strip CPT codes
    allowed = []
    stripped = []
    for code in codes:
        if is_cpt_code(code):
            stripped.append(code)
        else:
            allowed.append(code)

    if stripped:
        logger.info(
            "tier_guard: stripped %d CPT code(s) for free tier: %s",
            len(stripped), stripped
        )

    return allowed


def check_cpt_access(plan_tier: str) -> None:
    """
    Raise TierAccessDenied if the user cannot access CPT codes.
    Call this before any operation that would return or process CPT codes.
    """
    if plan_tier not in ("paid", "enterprise"):
        raise TierAccessDenied(
            "CPT codes are available on the paid tier only ($29/month). "
            "Free tier includes ICD-10-CM and HCPCS Level II. "
            "Upgrade at medscribepro.in."
        )


def get_cpt_placeholder_response(codes: List[str]) -> dict:
    """
    Return a structured placeholder for CPT codes on the free tier.
    Tells the user CPT was detected but gated, with an upgrade prompt.
    """
    cpt_codes = [c for c in codes if is_cpt_code(c)]
    return {
        "cpt_gated":    True,
        "cpt_detected": len(cpt_codes),
        "message": (
            f"{len(cpt_codes)} CPT code(s) detected but not returned on free tier. "
            "CPT codes are AMA-licensed and available on paid tier ($29/month). "
            "Upgrade at medscribepro.in."
        ),
        "upgrade_url": "https://medscribepro.in",
    }


def apply_tier_to_response(response_dict: dict, plan_tier: str) -> dict:
    """
    Post-process a tool response dict to enforce tier restrictions.

    - Strips CPT codes from 'codes' lists on free tier.
    - Adds a 'tier_info' block to every response.
    - Adds upgrade prompt if CPT codes were present but stripped.

    Use this as the final step before returning any tool response.
    """
    tier_info = {
        "plan_tier":   plan_tier,
        "cpt_access":  plan_tier in ("paid", "enterprise"),
        "upgrade_url": "https://medscribepro.in" if plan_tier == "free" else None,
    }

    cpt_gated_count = 0

    # Filter codes arrays anywhere in the response
    if "codes" in response_dict and isinstance(response_dict["codes"], list):
        original_count = len(response_dict["codes"])
        if plan_tier == "free":
            response_dict["codes"] = [
                c for c in response_dict["codes"]
                if not (isinstance(c, dict) and is_cpt_code(c.get("code", "")))
                and not (isinstance(c, str) and is_cpt_code(c))
            ]
            cpt_gated_count = original_count - len(response_dict["codes"])

    if "suggestions" in response_dict and isinstance(response_dict["suggestions"], list):
        original_count = len(response_dict["suggestions"])
        if plan_tier == "free":
            response_dict["suggestions"] = [
                s for s in response_dict["suggestions"]
                if not (isinstance(s, dict) and is_cpt_code(s.get("code", "")))
            ]
            cpt_gated_count += original_count - len(response_dict["suggestions"])

    if cpt_gated_count > 0:
        tier_info["cpt_gated_count"] = cpt_gated_count
        tier_info["cpt_upgrade_message"] = (
            f"{cpt_gated_count} CPT code(s) hidden on free tier. "
            "Upgrade at medscribepro.in for full CPT access."
        )

    response_dict["tier_info"] = tier_info
    return response_dict


# ---------------------------------------------------------------------------
# White-label enterprise config
# ---------------------------------------------------------------------------

def get_enterprise_config(api_key: str) -> Optional[dict]:
    """
    Returns white-label branding config for enterprise tier.
    Config is loaded from environment variable ENTERPRISE_CONFIG_{key_prefix}.
    Returns None for non-enterprise keys.

    Enterprise customers receive a key prefix that maps to their branding.
    Full white-label config is a paid feature — $499/month.
    """
    plan_tier = _get_tier_from_env_or_default(api_key)
    if plan_tier != "enterprise":
        return None

    # In production: load from Supabase enterprise_config table
    # For now: return a minimal config structure
    return {
        "branding":     os.environ.get("ENTERPRISE_BRAND_NAME", "MedScribe RCM"),
        "logo_url":     os.environ.get("ENTERPRISE_LOGO_URL", None),
        "support_email": os.environ.get("ENTERPRISE_SUPPORT_EMAIL", "contact@medscribepro.in"),
        "custom_domain": os.environ.get("ENTERPRISE_DOMAIN", "medscribepro.in"),
    }


def _get_tier_from_env_or_default(api_key: str) -> str:
    """Fallback tier lookup without Supabase — used during startup/testing."""
    import os
    # Allow override via env for testing
    override = os.environ.get("MEDSCRIBE_PLAN_TIER_OVERRIDE", "")
    if override in ("free", "paid", "enterprise"):
        return override
    return "free"


# Lazy import to avoid circular dependency with rate_limiter
import os
