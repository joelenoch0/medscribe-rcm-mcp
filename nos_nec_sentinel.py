"""
nos_nec_sentinel.py — NOS/NEC Sentinel Detection
==================================================
⚠️  TRADE SECRET — see NOTICE file.

The NOS/NEC Sentinel List (22 codes: 11 NOS + 11 NEC, updated Q2-2026)
and the contextual detection + prioritisation algorithm are proprietary
components of MedScribe Professional Resources.

This module exposes one public function: `check_nos_nec(code, label) → str|None`
The underlying list and weighting logic are NOT disclosed in the open-source
distribution.  The paid-tier binary ships an obfuscated version.

Free-tier behaviour: the list is loaded from environment variable
NOS_NEC_SENTINEL_JSON (base64-encoded) or falls back to a minimal public
subset of 4 codes sufficient for MVP demonstration.
"""

from __future__ import annotations

import base64
import json
import os
from typing import Dict, Optional, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# Sentinel list loader
# ─────────────────────────────────────────────────────────────────────────────

# Free-tier public subset (4 of 22 codes — enough for open-source MVP).
# Full 22-code list + detection algorithm shipped in paid tier only.
_PUBLIC_SUBSET: Dict[str, Tuple[str, str]] = {
    # code → (warning_message, recommended_specific_code)

    # NOS entries (Not Otherwise Specified)
    "E11.9": (
        "NOS ALERT: 'Type 2 DM without complications' is non-specific. "
        "Medicare LCD L33826 and most commercial payers deny medical necessity. "
        "Recommended: E11.65 (hyperglycaemia), E11.40 (neuropathy), "
        "E11.311 (retinopathy), or E11.51 (peripheral angiopathy).",
        "E11.65",
    ),
    "F32.9": (
        "NOS ALERT: 'Major depressive disorder, single episode, unspecified' "
        "is non-specific. Use severity specifier: F32.0 (mild), F32.1 (moderate), "
        "F32.2 (severe), F32.3 (with psychotic features), or F32.4 (in partial remission).",
        "F32.1",
    ),

    # NEC entries (Not Elsewhere Classified)
    "G89.29": (
        "NEC ALERT: 'Other chronic pain' is a NEC code — it signals the coder "
        "could not find a more specific code. Payers flag this for medical "
        "necessity review. Identify and code the underlying pain generator first "
        "(e.g. M54.50 low back pain, M79.621 pain in right upper arm).",
        "M54.50",
    ),
    "R68.89": (
        "NEC ALERT: 'Other specified general symptoms and signs' is a residual NEC. "
        "Document and code the specific symptom. Leaving this as primary "
        "will trigger payer edit review.",
        "R41.3",
    ),
}


def _load_sentinel_list() -> Dict[str, Tuple[str, str]]:
    """
    Load sentinel list.
    Priority: env-var (paid tier, base64 JSON) → public subset (free tier).
    """
    encoded = os.environ.get("NOS_NEC_SENTINEL_JSON", "")
    if encoded:
        try:
            decoded = base64.b64decode(encoded).decode("utf-8")
            data: Dict[str, list] = json.loads(decoded)
            # Expected format: {"CODE": ["warning", "recommended_code"], ...}
            return {k: (v[0], v[1]) for k, v in data.items()}
        except Exception:
            pass  # Fall through to public subset
    return _PUBLIC_SUBSET


# Module-level cache
_SENTINEL: Dict[str, Tuple[str, str]] = _load_sentinel_list()


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def check_nos_nec(code: str, label: str = "") -> Optional[str]:
    """
    Check whether a code is on the NOS/NEC Sentinel List.

    Parameters
    ----------
    code  : ICD-10-CM or HCPCS code string (e.g. 'E11.9').
    label : Human-readable label (used for secondary fuzzy matching
            in the paid-tier algorithm — ignored in free tier).

    Returns
    -------
    str   : Warning string with recommended specific replacement code.
    None  : Code is not on the sentinel list.

    ⚠️  Proprietary: contextual detection, priority scoring, and the full
    22-code list are NOT exposed here.  The paid-tier module performs
    additional NLP-based detection against the note context.
    """
    hit = _SENTINEL.get(code.strip().upper())
    if hit:
        warning, _ = hit
        return warning
    return None


def get_recommended_replacement(code: str) -> Optional[str]:
    """Return the recommended specific replacement code for a sentinel hit."""
    hit = _SENTINEL.get(code.strip().upper())
    if hit:
        _, recommended = hit
        return recommended
    return None


def sentinel_count() -> int:
    """Return the number of codes in the currently loaded sentinel list."""
    return len(_SENTINEL)
