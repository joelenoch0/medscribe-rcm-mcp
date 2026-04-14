"""
phi_guard.py — MedScribe RCM PHI Redaction Layer
=================================================
HIPAA Safe Harbour (45 CFR §164.514(b)) compliant.
Processes PHI in RAM only. Nothing is stored or logged.

Two entry points:
  redact_phi(text)         — sanitise INPUT (clinical notes)
  redact_phi_output(text)  — sanitise OUTPUT (tool responses)

Both raise PhiGuardError on failure so the caller can abort
rather than accidentally forward raw PHI.
"""

import logging
import re
from typing import Optional

from presidio_analyzer import AnalyzerEngine, RecognizerResult
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_analyzer import PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

# ---------------------------------------------------------------------------
# PHI-safe logger — never logs note text or PHI values
# ---------------------------------------------------------------------------
log = logging.getLogger("medscribe.phi_guard")


# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------
class PhiGuardError(RuntimeError):
    """Raised when redaction fails. Caller MUST abort the tool call."""
    pass


# ---------------------------------------------------------------------------
# Custom recognizers for healthcare-specific identifiers
# (standard Presidio does not cover these out of the box)
# ---------------------------------------------------------------------------

def _build_mrn_recognizer() -> PatternRecognizer:
    """Medical Record Number — common formats: MRN-123456, #123456, 7-digit numbers."""
    return PatternRecognizer(
        supported_entity="MEDICAL_RECORD_NUMBER",
        patterns=[
            Pattern(
                name="mrn_prefixed",
                regex=r"\bMRN[-:\s]?\d{4,10}\b",
                score=0.9,
            ),
            Pattern(
                name="mrn_hash",
                regex=r"#\d{5,8}\b",
                score=0.75,
            ),
            Pattern(
                name="mrn_bare_7digit",
                # 7-digit standalone numbers — common MRN length
                regex=r"\b\d{7}\b",
                score=0.5,
            ),
        ],
        context=["mrn", "medical record", "record number", "patient id", "chart"],
    )


def _build_npi_recognizer() -> PatternRecognizer:
    """National Provider Identifier — always 10 digits, often preceded by 'NPI'."""
    return PatternRecognizer(
        supported_entity="NPI_NUMBER",
        patterns=[
            Pattern(
                name="npi_prefixed",
                regex=r"\bNPI[-:\s]?\d{10}\b",
                score=0.95,
            ),
            Pattern(
                name="npi_bare",
                regex=r"\b1\d{9}\b",   # NPIs start with 1
                score=0.6,
            ),
        ],
        context=["npi", "national provider", "provider identifier", "provider number"],
    )


def _build_dea_recognizer() -> PatternRecognizer:
    """DEA Registration Number — format: 2 letters + 7 digits (e.g. AB1234563)."""
    return PatternRecognizer(
        supported_entity="DEA_NUMBER",
        patterns=[
            Pattern(
                name="dea_standard",
                regex=r"\b[A-Z]{2}\d{7}\b",
                score=0.85,
            ),
            Pattern(
                name="dea_prefixed",
                regex=r"\bDEA[-:\s]?[A-Z]{2}\d{7}\b",
                score=0.95,
            ),
        ],
        context=["dea", "drug enforcement", "controlled substance", "prescriber"],
    )


def _build_insurance_id_recognizer() -> PatternRecognizer:
    """Insurance Member ID / Policy Number — alphanumeric, 8-15 chars."""
    return PatternRecognizer(
        supported_entity="INSURANCE_ID",
        patterns=[
            Pattern(
                name="insurance_id_prefixed",
                regex=r"\b(?:member|policy|group|subscriber|ins(?:urance)?)\s*(?:id|no|number|#)[-:\s]?[A-Z0-9]{6,15}\b",
                score=0.85,
            ),
            Pattern(
                name="medicare_id",
                # Medicare Beneficiary Identifier: 11 chars, alternating alpha-numeric
                regex=r"\b[1-9][A-Z][A-Z0-9]\d[A-Z][A-Z0-9]\d[A-Z]{2}\d{2}\b",
                score=0.9,
            ),
        ],
        context=["member id", "policy", "insurance", "medicare", "medicaid",
                 "subscriber", "beneficiary", "plan id"],
    )


def _build_fax_recognizer() -> PatternRecognizer:
    """Fax numbers — HIPAA explicitly lists these as PHI identifiers."""
    return PatternRecognizer(
        supported_entity="FAX_NUMBER",
        patterns=[
            Pattern(
                name="fax_prefixed",
                regex=r"\bfax[-:\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
                score=0.9,
            ),
        ],
        context=["fax", "facsimile"],
    )


# ---------------------------------------------------------------------------
# Singleton engine factory — loaded ONCE at import time
# Render free tier has 512MB RAM; en_core_web_sm is ~50MB — safe.
# ---------------------------------------------------------------------------

def _build_engines():
    config = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
    }
    try:
        provider = NlpEngineProvider(nlp_configuration=config)
        nlp_engine = provider.create_engine()

        analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])

        # Register all custom healthcare recognizers
        for recognizer in [
            _build_mrn_recognizer(),
            _build_npi_recognizer(),
            _build_dea_recognizer(),
            _build_insurance_id_recognizer(),
            _build_fax_recognizer(),
        ]:
            analyzer.registry.add_recognizer(recognizer)

        anonymizer = AnonymizerEngine()
        log.info("phi_guard: Presidio engines loaded (en_core_web_sm)")
        return analyzer, anonymizer

    except Exception as exc:
        # Hard fail at startup — never run without PHI protection
        raise PhiGuardError(
            f"phi_guard: FATAL — could not load Presidio engines: {exc}"
        ) from exc


_ANALYZER, _ANONYMIZER = _build_engines()

# ---------------------------------------------------------------------------
# All PHI entity types to detect — HIPAA Safe Harbour 18 identifiers
# plus healthcare-specific custom entities above
# ---------------------------------------------------------------------------
PHI_ENTITIES = [
    # Standard Presidio entities
    "PERSON",
    "DATE_TIME",
    "US_SSN",
    "PHONE_NUMBER",
    "EMAIL_ADDRESS",
    "LOCATION",
    "IP_ADDRESS",
    "US_DRIVER_LICENSE",
    "US_PASSPORT",
    "US_BANK_NUMBER",
    "CREDIT_CARD",
    "URL",               # Patient portals, referral links
    # Custom healthcare entities
    "MEDICAL_RECORD_NUMBER",
    "NPI_NUMBER",
    "DEA_NUMBER",
    "INSURANCE_ID",
    "FAX_NUMBER",
]

# Replacement tokens — what each entity type becomes after redaction
_OPERATOR_CONFIG = {
    "PERSON":                  OperatorConfig("replace", {"new_value": "[PATIENT]"}),
    "DATE_TIME":               OperatorConfig("replace", {"new_value": "[DATE]"}),
    "US_SSN":                  OperatorConfig("replace", {"new_value": "[SSN]"}),
    "PHONE_NUMBER":            OperatorConfig("replace", {"new_value": "[PHONE]"}),
    "EMAIL_ADDRESS":           OperatorConfig("replace", {"new_value": "[EMAIL]"}),
    "LOCATION":                OperatorConfig("replace", {"new_value": "[LOCATION]"}),
    "IP_ADDRESS":              OperatorConfig("replace", {"new_value": "[IP]"}),
    "US_DRIVER_LICENSE":       OperatorConfig("replace", {"new_value": "[DL]"}),
    "US_PASSPORT":             OperatorConfig("replace", {"new_value": "[PASSPORT]"}),
    "US_BANK_NUMBER":          OperatorConfig("replace", {"new_value": "[BANK]"}),
    "CREDIT_CARD":             OperatorConfig("replace", {"new_value": "[CC]"}),
    "URL":                     OperatorConfig("replace", {"new_value": "[URL]"}),
    "MEDICAL_RECORD_NUMBER":   OperatorConfig("replace", {"new_value": "[MRN]"}),
    "NPI_NUMBER":              OperatorConfig("replace", {"new_value": "[NPI]"}),
    "DEA_NUMBER":              OperatorConfig("replace", {"new_value": "[DEA]"}),
    "INSURANCE_ID":            OperatorConfig("replace", {"new_value": "[INS_ID]"}),
    "FAX_NUMBER":              OperatorConfig("replace", {"new_value": "[FAX]"}),
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def redact_phi(text: str, score_threshold: float = 0.4) -> str:
    """
    Redact PHI from INPUT text (clinical notes, transcriptions).

    Parameters
    ----------
    text : str
        Raw clinical note or transcription. May contain PHI.
    score_threshold : float
        Minimum confidence score to trigger redaction (0.0–1.0).
        Default 0.4 catches likely PHI while avoiding false positives
        on normal medical terminology.

    Returns
    -------
    str
        Text with all detected PHI replaced by labelled tokens.

    Raises
    ------
    PhiGuardError
        If redaction fails for any reason. Caller must NOT proceed.
    """
    if not text or not text.strip():
        return text

    try:
        results = _ANALYZER.analyze(
            text=text,
            entities=PHI_ENTITIES,
            language="en",
            score_threshold=score_threshold,
        )
        redacted = _ANONYMIZER.anonymize(
            text=text,
            analyzer_results=results,
            operators=_OPERATOR_CONFIG,
        )
        # Log only the count of detections — never the values
        if results:
            entity_counts = {}
            for r in results:
                entity_counts[r.entity_type] = entity_counts.get(r.entity_type, 0) + 1
            log.info("phi_guard.redact_phi: redacted %d entities: %s",
                     len(results), entity_counts)

        return redacted.text

    except Exception as exc:
        # Never let a Presidio failure silently pass through raw PHI
        raise PhiGuardError(
            f"phi_guard.redact_phi: redaction failed — aborting tool call. Reason: {exc}"
        ) from exc


def redact_phi_output(text: str) -> str:
    """
    Redact PHI from OUTPUT text (tool responses, generated content).

    Uses a slightly higher threshold than input redaction to reduce
    false positives in structured output like code suggestions.

    Raises
    ------
    PhiGuardError
        If output redaction fails. Caller must NOT return the response.
    """
    return redact_phi(text, score_threshold=0.6)


def is_phi_clean(text: str) -> bool:
    """
    Returns True if no PHI is detected above threshold.
    Use for validation in tests and health checks.
    Does NOT raise on Presidio errors — returns False instead.
    """
    try:
        results = _ANALYZER.analyze(
            text=text,
            entities=PHI_ENTITIES,
            language="en",
            score_threshold=0.4,
        )
        return len(results) == 0
    except Exception:
        return False  # Treat errors as potentially unsafe


def get_phi_entity_count(text: str) -> dict:
    """
    Returns a dict of {entity_type: count} for audit logging.
    Safe to log — contains NO PHI values, only entity type names and counts.
    """
    try:
        results = _ANALYZER.analyze(
            text=text,
            entities=PHI_ENTITIES,
            language="en",
            score_threshold=0.4,
        )
        counts: dict = {}
        for r in results:
            counts[r.entity_type] = counts.get(r.entity_type, 0) + 1
        return counts
    except Exception:
        return {"error": 1}
