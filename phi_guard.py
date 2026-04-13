from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

from presidio_analyzer.nlp_engine import NlpEngineProvider
_config = {"nlp_engine_name": "spacy", "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}]}
_provider = NlpEngineProvider(nlp_configuration=_config)_nlp_engine = _provider.create_engine()
_nlp_engine = _provider.create_engine()
analyzer = AnalyzerEngine(nlp_engine=_nlp_engine)
anonymizer = AnonymizerEngine()

PHI_ENTITIES = [
    "PERSON", "DATE_TIME", "US_SSN",
    "PHONE_NUMBER", "EMAIL_ADDRESS",
    "LOCATION", "IP_ADDRESS", "US_DRIVER_LICENSE"
]

def redact_phi(text: str) -> str:
    results = analyzer.analyze(text=text, entities=PHI_ENTITIES, language="en")
    redacted = anonymizer.anonymize(text=text, analyzer_results=results)
    return redacted.text