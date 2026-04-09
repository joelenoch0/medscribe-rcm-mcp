from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

analyzer = AnalyzerEngine()
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