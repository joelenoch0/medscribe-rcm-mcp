from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

# Initialize Presidio engines
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

def redact_phi(text: str) -> str:
    """Redact PHI from a note using Presidio."""
    results = analyzer.analyze(text=text, entities=["PERSON", "DATE_TIME", "SSN"], language="en")
    redacted = anonymizer.anonymize(text=text, analyzer_results=results)
    return redacted.text

# Test
if __name__ == "__main__":
    note = "Patient John Doe, born on 01/01/1980, has SSN 123-45-6789."
    print("Original:", note)
    print("Redacted:", redact_phi(note))