path = r"C:\Users\DELL\medscribe-rcm-mcp\server.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

old = ("        results = PRESIDIO_ANALYZER.analyze(text=text, language=\"en\")\n"
       "        anonymized = PRESIDIO_ANONYMIZER.anonymize(text=text, analyzer_results=results)")

new = ("        analyzer, anonymizer = _get_presidio()\n"
       "        results = analyzer.analyze(text=text, language=\"en\")\n"
       "        anonymized = anonymizer.anonymize(text=text, analyzer_results=results)")

if old in content:
    content = content.replace(old, new)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print("Redact patch applied")
else:
    print("ERROR - text not found")
