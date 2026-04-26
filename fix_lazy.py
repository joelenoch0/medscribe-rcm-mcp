path = r"C:\Users\DELL\medscribe-rcm-mcp\server.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

old = ("from presidio_analyzer.nlp_engine import NlpEngineProvider\n"
       "_NLP_CONFIG = {\"nlp_engine_name\": \"spacy\", \"models\": [{\"lang_code\": \"en\", \"model_name\": \"en_core_web_sm\"}]}\n"
       "PRESIDIO_ANALYZER  = AnalyzerEngine(nlp_engine=NlpEngineProvider(nlp_configuration=_NLP_CONFIG).create_engine())\n"
       "PRESIDIO_ANONYMIZER = AnonymizerEngine()")

new = ("from presidio_analyzer.nlp_engine import NlpEngineProvider\n"
       "_PRESIDIO_ANALYZER  = None\n"
       "_PRESIDIO_ANONYMIZER = None\n"
       "\n"
       "def _get_presidio():\n"
       "    global _PRESIDIO_ANALYZER, _PRESIDIO_ANONYMIZER\n"
       "    if _PRESIDIO_ANALYZER is None:\n"
       "        _NLP_CONFIG = {\"nlp_engine_name\": \"spacy\", \"models\": [{\"lang_code\": \"en\", \"model_name\": \"en_core_web_sm\"}]}\n"
       "        _PRESIDIO_ANALYZER  = AnalyzerEngine(nlp_engine=NlpEngineProvider(nlp_configuration=_NLP_CONFIG).create_engine())\n"
       "        _PRESIDIO_ANONYMIZER = AnonymizerEngine()\n"
       "    return _PRESIDIO_ANALYZER, _PRESIDIO_ANONYMIZER")

if old in content:
    content = content.replace(old, new)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print("Lazy load patch applied")
else:
    print("ERROR - text not found")
