path = r"C:\Users\DELL\medscribe-rcm-mcp\server.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()
old = '        "compliance": ["HIPAA", "42_CFR_Part_2"],'
new = ('        "compliance":         ["HIPAA", "42_CFR_Part_2"],\n'
       '        "rules_engine_version": "2026-Q1",\n'
       '        "cms_ncci_release":   "2026-Q1-April",\n'
       '        "icd10_fiscal_year":  "FY2026",\n'
       '        "carc_version":       "2026-April",\n'
       '        "source_uri":         "https://www.cms.gov/medicare/coding-billing/place-of-service-codes/code-sets",')
if old in content:
    with open(path, "w", encoding="utf-8") as f:
        f.write(content.replace(old, new))
    print("Done")
else:
    print("ERROR - text not found")
