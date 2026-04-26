path = r"C:\Users\DELL\medscribe-rcm-mcp\server.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

old = ('        "compliance":         ["HIPAA", "42_CFR_Part_2"],\n'
       '        "rules_engine_version": "2026-Q1",\n'
       '        "cms_ncci_release":   "2026-Q1-April",\n'
       '        "icd10_fiscal_year":  "FY2026",\n'
       '        "carc_version":       "2026-April",\n'
       '        "source_uri":         "https://www.cms.gov/medicare/coding-billing/place-of-service-codes/code-sets",')

new = ('        "compliance":         ["HIPAA", "42_CFR_Part_2"],\n'
       '        "rules_engine_version": "2026-Q1",\n'
       '        "cms_ncci_release":   "2026-Q1-April",\n'
       '        "icd10_fiscal_year":  "FY2026",\n'
       '        "carc_version":       "2026-April",\n'
       '        "source_uri":         "https://www.cms.gov/medicare/coding-billing/place-of-service-codes/code-sets",\n'
       '    }')

# Also remove the stray closing brace that broke the function
old2 = ('        "source_uri":         "https://www.cms.gov/medicare/coding-billing/place-of-service-codes/code-sets",\n'
        '    }\n'
        '    return m')
new2 = ('        "source_uri":         "https://www.cms.gov/medicare/coding-billing/place-of-service-codes/code-sets",\n'
        '    }\n'
        '    if payer:\n'
        '        m["payer"] = payer\n'
        '    if extra:\n'
        '        m.update(extra)\n'
        '    return m')

if old2 in content:
    content = content.replace(old2, new2)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print("Done")
else:
    print("ERROR - checking structure...")
    idx = content.find("rules_engine_version")
    print(content[idx-50:idx+300])
