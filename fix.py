import json, os

rules = {
  "default": {"deny_unspecified": True, "require_laterality": ["M54", "S", "G89"], "max_units": {"99213": 1, "99214": 1, "99215": 1}, "ncci_blocked_pairs": [["99213", "99211"], ["36415", "99213"]], "requires_modifier_25": ["99213", "99214", "99215"], "requires_modifier_59": ["97110", "97530"], "sud_sensitive": False},
  "BCBS": {"deny_unspecified": True, "require_laterality": ["M54", "S", "G89", "H"], "max_units": {"99213": 1, "99214": 1, "97110": 4}, "ncci_blocked_pairs": [["99213", "99211"], ["36415", "99213"]], "requires_modifier_25": ["99213", "99214", "99215"], "requires_modifier_59": ["97110", "97530"], "sud_sensitive": True, "prior_auth_required": ["L8699", "J0702", "J2270"]},
  "MEDICARE": {"deny_unspecified": True, "require_laterality": ["M54", "S", "G89", "H", "M"], "max_units": {"99213": 1, "99214": 1, "97110": 3}, "ncci_blocked_pairs": [["99213", "99211"], ["G0008", "90686"]], "requires_modifier_25": ["99213", "99214", "99215"], "requires_modifier_59": ["97110", "97530"], "sud_sensitive": False, "prior_auth_required": []},
  "MEDICAID": {"deny_unspecified": True, "require_laterality": ["M54", "S"], "max_units": {"99213": 1, "97110": 2}, "ncci_blocked_pairs": [["99213", "99211"]], "requires_modifier_25": ["99213", "99214", "99215"], "requires_modifier_59": ["97110", "97530"], "sud_sensitive": True},
  "AETNA": {"deny_unspecified": True, "require_laterality": ["M54", "S", "G89"], "max_units": {"99213": 1, "99214": 1, "97110": 4}, "ncci_blocked_pairs": [["99213", "99211"]], "requires_modifier_25": ["99213", "99214", "99215"], "requires_modifier_59": ["97110", "97530"], "sud_sensitive": False},
  "UNITED": {"deny_unspecified": True, "require_laterality": ["M54", "S", "G89", "H"], "max_units": {"99213": 1, "99214": 1, "97110": 3}, "ncci_blocked_pairs": [["99213", "99211"], ["97110", "97530"]], "requires_modifier_25": ["99213", "99214", "99215"], "requires_modifier_59": ["97110", "97530"], "sud_sensitive": False, "prior_auth_required": ["J0702", "J2270"]}
}

os.makedirs("data", exist_ok=True)
with open("data/payer_rules.json", "w", encoding="utf-8") as f:
    json.dump(rules, f, indent=2)
print("payer_rules.json written OK")