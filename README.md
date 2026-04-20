# MedScribe RCM-MCP
**The only open-source FastMCP server that chains the complete 
Healthcare RCM pipeline: Transcription → Coding → Billing 
Validation → Denial Resolution.**

Maintained by [MedScribe Professional Resources](https://medscribepro.in)  
Contact: contact@medscribepro.in  
License: Apache 2.0 (see LICENSE + NOTICE)

---

## ⚠️ LEGAL & COMPLIANCE NOTICE

This server processes clinical data. Before deployment:
1. You must configure OAuth 2.1 authentication (server 
   refuses to start without it — by design)
2. You must NOT store PHI in any database (process in 
   memory only)
3. If processing SUD records: patient consent under 42 CFR 
   Part 2 is legally required (already enforced by the 
   built-in ConsentMiddleware)
4. You must sign a BAA with any cloud provider before 
   storing ePHI (Supabase free tier does not cover PHI)

Running this server without authentication is a HIPAA 
violation and violates 42 CFR Part 2.

---

## What This Server Does (Value Addition)

No other open-source MCP server chains these four steps:

| Tool | What It Does | Why It Matters |
|------|-------------|----------------|
| extract_codes_from_note | Extracts ICD-10/HCPCS from clinical notes. PHI redacted via Microsoft Presidio before any processing. | No PHI leaves the note unredacted |
| suggest_codes_with_context | Suggests codes + **flags NOS codes** before they trigger medical necessity denials | Prevents the most common denial type |
| validate_claim_bundle | Runs CMS NCCI/MUE edits. Returns risk score 0-100. | Clean claim before submission |
| analyze_denial_and_appeal | Root-causes denials using CARC/RARC + CMS-0057-F. Generates 72hr/7-day appeal templates. | Recovers denied revenue |

---

## Security Architecture

- **PHI never stored** — processed in-memory only
- **OAuth 2.1 mandatory** — server fails to start without it
- **42 CFR Part 2 consent gate** — SUD data requires 
  patient consent on file before any tool runs
- **Presidio PHI redaction** — on both INPUT and OUTPUT
- **Immutable audit logs** — tool name + timestamp only
- **Metadata lineage** — every response includes 
  rules_engine_version and source_uri

---

## Free vs Paid Tier

| Feature | Free (Open Source) | Paid ($29/month) |
|---------|-------------------|-----------------|
| All 4 RCM tools | ✅ | ✅ |
| ICD-10-CM + HCPCS | ✅ | ✅ |
| CPT descriptions | Placeholder only | ✅ (AMA licensed) |
| Rate limit | 20 calls/day | Unlimited |
| NOS code trapping | ✅ | ✅ |
| NCCI/MUE scrubbing | ✅ | ✅ |
| 42 CFR Part 2 consent | ✅ | ✅ |
| Support | GitHub Issues | contact@medscribepro.in |

**Start free. Upgrade when you're generating revenue.**

---

## Trade Secrets

See NOTICE file for full declaration.

The open-source framework is Apache 2.0. The Rules Engine 
(NOS sentinel list, appeal templates, payer benchmarks) is 
a proprietary trade secret delivered only via paid API.

---

## Data Sources (All Free, Public Domain)

- ICD-10-CM: CDC.gov (public domain)
- HCPCS Level II: CMS.gov (public domain)
- NCCI Edits: CMS.gov quarterly (public domain)
- CARC/RARC Codes: CMS.gov (public domain)
- CMS-0057-F Metrics: Payer public websites (mandated)
- CPT: AMA licensed (paid tier only)

---

## Contact & Business

MedScribe Professional Resources  
Warangal, Telangana, India  
contact@medscribepro.in  
GitHub: github.com/joelenoch0/medscribe-rcm-mcp