# MedScribe RCM-FastMCP

> The first open-source MCP server that chains the entire healthcare Revenue Cycle Management pipeline — Transcription → Coding → Validation → Appeal — in a single, PHI-safe, OAuth-secured server.

**Live server:** `https://mcp.medscribepro.in`  
**Health check:** `https://mcp.medscribepro.in/health`  
**Contact:** contact@medscribepro.in  
**License:** Apache 2.0 (see NOTICE for trade secret exceptions)

---

## What It Does

MedScribe RCM-FastMCP prevents claim denials before they happen by chaining 4 specialized tools:

| Tool | Function |
|------|----------|
| `extract_codes_from_note` | Extracts ICD-10 + procedure flags from clinical notes |
| `suggest_codes_with_context` | Suggests codes with NOS/NEC sentinel trapping |
| `validate_claim_bundle` | Validates against NCCI edits + MUE tables (risk score 0–100) |
| `analyze_denial_and_appeal` | Generates CARC/RARC-matched appeal letters |

---

## Core Differentiator: NOS/NEC Sentinel Engine

Tool 2 traps 22 ICD-10-CM sentinel codes (11 NOS + 11 NEC) that are the leading
cause of medical necessity denials. Both code types trigger denials equally and are
flagged before claim submission — not after rejection.

This engine is built from 20+ years of medical transcription and coding expertise
across multiple specialties.

---

## Compliance

- **HIPAA:** PHI processed in RAM only via Microsoft Presidio — never stored
- **42 CFR Part 2:** Consent middleware gates all SUD-related tool calls
- **CMS-0057-F:** Denial reason mapping and appeal template selection
- **NCCI/MUE:** Quarterly CMS edit tables applied at validation

---

## Security

- OAuth 2.1 via WorkOS AuthKit (JWT, scope: `rcm:use`)
- All requests require a valid signed JWT
- PHI never appears in logs, database, or responses
- See [SECURITY.md](SECURITY.md) for full details

---

## Stack

| Component | Technology |
|-----------|------------|
| Server | FastMCP (Python) |
| PHI Redaction | Microsoft Presidio |
| NLP | spaCy en_core_web_sm |
| Database | Supabase (non-PHI only) |
| Auth | WorkOS AuthKit |
| Hosting | Render.com |
| Payments | Gumroad |

---

## Getting Started (Self-Host)

```bash
# 1. Clone
git clone https://github.com/joelenoch0/medscribe-rcm-mcp.git
cd medscribe-rcm-mcp

# 2. Install
uv install
python -m spacy download en_core_web_sm

# 3. Configure
cp .env.example .env
# Fill in: WORKOS_JWKS_URI, SUPABASE_URL, SUPABASE_ANON_KEY

# 4. Run
uv run python server.py
```

Health check: `http://localhost:8000/health`

---

## Connect via Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "medscribe-rcm": {
      "url": "https://mcp.medscribepro.in/mcp",
      "headers": {
        "Authorization": "Bearer <your_jwt_token>"
      }
    }
  }
}
```

---

## SaaS Subscription

**$29/month** — includes live server access, JWT provisioning, and support.

Contact: contact@medscribepro.in

---

## Warning

Only connect to the official server at `https://mcp.medscribepro.in`.
See [SECURITY.md](SECURITY.md) for shadow MCP server risks.

---

*Built with 20+ years of medical coding expertise. Powered by FastMCP, Presidio, and spaCy.*
