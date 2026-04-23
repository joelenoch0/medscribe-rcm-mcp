# Security Policy — MedScribe RCM-FastMCP

## Reporting a Vulnerability

If you discover a security vulnerability, please email **contact@medscribepro.in**
with subject line: `[SECURITY] MedScribe RCM`.

Do **not** open a public GitHub issue for security vulnerabilities.

We will respond within 72 hours and issue a patch within 7 days for critical issues.

---

## Authentication Setup (Required)

This server **will not start** without OAuth configured. You must set:

```env
WORKOS_JWKS_URI=https://api.workos.com/sso/jwks/<your_client_id>
WORKOS_ISSUER=https://api.workos.com
WORKOS_CLIENT_ID=<your_client_id>
```

All API calls require a valid JWT with scope `rcm:use`. Requests without
a valid token receive a `401 Unauthorized` response.

---

## WARNING: Shadow MCP Servers (OWASP MCP Top 10 #9)

**Never connect to an unofficial or self-hosted clone of this server.**

MedScribe RCM-FastMCP is only officially served at:

```
https://mcp.medscribepro.in
```

Shadow MCP servers can:
- Steal PHI passed in tool calls
- Return malicious billing codes
- Manipulate appeal letters
- Exfiltrate credentials

Always verify the server URL before connecting any MCP client.

---

## PHI Safety Architecture

- PHI is **never written to disk or database**
- All clinical text is redacted via Microsoft Presidio before processing
- Supabase stores only: hashed patient tokens, consent flags, billing counts
- Audit logs contain tool names and timestamps — never note text

---

## 42 CFR Part 2 Compliance

All tool calls involving substance use disorder (SUD) data require explicit
patient consent registered in the `consent_registry` table before execution.
Calls without a valid consent record are blocked with a `403` error and the
following redisclosure notice is appended to all SUD-related outputs:

> "This information has been disclosed to you from records protected by federal
> confidentiality rules (42 CFR Part 2). Federal rules prohibit you from making
> any further disclosure of this information unless further disclosure is
> expressly permitted by the written consent of the person to whom it pertains."

---

## Dependency Security

Run quarterly:
```bash
uv pip audit
```

Keep `fastmcp`, `presidio-analyzer`, and `mcp` pinned and updated.
