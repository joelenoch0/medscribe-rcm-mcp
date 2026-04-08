import os
from fastmcp import FastMCP

# Startup guard
if not os.getenv("WORKOS_JWKS_URI"):
    raise RuntimeError("OAuth not configured. See SECURITY.md")

# Create FastMCP server
app = FastMCP("MedScribe-RCM")

# Health endpoint
@app.route("/health")
def health():
    return {"status": "ok"}

# Run server
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8000)))