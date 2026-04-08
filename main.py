import os

# ---------------- Startup Guard ----------------
if not os.getenv("WORKOS_JWKS_URI"):
    raise RuntimeError("OAuth not configured. See SECURITY.md")

# ---------------- Imports ----------------
from fastmcp import FastMCP
from fastapi import FastAPI
import threading
import uvicorn
from fastmcp import FastMCP
from fastapi import FastAPI
import threading
import uvicorn

# ---------------- FastMCP server ----------------
mcp_app = FastMCP("MedScribe-RCM")

@mcp_app.tool()
def health_tool() -> dict:
    return {"status": "ok (MCP)"}

# ---------------- HTTP server ----------------
http_app = FastAPI()

@http_app.get("/health")
def health():
    return {"status": "ok (HTTP)"}

# ---------------- Run HTTP server in a separate thread ----------------
def run_http():
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(http_app, host="0.0.0.0", port=port, log_level="info")

if __name__ == "__main__":
    # Start HTTP server first
    threading.Thread(target=run_http, daemon=True).start()
    # Then start MCP server
    mcp_app.run()