"""
launcher.py - MedScribe RCM-FastMCP
Loads environment variables and starts the MCP server.
All secrets must be set as environment variables - never hardcoded.
"""
import os
import subprocess
import sys

# ── Required environment variables ───────────────────────────────────────────
# Set these in Render dashboard (never in code)
required_vars = [
    "SUPABASE_URL",
    "SUPABASE_ANON_KEY",
]

missing = [v for v in required_vars if not os.getenv(v)]
if missing:
    print(f"ERROR: Missing environment variables: {', '.join(missing)}")
    print("Set them in Render dashboard under Environment Variables.")
    sys.exit(1)

# ── Start the MCP server ──────────────────────────────────────────────────────
if __name__ == "__main__":
    subprocess.run([sys.executable, "server.py"], check=True)
