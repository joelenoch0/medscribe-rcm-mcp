path = r"C:\Users\DELL\medscribe-rcm-mcp\server.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

old = '    """Build a PHI-free metadata lineage block attached to every response."""'
new = 'def _meta(tool: str, payer: str = "", extra: Dict[str, Any] | None = None) -> Dict[str, Any]:\n    """Build a PHI-free metadata lineage block attached to every response."""'

if old in content:
    content = content.replace(old, new, 1)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print("Done")
else:
    print("ERROR - text not found")
