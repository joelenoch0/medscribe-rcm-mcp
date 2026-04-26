path = r"C:\Users\DELL\medscribe-rcm-mcp\server.py"
with open(path, "r", encoding="utf-8") as f:
    lines = f.readlines()
for i, line in enumerate(lines[250:270], start=251):
    print(f"{i}: {line}", end="")
