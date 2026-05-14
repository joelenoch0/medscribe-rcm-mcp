"""
scripts/import_icd10_tabular.py
================================
One-time import of ICD-10-CM 2026 tabular XML into Supabase icd10_codes table.

Run once:
    uv run python scripts/import_icd10_tabular.py

Requires:
    - data/icd10cm_tabular_2026.xml present in project root
    - SUPABASE_URL and SUPABASE_KEY in .env

Progress: prints batch count every 500 rows.
Safe to re-run — upserts on primary key (code).
"""

import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from dotenv import load_dotenv
from supabase import create_client

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
XML_PATH     = Path(__file__).parent.parent / "data" / "icd10cm_tabular_2026.xml"
BATCH_SIZE   = 500
FISCAL_YEAR  = 2026


def _text_list(element, tag: str) -> list[str]:
    """Extract all text values of child elements with the given tag."""
    results = []
    for child in element.findall(tag):
        if tag == "inclusionTerm":
            for note in child.findall("note"):
                if note.text:
                    results.append(note.text.strip())
        else:
            for note in child.findall("note"):
                if note.text:
                    results.append(note.text.strip())
            if child.text and child.text.strip():
                results.append(child.text.strip())
    return results


def _seven_chr_note(element) -> str | None:
    """Extract sevenChrNote text if present."""
    node = element.find("sevenChrNote")
    if node is None:
        return None
    note = node.find("note")
    if note is not None and note.text:
        return note.text.strip()
    return node.text.strip() if node.text else None


def parse_tabular(xml_path: Path) -> list[dict]:
    """
    Parse icd10cm_tabular_2026.xml.
    Returns list of dicts ready for Supabase upsert.
    Includes both leaf (billable) and non-leaf (header) codes.
    """
    print(f"Parsing {xml_path} ...")
    tree = ET.parse(xml_path)
    root = tree.getroot()

    records = []
    seen    = set()

    for diag in root.iter("diag"):
        name_el = diag.find("name")
        desc_el = diag.find("desc")
        if name_el is None or desc_el is None:
            continue

        code = (name_el.text or "").strip()
        desc = (desc_el.text or "").strip()
        if not code or not desc or code in seen:
            continue
        seen.add(code)

        child_tags = [c.tag for c in diag]
        is_leaf    = "diag" not in child_tags

        records.append({
            "code":            code,
            "description":     desc,
            "is_leaf":         is_leaf,
            "inclusion_terms": _text_list(diag, "inclusionTerm"),
            "excludes1":       _text_list(diag, "excludes1"),
            "excludes2":       _text_list(diag, "excludes2"),
            "use_additional":  _text_list(diag, "useAdditionalCode"),
            "code_first":      _text_list(diag, "codeFirst"),
            "seven_chr_note":  _seven_chr_note(diag),
            "fiscal_year":     FISCAL_YEAR,
        })

    print(f"Parsed {len(records):,} codes "
          f"({sum(1 for r in records if r['is_leaf']):,} billable leaf codes)")
    return records


def upload(records: list[dict], supabase) -> None:
    total   = len(records)
    batches = (total + BATCH_SIZE - 1) // BATCH_SIZE
    print(f"Uploading {total:,} records in {batches} batches of {BATCH_SIZE} ...")

    for i in range(batches):
        batch = records[i * BATCH_SIZE : (i + 1) * BATCH_SIZE]
        try:
            supabase.table("icd10_codes").upsert(batch).execute()
            print(f"  Batch {i+1}/{batches} — "
                  f"{min((i+1)*BATCH_SIZE, total):,}/{total:,} rows")
        except Exception as exc:
            print(f"  ERROR batch {i+1}: {exc}")
            sys.exit(1)

    print("Done.")


def main():
    if not SUPABASE_URL or not SUPABASE_KEY:
        print("ERROR: SUPABASE_URL and SUPABASE_KEY must be set in .env")
        sys.exit(1)

    if not XML_PATH.exists():
        print(f"ERROR: {XML_PATH} not found")
        sys.exit(1)

    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    records  = parse_tabular(XML_PATH)
    upload(records, supabase)


if __name__ == "__main__":
    main()
