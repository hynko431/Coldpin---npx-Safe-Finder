#!/usr/bin/env python3
"""Reference & Fact-Ledger staleness monitor (Enterprise Commons `tools/staleness_check.py` parity).

Usage: python scripts/staleness_check.py [warn_days=30]
Exits 1 if any dated reference has passed its `review_by` date.
"""

import datetime
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DAYS = int(sys.argv[1]) if len(sys.argv) > 1 else 30
TODAY = datetime.date.today()

TARGETS = (
    sorted((ROOT / "skills" / "coldpin" / "references").glob("*.md"))
    + [ROOT / "docs" / "fact-ledger.md", ROOT / "MAINTENANCE.md"]
)

stale = 0
due_soon = 0
checked = 0

for fpath in TARGETS:
    if not fpath.exists():
        continue
    checked += 1
    head = fpath.read_text(encoding="utf-8")[:1500]
    m = re.search(r"review_by:\s*(\d{4}-\d{2}-\d{2})", head)
    if not m:
        print(f"MISSING review_by: {fpath.relative_to(ROOT).as_posix()}", file=sys.stderr)
        stale += 1
        continue
    review_date = datetime.date.fromisoformat(m.group(1))
    rel = fpath.relative_to(ROOT).as_posix()
    if review_date < TODAY:
        print(f"STALE {review_date} {rel}", file=sys.stderr)
        stale += 1
    elif (review_date - TODAY).days <= DAYS:
        print(f"DUE   {review_date} {rel}")
        due_soon += 1

print(f"STALENESS CHECK: checked={checked} stale={stale} due_within_{DAYS}d={due_soon}")
raise SystemExit(1 if stale else 0)
