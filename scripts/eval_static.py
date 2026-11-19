#!/usr/bin/env python3
"""Static coverage, positive trigger selection, and negative decoy rejection eval proxy.

Honest scope: does NOT invoke an LLM. Verifies:
1. Required safety invariants exist across SKILL.md + references/.
2. Positive prompts in evals/evals.json and tests/selection.jsonl match trigger vocabulary.
3. Negative decoy prompts in tests/selection.jsonl stay below trigger threshold (avoiding hijack).
4. Deterministic behavioral scenarios exist in test_scenarios.yaml.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILL_DIR = ROOT / "skill-src" / "coldpin"
SELECTION_PATH = ROOT / "tests" / "selection.jsonl"

STOP = set(
    "a an the to of for and or in on at is are we our my me you how what do does this that it with from be can should write explain draft configure convert".split()
)
TRIGGER_MIN_OVERLAP = 2


def tokenize(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9/+\-]{3,}", text.lower()) if w not in STOP}


def main() -> int:
    skill_md = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
    refs = sorted((SKILL_DIR / "references").glob("*.md"))
    corpus = "\n".join([skill_md] + [r.read_text(encoding="utf-8") for r in refs]).lower()

    required_invariants = [
        ("zero-exec", ["zero execution", "in memory", "--ignore-scripts"]),
        ("prompt-injection", ["untrusted data", "aml.t0051.001", "never override"]),
        ("private-scope", ["private scopes", ".npmrc", "verify-confusion"]),
        ("rea-boundary", ["rea-integration-playbook.md", "never run `npx -y rea-agents", "unverifiable_unknown"]),
        ("verdict-states", ["verified_clean_within_scope", "quarantine_suspicious", "malicious_indicators_found", "unverifiable_unknown"]),
        ("anchor-recovery", ["resolve-anchor", "rollback_to_safe_anchor", "switch_to_alternative"]),
        ("outputs", ["sarif 2.1.0", "cyclonedx 1.5", "hxxp://", "audit-verify"]),
    ]

    failures: list[str] = []
    for name, terms in required_invariants:
        missing = [t for t in terms if t not in corpus]
        if missing:
            failures.append(f"Invariant '{name}' missing terms: {missing}")

    frontmatter_head = skill_md.split("\n# ", 1)[0]
    trigger_tokens = tokenize(frontmatter_head)

    # 1. Check evals/evals.json positive tasks
    evals_doc = json.loads((SKILL_DIR / "evals" / "evals.json").read_text(encoding="utf-8"))
    eval_cases = evals_doc.get("evals", [])
    eval_hits = 0
    for case in eval_cases:
        overlap = tokenize(case["prompt"]) & trigger_tokens
        if len(overlap) >= TRIGGER_MIN_OVERLAP:
            eval_hits += 1
        else:
            failures.append(f"Eval '{case['id']}' weak trigger overlap ({len(overlap)}): {sorted(overlap)}")

    # 2. Check tests/selection.jsonl (positive + negative decoys)
    pos_ok = pos_tot = dec_ok = dec_tot = 0
    for line in SELECTION_PATH.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        overlap = tokenize(row["prompt"]) & trigger_tokens
        pred = "coldpin" if len(overlap) >= TRIGGER_MIN_OVERLAP else "none"
        if row["expect"] == "coldpin":
            pos_tot += 1
            if pred == "coldpin":
                pos_ok += 1
            else:
                failures.append(f"Selection positive MISS '{row['id']}': overlap={sorted(overlap)}")
        else:
            dec_tot += 1
            if pred == "none":
                dec_ok += 1
            else:
                failures.append(f"Selection decoy FALSE TRIGGER '{row['id']}': overlap={sorted(overlap)}")

    # 3. Verify deterministic behavioral scenarios in test_scenarios.yaml
    scenarios_txt = (SKILL_DIR / "test_scenarios.yaml").read_text(encoding="utf-8")
    scenario_ids = re.findall(r'scenario_id:\s*"([^"]+)"', scenarios_txt)
    if len(scenario_ids) < 4:
        failures.append(f"Expected >= 4 deterministic scenarios in test_scenarios.yaml, found {len(scenario_ids)}")

    print(
        f"Static eval: {len(required_invariants)} invariants | evals {eval_hits}/{len(eval_cases)} | "
        f"selection pos {pos_ok}/{pos_tot}, decoys avoided {dec_ok}/{dec_tot} | scenarios {len(scenario_ids)}"
    )
    if failures:
        for f in failures:
            print(f"  FAIL: {f}", file=sys.stderr)
        return 1

    print("EVAL STATIC OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
