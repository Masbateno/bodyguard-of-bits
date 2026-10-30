#!/usr/bin/env python3
"""Check that the repository settings the CI/CD relies on are still in place.

0.28.2 — these settings live on GitHub, not in the repository: a change made
in the web interface leaves every file unchanged and every test green. The
workflow token cannot read most of them (they need administrator rights), so
this script runs with the maintainer's `gh` login, before a push that leads to
a release (PROTOCOLS: "on pousse"), and prints what it read.

    python3 scripts/check_repo_settings.py            # exit 0 when all hold

What each value is, and why, is in DOCUMENTS/CI.md ("Repository settings").
"""
from __future__ import annotations

import json
import subprocess
import sys

REPO = "Masbateno/bodyguard-of-bits"

#: (label, API path, how to read the answer, the expected value)
CHECKS = [
    ("default token rights", "actions/permissions/workflow", "default_workflow_permissions", "read"),
    ("workflows may approve pull requests", "actions/permissions/workflow", "can_approve_pull_request_reviews", False),
    ("Actions enabled", "actions/permissions", "enabled", True),
    ("actions pinned by commit required", "actions/permissions", "sha_pinning_required", True),
    ("fork pull requests need approval", "actions/permissions/fork-pr-contributor-approval", "approval_policy",
     ("first_time_contributors_new_to_github", "first_time_contributors", "all_external_contributors")),
    ("secret scanning", "", "security_and_analysis.secret_scanning.status", "enabled"),
    ("push protection", "", "security_and_analysis.secret_scanning_push_protection.status", "enabled"),
    ("Dependabot vulnerability alerts", "vulnerability-alerts", "@status", 204),
    ("release: administrators may bypass", "environments/release", "can_admins_bypass", False),
    ("release: a required reviewer", "environments/release", "@reviewers", True),
    ("release: tag filter", "environments/release/deployment-branch-policies", "@tag_policies", ["[0-9]*.[0-9]*.[0-9]*"]),
    ("main: no deletion, no force-push", "rulesets", "@branch_rules", True),
    ("release tags: never deleted or moved", "rulesets", "@tag_rules", True),
]


def _dig(data, path: str):
    for key in path.split("."):
        data = data.get(key) if isinstance(data, dict) else None
    return data


def value_of(answers: "dict", path: str, how: str):
    data = answers.get(path)
    if how == "@status":
        return data
    if how == "@reviewers":
        rules = (data or {}).get("protection_rules", [])
        return any(r.get("type") == "required_reviewers" and r.get("reviewers") for r in rules)
    if how == "@tag_policies":
        return sorted(p["name"] for p in (data or {}).get("branch_policies", []) if p.get("type") == "tag")
    if how in ("@branch_rules", "@tag_rules"):
        target = "branch" if how == "@branch_rules" else "tag"
        wanted = {"deletion", "non_fast_forward"} | ({"update"} if target == "tag" else set())
        for ruleset in data or []:
            if ruleset.get("target") == target and ruleset.get("enforcement") == "active" \
                    and not ruleset.get("bypass_actors") and wanted <= {r["type"] for r in ruleset.get("rules", [])}:
                return True
        return False
    return _dig(data, how)


def evaluate(answers: "dict") -> "list[tuple[str, object, object, bool]]":
    """(label, expected, found, holds) for every check."""
    out = []
    for label, path, how, expected in CHECKS:
        found = value_of(answers, path, how)
        holds = found in expected if isinstance(expected, tuple) else found == expected
        out.append((label, expected, found, holds))
    return out


def fetch() -> "dict":
    """Every API answer the checks need, through the maintainer's `gh`."""
    answers: dict = {}
    for _label, path, how, _expected in CHECKS:
        if path in answers:
            continue
        if how == "@status":
            proc = subprocess.run(["gh", "api", "-i", f"repos/{REPO}/{path}"], capture_output=True, text=True)
            head = proc.stdout.splitlines()[0] if proc.stdout else ""
            answers[path] = int(head.split()[1]) if len(head.split()) > 1 and head.split()[1].isdigit() else None
            continue
        url = f"repos/{REPO}" + (f"/{path}" if path else "")
        if path == "rulesets":
            ids = json.loads(subprocess.run(["gh", "api", f"{url}"], capture_output=True, text=True, check=True).stdout)
            answers[path] = [json.loads(subprocess.run(["gh", "api", f"{url}/{r['id']}"], capture_output=True,
                                                       text=True, check=True).stdout) for r in ids]
            continue
        proc = subprocess.run(["gh", "api", url], capture_output=True, text=True)
        answers[path] = json.loads(proc.stdout) if proc.returncode == 0 else None
    return answers


def main() -> int:
    results = evaluate(fetch())
    for label, expected, found, holds in results:
        print(f"{'OK  ' if holds else 'DIFF'} {label}: {found!r}" + ("" if holds else f" (expected {expected!r})"))
    drifted = [r for r in results if not r[3]]
    if drifted:
        print(f"\n{len(drifted)} setting(s) changed since the 0.28.2 audit — see DOCUMENTS/CI.md")
        return 1
    print("\nall repository settings hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
