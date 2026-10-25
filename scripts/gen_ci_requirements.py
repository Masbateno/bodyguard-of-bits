#!/usr/bin/env python3
"""Regenerate requirements-ci.txt: the CI build/test/lint tools pinned by
version and SHA-256, with the linux x86_64 wheels (the CI platform), the
pure-python wheels and the sdists. Fetches the hashes from PyPI.

v0.27.0 (fifth review): pinning pip by hash does not pin what pip then
installs; this file closes that gap for the tools the workflows use.
"""
from __future__ import annotations
import json
import urllib.request

# Versions resolved on 2026-10-24 in a clean venv (pytest/beautifulsoup4/ruff/
# build and their transitive deps), plus tomli/exceptiongroup for Python < 3.11;
# each checked against Requires-Python for the whole 3.10-3.14 matrix.
PINS = [
    ("pytest", "9.1.1", None), ("beautifulsoup4", "4.15.0", None), ("ruff", "0.17.2", None),
    ("build", "1.6.1", None), ("iniconfig", "2.3.1", None), ("packaging", "26.3", None),
    ("pluggy", "1.7.0", None), ("Pygments", "2.21.0", None), ("pyproject_hooks", "1.3.3", None),
    # soupsieve 3.x requires Python >= 3.11.5 (found on the 0.27.0 CI run, 3.10
    # job): 2.10 for the older interpreters of the matrix.
    ("soupsieve", "3.0.4", 'python_full_version >= "3.11.5"'),
    ("soupsieve", "2.10", 'python_full_version < "3.11.5"'),
    ("typing_extensions", "4.16.0", None),
    ("tomli", "2.2.1", 'python_version < "3.11"'),
    ("exceptiongroup", "1.3.0", 'python_version < "3.11"'),
]


def _wanted(filename: str, packagetype: str) -> bool:
    if packagetype == "sdist":
        return True
    if not filename.endswith(".whl"):
        return False
    if "py3-none-any" in filename or "py2.py3-none-any" in filename:
        return True
    # version-specific wheels for the CI platform (linux x86_64, glibc or musl)
    return "x86_64" in filename and ("manylinux" in filename or "musllinux" in filename)


def main() -> None:
    out = [
        "# CI build/test/lint tools, pinned by version and SHA-256 (v0.27.0, fifth review).",
        "# Installed with: pip install --require-hashes -r requirements-ci.txt",
        "# Regenerate: python3 scripts/gen_ci_requirements.py",
        "# Only the linux x86_64 wheels (the CI platform), the pure-python wheels",
        "# and the sdists are pinned; --require-hashes fails closed if pip needs another.",
        "",
    ]
    for name, ver, marker in PINS:
        data = json.load(urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{ver}/json", timeout=30))
        shas = [f["digests"]["sha256"] for f in data["urls"] if _wanted(f["filename"], f["packagetype"])]
        if not shas:
            raise SystemExit(f"no file selected for {name}=={ver}")
        head = f"{name}=={ver}" + (f' ; {marker}' if marker else "")
        out.append(head + " \\\n" + " \\\n".join(f"    --hash=sha256:{s}" for s in shas))
    open("requirements-ci.txt", "w").write("\n".join(out) + "\n")
    print(f"wrote requirements-ci.txt ({len(PINS)} packages)")


if __name__ == "__main__":
    main()
