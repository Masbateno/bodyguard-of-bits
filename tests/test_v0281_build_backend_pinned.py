"""0.28.1 — the build backend of a publication is pinned by hash.

0.27.0 pinned pip and the CI tools by hash (requirements-ci.txt), but
`python -m build` builds in an isolated environment and installs
pyproject.toml's `requires = ["setuptools>=77"]` there itself: no version, no
hash. The 0.28.0 publication's build log shows it resolved setuptools 84.2.1
that day.

Measured (30 October 2026, pip 26.2.2, build 1.6.1, Python 3.12, the source of
tag 0.28.0): with PIP_CONSTRAINT naming a file that pins setuptools==84.2.1 by
its two SHA-256, the isolated environment installed 84.2.1 and built the wheel
and the sdist; the same file with the hashes altered failed the build ("THESE
PACKAGES DO NOT MATCH THE HASHES"); the wheel built this way held the same 155
files, byte for byte, as the 0.28.0 wheel on PyPI.

The workflows are read as text: the CI environment has no YAML parser
(requirements-ci.txt only), the lesson of 0.27.0.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
BUILD_REQ = ROOT / "requirements-build.txt"


def _steps(text: str) -> "list[str]":
    """Each workflow step as its block of text (from one `- name:` to the next)."""
    return re.split(r"\n(?=\s*- name:)", text)


def test_the_publication_build_reads_the_pinned_backend():
    text = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
    builds = [s for s in _steps(text) if re.search(r"run:\s*python -m build\s*$", s, re.MULTILINE)]
    assert builds, "publish.yml no longer runs python -m build"
    for step in builds:
        m = re.search(r"PIP_CONSTRAINT:[ \t]*(.+?)[ \t]*$", step, re.MULTILINE)
        assert m, "the build step does not hand the pinned backend to the isolated environment"
        assert m.group(1).endswith("/requirements-build.txt"), m.group(1)


def test_every_workflow_build_is_constrained():
    for wf in WORKFLOWS:
        for step in _steps(wf.read_text(encoding="utf-8")):
            if re.search(r"run:.*python -m build(?!\s+--version)", step):
                assert "PIP_CONSTRAINT:" in step, f"{wf.name}: a build without the pinned backend"


def test_requirements_build_pins_setuptools_by_hash():
    text = BUILD_REQ.read_text(encoding="utf-8")
    blocks = re.findall(r"^([A-Za-z0-9_.-]+)==(\S+) \\\n((?:\s+--hash=sha256:[0-9a-f]{64}(?: \\)?\n?)+)",
                        text, re.MULTILINE)
    names = {b[0].lower() for b in blocks}
    assert "setuptools" in names, "requirements-build.txt does not pin setuptools"
    for name, _ver, hashes in blocks:
        assert hashes.count("--hash=sha256:") >= 1, f"{name} has no hash"
    pkg_lines = re.findall(r"^[A-Za-z0-9_.-]+[=<>!~]", text, re.MULTILINE)
    assert len(pkg_lines) == len(blocks), "a package line without an exact pin and hashes"


def test_requirements_build_matches_the_generator():
    spec = importlib.util.spec_from_file_location("gen_ci_requirements", ROOT / "scripts" / "gen_ci_requirements.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    pinned = {f"{n}=={v}" for n, v, _ in mod.BUILD_PINS}
    in_file = set(re.findall(r"^([A-Za-z0-9_.-]+==[^\s;]+)", BUILD_REQ.read_text(encoding="utf-8"), re.MULTILINE))
    assert in_file == pinned, f"requirements-build.txt drifted from the generator: {in_file ^ pinned}"


def test_the_pinned_backend_satisfies_pyproject():
    """A pin outside pyproject's range would make the build fail closed — but
    the guard says so here, not on the day of a release."""
    from packaging.specifiers import SpecifierSet
    from packaging.requirements import Requirement
    toml = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    requires = re.search(r"^requires\s*=\s*\[(.*?)\]", toml, re.MULTILINE | re.DOTALL).group(1)
    wanted = {Requirement(r).name.lower(): Requirement(r).specifier
              for r in re.findall(r'"([^"]+)"', requires)}
    pins = dict(re.findall(r"^([A-Za-z0-9_.-]+)==(\S+)", BUILD_REQ.read_text(encoding="utf-8"), re.MULTILINE))
    for name, spec in wanted.items():
        assert name in {p.lower() for p in pins}, f"{name} is required to build but not pinned"
        ver = next(v for p, v in pins.items() if p.lower() == name)
        assert ver in SpecifierSet(str(spec)), f"{name}=={ver} is outside pyproject's {spec}"
