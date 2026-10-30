"""0.28.2 — the CI/CD audited, measured, and held where it was hardened.

Measured on 30 October 2026 (GitHub API, the three workflows read, zizmor
1.31.1 run offline as a cross-check: 31 findings before, 2 left after, both
written down):
- the token's rights were inherited from the repository setting (read) — now
  said in each workflow; only the PyPI upload (id-token) and the release
  (contents) write;
- every checkout left the token in .git/config (zizmor: artipacked);
- no job had a timeout (six hours by default) and no workflow a concurrency
  group;
- one script expanded a step output into the shell (template-injection);
- the integration matrix ran ubuntu:25.04 (end of life 17 January 2026) and
  fedora:41 (15 December 2025), which the README called "validated in CI",
  and no Tier 1 family outside Debian: Ubuntu 26.04, Fedora 44, Alpine 3.24
  and openSUSE Leap 16 replaced and joined them, each measured in podman
  first;
- the QEMU action pulled tonistiigi/binfmt:latest, run privileged;
- Dependabot proposed an action release the day it came out;
- the setuptools pin of 0.28.1 could not be shown to bite in CI while the
  pinned version was also the newest: a job now builds with the pinned file
  and with its hashes replaced, and requires the second to fail on the hash.

The workflows are read as text: the CI environment has no YAML parser.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WF = ROOT / ".github" / "workflows"
NAMES = ("tests.yml", "integration.yml", "publish.yml")


def _text(name: str) -> str:
    return (WF / name).read_text(encoding="utf-8")


def _jobs(text: str) -> "dict[str, str]":
    """Each job's block, keyed by its id (two-space indent under `jobs:`)."""
    body = text[text.index("\njobs:\n") + len("\njobs:\n"):]
    parts = re.split(r"(?m)^  (?=[\w-]+:\s*$)", body)
    return {p.split(":", 1)[0]: p for p in parts if re.match(r"[\w-]+:\s*\n", p)}


def _run_blocks(text: str) -> "list[str]":
    """The shell of every `run:` — a one-liner or the indented block under `run: |`."""
    out = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)run:\s*(.*)$", line)
        if not m:
            continue
        if m.group(2) and m.group(2) not in ("|", ">", ">-", "|-"):
            out.append(m.group(2))
            continue
        indent = len(m.group(1))
        block = []
        for nxt in lines[i + 1:]:
            if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= indent:
                break
            block.append(nxt)
        out.append("\n".join(block))
    return out


@pytest.mark.parametrize("name", NAMES)
def test_each_workflow_says_its_token_is_read_only(name):
    assert re.search(r"(?m)^permissions:\n  contents: read\n", _text(name)), \
        f"{name}: the token's rights are inherited, not said"


def test_only_the_publication_writes():
    for name in ("tests.yml", "integration.yml"):
        assert not re.search(r"(?m)^\s+[\w-]+: write\b", _text(name)), f"{name} asks for a write permission"
    jobs = _jobs(_text("publish.yml"))
    writers = {j: re.findall(r"(?m)^\s+([\w-]+): write\b", block) for j, block in jobs.items()}
    assert {j: w for j, w in writers.items() if w} == {"publish": ["id-token"], "github-release": ["contents"]}


@pytest.mark.parametrize("name", NAMES)
def test_no_checkout_leaves_the_token_behind(name):
    text = _text(name)
    for m in re.finditer(r"uses: actions/checkout@\S+.*\n((?:\s+.*\n){0,3})", text):
        assert "persist-credentials: false" in m.group(1), f"{name}: a checkout keeps the token in .git/config"


@pytest.mark.parametrize("name", NAMES)
def test_every_job_has_a_timeout(name):
    for job, block in _jobs(_text(name)).items():
        m = re.search(r"\n    timeout-minutes: (\d+)\n", block)
        assert m, f"{name}: job {job} has no timeout (six hours by default)"
        assert 5 <= int(m.group(1)) <= 60, f"{name}: job {job} timeout {m.group(1)}"


def test_a_newer_push_cancels_the_older_run_but_never_a_publication():
    for name in ("tests.yml", "integration.yml"):
        assert re.search(r"(?m)^concurrency:\n  group: .+\n  cancel-in-progress: true\n", _text(name)), name
    assert re.search(r"(?m)^concurrency:\n  group: publish\n  cancel-in-progress: false\n", _text("publish.yml"))


@pytest.mark.parametrize("name", NAMES)
def test_no_expression_is_expanded_into_a_script(name):
    for block in _run_blocks(_text(name)):
        assert "${{" not in block, f"{name}: an expression expanded into the shell: {block.strip()[:80]}"


def test_the_integration_matrix_runs_live_releases_of_every_tier1_family():
    text = _text("integration.yml")
    distros = set(re.findall(r"(?m)^\s+- distro: (\S+)", text))
    for dead in ("ubuntu:25.04", "fedora:41"):
        assert dead not in distros, f"{dead} is past its end of life"
    for live in ("debian:13", "ubuntu:26.04", "fedora:44", "alpine:3.24", "opensuse/leap:16.0", "kalilinux/kali-rolling"):
        assert live in distros, f"{live} (Tier 1) is not run in CI"
    families = set(re.findall(r"(?m)^\s+family: (\S+)", text))
    for fam in families:
        assert re.search(rf"if: matrix\.family == '{fam}'", text), f"no dependency step for the {fam} family"


def test_the_docs_name_the_matrix_ci_runs():
    """Each line that says what CI validates — not the whole file, where the
    same names appear for real hardware."""
    for f, marker in (("DOCUMENTS/README_TECH.md", "**CI-validated**"),
                      ("DOCUMENTS/README_TECH_FR.md", "**validé en CI**")):
        lines = [l for l in (ROOT / f).read_text(encoding="utf-8").splitlines() if marker in l]
        assert lines, f"{f}: no CI line"
        for line in lines:
            for live in ("26.04", "Fedora 44", "Alpine 3.24", "openSUSE Leap 16"):
                assert live in line, f"{f}: a CI line does not name {live}"
            assert "25.04" not in line and "Fedora 41" not in line, f"{f}: a CI line names an end-of-life release"
    snap = (ROOT / "DOCUMENTS" / "SNAPSHOT.md").read_text(encoding="utf-8")
    matrix = snap[snap.index("## CI matrix"):snap.index("plus an emulated arm64 job")]
    for live in ("26.04", "Fedora 44", "Alpine 3.24", "openSUSE Leap 16.0"):
        assert live in matrix, f"SNAPSHOT's CI matrix does not name {live}"
    for bullet in (l for l in matrix.splitlines() if l.startswith("- ")):
        assert "25.04" not in bullet and "Fedora 41" not in bullet, f"SNAPSHOT lists a dead release: {bullet}"
    for f in ("README.md", "README_FR.md"):
        tier2 = next(l for l in (ROOT / f).read_text(encoding="utf-8").splitlines() if l.startswith("| **Tier 2**"))
        assert "25.04" not in tier2 and "Fedora 41" not in tier2, f"{f}: Tier 2 names an end-of-life release"


def test_the_privileged_qemu_image_is_pinned_by_digest():
    m = re.search(r"uses: docker/setup-qemu-action@\S+.*\n((?:\s+.*\n){0,8})", _text("integration.yml"))
    assert m and re.search(r"image: \S+@sha256:[0-9a-f]{64}", m.group(1)), "binfmt image not pinned by digest"


def test_dependabot_waits_a_week():
    text = (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    m = re.search(r"cooldown:\n\s+default-days: (\d+)", text)
    assert m and int(m.group(1)) >= 7


def test_ci_proves_the_setuptools_pin_bites():
    block = _jobs(_text("tests.yml")).get("build-backend-pin")
    assert block, "no job proves the build backend pin"
    script = "\n".join(_run_blocks(block))
    assert 'PIP_CONSTRAINT="$PWD/requirements-build.txt" python -m build' in script
    assert "requirements-build-tampered.txt python -m build" in script
    assert re.search(r'if \[ "\$rc" -eq 0 \]; then .*exit 1', script), "a passing tampered build is not a failure"
    assert 'grep -q "DO NOT MATCH THE HASHES"' in script, "the tampered build may fail for another reason"
    assert "differs by more than its hashes" in script, "the tampered copy may differ in more than its hashes"


#: End of support of every image CI runs, measured on endoflife.date on
#: 30 October 2026. A release past its date fails this test: CI runs only
#: releases still supported — the LTS or stable line where the distribution
#: has one (Ubuntu, Debian, openSUSE Leap); the Tier 1 release where it has
#: none (Fedora, Alpine), replaced before its end; Kali is rolling.
SUPPORTED_UNTIL = {
    "debian:12": "2028-06-30", "debian:13": "2030-06-30",
    "debian:bookworm-slim": "2028-06-30",
    "ubuntu:22.04": "2027-06-01", "ubuntu:24.04": "2029-05-31", "ubuntu:26.04": "2031-05-29",
    "fedora:44": "2027-06-02", "alpine:3.24": "2028-06-01", "opensuse/leap:16.0": "2027-10-31",
    "kalilinux/kali-rolling": None,
}

#: Kali is rolling: no end date, so a date of last review instead — the image
#: still answers, still ships Python 3.10+, and every step still passes. Past
#: six months the suite asks for the review again (last: 30 October 2026, the
#: podman run of every step with pip 26.2.2 and setuptools 84.2.1).
ROLLING_REVIEWED = {"kalilinux/kali-rolling": "2026-10-30"}


def test_ci_runs_only_supported_releases():
    import datetime
    text = _text("integration.yml")
    images = set(re.findall(r"(?m)^\s+- distro: (\S+)", text)) | set(re.findall(r"\s(debian:[\w.-]+)\s*\\?\n", text))
    today = datetime.date.today().isoformat()
    for image in images:
        assert image in SUPPORTED_UNTIL, f"{image}: no end-of-support date recorded — measure it before adding it"
        until = SUPPORTED_UNTIL[image]
        assert until is None or today <= until, (
            f"{image} reached its end of support on {until}: replace it in integration.yml")
        if until is None:
            reviewed = datetime.date.fromisoformat(ROLLING_REVIEWED[image])
            assert (datetime.date.today() - reviewed).days <= 183, (
                f"{image} is rolling and was last reviewed on {reviewed}: run every step on it again, then update the date")


def test_the_release_is_made_by_github_cli_with_the_tag_it_was_built_from():
    block = _jobs(_text("publish.yml"))["github-release"]
    actions = re.findall(r"uses: ([\w./-]+)@", block)
    assert set(actions) <= {"actions/checkout", "actions/download-artifact"}, f"third-party action in the release job: {actions}"
    script = "\n".join(_run_blocks(block))
    assert 'gh release create "$GITHUB_REF_NAME" dist/*' in script
    assert "--verify-tag" in script, "the release could create a tag of its own"
    assert "--notes-file /tmp/notes.md" in script


def test_only_a_bare_version_tag_starts_a_publication():
    text = _text("publish.yml")
    trigger = text[text.index("\non:\n"):text.index("\npermissions:\n")]
    assert re.findall(r'- "([^"]+)"', trigger) == ["[0-9]+.[0-9]+.[0-9]+"]


def _bob_installs():
    """Every line that installs BOB itself (`.` or `-e .`), with its file."""
    sources = [(n, _text(n)) for n in NAMES] + [("ci/arm64_smoke.sh", (ROOT / "ci" / "arm64_smoke.sh").read_text(encoding="utf-8"))]
    out = []
    for name, text in sources:
        for line in text.splitlines():
            if re.search(r"pip install\b[^\n]*\s(?:-e\s+)?\.\s*$", line):
                out.append((name, line, text))
    return out


def test_every_install_of_bob_builds_against_the_pinned_setuptools():
    """Measured: a hashed PIP_CONSTRAINT makes pip refuse the local project
    ("no single file to hash"), so the test builds install setuptools from
    requirements-build.txt by hash and build BOB without isolation."""
    installs = _bob_installs()
    assert len(installs) >= 5, installs
    for name, line, text in installs:
        assert "--no-build-isolation" in line, f"{name}: BOB built with an unpinned setuptools: {line.strip()}"
        assert "--require-hashes -r requirements-build.txt" in text, f"{name}: setuptools not installed by hash"


def test_every_venv_gets_the_hash_pinned_pip_first():
    for name in ("integration.yml", "ci/arm64_smoke.sh"):
        text = _text(name) if name.endswith(".yml") else (ROOT / name).read_text(encoding="utf-8")
        venv = text.index("python3 -m venv /opt/bobenv")
        pin = text.index("pip-26.2.2-py3-none-any.whl#sha256=", venv)
        build = text.index("--no-build-isolation", venv)
        assert pin < build, f"{name}: the venv builds BOB before its pip is replaced"


def test_nothing_is_cached_on_the_privileged_path():
    m = re.search(r"uses: docker/setup-qemu-action@\S+.*\n((?:\s+.*\n){0,10})", _text("integration.yml"))
    assert m and "cache-image: false" in m.group(1)


def test_the_upload_container_is_pulled_by_digest_before_the_action_runs():
    block = _jobs(_text("publish.yml"))["publish"]
    action = re.search(r"uses: pypa/gh-action-pypi-publish@([0-9a-f]{40})", block)
    assert action, "the upload action is not pinned by commit"
    pull = block.index("- name: Pull the upload container by digest")
    assert pull < action.start(), "the image is pulled after the action already ran"
    refs = re.findall(r"REF: (\S+)\n", block)
    assert refs and set(refs) == {action.group(1)}, f"REF {refs} is not the commit the action is pinned to"
    assert re.search(r"DIGEST: sha256:[0-9a-f]{64}\n", block)
    script = "\n".join(_run_blocks(block))
    assert 'docker pull "$IMAGE@$DIGEST"' in script and 'docker tag "$IMAGE@$DIGEST" "$IMAGE:$REF"' in script


def test_publication_waits_for_green_ci_on_the_tagged_commit():
    jobs = _jobs(_text("publish.yml"))
    gate = jobs.get("ci-green")
    assert gate, "nothing holds the rule 'tag only a green commit'"
    assert re.search(r"needs: \[test, ci-green\]", jobs["build"]), "the build does not wait for the gate"
    assert re.search(r"permissions:\n\s+actions: read\b", gate)
    script = "\n".join(_run_blocks(gate))
    assert "head_sha=$GITHUB_SHA&event=push&branch=main" in script
    for wf in (".github/workflows/tests.yml", ".github/workflows/integration.yml"):
        assert wf in script, f"{wf} is not required green"
    assert 'red*) echo "::error::' in script and "exit 1" in script


def test_the_upload_container_is_checked_before_and_after():
    block = _jobs(_text("publish.yml"))["publish"]
    before = block.index("- name: Pull the upload container by digest")
    action = block.index("uses: pypa/gh-action-pypi-publish@")
    after = block.index("- name: The upload ran in the pinned container")
    assert before < action < after
    assert block.count('grep -qF "$IMAGE@$DIGEST" /tmp/digests.txt') == 2


def test_the_release_attaches_the_files_pypi_has():
    block = _jobs(_text("publish.yml"))["github-release"]
    check = block.index("- name: The files to attach are the files PyPI has")
    create = block.index("gh release create")
    assert check < create
    script = "\n".join(_run_blocks(block))
    assert 'f["digests"]["sha256"]' in script and "hashlib.sha256(p.read_bytes())" in script
    assert "if local != pypi:" in script


# --- the repository settings, which no file holds -----------------------------

def _settings():
    import importlib.util
    spec = importlib.util.spec_from_file_location("check_repo_settings", ROOT / "scripts" / "check_repo_settings.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


#: The answers the GitHub API gave on 30 October 2026, reduced to what the
#: checks read.
MEASURED = {
    "actions/permissions/workflow": {"default_workflow_permissions": "read", "can_approve_pull_request_reviews": False},
    "actions/permissions": {"enabled": True, "allowed_actions": "all", "sha_pinning_required": True},
    "actions/permissions/fork-pr-contributor-approval": {"approval_policy": "first_time_contributors"},
    "": {"security_and_analysis": {"secret_scanning": {"status": "enabled"},
                                   "secret_scanning_push_protection": {"status": "enabled"}}},
    "vulnerability-alerts": 204,
    "environments/release": {"can_admins_bypass": False, "protection_rules": [
        {"type": "required_reviewers", "reviewers": [{"type": "User"}]}, {"type": "branch_policy"}]},
    "environments/release/deployment-branch-policies": {"branch_policies": [{"name": "[0-9]*.[0-9]*.[0-9]*", "type": "tag"}]},
    "rulesets": [
        {"target": "branch", "enforcement": "active", "bypass_actors": [], "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}]},
        {"target": "tag", "enforcement": "active", "bypass_actors": [],
         "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}, {"type": "update"}]},
    ],
}


def test_the_measured_settings_hold():
    results = _settings().evaluate(MEASURED)
    assert len(results) == 13
    assert all(r[3] for r in results), [r for r in results if not r[3]]


@pytest.mark.parametrize("path, change", [
    ("actions/permissions/workflow", {"default_workflow_permissions": "write", "can_approve_pull_request_reviews": False}),
    ("actions/permissions", {"enabled": True, "allowed_actions": "all", "sha_pinning_required": False}),
    ("", {"security_and_analysis": {"secret_scanning": {"status": "enabled"},
                                    "secret_scanning_push_protection": {"status": "disabled"}}}),
    ("vulnerability-alerts", 404),
    ("environments/release", {"can_admins_bypass": True, "protection_rules": [
        {"type": "required_reviewers", "reviewers": [{"type": "User"}]}]}),
    ("environments/release", {"can_admins_bypass": False, "protection_rules": []}),
    ("rulesets", [{"target": "branch", "enforcement": "evaluate", "bypass_actors": [],
                   "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}]},
                  {"target": "tag", "enforcement": "active", "bypass_actors": [],
                   "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}, {"type": "update"}]}]),
], ids=["token-write", "sha-pinning-off", "push-protection-off", "alerts-off", "admin-bypass",
        "no-reviewer", "rulesets-not-enforced"])
def test_a_changed_setting_is_reported(path, change):
    answers = dict(MEASURED, **{path: change})
    assert not all(r[3] for r in _settings().evaluate(answers))


def test_the_container_steps_do_not_depend_on_the_images_path():
    """Found on the first 0.28.2 push: opensuse/leap:16.0 declares no PATH, the
    runner builds a container step's PATH from the image's, and the venv added
    to GITHUB_PATH became the whole PATH — the next step could not find `sh`
    (exit 127). The steps call the venv by its absolute path instead."""
    text = _text("integration.yml")
    smoke = _jobs(text)["smoke"]
    script = "\n".join(_run_blocks(smoke))
    assert "GITHUB_PATH" not in script
    after_install = script[script.index("--no-build-isolation ."):]
    for line in after_install.splitlines():
        cmd = line.strip()
        assert not re.match(r"(bob|python3|pip)\b", cmd), f"called through PATH: {cmd}"
    assert "/opt/bobenv/bin/bob --offline -v > audit.txt" in script
