"""
v0.15.1 — two translation calls did not pass the variables their template needs.

A new angle: match every ``t("key", **kwargs)`` call site against the
placeholders its locale template actually contains. ``i18n.t`` catches the
resulting ``KeyError`` and returns the raw template, so the failure is silent at
runtime and visible only to the operator, as a literal ``{pct}`` in their report.

Two were found among 399 call sites:

* ``disk.partition_critical_reason`` — the *deduction reason*, which is what the
  score breakdown prints to explain a lost point, rendered as
  "Partition /data is {pct}% full". The finding message immediately above it
  passed ``pct`` correctly; only the reason did not.
* ``file_perms.ssh_host_key_perms_detail`` — rendered
  "Fix: sudo chmod 600 {path}", telling the operator to run a command that
  cannot be copied, while the ``cmd`` field on the same finding carried the
  correct path.

Passing a variable the template does *not* use is harmless — ``str.format``
ignores extras — and three such calls exist deliberately, so this guard only
asserts the missing direction.
"""

from __future__ import annotations

import ast
import json
import pathlib
import re

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_PLACEHOLDER = re.compile(r"\{(\w+)")


def _flatten(d: dict, prefix: str = "") -> dict:
    out: dict = {}
    for key, value in d.items():
        full = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            out.update(_flatten(value, full))
        else:
            out[full] = value
    return out


def _translation_calls():
    """Yield (file, line, key, kwargs) for every literal t()/_t() call."""
    for path in sorted((_ROOT / "bob").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            name = (fn.id if isinstance(fn, ast.Name)
                    else fn.attr if isinstance(fn, ast.Attribute) else "")
            if name not in ("t", "_t"):
                continue
            if not node.args or not isinstance(node.args[0], ast.Constant):
                continue
            key = node.args[0].value
            if not isinstance(key, str):
                continue
            given = {kw.arg for kw in node.keywords if kw.arg}
            yield path.relative_to(_ROOT), node.lineno, key, given


@pytest.mark.parametrize("locale", ["en", "fr"])
def test_every_call_supplies_the_placeholders_its_template_needs(locale):
    templates = _flatten(json.loads(
        (_ROOT / "bob" / "locales" / f"{locale}.json").read_text(encoding="utf-8")))
    missing = []
    for path, line, key, given in _translation_calls():
        template = templates.get(key)
        if not isinstance(template, str):
            continue
        needed = set(_PLACEHOLDER.findall(template))
        absent = needed - given
        if absent:
            missing.append(f"  {path}:{line} {key} — missing {sorted(absent)}")
    assert not missing, (
        f"translation calls that render a literal placeholder in {locale}:\n"
        + "\n".join(missing))


def test_every_translated_key_exists_in_the_locale():
    templates = _flatten(json.loads(
        (_ROOT / "bob" / "locales" / "en.json").read_text(encoding="utf-8")))
    unknown = [f"  {p}:{l} {k}" for p, l, k, _ in _translation_calls()
               if k not in templates]
    assert not unknown, "translation keys with no locale entry:\n" + "\n".join(unknown)


class TestTheTwoThatWereBroken:
    """Rendered end to end, in both locales, so the guard above cannot pass
    while the operator still sees a brace."""

    def _render(self, lang):
        from bob import i18n
        from bob.checks.disk import DiskSnapshot, PartitionInfo, check_disk
        from bob.checks.file_perms import FilePermsSnapshot, check_file_perms
        i18n.init(lang)
        disk = check_disk(DiskSnapshot(partitions=[
            PartitionInfo(mountpoint="/data", device="/dev/sda1",
                          size_gb=100.0, used_pct=97)]), t=i18n.t)
        perms = check_file_perms(FilePermsSnapshot(
            ssh_host_key_issues=[("/etc/ssh/ssh_host_rsa_key", 0o644)]), t=i18n.t)
        return disk, perms

    @pytest.mark.parametrize("lang", ["en", "fr"])
    def test_the_deduction_reason_names_the_percentage(self, lang):
        disk, _ = self._render(lang)
        reasons = [d.reason for d in disk.deductions if "partition" in (d.key or "")]
        assert reasons, "the critical-partition deduction did not fire"
        assert "97" in reasons[0]
        assert "{" not in reasons[0]

    @pytest.mark.parametrize("lang", ["en", "fr"])
    def test_the_remediation_detail_names_the_key_path(self, lang):
        _, perms = self._render(lang)
        details = [f.detail for f in perms.findings if "ssh_host_key" in (f.key or "")]
        assert details, "the host-key permission finding did not fire"
        assert "/etc/ssh/ssh_host_rsa_key" in details[0]
        assert "{" not in details[0]
