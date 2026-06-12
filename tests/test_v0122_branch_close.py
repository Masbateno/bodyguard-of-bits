"""v0.12.2 — branch-closing hardening cleanup (deep-audit + unexplored-angles pass).

M-1: _DOMAIN_SECTIONS must hold real runner section names (not finding-key
     prefixes) so domain_inactive_reason's _section_enabled check is accurate.
Cron: defense-in-depth control-char strip on the cron name before it is written
     into the root /etc/cron.d "# name:" comment.
"""

from __future__ import annotations

import re
import pathlib


_REPO = pathlib.Path(__file__).resolve().parent.parent


class TestM1DomainSectionsAreRealSections:
    def test_every_domain_section_is_a_real_runner_section(self):
        """M-1: a domain's contributing sections feed runner._section_enabled,
        so every name in _DOMAIN_SECTIONS must be a real runner section — not a
        finding-key prefix that merely resembles one (virt / logs)."""
        from bob.domain_scores import _DOMAIN_SECTIONS
        from bob.runner import _SECTIONS
        real = {s.name for s in _SECTIONS}
        for domain, sections in _DOMAIN_SECTIONS.items():
            for sec in sections:
                assert sec in real, f"domain {domain!r}: {sec!r} is not a runner section"

    def test_stray_prefixes_remapped(self):
        from bob.domain_scores import _DOMAIN_SECTIONS
        h = _DOMAIN_SECTIONS["hardening"]
        assert "virtualization" in h and "ufw_logging" in h
        assert "virt" not in h and "logs" not in h


class TestCronNameControlCharStrip:
    _PAT = r"[\x00-\x1f\x7f]+"

    def test_control_chars_collapsed_to_space(self):
        # the exact sanitisation applied in _install.py before the # name: write
        def sanitise(name: str, slug: str = "custom") -> str:
            return re.sub(self._PAT, " ", name).strip() or slug
        assert "\n" not in sanitise("a\nb")
        assert "\r" not in sanitise("a\rb")
        assert sanitise("x\n0 5 * * * root /tmp/evil") == "x 0 5 * * * root /tmp/evil"
        assert sanitise("\n\n") == "custom"          # falls back to slug

    def test_install_strips_name_before_comment_write(self):
        """Static guard: the control-char strip on raw_name must precede the
        '# name: {raw_name}' write so a name can never inject a cron line."""
        src = (_REPO / "bob" / "cron" / "_install.py").read_text(encoding="utf-8")
        i_strip = src.index(r're.sub(r"[\x00-\x1f\x7f]+"')
        i_write = src.index("# name: {raw_name}")
        assert i_strip < i_write, "raw_name must be sanitised before the # name: write"

    def test_generated_comment_stays_single_line(self):
        """A sanitised name produces exactly one '# name:' line (no injected
        second cron line)."""
        raw = re.sub(self._PAT, " ", "evil\n0 5 * * * root /tmp/x").strip()
        content = f"# name: {raw}\n# email: a@b.com\n"
        name_lines = [l for l in content.splitlines() if l.startswith("# name:")]
        assert len(name_lines) == 1
        # the cron-entry-looking text is now inside the single comment line
        assert all(not re.match(r"^\d", l) for l in content.splitlines())
