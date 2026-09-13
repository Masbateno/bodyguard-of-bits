"""v0.20.0 — the audit banner shows a small distro logo beside the OS name.

An emoji stands in for the distribution's logo (a real terminal cannot render
the pixel logo portably). The one hard constraint is alignment: the banner draws
a box and pads each row to a fixed width with ``_visual_width``, so a logo whose
rendered width the code cannot predict would push the System row's right border
out of line. Every logo must therefore be a single code point of East-Asian
width Wide (``_visual_width`` == 2, and terminals agree). This guard pins the
mapping, the single-Wide invariant, and the box alignment.
"""

from __future__ import annotations

import io
import unicodedata
from contextlib import redirect_stdout

import pytest

from bob import output
from bob.output import distro_logo, _DISTRO_LOGOS, _visual_width, _strip_ansi


@pytest.fixture(autouse=True)
def _mono():
    output.init(no_color=True)
    yield
    output.init(no_color=False)


@pytest.mark.parametrize("pretty,glyph", [
    ("Ubuntu 22.04.3 LTS",            "🟠"),
    ("Debian GNU/Linux 13 (trixie)",  "🔴"),
    ("Fedora Linux 43",               "🔵"),
    ("Arch Linux",                    "🔷"),
    ("Alpine Linux v3.22",            "🗻"),
    ("openSUSE Leap 15.6",            "🦎"),
    ("Linux Mint 22.3",               "🌿"),
    ("Kali GNU/Linux Rolling",        "🐉"),
    ("Raspberry Pi OS (64-bit)",      "🍓"),
    ("Rocky Linux 9.3",               "🎩"),
    ("Manjaro Linux",                 "🟢"),
])
def test_known_distros_map_to_their_glyph(pretty, glyph):
    assert distro_logo(pretty) == glyph


def test_unknown_linux_falls_back_to_tux():
    assert distro_logo("SomeUnknownOS 1.0") == "🐧"
    assert distro_logo("") == "🐧"


def test_raspberry_beats_debian_on_a_pi():
    # Raspberry Pi OS is Debian-derived; the specific mark must win.
    assert distro_logo("Raspberry Pi OS (Debian GNU/Linux 12)") == "🍓"


def test_every_logo_is_single_codepoint_and_wide():
    """The alignment invariant: one code point, East-Asian width Wide.

    A multi-code-point emoji (a variation selector, a ZWJ sequence) or a
    non-Wide symbol renders at a width the banner cannot predict and breaks the
    box border. Tux (the fallback) is checked alongside the table.
    """
    glyphs = [g for _needles, g in _DISTRO_LOGOS] + ["🐧"]
    for g in glyphs:
        assert len(g) == 1, f"{g!r} is not a single code point"
        assert unicodedata.east_asian_width(g) == "W", (
            f"{g!r} is not East-Asian Wide — it will misalign the banner")
        assert _visual_width(g) == 2, f"{g!r} does not measure as width 2"


def _banner(system: str) -> list[str]:
    labels = {k: k.capitalize() for k in
              ("system", "host", "kernel", "ufw", "iptables", "nftables", "user", "date")}
    buf = io.StringIO()
    with redirect_stdout(buf):
        output.print_banner(
            version="v0.20.0", subtitle="Linux hardening auditor", system=system,
            host="h", kernel="k", ufw_version="", iptables="i", nftables="n",
            user="root", date="2026-09-13", labels=labels)
    return buf.getvalue().splitlines()


def test_banner_shows_the_logo_next_to_the_os_name():
    lines = _banner("openSUSE Leap 15.6")
    sys_line = next(l for l in lines if "openSUSE Leap 15.6" in l)
    assert "🦎" in sys_line
    assert sys_line.index("🦎") < sys_line.index("openSUSE")


@pytest.mark.parametrize("system", [
    "Debian GNU/Linux 13 (trixie)",  # 🔴
    "openSUSE Leap 15.6",            # 🦎
    "SomeUnknownOS 1.0",            # 🐧 fallback
])
def test_the_box_border_stays_aligned_with_a_logo(system):
    """Every boxed row must have the same visual width — the logo must not push
    the right border out."""
    lines = [l for l in _banner(system) if l.startswith("║") or l.startswith("╔")
             or l.startswith("╠") or l.startswith("╚")]
    widths = {_visual_width(_strip_ansi(l)) for l in lines}
    assert len(widths) == 1, f"box rows disagree on width: {sorted(widths)}"
