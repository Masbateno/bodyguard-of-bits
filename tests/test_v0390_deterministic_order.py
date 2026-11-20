"""v0.39.0 — directories are read in a fixed order (backlog B-020, B-021).

0.37.0's CI failed one run in two: a libvirt guard only bit when the broken
state file happened to be listed first — iterdir() answers in the
filesystem's order, which differs between machines. The verdict was the same;
which file was read first, and so what a test saw, was not.

Every scan whose order decides what is shown or what is found first is now
sorted: /proc by process number, the other directories by name. Counts and
any() keep the plain iterdir(): their result cannot depend on the order.

Measured (17 November 2026): the whole suite run with every Path.iterdir()
answering in reverse order fails only the release counters — no test depends
on the order of a directory any more.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

#: Each file, and how many scans in it must be sorted.
_SORTED_SCANS = {
    "bob/checks/firewall_stack.py": 2,     # libvirt network states, /proc
    "bob/checks/_run.py": 1,
    "bob/checks/_rootless_oci.py": 2,
    "bob/checks/_docker_daemon.py": 5,     # /proc ×4, a process's fds
    "bob/checks/docker_audit.py": 1,
    "bob/checks/kubernetes.py": 1,
    "bob/checks/file_integrity.py": 1,     # tripwire database
    "bob/checks/ssl_certs.py": 2,          # Let's Encrypt live, /etc/ssl/private
    "bob/checks/ssh/_parsers.py": 1,       # ~/.ssh
}


@pytest.mark.parametrize("rel", sorted(_SORTED_SCANS))
def test_every_ordered_scan_is_sorted(rel):
    src = (ROOT / rel).read_text(encoding="utf-8")
    code = "\n".join(line for line in src.splitlines() if not line.lstrip().startswith("#"))
    sorted_scans = len(re.findall(r"sorted\(\(?[^\n]*?\.iterdir\(\)", code))
    assert sorted_scans >= _SORTED_SCANS[rel], (rel, sorted_scans)


def test_no_process_scan_is_left_in_the_kernels_order():
    """/proc is read by process number everywhere."""
    for path in (ROOT / "bob").rglob("*.py"):
        src = path.read_text(encoding="utf-8")
        for m in re.finditer(r"[^\n]*(?:_PROC|Path\(\"/proc\"\))\.iterdir\(\)[^\n]*", src):
            line = m.group(0)
            if line.lstrip().startswith("#"):
                continue
            assert "sorted(" in line and "int(d.name)" in line, (path.relative_to(ROOT), line.strip())
