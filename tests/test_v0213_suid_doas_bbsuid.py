"""doas and busybox-suid are standard SUID root, not "unexpected".

On Alpine, suid_audit flagged `/usr/bin/doas` (the standard sudo replacement,
SUID by design) and `/bin/bbsuid` (busybox's SUID helper) as unexpected SUID
binaries — a false positive, since both are the platform's normal privileged
tooling (v0.21.2 Alpine field pass). They are now in the known-safe set, so a
basename-based classification no longer flags them.
"""

from __future__ import annotations

import os

from bob.checks.suid_audit import _KNOWN_SUID


def test_doas_is_known_safe_suid():
    assert "doas" in _KNOWN_SUID


def test_bbsuid_is_known_safe_suid():
    assert "bbsuid" in _KNOWN_SUID


def test_the_classification_predicate_clears_them():
    """The from_system filter is exactly `basename(p) not in _KNOWN_SUID`; a doas
    or bbsuid path must therefore not be classified unexpected."""
    for path in ("/usr/bin/doas", "/bin/bbsuid"):
        assert os.path.basename(path) in _KNOWN_SUID
