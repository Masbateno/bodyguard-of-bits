"""CIS benchmark reference lookup, loaded from data/cis_refs.json."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

_DATA_FILE = Path(__file__).parent / "data" / "cis_refs.json"


@lru_cache(maxsize=1)
def _load() -> dict[str, dict]:
    try:
        return json.loads(_DATA_FILE.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}


def get_cis_ref(key: str, lang: "str | None" = None) -> str | None:
    """Return the full CIS reference text for *key*, or None if not found.

    v0.11.2: locale-aware. ``Best practice`` entries (no formal CIS code)
    carry a French ``ref_fr`` translation; when the active locale is French
    and a ``ref_fr`` is present, it is returned. CIS-coded entries have no
    ``ref_fr`` — their canonical English benchmark titles are kept verbatim
    in every locale by design. ``lang`` defaults to the active interface
    language (resolved lazily to avoid an import cycle).
    """
    entry = _load().get(key)
    if entry is None:
        return None
    if lang is None:
        from bob.i18n import current_lang
        lang = current_lang()
    if lang == "fr":
        ref_fr = entry.get("ref_fr")
        if ref_fr:
            return ref_fr
    return entry.get("ref")


def get_cis_code(key: str) -> str | None:
    """Return the short machine-readable CIS code (e.g. 'CIS:5.2.7') or None."""
    entry = _load().get(key)
    if entry is None:
        return None
    return entry.get("code")


# ---------------------------------------------------------------------------
# The host's own benchmark (v0.42.0, B-043)
# ---------------------------------------------------------------------------

#: Release codenames a derivative names in /etc/os-release (``UBUNTU_CODENAME``,
#: ``DEBIAN_CODENAME``) → the version of the benchmark that covers its base.
#: Only releases a citation exists for; an unknown codename falls back.
_UBUNTU_CODENAMES = {"jammy": "22.04", "noble": "24.04"}
_DEBIAN_CODENAMES = {"bookworm": "12", "trixie": "13"}


def host_benchmark(os_release: "str | None" = None) -> "str | None":
    """The CIS benchmark label that covers this host, from /etc/os-release.

    Ubuntu and Debian by their ``VERSION_ID``; a derivative by the base it
    declares — Linux Mint 22 says ``UBUNTU_CODENAME=noble``, so CIS Ubuntu
    24.04; LMDE says ``DEBIAN_CODENAME=bookworm``, so CIS Debian 12. None when
    nothing says it (Kali, an unknown codename): never guessed.
    """
    text = _read_os_release() if os_release is None else os_release
    fields: "dict[str, str]" = {}
    for line in text.splitlines():
        name, sep, value = line.partition("=")
        if sep:
            fields[name.strip()] = value.strip().strip('"').strip("'")
    distro, version = fields.get("ID", ""), fields.get("VERSION_ID", "")
    if distro == "ubuntu" and version:
        return f"CIS Ubuntu {version}"
    if distro == "debian" and version:
        return f"CIS Debian {version.split('.')[0]}"
    if fields.get("UBUNTU_CODENAME") in _UBUNTU_CODENAMES:
        return f"CIS Ubuntu {_UBUNTU_CODENAMES[fields['UBUNTU_CODENAME']]}"
    if fields.get("DEBIAN_CODENAME") in _DEBIAN_CODENAMES:
        return f"CIS Debian {_DEBIAN_CODENAMES[fields['DEBIAN_CODENAME']]}"
    return None


@lru_cache(maxsize=1)
def _read_os_release() -> str:
    try:
        return Path("/etc/os-release").read_text(encoding="utf-8", errors="replace")[:8192]
    except OSError:
        return ""


def host_cis(key: str, lang: "str | None" = None,
             benchmark: "str | None" = None) -> "tuple[str | None, str | None]":
    """``(reference, code)`` to show for *key* on this host.

    v0.42.0 (B-043) — measured on the developer's workstation (Linux Mint 22.3,
    base Ubuntu 24.04): the screen cited "CIS Ubuntu 22.04 L1 — 5.2.7" while
    ``cis_refs.json`` holds the CIS Ubuntu 24.04 citation. Decided with the
    user: the host's own benchmark when a citation exists for it — generated
    from ComplianceAsCode like every other, never inferred — and the primary
    reference otherwise. *benchmark* overrides the host (tests).
    """
    entry = _load().get(key)
    if entry is None:
        return None, None
    label = benchmark if benchmark is not None else host_benchmark()
    cited = (entry.get("benchmarks") or {}).get(label) if label else None
    if cited and cited.get("code"):
        title = cited.get("title", "")
        return (f"{label} — {cited['code']} — {title}" if title else f"{label} — {cited['code']}",
                f"CIS:{cited['code']}")
    return get_cis_ref(key, lang), get_cis_code(key)


# ---------------------------------------------------------------------------
# Benchmark families — for grouping `--explain list` (v0.18.1)
# ---------------------------------------------------------------------------

#: Stable id for the best-practice family, whose display label is localised
#: ("Best practice" / "Bonne pratique") while every CIS family name is a
#: proper noun kept verbatim in both locales.
BEST_PRACTICE_FAMILY = "Best practice"

_LEVEL_SUFFIX = re.compile(r"\s+L[12]$")
_VERSION_SUFFIX = re.compile(r"\s+[0-9][0-9./]*$")
_PAREN_SUFFIX = re.compile(r"\s*\(.*\)$")


def _benchmark_label(ref: str) -> "str | None":
    """The full benchmark label a reference names, e.g. "CIS Ubuntu 22.04",
    "CIS Docker 1.6", "Best practice". The ref up to the em-dash, L1/L2 and a
    trailing ``(Samba)``-style qualifier stripped. Keeps the version."""
    if not ref:
        return None
    head = _PAREN_SUFFIX.sub("", ref.split(" — ", 1)[0].strip())
    head = _LEVEL_SUFFIX.sub("", head).strip()
    return head or None


def split_benchmark(label: str) -> "tuple[str, str]":
    """Split a benchmark label into (distro family, version).

        "CIS Ubuntu 22.04" -> ("CIS Ubuntu", "22.04")
        "CIS Debian 12"    -> ("CIS Debian", "12")
        "CIS Docker 1.6"   -> ("CIS Docker", "1.6")
        "CIS Red Hat 8/9"  -> ("CIS Red Hat", "8/9")
        "Best practice"    -> ("Best practice", "")
    """
    m = _VERSION_SUFFIX.search(label)
    if m:
        return label[: m.start()].strip(), m.group(0).strip()
    return label, ""


def benchmark_labels(key: str) -> "list[str]":
    """Every benchmark label a key carries a reference for — its primary
    ``ref`` plus any per-benchmark entries under ``benchmarks``."""
    entry = _load().get(key)
    if entry is None:
        return []
    labels = []
    primary = _benchmark_label(entry.get("ref", ""))
    if primary:
        labels.append(primary)
    for lbl in entry.get("benchmarks", {}):
        if lbl not in labels:
            labels.append(lbl)
    return labels


def benchmark_refs(key: str) -> "dict[str, dict]":
    """The per-benchmark ``{label: {code, title}}`` map added beyond the
    primary reference. Empty when the key has only its primary ref."""
    entry = _load().get(key)
    return dict(entry.get("benchmarks", {})) if entry else {}


def cis_family(key: str) -> "str | None":
    """The distro-level family a key belongs to, for the top-level grouping.

    v0.18.1: distro-level, not benchmark-version-level — "CIS Ubuntu 22.04"
    and a "CIS Ubuntu 24.04" reference both land in one "CIS Ubuntu" folder,
    the versions living one level down. Derived from the canonical English
    ``ref`` so grouping does not shift with the interface language.

        "CIS Ubuntu 22.04 L1 — …"  -> "CIS Ubuntu"
        "CIS Docker 1.6 — …"        -> "CIS Docker"
        "Best practice — …"         -> "Best practice"

    Returns None when the key has no reference entry at all.
    """
    label = _benchmark_label(_load().get(key, {}).get("ref", "")) if _load().get(key) else None
    if label is None:
        return None
    if label.startswith(BEST_PRACTICE_FAMILY):
        return BEST_PRACTICE_FAMILY
    return split_benchmark(label)[0]


def cis_family_sort_key(family: str) -> "tuple[int, str]":
    """Order distro families for display: CIS Ubuntu first (the primary
    benchmark), then the other CIS families alphabetically, then Best practice
    last. A family added later slots in among the CIS families by name.
    """
    if family == "CIS Ubuntu":
        return (0, "")
    if family == BEST_PRACTICE_FAMILY:
        return (2, "")
    return (1, family)


#: The official CIS benchmark landing page per distro family. Each URL was
#: verified to resolve (HTTP 200) against www.cisecurity.org; the pages are
#: per-distribution, covering every version BOB cites under that family. Best
#: practice is BOB-authored and has no CIS resource, so it is absent here.
CIS_BENCHMARK_URLS = {
    "CIS Ubuntu": "https://www.cisecurity.org/benchmark/ubuntu_linux",
    "CIS Debian": "https://www.cisecurity.org/benchmark/debian_linux",
    "CIS Docker": "https://www.cisecurity.org/benchmark/docker",
    "CIS Red Hat": "https://www.cisecurity.org/benchmark/red_hat_linux",
    "CIS Kubernetes": "https://www.cisecurity.org/benchmark/kubernetes",
}


def cis_benchmark_url(family: str) -> "str | None":
    """The online CIS benchmark page for a distro *family*, or None.

    None for Best practice (BOB-authored, no CIS resource) and for any family
    without a verified CIS page.
    """
    return CIS_BENCHMARK_URLS.get(family)
