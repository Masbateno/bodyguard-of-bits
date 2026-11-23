"""v0.43.0 — packaged files with no recorded digest are said, not counted as compared (B-046).

Measured in a Mint 22.3 container (dpkg 1.22.6, debsums 3.0.2.1, 22 November
2026), each file modified after the change:

- digest present (control): ``dpkg --verify`` prints ``??5??????`` and debsums
  -c the path;
- the file's line removed from the package's ``.md5sums``: both silent;
- no ``.md5sums`` at all: both silent (debsums -c says "no md5sums for less" on
  stderr only);
- a ``.md5sums`` with absolute paths: both see the change, but debsums prints
  ``//usr/bin/zcat``.

On the developer's workstation (3085 packages): no package without digests,
two with files left out — aspell-en (23, rewritten by its install script) and a
third-party office suite (8). ``package_integrity.clean`` stays true to the
letter ("no file differs from the recorded digest"); an INFO line names what
nothing compared.
"""

from __future__ import annotations

from bob.checks import package_integrity as pi
from bob.checks.package_integrity import (
    PackageIntegritySnapshot,
    _dpkg_undigested,
    _parse_debsums,
    check_package_integrity,
)
from bob.visibility import VISIBILITY_KEYS


def _db(tmp_path, packages):
    """A fake dpkg database. ``packages``: name → dict(status, arch, files,
    digests (None = no .md5sums), conffiles, multiarch, absolute)."""
    info = tmp_path / "info"
    info.mkdir()
    root = tmp_path / "root"
    root.mkdir()
    stanzas = []
    for name, spec in packages.items():
        arch = spec.get("arch", "amd64")
        stanza = [f"Package: {name}", f"Status: {spec.get('status', 'install ok installed')}",
                  f"Architecture: {arch}"]
        if spec.get("conffiles"):
            stanza.append("Conffiles:")
            stanza += [f" {c} 0123456789abcdef0123456789abcdef" for c in spec["conffiles"]]
        stanzas.append("\n".join(stanza))
        base = f"{name}:{arch}" if spec.get("multiarch") else name
        listed = ["/."]
        for rel in spec.get("files", ()):
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("x")
            listed.append(str(p))
        listed += spec.get("extra_listed", [])
        (info / f"{base}.list").write_text("\n".join(listed) + "\n")
        digests = spec.get("digests")
        if digests is not None:
            lines = []
            for rel in digests:
                path = str(root / rel)
                path = path if spec.get("absolute") else path.lstrip("/")
                lines.append(f"0123456789abcdef0123456789abcdef  {path}")
            (info / f"{base}.md5sums").write_text("\n".join(lines) + "\n")
    status = tmp_path / "status"
    status.write_text("\n\n".join(stanzas) + "\n")
    return str(status), str(info), root


def test_a_file_left_out_of_the_digests_is_counted(tmp_path):
    status, info, _ = _db(tmp_path, {"aspell-en": {"files": ["a", "b", "c"], "digests": ["a"]}})
    assert _dpkg_undigested(status, info) == {"aspell-en": 2}


def test_a_package_with_no_digests_counts_every_regular_file(tmp_path):
    status, info, _ = _db(tmp_path, {"less": {"files": ["bin/less", "bin/lessecho"], "digests": None}})
    assert _dpkg_undigested(status, info) == {"less": 2}


def test_digests_written_with_absolute_paths_still_cover(tmp_path):
    status, info, _ = _db(tmp_path, {"thirdparty": {"files": ["a", "b"], "digests": ["a", "b"], "absolute": True}})
    assert _dpkg_undigested(status, info) == {}


def test_fully_covered_packages_give_nothing(tmp_path):
    status, info, _ = _db(tmp_path, {"hostname": {"files": ["bin/hostname"], "digests": ["bin/hostname"]}})
    assert _dpkg_undigested(status, info) == {}


def test_directories_symlinks_missing_files_etc_and_conffiles_are_left_out(tmp_path):
    status, info, root = _db(tmp_path, {"pkg": {
        "files": ["share/doc"], "digests": ["share/doc"],
        "extra_listed": ["/etc/passwd", "/nonexistent/bob-b046-gone", str(tmp_path)],
    }})
    (root / "link").symlink_to(root / "share" / "doc")
    with open(f"{info}/pkg.list", "a") as fh:
        fh.write(str(root / "link") + "\n")
    assert _dpkg_undigested(status, info) == {}


def test_a_conffile_outside_etc_is_left_out(tmp_path):
    status, info, root = _db(tmp_path, {"pkg": {"files": ["conf/x.conf"], "digests": []}})
    text = open(status).read().replace("Architecture: amd64",
                                       f"Architecture: amd64\nConffiles:\n {root / 'conf' / 'x.conf'} 0123 ")
    open(status, "w").write(text)
    assert _dpkg_undigested(status, info) == {}


def test_a_package_not_installed_is_ignored(tmp_path):
    status, info, _ = _db(tmp_path, {"old": {"files": ["x"], "digests": None,
                                             "status": "deinstall ok config-files"}})
    assert _dpkg_undigested(status, info) == {}


def test_a_multiarch_package_is_found_under_its_qualified_name(tmp_path):
    status, info, _ = _db(tmp_path, {"libfoo": {"files": ["lib/libfoo.so"], "digests": None, "multiarch": True}})
    assert _dpkg_undigested(status, info) == {"libfoo": 1}


def test_an_unreadable_database_is_not_counted_never_none(tmp_path):
    assert _dpkg_undigested(str(tmp_path / "absent"), str(tmp_path)) is None


def _render(undigested, checked=True):
    snap = PackageIntegritySnapshot(manager="apt", tool="dpkg", tool_available=True, ran=True,
                                    undigested_checked=checked, undigested=undigested)
    return check_package_integrity(snap).findings


def test_files_with_no_digest_are_said_beside_the_clean_line():
    findings = _render({"onlyoffice-desktopeditors": 8, "aspell-en": 23})
    assert [f.key for f in findings] == ["package_integrity.clean", "package_integrity.no_digest"]
    line = findings[1]
    assert line.level.name == "INFO"
    assert line.key not in VISIBILITY_KEYS  # the section was read: the score stays certain
    assert "aspell-en (23), onlyoffice-desktopeditors (8)" in line.message


def test_the_unread_database_is_said():
    assert [f.key for f in _render(None)][-1] == "package_integrity.no_digest_not_counted"


def test_nothing_is_added_when_every_file_has_a_digest_or_nothing_was_checked():
    assert [f.key for f in _render({})] == ["package_integrity.clean"]
    assert [f.key for f in _render(None, checked=False)] == ["package_integrity.clean"]


def test_the_package_list_is_bounded():
    many = {f"p{i:02d}": 1 for i in range(11)}
    message = _render(many)[-1].message
    # identity translation outside the CLI: the suffix shows as its key
    assert "p07 (1)" in message and "p08 (" not in message and "output.more_items count=3" in message


def test_only_apt_hosts_count(monkeypatch):
    calls = []
    monkeypatch.setattr(pi, "_dpkg_undigested", lambda *a: calls.append(1) or {})
    monkeypatch.setattr(pi, "_command_exists", lambda tool: True)
    monkeypatch.setattr(pi, "_run_capped", lambda args: ("", True, False, True))
    for mgr, expected in (("apt", 1), ("dnf", 0)):
        calls.clear()
        monkeypatch.setattr(pi, "detect_install_manager", lambda m=mgr: m)
        snap = PackageIntegritySnapshot.from_system()
        assert len(calls) == expected and snap.undigested_checked == bool(expected)


def test_debsums_double_slash_is_brought_back_to_one():
    assert _parse_debsums("//usr/bin/zcat\n//etc/gzip.conf\n/usr/bin/cmp\n") == ["/usr/bin/zcat", "/usr/bin/cmp"]
