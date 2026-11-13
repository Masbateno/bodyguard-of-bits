"""v0.35.0 — a reboot a package asked for (/run/reboot-required) is said.

Measured on Linux Mint 22.3 (b50350, 12 November 2026): 0.34.0 already said
"Reboot pending" when the running kernel (7.0.0-34) was not the latest
installed (7.0.0-43) — on dpkg hosts. It did not read /run/reboot-required,
which a libc6 or dbus update writes with no new kernel. update-notifier-common
is not installed on Mint by default: libc6's postinst then writes nothing, so
the file's absence is no verdict. With it installed, the kernel install wrote
the file, listing "linux-base".
"""

from __future__ import annotations

from bob.checks.kernel_modules import KernelModulesSnapshot, _read_reboot_required, check_kernel_modules


def _keys(**kw):
    snap = KernelModulesSnapshot(lsmod_available=True, loaded_modules=[], **kw)
    return {f.key: f.message for f in check_kernel_modules(snap).findings}


def test_read_lists_each_package_once(tmp_path):
    f = tmp_path / "reboot-required"
    assert _read_reboot_required(f) == (False, [])
    f.write_text("*** System restart required ***\n")
    assert _read_reboot_required(f) == (True, [])
    (tmp_path / "reboot-required.pkgs").write_text("libc6\ndbus\nlibc6\n\n")
    assert _read_reboot_required(f) == (True, ["libc6", "dbus"])


def test_a_libc_reboot_is_said_with_its_package():
    got = _keys(reboot_required=True, reboot_required_pkgs=["libc6", "dbus"])
    assert "libc6, dbus" in got["kernel_modules.reboot_required"]


def test_unlisted_packages_still_say_the_reboot():
    got = _keys(reboot_required=True)
    assert got["kernel_modules.reboot_required"] == "kernel_modules.reboot_required_unlisted"


def test_no_file_says_nothing():
    assert "kernel_modules.reboot_required" not in _keys()


_MEASURED = dict(dpkg_available=True, running_kernel="7.0.0-34-generic",
                 installed_kernels=["7.0.0-34-generic", "7.0.0-43-generic"])


def test_the_measured_kernel_case_is_said_once():
    got = _keys(reboot_required=True, reboot_required_pkgs=["linux-base"], **_MEASURED)
    assert "kernel_modules.kernels_reboot_pending" in got
    assert "kernel_modules.reboot_required" not in got


def test_a_libc_reboot_beside_a_kernel_one_is_still_said():
    got = _keys(reboot_required=True, reboot_required_pkgs=["linux-base", "libc6"], **_MEASURED)
    assert "kernel_modules.kernels_reboot_pending" in got and "kernel_modules.reboot_required" in got


def test_linux_base_alone_without_a_kernel_line_is_said():
    got = _keys(reboot_required=True, reboot_required_pkgs=["linux-base"])
    assert "kernel_modules.reboot_required" in got


def test_from_system_reads_the_file(tmp_path, monkeypatch):
    from bob.checks import kernel_modules as K
    f = tmp_path / "reboot-required"
    f.write_text("x\n")
    (tmp_path / "reboot-required.pkgs").write_text("libc6\n")
    monkeypatch.setattr(K, "_REBOOT_REQUIRED", f)
    monkeypatch.setattr(K, "_command_exists", lambda n: False)
    monkeypatch.setattr(K, "_run", lambda *a, **kw: "")
    monkeypatch.setattr(K, "_query_apt_kernel_update", lambda: (False, False, ""))
    snap = K.KernelModulesSnapshot.from_system()
    assert (snap.reboot_required, snap.reboot_required_pkgs) == (True, ["libc6"])


# --- B5b: the reboot an rpm host's newer kernel waits for (Fedora 44, b5f0350)

_FEDORA = dict(running_kernel="6.19.10-300.fc44.x86_64",
               rpm_kernels=["6.19.10-300.fc44.x86_64", "7.3.3-200.fc44.x86_64"])


def test_the_measured_fedora_case_is_said():
    got = _keys(**_FEDORA)
    assert "7.3.3-200.fc44.x86_64" in got["kernel_modules.kernels_reboot_pending"]


def test_running_the_newest_says_nothing():
    got = _keys(running_kernel="7.3.3-200.fc44.x86_64", rpm_kernels=_FEDORA["rpm_kernels"])
    assert "kernel_modules.kernels_reboot_pending" not in got


def test_numbers_are_compared_as_numbers():
    got = _keys(running_kernel="6.9.1-100.fc44.x86_64",
                rpm_kernels=["6.9.1-100.fc44.x86_64", "6.10.0-100.fc44.x86_64"])
    assert "6.10.0-100.fc44.x86_64" in got["kernel_modules.kernels_reboot_pending"]


def test_a_kernel_rpm_does_not_manage_claims_nothing():
    got = _keys(running_kernel="6.20.0-custom", rpm_kernels=_FEDORA["rpm_kernels"])
    assert "kernel_modules.kernels_reboot_pending" not in got


def test_from_system_reads_rpm_where_dpkg_is_absent(monkeypatch):
    from bob.checks import kernel_modules as K
    monkeypatch.setattr(K, "_command_exists", lambda n: n == "rpm")
    outs = {("uname", "-r"): "6.19.10-300.fc44.x86_64\n",
            ("rpm", "-q", "kernel-core"): "6.19.10-300.fc44.x86_64\n7.3.3-200.fc44.x86_64\n"}
    monkeypatch.setattr(K, "_run", lambda *a, **kw: outs.get(a[:3] if a[0] == "rpm" else a[:2], ""))
    monkeypatch.setattr(K, "_query_apt_kernel_update", lambda: (False, False, ""))
    monkeypatch.setattr(K, "_read_reboot_required", lambda: (False, []))
    snap = K.KernelModulesSnapshot.from_system()
    assert snap.rpm_kernels == _FEDORA["rpm_kernels"] and snap.running_kernel == _FEDORA["running_kernel"]
