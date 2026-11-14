"""v0.36.0 — installed kernels on any rpm host, read by their module directory.

0.35.0 read `rpm -q kernel-core --qf %{VERSION}-%{RELEASE}.%{ARCH}`: right on
Fedora, where that string is `uname -r`, and the limit it wrote down for
openSUSE. Measured in containers (14 November 2026):

| image          | package providing "kernel" | %{VERSION}-%{RELEASE}.%{ARCH} | module directory (= uname -r)          |
|----------------|----------------------------|-------------------------------|----------------------------------------|
| Fedora 44      | kernel-core                | 7.3.3-200.fc44.x86_64         | /lib/modules/7.3.3-200.fc44.x86_64     |
| openSUSE Leap 16.0 | kernel-default         | 6.12.0-160000.41.1.x86_64     | /usr/lib/modules/6.12.0-160000.41-default |

`rpm -q --whatprovides kernel --qf '[%{FILENAMES}\\n]'` lists both; the module
directory holding vmlinuz names the release as uname prints it.
"""

from __future__ import annotations

from bob.checks import kernel_modules as K

_SUSE = """/boot/.vmlinuz-6.12.0-160000.41-default.hmac
/boot/System.map-6.12.0-160000.41-default
/boot/vmlinuz-6.12.0-160000.41-default
/usr/lib/modules/6.12.0-160000.41-default
/usr/lib/modules/6.12.0-160000.41-default/vmlinuz
/boot/vmlinuz-6.12.0-160000.44-default
/usr/lib/modules/6.12.0-160000.44-default/vmlinuz
"""


def test_opensuse_kernel_default_is_read_in_uname_form():
    assert K._rpm_kernel_releases(_SUSE) == ["6.12.0-160000.41-default", "6.12.0-160000.44-default"]


def test_a_newer_opensuse_kernel_waiting_is_said():
    snap = K.KernelModulesSnapshot(dpkg_available=False, running_kernel="6.12.0-160000.41-default",
                                   rpm_kernels=K._rpm_kernel_releases(_SUSE))
    r = K.check_kernel_modules(snap, t=lambda k, **v: f"{k} {v}")
    f = next(f for f in r.findings if f.key == "kernel_modules.kernels_reboot_pending")
    assert "6.12.0-160000.44-default" in f.message


def test_only_a_kernel_image_names_a_kernel():
    """A module directory's vmlinuz, or /boot/vmlinuz-<release> (Leap 15.6,
    v0.37.0); not the bare /boot/vmlinuz link, not vmlinux.gz, not modules.dep."""
    text = ("/boot/vmlinuz\n/boot/vmlinux-6.4.0-150600.23.100-default.gz\n"
            "/usr/lib/modules/x/modules.dep\n/lib/modules/6.4.0-150600.23.100-default/kernel\n")
    assert K._rpm_kernel_releases(text) == []


def test_rpms_own_refusal_on_stdout_yields_nothing():
    assert K._rpm_kernel_releases("no package provides kernel\n") == []
    assert K._rpm_kernel_releases("") == []


def test_the_query_is_by_what_provides_kernel(monkeypatch):
    seen = []
    monkeypatch.setattr(K, "_command_exists", lambda n: n == "rpm")
    monkeypatch.setattr(K, "_run", lambda *a, **kw: seen.append(a) or "")
    monkeypatch.setattr(K, "_query_apt_kernel_update", lambda: (False, False, ""))
    monkeypatch.setattr(K, "_read_reboot_required", lambda: (False, []))
    K.KernelModulesSnapshot.from_system()
    assert ("rpm", "-q", "--whatprovides", "kernel", "--qf", "[%{FILENAMES}\\n]") in seen
