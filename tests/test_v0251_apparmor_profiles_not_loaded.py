"""v0.25.1 — AppArmor profiles installed but not loaded: start the service.

Measured on Alpine 3.24 (OpenRC): AppArmor live in the kernel, 145 profile
files in /etc/apparmor.d, none loaded because the `apparmor` service had not
been started. BOB told the operator to install the profile packages that were
already installed, and said it did not know the apk package name. The printed
fix `rc-update add apparmor boot && rc-service apparmor start`, applied as
printed through doas, loaded 161 profiles (78 enforce, 5 complain); the WARN
cleared, and held after a reboot.
"""

from bob.checks.mac_policy import MacPolicySnapshot, check_mac_policy


def _snap(**kw):
    base = dict(apparmor_installed=True, apparmor_active=True, apparmor_enforcing=0,
                apparmor_complain=0, apparmor_profiles_readable=True)
    base.update(kw)
    return MacPolicySnapshot(**base)


def _finding(result):
    return next(f for f in result.findings if f.key == "mac_policy.apparmor_no_profiles")


def test_unloaded_profiles_ask_for_the_service(monkeypatch):
    monkeypatch.setattr("bob.checks.mac_policy.service_enable_cmd",
                        lambda unit, runlevel="default": f"sudo rc-update add {unit} {runlevel} && sudo rc-service {unit} start")
    f = _finding(check_mac_policy(_snap(apparmor_profiles_on_disk=145, apparmor_service_state="stopped")))
    assert "rc-update add apparmor boot" in f.cmd
    assert "apparmor_profiles_not_loaded_detail" in f.detail and "145" in f.detail


def test_no_profile_on_disk_still_asks_for_packages():
    f = _finding(check_mac_policy(_snap(apparmor_profiles_on_disk=0, apparmor_service_state=None)))
    assert "rc-update" not in (f.cmd or "") and "systemctl enable" not in (f.cmd or "")


def test_the_apk_package_name_is_known():
    from bob.checks._run import package_name
    assert package_name("apparmor-profiles", "apk") == "apparmor-profiles"
