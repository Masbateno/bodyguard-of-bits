"""v0.25.0 — fixes written for the host's init system, and that actually fix.

A sweep of the printed commands for a hard-coded ``systemctl``, measured on an
Alpine 3.22 VM (OpenRC, doas) and in Debian 13 / Fedora 43 containers:

  - CUPS listening on the network: ``systemctl restart cups`` on Alpine, whose
    service is ``cupsd``; and the first half, ``cupsctl --no-remote-any``,
    exited 0 and changed nothing for a hand-written ``Listen 0.0.0.0:631`` on
    all three (it rewrites the file only when one of its settings changes),
    and answered "Forbidden" to root on Alpine (SystemGroup lpadmin);
  - Docker userns-remap: ``systemctl restart docker`` on Alpine; ``tee`` into
    an /etc/docker that does not exist; and with the directory there, dockerd
    "Can't create ID mappings: open /etc/subuid" — stopped, while OpenRC said
    "started" and the command exited 0;
  - AppArmor: ``systemctl enable --now apparmor`` (not reached on Alpine, whose
    kernel carries AppArmor switched off — the kernel finding answers first).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bob.checks import _run, cups, docker_audit
from bob.checks.cups import CupsSnapshot, _listen_fix, check_cups
from bob.checks.docker_audit import _DOCKREMAP_USER


@pytest.fixture
def openrc(monkeypatch):
    monkeypatch.setattr(_run, "openrc_available", lambda: True)
    monkeypatch.setattr(_run, "_command_exists", lambda c: c != "systemctl")
    monkeypatch.setattr(cups, "openrc_available", lambda: True)
    monkeypatch.setattr(cups, "_command_exists", lambda c: c != "systemctl")
    monkeypatch.setattr(cups, "path_exists", lambda p: str(p) == "/etc/init.d/cupsd")


@pytest.fixture
def systemd(monkeypatch):
    monkeypatch.setattr(_run, "openrc_available", lambda: False)
    monkeypatch.setattr(_run, "_command_exists", lambda c: True)
    monkeypatch.setattr(cups, "openrc_available", lambda: False)


class TestCupsListen:
    def _cmd(self, *values):
        return next(f.cmd for f in check_cups(CupsSnapshot(cfg_present=True, listen_values=list(values),
                                                           listens_non_loopback=True)).findings
                    if f.key == "cups.listen_exposed")

    def test_openrc_restarts_cupsd(self, openrc):
        assert self._cmd("0.0.0.0:631").endswith("sudo rc-service cupsd restart")

    def test_systemd_restarts_cups(self, systemd):
        assert self._cmd("0.0.0.0:631").endswith("sudo systemctl restart cups")

    def test_no_cupsctl(self, systemd):
        """cupsctl --no-remote-any left a hand-written Listen in place, exit 0."""
        assert "cupsctl" not in self._cmd("0.0.0.0:631")

    def test_only_the_exposed_lines_go(self, systemd):
        cmd = _listen_fix(["localhost:631", "/run/cups/cups.sock", "0.0.0.0:631", "Port 8631"])
        assert "0\\.0\\.0\\.0:631" in cmd and "[Pp][Oo][Rr][Tt][[:space:]]+8631" in cmd
        assert "localhost" not in cmd.split(" && ")[0]            # the sed removes nothing local
        assert "Listen localhost:631" in cmd and "Listen localhost:8631" in cmd

    def test_nothing_exposed_no_command(self):
        assert _listen_fix(["localhost:631", "/run/cups/cups.sock"]) is None

    @pytest.mark.parametrize("value", ["ev$il:631", "a;b:631", "x'y:631", "host:63a"])
    def test_an_unexpected_operand_gets_no_command(self, value):
        assert _listen_fix([value]) is None

    @pytest.mark.parametrize("form, line", [
        ("Listen 0.0.0.0:631", "Listen 0.0.0.0:631"),
        ("Listen *:631", "Listen *:631   # all interfaces"),
        ("Port 631", "Port 631"),
        ("Listen [::]:631", "  listen [::]:631"),
    ])
    def test_the_command_rewrites_the_file(self, tmp_path, monkeypatch, systemd, form, line):
        """The sed and grep halves run here against a copy of the file, as on
        Alpine where all three measured forms ended on 127.0.0.1/::1 only."""
        import subprocess
        conf = tmp_path / "cupsd.conf"
        conf.write_text(f"LogLevel warn\n{line}\nListen /run/cups/cups.sock\n<Location />\n  Order allow,deny\n</Location>\n")
        monkeypatch.setattr(cups, "_CUPSD_CONF", str(conf))
        snap = CupsSnapshot.from_system()
        cmd = _listen_fix(snap.listen_values)
        edit = cmd.rsplit(" && ", 1)[0].replace("sudo ", "")      # not the restart
        subprocess.run(["sh", "-c", edit], check=True, timeout=30)
        after = CupsSnapshot.from_system()
        assert not after.listens_non_loopback, conf.read_text()
        assert "localhost:631" in after.listen_values
        once = conf.read_text()
        subprocess.run(["sh", "-c", edit], check=True, timeout=30)       # applied twice
        assert conf.read_text() == once


class TestDockerUserns:
    def _cmd(self):
        from bob.checks.docker_audit import DockerAuditSnapshot, check_docker_audit
        snap = DockerAuditSnapshot(runtime="docker", docker_installed=True, userns_remap=False,
                                   running_count=1)
        return next(f.cmd for f in check_docker_audit(snap).findings
                    if f.key == "docker_hardening.userns_not_configured")

    def test_openrc(self, openrc):
        assert self._cmd().endswith("sudo rc-service docker restart; }")

    def test_systemd(self, systemd):
        assert self._cmd().endswith("sudo systemctl restart docker; }")

    def test_the_directory_and_the_id_ranges_come_first(self, systemd):
        cmd = self._cmd()
        assert cmd.index("mkdir -p /etc/docker") < cmd.index("tee /etc/docker/daemon.json")
        assert cmd.index("^dockremap:' /etc/subuid") < cmd.index("restart docker")
        assert cmd.index("^dockremap:' /etc/subgid") < cmd.index("restart docker")

    def test_the_user_comes_before_the_restart(self, systemd):
        cmd = self._cmd()
        assert cmd.index("id dockremap") < cmd.index("restart docker")
        assert "useradd -r -U -M -s /bin/false dockremap" in cmd
        assert "adduser -S -D -H -G dockremap -s /bin/false dockremap" in cmd

    def test_the_user_step_picks_the_tool_there_is(self, tmp_path):
        """Run against stand-ins: no useradd -> BusyBox addgroup + adduser;
        an existing dockremap -> nothing."""
        import subprocess
        log = tmp_path / "calls"
        for name, body in {"sudo": 'exec "$@"', "addgroup": f'echo "addgroup $*" >> {log}',
                           "adduser": f'echo "adduser $*" >> {log}', "id": "exit 1"}.items():
            (tmp_path / name).write_text(f"#!/bin/sh\n{body}\n")
            (tmp_path / name).chmod(0o755)
        env = {"PATH": f"{tmp_path}:/bin:/usr/bin"}
        if any(Path(d, "useradd").exists() for d in ("/bin", "/usr/bin")):
            pytest.skip("a real useradd on /bin or /usr/bin would be picked")
        subprocess.run(["sh", "-c", _DOCKREMAP_USER], check=True, env=env, timeout=30)
        assert log.read_text().splitlines() == ["addgroup -S dockremap",
                                                "adduser -S -D -H -G dockremap -s /bin/false dockremap"]
        (tmp_path / "id").write_text("#!/bin/sh\nexit 0\n")
        log.unlink()
        subprocess.run(["sh", "-c", _DOCKREMAP_USER], check=True, env=env, timeout=30)
        assert not log.exists()

    def test_the_command_runs_where_nothing_exists(self, tmp_path, systemd):
        """Run with the paths moved into a sandbox: the first run writes
        daemon.json and both range files, the second changes nothing."""
        import subprocess
        cmd = (self._cmd().replace(_DOCKREMAP_USER, "true").replace("/etc/", f"{tmp_path}/etc/")
               .replace("sudo ", "").replace("systemctl restart docker", "true"))
        (tmp_path / "etc").mkdir()
        subprocess.run(["sh", "-c", cmd], check=True, timeout=30)
        assert (tmp_path / "etc/docker/daemon.json").read_text().strip() == '{"userns-remap": "default"}'
        assert (tmp_path / "etc/subuid").read_text() == "dockremap:100000:65536\n"
        assert (tmp_path / "etc/subgid").read_text() == "dockremap:100000:65536\n"
        (tmp_path / "etc/docker/daemon.json").unlink()
        subprocess.run(["sh", "-c", cmd], check=True, timeout=30)
        assert (tmp_path / "etc/subuid").read_text() == "dockremap:100000:65536\n"   # not twice

    def test_a_range_already_taken_is_not_reused(self, tmp_path, systemd):
        """Measured on Mint 22.3, docker 29.1.3: left to docker, dockremap got
        100000:65536 - so6's range. BOB writes the next free one."""
        import subprocess
        cmd = (self._cmd().replace(_DOCKREMAP_USER, "true").replace("/etc/", f"{tmp_path}/etc/")
               .replace("sudo ", "").replace("systemctl restart docker", "true"))
        (tmp_path / "etc").mkdir()
        for name in ("subuid", "subgid"):
            (tmp_path / f"etc/{name}").write_text("so6:100000:65536\nalice:165536:65536\n")
        subprocess.run(["sh", "-c", cmd], check=True, timeout=30)
        for name in ("subuid", "subgid"):
            assert (tmp_path / f"etc/{name}").read_text().splitlines()[-1] == "dockremap:231072:65536"


class TestAppArmorEnable:
    """Only an apt host gets a command here (the apparmor-utils step is
    Debian's), so OpenRC matters for apt + OpenRC (Devuan can run it). Not
    measured — by construction: the same helper as the measured services."""

    def test_apt_under_openrc(self, openrc, monkeypatch):
        monkeypatch.setattr(_run, "detect_install_manager", lambda: "apt")
        from bob.checks.mac_policy import MacPolicySnapshot, check_mac_policy
        f = next(f for f in check_mac_policy(MacPolicySnapshot()).findings if f.key == "mac_policy.no_mac")
        assert "systemctl" not in f.cmd
        assert "sudo rc-update add apparmor default && sudo rc-service apparmor start" in f.cmd

    def test_apt_under_systemd(self, systemd, monkeypatch):
        monkeypatch.setattr(_run, "detect_install_manager", lambda: "apt")
        from bob.checks.mac_policy import MacPolicySnapshot, check_mac_policy
        f = next(f for f in check_mac_policy(MacPolicySnapshot()).findings if f.key == "mac_policy.no_mac")
        assert "sudo systemctl enable --now apparmor" in f.cmd


def test_docker_audit_still_imports_the_restart_helper():
    assert docker_audit.service_restart_cmd is _run.service_restart_cmd
