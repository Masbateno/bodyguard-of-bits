"""v0.37.0 — a rootless dockerd's containers are named, not shown by short ID.

0.36.0 read each rootless Docker container's OCI configuration through its
shim, and showed it by the 12 first characters of its ID: the shim carries the
ID, and the OCI config has no name (annotations null, hostname = the short ID,
measured). The name is in dockerd's own state,
``<data-root>/containers/<id>/config.v2.json`` (``"Name": "/rl-plain"``, owned
by the user, 0600). Measured on Linux Mint 22.3, docker 29.1.3 rootless +
rootlesskit 1.1.1 (a10370, 14 November 2026), `docker info` → DockerRootDir and
BOB's names, each variant with a fresh container:

| data root set by                         | DockerRootDir                 | BOB named   |
|------------------------------------------|-------------------------------|-------------|
| nothing                                  | /home/bobrl/.local/share/docker | rl-plain … |
| dockerd-rootless.sh --data-root …/dr-flag | /home/bobrl/dr-flag          | rl-v-flag   |
| ~/.config/docker/daemon.json data-root   | /home/bobrl/dr-json           | rl-v-json   |
| XDG_DATA_HOME=/home/bobrl/dr-xdg         | /home/bobrl/dr-xdg/docker     | rl-v-xdg    |

The file is the user's: read with the protections of the OCI config (regular
file of the user, no final symlink, ≤ 1 MiB), kept only if its ID is the
shim's and its name is one Docker could give; anything else keeps the short ID.
"""

from __future__ import annotations

import json
import os

from bob.checks import _rootless_oci as R

_ID = "8b3411482f8a8910e139dc25e8c6cee5217861c50ad3a6d23d000e5aab691593"


def _proc(tmp_path, pid, argv, uid, cwd=None, environ=None):
    d = tmp_path / "proc" / str(pid)
    d.mkdir(parents=True)
    (d / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")
    (d / "status").write_text(f"Name:\tx\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
    if cwd is not None:
        os.symlink(cwd, d / "cwd")
    os.symlink("/", d / "root")
    if environ is not None:
        (d / "environ").write_bytes(b"\0".join(f"{k}={v}".encode() for k, v in environ.items()) + b"\0")


def _bench(tmp_path, monkeypatch, name="/rl-plain", cid=_ID, dockerd_argv=("dockerd",), environ=None,
           daemon_json=None, data_root=None):
    home = tmp_path / "home" / "bobrl"
    root = data_root or (home / ".local" / "share" / "docker")
    cdir = root / "containers" / _ID
    cdir.mkdir(parents=True)
    (cdir / "config.v2.json").write_text(json.dumps({"ID": cid, "Name": name}))
    if daemon_json is not None:
        (home / ".config" / "docker").mkdir(parents=True)
        (home / ".config" / "docker" / "daemon.json").write_text(json.dumps(daemon_json))
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "config.json").write_text("{}")
    me = os.getuid()
    _proc(tmp_path, 20, ["/usr/bin/containerd-shim-runc-v2", "-namespace", "moby", "-id", _ID], me, cwd=bundle)
    _proc(tmp_path, 21, list(dockerd_argv), me, environ=environ if environ is not None else {"HOME": str(home)})
    monkeypatch.setattr(R, "_PROC", tmp_path / "proc")
    monkeypatch.setattr(R, "_cap_total", lambda: 41)
    return [c.name for c in R.rootless_containers()]


def test_the_default_data_root_gives_the_name(tmp_path, monkeypatch):
    assert _bench(tmp_path, monkeypatch) == ["rl-plain"]


def test_data_root_flag(tmp_path, monkeypatch):
    dr = tmp_path / "dr-flag"
    assert _bench(tmp_path, monkeypatch, dockerd_argv=("dockerd", "--data-root", str(dr)), data_root=dr) == ["rl-plain"]


def test_data_root_in_daemon_json(tmp_path, monkeypatch):
    dr = tmp_path / "dr-json"
    assert _bench(tmp_path, monkeypatch, daemon_json={"data-root": str(dr)}, data_root=dr) == ["rl-plain"]


def test_xdg_data_home(tmp_path, monkeypatch):
    dr = tmp_path / "dr-xdg"
    env = {"HOME": str(tmp_path / "home" / "bobrl"), "XDG_DATA_HOME": str(dr)}
    assert _bench(tmp_path, monkeypatch, environ=env, data_root=dr / "docker") == ["rl-plain"]


def test_a_name_docker_would_not_give_keeps_the_short_id(tmp_path, monkeypatch):
    assert _bench(tmp_path, monkeypatch, name="/\x1b[2Jowned") == [_ID[:12]]


def test_a_file_for_another_container_keeps_the_short_id(tmp_path, monkeypatch):
    assert _bench(tmp_path, monkeypatch, cid="0" * 64) == [_ID[:12]]


def test_a_file_of_another_owner_is_not_read(tmp_path, monkeypatch):
    monkeypatch.setattr(R, "_uid", lambda pid: os.getuid() + 1)
    monkeypatch.setattr("pwd.getpwuid", lambda uid: type("P", (), {"pw_name": "other"})())
    assert _bench(tmp_path, monkeypatch) == [_ID[:12]]


def test_an_id_that_is_not_one_is_never_a_path(tmp_path):
    # The shim's command line is the user's to write: "-id ../../x" would
    # otherwise walk out of containers/ to a file the user placed, whose ID
    # field can say the same.
    root = tmp_path / "b"
    (root / "containers").mkdir(parents=True)
    (tmp_path / "x").mkdir()
    (tmp_path / "x" / "config.v2.json").write_text(json.dumps({"ID": "../../x", "Name": "/planted"}))
    assert R.read_config(root / "containers" / "../../x" / "config.v2.json", os.getuid())  # the walk is real
    assert R._docker_name([root], os.getuid(), "../../x") is None
