"""v0.31.0 — the anonymous Kubernetes probes go only to the kubelet and the API server.

pkgradar flagged `ssl.CERT_NONE` in bob/checks/kubernetes.py (4 November
2026). The probes are anonymous and aimed at 127.0.0.1 only, and the
kubelet's own certificate is self-signed, so they do not verify it — and
whatever held the port was answered. Measured in a network namespace
(`~/.cache/bob-fieldtest/netnsbench/kspoof.sh`, `kspoof-root.txt`): a
server with a self-signed certificate on 127.0.0.1:10250 answering 401 made
0.30.0 read "the kubelet requires authentication" (`kubelet_auth_ok`, OK).
Decided with the maintainer: check who holds the port before asking.

| server on 127.0.0.1:10250 | 0.30.0 | now |
|---|---|---|
| python3, as root | asked: "requires authentication" | not asked: held by python3 |
| named kubelet, as uid 1000 | asked: "requires authentication" | not asked: held by kubelet (uid 1000) |
| named kubelet, as root | asked | asked |

A process of a kubelet's (or an API server's) name run by root is asked: the
kubelet, kubelite, k3s and kube-apiserver run as root, and a root attacker has
no need to deceive BOB.

After review: every user id is read (real, effective, saved, filesystem — the
first alone let an effective root, or a process that dropped root, pass
either way); every owner of every socket that may take the connection counts
(SO_REUSEPORT: measured, two lines); ``[::]`` as ss shows it is IPv6-only and
does not take 127.0.0.1 (measured `ssforms.txt`; a dual-stack one shows as
``*``); a user that could not be read is said as such.
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.checks import kubernetes as k
from bob.checks._run import CommandResult
from bob.visibility import is_visibility_key

SS = 'LISTEN 0 4096 {addr}:{port} 0.0.0.0:* users:(("{name}",pid={pid},fd=3))'


def _ss(monkeypatch, lines, ok=True, uids=None):
    monkeypatch.setattr(k, "run_result", lambda *a, **kw: CommandResult(stdout="\n".join(lines) + "\n", ok=ok))
    uids = uids or {}

    def owner(name, pid):
        uid = uids.get(pid, "0")
        return f"{name} (uid ?)" if uid is None else name if uid == "0" else f"{name} (uid {uid})"
    monkeypatch.setattr(k, "_owner", owner)


class TestWhoHoldsThePort:

    @pytest.mark.parametrize("lines, owners", [
        ([SS.format(addr="127.0.0.1", port=10250, name="kubelet", pid=1)], ["kubelet"]),
        ([SS.format(addr="*", port=10250, name="kubelet", pid=1)], ["kubelet"]),
        ([SS.format(addr="0.0.0.0", port=10250, name="kubelite", pid=1)], ["kubelite"]),
        ([SS.format(addr="[::ffff:127.0.0.1]", port=10250, name="k3s", pid=1)], ["k3s"]),
        ([SS.format(addr="[::]", port=10250, name="k3s-server", pid=1)], []),
        ([SS.format(addr="0.0.0.0", port=10250, name="kubelet", pid=1),
          SS.format(addr="127.0.0.1", port=10250, name="python3", pid=2)], ["python3"]),
        ([SS.format(addr="192.0.2.5", port=10250, name="kubelet", pid=1)], []),
        ([SS.format(addr="[::1]", port=10250, name="kubelet", pid=1)], []),
        ([], []),
        (["LISTEN 0 4096 127.0.0.1:10250 0.0.0.0:*"], None),
        (["LISTEN 0 4096 0.0.0.0:10250 0.0.0.0:*",
          SS.format(addr="127.0.0.1", port=10250, name="kubelet", pid=1)], ["kubelet"]),
        ([SS.format(addr="0.0.0.0", port=10250, name="kubelet", pid=1),
          "LISTEN 0 4096 0.0.0.0:10250 0.0.0.0:*"], None),
    ], ids=["loopback", "any", "all-v4", "v4-mapped-loopback", "v6-only", "the-loopback-socket-wins",
            "another-address", "v6-loopback", "none", "owner-not-shown",
            "a-hidden-owner-the-loopback-socket-beats", "a-hidden-owner-beside"])
    def test_it(self, monkeypatch, lines, owners):
        _ss(monkeypatch, lines)
        assert k._loopback_listener(10250) == owners

    def test_ss_failed(self, monkeypatch):
        _ss(monkeypatch, [], ok=False)
        assert k._loopback_listener(10250) is None

    def test_a_process_not_run_by_root(self, monkeypatch):
        _ss(monkeypatch, [SS.format(addr="127.0.0.1", port=10250, name="kubelet", pid=7)], uids={"7": "1000"})
        assert k._loopback_listener(10250) == ["kubelet (uid 1000)"]

    def test_a_user_not_read(self, monkeypatch):
        _ss(monkeypatch, [SS.format(addr="127.0.0.1", port=10250, name="kubelet", pid=7)], uids={"7": None})
        assert k._loopback_listener(10250) == ["kubelet (uid ?)"]

    def test_every_socket_sharing_the_port(self, monkeypatch):
        """SO_REUSEPORT: measured, two lines for one port."""
        _ss(monkeypatch, [SS.format(addr="127.0.0.1", port=10250, name="kubelet", pid=1),
                          SS.format(addr="127.0.0.1", port=10250, name="kubelet", pid=2)], uids={"2": "1000"})
        assert k._loopback_listener(10250) == ["kubelet", "kubelet (uid 1000)"]

    def test_every_process_sharing_a_socket(self, monkeypatch):
        line = 'LISTEN 0 4096 127.0.0.1:10250 0.0.0.0:* users:(("kubelet",pid=1,fd=3),("python3",pid=2,fd=4))'
        _ss(monkeypatch, [line])
        assert k._loopback_listener(10250) == ["kubelet", "python3"]

    @pytest.mark.parametrize("status, owner", [
        ("Name:\tkubelet\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n", "kubelet"),
        ("Name:\tkubelet\nUid:\t1000\t1000\t1000\t1000\n", "kubelet (uid 1000)"),
        ("Name:\tkubelet\nUid:\t1000\t0\t0\t0\n", "kubelet (uid 0)"),
        ("Name:\tkubelet\nUid:\t0\t1000\t0\t1000\n", "kubelet (uid 1000)"),
        ("Name:\tkubelet\nUid:\t0\t0\t1000\t0\n", "kubelet (uid 0)"),
        ("Name:\tkubelet\nUid:\t0\t0\t0\t1000\n", "kubelet (uid 0)"),
        ("Name:\tkubelet\nUid:\t0\n", "kubelet (uid ?)"),
        ("Name:\tkubelet\n", "kubelet (uid ?)"),
        (None, "kubelet (uid ?)"),
    ], ids=["root", "a-user", "effective-root-of-a-user", "root-dropped-to-a-user", "saved-user",
            "filesystem-user", "a-short-line", "no-uid-line", "gone"])
    def test_the_owner(self, monkeypatch, status, owner):
        class P:
            def __init__(self, path):
                pass

            def read_text(self, **kw):
                if status is None:
                    raise FileNotFoundError("gone")
                return status
        monkeypatch.setattr(k, "Path", P)
        assert k._owner("kubelet", "7") == owner

    @pytest.mark.parametrize("owners, deciding", [
        (None, None), ([], ""), (["kubelet"], "kubelet"), (["kubelet", "kubelet"], "kubelet"),
        (["kubelet", "python3"], "python3"), (["kubelet", "kubelet (uid 1000)"], "kubelet (uid 1000)"),
        (["kubelet (uid ?)", "python3"], "kubelet (uid ?)"),
    ], ids=["unknown", "none", "one", "two-kubelets", "a-stranger-beside", "a-user-beside", "the-first-stranger"])
    def test_the_deciding_owner(self, owners, deciding):
        assert k._deciding(owners, k._KUBELET_NAMES) == deciding


class TestOnlyTheKubeletIsAsked:

    @staticmethod
    def _snap(monkeypatch, held):
        asked = []
        monkeypatch.setattr(k, "kubelet_running", lambda: True)
        monkeypatch.setattr(k, "_ctr_command", lambda: None)
        monkeypatch.setattr(k, "_command_exists", lambda n: False)
        monkeypatch.setattr(k, "_read_apiserver", lambda snap: None)
        monkeypatch.setattr(k, "_runtime_socket", lambda: None)
        monkeypatch.setattr(k, "_loopback_listener", lambda port: held.get(port, []))
        monkeypatch.setattr(k, "_probe", lambda url: asked.append(url) or 401)
        return k.KubernetesSnapshot.from_system(), asked

    def test_the_kubelet(self, monkeypatch):
        snap, asked = self._snap(monkeypatch, {10250: ["kubelet"], 10255: ["kubelet"]})
        assert snap.anonymous_status == 401 and len(asked) == 2

    @pytest.mark.parametrize("owners, said", [
        (["python3"], "python3"), (["kubelet (uid 1000)"], "kubelet (uid 1000)"), (None, None),
        (["kubelet (uid ?)"], "kubelet (uid ?)"), (["kubelet", "python3"], "python3"),
    ], ids=["a-stranger", "a-user", "unknown", "unverified", "a-stranger-sharing-the-port"])
    def test_another_process(self, monkeypatch, owners, said):
        snap, asked = self._snap(monkeypatch, {10250: owners, 10255: owners})
        assert snap.anonymous_status is None and asked == [] and not snap.run_probed
        assert snap.kubelet_listener == said

    def test_the_api_server(self, tmp_path, monkeypatch):
        args = tmp_path / "kube-apiserver"
        args.write_text("--secure-port=16443\n", encoding="utf-8")
        monkeypatch.setattr(k, "_MICROK8S_APISERVER_ARGS", args)
        monkeypatch.setattr(k, "_command_exists", lambda n: False)
        asked = []
        monkeypatch.setattr(k, "_probe", lambda url: asked.append(url) or 401)
        for owners, said, probed in ((["kubelite"], "kubelite", True), (["python3"], "python3", False),
                                     (None, None, False), ([], "", False),
                                     (["kubelite", "kubelite (uid 1000)"], "kubelite (uid 1000)", False)):
            asked.clear()
            monkeypatch.setattr(k, "_loopback_listener", lambda port, o=owners: o)
            snap = k.KubernetesSnapshot(kubelet_running=True)
            k._read_apiserver(snap)
            assert (snap.apiserver_anonymous_status == 401) is probed and bool(asked) is probed
            assert snap.apiserver_listener == said


class TestWhatIsSaid:

    @staticmethod
    def _keys(snap):
        r = k.check_kubernetes(snap, t=i18n.t)
        return {f.key: f.message for f in r.findings}

    def test_held_by_another(self):
        said = self._keys(k.KubernetesSnapshot(kubelet_running=True, kubelet_listener="python3"))
        assert "kubernetes.kubelet_listener_foreign" in said and "python3" in said["kubernetes.kubelet_listener_foreign"]
        assert "kubernetes.kubelet_auth_ok" not in said and "kubernetes.kubelet_unprobed" not in said

    def test_held_by_a_process_bob_could_not_name(self):
        said = self._keys(k.KubernetesSnapshot(kubelet_running=True, kubelet_listener=None))
        assert "kubernetes.kubelet_listener_unknown" in said

    def test_held_by_a_process_whose_user_bob_could_not_read(self):
        said = self._keys(k.KubernetesSnapshot(kubelet_running=True, kubelet_listener="kubelet (uid ?)"))
        assert set(said) & {"kubernetes.kubelet_listener_unverified", "kubernetes.kubelet_listener_foreign",
                            "kubernetes.kubelet_auth_ok"} == {"kubernetes.kubelet_listener_unverified"}
        assert "(kubelet)" in said["kubernetes.kubelet_listener_unverified"]
        assert "uid ?" not in said["kubernetes.kubelet_listener_unverified"]

    def test_nothing_listening_is_no_answer_as_before(self):
        said = self._keys(k.KubernetesSnapshot(kubelet_running=True, kubelet_listener=""))
        assert "kubernetes.kubelet_unprobed" in said

    def test_the_kubelet_read_as_before(self):
        said = self._keys(k.KubernetesSnapshot(kubelet_running=True, anonymous_status=401))
        assert "kubernetes.kubelet_auth_ok" in said

    @pytest.mark.parametrize("owner, key", [("python3", "kubernetes.apiserver_listener_foreign"),
                                            (None, "kubernetes.apiserver_listener_unknown"),
                                            ("kubelite (uid ?)", "kubernetes.apiserver_listener_unverified")])
    def test_the_api_server(self, owner, key):
        said = self._keys(k.KubernetesSnapshot(kubelet_running=True, apiserver_port=16443,
                                               authorization_modes=("RBAC",), apiserver_listener=owner,
                                               apiserver_anonymous_status=None))
        assert key in said and "16443" in said[key] and "uid ?" not in said[key]
        assert "kubernetes.apiserver_anonymous_unprobed" not in said

    @pytest.mark.parametrize("key", ["kubernetes.kubelet_listener_foreign", "kubernetes.kubelet_listener_unknown",
                                     "kubernetes.kubelet_listener_unverified",
                                     "kubernetes.apiserver_listener_foreign", "kubernetes.apiserver_listener_unknown",
                                     "kubernetes.apiserver_listener_unverified"])
    def test_each_is_a_ceiling(self, key):
        assert is_visibility_key(key)

    @pytest.mark.parametrize("lang, key, words", [
        ("en", "kubernetes.kubelet_listener_foreign",
         "127.0.0.1:10250 is owned by python3, not a recognised kubelet process run by root."),
        ("fr", "kubernetes.kubelet_listener_foreign",
         "127.0.0.1:10250 appartient à python3, qui n'est pas un processus kubelet reconnu exécuté par root."),
        ("en", "kubernetes.kubelet_listener_unverified",
         "could not verify that the process owning 127.0.0.1:10250 (python3) runs as root"),
        ("fr", "kubernetes.kubelet_listener_unverified",
         "n'a pas pu vérifier que le processus propriétaire de 127.0.0.1:10250 (python3) s'exécute en root"),
        ("en", "kubernetes.apiserver_listener_unknown", "Anonymous API server access could not be established."),
        ("fr", "kubernetes.apiserver_listener_unknown", "L'accès anonyme au serveur d'API n'a pas pu être établi."),
    ])
    def test_the_words(self, lang, key, words):
        i18n.init(lang)
        try:
            assert words in i18n.t(key, process="python3", port=16443)
        finally:
            i18n.init("en")
