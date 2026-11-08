"""v0.31.3 — a k3s server's API server is read, and its pods through its own containerd.

0.28.0 read the API server where MicroK8s keeps its arguments; 0.29.0 said, on
k3s, that it was not read. Measured on Kali (k3s v1.37.2+k3s1, 8 November 2026,
~/.cache/bob-fieldtest/netnsbench/k3s0313/):

- the ``k3s server`` process blanks its command line (``/proc/<pid>/cmdline`` reads
  ``k3s server`` and NUL bytes whatever flags or ``config.yaml`` set); what the
  API server runs with is in the line k3s logs as it starts it, ``Running
  kube-apiserver --…``, which under systemd reaches the journal attached to that
  process (``_PID``, ``_COMM=k3s-server``);
- the port its clients reach is the one in ``/etc/rancher/k3s/k3s.yaml``, not
  ``--advertise-port`` (7000 announced while k3s listened on 6443);
- ``k3s`` is in /usr/local/bin, outside sudo's secure_path on Kali: ``sudo bob``
  did not find it, fell through to ``/usr/bin/ctr`` on Docker's containerd, listed
  0 containers and said "0 pod(s) … OK" while a privileged pod ran in k3s. The
  ``kubectl`` and ``ctr`` links beside the binary the server runs are used now.

Field (0.31.2 → this tree): stock k3s, API not read → Node,RBAC read, anonymous
refused (401); AlwaysAllow → ALERT −2; anonymous 200 + cluster-admin bound to
system:authenticated → WARN −1 + ALERT −3; privileged pod in default → WARN −1
(was OK); k3s started by hand (line not in the journal) → not read, as before.
"""

from __future__ import annotations

import json
import os
import socket

import pytest

from bob import i18n
from bob.checks import kubernetes as k
from bob.checks._run import CommandResult

#: The line measured on Kali (F2, stock settings), as journalctl -o cat prints it.
_LINE = (
    'time="2026-11-08T20:19:58+01:00" level=info msg="Running kube-apiserver --advertise-port=6443 '
    '--allow-privileged=true --anonymous-auth=false '
    '--api-audiences=https://kubernetes.default.svc.cluster.local,k3s --authorization-mode=Node,RBAC '
    '--bind-address=127.0.0.1 --cert-dir=/var/lib/rancher/k3s/server/tls/temporary-certs '
    '--client-ca-file=/var/lib/rancher/k3s/server/tls/client-ca.crt '
    '--egress-selector-config-file=/var/lib/rancher/k3s/server/etc/egress-selector-config.yaml '
    '--enable-admission-plugins=NodeRestriction --enable-aggregator-routing=true '
    '--enable-bootstrap-token-auth=true --etcd-servers=unix://kine.sock '
    '--kubelet-certificate-authority=/var/lib/rancher/k3s/server/tls/server-ca.crt '
    '--kubelet-client-certificate=/var/lib/rancher/k3s/server/tls/client-kube-apiserver.crt '
    '--kubelet-client-key=/var/lib/rancher/k3s/server/tls/client-kube-apiserver.key '
    '--kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname --profiling=false '
    '--proxy-client-cert-file=/var/lib/rancher/k3s/server/tls/client-auth-proxy.crt '
    '--proxy-client-key-file=/var/lib/rancher/k3s/server/tls/client-auth-proxy.key '
    '--requestheader-allowed-names=system:auth-proxy '
    '--requestheader-client-ca-file=/var/lib/rancher/k3s/server/tls/request-header-ca.crt '
    '--requestheader-extra-headers-prefix=X-Remote-Extra- '
    '--requestheader-group-headers=X-Remote-Group --requestheader-username-headers=X-Remote-User '
    '--secure-port=6444 --service-account-issuer=https://kubernetes.default.svc.cluster.local '
    '--service-account-key-file=/var/lib/rancher/k3s/server/tls/service.key '
    '--service-account-signing-key-file=/var/lib/rancher/k3s/server/tls/service.current.key '
    '--service-cluster-ip-range=10.43.0.0/16 --service-node-port-range=30000-32767 '
    '--storage-backend=etcd3 '
    '--tls-cert-file=/var/lib/rancher/k3s/server/tls/serving-kube-apiserver.crt --tls-cipher-suites=T'
    'LS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WIT'
    'H_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY130'
    '5,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305 '
    '--tls-private-key-file=/var/lib/rancher/k3s/server/tls/serving-kube-apiserver.key"'
)

_ALWAYS = _LINE.replace("--authorization-mode=Node,RBAC", "--authorization-mode=AlwaysAllow")
_KUBECONFIG = "apiVersion: v1\nclusters:\n- cluster:\n    certificate-authority-data: AAAA\n    server: https://127.0.0.1:{port}\n  name: default\n"
_BINDINGS = json.dumps({"items": [
    {"metadata": {"name": "cluster-admin"}, "roleRef": {"name": "cluster-admin"},
     "subjects": [{"kind": "Group", "name": "system:masters"}]},
    {"metadata": {"name": "bob-broad-admin"}, "roleRef": {"name": "cluster-admin"},
     "subjects": [{"kind": "Group", "name": "system:authenticated"}]}]})


@pytest.fixture
def node(tmp_path, monkeypatch):
    """A k3s server node: no MicroK8s args file, one k3s-server, its journal line,
    its kubeconfig, its kubectl. Returns the calls made, for the tests to read."""
    calls = {"probe": [], "run": []}
    kc = tmp_path / "k3s.yaml"
    kc.write_text(_KUBECONFIG.format(port=6443), encoding="utf-8")
    monkeypatch.setattr(k, "_MICROK8S_APISERVER_ARGS", tmp_path / "no-microk8s")
    monkeypatch.setattr(k, "_K3S_KUBECONFIG", kc)
    monkeypatch.setattr(k, "_k3s_server_pid", lambda: "4242")
    monkeypatch.setattr(k, "_k3s_apiserver_line", lambda pid: _LINE)
    monkeypatch.setattr(k, "_k3s_tool", lambda pid, name: f"/data/bin/{name}")
    monkeypatch.setattr(k, "_loopback_listener", lambda port: ["k3s-server"])
    monkeypatch.setattr(k, "_probe", lambda url: calls["probe"].append(url) or 401)

    def run(*args, **kw):
        calls["run"].append(args)
        return CommandResult(_BINDINGS, True)
    monkeypatch.setattr(k, "run_result", run)
    calls["kubeconfig"] = kc
    return calls


def _read():
    snap = k.KubernetesSnapshot(kubelet_running=True)
    k._read_apiserver(snap)
    return snap


def _keys(snap):
    return {f.key: f for f in k.check_kubernetes(snap, t=lambda key, **kw: key).findings}


class TestTheApiServerOfAK3sServer:
    def test_its_journal_line_is_read(self, node):
        snap = _read()
        assert snap.authorization_modes == ("Node", "RBAC")
        assert snap.apiserver_port == 6443 and snap.apiserver_anonymous_status == 401
        assert node["probe"] == ["https://127.0.0.1:6443/api/v1/namespaces"]
        keys = _keys(snap)
        assert "kubernetes.apiserver_unread" not in keys and "kubernetes.apiserver_anonymous_refused" in keys

    def test_always_allow_is_weighed(self, node, monkeypatch):
        monkeypatch.setattr(k, "_k3s_apiserver_line", lambda pid: _ALWAYS)
        snap = _read()
        assert snap.authorization_modes == ("AlwaysAllow",)
        res = k.check_kubernetes(snap, t=lambda key, **kw: key)
        assert any(d.key == "kubernetes.apiserver_always_allow" and d.points == 2 for d in res.deductions)

    def test_no_line_in_the_journal_is_not_read(self, node, monkeypatch):
        """Measured: k3s started by hand logs to its own output, not the journal."""
        monkeypatch.setattr(k, "_k3s_apiserver_line", lambda pid: None)
        snap = _read()
        assert snap.authorization_modes is None and not node["probe"]
        assert "kubernetes.apiserver_unread" in _keys(snap)

    def test_no_k3s_server_is_not_read(self, node, monkeypatch):
        asked = []
        monkeypatch.setattr(k, "_k3s_server_pid", lambda: None)
        monkeypatch.setattr(k, "_k3s_apiserver_line", lambda pid: asked.append(pid) or _LINE)
        assert _read().authorization_modes is None and not asked

    def test_the_port_is_the_kubeconfigs_not_the_advertised_one(self, node, monkeypatch):
        """Measured: --advertise-port=7000 while k3s listened on 6443."""
        monkeypatch.setattr(k, "_k3s_apiserver_line",
                            lambda pid: _LINE.replace("--advertise-port=6443", "--advertise-port=7000"))
        assert _read().apiserver_port == 6443

    @pytest.mark.parametrize("server", ["https://203.0.113.7:6443", "https://k3s.example:6443"])
    def test_a_kubeconfig_naming_another_host_is_not_probed(self, node, server):
        node["kubeconfig"].write_text(_KUBECONFIG.format(port=6443).replace("https://127.0.0.1:6443", server))
        snap = _read()
        assert snap.apiserver_port is None and not node["probe"]
        assert snap.authorization_modes == ("Node", "RBAC")

    def test_a_kubeconfig_with_two_servers_is_not_read(self, node):
        node["kubeconfig"].write_text(_KUBECONFIG.format(port=6443) + _KUBECONFIG.format(port=6443).split("clusters:\n")[1])
        assert _read().apiserver_port is None

    def test_an_unreadable_kubeconfig_is_not_probed(self, node, tmp_path, monkeypatch):
        monkeypatch.setattr(k, "_K3S_KUBECONFIG", tmp_path / "gone.yaml")
        assert _read().apiserver_port is None and not node["probe"]

    def test_the_bindings_are_read_from_k3s_s_own_kubeconfig(self, node):
        snap = _read()
        assert node["run"] == [("/data/bin/kubectl", f"--kubeconfig={node['kubeconfig']}", "get",
                                "clusterrolebindings", "-o", "json")]
        assert snap.broad_admin_bindings == ["bob-broad-admin: Group/system:authenticated"]
        assert "kubernetes.cluster_admin_broad" in _keys(snap)

    def test_the_bindings_are_not_asked_without_rbac(self, node, monkeypatch):
        monkeypatch.setattr(k, "_k3s_apiserver_line", lambda pid: _ALWAYS)
        assert _read().broad_admin_bindings is None and not node["run"]

    def test_without_its_kubectl_the_bindings_are_not_read(self, node, monkeypatch):
        monkeypatch.setattr(k, "_k3s_tool", lambda pid, name: None)
        snap = _read()
        assert snap.broad_admin_bindings is None and not node["run"]
        assert "kubernetes.cluster_admin_unread" in _keys(snap)

    def test_microk8s_args_are_still_read_first(self, node, tmp_path, monkeypatch):
        args = tmp_path / "kube-apiserver"
        args.write_text("--authorization-mode=AlwaysAllow\n--secure-port=16443\n")
        monkeypatch.setattr(k, "_MICROK8S_APISERVER_ARGS", args)
        snap = _read()
        assert snap.authorization_modes == ("AlwaysAllow",) and snap.apiserver_port == 16443


def _proc(tmp_path, monkeypatch, comms):
    proc = tmp_path / "proc"
    proc.mkdir()
    for pid, comm in comms.items():
        (proc / pid).mkdir()
        (proc / pid / "comm").write_text(comm + "\n")
    (proc / "self").mkdir()
    monkeypatch.setattr(k, "_PROC", proc)
    return proc


class TestTheServerProcess:
    def test_the_one_k3s_server(self, tmp_path, monkeypatch):
        _proc(tmp_path, monkeypatch, {"1": "systemd", "4242": "k3s-server", "4300": "containerd"})
        assert k._k3s_server_pid() == "4242"

    def test_two_servers_are_not_told_apart(self, tmp_path, monkeypatch):
        _proc(tmp_path, monkeypatch, {"4242": "k3s-server", "5151": "k3s-server"})
        assert k._k3s_server_pid() is None

    @pytest.mark.parametrize("comm", ["k3s-agent", "k3s", "kubelite"])
    def test_other_names_are_not_a_k3s_server(self, tmp_path, monkeypatch, comm):
        _proc(tmp_path, monkeypatch, {"4242": comm})
        assert k._k3s_server_pid() is None

    def test_when_it_started(self, tmp_path, monkeypatch):
        proc = _proc(tmp_path, monkeypatch, {"4242": "k3s-server"})
        fields = ["S"] + ["0"] * 18 + ["123456"] + ["0"] * 30     # field 22 = starttime
        (proc / "4242" / "stat").write_text("4242 (k3s server) " + " ".join(fields) + "\n")
        (proc / "stat").write_text("cpu  1 2 3\nbtime 1794000000\nprocesses 9\n")
        assert k._process_start("4242") == 1794000000 + 123456 // os.sysconf("SC_CLK_TCK")

    def test_an_unreadable_start_is_none(self, tmp_path, monkeypatch):
        _proc(tmp_path, monkeypatch, {"4242": "k3s-server"})
        assert k._process_start("4242") is None


class TestTheJournal:
    def _ask(self, monkeypatch, out, start=1794164347):
        asked = []
        monkeypatch.setattr(k, "_process_start", lambda pid: start)
        monkeypatch.setattr(k, "run_result", lambda *a, **kw: asked.append(a) or CommandResult(out, True))
        return k._k3s_apiserver_line("4242"), asked

    def test_only_this_process_since_it_started(self, monkeypatch):
        line, asked = self._ask(monkeypatch, _LINE + "\n")
        assert line == _LINE
        args = asked[0]
        assert args[0] == "journalctl"
        for wanted in ("_PID=4242", "_COMM=k3s-server", "-b", "--since=@1794164347"):
            assert wanted in args

    def test_the_last_start_line_wins(self, monkeypatch):
        line, _ = self._ask(monkeypatch, _ALWAYS + "\n" + _LINE + "\n")
        assert line == _LINE

    def test_other_lines_are_not_taken(self, monkeypatch):
        line, _ = self._ask(monkeypatch, "-- No entries --\n")
        assert line is None

    def test_an_unknown_start_asks_nothing(self, monkeypatch):
        line, asked = self._ask(monkeypatch, _LINE, start=None)
        assert line is None and not asked


class TestItsOwnTools:
    def _layout(self, tmp_path, monkeypatch, other=False):
        proc = _proc(tmp_path, monkeypatch, {"4242": "k3s-server"})
        bindir = tmp_path / "data" / "bin"
        bindir.mkdir(parents=True)
        (bindir / "k3s").write_text("binary")
        (bindir / "other").write_text("another binary")
        (bindir / "kubectl").symlink_to("other" if other else "k3s")
        (bindir / "ctr").symlink_to("k3s")
        (proc / "4242" / "exe").symlink_to(bindir / "k3s")
        return bindir

    def test_the_link_beside_the_running_binary(self, tmp_path, monkeypatch):
        bindir = self._layout(tmp_path, monkeypatch)
        assert k._k3s_tool("4242", "kubectl") == str(bindir / "kubectl")
        assert k._k3s_tool("4242", "ctr") == str(bindir / "ctr")

    def test_a_link_to_another_file_is_not_used(self, tmp_path, monkeypatch):
        self._layout(tmp_path, monkeypatch, other=True)
        assert k._k3s_tool("4242", "kubectl") is None

    def test_a_missing_link_is_none(self, tmp_path, monkeypatch):
        self._layout(tmp_path, monkeypatch)
        assert k._k3s_tool("4242", "crictl") is None


class TestItsContainers:
    def test_a_k3s_server_is_asked_through_its_own_ctr(self, monkeypatch):
        monkeypatch.setattr(k, "_k3s_server_pid", lambda: "4242")
        monkeypatch.setattr(k, "_k3s_tool", lambda pid, name: f"/data/bin/{name}")
        monkeypatch.setattr(k, "_command_exists", lambda c: True)     # microk8s.ctr, k3s, ctr: all there
        assert k._ctr_command() == ("/data/bin/ctr", "-a", "/run/k3s/containerd/containerd.sock", "-n", "k8s.io")

    def test_without_its_ctr_nothing_else_is_asked(self, monkeypatch):
        """Measured: the fallback was /usr/bin/ctr on Docker's containerd, 0 containers, "OK"."""
        monkeypatch.setattr(k, "_k3s_server_pid", lambda: "4242")
        monkeypatch.setattr(k, "_k3s_tool", lambda pid, name: None)
        monkeypatch.setattr(k, "_command_exists", lambda c: True)
        monkeypatch.setattr(k, "path_exists", lambda p: True)
        assert k._ctr_command() is None

    def test_from_system_reads_nothing_then_not_even_crictl(self, monkeypatch):
        asked = []
        monkeypatch.setattr(k, "kubelet_running", lambda: True)
        monkeypatch.setattr(k, "_ctr_command", lambda: None)
        monkeypatch.setattr(k, "_command_exists", lambda c: True)
        monkeypatch.setattr(k, "_read_pods_cri", lambda c: asked.append(c) or ([], 0))
        monkeypatch.setattr(k, "_loopback_listener", lambda port: [])
        monkeypatch.setattr(k, "_read_apiserver", lambda snap: None)
        monkeypatch.setattr(k, "_runtime_socket", lambda: None)
        snap = k.KubernetesSnapshot.from_system()
        assert not snap.workloads_read and not asked

    def test_without_k3s_the_order_is_unchanged(self, monkeypatch):
        monkeypatch.setattr(k, "_k3s_server_pid", lambda: None)
        monkeypatch.setattr(k, "_command_exists", lambda c: c == "microk8s.ctr")
        assert k._ctr_command() == ("microk8s.ctr",)

    @pytest.mark.parametrize("k3s_runs", [True, False])
    def test_the_runtime_socket_is_k3s_s_own(self, tmp_path, monkeypatch, k3s_runs):
        """Measured: Docker's /run/containerd/containerd.sock was reported on a k3s node."""
        paths = []
        for name in ("d.sock", "k.sock"):                 # short: AF_UNIX paths stop at 108 bytes
            with socket.socket(socket.AF_UNIX) as s:
                s.bind(str(tmp_path / name))
            paths.append(str(tmp_path / name))
        monkeypatch.setattr(k, "_RUNTIME_SOCKETS", (paths[0],))
        monkeypatch.setattr(k, "_K3S_CONTAINERD_SOCKET", paths[1])
        monkeypatch.setattr(k, "_k3s_server_pid", lambda: "4242" if k3s_runs else None)
        assert k._runtime_socket()[0] == (paths[1] if k3s_runs else paths[0])


def _explain(lang, entry, part):
    with open(f"bob/locales/{lang}.json", encoding="utf-8") as fh:
        return json.load(fh)["explain"]["kubernetes"][entry][part]


class TestWhatIsSaid:
    @pytest.mark.parametrize("lang, words", [
        ("en", "Not AlwaysAllow: with it the API server turns anonymous authentication off"),
        ("fr", "Pas AlwaysAllow : avec lui, le serveur d'API coupe l'authentification anonyme")], ids=["en", "fr"])
    def test_anonymous_access_is_not_said_to_add_up_with_always_allow(self, lang, words):
        """Measured: under AlwaysAllow the API server resets anonymous auth to false (401)."""
        why = _explain(lang, "apiserver_anonymous", "why")
        assert words in why and "AlwaysAllow, it is everything" not in why and "adds up" not in why

    @pytest.mark.parametrize("lang, entry, words", [
        ("en", "apiserver_always_allow", "k3s: remove the authorization-mode entry from kube-apiserver-arg"),
        ("en", "apiserver_anonymous", "k3s: remove anonymous-auth=true from kube-apiserver-arg"),
        ("fr", "apiserver_always_allow", "k3s : retirer l'entrée authorization-mode de kube-apiserver-arg"),
        ("fr", "apiserver_anonymous", "k3s : retirer anonymous-auth=true de kube-apiserver-arg")],
        ids=["en-always-allow", "en-anonymous", "fr-always-allow", "fr-anonymous"])
    def test_the_k3s_fix_is_given(self, lang, entry, words):
        """Measured: removing the entry and `systemctl restart k3s` cleared each finding."""
        how = _explain(lang, entry, "how")
        assert words in how

    @pytest.mark.parametrize("lang, words", [("en", "the line the running k3s server wrote to the systemd journal"),
                                             ("fr", "la ligne que le serveur k3s en cours a écrite dans le journal systemd")],
                             ids=["en", "fr"])
    def test_what_is_not_read_says_where_k3s_is_read(self, lang, words):
        i18n.init(lang)
        try:
            assert words in i18n.t("kubernetes.apiserver_unread_detail")
        finally:
            i18n.init(lang="en")
