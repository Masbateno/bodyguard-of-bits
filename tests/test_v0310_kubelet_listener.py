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
kubelet, kubelite, k3s and kube-apiserver are expected to run as root (measured
in namespaces only, not yet on a MicroK8s or a k3s node); an attacker who is
already root is outside what this check protects against.

After review: every user id is read (real, effective, saved, filesystem — the
first alone let an effective root, or a process that dropped root, pass
either way); every owner of every socket that may take the connection counts
(SO_REUSEPORT: measured, two lines); ``[::]`` as ss shows it is IPv6-only and
does not take 127.0.0.1 (measured `ssforms.txt`; a dual-stack one shows as
``*``); a user that could not be read is said as such. Second review: user ids
that differ are shown whole — the effective one alone read "kubelet (uid 0)"
beside "not run by root" for ``Uid: 1000 0 0 0``.

Third review (partial ``ss`` output), measured (`kspoof4.sh`,
`kspoof-comm.txt`, `kspoof-comm-fix.txt`): ss writes a process's name as it
is, and any user may choose it. A uid 1000 server named ``kubelet",pid=1``
showed as ``users:(("kubelet",pid=1",pid=10,fd=3))``, was read as pid 1 —
root — and asked: "the kubelet requires authentication". The owners are no
longer read from ss: it gives each socket's address and inode (``-e``), and the
processes holding that inode are found in /proc/<pid>/fd, their names in
/proc/<pid>/comm. A line too short, a socket without an inode, one no process
was seen holding, descriptors that could not be read: not known. In a user
namespace the user ids /proc shows are not the host's — not verified.

Fourth review, measured (`review4.txt`): in a pid namespace with its own
/proc, 3 processes are seen of the host's 500 — a holder of the socket may
be unseen, so /proc must be the initial pid namespace's; a nested user
namespace's map reads ``0 0 1``, the identity to its parent only, so the user
ids are the host's only in the initial user namespace itself; ss -e writes
``uid:N`` before ``ino:N`` for a socket not root's, and the inode is read in
that place only.

Sixth review, measured (`hidepid.sh`, `hidepid.txt`): with /proc mounted
hidepid=2 or 4 and BOB run as root without CAP_SYS_PTRACE, a root holder
without it was seen and its uid 1000 child, sharing the socket, was not —
no error, a list taken as whole. With CAP_SYS_PTRACE every holder was seen;
without hidepid the descriptors refused to be read (not known). The holders
are sought only when BOB has CAP_SYS_PTRACE.

Seventh review (a security policy hiding a holder), measured: with hidepid=1
every process was still listed and a refused read was an error
(`hidepid1.txt`); on a real AppArmor node (`lsmhide.txt`, `lsmhide2.txt`),
BOB unconfined read every holder, BOB confined failed with an error, under
hidepid=0 and 2 alike. Not every policy can be listed; hidepid=2 or 4 is what
turns a refused read into an absence. The holders are sought only when /proc
is mounted with hidepid off or noaccess.
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.checks import kubernetes as k
from bob.checks._run import CommandResult
from bob.visibility import is_visibility_key

SS = "LISTEN 0 4096 {addr}:10250 0.0.0.0:* ino:{ino} sk:1 cgroup:/system.slice/kubelet.service <->"


def _ss(monkeypatch, lines, ok=True, holders=None, owners=None):
    """ss answers *lines*; inode N is held by pid N unless *holders* says
    otherwise; pid N is "kubelet" run by root unless *owners* says otherwise."""
    asked = []

    def run(*a, **kw):
        asked.append(a)
        return CommandResult(stdout="\n".join(lines) + "\n", ok=ok)
    monkeypatch.setattr(k, "run_result", run)
    monkeypatch.setattr(k, "_socket_holders",
                        (lambda inodes: {i: [i] for i in inodes}) if holders is None else (lambda inodes: holders))
    owners = owners or {}
    monkeypatch.setattr(k, "_owner", lambda pid: owners.get(pid, "kubelet"))
    return asked


class TestWhoHoldsThePort:

    @pytest.mark.parametrize("lines, owners", [
        ([SS.format(addr="127.0.0.1", ino=11)], ["kubelet"]),
        ([SS.format(addr="*", ino=11)], ["kubelet"]),
        ([SS.format(addr="0.0.0.0", ino=11)], ["kubelet"]),
        ([SS.format(addr="[::ffff:127.0.0.1]", ino=11)], ["kubelet"]),
        ([SS.format(addr="[::]", ino=11)], []),
        ([SS.format(addr="192.0.2.5", ino=11)], []),
        ([SS.format(addr="[::1]", ino=11)], []),
        ([], []),
        (["", SS.format(addr="127.0.0.1", ino=11), ""], ["kubelet"]),
    ], ids=["loopback", "any", "all-v4", "v4-mapped-loopback", "v6-only", "another-address", "v6-loopback",
            "none", "blank-lines"])
    def test_which_sockets(self, monkeypatch, lines, owners):
        _ss(monkeypatch, lines)
        assert k._loopback_listener(10250) == owners

    def test_the_loopback_socket_wins(self, monkeypatch):
        _ss(monkeypatch, [SS.format(addr="0.0.0.0", ino=11), SS.format(addr="127.0.0.1", ino=12)],
            owners={"12": "python3"})
        assert k._loopback_listener(10250) == ["python3"]

    @pytest.mark.parametrize("lines", [
        ["LISTEN 0 4096 127.0.0.1:10250"],
        ["LISTEN 0 4096 127.0.0.1:10250 0.0.0.0:*"],
        ["LISTEN 0 4096 127.0.0.1:10250 0.0.0.0:* sk:1"],
        [SS.format(addr="127.0.0.1", ino=0)],
        [SS.format(addr="127.0.0.1", ino="x1")],
        [SS.format(addr="127.0.0.1", ino=11), "LISTEN 0 4096 127.0.0.1:10250 0.0.0.0:*"],
    ], ids=["truncated", "no-inode", "no-inode-but-more", "inode-zero", "inode-not-a-number", "one-of-two-without"])
    def test_a_partial_answer_is_not_a_list(self, monkeypatch, lines):
        _ss(monkeypatch, lines)
        assert k._loopback_listener(10250) is None

    def test_a_socket_without_an_inode_the_loopback_one_beats(self, monkeypatch):
        _ss(monkeypatch, ["LISTEN 0 4096 0.0.0.0:10250 0.0.0.0:*", SS.format(addr="127.0.0.1", ino=11)])
        assert k._loopback_listener(10250) == ["kubelet"]

    def test_the_first_inode_is_the_socket_s(self, monkeypatch):
        """The cgroup path, written after the inode, is a delegated user's to name."""
        line = "LISTEN 0 4096 127.0.0.1:10250 0.0.0.0:* ino:11 sk:1 cgroup:/user.slice/x ino:12 <->"
        _ss(monkeypatch, [line], owners={"12": "python3"})
        assert k._loopback_listener(10250) == ["kubelet"]

    def test_after_the_socket_s_user(self, monkeypatch):
        """Measured: a socket not root's reads ``uid:1000 ino:N``."""
        _ss(monkeypatch, ["LISTEN 0 128 0.0.0.0:10250 0.0.0.0:* uid:1000 ino:11 sk:2 cgroup:/x <->"],
            owners={"11": "python3 (uid 1000)"})
        assert k._loopback_listener(10250) == ["python3 (uid 1000)"]

    @pytest.mark.parametrize("line", [
        "LISTEN 0 128 127.0.0.1:10250 0.0.0.0:* sk:1 ino:11 <->",
        "LISTEN 0 128 127.0.0.1:10250 0.0.0.0:* cgroup:/x ino:11 <->",
        "LISTEN 0 128 127.0.0.1:10250 0.0.0.0:* uid:1000 uid:0 ino:11 <->",
    ], ids=["after-another-field", "after-the-cgroup", "after-two-uids"])
    def test_an_inode_out_of_its_place_is_not_read(self, monkeypatch, line):
        _ss(monkeypatch, [line])
        assert k._loopback_listener(10250) is None

    def test_ss_is_not_asked_for_names(self, monkeypatch):
        """Measured: a name may forge another pid in ss -p's users:(...)."""
        asked = _ss(monkeypatch, [SS.format(addr="127.0.0.1", ino=11)])
        k._loopback_listener(10250)
        assert asked == [("ss", "-Htlne", "sport", "=", ":10250")]

    def test_ss_failed(self, monkeypatch):
        _ss(monkeypatch, [], ok=False)
        assert k._loopback_listener(10250) is None

    @pytest.mark.parametrize("holders, owners", [
        (None, None), ({"11": []}, None), ({}, None), ({"11": ["7"]}, ["kubelet"]),
    ], ids=["descriptors-not-read", "held-by-no-process-seen", "inode-missing", "held"])
    def test_the_holders(self, monkeypatch, holders, owners):
        _ss(monkeypatch, [SS.format(addr="127.0.0.1", ino=11)], holders=holders)
        if holders is None:
            monkeypatch.setattr(k, "_socket_holders", lambda inodes: None)
        assert k._loopback_listener(10250) == owners

    def test_a_process_not_run_by_root(self, monkeypatch):
        _ss(monkeypatch, [SS.format(addr="127.0.0.1", ino=7)], owners={"7": "kubelet (uid 1000)"})
        assert k._loopback_listener(10250) == ["kubelet (uid 1000)"]

    def test_a_name_not_read(self, monkeypatch):
        _ss(monkeypatch, [SS.format(addr="127.0.0.1", ino=7), SS.format(addr="127.0.0.1", ino=8)],
            owners={"8": None})
        assert k._loopback_listener(10250) is None

    def test_every_socket_sharing_the_port(self, monkeypatch):
        """SO_REUSEPORT: measured, two lines for one port."""
        _ss(monkeypatch, [SS.format(addr="127.0.0.1", ino=1), SS.format(addr="127.0.0.1", ino=2)],
            owners={"2": "kubelet (uid 1000)"})
        assert k._loopback_listener(10250) == ["kubelet", "kubelet (uid 1000)"]

    def test_a_kubelet_whose_user_was_not_read_beside_one(self, monkeypatch):
        _ss(monkeypatch, [SS.format(addr="127.0.0.1", ino=1), SS.format(addr="127.0.0.1", ino=2)],
            owners={"2": "kubelet (uid ?)"})
        assert k._deciding(k._loopback_listener(10250), k._KUBELET_NAMES) == "kubelet (uid ?)"

    def test_every_process_sharing_a_socket(self, monkeypatch):
        _ss(monkeypatch, [SS.format(addr="127.0.0.1", ino=11)], holders={"11": ["1", "2"]}, owners={"2": "python3"})
        assert k._loopback_listener(10250) == ["kubelet", "python3"]


class TestTheProcFiles:

    @staticmethod
    def _proc(monkeypatch, fds, denied=(), gone=(), listing=True):
        """*fds*: pid -> {fd: link}; *denied*/*gone*: pids whose fd directory
        raises PermissionError/FileNotFoundError; a link None raises
        FileNotFoundError (closed meanwhile), "denied" PermissionError."""
        def listdir(path):
            if path == "/proc":
                if not listing:
                    raise PermissionError(path)
                return list(fds) + list(denied) + list(gone) + ["self", "net"]
            pid = path.split("/")[2]
            if pid in denied:
                raise PermissionError(path)
            if pid in gone:
                raise FileNotFoundError(path)
            return list(fds[pid])

        def readlink(path):
            pid, fd = path.split("/")[2], path.split("/")[4]
            link = fds[pid][fd]
            if link is None:
                raise FileNotFoundError(path)
            if link == "denied":
                raise PermissionError(path)
            return link
        monkeypatch.setattr(k.os, "listdir", listdir)
        monkeypatch.setattr(k.os, "readlink", readlink)
        monkeypatch.setattr(k, "_whole_proc", lambda: True)

    def test_found(self, monkeypatch):
        self._proc(monkeypatch, {"1": {"3": "socket:[11]", "4": "socket:[11]"}, "2": {"0": "/dev/null"},
                                 "3": {"5": "socket:[11]", "6": "socket:[12]"}, "4": {"1": "socket:[111]"}},
                   gone=("9",))
        assert k._socket_holders({"11", "12"}) == {"11": ["1", "3"], "12": ["3"]}

    def test_a_descriptor_closed_meanwhile(self, monkeypatch):
        self._proc(monkeypatch, {"1": {"3": None, "4": "socket:[11]"}})
        assert k._socket_holders({"11"}) == {"11": ["1"]}

    @pytest.mark.parametrize("kw", [{"denied": ("5",)}, {"listing": False}],
                             ids=["a-process-not-read", "proc-not-listed"])
    def test_not_read(self, monkeypatch, kw):
        self._proc(monkeypatch, {"1": {"3": "socket:[11]"}}, **kw)
        assert k._socket_holders({"11"}) is None

    def test_a_link_not_read(self, monkeypatch):
        self._proc(monkeypatch, {"1": {"3": "denied", "4": "socket:[11]"}})
        assert k._socket_holders({"11"}) is None

    def test_a_proc_that_does_not_show_every_process(self, monkeypatch):
        """Measured: a pid namespace's own /proc shows 3 processes of 500."""
        self._proc(monkeypatch, {"1": {"3": "socket:[11]"}})
        monkeypatch.setattr(k, "_whole_proc", lambda: False)
        assert k._socket_holders({"11"}) is None

    @pytest.mark.parametrize("link, ns, whole", [
        ("/proc/1/ns/pid", "pid:[4026531836]", True), ("/proc/1/ns/pid", "pid:[4026533340]", False),
        ("/proc/1/ns/pid", None, False),
        ("/proc/self/ns/user", "user:[4026531837]", True), ("/proc/self/ns/user", "user:[4026532926]", False),
        ("/proc/self/ns/user", None, False),
    ], ids=["pid-initial", "pid-another", "pid-not-read", "user-initial", "user-another", "user-not-read"])
    def test_the_namespaces(self, monkeypatch, link, ns, whole):
        def readlink(path):
            assert path == link
            if ns is None:
                raise PermissionError(path)
            return ns
        monkeypatch.setattr(k.os, "readlink", readlink)
        monkeypatch.setattr(k, "_ptrace_capable", lambda: True)
        monkeypatch.setattr(k, "_proc_hidepid", lambda: "off")
        read = k._whole_proc if link == "/proc/1/ns/pid" else k._host_user_ids
        assert read() is whole

    @pytest.mark.parametrize("level, whole", [
        ("off", True), ("noaccess", True), ("invisible", False), ("ptraceable", False), ("unknown", False),
    ])
    def test_a_proc_that_hides_processes(self, monkeypatch, level, whole):
        """Measured: hidepid=2 or 4 leaves out, with no error, what BOB may not read."""
        monkeypatch.setattr(k.os, "readlink", lambda path: "pid:[4026531836]")
        monkeypatch.setattr(k, "_ptrace_capable", lambda: True)
        monkeypatch.setattr(k, "_proc_hidepid", lambda: level)
        assert k._whole_proc() is whole

    @pytest.mark.parametrize("mounts, level", [
        ("proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n", "off"),
        ("proc /proc proc rw,relatime,hidepid=invisible 0 0\n", "invisible"),
        ("proc /proc proc rw,relatime,hidepid=2 0 0\n", "invisible"),
        ("proc /proc proc rw,relatime,hidepid=noaccess 0 0\n", "noaccess"),
        ("proc /proc proc rw,relatime 0 0\nproc /proc proc rw,relatime,hidepid=ptraceable 0 0\n", "ptraceable"),
        ("proc /proc proc rw,relatime,hidepid=4 0 0\nproc /proc proc rw,relatime 0 0\n", "off"),
        ("tmpfs /proc tmpfs rw 0 0\nproc /proc/x proc rw,hidepid=2 0 0\n", "unknown"),
        ("", "unknown"),
        (None, "unknown"),
    ], ids=["off", "invisible", "two", "noaccess", "the-last-wins", "the-last-wins-off", "no-proc-at-proc",
            "empty", "not-read"])
    def test_the_hidepid_level(self, monkeypatch, mounts, level):
        class P:
            def __init__(self, path):
                assert path == "/proc/mounts"

            def read_text(self, **kw):
                if mounts is None:
                    raise PermissionError("denied")
                return mounts
        monkeypatch.setattr(k, "Path", P)
        assert k._proc_hidepid() == level

    def test_every_process_only_with_cap_sys_ptrace(self, monkeypatch):
        """Measured: hidepid=2 or 4 hides, with no error, what BOB may not read."""
        monkeypatch.setattr(k.os, "readlink", lambda path: "pid:[4026531836]")
        monkeypatch.setattr(k, "_proc_hidepid", lambda: "off")
        monkeypatch.setattr(k, "_ptrace_capable", lambda: False)
        assert k._whole_proc() is False

    @pytest.mark.parametrize("status, capable", [
        ("Name:\tbob\nCapEff:\t000001ffffffffff\n", True),
        ("Name:\tbob\nCapEff:\t0000000000080000\n", True),
        ("Name:\tbob\nCapEff:\t000001fffff7ffff\n", False),
        ("Name:\tbob\nCapEff:\t0000000000000000\n", False),
        ("Name:\tbob\nCapEff:\tzz\n", False),
        ("Name:\tbob\n", False),
        (None, False),
    ], ids=["root", "it-alone", "all-but-it", "none", "malformed", "no-line", "not-read"])
    def test_cap_sys_ptrace(self, monkeypatch, status, capable):
        class P:
            def __init__(self, path):
                assert path == "/proc/self/status"

            def read_text(self, **kw):
                if status is None:
                    raise PermissionError("denied")
                return status
        monkeypatch.setattr(k, "Path", P)
        assert k._ptrace_capable() is capable

    @staticmethod
    def _files(monkeypatch, comm, status, host=True):
        files = {"/proc/7/comm": comm, "/proc/7/status": status}

        class P:
            def __init__(self, path):
                self.path = path

            def read_text(self, **kw):
                if files[self.path] is None:
                    raise FileNotFoundError(self.path)
                return files[self.path]
        monkeypatch.setattr(k, "Path", P)
        monkeypatch.setattr(k, "_host_user_ids", lambda: host)

    @pytest.mark.parametrize("status, owner", [
        ("Name:\tkubelet\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n", "kubelet"),
        ("Name:\tkubelet\nUid:\t1000\t1000\t1000\t1000\n", "kubelet (uid 1000)"),
        ("Name:\tkubelet\nUid:\t1000\t0\t0\t0\n", "kubelet (uids 1000 0 0 0)"),
        ("Name:\tkubelet\nUid:\t0\t1000\t0\t1000\n", "kubelet (uids 0 1000 0 1000)"),
        ("Name:\tkubelet\nUid:\t0\t0\t1000\t0\n", "kubelet (uids 0 0 1000 0)"),
        ("Name:\tkubelet\nUid:\t0\t0\t0\t1000\n", "kubelet (uids 0 0 0 1000)"),
        ("Name:\tkubelet\nUid:\t0\n", "kubelet (uid ?)"),
        ("Name:\tkubelet\n", "kubelet (uid ?)"),
        (None, "kubelet (uid ?)"),
    ], ids=["root", "a-user", "effective-root-of-a-user", "root-dropped-to-a-user", "saved-user",
            "filesystem-user", "a-short-line", "no-uid-line", "gone"])
    def test_the_owner(self, monkeypatch, status, owner):
        self._files(monkeypatch, "kubelet\n", status)
        assert k._owner("7") == owner

    def test_the_name_is_comm_s(self, monkeypatch):
        """Not the name ss writes: comm, whole, compared whole."""
        self._files(monkeypatch, 'kubelet",pid=1\n', "Uid:\t1000\t1000\t1000\t1000\n")
        assert k._owner("7") == 'kubelet",pid=1 (uid 1000)'

    def test_a_name_not_read(self, monkeypatch):
        self._files(monkeypatch, None, "Uid:\t0\t0\t0\t0\n")
        assert k._owner("7") is None

    def test_in_a_user_namespace(self, monkeypatch):
        """Measured: the bench namespace's root is uid 1000 outside it."""
        self._files(monkeypatch, "kubelet\n", "Uid:\t0\t0\t0\t0\n", host=False)
        assert k._owner("7") == "kubelet (uid ?)"

    @pytest.mark.parametrize("owners, deciding", [
        (None, None), ([], ""), (["kubelet"], "kubelet"), (["kubelet", "kubelet"], "kubelet"),
        (["kubelet", "python3"], "python3"), (["kubelet", "kubelet (uid 1000)"], "kubelet (uid 1000)"),
        (["kubelet (uid ?)", "python3"], "kubelet (uid ?)"),
        (["kubelet", "kubelet (uid ?)"], "kubelet (uid ?)"),
    ], ids=["unknown", "none", "one", "two-kubelets", "a-stranger-beside", "a-user-beside", "the-first-stranger",
            "a-kubelet-unverified-beside"])
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
        (["kubelet", "kubelet (uid ?)"], "kubelet (uid ?)"),
    ], ids=["a-stranger", "a-user", "unknown", "unverified", "a-stranger-sharing-the-port",
            "a-kubelet-unverified-sharing-the-port"])
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
