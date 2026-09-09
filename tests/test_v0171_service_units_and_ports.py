"""A service BOB believed stopped removed its own port from the audit.

Found on a real Fedora 43 VM, which is the first machine in this project's
history where a service was actually *running* while BOB looked at it.
Containers have no init, so every services verdict there is "no systemctl";
the local Mint host is the maintainer's own and nothing is installed on it to
be wrong about.

Apache was active, enabled, and listening on ``*:80``. The audit produced no
warning about it anywhere. Two defects in series:

**The unit names were Debian's.** ``services.json`` declared Apache's systemd
unit as ``apache2``; Fedora ships ``httpd``. The ``packages`` field of the same
records already listed both spellings (``openssh-server`` *and* ``openssh``) —
the cross-distro work was done for packages and never for units. So
``is_unit_active("apache2")`` answered False and the check reported *"installed
but stopped and disabled. No immediate risk"* about a running web server.

**And a service believed stopped suppressed its own port.** The runner fed
every registry service's ports into ``audited_ports`` unconditionally, and the
ports check skips anything in that set — "already handled by services". So the
wrong verdict did not merely mislead: it deleted the finding that would have
contradicted it. A service wrongly believed inactive, whose port is listening,
is precisely the case the ports section exists for.

The second defect is not distro-specific. Any service BOB misjudges as
inactive — for any reason, on any distribution — hides its own port.
"""

from __future__ import annotations

import ast
import json
import pathlib

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _registry() -> list:
    data = json.loads((_ROOT / "bob" / "data" / "services.json").read_text(encoding="utf-8"))
    return data if isinstance(data, list) else list(data.values())


class TestUnitNamesAreNotOnlyDebians:
    """Measured on Fedora 43 with ``dnf repoquery -l``, not recalled."""

    #: service id → a unit name Fedora ships that Debian does not use.
    _FEDORA_UNITS = {
        "ssh":    "sshd",        # openssh-server ships sshd.service
        "apache": "httpd",       # httpd ships httpd.service, not apache2
        "mysql":  "mysqld",      # mariadb-server ships mariadb, mysql, mysqld
        "samba":  "smb",         # samba ships smb.service and nmb.service
        "nfs":    "nfs-server",  # nfs-utils ships nfs-server.service
    }

    @pytest.mark.parametrize("svc_id,unit", sorted(_FEDORA_UNITS.items()))
    def test_the_fedora_unit_is_declared(self, svc_id, unit):
        entry = next((s for s in _registry() if s.get("id") == svc_id), None)
        assert entry is not None, f"{svc_id} is gone from the registry"
        assert unit in entry.get("services", []), (
            f"{svc_id} declares {entry.get('services')} — Fedora's unit is "
            f"{unit!r}, so BOB asks systemd about a unit that does not exist "
            f"there and concludes the service is stopped"
        )

    @pytest.mark.parametrize("svc_id", sorted(_FEDORA_UNITS))
    def test_debians_unit_is_still_declared(self, svc_id):
        """Adding names must not drop the ones that were already right."""
        debian = {"ssh": "ssh", "apache": "apache2", "mysql": "mysql",
                  "samba": "smbd", "nfs": "nfs-kernel-server"}[svc_id]
        entry = next(s for s in _registry() if s.get("id") == svc_id)
        assert debian in entry["services"]

    def test_extra_unit_names_are_safe_by_construction(self):
        """Why this fix is data and not code.

        ``_detect_state`` already aggregates across every declared unit and
        keeps the highest-priority state, precisely so an inactive sibling
        cannot mask an active one. A unit that does not exist on this host
        answers UNKNOWN, which has the lowest priority — so declaring a name
        for a distribution you are not running costs a query and changes
        nothing.
        """
        from bob.checks.services import _STATE_PRIORITY, ServiceState

        assert _STATE_PRIORITY[ServiceState.UNKNOWN] == min(_STATE_PRIORITY.values())
        for state in ServiceState:
            if state is not ServiceState.UNKNOWN:
                assert _STATE_PRIORITY[state] > _STATE_PRIORITY[ServiceState.UNKNOWN]


class TestAnInactiveServiceDoesNotSwallowItsPort:
    """The suppression is the part that made the wrong verdict dangerous."""

    def test_the_runner_only_credits_ports_of_an_active_service(self):
        src = (_ROOT / "bob" / "runner.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        updates = [
            n for n in ast.walk(tree)
            if isinstance(n, ast.Call)
            and getattr(n.func, "attr", "") == "update"
            and getattr(n.func.value, "id", "") == "audited_ports"
        ]
        assert updates, "audited_ports is no longer fed — the scrape broke"

        # Every such call must sit under a test of `.is_active`.
        guarded = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.If):
                continue
            test_src = ast.dump(node.test)
            if "is_active" not in test_src:
                continue
            for sub in ast.walk(node):
                if sub in updates:
                    guarded.append(sub)
        assert len(guarded) == len(updates), (
            "a port is credited as 'already handled by services' without the "
            "service being active; the ports check then skips it, so a service "
            "wrongly believed stopped deletes its own exposure finding"
        )

    def test_the_ports_check_reports_what_is_not_credited(self):
        """The other half of the contract, at the level it is decided."""
        from bob.checks.ports import ListeningPort, PortsSnapshot, check_ports
        from bob import i18n

        i18n.init(lang="en")
        port = ListeningPort(port=80, proto="tcp", address="*",
                             raw_line="tcp LISTEN 0 511 *:80 *:* users:((\"httpd\",pid=1,fd=4))",
                             process="httpd", iface="")
        snap = PortsSnapshot(ports=[port], ufw_rules="", ss_output=port.raw_line,
                             ufw_apps={}, ports_readable=True)

        seen = {f.key for f in check_ports(snap, audited_ports=set(),
                                           ufw_active=False, t=i18n.t).findings}
        assert any(k.startswith("ports.uncovered") for k in seen), (
            f"a wildcard listener on every interface produced nothing: {seen}"
        )

        hidden = {f.key for f in check_ports(snap, audited_ports={"80/tcp"},
                                             ufw_active=False, t=i18n.t).findings}
        assert not any(k.startswith("ports.uncovered") for k in hidden), (
            "crediting the port did not suppress it — the two halves of this "
            "contract must stay opposite, or the guard above means nothing"
        )

    def test_a_wildcard_address_counts_as_every_interface(self):
        """`ss` renders Apache's bind as `*:80`, not `0.0.0.0:80`."""
        from bob.checks.ports import ListeningPort

        for addr in ("0.0.0.0", "::", "*"):
            p = ListeningPort(port=80, proto="tcp", address=addr,
                              raw_line="", process="httpd", iface="")
            assert p.is_all_interfaces, f"{addr!r} was not read as all-interfaces"
        local = ListeningPort(port=80, proto="tcp", address="127.0.0.1",
                              raw_line="", process="httpd", iface="")
        assert not local.is_all_interfaces
