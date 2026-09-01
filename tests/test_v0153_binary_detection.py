"""v0.15.3 — a verdict must not depend on where the operator was standing.

The registry's `binary` field is declared two different ways. `bob/registry.py`
called it "absolute paths"; the JSON schema calls it "bare command names
(resolved via $PATH) or absolute paths", and the registry uses both — `mongod`
and `jenkins` are bare. The code honoured neither: `Path(x).is_file()` resolves
a bare name against the *working directory*.

So running BOB from a directory that happened to hold a file called `mongod`
reported MongoDB — a critical-risk service — as installed, and the whole
exposure analysis for port 27017 followed on a host that had none. From
anywhere else the same host said nothing.

The schema is now the implemented contract: bare names go through $PATH,
absolute paths through the filesystem, and the docstring says so too.
"""

import dataclasses

import pytest

from bob.checks.services import _detect_installation
from bob.registry import Detection, Service


def _service(*binaries: str) -> Service:
    return Service(id="probe", label="Probe", packages=(), services=(),
                   ports=("1/tcp",), risk="low", config_key="fixed",
                   detection=Detection(binary=binaries, snap=(), config_files=()))


class TestABareNameGoesThroughPath:
    def test_a_command_on_the_path_is_found(self):
        assert _detect_installation(_service("python3")) == (True, "binary")

    def test_a_command_that_does_not_exist_is_not(self):
        assert _detect_installation(_service("bob-no-such-command")) == (False, "")

    def test_the_working_directory_is_not_consulted(self, tmp_path, monkeypatch):
        """The defect in one sentence: a file here is not a command."""
        decoy = tmp_path / "bob-no-such-command"
        decoy.write_text("")
        decoy.chmod(0o755)
        monkeypatch.chdir(tmp_path)
        assert _detect_installation(_service("bob-no-such-command")) == (False, "")

    def test_a_real_service_name_is_not_faked_by_a_local_file(self, tmp_path,
                                                              monkeypatch):
        """`mongod` in the current directory must not mean MongoDB is installed."""
        (tmp_path / "mongod").write_text("")
        monkeypatch.chdir(tmp_path)
        assert _detect_installation(_service("mongod"))[0] is False


class TestAnAbsolutePathGoesThroughTheFilesystem:
    def test_an_existing_file_is_found(self, tmp_path):
        target = tmp_path / "daemon"
        target.write_text("")
        assert _detect_installation(_service(str(target))) == (True, "binary")

    def test_a_missing_file_is_not(self, tmp_path):
        assert _detect_installation(_service(str(tmp_path / "absent"))) == (False, "")

    def test_a_directory_is_not_a_binary(self, tmp_path):
        directory = tmp_path / "somewhere"
        directory.mkdir()
        assert _detect_installation(_service(str(directory))) == (False, "")

    def test_the_first_match_wins(self, tmp_path):
        target = tmp_path / "daemon"
        target.write_text("")
        assert _detect_installation(
            _service(str(tmp_path / "absent"), str(target))
        ) == (True, "binary")


class TestTheRegistryStaysWithinTheContract:
    """Every declared binary is either absolute or a bare command name."""

    def test_no_entry_is_a_relative_path(self):
        from bob.registry import ServiceRegistry
        offenders = [
            f"{s.id}: {b}"
            for s in ServiceRegistry.load()._services
            for b in s.detection.binary
            if not b.startswith("/") and "/" in b
        ]
        assert not offenders, (
            "a relative path with a separator is neither an absolute path nor a "
            "bare command name, and would be resolved against the working "
            "directory: " + ", ".join(offenders)
        )

    def test_no_declared_config_file_is_a_known_directory(self):
        """`/usr/share/jenkins` and `/etc/openvpn` were directories.

        Reading one raises IsADirectoryError, which the caller swallows — so
        the entry was inert, and openvpn's port was never read from the server
        configs that live one level down. Both are globs or files now.
        """
        from bob.registry import ServiceRegistry
        for service in ServiceRegistry.load()._services:
            for path in service.detection.config_files:
                assert not path.rstrip("/").endswith(("/etc/openvpn", "/usr/share/jenkins")), (
                    f"{service.id}: {path} is a directory, not a config file"
                )
