"""
Unit tests for bob.sysinfo — get_public_ip() and detect_network_context().
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from bob.sysinfo import detect_network_context, get_public_ip


# ---------------------------------------------------------------------------
# get_public_ip
# ---------------------------------------------------------------------------

class TestGetPublicIp:
    def test_offline_returns_empty(self):
        """--offline mode must never make any HTTP call."""
        with patch("urllib.request.urlopen") as mock_open:
            result = get_public_ip(offline=True)
        assert result == ""
        mock_open.assert_not_called()

    def test_first_provider_success(self):
        """Returns IP from the first provider when it responds correctly."""
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b"1.2.3.4"

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = get_public_ip()
        assert result == "1.2.3.4"

    def test_fallback_to_second_provider(self):
        """Falls back to second provider when first raises."""
        import urllib.error

        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b"5.6.7.8"

        call_count = 0

        def side_effect(url, timeout):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise OSError("network error")
            return mock_resp

        with patch("urllib.request.urlopen", side_effect=side_effect):
            result = get_public_ip()
        assert result == "5.6.7.8"
        assert call_count == 2

    def test_all_providers_fail_returns_empty(self):
        """Returns empty string when all providers fail."""
        with patch("urllib.request.urlopen", side_effect=OSError("down")):
            result = get_public_ip()
        assert result == ""

    def test_invalid_response_skips_provider(self):
        """Non-IP response from a provider is ignored; falls back to next."""
        responses = [b"not-an-ip", b"9.10.11.12"]
        idx = 0

        def side_effect(url, timeout):
            nonlocal idx
            mock_resp = MagicMock()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_resp.read.return_value = responses[idx]
            idx += 1
            return mock_resp

        with patch("urllib.request.urlopen", side_effect=side_effect):
            result = get_public_ip()
        assert result == "9.10.11.12"


# ---------------------------------------------------------------------------
# detect_network_context
# ---------------------------------------------------------------------------

class TestDetectNetworkContext:
    def _run_result(self, stdout: str):
        mock = MagicMock()
        mock.stdout = stdout
        mock.returncode = 0
        return mock

    def test_private_gateway_returns_local(self):
        """Default route via private IP → 'local'."""
        route_out = "default via 192.168.1.1 dev eth0"
        addr_out  = ""

        with patch("subprocess.run") as mock_run, \
             patch("bob.sysinfo.get_public_ip", return_value="1.2.3.4") as mock_gip:
            mock_run.return_value = self._run_result(route_out)
            ctx, ip = detect_network_context()

        assert ctx == "local"
        assert ip == "1.2.3.4"
        mock_gip.assert_called_once_with(offline=False)

    def test_private_gateway_offline_skips_lookup(self):
        """offline=True must be forwarded to get_public_ip."""
        route_out = "default via 10.0.0.1 dev eth0"

        with patch("subprocess.run", return_value=self._run_result(route_out)), \
             patch("bob.sysinfo.get_public_ip", return_value="") as mock_gip:
            ctx, ip = detect_network_context(offline=True)

        assert ctx == "local"
        mock_gip.assert_called_once_with(offline=True)

    def test_public_ipv4_on_interface_returns_public(self):
        """Public IPv4 address on an interface → 'public'."""
        route_out = ""   # no default route match
        addr_out  = "inet 203.0.113.5/24 brd 203.0.113.255 scope global eth0"

        call_count = 0
        def run_side(args, **kwargs):
            nonlocal call_count
            call_count += 1
            if "route" in args:
                return self._run_result(route_out)
            return self._run_result(addr_out)

        with patch("subprocess.run", side_effect=run_side):
            ctx, ip = detect_network_context()

        assert ctx == "public"
        assert ip == "203.0.113.5"

    def test_public_ipv6_on_interface_returns_public(self):
        """Public IPv6 address on an interface → 'public' (no public IPv4)."""
        route_out = ""
        addr_out  = (
            "inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0\n"
            "inet6 2001:db8::1/64 scope global\n"
        )

        def run_side(args, **kwargs):
            if "route" in args:
                return self._run_result(route_out)
            return self._run_result(addr_out)

        with patch("subprocess.run", side_effect=run_side):
            ctx, ip = detect_network_context()

        assert ctx == "public"
        assert ip == "2001:db8::1"

    def test_link_local_ipv6_not_treated_as_public(self):
        """fe80:: addresses must not trigger 'public'."""
        route_out = ""
        addr_out  = (
            "inet 192.168.1.10/24 scope global eth0\n"
            "inet6 fe80::1/64 scope link\n"
        )

        def run_side(args, **kwargs):
            if "route" in args:
                return self._run_result(route_out)
            return self._run_result(addr_out)

        with patch("subprocess.run", side_effect=run_side), \
             patch("bob.sysinfo.get_public_ip", return_value=""):
            ctx, ip = detect_network_context()

        assert ctx == "local"

    def test_subprocess_failure_falls_back(self):
        """OSError on subprocess → falls back to get_public_ip."""
        with patch("subprocess.run", side_effect=OSError("no ip")), \
             patch("bob.sysinfo.get_public_ip", return_value="") as mock_gip:
            ctx, ip = detect_network_context()

        assert ctx == "local"
        mock_gip.assert_called_once_with(offline=False)
