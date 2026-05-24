"""Tests for the Nmap scanner integration.

Validates authorization enforcement, flag blocking, XML parsing,
timeout handling, and service enrichment logic.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from app.core.errors import ScanTargetRejected
from app.services.nmap_scanner import (
    BLOCKED_FLAGS,
    NmapScanResult,
    NmapServiceResult,
    _build_command,
    _parse_xml,
    _validate_flags,
    enrich_services,
    is_nmap_available,
    run_nmap_scan,
)


SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sS -sV -T3 -p 22,80,443 203.0.113.10"
         start="1716508800" startstr="Fri May 24 00:00:00 2026"
         version="7.94" xmloutputversion="1.05">
<host starttime="1716508800" endtime="1716508810">
  <status state="up" reason="syn-ack"/>
  <address addr="203.0.113.10" addrtype="ipv4"/>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open" reason="syn-ack"/>
      <service name="ssh" product="OpenSSH" version="9.6p1"
               extrainfo="Ubuntu Linux; protocol 2.0" method="probed" conf="10">
        <cpe>cpe:/a:openbsd:openssh:9.6p1</cpe>
      </service>
    </port>
    <port protocol="tcp" portid="80">
      <state state="open" reason="syn-ack"/>
      <service name="http" product="nginx" version="1.24.0" method="probed" conf="10">
        <cpe>cpe:/a:igor_sysoev:nginx:1.24.0</cpe>
      </service>
    </port>
    <port protocol="tcp" portid="443">
      <state state="open" reason="syn-ack"/>
      <service name="ssl/http" product="nginx" version="1.24.0" method="probed" conf="10">
        <cpe>cpe:/a:igor_sysoev:nginx:1.24.0</cpe>
      </service>
    </port>
  </ports>
</host>
</nmaprun>
"""

SAMPLE_NMAP_XML_EMPTY = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94" xmloutputversion="1.05">
<host>
  <status state="up"/>
  <address addr="203.0.113.10" addrtype="ipv4"/>
  <ports></ports>
</host>
</nmaprun>
"""


class TestFlagValidation:
    def test_rejects_os_fingerprint(self) -> None:
        with pytest.raises(ValueError, match="Blocked"):
            _validate_flags(["-O"])

    def test_rejects_script_flag(self) -> None:
        with pytest.raises(ValueError, match="Blocked"):
            _validate_flags(["--script"])

    def test_rejects_input_file(self) -> None:
        with pytest.raises(ValueError, match="Blocked"):
            _validate_flags(["-iL"])

    def test_rejects_decoy(self) -> None:
        with pytest.raises(ValueError, match="Blocked"):
            _validate_flags(["-D"])

    def test_rejects_spoof_mac(self) -> None:
        with pytest.raises(ValueError, match="Blocked"):
            _validate_flags(["--spoof-mac"])

    def test_rejects_aggressive(self) -> None:
        with pytest.raises(ValueError, match="Blocked"):
            _validate_flags(["-A"])

    def test_rejects_udp(self) -> None:
        with pytest.raises(ValueError, match="Blocked"):
            _validate_flags(["-sU"])

    def test_rejects_source_spoof(self) -> None:
        with pytest.raises(ValueError, match="Blocked"):
            _validate_flags(["-S"])

    def test_accepts_empty(self) -> None:
        assert _validate_flags(None) == []
        assert _validate_flags([]) == []

    def test_accepts_safe_timing(self) -> None:
        result = _validate_flags(["-T2"])
        assert result == ["-T2"]

    def test_all_blocked_flags_rejected(self) -> None:
        for flag in BLOCKED_FLAGS:
            with pytest.raises(ValueError, match="Blocked"):
                _validate_flags([flag])


class TestXMLParsing:
    def test_parses_valid_xml(self) -> None:
        results = _parse_xml(SAMPLE_NMAP_XML)
        assert len(results) == 3

        ssh = next(r for r in results if r.port == 22)
        assert ssh.service == "ssh"
        assert ssh.product == "OpenSSH"
        assert ssh.version == "9.6p1"
        assert ssh.cpe == "cpe:/a:openbsd:openssh:9.6p1"
        assert ssh.protocol == "tcp"
        assert ssh.state == "open"

        http = next(r for r in results if r.port == 80)
        assert http.product == "nginx"
        assert http.version == "1.24.0"

    def test_parses_empty_ports(self) -> None:
        results = _parse_xml(SAMPLE_NMAP_XML_EMPTY)
        assert results == []

    def test_handles_malformed_xml(self) -> None:
        results = _parse_xml("this is not xml <><>")
        assert results == []

    def test_handles_empty_string(self) -> None:
        results = _parse_xml("")
        assert results == []

    def test_handles_partial_service_info(self) -> None:
        xml = """<?xml version="1.0"?>
        <nmaprun><host><ports>
          <port protocol="tcp" portid="8080">
            <state state="open"/>
            <service name="http-proxy"/>
          </port>
        </ports></host></nmaprun>"""
        results = _parse_xml(xml)
        assert len(results) == 1
        assert results[0].port == 8080
        assert results[0].service == "http-proxy"
        assert results[0].product == ""
        assert results[0].version == ""
        assert results[0].cpe == ""


class TestBuildCommand:
    def test_default_command(self) -> None:
        cmd = _build_command("203.0.113.10", [80, 443])
        assert cmd[0] == "nmap"
        assert "-sT" in cmd
        assert "-sV" in cmd
        assert "-T3" in cmd
        assert "--max-rate" in cmd
        assert "100" in cmd
        assert "--host-timeout" in cmd
        assert "90s" in cmd
        assert "-p" in cmd
        assert "80,443" in cmd
        assert "203.0.113.10" == cmd[-1]

    def test_rejects_blocked_flags(self) -> None:
        with pytest.raises(ValueError):
            _build_command("203.0.113.10", [80], extra_flags=["-A"])


class TestAuthorization:
    @pytest.mark.asyncio
    async def test_rejects_unauthorized_scan(self) -> None:
        with pytest.raises(ScanTargetRejected, match="asset_authorized"):
            await run_nmap_scan("203.0.113.10", [80], asset_authorized=False)

    @pytest.mark.asyncio
    async def test_rejects_private_ip(self) -> None:
        with pytest.raises(ScanTargetRejected):
            await run_nmap_scan("10.0.0.1", [80], asset_authorized=True)

    @pytest.mark.asyncio
    async def test_rejects_loopback(self) -> None:
        with pytest.raises(ScanTargetRejected):
            await run_nmap_scan("127.0.0.1", [80], asset_authorized=True)

    @pytest.mark.asyncio
    async def test_rejects_multicast(self) -> None:
        with pytest.raises(ScanTargetRejected):
            await run_nmap_scan("224.0.0.1", [80], asset_authorized=True)

    @pytest.mark.asyncio
    async def test_rejects_link_local(self) -> None:
        with pytest.raises(ScanTargetRejected):
            await run_nmap_scan("169.254.1.1", [80], asset_authorized=True)

    @pytest.mark.asyncio
    async def test_rejects_blocked_flags_in_scan(self) -> None:
        with pytest.raises(ScanTargetRejected):
            await run_nmap_scan(
                "203.0.113.10", [80],
                asset_authorized=True,
                extra_flags=["--script", "vuln"],
            )


class TestNmapDisabled:
    @pytest.mark.asyncio
    async def test_returns_disabled_when_feature_off(self) -> None:
        with patch("app.services.nmap_scanner.settings") as mock_settings:
            mock_settings.nmap_enabled = False
            mock_settings.blocked_networks = []
            result = await run_nmap_scan("203.0.113.10", [80], asset_authorized=True)
            assert result.error == "nmap_disabled"

    @pytest.mark.asyncio
    async def test_returns_not_installed_when_missing(self) -> None:
        with patch("app.services.nmap_scanner.settings") as mock_settings, \
             patch("app.services.nmap_scanner.is_nmap_available", return_value=False):
            mock_settings.nmap_enabled = True
            mock_settings.blocked_networks = []
            result = await run_nmap_scan("203.0.113.10", [80], asset_authorized=True)
            assert result.error == "nmap_not_installed"


class TestTimeout:
    @pytest.mark.asyncio
    async def test_handles_timeout(self) -> None:
        async def slow_communicate():
            await asyncio.sleep(10)
            return b"", b""

        with patch("app.services.nmap_scanner.settings") as mock_settings, \
             patch("app.services.nmap_scanner.is_nmap_available", return_value=True), \
             patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_settings.nmap_enabled = True
            mock_settings.blocked_networks = []

            mock_proc = AsyncMock()
            mock_proc.communicate = slow_communicate
            mock_proc.kill = AsyncMock()
            mock_proc.wait = AsyncMock()
            mock_exec.return_value = mock_proc

            result = await run_nmap_scan(
                "203.0.113.10", [80],
                asset_authorized=True,
                timeout=1,
            )
            assert result.error == "timeout"


class TestEnrichServices:
    def test_enriches_matching_ports(self) -> None:
        existing = [
            {"port": 22, "protocol": "tcp", "state": "open", "banner": "SSH-2.0"},
            {"port": 80, "protocol": "tcp", "state": "open", "banner": ""},
        ]
        nmap_results = [
            NmapServiceResult(port=22, protocol="tcp", state="open",
                              service="ssh", product="OpenSSH", version="9.6p1",
                              cpe="cpe:/a:openbsd:openssh:9.6p1"),
            NmapServiceResult(port=80, protocol="tcp", state="open",
                              service="http", product="nginx", version="1.24.0",
                              cpe="cpe:/a:igor_sysoev:nginx:1.24.0"),
        ]
        enriched = enrich_services(existing, nmap_results)
        assert len(enriched) == 2
        assert enriched[0]["product"] == "OpenSSH"
        assert enriched[0]["version"] == "9.6p1"
        assert enriched[0]["cpe"] == "cpe:/a:openbsd:openssh:9.6p1"
        assert enriched[1]["product"] == "nginx"

    def test_does_not_add_new_ports(self) -> None:
        existing = [{"port": 80, "protocol": "tcp", "state": "open"}]
        nmap_results = [
            NmapServiceResult(port=80, protocol="tcp", state="open",
                              service="http", product="nginx", version="1.24.0", cpe=""),
            NmapServiceResult(port=443, protocol="tcp", state="open",
                              service="https", product="nginx", version="1.24.0", cpe=""),
        ]
        enriched = enrich_services(existing, nmap_results)
        assert len(enriched) == 1
        assert enriched[0]["port"] == 80

    def test_does_not_overwrite_with_empty(self) -> None:
        existing = [{"port": 80, "protocol": "tcp", "state": "open", "banner": "hello"}]
        nmap_results = [
            NmapServiceResult(port=80, protocol="tcp", state="open",
                              service="", product="", version="", cpe=""),
        ]
        enriched = enrich_services(existing, nmap_results)
        assert enriched[0]["banner"] == "hello"
        assert "product" not in enriched[0]

    def test_skips_closed_ports(self) -> None:
        existing = [{"port": 80, "protocol": "tcp", "state": "open"}]
        nmap_results = [
            NmapServiceResult(port=80, protocol="tcp", state="closed",
                              service="http", product="nginx", version="1.24.0", cpe=""),
        ]
        enriched = enrich_services(existing, nmap_results)
        assert "product" not in enriched[0]

    def test_preserves_existing_fields(self) -> None:
        existing = [{"port": 22, "protocol": "tcp", "state": "open", "banner": "SSH-2.0", "title": "My SSH"}]
        nmap_results = [
            NmapServiceResult(port=22, protocol="tcp", state="open",
                              service="ssh", product="OpenSSH", version="8.9", cpe=""),
        ]
        enriched = enrich_services(existing, nmap_results)
        assert enriched[0]["banner"] == "SSH-2.0"
        assert enriched[0]["title"] == "My SSH"
        assert enriched[0]["product"] == "OpenSSH"


class TestScanGuardIntegration:
    def test_nmap_available_check(self) -> None:
        result = is_nmap_available()
        assert isinstance(result, bool)

    @pytest.mark.asyncio
    async def test_empty_ports_returns_early(self) -> None:
        with patch("app.services.nmap_scanner.settings") as mock_settings:
            mock_settings.nmap_enabled = True
            mock_settings.blocked_networks = []
            result = await run_nmap_scan("203.0.113.10", [], asset_authorized=True)
            assert result.error == "no_ports_specified"
