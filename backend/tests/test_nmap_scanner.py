"""Tests for the Nmap scanner integration.

Validates authorization enforcement, flag blocking, XML parsing,
timeout handling, concurrency semaphore, Redis cache/cooldown,
metrics, and service enrichment logic.
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.errors import ScanTargetRejected
from app.services.nmap_scanner import (
    BLOCKED_FLAGS,
    NmapScanResult,
    NmapServiceResult,
    _build_command,
    _cache_dict_to_result,
    _parse_xml,
    _result_to_cache_dict,
    _validate_flags,
    enrich_services,
    is_nmap_available,
    run_nmap_scan,
)


SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -sV -T3 -p 22,80,443 203.0.113.10"
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

    def test_rejects_syn_scan(self) -> None:
        with pytest.raises(ValueError, match="Blocked"):
            _validate_flags(["-sS"])

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
        assert "--host-timeout" in cmd
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
            mock_settings.nmap_max_concurrent = 4
            mock_settings.nmap_max_rate_pps = 100
            mock_settings.blocked_networks = []
            result = await run_nmap_scan("203.0.113.10", [80], asset_authorized=True)
            assert result.error == "nmap_disabled"

    @pytest.mark.asyncio
    async def test_returns_not_installed_when_missing(self) -> None:
        with patch("app.services.nmap_scanner.settings") as mock_settings, \
             patch("app.services.nmap_scanner.is_nmap_available", return_value=False), \
             patch("app.services.nmap_scanner._check_cooldown", return_value=False), \
             patch("app.services.nmap_scanner._check_cache", return_value=None):
            mock_settings.nmap_enabled = True
            mock_settings.nmap_max_concurrent = 4
            mock_settings.nmap_max_rate_pps = 100
            mock_settings.blocked_networks = []
            result = await run_nmap_scan("203.0.113.10", [80], asset_authorized=True)
            assert result.error == "nmap_not_installed"


class TestCooldown:
    @pytest.mark.asyncio
    async def test_cooldown_rejects_repeated_scan(self) -> None:
        with patch("app.services.nmap_scanner.settings") as mock_settings, \
             patch("app.services.nmap_scanner._check_cooldown", return_value=True):
            mock_settings.nmap_enabled = True
            mock_settings.nmap_max_concurrent = 4
            mock_settings.nmap_max_rate_pps = 100
            mock_settings.blocked_networks = []
            result = await run_nmap_scan("203.0.113.10", [80], asset_authorized=True)
            assert result.error == "cooldown_active"

    @pytest.mark.asyncio
    async def test_bypass_cooldown_for_monitors(self) -> None:
        with patch("app.services.nmap_scanner.settings") as mock_settings, \
             patch("app.services.nmap_scanner._check_cooldown", return_value=True) as mock_cd, \
             patch("app.services.nmap_scanner._check_cache", return_value=None), \
             patch("app.services.nmap_scanner.is_nmap_available", return_value=False):
            mock_settings.nmap_enabled = True
            mock_settings.nmap_max_concurrent = 4
            mock_settings.nmap_max_rate_pps = 100
            mock_settings.blocked_networks = []
            result = await run_nmap_scan(
                "203.0.113.10", [80],
                asset_authorized=True,
                bypass_cooldown=True,
            )
            # Cooldown check should be skipped; hits nmap_not_installed instead
            mock_cd.assert_not_called()
            assert result.error == "nmap_not_installed"


class TestCache:
    @pytest.mark.asyncio
    async def test_cache_hit_returns_cached_result(self) -> None:
        cached = NmapScanResult(
            ip="203.0.113.10",
            services=[NmapServiceResult(
                port=80, protocol="tcp", state="open",
                service="http", product="nginx", version="1.24.0", cpe="",
            )],
            scan_time_ms=500,
            from_cache=True,
        )
        with patch("app.services.nmap_scanner.settings") as mock_settings, \
             patch("app.services.nmap_scanner._check_cooldown", return_value=False), \
             patch("app.services.nmap_scanner._check_cache", return_value=cached):
            mock_settings.nmap_enabled = True
            mock_settings.nmap_max_concurrent = 4
            mock_settings.nmap_max_rate_pps = 100
            mock_settings.blocked_networks = []
            result = await run_nmap_scan("203.0.113.10", [80], asset_authorized=True)
            assert result.from_cache is True
            assert result.services[0].product == "nginx"

    @pytest.mark.asyncio
    async def test_force_refresh_skips_cache(self) -> None:
        with patch("app.services.nmap_scanner.settings") as mock_settings, \
             patch("app.services.nmap_scanner._check_cooldown", return_value=False), \
             patch("app.services.nmap_scanner._check_cache") as mock_cache, \
             patch("app.services.nmap_scanner.is_nmap_available", return_value=False):
            mock_settings.nmap_enabled = True
            mock_settings.nmap_max_concurrent = 4
            mock_settings.nmap_max_rate_pps = 100
            mock_settings.blocked_networks = []
            result = await run_nmap_scan(
                "203.0.113.10", [80],
                asset_authorized=True,
                force_refresh=True,
            )
            # Cache should NOT be checked when force_refresh=True
            mock_cache.assert_not_called()
            assert result.error == "nmap_not_installed"

    def test_cache_serialization_roundtrip(self) -> None:
        original = NmapScanResult(
            ip="203.0.113.10",
            services=[NmapServiceResult(
                port=22, protocol="tcp", state="open",
                service="ssh", product="OpenSSH", version="9.6p1",
                cpe="cpe:/a:openbsd:openssh:9.6p1", extra_info="Ubuntu",
            )],
            scan_time_ms=1234,
        )
        cache_dict = _result_to_cache_dict(original)
        restored = _cache_dict_to_result(cache_dict)
        assert restored.ip == original.ip
        assert len(restored.services) == 1
        assert restored.services[0].product == "OpenSSH"
        assert restored.services[0].cpe == "cpe:/a:openbsd:openssh:9.6p1"
        assert restored.from_cache is True


class TestSemaphore:
    @pytest.mark.asyncio
    async def test_concurrency_bounded(self) -> None:
        """Verify the distributed semaphore limits concurrent nmap processes."""
        from app.services.nmap_scanner import RedisDistributedSemaphore

        execution_order: list[str] = []
        max_concurrent = 0
        current_concurrent = 0

        # Use a real asyncio.Semaphore to simulate Redis-based limiting
        local_sem = asyncio.Semaphore(2)

        async def mock_acquire(self) -> bool:
            acquired = local_sem._value > 0
            if acquired:
                await local_sem.acquire()
                self._slot_id = "mock_slot"
            return acquired

        async def mock_release(self) -> None:
            if self._slot_id is not None:
                local_sem.release()
                self._slot_id = None

        async def mock_exec(*args, **kwargs):
            nonlocal current_concurrent, max_concurrent
            current_concurrent += 1
            max_concurrent = max(max_concurrent, current_concurrent)
            execution_order.append(f"start_{current_concurrent}")

            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(
                SAMPLE_NMAP_XML.encode(), b""
            ))
            mock_proc.returncode = 0

            await asyncio.sleep(0.05)
            current_concurrent -= 1
            return mock_proc

        with patch("app.services.nmap_scanner.settings") as mock_settings, \
             patch("app.services.nmap_scanner._check_cooldown", return_value=False), \
             patch("app.services.nmap_scanner._check_cache", return_value=None), \
             patch("app.services.nmap_scanner._store_cache", new_callable=AsyncMock), \
             patch("app.services.nmap_scanner._set_cooldown", new_callable=AsyncMock), \
             patch("app.services.nmap_scanner.is_nmap_available", return_value=True), \
             patch.object(RedisDistributedSemaphore, "acquire", mock_acquire), \
             patch.object(RedisDistributedSemaphore, "release", mock_release), \
             patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            mock_settings.nmap_enabled = True
            mock_settings.nmap_max_concurrent = 2
            mock_settings.nmap_max_rate_pps = 100
            mock_settings.blocked_networks = []

            tasks = [
                run_nmap_scan("203.0.113.10", [80], asset_authorized=True),
                run_nmap_scan("203.0.113.10", [443], asset_authorized=True),
                run_nmap_scan("203.0.113.10", [22], asset_authorized=True),
            ]
            results = await asyncio.gather(*tasks)
            assert all(r.error is None for r in results)
            # Semaphore(2) means at most 2 concurrent
            assert max_concurrent <= 2


class TestTimeout:
    @pytest.mark.asyncio
    async def test_handles_timeout(self) -> None:
        from app.services.nmap_scanner import RedisDistributedSemaphore

        async def slow_communicate():
            await asyncio.sleep(10)
            return b"", b""

        async def mock_acquire(self) -> bool:
            self._slot_id = "mock"
            return True

        async def mock_release(self) -> None:
            self._slot_id = None

        with patch("app.services.nmap_scanner.settings") as mock_settings, \
             patch("app.services.nmap_scanner._check_cooldown", return_value=False), \
             patch("app.services.nmap_scanner._check_cache", return_value=None), \
             patch("app.services.nmap_scanner.is_nmap_available", return_value=True), \
             patch.object(RedisDistributedSemaphore, "acquire", mock_acquire), \
             patch.object(RedisDistributedSemaphore, "release", mock_release), \
             patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_settings.nmap_enabled = True
            mock_settings.nmap_max_concurrent = 4
            mock_settings.nmap_max_rate_pps = 100
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


class TestMetrics:
    @pytest.mark.asyncio
    async def test_rejected_scan_increments_counter(self) -> None:
        from app.services.metrics import SCAN_REJECTED
        before = SCAN_REJECTED.labels(scan_type="nmap", reason="unauthorized")._value.get()
        with pytest.raises(ScanTargetRejected):
            await run_nmap_scan("203.0.113.10", [80], asset_authorized=False)
        after = SCAN_REJECTED.labels(scan_type="nmap", reason="unauthorized")._value.get()
        assert after == before + 1

    @pytest.mark.asyncio
    async def test_cooldown_increments_counter(self) -> None:
        from app.services.metrics import NMAP_COOLDOWN_REJECTED
        before = NMAP_COOLDOWN_REJECTED._value.get()
        with patch("app.services.nmap_scanner.settings") as mock_settings, \
             patch("app.services.nmap_scanner._check_cooldown", return_value=True):
            mock_settings.nmap_enabled = True
            mock_settings.nmap_max_concurrent = 4
            mock_settings.nmap_max_rate_pps = 100
            mock_settings.blocked_networks = []
            await run_nmap_scan("203.0.113.10", [80], asset_authorized=True)
        after = NMAP_COOLDOWN_REJECTED._value.get()
        assert after == before + 1


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
            mock_settings.nmap_max_concurrent = 4
            mock_settings.nmap_max_rate_pps = 100
            mock_settings.blocked_networks = []
            result = await run_nmap_scan("203.0.113.10", [], asset_authorized=True)
            assert result.error == "no_ports_specified"
