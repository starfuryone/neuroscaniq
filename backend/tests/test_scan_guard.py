"""Tests for scan_guard -- the central enforcement point for defensive posture.

These are the most important tests in the project. If any of them break,
the platform may be issuing probes against unauthorized infrastructure
and must be considered compromised in its security posture.
"""

from __future__ import annotations

import pytest

from app.core.errors import ScanTargetRejected
from app.core.scan_guard import assert_scan_allowed


class TestScanGuardBlocksUnsafeTargets:
    """Probes against private/reserved space MUST always fail."""

    @pytest.mark.asyncio
    async def test_blocks_rfc1918_10(self) -> None:
        with pytest.raises(ScanTargetRejected):
            await assert_scan_allowed("10.0.0.1", asset_authorized=True)

    @pytest.mark.asyncio
    async def test_blocks_rfc1918_192(self) -> None:
        with pytest.raises(ScanTargetRejected):
            await assert_scan_allowed("192.168.1.1", asset_authorized=True)

    @pytest.mark.asyncio
    async def test_blocks_rfc1918_172(self) -> None:
        with pytest.raises(ScanTargetRejected):
            await assert_scan_allowed("172.16.5.5", asset_authorized=True)

    @pytest.mark.asyncio
    async def test_blocks_loopback_v4(self) -> None:
        with pytest.raises(ScanTargetRejected):
            await assert_scan_allowed("127.0.0.1", asset_authorized=True)

    @pytest.mark.asyncio
    async def test_blocks_loopback_v6(self) -> None:
        with pytest.raises(ScanTargetRejected):
            await assert_scan_allowed("::1", asset_authorized=True)

    @pytest.mark.asyncio
    async def test_blocks_link_local(self) -> None:
        with pytest.raises(ScanTargetRejected):
            await assert_scan_allowed("169.254.1.1", asset_authorized=True)

    @pytest.mark.asyncio
    async def test_blocks_multicast(self) -> None:
        with pytest.raises(ScanTargetRejected):
            await assert_scan_allowed("224.0.0.1", asset_authorized=True)

    @pytest.mark.asyncio
    async def test_blocks_when_not_authorized(self) -> None:
        # 8.8.8.8 is public but the caller hasn't proven ownership.
        with pytest.raises(ScanTargetRejected):
            await assert_scan_allowed("8.8.8.8", asset_authorized=False)


class TestScanGuardAllowsValid:
    """Authorized public targets covered by the allow-list pass through."""

    @pytest.mark.asyncio
    async def test_allows_test_net_3_when_authorized(self) -> None:
        # Conftest sets ALLOWED_SCAN_CIDRS=203.0.113.0/24
        result = await assert_scan_allowed("203.0.113.42", asset_authorized=True)
        assert result == ["203.0.113.42"]


class TestScanGuardRejectsMalformed:
    @pytest.mark.asyncio
    async def test_rejects_empty_target(self) -> None:
        with pytest.raises(ScanTargetRejected):
            await assert_scan_allowed("", asset_authorized=True)

    @pytest.mark.asyncio
    async def test_rejects_garbage_target(self) -> None:
        with pytest.raises(ScanTargetRejected):
            await assert_scan_allowed("not-an-ip-or-domain-!!!", asset_authorized=True)
