"""Tests for the deterministic risk scorer."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.services.risk_scorer import risk_scorer


class TestRiskScorer:
    def test_no_exposure_is_low(self) -> None:
        r = risk_scorer.score(ports=[443], services=[{"port": 443}], tls={"not_after": (datetime.now(timezone.utc) + timedelta(days=200)).strftime("%b %d %H:%M:%S %Y GMT")}, http=None, tags=[])
        assert r.level == "low"
        assert r.score < 25

    def test_exposed_mongodb_is_high_or_critical(self) -> None:
        r = risk_scorer.score(ports=[27017], services=[{"port": 27017, "banner": "MongoDB"}], tls=None, http=None, tags=[])
        assert r.level in ("high", "critical")

    def test_exposed_rdp_is_high(self) -> None:
        r = risk_scorer.score(ports=[3389], services=[{"port": 3389}], tls=None, http=None, tags=[])
        assert r.score >= 25

    def test_multiple_sensitive_ports_stacks(self) -> None:
        single = risk_scorer.score(ports=[3389], services=[{"port": 3389}], tls=None, http=None, tags=[])
        many = risk_scorer.score(
            ports=[3389, 6379, 27017],
            services=[{"port": 3389}, {"port": 6379}, {"port": 27017}],
            tls=None,
            http=None,
            tags=[],
        )
        assert many.score > single.score

    def test_factors_are_explainable(self) -> None:
        r = risk_scorer.score(ports=[6379], services=[{"port": 6379, "banner": "redis"}], tls=None, http=None, tags=[])
        # Every contribution must be present in factors so the UI can show *why*.
        assert isinstance(r.factors, dict)
        assert len(r.factors) > 0

    def test_score_is_capped_at_100(self) -> None:
        r = risk_scorer.score(
            ports=[21, 23, 3389, 6379, 27017, 9200, 5432, 3306, 1433, 445],
            services=[{"port": p} for p in [21, 23, 3389, 6379, 27017, 9200, 5432, 3306, 1433, 445]],
            tls=None,
            http=None,
            tags=["default_credentials_likely", "known_botnet_c2"],
        )
        assert r.score <= 100
