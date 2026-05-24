"""Tests for the Shodan-style query parser."""

from __future__ import annotations

from app.services.query_parser import parse_query


def _walk(node, path: list[str]) -> bool:
    """Return True if `path` (a list of dict keys) exists in the DSL tree."""
    cur = node
    for key in path:
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        elif isinstance(cur, list):
            for item in cur:
                if _walk(item, [key, *path[path.index(key) + 1 :]]):
                    return True
            return False
        else:
            return False
    return True


class TestQueryParser:
    def test_empty_returns_match_all(self) -> None:
        dsl = parse_query("")
        assert dsl == {"match_all": {}} or "match_all" in dsl

    def test_port_filter(self) -> None:
        dsl = parse_query("port:443")
        text = repr(dsl)
        assert "443" in text
        assert "port" in text or "ports" in text

    def test_country_filter(self) -> None:
        dsl = parse_query("country:US")
        text = repr(dsl)
        assert "US" in text or "us" in text

    def test_combined_filters(self) -> None:
        dsl = parse_query("port:443 country:US")
        text = repr(dsl)
        assert "443" in text
        assert "US" in text or "us" in text

    def test_free_text_only(self) -> None:
        dsl = parse_query("nginx")
        text = repr(dsl)
        assert "nginx" in text

    def test_filter_with_quoted_value(self) -> None:
        dsl = parse_query('org:"Acme Corp"')
        text = repr(dsl)
        assert "Acme" in text

    def test_tls_subject_cn_filter(self) -> None:
        dsl = parse_query("tls.subject_cn:example.com")
        text = repr(dsl)
        assert "example.com" in text
