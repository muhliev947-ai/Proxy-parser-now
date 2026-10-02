"""Tests for server geolocation and the country exclusion filter.

The country filter used to be dead code: ``proxy.country`` was never populated
by anything, so ``countries`` matched nothing and ``exclude_countries`` did not
exist. These tests cover both the offline name heuristic and the IP lookup.
"""

from __future__ import annotations

import json
from unittest.mock import patch

from src.parser.geolocation import (
    annotate_countries,
    country_from_name,
    geolocate_ips,
    load_cache,
    proxy_host,
    resolve_host,
)
from src.parser.model import ProxyConfig


def _proxy(server: str, name: str = "") -> ProxyConfig:
    return ProxyConfig("vless", server, 443, uuid="550e8400-e29b-41d4-a716-446655440000", name=name)


# ---------------------------------------------------------------------------
# Name heuristic
# ---------------------------------------------------------------------------

def test_flag_emoji_gives_country_code():
    assert country_from_name("🇷🇺 Moscow 01") == "RU"
    assert country_from_name("🇮🇳IN_12 | 239KB/s") == "IN"
    assert country_from_name("🇳🇱 NL-1") == "NL"


def test_country_and_city_names_give_country_code():
    assert country_from_name("荷兰_100111200") == "NL"
    assert country_from_name("美国_1001111233") == "US"
    assert country_from_name("印度_100111006") == "IN"
    assert country_from_name("Frankfurt fast node") == "DE"


def test_unambiguous_two_letter_code_is_used():
    assert country_from_name("FR-1.2.3.4") == "FR"
    assert country_from_name("JP-tokyo-7") == "JP"


def test_ambiguous_two_letter_code_is_not_misread():
    """"IN" is both India and a common English word, so it is not trusted as a code."""
    assert country_from_name("IN-152.67.160.174-0963") is None
    assert country_from_name("EPODONIOS") is None
    assert country_from_name("server1") is None


def test_empty_name_gives_no_country():
    assert country_from_name(None) is None
    assert country_from_name("") is None
    assert country_from_name("   ") is None


# ---------------------------------------------------------------------------
# Host resolution
# ---------------------------------------------------------------------------

def test_proxy_host_handles_ipv6_and_port():
    assert proxy_host(_proxy("example.com")) == "example.com"
    assert proxy_host(_proxy("[2001:db8::1]:8443")) == "2001:db8::1"
    assert proxy_host(_proxy("")) is None


def test_proxy_host_returns_none_for_blank_server():
    assert proxy_host(_proxy("   ")) is None


def test_resolve_host_passes_ips_through():
    assert resolve_host("8.8.8.8") == "8.8.8.8"


def test_resolve_host_returns_none_for_unresolvable_name():
    with patch("src.parser.geolocation.socket.gethostbyname", side_effect=OSError("no such host")):
        assert resolve_host("definitely-not-a-real-host.invalid") is None


# ---------------------------------------------------------------------------
# IP lookup with a stubbed ip-api
# ---------------------------------------------------------------------------

def test_geolocate_ips_uses_cache_and_writes_new_entries(tmp_path):
    cache_path = tmp_path / "geolocation_cache.json"
    cache_path.write_text(json.dumps({"8.8.8.8": "US"}), encoding="utf-8")

    def fake_post(chunk: list[str]) -> dict[str, str]:
        # Only the uncached IP should be queried.
        assert chunk == ["1.1.1.1"]
        return {"1.1.1.1": "AU"}

    with patch("src.parser.geolocation._post_batch", side_effect=fake_post):
        codes = geolocate_ips(["8.8.8.8", "1.1.1.1"], cache_path=str(cache_path))

    assert codes == {"8.8.8.8": "US", "1.1.1.1": "AU"}
    stored = json.loads(cache_path.read_text(encoding="utf-8"))
    assert stored["1.1.1.1"] == "AU"


def test_geolocate_ips_skips_network_when_everything_is_cached(tmp_path):
    cache_path = tmp_path / "geolocation_cache.json"
    cache_path.write_text(json.dumps({"8.8.8.8": "US"}), encoding="utf-8")

    with patch("src.parser.geolocation._post_batch", side_effect=AssertionError("no network call expected")):
        codes = geolocate_ips(["8.8.8.8"], cache_path=str(cache_path))

    assert codes == {"8.8.8.8": "US"}


def test_geolocate_ips_survives_a_failed_batch(tmp_path):
    cache_path = tmp_path / "geolocation_cache.json"

    with patch("src.parser.geolocation._post_batch", return_value=None):
        codes = geolocate_ips(["8.8.8.8"], cache_path=str(cache_path))

    assert codes == {}
    # The cache file is still created, so the next run can proceed.
    assert cache_path.exists()


def test_load_cache_tolerates_missing_and_corrupt_files(tmp_path):
    assert load_cache(str(tmp_path / "absent.json")) == {}
    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("{not json", encoding="utf-8")
    assert load_cache(str(corrupt)) == {}


# ---------------------------------------------------------------------------
# annotate_countries
# ---------------------------------------------------------------------------

def test_annotate_countries_prefers_ip_lookup_over_name(tmp_path):
    cache_path = tmp_path / "geolocation_cache.json"
    proxies = [
        # Name says India, server is really in Russia: the IP wins.
        _proxy("185.220.101.1", name="🇮🇳 fast node"),
        # Name says nothing, IP is in Germany.
        _proxy("185.220.101.2", name="EPODONIOS"),
    ]

    def fake_post(chunk: list[str]) -> dict[str, str]:
        return {"185.220.101.1": "RU", "185.220.101.2": "DE"}

    with patch("src.parser.geolocation.resolve_host", side_effect=lambda host: host), \
            patch("src.parser.geolocation._post_batch", side_effect=fake_post):
        annotate_countries(proxies, cache_path=str(cache_path))

    assert [p.country for p in proxies] == ["RU", "DE"]


def test_annotate_countries_falls_back_to_name_when_network_fails(tmp_path):
    """No IP resolves, so the name hint is the only signal available."""
    cache_path = tmp_path / "geolocation_cache.json"
    proxies = [_proxy("ru-node.example", name="🇷🇺 Moscow 01")]

    with patch("src.parser.geolocation.resolve_host", return_value=None):
        annotate_countries(proxies, cache_path=str(cache_path))

    assert proxies[0].country == "RU"


def test_annotate_countries_leaves_unknown_countries_blank(tmp_path):
    cache_path = tmp_path / "geolocation_cache.json"
    proxies = [_proxy("10.0.0.1", name="server1")]

    with patch("src.parser.geolocation.resolve_host", side_effect=lambda host: host), \
            patch("src.parser.geolocation._post_batch", return_value={}):
        annotate_countries(proxies, cache_path=str(cache_path))

    assert proxies[0].country is None
