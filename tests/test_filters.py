"""Tests for the filtering layer in the shared pipeline.

The spec requires filters by country, proxy type, protocol, minimum speed and
availability, so each one is exercised here against a fixed candidate set.
"""

from unittest.mock import patch

import yaml

from src.checker.pipeline import build
from src.parser.model import ProxyConfig


def _proxy(server, ptype="vless", speed_kbps=None, verified=False, country=None,
           network=None, reality=None):
    credentials = (
        {"uuid": "550e8400-e29b-41d4-a716-446655440000"}
        if ptype in {"vless", "vmess"}
        else {"password": "secretpassword"}
    )
    proxy = ProxyConfig(ptype, server, 443, **credentials)
    proxy.speed_kbps = speed_kbps
    proxy.verified = verified
    proxy.country = country
    proxy.network = network
    proxy.reality = reality
    return proxy


def _config(tmp_path, monkeypatch, filters):
    monkeypatch.chdir(tmp_path)
    config = {
        "sources": [],
        "check": {"reverify_before_publish": False},
        "output": {"directory": str(tmp_path / "output"), "formats": ["plaintext"]},
    }
    config.update(filters)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return config_path


def _run(tmp_path, monkeypatch, candidates, filters):
    config_path = _config(tmp_path, monkeypatch, filters)
    with patch("src.checker.pipeline.parse_sources", return_value=candidates), \
            patch("src.checker.pipeline.check_proxy", side_effect=lambda p, c: p), \
            patch("src.checker.pipeline.annotate_countries", side_effect=lambda proxies, **kwargs: None):
        count = build(str(config_path))
    text = (tmp_path / "output" / "subscription.txt").read_text(encoding="utf-8")
    return count, text


def test_filter_by_type(tmp_path, monkeypatch):
    vless = _proxy("192.0.2.1", "vless", verified=True)
    trojan = _proxy("192.0.2.2", "trojan", verified=True)

    count, text = _run(tmp_path, monkeypatch, [vless, trojan], {"types": ["trojan"]})

    assert count == 1
    assert "192.0.2.2" in text
    assert "192.0.2.1" not in text


def test_filter_by_country(tmp_path, monkeypatch):
    ru = _proxy("192.0.2.1", country="RU", verified=True)
    de = _proxy("192.0.2.2", country="DE", verified=True)

    count, text = _run(tmp_path, monkeypatch, [ru, de], {"countries": ["RU"]})

    assert count == 1
    assert "192.0.2.1" in text
    assert "192.0.2.2" not in text


def test_exclude_countries_drops_listed_country(tmp_path, monkeypatch):
    """Russia is excluded while every other country is kept."""
    ru = _proxy("192.0.2.1", country="RU", verified=True)
    de = _proxy("192.0.2.2", country="DE", verified=True)
    in_ = _proxy("192.0.2.3", country="IN", verified=True)

    count, text = _run(tmp_path, monkeypatch, [ru, de, in_], {"exclude_countries": ["RU"]})

    assert count == 2
    assert "192.0.2.1" not in text
    assert "192.0.2.2" in text
    assert "192.0.2.3" in text


def test_exclude_countries_never_reaches_verification(tmp_path, monkeypatch):
    """A node from an excluded country must not be checked at all."""
    ru = _proxy("192.0.2.1", country="RU", verified=True)
    de = _proxy("192.0.2.2", country="DE", verified=True)

    checked: list[str] = []

    def verify_fn(proxies, _round):
        checked.extend(proxy.server for proxy in proxies)
        return proxies

    config_path = _config(tmp_path, monkeypatch, {"exclude_countries": ["RU"]})
    with patch("src.checker.pipeline.parse_sources", return_value=[ru, de]), \
            patch("src.checker.pipeline.HiddifyBackend.verify_batch", side_effect=lambda p: verify_fn(p, 1)), \
            patch("src.checker.pipeline.HiddifyBackend.load_tags", return_value=None):
        build(str(config_path))

    assert checked == ["192.0.2.2"]


def test_exclude_countries_can_be_combined_with_countries(tmp_path, monkeypatch):
    """`countries` narrows the allow-list, `exclude_countries` removes from it."""
    ru = _proxy("192.0.2.1", country="RU", verified=True)
    de = _proxy("192.0.2.2", country="DE", verified=True)
    in_ = _proxy("192.0.2.3", country="IN", verified=True)

    count, text = _run(
        tmp_path, monkeypatch, [ru, de, in_],
        {"countries": ["DE", "IN"], "exclude_countries": ["IN"]},
    )

    assert count == 1
    assert "192.0.2.2" in text


def test_filter_by_protocol_reality(tmp_path, monkeypatch):
    reality = _proxy("192.0.2.1", reality={"public_key": "pk", "short_id": "sid"}, verified=True)
    plain = _proxy("192.0.2.2", network="ws", verified=True)

    count, text = _run(tmp_path, monkeypatch, [reality, plain], {"protocols": ["reality"]})

    assert count == 1
    assert "192.0.2.1" in text
    assert "192.0.2.2" not in text


def test_filter_by_min_speed(tmp_path, monkeypatch):
    fast = _proxy("192.0.2.1", speed_kbps=900, verified=True)
    slow = _proxy("192.0.2.2", speed_kbps=100, verified=True)

    count, text = _run(tmp_path, monkeypatch, [fast, slow], {"min_speed_kbps": 500})

    assert count == 1
    assert "192.0.2.1" in text
    assert "192.0.2.2" not in text


def test_include_unchecked_publishes_unverified(tmp_path, monkeypatch):
    verified = _proxy("192.0.2.1", verified=True)
    unverified = _proxy("192.0.2.2")

    count, _text = _run(
        tmp_path, monkeypatch, [verified, unverified],
        {"output": {"directory": str(tmp_path / "output"), "formats": ["plaintext"], "include_unchecked": True}},
    )

    assert count == 2


def test_exclude_unchecked_drops_unverified(tmp_path, monkeypatch):
    verified = _proxy("192.0.2.1", verified=True)
    unverified = _proxy("192.0.2.2")

    count, text = _run(
        tmp_path, monkeypatch, [verified, unverified],
        {"output": {"directory": str(tmp_path / "output"), "formats": ["plaintext"], "include_unchecked": False}},
    )

    assert count == 1
    assert "192.0.2.1" in text
    assert "192.0.2.2" not in text


def test_empty_filters_keep_everything(tmp_path, monkeypatch):
    first = _proxy("192.0.2.1", "trojan", verified=True)
    second = _proxy("192.0.2.2", "vless", verified=True)

    count, _text = _run(tmp_path, monkeypatch, [first, second], {})

    assert count == 2
