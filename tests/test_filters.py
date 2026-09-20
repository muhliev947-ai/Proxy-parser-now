"""Tests for the filtering layer in src/main.py.

The spec requires filters by country, proxy type, protocol, minimum speed and
availability, so each one is exercised here against a fixed candidate set.
"""

from unittest.mock import patch

import yaml

from src.main import build
from src.parser.model import ProxyConfig


def _proxy(server, ptype="vless", speed_kbps=None, verified=False, country=None, network=None, reality=None):
    # vless/vmess authenticate with a UUID; trojan/hy2/ss need a password,
    # otherwise to_plaintext_uris() cannot emit a usable URI for them.
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
        "output": {"directory": str(tmp_path / "output"), "formats": ["plaintext"]},
    }
    config.update(filters)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return config_path


def _run(tmp_path, monkeypatch, candidates, filters):
    config_path = _config(tmp_path, monkeypatch, filters)
    with patch("src.main.parse_sources", return_value=candidates):
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

    count, text = _run(
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

    count, text = _run(tmp_path, monkeypatch, [first, second], {})

    assert count == 2
