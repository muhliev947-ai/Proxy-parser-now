import json
from pathlib import Path
from unittest.mock import patch

import yaml

from src.generator.generators import sort_by_latency, to_clash, to_singbox
from src.main import build
from src.parser.model import ProxyConfig


def _proxy(server, port, speed_kbps=None, verified=False):
    proxy = ProxyConfig("vless", server, port, uuid="550e8400-e29b-41d4-a716-446655440000")
    proxy.speed_kbps = speed_kbps
    proxy.verified = verified
    return proxy


def test_to_clash_generates_expected_fields():
    proxy = _proxy("192.0.2.10", 443)
    proxy.tls = True
    proxy.flow = "xtls-rprx-vision"

    document = yaml.safe_load(to_clash([proxy]))
    item = document["proxies"][0]

    assert item["server"] == "192.0.2.10"
    assert item["port"] == 443
    assert item["type"] == "vless"
    assert item["uuid"] == "550e8400-e29b-41d4-a716-446655440000"
    assert item["tls"] is True
    assert item["flow"] == "xtls-rprx-vision"


def test_to_singbox_generates_expected_fields():
    proxy = _proxy("192.0.2.11", 443)
    proxy.tls = True
    proxy.sni = "example.org"

    document = json.loads(to_singbox([proxy]))
    item = document["outbounds"][0]

    assert item["type"] == "vless"
    assert item["server"] == "192.0.2.11"
    assert item["server_port"] == 443
    assert item["uuid"] == "550e8400-e29b-41d4-a716-446655440000"
    assert item["tls"]["enabled"] is True


def test_sort_by_latency_puts_fastest_first():
    slow = _proxy("192.0.2.1", 443, speed_kbps=100)
    fast = _proxy("192.0.2.2", 443, speed_kbps=900)
    medium = _proxy("192.0.2.3", 443, speed_kbps=500)

    result = sort_by_latency([slow, fast, medium])

    assert [proxy.server for proxy in result] == ["192.0.2.2", "192.0.2.3", "192.0.2.1"]


def test_sort_by_latency_keeps_unverified_last():
    verified = _proxy("192.0.2.1", 443, speed_kbps=100, verified=True)
    unknown = _proxy("192.0.2.2", 443)

    result = sort_by_latency([unknown, verified])

    assert result[0].server == "192.0.2.1"
    assert result[1].server == "192.0.2.2"


def _write_config(tmp_path, **overrides):
    config = {
        "sources": [],
        "output": {"directory": str(tmp_path / "output"), "formats": ["plaintext"]},
    }
    config.update(overrides)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return config_path


def test_build_writes_subscription_and_docs_copy(tmp_path, monkeypatch):
    """The docs/ copy must stay in sync with output/subscription.txt."""
    monkeypatch.chdir(tmp_path)
    config_path = _write_config(tmp_path)

    proxy = _proxy("192.0.2.10", 443, verified=True)
    with patch("src.main.parse_sources", return_value=[proxy]):
        count = build(str(config_path))

    assert count == 1
    output_text = (tmp_path / "output" / "subscription.txt").read_text(encoding="utf-8")
    docs_text = (tmp_path / "docs" / "subscription.txt").read_text(encoding="utf-8")

    assert "vless://550e8400-e29b-41d4-a716-446655440000@192.0.2.10:443" in output_text
    assert output_text == docs_text


def test_build_clears_stale_subscription_when_nothing_works(tmp_path, monkeypatch):
    """A run that finds no proxies must not leave the old file behind."""
    monkeypatch.chdir(tmp_path)
    config_path = _write_config(tmp_path, output={"directory": str(tmp_path / "output"), "formats": ["plaintext"]})
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "subscription.txt").write_text("stale-content\n", encoding="utf-8")

    with patch("src.main.parse_sources", return_value=[]):
        count = build(str(config_path))

    assert count == 0
    assert (tmp_path / "output" / "subscription.txt").read_text(encoding="utf-8") == ""
    assert (tmp_path / "docs" / "subscription.txt").read_text(encoding="utf-8") == ""


def test_build_applies_latency_sorting(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config_path = _write_config(
        tmp_path,
        output={"directory": str(tmp_path / "output"), "formats": ["plaintext"], "sort_by_latency": True},
    )

    slow = _proxy("192.0.2.1", 443, speed_kbps=100, verified=True)
    fast = _proxy("192.0.2.2", 443, speed_kbps=900, verified=True)
    with patch("src.main.parse_sources", return_value=[slow, fast]):
        build(str(config_path))

    text = (tmp_path / "output" / "subscription.txt").read_text(encoding="utf-8")
    assert text.index("192.0.2.2") < text.index("192.0.2.1")


def test_build_skips_sorting_by_default(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config_path = _write_config(tmp_path)

    slow = _proxy("192.0.2.1", 443, speed_kbps=100, verified=True)
    fast = _proxy("192.0.2.2", 443, speed_kbps=900, verified=True)
    with patch("src.main.parse_sources", return_value=[slow, fast]):
        build(str(config_path))

    text = (tmp_path / "output" / "subscription.txt").read_text(encoding="utf-8")
    assert text.index("192.0.2.1") < text.index("192.0.2.2")
