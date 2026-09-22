import json
from unittest.mock import patch

import yaml

from scripts.metrics_summary import build_alert, build_summary
from src.checker.pipeline import build
from src.generator.generators import sort_by_latency, to_clash, to_singbox
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
        "check": {"reverify_before_publish": False},
        "output": {"directory": str(tmp_path / "output"), "formats": ["plaintext"]},
    }
    config.update(overrides)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return config_path


def test_build_writes_metrics_json(tmp_path, monkeypatch):
    """Each successful build must produce output/metrics.json with run counts."""
    monkeypatch.chdir(tmp_path)
    config_path = _write_config(
        tmp_path,
        check={"reverify_before_publish": False, "min_working_nodes": 2},
    )
    proxies = [
        _proxy("192.0.2.1", 443, verified=True),
        _proxy("192.0.2.2", 443, verified=False),
        _proxy("192.0.2.3", 443, verified=True),
    ]
    with patch("src.checker.pipeline.parse_sources", return_value=proxies), \
            patch("src.checker.pipeline.check_proxy", side_effect=lambda p, c: p):
        build(str(config_path))

    metrics = json.loads((tmp_path / "output" / "metrics.json").read_text(encoding="utf-8"))
    assert metrics["checked"] == 3
    assert metrics["verified"] == 2
    assert metrics["published"] == 2
    assert metrics["min_working_nodes"] == 2
    assert metrics["healthy"] is True


def test_build_metrics_healthy_flag(tmp_path, monkeypatch):
    """healthy is False when published < min_working_nodes."""
    monkeypatch.chdir(tmp_path)
    config_path = _write_config(
        tmp_path,
        check={"reverify_before_publish": False, "min_working_nodes": 5},
    )
    proxies = [
        _proxy(f"192.0.2.{i}", 443, verified=True) for i in range(1, 4)
    ]
    with patch("src.checker.pipeline.parse_sources", return_value=proxies), \
            patch("src.checker.pipeline.check_proxy", side_effect=lambda p, c: p):
        build(str(config_path))

    metrics = json.loads((tmp_path / "output" / "metrics.json").read_text(encoding="utf-8"))
    assert metrics["published"] == 3
    assert metrics["min_working_nodes"] == 5
    assert metrics["healthy"] is False


def test_metrics_summary_healthy():
    """build_summary produces normal output without warning when healthy."""
    metrics = {
        "checked": 32, "verified": 9, "published": 9,
        "timestamp_utc": "2026-01-01T00:00:00Z",
        "min_working_nodes": 5, "healthy": True,
    }
    text = build_summary(metrics)
    assert "## Build metrics" in text
    assert "Checked: **32**" in text
    assert "Published: **9**" in text
    assert "⚠️" not in text


def test_metrics_summary_warning_when_unhealthy():
    """build_summary includes the warning when published < min_working_nodes."""
    metrics = {
        "checked": 10, "verified": 2, "published": 2,
        "timestamp_utc": "2026-01-01T00:00:00Z",
        "min_working_nodes": 5, "healthy": False,
    }
    text = build_summary(metrics)
    assert "⚠️" in text
    assert "Pool may be degrading" in text


def test_metrics_summary_includes_degradation_alert():
    """When the pool shrinks ≥ 50% vs the previous run, an alert line is added."""
    previous = {
        "checked": 50, "verified": 10, "published": 10,
        "min_working_nodes": 5, "healthy": True,
    }
    current = {
        "checked": 50, "verified": 2, "published": 2,
        "min_working_nodes": 5, "healthy": False,
    }
    text = build_summary(current, previous)
    assert "🚨" in text
    assert "dropped from 10 to 2" in text


def test_metrics_summary_no_alert_when_stable():
    """No alert when the pool count is stable or growing."""
    previous = {
        "checked": 50, "verified": 10, "published": 10,
        "min_working_nodes": 5, "healthy": True,
    }
    current = {
        "checked": 50, "verified": 9, "published": 9,
        "min_working_nodes": 5, "healthy": True,
    }
    text = build_summary(current, previous)
    assert "🚨" not in text


def test_build_alert_returns_none_for_small_drops():
    """A drop of < 50% does not trigger the alert."""
    assert build_alert(
        {"published": 10, "min_working_nodes": 5},
        {"published": 6, "min_working_nodes": 5},
    ) is None


def test_build_writes_subscription_and_docs_copy(tmp_path, monkeypatch):
    """The docs/ copy must stay in sync with output/subscription.txt."""
    monkeypatch.chdir(tmp_path)
    config_path = _write_config(tmp_path)

    proxy = _proxy("192.0.2.10", 443, verified=True)
    with patch("src.checker.pipeline.parse_sources", return_value=[proxy]), \
            patch("src.checker.pipeline.check_proxy", side_effect=lambda p, c: p):
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
    (tmp_path / "output").mkdir()
    (tmp_path / "output" / "subscription.txt").write_text("stale-content\n", encoding="utf-8")

    with patch("src.checker.pipeline.parse_sources", return_value=[]):
        count = build(str(config_path))

    # Empty-pub guard: existing non-empty subscription is preserved, not cleared
    assert count == 0
    assert (tmp_path / "output" / "subscription.txt").read_text(encoding="utf-8") == "stale-content\n"
    assert (tmp_path / "docs" / "subscription.txt").read_text(encoding="utf-8") == "stale-content\n"


def test_build_applies_latency_sorting(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config_path = _write_config(
        tmp_path,
        output={"directory": str(tmp_path / "output"), "formats": ["plaintext"], "sort_by_latency": True},
    )

    slow = _proxy("192.0.2.1", 443, speed_kbps=100, verified=True)
    fast = _proxy("192.0.2.2", 443, speed_kbps=900, verified=True)
    with patch("src.checker.pipeline.parse_sources", return_value=[slow, fast]), \
            patch("src.checker.pipeline.check_proxy", side_effect=lambda p, c: p):
        build(str(config_path))

    text = (tmp_path / "output" / "subscription.txt").read_text(encoding="utf-8")
    assert text.index("192.0.2.2") < text.index("192.0.2.1")


def test_build_skips_sorting_by_default(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config_path = _write_config(tmp_path)

    slow = _proxy("192.0.2.1", 443, speed_kbps=100, verified=True)
    fast = _proxy("192.0.2.2", 443, speed_kbps=900, verified=True)
    with patch("src.checker.pipeline.parse_sources", return_value=[slow, fast]), \
            patch("src.checker.pipeline.check_proxy", side_effect=lambda p, c: p):
        build(str(config_path))

    text = (tmp_path / "output" / "subscription.txt").read_text(encoding="utf-8")
    assert text.index("192.0.2.1") < text.index("192.0.2.2")
