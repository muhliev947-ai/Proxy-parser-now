"""Tests for the publication safety net in src/main.py.

Free proxies die within hours, so the pipeline must (a) keep verifying
candidates until a pool of working nodes is built rather than stopping at the
first success, and (b) re-check the top nodes immediately before writing the
subscription, because a node verified minutes ago may already be dead.
"""

from unittest.mock import patch

import yaml

from src.main import build
from src.parser.model import ProxyConfig


def _proxy(server, verified=False, speed_kbps=None):
    proxy = ProxyConfig("vless", server, 443, uuid="550e8400-e29b-41d4-a716-446655440000")
    proxy.verified = verified
    proxy.speed_kbps = speed_kbps
    return proxy


def _config(tmp_path, monkeypatch, check):
    monkeypatch.chdir(tmp_path)
    config = {
        "sources": [],
        "check": {"enabled": True, "clash_api_url": "http://127.0.0.1:16756", **check},
        "output": {"directory": str(tmp_path / "output"), "formats": ["plaintext"], "include_unchecked": False},
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return config_path


def _run(tmp_path, monkeypatch, candidates, check, check_proxies):
    """Run build() with _check_proxies stubbed.

    The stub receives the list of candidates for one round and returns them
    with their verification state set. It is called once per pool batch and
    once more for the pre-publication re-verification.
    """
    rounds: list[list[ProxyConfig]] = []

    def stub(proxies, _check_config):
        rounds.append(list(proxies))
        return check_proxies(list(proxies), len(rounds))

    config_path = _config(tmp_path, monkeypatch, check)
    with patch("src.main.parse_sources", return_value=candidates), \
            patch("src.main.load_hiddify_tags", return_value={}), \
            patch("src.main._check_proxies", side_effect=stub):
        count = build(str(config_path))

    text = (tmp_path / "output" / "subscription.txt").read_text(encoding="utf-8")
    return count, text, rounds


def test_min_working_nodes_checks_until_pool_is_filled(tmp_path, monkeypatch):
    """Only the later candidates work, so every batch must be verified."""
    candidates = [
        _proxy("192.0.2.1", verified=False),
        _proxy("192.0.2.2", verified=False),
        _proxy("192.0.2.3", verified=True, speed_kbps=500),
        _proxy("192.0.2.4", verified=True, speed_kbps=400),
    ]

    count, text, rounds = _run(
        tmp_path, monkeypatch, candidates,
        {"min_working_nodes": 2, "max_candidates": 1, "reverify_before_publish": False},
        lambda proxies, _round: proxies,
    )

    # With max_candidates=1 the pool pass runs in small batches until two
    # verified nodes exist, so all four candidates are checked.
    assert count == 2
    assert "192.0.2.3" in text
    assert "192.0.2.4" in text
    assert [proxy.server for batch in rounds for proxy in batch] == [
        "192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4",
    ]


def test_reverify_drops_node_that_died_before_publication(tmp_path, monkeypatch):
    """A node alive in the pool pass must be re-checked right before writing.

    The fastest node dies between the two rounds, which is exactly the failure
    mode seen with short-lived free proxies.
    """
    alive = _proxy("192.0.2.1", verified=True, speed_kbps=900)
    dying = _proxy("192.0.2.2", verified=True, speed_kbps=800)
    candidates = [alive, dying]

    def check_proxies(proxies, round_number):
        if round_number == 1:
            return proxies
        # Second round is the pre-publication re-check: the dying node is dead now.
        return [proxy for proxy in proxies if proxy is not dying]

    count, text, rounds = _run(tmp_path, monkeypatch, candidates, {"reverify_top_n": 10}, check_proxies)

    assert count == 1
    assert "192.0.2.1" in text
    assert "192.0.2.2" not in text
    assert len(rounds) == 2
    assert [proxy.server for proxy in rounds[1]] == ["192.0.2.1", "192.0.2.2"]


def test_reverify_can_be_disabled(tmp_path, monkeypatch):
    candidates = [_proxy("192.0.2.1", verified=True, speed_kbps=900)]

    count, text, rounds = _run(
        tmp_path, monkeypatch, candidates,
        {"reverify_before_publish": False},
        lambda proxies, _round: proxies,
    )

    assert count == 1
    assert "192.0.2.1" in text
    assert len(rounds) == 1


def test_static_filters_run_before_verification(tmp_path, monkeypatch):
    """A node rejected by the type filter must never reach check_proxy."""
    allowed = _proxy("192.0.2.1", verified=True)
    rejected = _proxy("192.0.2.2", verified=True)
    rejected.type = "http"

    checked: list[ProxyConfig] = []

    def check_proxies(proxies, _round):
        checked.extend(proxies)
        return proxies

    config_path = tmp_path / "config.yaml"
    monkeypatch.chdir(tmp_path)
    config_path.write_text(yaml.safe_dump({
        "sources": [],
        "types": ["vless"],
        "check": {"enabled": True, "clash_api_url": "http://127.0.0.1:16756", "reverify_before_publish": False},
        "output": {"directory": str(tmp_path / "output"), "formats": ["plaintext"], "include_unchecked": True},
    }), encoding="utf-8")

    with patch("src.main.parse_sources", return_value=[allowed, rejected]), \
            patch("src.main.load_hiddify_tags", return_value={}), \
            patch("src.main._check_proxies", side_effect=lambda p, _c: check_proxies(p, 1)):
        build(str(config_path))

    assert [proxy.server for proxy in checked] == ["192.0.2.1"]
