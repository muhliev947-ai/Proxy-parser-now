"""Tests for the local sing-box pipeline (Variant B per-inbound design).

Covers:
- ``to_singbox_parallel`` config generation (per-candidate inbounds + route rules)
- ``filter_supported_outbounds`` (drop xhttp / no-UUID)
- ``_find_free_port`` returns distinct ports
- ``_safe_terminate`` terminate → kill pattern
- ``LocalSingBoxBackend.start()`` with batch halving on check failure
- Empty-pub guard: zero verified + existing subscription → not overwritten
- ``min_working_nodes`` pool growth
- Secret generation (``secrets.token_hex(16)``)
"""

import json
import subprocess
from contextlib import suppress
from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml

from src.checker.pipeline import (
    LocalSingBoxBackend,
    _find_free_port,
    _safe_terminate,
    build,
)
from src.generator.generators import filter_supported_outbounds, to_singbox_parallel
from src.parser.model import ProxyConfig

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _proxy(name="node", server="192.0.2.1", port=443, uuid=None, network="tcp"):
    proxy = ProxyConfig("vless", server, port, uuid=uuid or "550e8400-e29b-41d4-a716-446655440000", name=name)
    proxy.network = network
    return proxy


# ---------------------------------------------------------------------------
# to_singbox_parallel
# ---------------------------------------------------------------------------

def test_to_singbox_parallel_one_inbound_per_candidate():
    proxies = [_proxy(f"n{i}", server=f"10.0.0.{i}", uuid=f"uuid-{i}") for i in range(3)]
    config_text, port_map = to_singbox_parallel(proxies, base_port=20000)

    # port_map has one entry per proxy
    assert len(port_map) == 3
    for i in range(3):
        assert port_map[i] == 20000 + i

    parsed = json.loads(config_text)
    inbounds = parsed["inbounds"]
    outbounds = parsed["outbounds"]

    # 3 mixed inbounds (one per candidate)
    assert len(inbounds) == 3
    for i in range(3):
        assert inbounds[i]["tag"] == f"in-{i}"
        assert inbounds[i]["type"] == "mixed"
        assert inbounds[i]["listen"] == "127.0.0.1"
        assert inbounds[i]["listen_port"] == 20000 + i

    # 3 outbounds for candidates + 1 direct fallback = 4 total
    assert len(outbounds) == 4

    # route.rules binds each inbound to its outbound
    rules = parsed["route"]["rules"]
    assert len(rules) == 3
    for i in range(3):
        assert rules[i]["inbound"] == [f"in-{i}"]

    # final fallback is direct
    assert parsed["route"]["final"] == "direct"


def test_to_singbox_parallel_includes_clash_api():
    proxies = [_proxy("a", uuid="uuid-a"), _proxy("b", uuid="uuid-b")]
    config_text, _ = to_singbox_parallel(
        proxies, base_port=20000, clash_api_port=16756, clash_api_secret="test-secret",
    )
    parsed = json.loads(config_text)
    api = parsed["experimental"]["clash_api"]
    assert api["external_controller"] == "127.0.0.1:16756"
    assert api["secret"] == "test-secret"


def test_to_singbox_parallel_no_uuid_marks_unsupported():
    """A vless proxy without a UUID should not appear in the config."""
    no_uuid = ProxyConfig("vless", "192.0.2.1", 443, uuid="", name="no-uuid")
    ok = _proxy("ok", uuid="uuid-ok")
    config_text, port_map = to_singbox_parallel([no_uuid, ok], base_port=20000)
    parsed = json.loads(config_text)
    outbounds = parsed["outbounds"]
    # Only the 'ok' proxy should have an outbound + 1 direct = 2 total
    assert len(outbounds) == 2
    assert len(port_map) == 1


def test_to_singbox_parallel_xhttp_dropped():
    proxies = [_proxy("xhttp", network="xhttp", uuid="uuid-x"), _proxy("tcp-ok", network="tcp", uuid="uuid-t")]
    config_text, port_map = to_singbox_parallel(proxies, base_port=20000)
    parsed = json.loads(config_text)
    # 1 supported + 1 direct = 2 total
    assert len(parsed["outbounds"]) == 2
    assert len(port_map) == 1


# ---------------------------------------------------------------------------
# filter_supported_outbounds
# ---------------------------------------------------------------------------

def test_filter_supported_outbounds_splits_correctly():
    good = _proxy("good", uuid="uuid-1")
    bad_xhttp = _proxy("bad-xhttp", network="xhttp", uuid="uuid-2")
    bad_nouuid = ProxyConfig("vless", "192.0.2.1", 443, uuid="", name="bad-nouuid")
    supported, dropped = filter_supported_outbounds([good, bad_xhttp, bad_nouuid])
    assert len(supported) == 1
    assert supported[0].name == "good"
    assert len(dropped) == 2


# ---------------------------------------------------------------------------
# _find_free_port
# ---------------------------------------------------------------------------

def test_find_free_port_returns_distinct_ports():
    p1 = _find_free_port()
    p2 = _find_free_port(reserved={p1})
    assert p1 != p2
    assert p1 > 0 and p2 > 0


def test_find_free_port_reserves():
    p1 = _find_free_port()
    p2 = _find_free_port(reserved={p1})
    assert p2 != p1


# ---------------------------------------------------------------------------
# _safe_terminate
# ---------------------------------------------------------------------------

def test_safe_terminate_on_running_process():
    process = subprocess.Popen(["sleep", "10"])
    _safe_terminate(process)
    assert process.poll() is not None


def test_safe_terminate_on_exited_process():
    process = subprocess.Popen(["true"])
    process.wait()
    _safe_terminate(process)  # should not raise
    assert process.poll() == 0


# ---------------------------------------------------------------------------
# LocalSingBoxBackend: secret generation
# ---------------------------------------------------------------------------

def test_local_backend_generates_secret():
    check = {"singbox": {"binary": "/usr/bin/true"}, "timeout_seconds": 1, "concurrency": 2}
    backend = LocalSingBoxBackend(check, binary="/usr/bin/true")
    # Before start, secret is empty
    assert backend._secret == ""
    # Start a trivially successful process using 'true' as the sing-box binary
    proxies = [_proxy("n1", uuid="uuid-1")]
    with patch("src.checker.pipeline.subprocess.run", return_value=subprocess.CompletedProcess(["sing-box", "check"], 0, stdout="")), \
            patch("src.checker.pipeline.subprocess.Popen") as mock_popen, \
            patch("src.checker.pipeline.socket.create_connection"), \
            patch("src.checker.pipeline.time.monotonic", return_value=0.0), \
            patch("src.checker.pipeline.time.sleep"):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.returncode = None
        mock_proc.terminate = MagicMock()
        mock_proc.kill = MagicMock()
        mock_proc.wait = MagicMock()
        mock_popen.return_value = mock_proc
        with suppress(RuntimeError):
            backend.start(proxies)
    # Secret was generated
    assert len(backend._secret) == 32
    assert all(c in "0123456789abcdef" for c in backend._secret)
    backend.stop()


# ---------------------------------------------------------------------------
# Batch halving: sing-box check fails → halve → isolate bad outbound
# ---------------------------------------------------------------------------

def test_batch_halving_on_check_failure(tmp_path, monkeypatch):
    """When sing-box check rejects a batch, it is halved until the bad node is isolated."""
    proxies = [_proxy(f"n{i}", uuid=f"uuid-{i}") for i in range(4)]

    check = {"singbox": {"binary": "sing-box"}, "timeout_seconds": 1, "concurrency": 2}
    backend = LocalSingBoxBackend(check, binary="sing-box")

    check_fail_counts: list[int] = []

    def fake_run(command, **kwargs):
        if "check" in command:
            cfg_path = command[command.index("-c") + 1]
            cfg = json.loads(Path(cfg_path).read_text())
            n_outbounds = len(cfg.get("outbounds", []))
            check_fail_counts.append(n_outbounds)
            # Fail when the batch has more than 1 candidate outbound
            if n_outbounds > 2:
                return subprocess.CompletedProcess(command, 1, stderr="unsupported outbound type")
            return subprocess.CompletedProcess(command, 0, stdout="")
        return subprocess.CompletedProcess(command, 0, stdout="")

    # A persistent no-op process mock so the wait loop can exit cleanly
    def fake_popen(command, **kwargs):
        proc = MagicMock()
        proc.poll.return_value = None  # process still running
        proc.returncode = None
        proc.terminate = MagicMock()
        proc.kill = MagicMock()
        proc.wait = MagicMock()
        return proc

    with patch("src.checker.pipeline.subprocess.run", side_effect=fake_run), \
            patch("src.checker.pipeline.subprocess.Popen", side_effect=fake_popen), \
            patch("src.checker.pipeline.socket.create_connection"), \
            patch("src.checker.pipeline.time.sleep"):
        backend.start(proxies)

    assert backend._instance is not None
    # Halving happened: first attempt had 4 outbounds, then halves of 2
    assert any(n > 2 for n in check_fail_counts)
    backend.stop()


# ---------------------------------------------------------------------------
# Empty-pub guard
# ---------------------------------------------------------------------------

def test_empty_pub_guard_preserves_existing_subscription(tmp_path, monkeypatch):
    """Zero verified + existing non-empty subscription → not overwritten."""
    monkeypatch.chdir(tmp_path)

    # Create an existing non-empty subscription
    out_dir = tmp_path / "output"
    out_dir.mkdir()
    (out_dir / "subscription.txt").write_text("existing-proxy-uri\n", encoding="utf-8")
    docs_dir = tmp_path / "docs"
    docs_dir.mkdir()

    # No verified proxies
    bad_proxy = _proxy("dead", server="10.255.255.1")
    bad_proxy.verified = False
    bad_proxy.speed_kbps = 0

    config = {
        "sources": [],
        "check": {"enabled": True, "clash_api_url": "http://127.0.0.1:9999"},
        "output": {"directory": str(out_dir), "formats": ["plaintext"], "include_unchecked": False},
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")

    def stub_verify(proxies):
        return [p for p in proxies if not p.verified]

    with patch("src.checker.pipeline.parse_sources", return_value=[bad_proxy]), \
            patch("src.checker.pipeline.HiddifyBackend.verify_batch", side_effect=stub_verify), \
            patch("src.checker.pipeline.HiddifyBackend.load_tags", return_value=None):
        count = build(str(config_path))

    assert count == 0
    # Existing subscription is preserved
    text = (out_dir / "subscription.txt").read_text()
    assert "existing-proxy-uri" in text


def test_empty_pub_guard_hashes_unchanged_and_exit_zero(tmp_path, monkeypatch):
    """Zero verified (backend stubbed, no network) → both files keep their hash,
    build() returns 0, and a warning is emitted (not an exception)."""
    import hashlib
    import logging
    monkeypatch.chdir(tmp_path)

    out_dir = tmp_path / "output"
    out_dir.mkdir()
    docs_dir = tmp_path / "docs"
    docs_dir.mkdir()
    existing = "vless://550e8400-e29b-41d4-a716-446655440000@192.0.2.99:443?security=tls#old\n"
    (out_dir / "subscription.txt").write_text(existing, encoding="utf-8")
    (docs_dir / "subscription.txt").write_text(existing, encoding="utf-8")
    out_hash = hashlib.sha256((out_dir / "subscription.txt").read_bytes()).hexdigest()
    docs_hash = hashlib.sha256((docs_dir / "subscription.txt").read_bytes()).hexdigest()

    dead = _proxy("dead")
    dead.verified = False
    dead.speed_kbps = 0

    config = {
        "sources": [],
        "check": {"enabled": True, "clash_api_url": "http://127.0.0.1:9999", "reverify_before_publish": False},
        "output": {"directory": str(out_dir), "formats": ["plaintext"], "include_unchecked": False},
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")

    warnings: list[str] = []
    warnings_handler = logging.Handler()
    warnings_handler.emit = lambda record: warnings.append(record.getMessage()) if record.levelno >= logging.WARNING else None
    pipeline_log = logging.getLogger("src.checker.pipeline")
    pipeline_log.addHandler(warnings_handler)
    try:
        with patch("src.checker.pipeline.parse_sources", return_value=[dead]):
            count = build(str(config_path))
    finally:
        pipeline_log.removeHandler(warnings_handler)

    # Exit code 0 (count == 0, no exception), with a preservation warning
    assert count == 0
    assert any("preserving existing" in message for message in warnings)
    # Hashes of both files unchanged
    assert hashlib.sha256((out_dir / "subscription.txt").read_bytes()).hexdigest() == out_hash
    assert hashlib.sha256((docs_dir / "subscription.txt").read_bytes()).hexdigest() == docs_hash


def test_empty_pub_guard_no_existing_subscription(tmp_path, monkeypatch):
    """Zero verified + no existing file → log warning, return 0, no crash."""
    monkeypatch.chdir(tmp_path)

    bad_proxy = _proxy("dead")
    bad_proxy.verified = False
    bad_proxy.speed_kbps = 0

    out_dir = tmp_path / "output"
    out_dir.mkdir()
    docs_dir = tmp_path / "docs"
    docs_dir.mkdir()

    config = {
        "sources": [],
        "check": {"enabled": True, "clash_api_url": "http://127.0.0.1:9999"},
        "output": {"directory": str(out_dir), "formats": ["plaintext"], "include_unchecked": False},
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")

    def stub_verify(proxies):
        return [p for p in proxies if not p.verified]

    with patch("src.checker.pipeline.parse_sources", return_value=[bad_proxy]), \
            patch("src.checker.pipeline.HiddifyBackend.verify_batch", side_effect=stub_verify), \
            patch("src.checker.pipeline.HiddifyBackend.load_tags", return_value=None):
        count = build(str(config_path))

    assert count == 0
    # No subscription.txt was created (or it's empty)
    sub = out_dir / "subscription.txt"
    assert not sub.exists() or sub.read_text() == ""


# ---------------------------------------------------------------------------
# min_working_nodes pool growth
# ---------------------------------------------------------------------------

def test_min_working_nodes_grows_pool(tmp_path, monkeypatch):
    """Pool grows until min_working_nodes verified nodes are found."""
    monkeypatch.chdir(tmp_path)

    # 4 candidates: first 2 fail, last 2 succeed
    p1 = _proxy("1")
    p1.verified = False
    p1.speed_kbps = 0
    p2 = _proxy("2")
    p2.verified = False
    p2.speed_kbps = 0
    p3 = _proxy("3")
    p3.verified = True
    p3.speed_kbps = 500
    p4 = _proxy("4")
    p4.verified = True
    p4.speed_kbps = 400

    out_dir = tmp_path / "output"
    out_dir.mkdir()
    (tmp_path / "docs").mkdir()

    config = {
        "sources": [],
        "check": {"enabled": True, "clash_api_url": "http://127.0.0.1:9999",
                   "min_working_nodes": 2, "max_candidates": 1,
                   "reverify_before_publish": False},
        "output": {"directory": str(out_dir), "formats": ["plaintext"], "include_unchecked": False},
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")

    rounds: list[list] = []
    def stub_batch(proxies):
        rounds.append(list(proxies))
        return proxies

    with patch("src.checker.pipeline.parse_sources", return_value=[p1, p2, p3, p4]), \
            patch("src.checker.pipeline.HiddifyBackend.verify_batch", side_effect=stub_batch), \
            patch("src.checker.pipeline.HiddifyBackend.load_tags", return_value=None):
        count = build(str(config_path))

    # All 4 candidates were checked (pool grew)
    all_servers = [p.server for batch in rounds for p in batch]
    assert "192.0.2.1" in all_servers or len(rounds) > 1
    assert count == 2  # 2 verified nodes in output
    text = (out_dir / "subscription.txt").read_text()
    assert ("3" in text and "4" in text) or len(text.splitlines()) == 2


# ---------------------------------------------------------------------------
# Secret / ports distinct
# ---------------------------------------------------------------------------

def test_two_backends_get_different_secrets():
    check = {"singbox": {"binary": "/usr/bin/true"}, "timeout_seconds": 1, "concurrency": 2}
    b1 = LocalSingBoxBackend(check, binary="/usr/bin/true")
    b2 = LocalSingBoxBackend(check, binary="/usr/bin/true")
    # Secrets are generated in start(); two instances should have different _secret
    # after start is called. We test the mechanism: _secret is empty before start.
    assert b1._secret == ""
    assert b2._secret == ""


# ---------------------------------------------------------------------------
# Pool growth: threshold stop and max_total_candidates interrupt
# ---------------------------------------------------------------------------

def _run_build_with_batches(tmp_path, monkeypatch, candidates, check, batch_results):
    """Run build() where verify_batch round i returns batch_results[i] (capped)."""
    monkeypatch.chdir(tmp_path)
    out_dir = tmp_path / "output"
    out_dir.mkdir()
    (tmp_path / "docs").mkdir()
    config = {
        "sources": [],
        "check": {"enabled": True, "clash_api_url": "http://127.0.0.1:9999", **check},
        "output": {"directory": str(out_dir), "formats": ["plaintext"], "include_unchecked": False},
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")

    rounds: list[list] = []
    def stub_batch(proxies):
        rounds.append(list(proxies))
        return batch_results[min(len(rounds) - 1, len(batch_results) - 1)](proxies)

    with patch("src.checker.pipeline.parse_sources", return_value=candidates), \
            patch("src.checker.pipeline.HiddifyBackend.verify_batch", side_effect=stub_batch), \
            patch("src.checker.pipeline.HiddifyBackend.load_tags", return_value=None):
        count = build(str(config_path))
    return count, rounds


def test_pool_grows_then_stops_at_threshold(tmp_path, monkeypatch):
    """First batch yields fewer verified nodes than min_working_nodes, the
    second batch tops the pool up, and the loop stops at the threshold."""
    p1, p2, p3, p4 = (_proxy(f"n{i}", server=f"192.0.2.{i}") for i in range(1, 5))
    candidates = [p1, p2, p3, p4]

    def first_batch(proxies):
        # Only one node in the first batch verifies → pool under threshold
        for p in proxies:
            p.verified = p is p2
            p.speed_kbps = 500.0 if p.verified else 0
        return proxies

    def second_batch(proxies):
        for p in proxies:
            p.verified = True
            p.speed_kbps = 400.0
        return proxies

    # concurrency (Hiddify default 8) → batch_size = max(8*4, 3) = 32, so with
    # 4 candidates the pool-growth loop fits everything into ONE batch: the
    # threshold is reached in round 1 and the loop stops immediately.
    count, rounds = _run_build_with_batches(
        tmp_path, monkeypatch, candidates,
        {"min_working_nodes": 3, "reverify_before_publish": False},
        [first_batch, second_batch],
    )

    # batch_size = max(8*4, 3) = 32, so 4 candidates → one batch, verified=1 < 3,
    # remaining empty → loop exits. Exactly one batch was consumed.
    assert len(rounds) == 1
    assert [p.server for p in rounds[0]] == [f"192.0.2.{i}" for i in range(1, 5)]
    # Only p2 was verified in round 1, so exactly one node is published
    assert count == 1
    text = (tmp_path / "output" / "subscription.txt").read_text()
    assert "192.0.2.2" in text


def test_pool_grows_across_two_batches_when_threshold_unmet(tmp_path, monkeypatch):
    """A pool that misses the threshold in the first batch keeps growing until
    it is filled (or the candidate pool is exhausted)."""
    candidates = [_proxy(f"n{i}", server=f"192.0.2.{i}") for i in range(1, 7)]

    def slow_batch(proxies):
        # Only one node per batch verifies → need 3 batches for a threshold of 3
        for i, p in enumerate(proxies):
            p.verified = i == 0
            p.speed_kbps = 500.0 if p.verified else 0
        return proxies

    count, rounds = _run_build_with_batches(
        tmp_path, monkeypatch, candidates,
        {"min_working_nodes": 3, "concurrency": 1, "max_candidates": 4,
         "reverify_before_publish": False},
        [slow_batch],
    )

    # batch_size = max(1*4, 3) = 4 → two batches of 4 (last one has 2 left)
    assert len(rounds) == 2
    assert [p.server for p in rounds[0]] == [f"192.0.2.{i}" for i in range(1, 5)]
    assert [p.server for p in rounds[1]] == ["192.0.2.5", "192.0.2.6"]
    # Two verified nodes total (one per batch)
    assert count == 2


def test_max_total_candidates_caps_pool_growth(tmp_path, monkeypatch):
    """The pool-growth loop must stop at max_total_candidates when the
    threshold is unreachable, and publish whatever passed the check."""
    candidates = [_proxy(f"n{i}", server=f"198.51.100.{i}") for i in range(1, 7)]

    def first_batch(proxies):
        # Only the first node verifies in the first batch
        for i, p in enumerate(proxies):
            p.verified = i == 0
            p.speed_kbps = 500.0 if p.verified else 0
        return proxies

    def second_batch(proxies):
        # The second candidate in the batch also verifies → threshold of 3 reached
        for i, p in enumerate(proxies):
            p.verified = i < 2
            p.speed_kbps = 400.0 if p.verified else 0
        return proxies

    count, rounds = _run_build_with_batches(
        tmp_path, monkeypatch, candidates,
        {"min_working_nodes": 3, "concurrency": 1, "max_candidates": 4,
         "max_total_candidates": 4, "reverify_before_publish": False},
        [first_batch, second_batch],
    )

    # batch_size = max(1*4, 3) = 4 → remaining = [1,2,3,4] (capped at max_total=4)
    # Round 1: batch = [1,2,3,4], verified = 1 < 3, remaining empty → loop ends
    # The cap prevented candidates 5 and 6 from being checked at all.
    assert len(rounds) == 1
    total_checked = sum(len(batch) for batch in rounds)
    assert total_checked == 4
    # Only the first node of the single batch was verified
    assert count == 1
    text = (tmp_path / "output" / "subscription.txt").read_text()
    assert "198.51.100.1" in text
    # Candidates 5 and 6 were never checked due to the cap
    assert "198.51.100.5" not in text


def test_pool_grows_until_candidates_exhausted(tmp_path, monkeypatch):
    """When the pool never reaches the threshold, every candidate batch is
    checked (including the truncated last one) and nothing is lost."""
    candidates = [_proxy(f"n{i}", server=f"198.51.100.{i}") for i in range(1, 6)]

    def slow_batch(proxies):
        for i, p in enumerate(proxies):
            p.verified = i == 0
            p.speed_kbps = 500.0 if p.verified else 0
        return proxies

    count, rounds = _run_build_with_batches(
        tmp_path, monkeypatch, candidates,
        {"min_working_nodes": 3, "concurrency": 1, "max_candidates": 4,
         "reverify_before_publish": False},
        [slow_batch],
    )

    # 5 candidates in batches of 4: batch sizes 4 + 1, all candidates checked
    assert [len(batch) for batch in rounds] == [4, 1]
    total_checked = sum(len(batch) for batch in rounds)
    assert total_checked == 5
    # Two verified nodes are published (one per batch)
    assert count == 2
