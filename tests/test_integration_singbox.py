"""Integration test that exercises the real sing-box binary.

Skipped when the binary is not found on PATH or in the project root.
Run locally with::

    python -m pytest tests/test_integration_singbox.py -v --tb=long

or force the binary path via ``SINGBOX_BIN`` env var::

    SINGBOX_BIN=./sing-box python -m pytest tests/test_integration_singbox.py -v
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from src.checker.pipeline import LocalSingBoxBackend
from src.generator.generators import to_singbox_parallel
from src.parser.model import ProxyConfig

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_singbox() -> str | None:
    """Return the path to the sing-box binary, or None."""
    env = os.environ.get("SINGBOX_BIN")
    if env:
        return env if Path(env).exists() else None
    found = shutil.which("sing-box")
    if found:
        return found
    local = Path(__file__).resolve().parent.parent / "sing-box"
    return str(local) if local.exists() else None


HAS_SINGBOX = _find_singbox() is not None
SINGBOX_BIN = _find_singbox()


def _make_vless_proxy(name: str, server: str = "10.0.0.1", port: int = 443) -> ProxyConfig:
    """Create a syntactically valid vless proxy that sing-box accepts."""
    proxy = ProxyConfig(
        "vless", server, port,
        uuid="11111111-2222-3333-4444-555555555555",
        name=name,
    )
    proxy.network = "tcp"
    return proxy


def _make_reality_proxy(name: str, server: str = "10.0.0.1", port: int = 443) -> ProxyConfig:
    """Create a vless proxy that uses reality security.

    The public key is a valid x25519 key (43 base64 chars, no padding) so
    that ``sing-box check`` accepts the outbound — the pinned 1.13.1 release
    is built with ``with_utls``, and a REALITY client additionally requires
    a utls block, which the generator emits.
    """
    public_key = "JQX7allKy1F6yFL88mkc8gX9Hc07KsZMACZXIC1c0gE"
    proxy = ProxyConfig(
        "vless", server, port,
        uuid="11111111-2222-3333-4444-555555555555",
        name=name,
    )
    proxy.network = "tcp"
    proxy.security = "reality"
    proxy.reality = {"public_key": public_key, "short_id": "0123456789abcdef"}
    proxy.sni = "example.com"
    proxy.fingerprint = "chrome"
    return proxy


# ---------------------------------------------------------------------------
# Config generation with real sing-box check
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not HAS_SINGBOX, reason=f"sing-box binary not found ({SINGBOX_BIN})")
def test_singbox_check_accepts_generated_config(tmp_path: Path) -> None:
    """to_singbox_parallel output passes `sing-box check -c`."""
    proxies = [_make_vless_proxy(f"n{i}", server=f"10.0.0.{i + 1}") for i in range(3)]
    config_text, port_map = to_singbox_parallel(proxies, base_port=20000)

    cfg_path = tmp_path / "test.json"
    cfg_path.write_text(config_text, encoding="utf-8")

    result = subprocess.run(
        [SINGBOX_BIN, "check", "-c", str(cfg_path)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, f"sing-box check failed: {result.stderr}"
    assert len(port_map) == 3


@pytest.mark.skipif(not HAS_SINGBOX, reason=f"sing-box binary not found ({SINGBOX_BIN})")
def test_singbox_check_filters_unsupported_transports(tmp_path: Path) -> None:
    """xhttp / httpupgrade transports are dropped before config generation."""
    good = _make_vless_proxy("good", server="10.0.0.1")
    bad = _make_vless_proxy("bad", server="10.0.0.2")
    bad.network = "xhttp"  # unsupported transport

    config_text, port_map = to_singbox_parallel([good, bad], base_port=20000)
    parsed = __import__("json").loads(config_text)
    # Only 1 candidate outbound + 1 direct fallback
    assert len(parsed["outbounds"]) == 2
    assert len(port_map) == 1

    cfg_path = tmp_path / "test.json"
    cfg_path.write_text(config_text, encoding="utf-8")
    result = subprocess.run(
        [SINGBOX_BIN, "check", "-c", str(cfg_path)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0


@pytest.mark.skipif(not HAS_SINGBOX, reason=f"sing-box binary not found ({SINGBOX_BIN})")
def test_reality_proxies_pass_singbox_check(tmp_path: Path) -> None:
    """A reality vless proxy is included in the config and passes `sing-box check`."""
    reality_proxy = _make_reality_proxy("reality", server="10.0.0.1")
    vless_proxy = _make_vless_proxy("vless", server="10.0.0.2")

    config_text, port_map = to_singbox_parallel([reality_proxy, vless_proxy], base_port=20000)
    parsed = __import__("json").loads(config_text)
    # 2 candidate outbounds + 1 direct fallback
    assert len(parsed["outbounds"]) == 3
    assert len(port_map) == 2

    # Verify the reality outbound has the required utls block and a valid key
    reality_outbound = next(
        ob for ob in parsed["outbounds"] if ob.get("tag") == "reality"
    )
    public_key = reality_outbound["tls"]["reality"]["public_key"]
    import base64
    assert len(base64.b64decode(public_key + "=")) == 32, "public_key must be a valid x25519 key"
    assert reality_outbound["tls"]["utls"]["enabled"] is True
    assert reality_outbound["tls"]["utls"]["fingerprint"] == "chrome"

    cfg_path = tmp_path / "test.json"
    cfg_path.write_text(config_text, encoding="utf-8")
    result = subprocess.run(
        [SINGBOX_BIN, "check", "-c", str(cfg_path)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, f"sing-box check failed for reality proxy: {result.stderr}"


# ---------------------------------------------------------------------------
# End-to-end: dead node rejected by local backend
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not HAS_SINGBOX, reason=f"sing-box binary not found ({SINGBOX_BIN})")
def test_dead_node_rejected_by_local_backend(tmp_path: Path) -> None:
    """A proxy pointing to a dead IP is marked unavailable after verify_batch."""
    check = {
        "singbox": {"binary": SINGBOX_BIN},
        "timeout_seconds": 3,
        "concurrency": 2,
        "urls": ["https://cp.cloudflare.com/generate_204"],
        "expected_status": 204,
    }
    backend = LocalSingBoxBackend(check, binary=SINGBOX_BIN, wait_seconds=20)

    dead = _make_vless_proxy("dead", server="192.0.2.1")  # TEST-NET-2, unroutable

    try:
        backend.start([dead])
        results = backend.verify_batch([dead])
        assert len(results) == 1
        assert results[0].verified is False
        assert results[0].available is False
    finally:
        backend.stop()


# ---------------------------------------------------------------------------
# End-to-end: full lifecycle with two dead nodes
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not HAS_SINGBOX, reason=f"sing-box binary not found ({SINGBOX_BIN})")
def test_local_backend_start_verify_stop_lifecycle(tmp_path: Path) -> None:
    """Full start → verify → stop cycle; both dead nodes fail verification."""
    check = {
        "singbox": {"binary": SINGBOX_BIN},
        "timeout_seconds": 3,
        "concurrency": 2,
        "urls": ["https://cp.cloudflare.com/generate_204"],
        "expected_status": 204,
    }
    backend = LocalSingBoxBackend(check, binary=SINGBOX_BIN, wait_seconds=20)

    p1 = _make_vless_proxy("dead-1", server="192.0.2.10")
    p2 = _make_vless_proxy("dead-2", server="192.0.2.20")

    try:
        backend.start([p1, p2])
        assert backend._instance is not None
        # port_map is keyed by id(proxy), one entry per candidate
        assert len(backend._instance.port_map) == 2

        results = backend.verify_batch([p1, p2])
        assert len(results) == 2
        assert all(r.verified is False for r in results)
    finally:
        backend.stop()
        assert backend._instance is None
