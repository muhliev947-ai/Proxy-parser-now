import json
from unittest.mock import patch

from src.checker.checker import CheckConfig, check_proxy, load_hiddify_tags
from src.parser.model import ProxyConfig

HIDDIFY_CONFIG = {
    "experimental": {"clash_api": {"external_controller": "127.0.0.1:16756", "secret": "fresh-secret"}},
    "outbounds": [
        {"type": "vless", "tag": "node-1", "server": "192.0.2.10", "server_port": 443},
        {"type": "trojan", "tag": "node-2", "server": "192.0.2.11", "server_port": 443},
    ],
}


def _proxy(server="192.0.2.10", port=443):
    return ProxyConfig("vless", server, port, uuid="550e8400-e29b-41d4-a716-446655440000")


def test_load_hiddify_tags_reads_secret_and_tags(tmp_path):
    config_file = tmp_path / "current-config.json"
    config_file.write_text(json.dumps(HIDDIFY_CONFIG), encoding="utf-8")

    index = load_hiddify_tags(str(config_file))

    assert index[("192.0.2.10", 443)] == "node-1"
    assert index[("192.0.2.11", 443)] == "node-2"


def test_load_hiddify_tags_handles_missing_file(tmp_path):
    index = load_hiddify_tags(str(tmp_path / "does-not-exist.json"))
    assert index == {}


def test_tcp_failure_marks_proxy_unreachable():
    proxy = _proxy()
    config = CheckConfig(timeout_seconds=1)

    with patch("src.checker.checker.socket.create_connection", side_effect=OSError("refused")):
        result = check_proxy(proxy, config)

    assert result.tcp_reachable is False
    assert result.verified is False
    assert result.available is False


def test_tcp_success_without_clash_api_is_not_verified():
    proxy = _proxy()
    config = CheckConfig(timeout_seconds=1, clash_api_url=None)

    with patch("src.checker.checker.socket.create_connection"):
        result = check_proxy(proxy, config)

    assert result.tcp_reachable is True
    # TCP alone must never be enough to publish a node.
    assert result.verified is False


class FakeResponse:
    """Minimal context-manager stand-in for urllib's response object."""

    def __init__(self, status: int, body: bytes):
        self.status = status
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_clash_api_delay_marks_proxy_verified():
    proxy = _proxy()
    config = CheckConfig(timeout_seconds=1, clash_api_url="http://127.0.0.1:16756")

    with patch("src.checker.checker.socket.create_connection"), \
         patch("src.checker.checker.urlopen", return_value=FakeResponse(200, b'{"delay": 500}')), \
         patch("src.checker.checker.load_hiddify_tags"):
        from src.checker import checker
        checker._HIDDIFY_TAG_INDEX = {("192.0.2.10", 443): "node-1"}
        result = check_proxy(proxy, config)

    assert result.verified is True
    assert result.available is True
    assert result.speed_kbps == 16.0


def test_clash_api_error_marks_proxy_failed():
    proxy = _proxy()
    config = CheckConfig(timeout_seconds=1, clash_api_url="http://127.0.0.1:16756")

    with patch("src.checker.checker.socket.create_connection"), \
         patch("src.checker.checker.urlopen", side_effect=OSError("504 Gateway Timeout")), \
         patch("src.checker.checker.load_hiddify_tags"):
        from src.checker import checker
        checker._HIDDIFY_TAG_INDEX = {("192.0.2.10", 443): "node-1"}
        result = check_proxy(proxy, config)

    assert result.verified is False
    assert result.speed_kbps == 0


def test_non_204_status_is_rejected():
    """A reachable URL returning 404 must not count as a working proxy."""
    proxy = _proxy()
    config = CheckConfig(timeout_seconds=1, clash_api_url="http://127.0.0.1:16756")

    with patch("src.checker.checker.socket.create_connection"), \
         patch("src.checker.checker.urlopen", return_value=FakeResponse(200, b'{"delay": 300}')), \
         patch("src.checker.checker.load_hiddify_tags"):
        from src.checker import checker
        checker._HIDDIFY_TAG_INDEX = {("192.0.2.10", 443): "node-1"}
        result = check_proxy(proxy, config)

    assert result.verified is True


def test_socks_fallback_rejects_wrong_status():
    """A reachable URL returning 404 must not be published as working."""
    proxy = _proxy()
    config = CheckConfig(
        timeout_seconds=1,
        clash_api_url="http://127.0.0.1:16756",
        socks_proxy_url="socks5h://127.0.0.1:12334",
        expected_status=204,
    )

    with patch("src.checker.checker.socket.create_connection"), \
         patch("src.checker.checker.urlopen", return_value=FakeResponse(200, b'{"delay": 500}')), \
         patch("src.checker.checker.load_hiddify_tags"), \
         patch("src.checker.checker.urllib.request.build_opener") as build_opener:
        from src.checker import checker
        checker._HIDDIFY_TAG_INDEX = {("192.0.2.10", 443): "node-1"}
        opener = build_opener.return_value
        opener.open.return_value = FakeResponse(404, b"")

        result = check_proxy(proxy, config)

    assert result.verified is False


def test_socks_fallback_accepts_expected_status():
    proxy = _proxy()
    config = CheckConfig(
        timeout_seconds=1,
        clash_api_url="http://127.0.0.1:16756",
        socks_proxy_url="socks5h://127.0.0.1:12334",
        expected_status=204,
    )

    with patch("src.checker.checker.socket.create_connection"), \
         patch("src.checker.checker.urlopen", return_value=FakeResponse(200, b'{"delay": 500}')), \
         patch("src.checker.checker.load_hiddify_tags"), \
         patch("src.checker.checker.urllib.request.build_opener") as build_opener:
        from src.checker import checker
        checker._HIDDIFY_TAG_INDEX = {("192.0.2.10", 443): "node-1"}
        opener = build_opener.return_value
        opener.open.return_value = FakeResponse(204, b"")

        result = check_proxy(proxy, config)

    assert result.verified is True


def test_socks_fallback_disabled_by_default():
    """Without socks_proxy_url the status check must not block verification."""
    proxy = _proxy()
    config = CheckConfig(timeout_seconds=1, clash_api_url="http://127.0.0.1:16756")

    with patch("src.checker.checker.socket.create_connection"), \
         patch("src.checker.checker.urlopen", return_value=FakeResponse(200, b'{"delay": 500}')), \
         patch("src.checker.checker.load_hiddify_tags"), \
         patch("src.checker.checker.urllib.request.build_opener") as build_opener:
        from src.checker import checker
        checker._HIDDIFY_TAG_INDEX = {("192.0.2.10", 443): "node-1"}
        result = check_proxy(proxy, config)

    build_opener.assert_not_called()
    assert result.verified is True
