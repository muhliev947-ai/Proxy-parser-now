import base64
import json

from src.generator.generators import to_clash, to_singbox
from src.parser.parser import parse_sources, parse_text, parse_uri


def test_parse_vless_uri_with_reality():
    proxy = parse_uri("vless://abc@example.com:443?security=reality&sni=example.com&pbk=key&sid=id#demo")
    assert proxy and proxy.uuid == "abc"
    assert proxy.reality == {"public_key": "key", "short_id": "id"}


def test_parse_base64_subscription():
    source = base64.b64encode(b"trojan://secret@example.com:443#node").decode()
    assert parse_text(source)[0].type == "trojan"


def test_parse_clash_and_generate_formats():
    proxies = parse_text("proxies:\n  - name: node\n    type: vless\n    server: example.com\n    port: 443\n    uuid: abc\n    tls: true\n")
    assert len(proxies) == 1
    assert "server: example.com" in to_clash(proxies)
    assert json.loads(to_singbox(proxies))["outbounds"][0]["uuid"] == "abc"


def test_parse_sources_from_github_repo(monkeypatch):
    class FakeResponse:
        def __init__(self, payload: bytes):
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return self.payload

    def fake_urlopen(request, timeout=15):
        url = request.full_url
        if url.endswith("/contents"):
            return FakeResponse(json.dumps([
                {"type": "file", "path": "proxy.txt", "download_url": "https://example.com/proxy.txt"}
            ]).encode())
        if "commits?path=proxy.txt" in url:
            return FakeResponse(json.dumps([
                {"commit": {"author": {"date": "2026-09-10T12:00:00Z"}}}
            ]).encode())
        if url == "https://example.com/proxy.txt":
            return FakeResponse(b"vless://abc@example.com:443#demo")
        raise AssertionError(f"unexpected url: {url}")

    monkeypatch.setattr("src.parser.parser.urlopen", fake_urlopen)
    proxies = parse_sources(["github:demo/repo"], freshness_days=30)
    assert len(proxies) == 1
    assert proxies[0].server == "example.com"


def test_parse_sources_uses_fallback_when_sources_fail(tmp_path):
    fallback = tmp_path / "fallback.txt"
    fallback.write_text("vless://abc@example.com:443?security=tls&sni=example.com#fallback", encoding="utf-8")

    proxies = parse_sources(["https://bad.example.invalid/source.txt"], fallback_file=str(fallback))
    assert len(proxies) == 1
    assert proxies[0].server == "example.com"