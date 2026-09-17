import base64
import json

from src.generator.generators import to_clash, to_singbox
from src.parser.parser import parse_text, parse_uri


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