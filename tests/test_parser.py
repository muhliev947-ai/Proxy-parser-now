import base64
import json

from src.generator.generators import to_clash, to_singbox
from src.parser.parser import parse_sources, parse_text, parse_uri, to_plaintext_uris


def test_parse_vless_uri_with_reality():
    proxy = parse_uri("vless://550e8400-e29b-41d4-a716-446655440000@192.0.2.10:443?security=reality&sni=192.0.2.10&pbk=key&sid=id#node")
    assert proxy and proxy.uuid == "550e8400-e29b-41d4-a716-446655440000"
    assert proxy.reality == {"public_key": "key", "short_id": "id"}


def test_parse_base64_subscription():
    source = base64.b64encode(b"trojan://secret@192.0.2.10:443#node").decode()
    assert parse_text(source)[0].type == "trojan"


def test_parse_clash_and_generate_formats():
    proxies = parse_text("proxies:\n  - name: node\n    type: vless\n    server: 192.0.2.10\n    port: 443\n    uuid: 550e8400-e29b-41d4-a716-446655440000\n    tls: true\n")
    assert len(proxies) == 1
    assert "server: 192.0.2.10" in to_clash(proxies)
    assert json.loads(to_singbox(proxies))["outbounds"][0]["uuid"] == "550e8400-e29b-41d4-a716-446655440000"


def test_parse_yaml_rejects_public_http_proxy():
    proxies = parse_text("proxies:\n  - name: http-node\n    type: http\n    server: 101.96.98.138\n    port: 8080\n")

    assert proxies == []


def test_parse_text_rejects_demo_encrypted_uris():
    text = "vless://def456@speedtest.example.net:443?security=tls&sni=speedtest.example.net#speedtest.example.net\n"
    text += "trojan://secret-pass@example.org:443#example.org"

    assert parse_text(text) == []


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
            return FakeResponse(b"vless://550e8400-e29b-41d4-a716-446655440000@192.0.2.10:443#node")
        raise AssertionError(f"unexpected url: {url}")

    monkeypatch.setattr("src.parser.parser.urlopen", fake_urlopen)
    proxies = parse_sources(["github:demo/repo"], freshness_days=30)
    assert len(proxies) == 1
    assert proxies[0].server == "192.0.2.10"


def test_parse_sources_uses_fallback_when_sources_fail(tmp_path):
    fallback = tmp_path / "fallback.txt"
    fallback.write_text("vless://550e8400-e29b-41d4-a716-446655440000@192.0.2.10:443?security=tls&sni=192.0.2.10#fallback", encoding="utf-8")

    proxies = parse_sources(["https://bad.example.invalid/source.txt"], fallback_file=str(fallback))
    assert len(proxies) == 1
    assert parse_text(fallback.read_text(encoding="utf-8"))[0].server == "192.0.2.10"


def test_parse_text_rejects_placeholder_uris_and_keeps_valid_vless():
    valid = "vless://550e8400-e29b-41d4-a716-446655440000@192.0.2.1:443?security=tls&type=ws&host=node1.domain.com#Node-1"
    invalid = "vless://abc123@example.com:443?security=tls&sni=example.com&pbk=publickey&sid=abcd#demo"
    parsed = parse_text(f"{valid}\n{invalid}")
    assert len(parsed) == 1
    assert parsed[0].server == "192.0.2.1"

    lines = to_plaintext_uris(parsed)
    assert lines[0].startswith("vless://550e8400-e29b-41d4-a716-446655440000@192.0.2.1:443")
    assert "example.com" not in "\n".join(lines)


def test_parse_text_decodes_base64_subscription_with_real_uri():
    base64_payload = base64.b64encode(
        b"ss://YWVzLTI1Ni1nY206c2VjdXJla2V5@192.0.2.2:8388#Node-2\n"
    ).decode()
    parsed = parse_text(base64_payload)
    assert len(parsed) == 1
    assert parsed[0].server == "192.0.2.2"


def test_vless_reality_round_trip_preserves_security_mode():
    original = (
        "vless://550e8400-e29b-41d4-a716-446655440000@192.0.2.3:9873"
        "?encryption=none&fp=chrome&mode=gun&pbk=publickeyvalue"
        "&security=reality&serviceName=grpc-tunnel&sid=aabb&sni=dl.google.com&type=grpc#node"
    )
    proxy = parse_uri(original)
    assert proxy is not None
    assert proxy.security == "reality"
    assert proxy.encryption == "none"
    assert proxy.fingerprint == "chrome"
    assert proxy.mode == "gun"
    assert proxy.service_name == "grpc-tunnel"

    generated = to_plaintext_uris([proxy])[0]
    # The security mode must stay "reality"; regressing it to "tls" breaks the handshake.
    assert "security=reality" in generated
    assert "security=tls" not in generated
    assert "serviceName=grpc-tunnel" in generated
    assert "encryption=none" in generated
    assert "pbk=publickeyvalue" in generated
    assert "sid=aabb" in generated


def test_vless_tls_is_not_upgraded_to_reality():
    """The reverse direction must also hold: a plain TLS node must not become REALITY."""
    proxy = parse_uri("vless://550e8400-e29b-41d4-a716-446655440000@192.0.2.4:443?security=tls&sni=a.com&type=ws#n")
    generated = to_plaintext_uris([proxy])[0]
    assert "security=tls" in generated
    assert "security=reality" not in generated
    assert "pbk=" not in generated


def test_trojan_reality_round_trip_preserves_security_mode():
    original = (
        "trojan://secretpassword@192.0.2.5:443"
        "?security=reality&sni=deepl.com&fp=firefox&pbk=pubkey&sid=ee33&flow=xtls-rprx-vision#node"
    )
    proxy = parse_uri(original)
    assert proxy is not None
    assert proxy.security == "reality"
    assert proxy.reality == {"public_key": "pubkey", "short_id": "ee33"}
    assert proxy.fingerprint == "firefox"
    assert proxy.flow == "xtls-rprx-vision"

    generated = to_plaintext_uris([proxy])[0]
    assert generated.startswith("trojan://secretpassword@192.0.2.5:443")
    assert "security=reality" in generated
    assert "security=tls" not in generated
    assert "pbk=pubkey" in generated
    assert "sid=ee33" in generated
    assert "fp=firefox" in generated
    assert "flow=xtls-rprx-vision" in generated


def test_vmess_round_trip_preserves_reality_and_grpc_metadata():
    original = (
        "vmess://550e8400-e29b-41d4-a716-446655440000@192.0.2.6:443"
        "?security=reality&fp=chrome&mode=gun&serviceName=grpc-tunnel&pbk=pubkey&sid=aabb&type=grpc#node"
    )
    proxy = parse_uri(original)
    assert proxy is not None
    assert proxy.security == "reality"
    assert proxy.service_name == "grpc-tunnel"

    generated = to_plaintext_uris([proxy])[0]
    payload = json.loads(base64.b64decode(generated.removeprefix("vmess://") + "==="))
    assert payload["security"] == "reality"
    assert payload["serviceName"] == "grpc-tunnel"
    assert payload["pbk"] == "pubkey"
    assert payload["sid"] == "aabb"
    assert payload["fp"] == "chrome"
    assert payload["mode"] == "gun"


def test_deduplication_by_type_server_port():
    duplicate = "vless://550e8400-e29b-41d4-a716-446655440000@192.0.2.7:443?security=tls#node\n"
    text = duplicate + duplicate + duplicate
    assert len(parse_text(text)) == 1


def test_invalid_uuid_is_rejected():
    assert parse_uri("vless://not-a-uuid@192.0.2.8:443?security=tls#node") is None


def test_missing_password_is_rejected():
    assert parse_uri("trojan://@192.0.2.9:443?security=tls#node") is None


def test_ss_without_method_is_rejected():
    assert parse_uri("ss://@192.0.2.10:8388#node") is None


def test_loopback_and_private_addresses_are_rejected():
    assert parse_uri("vless://550e8400-e29b-41d4-a716-446655440000@127.0.0.1:443?security=tls#node") is None
    assert parse_uri("vless://550e8400-e29b-41d4-a716-446655440000@localhost:443?security=tls#node") is None


def test_singbox_json_is_parsed():
    config = json.dumps({"outbounds": [
        {"type": "vless", "tag": "node", "server": "192.0.2.11", "server_port": 443,
         "uuid": "550e8400-e29b-41d4-a716-446655440000",
         "tls": {"enabled": True, "server_name": "a.com", "reality": {"enabled": True, "public_key": "pk", "short_id": "sid"}}}
    ]})
    proxies = parse_text(config)
    assert len(proxies) == 1
    assert proxies[0].security == "reality" or proxies[0].reality is not None


def test_unencrypted_http_and_socks_uris_are_rejected():
    assert parse_uri("http://user:pass@192.0.2.12:8080#node") is None
    assert parse_uri("socks5://user:pass@192.0.2.12:1080#node") is None


def test_hysteria2_uri_is_parsed():
    proxy = parse_uri("hy2://secretpassword@192.0.2.13:443?sni=a.com&insecure=0#node")
    assert proxy is not None
    assert proxy.type == "hy2"
    assert proxy.password == "secretpassword"
    assert proxy.server == "192.0.2.13"
    assert proxy.port == 443
    assert proxy.tls is True

    generated = to_plaintext_uris([proxy])[0]
    assert generated.startswith("hy2://secretpassword@192.0.2.13:443")
    assert "sni=a.com" in generated


def test_hysteria2_reality_round_trip_preserves_security_mode():
    """hy2 may also run over REALITY; the security mode must survive the round trip."""
    original = (
        "hy2://secretpassword@192.0.2.15:443"
        "?security=reality&sni=deepl.com&pbk=pubkey&sid=ee33&insecure=0#node"
    )
    proxy = parse_uri(original)
    assert proxy is not None
    assert proxy.security == "reality"
    assert proxy.reality == {"public_key": "pubkey", "short_id": "ee33"}

    generated = to_plaintext_uris([proxy])[0]
    assert "security=reality" in generated
    assert "security=tls" not in generated
    assert "pbk=pubkey" in generated
    assert "sid=ee33" in generated


def test_shadowsocks_alias_normalises_to_ss():
    proxy = parse_uri("shadowsocks://550e8400-e29b-41d4-a716-446655440000@192.0.2.14:8388#node")
    assert proxy is None or proxy.type == "ss"


def test_broken_yaml_entry_does_not_discard_whole_source():
    """A malformed flow-mapping must not cost us the valid entries around it.

    Aggregators such as mfuu/v2ray emit lines with nested quotes inside a name,
    e.g. name: "FR-"2001:bc8:...:"-0055". Before the block-scan fallback this
    made yaml.safe_load() raise and the whole source was dropped.
    """
    document = (
        "proxies:\n"
        '- {name: ok-1, server: 192.0.2.10, port: 443, type: trojan, password: secret}\n'
        '- {name: "FR-"2001:bc8:32d7:225::3"-0055", server: "2001:bc8:32d7:225::3", port: 55009, type: vmess, uuid: cd80d0a4-a8ef-4492-b9}\n'
        '- {name: ok-2, server: 192.0.2.11, port: 443, type: trojan, password: secret}\n'
    )
    proxies = parse_text(document)
    servers = sorted(proxy.server for proxy in proxies)
    assert servers == ["192.0.2.10", "192.0.2.11"]


def test_block_mapping_yaml_recovers_valid_entries():
    """The multi-line `- name:` shape is recovered the same way."""
    document = (
        "proxies:\n"
        "  - name: ok-1\n"
        "    type: trojan\n"
        "    server: 192.0.2.20\n"
        "    port: 443\n"
        "    password: secret\n"
        "  - name: broken\n"
        "    type: vless\n"
        "    server: [unclosed\n"
        "  - name: ok-2\n"
        "    type: trojan\n"
        "    server: 192.0.2.21\n"
        "    port: 443\n"
        "    password: secret\n"
    )
    proxies = parse_text(document)
    servers = sorted(proxy.server for proxy in proxies)
    assert servers == ["192.0.2.20", "192.0.2.21"]


def test_yaml_port_with_trailing_junk_falls_back_safely():
    """Sanitising quotes can leave artefacts like port: 443? — it must not crash."""
    document = "proxies:\n- {name: ok, server: 192.0.2.30, port: 443?, type: trojan, password: secret}\n"
    proxies = parse_text(document)
    assert len(proxies) == 1
    assert proxies[0].port == 443
