import json
from typing import Any

import yaml

from src.parser.model import ProxyConfig

#: Maps internal proxy type names to sing-box outbound type names.
_SINGBOX_TYPE_MAP: dict[str, str] = {
    "ss": "shadowsocks",
    "hy2": "hysteria2",
    "socks4": "socks",
    "socks5": "socks",
}


def _clash_proxy(proxy: ProxyConfig) -> dict[str, Any]:
    item: dict[str, Any] = {"name": proxy.name, "type": proxy.type, "server": proxy.server, "port": proxy.port}
    if proxy.type in {"vless", "vmess"}:
        item["uuid"] = proxy.uuid
    if proxy.type == "trojan":
        item["password"] = proxy.password
    if proxy.type == "ss":
        item.update(cipher=proxy.method, password=proxy.password)
    if proxy.type in {"hy2", "http", "socks", "socks4", "socks5"} and proxy.password:
        item["password"] = proxy.password
    if proxy.tls:
        item["tls"] = True
    for key, value in (("flow", proxy.flow), ("servername", proxy.sni), ("network", proxy.network), ("ws-opts", {"path": proxy.path, "headers": {"Host": proxy.host}} if proxy.network == "ws" else None)):
        if value:
            item[key] = value
    return item


def to_clash(proxies: list[ProxyConfig]) -> str:
    return yaml.safe_dump({"proxies": [_clash_proxy(proxy) for proxy in proxies]}, allow_unicode=True, sort_keys=False)


def _singbox_proxy(proxy: ProxyConfig) -> dict[str, Any]:
    sb_type = _SINGBOX_TYPE_MAP.get(proxy.type, proxy.type)
    item: dict[str, Any] = {"type": sb_type, "tag": proxy.name, "server": proxy.server, "server_port": proxy.port}
    if proxy.uuid:
        item["uuid"] = proxy.uuid
    if proxy.password:
        item["password"] = proxy.password
    if proxy.method:
        item["method"] = proxy.method
    if sb_type == "socks":
        item["version"] = "5"
    tls_block: dict[str, Any] = {"enabled": True}
    if proxy.sni:
        tls_block["server_name"] = proxy.sni
    if proxy.security == "reality" and proxy.reality:
        tls_block["reality"] = {
            "enabled": True,
            "public_key": proxy.reality.get("public_key"),
            "short_id": proxy.reality.get("short_id") or "",
        }
        # The pinned sing-box 1.13.1 release is built with with_utls, so a
        # reality client also needs a uTLS fingerprint enabled.
        tls_block["utls"] = {"enabled": True, "fingerprint": proxy.fingerprint or _DEFAULT_UTLS_FINGERPRINT}
    if proxy.tls or proxy.security == "reality":
        item["tls"] = tls_block
    # sing-box >= 1.12 uses a transport field with type for V2Ray transports.
    # Only vless, vmess, trojan, and naive support transport.
    if proxy.type in {"vless", "vmess", "trojan", "naive"}:
        if proxy.network == "grpc":
            item["transport"] = {"type": "grpc", "service_name": proxy.service_name or ""}
        elif proxy.network == "ws":
            ws: dict[str, Any] = {"type": "ws", "path": proxy.path or ""}
            if proxy.host:
                ws["headers"] = {"Host": proxy.host}
            item["transport"] = ws
    return item


def to_singbox(
    proxies: list[ProxyConfig],
    clash_api_port: int = 16756,
    clash_api_secret: str = "sbox-check",
    socks_port: int = 12334,
    mixed_port: int = 12335,
) -> str:
    """Build a full sing-box config with one outbound per proxy candidate.

    The config is meant for a short-lived local verification instance:
    inbounds listen on localhost, outbounds contain all candidates, and the
    Clash API allows the checker to measure each tag independently. A single
    instance can hold many candidates, but for deterministic status checks
    the recommended flow is to start one instance per candidate.
    """
    outbounds = [_singbox_proxy(proxy) for proxy in proxies]
    document: dict[str, Any] = {
        "log": {"level": "warning"},
        "dns": _dns_config(),
        "inbounds": [
            {"type": "socks", "tag": "socks-inbound", "listen": "127.0.0.1", "listen_port": socks_port, "udp": True},
            {"type": "mixed", "tag": "mixed-inbound", "listen": "127.0.0.1", "listen_port": mixed_port},
        ],
        "outbounds": [*outbounds, {"type": "direct", "tag": "direct"}],
        "experimental": {
            "clash_api": {
                "external_controller": f"127.0.0.1:{clash_api_port}",
                "secret": clash_api_secret,
            }
        },
    }
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"


# ---------------------------------------------------------------------------
# Parallel per-inbound variant (CI mode)
# ---------------------------------------------------------------------------

#: Proxy types that sing-box 1.13 does not support as outbounds.
_UNSUPPORTED_OUTBOUND_TYPES: frozenset[str] = frozenset()

#: Network/transport values that sing-box does not recognise.
_UNSUPPORTED_TRANSPORTS: frozenset[str] = frozenset({"xhttp", "httpupgrade"})

# Default uTLS fingerprint used when proxy.fingerprint is not set.
_DEFAULT_UTLS_FINGERPRINT = "chrome"


def _is_supported_outbound(proxy: ProxyConfig) -> bool:
    """Return True when sing-box can express this proxy as an outbound."""
    if proxy.type in _UNSUPPORTED_OUTBOUND_TYPES:
        return False
    if proxy.network in _UNSUPPORTED_TRANSPORTS:
        return False
    # vless/vmess require a valid UUID for the sing-box config to be valid.
    return not (proxy.type in {"vless", "vmess"} and not proxy.uuid)


def to_singbox_parallel(
    proxies: list[ProxyConfig],
    base_port: int = 20000,
    clash_api_port: int = 0,
    clash_api_secret: str = "",
    port_per_candidate: int = 1,
) -> tuple[str, dict[int, int]]:
    """Build a sing-box config where each candidate gets its own inbound.

    Variant B from the CI spec: one ``mixed`` inbound per candidate on
    ``127.0.0.1:base_port+i`` plus a route rule binding that inbound to the
    corresponding outbound.  All candidates are checked in parallel without
    switching the global proxy.

    Unsupported outbounds (xhttp, no-UUID, etc.) are filtered out
    automatically; the returned port_map only contains entries for proxies
    that actually appear in the config.

    Returns:
        config_text: JSON config string.
        port_map: mapping of index-in-original-list -> assigned port.
    """
    # Filter to supported outbounds only
    supported = [p for p in proxies if _is_supported_outbound(p)]

    # Assign free ports starting from base_port
    port_map: dict[int, int] = {}
    inbounds: list[dict[str, Any]] = []
    outbounds: list[dict[str, Any]] = []
    rules: list[dict[str, Any]] = []
    used_tags: set[str] = set()

    for idx, proxy in enumerate(supported):
        port = base_port + idx * port_per_candidate
        # Map back to the original index so callers can correlate
        port_map[proxies.index(proxy)] = port
        in_tag = f"in-{idx}"
        # Ensure unique outbound tags (proxy.name can collide across servers)
        out_tag = proxy.name
        if out_tag in used_tags:
            out_tag = f"{out_tag}-{idx}"
        used_tags.add(out_tag)
        inbounds.append({
            "type": "mixed",
            "tag": in_tag,
            "listen": "127.0.0.1",
            "listen_port": port,
        })
        ob = _singbox_proxy(proxy)
        ob["tag"] = out_tag
        outbounds.append(ob)
        rules.append({
            "inbound": [in_tag],
            "outbound": out_tag,
        })

    # Direct fallback outbound for any unrouted traffic
    outbounds.append({"type": "direct", "tag": "direct"})

    document: dict[str, Any] = {
        "log": {"level": "warning"},
        "dns": _dns_config(),
        "inbounds": inbounds,
        "route": {"rules": rules, "final": "direct"},
        "outbounds": outbounds,
        "experimental": {
            "clash_api": {
                "external_controller": f"127.0.0.1:{clash_api_port}",
                "secret": clash_api_secret,
            }
        },
    }
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n", port_map


def filter_supported_outbounds(proxies: list[ProxyConfig]) -> tuple[list[ProxyConfig], list[ProxyConfig]]:
    """Split proxies into (supported, unsupported) for sing-box outbounds."""
    supported: list[ProxyConfig] = []
    unsupported: list[ProxyConfig] = []
    for proxy in proxies:
        if _is_supported_outbound(proxy):
            supported.append(proxy)
        else:
            unsupported.append(proxy)
    return supported, unsupported


def sort_by_latency(proxies: list[ProxyConfig]) -> list[ProxyConfig]:
    """Sort proxies by measured latency, fastest first.

    speed_kbps is derived from the delay (8000 / delay), so a higher value
    means a faster node. Unverified nodes have no measurement and are pushed
    to the end while keeping their original relative order.
    """
    return sorted(proxies, key=lambda proxy: proxy.speed_kbps or -1, reverse=True)


def _dns_config() -> dict:
    """Return DNS config compatible with sing-box >= 1.12 (new typed servers)."""
    return {
        "servers": [
            {
                "type": "local",
                "tag": "local",
            }
        ],
        "final": "local",
    }
