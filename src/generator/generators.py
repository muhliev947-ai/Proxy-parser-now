import json
from typing import Any

import yaml

from src.parser.model import ProxyConfig


def _clash_proxy(proxy: ProxyConfig) -> dict[str, Any]:
    item: dict[str, Any] = {"name": proxy.name, "type": proxy.type, "server": proxy.server, "port": proxy.port}
    if proxy.type in {"vless", "vmess"}:
        item["uuid"] = proxy.uuid
    if proxy.type == "trojan":
        item["password"] = proxy.password
    if proxy.type == "ss":
        item.update(cipher=proxy.method, password=proxy.password)
    if proxy.type in {"hy2", "http", "socks", "socks4", "socks5"}:
        if proxy.password:
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
    item: dict[str, Any] = {"type": proxy.type, "tag": proxy.name, "server": proxy.server, "server_port": proxy.port}
    if proxy.uuid:
        item["uuid"] = proxy.uuid
    if proxy.password:
        item["password"] = proxy.password
    if proxy.method:
        item["method"] = proxy.method
    if proxy.type in {"socks", "socks5"}:
        item["version"] = "5"
    if proxy.tls:
        item["tls"] = {"enabled": True, **({"server_name": proxy.sni} if proxy.sni else {})}
    return item


def to_singbox(proxies: list[ProxyConfig]) -> str:
    return json.dumps({"outbounds": [_singbox_proxy(proxy) for proxy in proxies]}, ensure_ascii=False, indent=2) + "\n"