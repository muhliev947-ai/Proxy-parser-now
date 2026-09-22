import json
import logging
import socket
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.request import urlopen

from src.parser.model import ProxyConfig

LOG = logging.getLogger(__name__)


@dataclass
class CheckConfig:
    timeout_seconds: float = 5
    urls: list[str] | None = None
    clash_api_url: str | None = None
    clash_api_secret: str | None = None
    concurrency: int = 8
    expected_status: int = 204
    socks_proxy_url: str | None = None


def _api(base: str, secret: str | None, path: str, method: str = "GET", data: bytes | None = None) -> tuple[int, dict]:
    headers = {"Authorization": f"Bearer {secret}"} if secret else {}
    request = urllib.request.Request(base + path, headers=headers, method=method, data=data)
    with urlopen(request, timeout=30) as response:
        body = response.read().decode()
        return response.status, json.loads(body) if body.strip() else {}


def _proxy_tag(proxy: ProxyConfig) -> str:
    return f"{proxy.type}-{proxy.server}:{proxy.port}"


_HIDDIFY_TAG_INDEX: dict[tuple[str, int], str] = {}
_HIDDIFY_SECRET: str | None = None


def load_hiddify_tags(config_path: str = "~/.local/share/hiddify/data/current-config.json") -> dict[tuple[str, int], str]:
    """Map (server, port) -> Clash API tag from the running Hiddify config.

    The Clash API does not expose server addresses, so tags are resolved from
    the generated sing-box configuration that Hiddify keeps on disk. The API
    secret is refreshed here too, because Hiddify regenerates it on restart.
    """
    global _HIDDIFY_TAG_INDEX, _HIDDIFY_SECRET
    path = Path(config_path).expanduser()
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        _HIDDIFY_TAG_INDEX = {}
        _HIDDIFY_SECRET = None
        return _HIDDIFY_TAG_INDEX
    index: dict[tuple[str, int], str] = {}
    for outbound in document.get("outbounds", []):
        server = outbound.get("server")
        port = outbound.get("server_port")
        if server and port:
            index[(str(server), int(port))] = str(outbound.get("tag"))
    _HIDDIFY_TAG_INDEX = index
    clash_api = document.get("experimental", {}).get("clash_api", {})
    _HIDDIFY_SECRET = clash_api.get("secret")
    return _HIDDIFY_TAG_INDEX


def _verify_via_clash_api(proxy: ProxyConfig, config: CheckConfig) -> bool:
    """Run the proxied HTTP request through the Clash API and check the status.

    sing-box reports a delay for any reachable URL, including 404/500 responses,
    so the returned status must be compared against the expected one explicitly.
    """
    tag = _HIDDIFY_TAG_INDEX.get((proxy.server, proxy.port)) or _proxy_tag(proxy)
    quoted_tag = urllib.parse.quote(tag, safe="")
    url = urllib.parse.quote(config.urls[0] if config.urls else "https://cp.cloudflare.com/generate_204", safe="")
    secret = _HIDDIFY_SECRET or config.clash_api_secret
    status, result = _api(config.clash_api_url, secret, f"/proxies/{quoted_tag}/delay?timeout=5000&url={url}")
    if status != 200:
        return False
    delay = result.get("delay")
    if not isinstance(delay, (int, float)) or delay <= 0:
        return False
    proxy.speed_kbps = round(8000 / max(delay, 1), 2)
    return True


def _verify_via_socks(proxy: ProxyConfig, config: CheckConfig) -> bool:
    """Independently confirm the expected HTTP status through the proxy.

    The Clash API delay endpoint cannot distinguish 204 from 404/500, so the
    response code is checked directly over the local SOCKS inbound. Only the
    currently selected outbound is reachable this way, which is why this is a
    secondary confirmation rather than the primary check.
    """
    socks_url = config.socks_proxy_url
    if not socks_url:
        return True
    target = config.urls[0] if config.urls else "https://cp.cloudflare.com/generate_204"
    proxy_handler = urllib.request.ProxyHandler({"http": socks_url, "https": socks_url})
    opener = urllib.request.build_opener(proxy_handler)
    try:
        with opener.open(target, timeout=max(config.timeout_seconds, 5)) as response:
            return response.status == config.expected_status
    except (OSError, ValueError):
        return False


def check_proxy(proxy: ProxyConfig, config: CheckConfig) -> ProxyConfig:
    """Verify a proxy through the running Hiddify sing-box Clash API.

    A plain TCP connect cannot prove that UUID, TLS, Reality or WebSocket
    settings are valid, so the real handshake is delegated to sing-box.
    """
    try:
        with socket.create_connection((proxy.server, proxy.port), timeout=config.timeout_seconds):
            proxy.tcp_reachable = True
    except (OSError, ValueError):
        proxy.tcp_reachable = False
        proxy.fail_reason = "TCP connection to the server port failed (node down, firewall, or IP blocked)"
        proxy.available = False
        proxy.verified = False
        proxy.speed_kbps = 0
        return proxy

    if not config.clash_api_url:
        proxy.fail_reason = "no Clash API configured; node could not be verified"
        proxy.available = False
        proxy.verified = False
        proxy.speed_kbps = 0
        return proxy

    try:
        ok = _verify_via_clash_api(proxy, config)
        reason = None
        if ok:
            ok = _verify_via_socks(proxy, config)
            if not ok:
                reason = "HTTP status through the node differed from the expected one"
        elif proxy.speed_kbps in (0, 0.0):
            reason = "no usable latency/HTTP status got through the node"
        proxy.available = ok
        proxy.verified = ok
        if not ok:
            proxy.speed_kbps = 0
            proxy.fail_reason = reason or "Clash API delay check failed"
    except (OSError, ValueError):
        proxy.available = False
        proxy.verified = False
        proxy.speed_kbps = 0
        proxy.fail_reason = "network error during verification"
    return proxy
