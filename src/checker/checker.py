import socket
import time
from dataclasses import dataclass
from urllib.request import urlopen

from src.parser.model import ProxyConfig


@dataclass
class CheckConfig:
    timeout_seconds: float = 5
    urls: list[str] | None = None


def check_proxy(proxy: ProxyConfig, config: CheckConfig) -> ProxyConfig:
    started = time.monotonic()
    try:
        with socket.create_connection((proxy.server, proxy.port), timeout=config.timeout_seconds):
            pass
        if config.urls:
            with urlopen(config.urls[0], timeout=config.timeout_seconds) as response:
                response.read(1)
        proxy.available = True
        proxy.speed_kbps = round(8 / max(time.monotonic() - started, 0.001), 2)
    except (OSError, ValueError):
        proxy.available = False
        proxy.speed_kbps = 0
    return proxy