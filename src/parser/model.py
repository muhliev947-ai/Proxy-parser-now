from dataclasses import dataclass, field
from typing import Any


@dataclass
class ProxyConfig:
    type: str
    server: str
    port: int
    name: str = ""
    uuid: str | None = None
    password: str | None = None
    method: str | None = None
    tls: bool = False
    security: str | None = None
    flow: str | None = None
    sni: str | None = None
    fingerprint: str | None = None
    encryption: str | None = None
    mode: str | None = None
    network: str | None = None
    path: str | None = None
    host: str | None = None
    service_name: str | None = None
    reality: dict[str, Any] | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    country: str | None = None
    speed_kbps: float | None = None
    available: bool | None = None
    tcp_reachable: bool | None = None
    verified: bool = False
    fail_reason: str = ""

    def __post_init__(self) -> None:
        self.type = self.type.lower().replace("shadowsocks", "ss").replace("hysteria2", "hy2")
        if not self.name:
            self.name = f"{self.type}-{self.server}:{self.port}"

    @property
    def protocol(self) -> str | None:
        if self.reality or self.security == "reality":
            return "reality"
        return self.network
