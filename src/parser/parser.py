import base64
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse
from urllib.request import Request, urlopen

import yaml

from .model import ProxyConfig

LOG = logging.getLogger(__name__)
SUPPORTED = {"vless", "vmess", "trojan", "ss", "shadowsocks", "hy2", "hysteria2"}
PLACEHOLDER_HOSTS = {"localhost"}
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _query_value(query: dict[str, list[str]], key: str) -> str | None:
    return query.get(key, [None])[0]


def _looks_like_placeholder(value: str | None) -> bool:
    if value is None:
        return True
    clean = str(value).strip().lower()
    if not clean:
        return True
    if clean in {"uuid", "null", "none", "", "publickey", "placeholder", "abc123"}:
        return True
    if any(fragment in clean for fragment in ("publickey", "placeholder", "abc123", "demo")):
        return True
    return False


def _should_skip_value(value: str) -> bool:
    lowered = value.lower()
    if "publickey" in lowered or "placeholder" in lowered or "abc123" in lowered:
        return True
    if "demo" in lowered and ("pbk=" in lowered or "sid=" in lowered or "security=reality" in lowered):
        return True
    if "example.com" in lowered and ("pbk=" in lowered or "sid=" in lowered or "security=reality" in lowered or "publickey" in lowered or "#fallback" in lowered):
        return True
    if "example.com" in lowered and "sni=example.com" in lowered and ("security=tls" in lowered or "security=reality" in lowered):
        return True
    return False


def _is_real_proxy(proxy: ProxyConfig) -> bool:
    host = (proxy.server or "").strip().lower()
    if not host:
        return False
    if host in PLACEHOLDER_HOSTS:
        return False
    if _is_placeholder_uri(host):
        return False
    if proxy.type in {"vless", "vmess"} and (
        not proxy.uuid or not UUID_PATTERN.fullmatch(proxy.uuid) or _looks_like_placeholder(proxy.uuid)
    ):
        return False
    if proxy.type in {"trojan", "hy2", "ss", "shadowsocks"} and (not proxy.password or _looks_like_placeholder(proxy.password)):
        return False
    if proxy.type in {"ss", "shadowsocks"} and not proxy.method:
        return False
    if proxy.name and _looks_like_placeholder(proxy.name):
        return False
    if any(_is_placeholder_uri(str(value)) for value in (proxy.uuid, proxy.password, proxy.sni) if value):
        return False
    return True


def _is_placeholder_uri(value: str) -> bool:
    lowered = value.lower()
    return any(token in lowered for token in (
        "example.com", "example.org", "example.net", "speedtest.example.net",
        "localhost", "127.0.0.1", "publickey", "secret-pass", "placeholder",
        "demo", "test", "speedtest",
        "00000000-0000-0000-0000-000000000000",
    ))


def parse_uri(value: str) -> ProxyConfig | None:
    raw = value.strip()
    if not raw:
        return None
    try:
        parsed = urlparse(raw)
    except ValueError:
        # urlparse raises "Invalid IPv6 URL" for malformed netlocs (e.g. unbalanced
        # brackets or control characters in the password). A single such line must not
        # abort parsing of the whole subscription, so it is discarded here.
        LOG.debug("Skipping malformed URI: %s", raw[:120])
        return None
    scheme = parsed.scheme.lower()
    if scheme not in SUPPORTED:
        # Unencrypted http:// and socks:// are explicitly rejected: the spec
        # requires only encrypted protocols to be published.
        return None
    query = parse_qs(parsed.query)
    params = {key: unquote(values[0]) for key, values in query.items() if values}
    user = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    # Trojan and Hysteria2 put the credential in the userinfo "user" slot
    # (trojan://PASSWORD@host), and urlparse leaves .password empty.
    if scheme in {"trojan", "hy2", "hysteria2"} and not password:
        password = user
    if scheme == "vmess":
        # A standard vmess URI is vmess://UUID@host:port?params#name.
        # Only the legacy form vmess://<base64-json> needs decoding here.
        payload = raw.split("://", 1)[1]
        looks_like_base64 = payload and not payload.startswith(("@", "[")) and not urlparse("http://" + payload).hostname
        if looks_like_base64:
            try:
                decoded = base64.b64decode(payload + "===").decode()
                item = json.loads(decoded)
                config = _from_mapping(item, "vmess")
                return config if config and _is_real_proxy(config) else None
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
                return None
    if scheme in {"ss", "shadowsocks"} and not parsed.hostname:
        try:
            decoded = base64.b64decode(parsed.netloc + "===").decode()
            user, hostport = decoded.rsplit("@", 1)
            method, password = user.split(":", 1)
            host, port = hostport.rsplit(":", 1)
            config = ProxyConfig(scheme, host, int(port), method=method, password=password,
                                 name=params.get("remarks", host))
            return config if _is_real_proxy(config) else None
        except (ValueError, UnicodeDecodeError):
            return None
    if scheme in {"ss", "shadowsocks"} and parsed.hostname:
        try:
            decoded = base64.urlsafe_b64decode(unquote(user) + "===").decode()
            method, password = decoded.split(":", 1)
        except (ValueError, UnicodeDecodeError):
            return None
    if not parsed.hostname:
        return None
    try:
        port = parsed.port
    except ValueError:
        # A non-numeric port (e.g. "443%40name") makes the URI unusable; skip it
        # instead of letting the whole subscription fail.
        LOG.debug("Skipping URI with invalid port: %s", raw[:120])
        return None
    if not port:
        return None
    security = params.get("security", "").lower()
    config = ProxyConfig(
        scheme, parsed.hostname, port, name=params.get("remarks", parsed.hostname),
        uuid=user if scheme in {"vless", "vmess"} else None,
        password=password or (user if scheme in {"trojan", "hy2"} else None),
        method=method if scheme in {"ss", "shadowsocks"} else params.get("method"),
        # Hysteria2 is QUIC-over-TLS by definition, so it always implies TLS even
        # when the URI does not carry an explicit security= parameter.
        tls=security in {"tls", "reality"} or scheme in {"trojan", "hy2", "hysteria2"},
        security=security or None,
        flow=params.get("flow"), sni=params.get("sni") or params.get("peer"),
        fingerprint=params.get("fp"),
        encryption=params.get("encryption"),
        mode=params.get("mode"),
        network=params.get("type") or params.get("network"), path=params.get("path"),
        host=params.get("host"), service_name=params.get("serviceName"),
        reality={"public_key": params.get("pbk"), "short_id": params.get("sid")} if params.get("pbk") or params.get("sid") else None,
        raw=params,
    )
    return config if _is_real_proxy(config) else None


def _from_mapping(item: dict, fallback_type: str | None = None) -> ProxyConfig | None:
    kind = str(item.get("type", fallback_type or "")).lower()
    if kind not in SUPPORTED or not item.get("server"):
        return None
    tls = item.get("tls", False)
    if isinstance(tls, dict):
        tls = tls.get("enabled", False)
    reality = item.get("reality") or (item.get("tls", {}).get("reality") if isinstance(item.get("tls"), dict) else None)
    return ProxyConfig(kind, str(item["server"]), int(item.get("port", 443)),
                       name=str(item.get("name", item.get("server"))), uuid=item.get("uuid"),
                       password=item.get("password"), method=item.get("cipher", item.get("method")),
                       tls=bool(tls), flow=item.get("flow"), sni=item.get("servername", item.get("sni")),
                       network=item.get("network", item.get("transport", {}).get("type") if isinstance(item.get("transport"), dict) else item.get("network")),
                       path=item.get("path"), host=item.get("host"), service_name=item.get("service_name"),
                       reality=reality, raw=item)


def _decode_payload(text: str) -> str:
    stripped = "".join(text.split())
    if stripped and len(stripped) % 4 in {0, 2, 3} and all(char.isalnum() or char in "+/=_-" for char in stripped):
        try:
            decoded = base64.urlsafe_b64decode(stripped + "===").decode()
            if "://" in decoded or decoded.lstrip().startswith(("{", "proxies:", "outbounds:")):
                return decoded
        except (ValueError, UnicodeDecodeError):
            pass
    return text


def parse_text(text: str) -> list[ProxyConfig]:
    text = _decode_payload(text)
    result: list[ProxyConfig] = []
    try:
        document = json.loads(text)
        items = document.get("outbounds", []) if isinstance(document, dict) else []
        for item in items:
            parsed = _from_mapping(item)
            if parsed and _is_real_proxy(parsed):
                result.append(parsed)
        if result:
            return result
    except json.JSONDecodeError:
        pass
    try:
        document = yaml.safe_load(text)
        for item in document.get("proxies", []) if isinstance(document, dict) else []:
            parsed = _from_mapping(item)
            if parsed and _is_real_proxy(parsed):
                result.append(parsed)
        if result:
            return result
    except yaml.YAMLError as exc:
        LOG.debug("Not YAML: %s", exc)
    for line in text.splitlines():
        value = line.strip().strip('"\',')
        if not value:
            continue
        if _should_skip_value(value) or _is_placeholder_uri(value):
            continue
        if not re.match(r"^(?:vless|vmess|ss|trojan|hy2|hysteria2)://", value, re.I):
            continue
        parsed = parse_uri(value)
        if parsed:
            result.append(parsed)
    unique: dict[tuple[str, str, int], ProxyConfig] = {}
    for proxy in result:
        if _is_real_proxy(proxy):
            unique[(proxy.type, proxy.server, proxy.port)] = proxy
    return list(unique.values())


def _read_json(url: str, timeout: int = 15) -> object:
    request = Request(url, headers={"User-Agent": "proxy-subscription-builder/0.1", "Accept": "application/vnd.github+json"})
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8", errors="replace"))


def _github_repo_files(repo_source: str, freshness_days: int = 7, timeout: int = 15) -> list[str]:
    repo_source = repo_source.removeprefix("github:")
    repo_source = repo_source.strip("/")
    if repo_source.startswith("https://github.com/"):
        repo_source = repo_source[len("https://github.com/"):]
    if repo_source.startswith("http://github.com/"):
        repo_source = repo_source[len("http://github.com/"):]
    repo_source = repo_source.strip("/")
    if repo_source.count("/") < 1:
        return []
    owner, repo_name = repo_source.split("/", 1)
    repo_name = repo_name.split("/", 1)[0]

    def list_files(path: str = "") -> list[dict]:
        base = f"https://api.github.com/repos/{owner}/{repo_name}/contents"
        if path:
            base = f"{base}/{path}"
        try:
            items = _read_json(base, timeout=timeout)
        except (OSError, ValueError, json.JSONDecodeError):
            return []
        if not isinstance(items, list):
            return []
        return items

    def _collect(path: str = "") -> list[str]:
        files: list[str] = []
        for item in list_files(path):
            if not isinstance(item, dict):
                continue
            item_type = item.get("type")
            item_path = str(item.get("path", ""))
            if item_type == "dir":
                files.extend(_collect(item_path))
                continue
            if item_type != "file":
                continue
            if not item_path.lower().endswith((".txt", ".yaml", ".yml", ".json", ".conf", ".sub")):
                continue
            if not item.get("download_url"):
                continue
            commit_url = f"https://api.github.com/repos/{owner}/{repo_name}/commits?path={quote(item_path)}&per_page=1"
            try:
                commit_data = _read_json(commit_url, timeout=timeout)
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            if not isinstance(commit_data, list) or not commit_data:
                continue
            date_value = commit_data[0].get("commit", {}).get("author", {}).get("date")
            if not date_value:
                continue
            try:
                commit_time = datetime.fromisoformat(date_value.replace("Z", "+00:00")).astimezone(timezone.utc)
            except ValueError:
                continue
            if datetime.now(timezone.utc) - commit_time <= timedelta(days=freshness_days):
                files.append(item["download_url"])
        return files

    return _collect()


def parse_sources(sources: list[str], timeout: int = 15, freshness_days: int = 7, fallback_file: str | None = None) -> list[ProxyConfig]:
    result: list[ProxyConfig] = []
    for source in sources:
        try:
            if source.startswith("github:") or "github.com/" in source:
                for github_url in _github_repo_files(source, freshness_days=freshness_days, timeout=timeout):
                    try:
                        request = Request(github_url, headers={"User-Agent": "proxy-subscription-builder/0.1"})
                        with urlopen(request, timeout=timeout) as response:
                            text = response.read().decode("utf-8", errors="replace")
                        result.extend(parse_text(text))
                    except (OSError, ValueError):
                        LOG.warning("Could not read GitHub source %s", github_url)
                continue
            if source.startswith(("http://", "https://")):
                request = Request(source, headers={"User-Agent": "proxy-subscription-builder/0.1"})
                with urlopen(request, timeout=timeout) as response:
                    text = response.read().decode("utf-8", errors="replace")
            else:
                text = Path(source).read_text(encoding="utf-8")
            result.extend(parse_text(text))
            LOG.info("Parsed proxies from %s", source)
        except (OSError, ValueError) as exc:
            LOG.warning("Could not read source %s: %s", source, exc)
    if not result and fallback_file:
        try:
            fallback_text = Path(fallback_file).read_text(encoding="utf-8")
            result.extend(parse_text(fallback_text))
            LOG.warning("No live proxies found; used fallback file %s", fallback_file)
        except OSError as exc:
            LOG.warning("Could not read fallback file %s: %s", fallback_file, exc)
    unique: dict[tuple[str, str, int], ProxyConfig] = {}
    for proxy in result:
        if _is_real_proxy(proxy):
            unique[(proxy.type, proxy.server, proxy.port)] = proxy
    return list(unique.values())


def to_plaintext_uris(proxies: list[ProxyConfig]) -> list[str]:
    uris: list[str] = []
    seen: set[str] = set()
    for proxy in proxies:
        if not _is_real_proxy(proxy):
            continue
        if proxy.type == "vless":
            q = []
            # Preserve the original security mode. Writing "tls" for a REALITY
            # server makes the handshake fail, so keep "reality" when present.
            security = proxy.security or ("reality" if proxy.reality else ("tls" if proxy.tls else None))
            if security:
                q.append(f"security={security}")
            if proxy.encryption:
                q.append(f"encryption={proxy.encryption}")
            if proxy.fingerprint:
                q.append(f"fp={proxy.fingerprint}")
            if proxy.flow:
                q.append(f"flow={proxy.flow}")
            if proxy.mode:
                q.append(f"mode={proxy.mode}")
            if proxy.sni:
                q.append(f"sni={proxy.sni}")
            if proxy.network:
                q.append(f"type={proxy.network}")
            if proxy.host:
                q.append(f"host={proxy.host}")
            if proxy.path:
                q.append(f"path={proxy.path}")
            if proxy.service_name:
                q.append(f"serviceName={proxy.service_name}")
            if proxy.reality:
                pbk = proxy.reality.get("public_key")
                sid = proxy.reality.get("short_id")
                if pbk:
                    q.append(f"pbk={pbk}")
                if sid:
                    q.append(f"sid={sid}")
            uri = f"vless://{proxy.uuid}@{proxy.server}:{proxy.port}"
            if q:
                uri += "?" + "&".join(q)
            uri += f"#{quote(proxy.name, safe='')}"
            if uri not in seen:
                seen.add(uri)
                uris.append(uri)
        elif proxy.type == "vmess":
            payload = {
                "v": "2",
                "ps": proxy.name,
                "add": proxy.server,
                "port": str(proxy.port),
                "id": proxy.uuid,
                "aid": "0",
                "scy": "auto",
                "net": proxy.network or "tcp",
                "type": "none",
                "host": proxy.host or "",
                "path": proxy.path or "",
                "tls": "tls" if proxy.tls else "",
                "sni": proxy.sni or "",
            }
            # Preserve security-critical metadata. Losing these breaks REALITY
            # and gRPC handshakes exactly like mixing up security=reality/tls.
            if proxy.security:
                payload["security"] = proxy.security
            if proxy.fingerprint:
                payload["fp"] = proxy.fingerprint
            if proxy.mode:
                payload["mode"] = proxy.mode
            if proxy.service_name:
                payload["serviceName"] = proxy.service_name
            if proxy.flow:
                payload["flow"] = proxy.flow
            if proxy.reality:
                pbk = proxy.reality.get("public_key")
                sid = proxy.reality.get("short_id")
                if pbk:
                    payload["pbk"] = pbk
                if sid:
                    payload["sid"] = sid
            encoded = base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()
            uri = "vmess://" + encoded
            if uri not in seen:
                seen.add(uri)
                uris.append(uri)
        elif proxy.type in {"ss", "shadowsocks"}:
            method = proxy.method or "aes-256-gcm"
            password = proxy.password or ""
            if not password:
                continue
            encoded = base64.b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
            uri = f"ss://{encoded}@{proxy.server}:{proxy.port}#{proxy.name}"
            if uri not in seen:
                seen.add(uri)
                uris.append(uri)
        elif proxy.type in {"trojan", "hy2", "hysteria2"}:
            password = proxy.password or ""
            if not password:
                continue
            uri = f"{proxy.type}://{quote(password, safe='')}@{proxy.server}:{proxy.port}"
            q = []
            # Preserve the original security mode: trojan/hy2 may also use REALITY,
            # and writing plain "tls" for such a server breaks the handshake.
            security = proxy.security or ("reality" if proxy.reality else ("tls" if proxy.tls else None))
            if security:
                q.append(f"security={security}")
            if proxy.sni:
                q.append(f"sni={proxy.sni}")
            if proxy.fingerprint:
                q.append(f"fp={proxy.fingerprint}")
            if proxy.flow:
                q.append(f"flow={proxy.flow}")
            if proxy.network:
                q.append(f"type={proxy.network}")
            if proxy.host:
                q.append(f"host={proxy.host}")
            if proxy.path:
                q.append(f"path={proxy.path}")
            if proxy.service_name:
                q.append(f"serviceName={proxy.service_name}")
            if proxy.reality:
                pbk = proxy.reality.get("public_key")
                sid = proxy.reality.get("short_id")
                if pbk:
                    q.append(f"pbk={pbk}")
                if sid:
                    q.append(f"sid={sid}")
            if q:
                uri += "?" + "&".join(q)
            uri += f"#{quote(proxy.name, safe='')}"
            if uri not in seen:
                seen.add(uri)
                uris.append(uri)
    return uris
