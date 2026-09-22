import base64
import json
import logging
import re
from datetime import UTC, datetime, timedelta
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
    return any(fragment in clean for fragment in ("publickey", "placeholder", "abc123", "demo"))


def _should_skip_value(value: str) -> bool:
    lowered = value.lower()
    if "publickey" in lowered or "placeholder" in lowered or "abc123" in lowered:
        return True
    if "demo" in lowered and ("pbk=" in lowered or "sid=" in lowered or "security=reality" in lowered):
        return True
    if "example.com" in lowered and ("pbk=" in lowered or "sid=" in lowered or "security=reality" in lowered or "publickey" in lowered or "#fallback" in lowered):
        return True
    return "example.com" in lowered and "sni=example.com" in lowered and ("security=tls" in lowered or "security=reality" in lowered)


def _is_real_proxy(proxy: ProxyConfig) -> bool:
    host = (proxy.server or "").strip().lower()
    if not host:
        return False
    if host in PLACEHOLDER_HOSTS:
        return False
    if _is_placeholder_uri(host):
        return False
    if proxy.type in {"vless", "vmess"} and (
        not proxy.uuid
        or not isinstance(proxy.uuid, str)
        or not UUID_PATTERN.fullmatch(proxy.uuid)
        or _looks_like_placeholder(proxy.uuid)
    ):
        return False
    if proxy.type in {"trojan", "hy2", "ss", "shadowsocks"} and (not proxy.password or _looks_like_placeholder(proxy.password)):
        return False
    if proxy.type in {"ss", "shadowsocks"} and not proxy.method:
        return False
    if proxy.name and _looks_like_placeholder(proxy.name):
        return False
    return not any(_is_placeholder_uri(str(value)) for value in (proxy.uuid, proxy.password, proxy.sni) if value)


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
    # A single-line flow mapping parsed on its own (e.g. "{name: ..., server: ...}"
    # without the leading "- ") comes back as a one-element list, not a dict.
    if isinstance(item, list):
        item = item[0] if item and isinstance(item[0], dict) else None
    if not isinstance(item, dict):
        return None
    kind = str(item.get("type", fallback_type or "")).lower()
    if kind not in SUPPORTED or not item.get("server"):
        return None
    tls = item.get("tls", False)
    if isinstance(tls, dict):
        tls = tls.get("enabled", False)
    reality = item.get("reality") or (item.get("tls", {}).get("reality") if isinstance(item.get("tls"), dict) else None)
    try:
        # Port values from sanitised YAML may carry trailing junk ("443?"), so
        # only the leading digits are used and anything else falls back to 443.
        port = int(re.sub(r"[^0-9]", "", str(item.get("port", 443))) or 443)
    except (TypeError, ValueError):
        port = 443
    return ProxyConfig(kind, str(item["server"]), port,
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


def _parse_yaml_proxies(text: str) -> list[ProxyConfig]:
    """Parse a Clash YAML document, tolerating malformed individual entries.

    Aggregators sometimes emit a broken flow-mapping (e.g. an unquoted IPv6
    address inside a name). A single such line used to make yaml.safe_load()
    raise and discard the whole source, which is how the subscription ended
    up with a single node. Fall back to a line-wise block scan that keeps
    every valid entry around the broken one.
    """
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        LOG.debug("YAML document is malformed, falling back to block scan: %s", exc)
        return _parse_yaml_blocks(text)
    if not isinstance(document, dict):
        return []
    items = document.get("proxies", [])
    if not isinstance(items, list):
        return []
    result: list[ProxyConfig] = []
    for item in items:
        if isinstance(item, dict):
            parsed = _from_mapping(item)
            if parsed and _is_real_proxy(parsed):
                result.append(parsed)
    return result


def _parse_yaml_blocks(text: str) -> list[ProxyConfig]:
    """Recover valid `proxies:` entries from a document yaml.safe_load() rejects.

    Two shapes are handled, because both appear in the wild:
    - one flow mapping per line: `- {name: ..., server: ...}`
    - one block mapping per entry spanning several lines, starting with
      `- name: ...` and ending at the next top-level dash.
    """
    blocks: list[str] = []
    current: list[str] = []
    in_flow = False
    for line in text.splitlines():
        if re.match(r"^\s*-\s*\{", line):
            # A flow mapping is complete on its own line: close any open block
            # mapping and treat this line as its own block.
            if current:
                blocks.append("\n".join(current))
                current = []
            blocks.append(line)
            in_flow = True
            continue
        if re.match(r"^\s*-\s+name\s*:", line):
            if current:
                blocks.append("\n".join(current))
            current = [line]
            in_flow = False
            continue
        if current and not in_flow:
            current.append(line)
    if current:
        blocks.append("\n".join(current))
    result: list[ProxyConfig] = []
    for block in blocks:
        try:
            item = yaml.safe_load(block)
        except yaml.YAMLError:
            # Aggregators sometimes produce unbalanced quotes inside a value,
            # e.g. name: "FR-"2001:bc8:...:"-0055". Strip the inner quotes and
            # retry, so one malformed node does not cost us the whole source.
            try:
                item = yaml.safe_load(_repair_yaml_quotes(block))
            except yaml.YAMLError:
                continue
        if isinstance(item, list):
            item = item[0] if item and isinstance(item[0], dict) else None
        if isinstance(item, dict):
            parsed = _from_mapping(item)
            if parsed and _is_real_proxy(parsed):
                result.append(parsed)
    return result


def _repair_yaml_quotes(line: str) -> str:
    """Make a single-line flow mapping parseable despite aggregator quirks.

    Two defects are handled, both seen in the wild:
    - nested quotes inside a value, e.g. name: "FR-"2001:bc8:...:"-0055"
    - a scalar polluted with punctuation, e.g. port: 443?
    Only the inner quotes/punctuation are touched; the keys that matter for the
    subscription (server, port, uuid, password) stay intact.
    """
    repaired = re.sub(r'(:\s*)"([^"]*"[^"]*)"', r"\1\2", line)
    repaired = re.sub(r"(:\s*)([0-9]+)[^,}]*", r"\1\2", repaired)
    return repaired


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
    except json.JSONDecodeError as exc:
        # Malformed JSON (e.g. a truncated sing-box export) must not drop the
        # whole source: fall through to the YAML/URI recovery paths below,
        # matching the YAML partial-recovery behaviour.
        LOG.warning("Source is not valid JSON (%s); falling back to YAML/URI parsing", exc)
    result = _parse_yaml_proxies(text)
    if result:
        return result
    for line in text.splitlines():
        value = line.strip().strip('"\',')
        if not value:
            continue
        if _should_skip_value(value) or _is_placeholder_uri(value):
            continue
        if not re.match(r"^(?:vless|vmess|ss|trojan|hy2|hysteria2)://", value, re.IGNORECASE):
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
    repo_source = repo_source.removeprefix("https://github.com/")
    repo_source = repo_source.removeprefix("http://github.com/")
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
                # Python 3.11+ parses the trailing "Z" directly, so no manual
                # timezone replacement is needed here.
                commit_time = datetime.fromisoformat(date_value).astimezone(UTC)
            except ValueError:
                continue
            if datetime.now(UTC) - commit_time <= timedelta(days=freshness_days):
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
