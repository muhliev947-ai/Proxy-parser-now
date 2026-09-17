import base64
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse
from urllib.request import Request, urlopen

import yaml

from .model import ProxyConfig

LOG = logging.getLogger(__name__)
SUPPORTED = {"vless", "vmess", "trojan", "ss", "shadowsocks", "hy2", "hysteria2"}


def _query_value(query: dict[str, list[str]], key: str) -> str | None:
    return query.get(key, [None])[0]


def parse_uri(value: str) -> ProxyConfig | None:
    parsed = urlparse(value.strip())
    scheme = parsed.scheme.lower()
    if scheme not in SUPPORTED:
        return None
    query = parse_qs(parsed.query)
    params = {key: unquote(values[0]) for key, values in query.items() if values}
    user = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    if scheme == "vmess":
        try:
            decoded = base64.b64decode(value.split("://", 1)[1] + "===").decode()
            return _from_mapping(json.loads(decoded), "vmess")
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            return None
    if scheme in {"ss", "shadowsocks"} and not parsed.hostname:
        try:
            decoded = base64.b64decode(parsed.netloc + "===").decode()
            user, hostport = decoded.rsplit("@", 1)
            method, password = user.split(":", 1)
            host, port = hostport.rsplit(":", 1)
            return ProxyConfig(scheme, host, int(port), method=method, password=password,
                               name=params.get("remarks", ""))
        except (ValueError, UnicodeDecodeError):
            return None
    if not parsed.hostname or not parsed.port:
        return None
    config = ProxyConfig(
        scheme, parsed.hostname, parsed.port, name=params.get("remarks", parsed.hostname),
        uuid=user if scheme in {"vless", "vmess"} else None,
        password=password or (user if scheme in {"trojan", "hy2"} else None),
        method=params.get("method"), tls=params.get("security", "").lower() in {"tls", "reality"} or scheme == "trojan",
        flow=params.get("flow"), sni=params.get("sni") or params.get("peer"),
        network=params.get("type") or params.get("network"), path=params.get("path"),
        host=params.get("host"), service_name=params.get("serviceName"),
        reality={"public_key": params.get("pbk"), "short_id": params.get("sid")} if params.get("pbk") else None,
        raw=params,
    )
    return config


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
            if parsed:
                result.append(parsed)
        if result:
            return result
    except json.JSONDecodeError:
        pass
    try:
        document = yaml.safe_load(text)
        for item in document.get("proxies", []) if isinstance(document, dict) else []:
            parsed = _from_mapping(item)
            if parsed:
                result.append(parsed)
        if result:
            return result
    except yaml.YAMLError as exc:
        LOG.debug("Not YAML: %s", exc)
    for line in text.splitlines():
        parsed = parse_uri(line.strip().strip('"\','))
        if parsed:
            result.append(parsed)
    return result


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


def parse_sources(sources: list[str], timeout: int = 15, freshness_days: int = 7) -> list[ProxyConfig]:
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
    unique: dict[tuple[str, str, int], ProxyConfig] = {}
    for proxy in result:
        unique[(proxy.type, proxy.server, proxy.port)] = proxy
    return list(unique.values())