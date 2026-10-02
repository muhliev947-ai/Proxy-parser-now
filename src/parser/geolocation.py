"""Server geolocation: map proxy hosts to ISO country codes.

The pipeline uses this to exclude nodes by country (e.g. never publish
Russian servers) without relying on the node names aggregators invent,
which are frequently wrong or missing entirely.

Two layers, cheapest first:

1. ``country_from_name`` — free, instant, offline. Aggregators tag node
   names with flags / country codes / city names ("🇮🇳IN_12", "荷兰_100111200",
   "US-1.2.3.4"). Only used as a *hint*: a name that mentions a country is
   normally right, but an uninformative name ("EPODONIOS") says nothing.
2. ``annotate_countries`` — authoritative. Resolves every host to an IP and
   looks the IP up via the ip-api.com batch endpoint (45 req/min free tier),
   with an on-disk cache so repeat runs cost nothing.

The name hint is applied *before* the network lookup and only when it yields
a definite country, so a node whose name clearly says "🇷🇺" is dropped even
when the network is unreachable.
"""

from __future__ import annotations

import json
import logging
import re
import socket
import time
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

LOG = logging.getLogger(__name__)

IPAPI_BATCH = "http://ip-api.com/batch"
IPAPI_FIELDS = "status,countryCode,query"
BATCH_LIMIT = 100
# ip-api.com free tier allows ~45 requests/minute; staying below that avoids
# the HTTP 429 / connection-reset storms that drop whole batches.
BATCH_PAUSE_SECONDS = 1.6
MAX_RETRIES = 6

DEFAULT_CACHE_PATH = "output/geolocation_cache.json"

# Flag emoji are two REGIONAL INDICATOR code points; the letter pair is what
# actually identifies the country, so both spellings are matched.
_FLAG_PAIR = "".join(chr(code) for code in range(0x1F1E6, 0x1F1FF + 1))
_FLAG_RE = re.compile(f"[{_FLAG_PAIR}]{{2}}")

# Explicit ISO-3166-1 alpha-2 codes in the name ("IN_12", "US-1.2.3.4").
_CODE_RE = re.compile(r"(?<![A-Za-z0-9])([A-Z]{2})(?![A-Za-z0-9])")

# Common full country/region names seen in aggregator node names. Only entries
# that are unambiguous in a proxy context are included.
_COUNTRY_NAMES: dict[str, str] = {
    # English country and city names.
    "russia": "RU", "moscow": "RU", "saint petersburg": "RU",
    "netherlands": "NL", "amsterdam": "NL", "holland": "NL",
    "germany": "DE", "frankfurt": "DE", "berlin": "DE",
    "united states": "US", "america": "US",
    "united kingdom": "GB", "london": "GB", "britain": "GB",
    "france": "FR", "paris": "FR",
    "singapore": "SG",
    "japan": "JP", "tokyo": "JP",
    "hong kong": "HK", "hongkong": "HK",
    "turkey": "TR", "istanbul": "TR",
    "india": "IN", "mumbai": "IN", "delhi": "IN",
    "canada": "CA", "toronto": "CA",
    "australia": "AU", "sydney": "AU",
    "sweden": "SE", "stockholm": "SE",
    "finland": "FI", "helsinki": "FI",
    "poland": "PL", "warsaw": "PL",
    "ukraine": "UA", "kyiv": "UA", "kiev": "UA",
    "china": "CN", "shanghai": "CN", "beijing": "CN",
    "south korea": "KR", "korea": "KR", "seoul": "KR",
    "brazil": "BR", "sao paulo": "BR",
    "spain": "ES", "madrid": "ES",
    "italy": "IT", "milan": "IT", "rome": "IT",
    "austria": "AT", "vienna": "AT",
    "switzerland": "CH", "zurich": "CH",
    "ireland": "IE", "dublin": "IE",
    "luxembourg": "LU",
    "norway": "NO", "oslo": "NO",
    "denmark": "DK", "copenhagen": "DK",
    "belgium": "BE", "brussels": "BE",
    "czech": "CZ", "prague": "CZ",
    "romania": "RO", "bucharest": "RO",
    "bulgaria": "BG", "sofia": "BG",
    "serbia": "RS", "belgrade": "RS",
    "moldova": "MD", "chisinau": "MD",
    "kazakhstan": "KZ", "almaty": "KZ",
    "united arab emirates": "AE", "dubai": "AE",
    "israel": "IL", "tel aviv": "IL",
    "egypt": "EG", "cairo": "EG",
    "south africa": "ZA", "johannesburg": "ZA",
    "argentina": "AR", "buenos aires": "AR",
    "mexico": "MX", "chile": "CL", "colombia": "CO",
    "indonesia": "ID", "jakarta": "ID",
    "malaysia": "MY", "kuala lumpur": "MY",
    "thailand": "TH", "bangkok": "TH",
    "vietnam": "VN", "hanoi": "VN",
    "philippines": "PH", "manila": "PH",
    "taiwan": "TW", "taipei": "TW",
    "bangladesh": "BD", "dhaka": "BD",
    "pakistan": "PK", "karachi": "PK", "lahore": "PK",
    "sri lanka": "LK", "colombo": "LK",
    "nepal": "NP", "kathmandu": "NP",
    "georgia": "GE", "tbilisi": "GE",
    "armenia": "AM", "yerevan": "AM",
    "azerbaijan": "AZ", "baku": "AZ",
    "uzbekistan": "UZ", "tashkent": "UZ",
    "kyrgyzstan": "KG", "bishkek": "KG",
    "tajikistan": "TJ", "dushanbe": "TJ",
    "turkmenistan": "TM", "ashgabat": "TM",
    "belarus": "BY", "minsk": "BY",
    "latvia": "LV", "riga": "LV",
    "lithuania": "LT", "vilnius": "LT",
    "estonia": "EE", "tallinn": "EE",
    "iceland": "IS", "reykjavik": "IS",
    "portugal": "PT", "lisbon": "PT",
    "greece": "GR", "athens": "GR",
    "hungary": "HU", "budapest": "HU",
    "slovakia": "SK", "bratislava": "SK",
    "croatia": "HR", "slovenia": "SI", "bosnia": "BA", "albania": "AL",
    "north macedonia": "MK", "montenegro": "ME", "kosovo": "XK",
    "malta": "MT", "cyprus": "CY", "gibraltar": "GI",
    "andorra": "AD", "monaco": "MC", "san marino": "SM", "liechtenstein": "LI",
    "faroe islands": "FO", "greenland": "GL",
    "mongolia": "MN", "cambodia": "KH", "myanmar": "MM",
    "saudi arabia": "SA", "riyadh": "SA",
    "qatar": "QA", "doha": "QA",
    "kuwait": "KW", "bahrain": "BH", "oman": "OM",
    "jordan": "JO", "amman": "JO",
    "lebanon": "LB", "beirut": "LB",
    "iraq": "IQ", "baghdad": "IQ",
    "iran": "IR", "tehran": "IR",
    "afghanistan": "AF", "kabul": "AF",
    "nigeria": "NG", "lagos": "NG",
    "kenya": "KE", "nairobi": "KE",
    "ghana": "GH", "accra": "GH",
    "morocco": "MA", "casablanca": "MA",
    "algeria": "DZ", "tunisia": "TN", "libya": "LY",
    "ethiopia": "ET", "addis ababa": "ET",
    "tanzania": "TZ", "uganda": "UG", "zimbabwe": "ZW", "botswana": "BW",
    "namibia": "NA", "angola": "AO", "mozambique": "MZ", "senegal": "SN",
    "ivory coast": "CI", "cameroon": "CM",
    # Localised names used by Chinese aggregators (v2rayN-style node names).
    # These are the labels actually seen in the wild, e.g. "荷兰_100111200".
    "俄罗斯": "RU", "俄国": "RU", "莫斯科": "RU",
    "荷兰": "NL", "阿姆斯特丹": "NL",
    "德国": "DE", "法兰克福": "DE",
    "美国": "US", "美利坚": "US", "洛杉矶": "US", "圣何塞": "US", "西雅图": "US",
    "英国": "GB", "伦敦": "GB",
    "法国": "FR", "巴黎": "FR",
    "新加坡": "SG", "狮城": "SG",
    "日本": "JP", "东京": "JP", "大阪": "JP",
    "香港": "HK", "台湾": "TW", "台北": "TW",
    "土耳其": "TR", "伊斯坦布尔": "TR",
    "印度": "IN", "孟买": "IN", "德里": "IN",
    "加拿大": "CA", "多伦多": "CA", "温哥华": "CA",
    "澳大利亚": "AU", "悉尼": "AU",
    "瑞典": "SE", "芬兰": "FI", "波兰": "PL", "华沙": "PL",
    "乌克兰": "UA", "基辅": "UA",
    "中国": "CN", "上海": "CN", "北京": "CN", "广州": "CN",
    "韩国": "KR", "首尔": "KR",
    "巴西": "BR", "西班牙": "ES", "马德里": "ES",
    "意大利": "IT", "米兰": "IT", "罗马": "IT",
    "奥地利": "AT", "维也纳": "AT",
    "瑞士": "CH", "苏黎世": "CH",
    "爱尔兰": "IE", "都柏林": "IE",
    "卢森堡": "LU", "挪威": "NO", "丹麦": "DK", "比利时": "BE",
    "捷克": "CZ", "布拉格": "CZ",
    "罗马尼亚": "RO", "保加利亚": "BG", "塞尔维亚": "RS",
    "摩尔多瓦": "MD", "哈萨克斯坦": "KZ",
    "阿联酋": "AE", "迪拜": "AE",
    "以色列": "IL", "埃及": "EG",
    "南非": "ZA", "阿根廷": "AR", "墨西哥": "MX", "智利": "CL", "哥伦比亚": "CO",
    "印尼": "ID", "雅加达": "ID", "马来西亚": "MY", "泰国": "TH", "曼谷": "TH",
    "越南": "VN", "菲律宾": "PH", "孟加拉": "BD", "巴基斯坦": "PK",
    "尼泊尔": "NP", "格鲁吉亚": "GE", "亚美尼亚": "AM", "阿塞拜疆": "AZ",
    "乌兹别克斯坦": "UZ", "白俄罗斯": "BY", "拉脱维亚": "LV",
    "立陶宛": "LT", "爱沙尼亚": "EE", "冰岛": "IS",
    "葡萄牙": "PT", "希腊": "GR", "雅典": "GR", "匈牙利": "HU", "布达佩斯": "HU",
    "斯洛伐克": "SK", "克罗地亚": "HR", "斯洛文尼亚": "SI",
    "马耳他": "MT", "塞浦路斯": "CY",
    "蒙古": "MN", "柬埔寨": "KH", "缅甸": "MM",
    "沙特": "SA", "卡塔尔": "QA", "科威特": "KW", "巴林": "BH", "阿曼": "OM",
    "约旦": "JO", "黎巴嫩": "LB", "伊拉克": "IQ", "伊朗": "IR", "阿富汗": "AF",
    "尼日利亚": "NG", "肯尼亚": "KE", "加纳": "GH", "摩洛哥": "MA",
    "阿尔及利亚": "DZ", "突尼斯": "TN", "埃塞俄比亚": "ET", "坦桑尼亚": "TZ",
    "乌干达": "UG", "津巴布韦": "ZW", "纳米比亚": "NA", "安哥拉": "AO",
    "塞内加尔": "SN", "喀麦隆": "CM",
}

# Two-letter tokens that are ambiguous or are common words in node names and
# must therefore never be read as country codes.
_AMBIGUOUS_CODES = {
    "AT", "BE", "BY", "CC", "CH", "CI", "CM", "DE", "DO", "EH", "FM", "GB",
    "GR", "GT", "HK", "ID", "IE", "IN", "IS", "IT", "LA", "LI", "LT", "LV",
    "MA", "MC", "MD", "MK", "MT", "MX", "NO", "NP", "PE", "RU", "SM", "SO",
    "SR", "ST", "SZ", "TJ", "TM", "TO", "TV", "UA", "US", "UZ", "VA", "VG",
    "VI", "VN", "WS", "YE", "ZA",
}


# Tokens that match a country name but are common English words or name
# fragments, and must therefore never be read as a country on their own.
_AMBIGUOUS_NAMES = {"us", "uk", "in", "is", "no", "so", "to", "or", "by", "at", "do"}


def _name_matches(phrase: str, lowered: str) -> bool:
    """Whether *phrase* appears in *lowered* as a real word, not a substring.

    "in" inside "Frankfurt" is not India; "in" as a standalone token is.
    """
    if not phrase:
        return False
    if phrase in _AMBIGUOUS_NAMES:
        # Require word boundaries on both sides so the token is genuinely
        # standalone and not a fragment of a longer word.
        return re.search(rf"(?<![a-z0-9]){re.escape(phrase)}(?![a-z0-9])", lowered) is not None
    return phrase in lowered


def _flag_to_code(text: str) -> str | None:
    """Convert a flag emoji pair to an ISO code ("🇷🇺" -> "RU")."""
    for match in _FLAG_RE.finditer(text):
        pair = match.group(0)
        code = "".join(
            chr(ord(char) - 0x1F1E6 + ord("A"))
            for char in pair
        )
        if len(code) == 2 and code.isalpha():
            return code
    return None


def country_from_name(name: str | None) -> str | None:
    """Best-effort ISO country code from a node name; None if it says nothing.

    Only a *positive* identification is returned. A name like "EPODONIOS" or
    "server1" carries no country information, so it yields None rather than a
    guess — the network lookup then decides.
    """
    if not name:
        return None
    text = str(name).strip()
    if not text:
        return None

    # Flag emoji are the strongest signal: aggregators add them precisely to
    # label the node's country, and they encode nothing else.
    flag_code = _flag_to_code(text)
    if flag_code:
        return flag_code

    lowered = text.lower()

    # Full country / city names, longest first so "united kingdom" wins over "uk".
    for phrase, code in sorted(_COUNTRY_NAMES.items(), key=lambda item: -len(item[0])):
        if _name_matches(phrase, lowered):
            return code

    # Bare two-letter codes, but only the unambiguous ones: "DE" is Germany,
    # "IN" is India, yet both are also ordinary substrings of other tokens.
    for match in _CODE_RE.finditer(text):
        code = match.group(1)
        if code not in _AMBIGUOUS_CODES:
            return code

    return None


def resolve_host(host: str) -> str | None:
    """Resolve a hostname to an IPv4 address; IPs pass through unchanged."""
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def proxy_host(proxy) -> str | None:
    """The hostname to geolocate for a proxy (bracketed IPv6 aware)."""
    server = (getattr(proxy, "server", "") or "").strip()
    if not server:
        return None
    return urlparse(f"//{server}").hostname or server


def load_cache(path: str = DEFAULT_CACHE_PATH) -> dict[str, str]:
    """Read the on-disk IP -> country cache; a missing/corrupt file is empty."""
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    return {str(key): str(value) for key, value in data.items() if isinstance(data, dict)}


def save_cache(cache: dict[str, str], path: str = DEFAULT_CACHE_PATH) -> None:
    """Write the IP -> country cache for the next run."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(cache, handle, indent=2, sort_keys=True)


def _post_batch(chunk: list[str]) -> dict[str, str] | None:
    """POST one ip-api batch with exponential backoff; None if all retries fail."""
    payload = json.dumps([{"query": ip, "fields": IPAPI_FIELDS} for ip in chunk]).encode()
    for attempt in range(MAX_RETRIES):
        request = Request(IPAPI_BATCH, data=payload, headers={"Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=45) as response:
                rows = json.loads(response.read().decode("utf-8", errors="replace"))
            if isinstance(rows, list):
                return {
                    str(row.get("query")): str(row.get("countryCode") or "").upper()
                    for row in rows
                    if isinstance(row, dict) and row.get("status") == "success"
                }
        except OSError as exc:
            # 429 and connection resets are transient under rate limiting; the
            # backoff below is what makes a full sweep possible at all.
            LOG.debug("ip-api batch attempt %d/%d failed: %s", attempt + 1, MAX_RETRIES, exc)
        except ValueError as exc:
            LOG.debug("ip-api batch attempt %d/%d bad payload: %s", attempt + 1, MAX_RETRIES, exc)
        # Exponential backoff: 2s, 4s, 8s, 16s, 32s — long enough to clear the
        # per-minute rate window before the next retry.
        time.sleep(2 ** (attempt + 1))
    return None


def geolocate_ips(
    ips: list[str],
    cache_path: str = DEFAULT_CACHE_PATH,
) -> dict[str, str]:
    """Map IP addresses to ISO country codes, caching results on disk.

    Hostnames must be resolved first (see :func:`resolve_host`): ip-api's batch
    endpoint rejects names and reports them as failures.
    """
    unique_ips = sorted({ip for ip in ips if ip})
    if not unique_ips:
        return {}

    cache = load_cache(cache_path)
    codes: dict[str, str] = {ip: code for ip, code in cache.items() if ip in unique_ips}
    pending = sorted(set(unique_ips) - set(codes))
    LOG.info(
        "Geolocating %d IPs (%d cached, %d pending)",
        len(unique_ips), len(unique_ips) - len(pending), len(pending),
    )

    total_batches = -(-len(pending) // BATCH_LIMIT)
    for index, start in enumerate(range(0, len(pending), BATCH_LIMIT), start=1):
        chunk = pending[start : start + BATCH_LIMIT]
        result = _post_batch(chunk)
        if result is None:
            LOG.warning(
                "ip-api batch %d/%d failed after %d retries", index, total_batches, MAX_RETRIES,
            )
            continue
        codes.update(result)
        cache.update(result)
        if index % 10 == 0:
            save_cache(cache, cache_path)
            LOG.info("  progress: %d/%d IPs", start + len(chunk), len(pending))
        time.sleep(BATCH_PAUSE_SECONDS)

    save_cache(cache, cache_path)
    return codes


def annotate_countries(
    proxies: list,
    cache_path: str = DEFAULT_CACHE_PATH,
) -> None:
    """Set ``proxy.country`` on every proxy, in place.

    The name hint is applied first so that nodes whose name identifies a
    country are labelled even when the network is unreachable; the IP lookup
    then fills in the rest and overrides a name that disagrees with the
    actual server location.
    """
    for proxy in proxies:
        if not getattr(proxy, "country", None):
            proxy.country = country_from_name(getattr(proxy, "name", None))

    hosts = sorted({host for host in (proxy_host(p) for p in proxies) if host})
    if not hosts:
        return

    resolved: dict[str, str | None] = {host: resolve_host(host) for host in hosts}
    ips = sorted({ip for ip in resolved.values() if ip})
    if not ips:
        LOG.warning("Could not resolve any server host; country filter uses name hints only")
        return

    ip_country = geolocate_ips(ips, cache_path=cache_path)
    for proxy in proxies:
        host = proxy_host(proxy)
        ip = host and resolved.get(host)
        code = ip and ip_country.get(ip)
        if code:
            proxy.country = code
