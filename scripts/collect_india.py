"""One-off helper: collect every proxy of one country from the configured sources.

Reads the same `sources` list as the main pipeline, parses everything with
the project's own parser, geolocates the resolved server IPs via ip-api.com
batch endpoint and writes the requested country subset to `docs/subscription.txt`
in the same plain-text URI format the subscription already uses.

Not part of the pipeline: run manually when a single-country subscription is
needed.

    python scripts/collect_india.py [--config config.yaml] \
        [--out docs/subscription.txt] [--country IN] [--max-per-source 0]
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.parser.geolocation import DEFAULT_CACHE_PATH, annotate_countries
from src.parser.parser import _query_value, parse_sources, to_plaintext_uris

LOG = logging.getLogger("collect_india")


def _load_sources(config_path: str) -> list[str]:
    with open(config_path, encoding="utf-8") as handle:
        config = yaml.safe_load(handle) or {}
    sources = list(config.get("sources", []))
    fallback = config.get("fallback_file")
    if fallback:
        sources.append(fallback)
    return [source for source in sources if isinstance(source, str)]


def _recover_reality(proxy, raw_uri: str) -> None:
    """Restore REALITY keys and the original node name lost by parse_uri().

    Some aggregators put `pbk`/`sid` after the `#` fragment separator, so a URI
    like `...#name&pbk=KEY&sid=ID#tag` has urlparse() treat everything after the
    first `#` as the fragment. The project parser then drops those keys, and a
    REALITY node is published without them — the handshake cannot succeed.
    Nothing in the URI is invented here: the values are only moved back from the
    fragment into the query where they belong.
    """
    if proxy.reality:
        return
    fragment = urlparse(raw_uri).fragment or ""
    if "pbk=" not in fragment and "sid=" not in fragment:
        return
    pairs = parse_qs(fragment, keep_blank_values=True)
    public_key = _query_value(pairs, "pbk")
    short_id = _query_value(pairs, "sid")
    if public_key or short_id:
        proxy.reality = {"public_key": public_key, "short_id": short_id}


def _recover_name(proxy, raw_uri: str) -> None:
    """Keep the aggregator's node name instead of the generated `type-server:port`."""
    fragment = urlparse(raw_uri).fragment or ""
    if not fragment:
        return
    # The useful name is the tail of a double-fragment URI (`#name&pbk=...#tag`)
    # or the whole fragment otherwise, minus any recovered REALITY parameters.
    tail = fragment.rsplit("#", 1)[-1]
    for marker in ("pbk=", "sid="):
        tail = tail.split(marker)[0]
    tail = tail.rstrip("&@").strip()
    if tail:
        proxy.name = unquote(tail)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--out", default="docs/subscription.txt")
    parser.add_argument("--country", default="IN", help="ISO country code to keep")
    parser.add_argument("--max-per-source", type=int, default=0, help="0 = no cap")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    sources = _load_sources(args.config)
    LOG.info("Loaded %d sources from %s", len(sources), args.config)

    proxies = parse_sources(sources, timeout=30, freshness_days=0)
    LOG.info("Parsed %d unique proxies", len(proxies))

    annotate_countries(proxies, cache_path=DEFAULT_CACHE_PATH)

    found = []
    seen = set()
    per_source: dict[str, int] = {}
    for proxy in proxies:
        if (proxy.country or "").upper() != args.country.upper():
            continue
        key = (proxy.type, proxy.server, proxy.port)
        if key in seen:
            continue
        seen.add(key)
        if args.max_per_source and per_source.get(proxy.source, 0) >= args.max_per_source:
            continue
        per_source[proxy.source] = per_source.get(proxy.source, 0) + 1
        # parse_uri() drops REALITY keys and node names that some aggregators
        # place after the `#` fragment separator; restore them here so the
        # published URI can actually complete a handshake.
        raw_uri = str(proxy.raw.get("raw_uri") or "")
        if raw_uri:
            _recover_reality(proxy, raw_uri)
            _recover_name(proxy, raw_uri)
        found.append(proxy)

    LOG.info("Found %d %s proxies", len(found), args.country)
    for source, count in sorted(per_source.items(), key=lambda item: -item[1]):
        LOG.info("  %3d  %s", count, source)

    uris = to_plaintext_uris(found)
    LOG.info("Rendered %d URIs", len(uris))
    with open(args.out, "w", encoding="utf-8") as handle:
        handle.writelines(uri + "\n" for uri in uris)
    LOG.info("Wrote %s", args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
