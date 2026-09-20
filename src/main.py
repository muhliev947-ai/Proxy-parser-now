import argparse
import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

from src.checker.checker import CheckConfig, check_proxy, load_hiddify_tags
from src.generator.generators import sort_by_latency, to_clash, to_singbox
from src.parser.parser import parse_sources, to_plaintext_uris


def build(config_path: str = "config.yaml") -> int:
    config = yaml.safe_load(Path(config_path).read_text(encoding="utf-8"))
    freshness_days = int(config.get("freshness_days", 7))
    fallback_file = config.get("fallback_file")
    proxies = parse_sources(config.get("sources", []), freshness_days=freshness_days, fallback_file=fallback_file)
    max_candidates = int(config.get("check", {}).get("max_candidates", 500))
    if max_candidates > 0:
        proxies = proxies[:max_candidates]
        logging.info("Checking up to %d candidates", len(proxies))
    output = Path(config.get("output", {}).get("directory", "output"))
    output.mkdir(parents=True, exist_ok=True)
    docs = Path("docs")
    docs.mkdir(parents=True, exist_ok=True)
    (output / "subscription.txt").write_text("", encoding="utf-8")
    (docs / "subscription.txt").write_text("", encoding="utf-8")
    check = config.get("check", {})
    if check.get("enabled"):
        check_config = CheckConfig(
            check.get("timeout_seconds", 5),
            check.get("urls", []),
            check.get("clash_api_url"),
            check.get("clash_api_secret"),
            check.get("concurrency", 8),
            check.get("expected_status", 204),
            check.get("socks_proxy_url"),
        )
        if check_config.clash_api_url:
            load_hiddify_tags()
        with ThreadPoolExecutor(max_workers=check_config.concurrency) as pool:
            proxies = list(pool.map(lambda proxy: check_proxy(proxy, check_config), proxies))
    filters = config.get("types")
    countries = set(config.get("countries", []))
    protocols = set(config.get("protocols", []))
    minimum = config.get("min_speed_kbps", 0)
    proxies = [proxy for proxy in proxies if (not filters or proxy.type in filters)
               and (not countries or proxy.country in countries)
               and (not protocols or proxy.protocol in protocols)
               and (config.get("output", {}).get("include_unchecked", True) or proxy.verified)
               and (proxy.speed_kbps is None or proxy.speed_kbps >= minimum)]
    formats = config.get("output", {}).get("formats", ["plaintext"])
    if config.get("output", {}).get("sort_by_latency"):
        proxies = sort_by_latency(proxies)
        logging.info("Sorted %d proxies by latency", len(proxies))
    if "plaintext" in formats:
        lines = to_plaintext_uris(proxies)
        (output / "subscription.txt").write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        if not lines:
            logging.warning("No valid encrypted proxy URIs found")
        (docs / "subscription.txt").write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    if "clash" in formats:
        (output / "subscription.yaml").write_text(to_clash(proxies), encoding="utf-8")
    if "singbox" in formats:
        (output / "subscription.json").write_text(to_singbox(proxies), encoding="utf-8")
    logging.info("Wrote %d proxies to %s", len(proxies), output)
    return len(proxies)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    build(args.config)


if __name__ == "__main__":
    main()