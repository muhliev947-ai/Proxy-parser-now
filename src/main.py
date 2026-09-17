import argparse
import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

from src.checker.checker import CheckConfig, check_proxy
from src.generator.generators import to_clash, to_singbox
from src.parser.parser import parse_sources


def build(config_path: str = "config.yaml") -> int:
    config = yaml.safe_load(Path(config_path).read_text(encoding="utf-8"))
    proxies = parse_sources(config.get("sources", []))
    check = config.get("check", {})
    if check.get("enabled"):
        check_config = CheckConfig(check.get("timeout_seconds", 5), check.get("urls", []))
        with ThreadPoolExecutor(max_workers=check.get("concurrency", 32)) as pool:
            proxies = list(pool.map(lambda proxy: check_proxy(proxy, check_config), proxies))
    filters = config.get("types")
    countries = set(config.get("countries", []))
    protocols = set(config.get("protocols", []))
    minimum = config.get("min_speed_kbps", 0)
    proxies = [proxy for proxy in proxies if (not filters or proxy.type in filters)
               and (not countries or proxy.country in countries)
               and (not protocols or proxy.protocol in protocols)
               and (config.get("output", {}).get("include_unchecked", True) or proxy.available)
               and (proxy.speed_kbps is None or proxy.speed_kbps >= minimum)]
    output = Path(config.get("output", {}).get("directory", "output"))
    output.mkdir(parents=True, exist_ok=True)
    formats = config.get("output", {}).get("formats", ["clash", "singbox"])
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