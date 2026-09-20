import argparse
import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

from src.checker.checker import CheckConfig, check_proxy, load_hiddify_tags
from src.generator.generators import sort_by_latency, to_clash, to_singbox
from src.parser.model import ProxyConfig
from src.parser.parser import parse_sources, to_plaintext_uris

LOG = logging.getLogger(__name__)


def _build_check_config(check: dict) -> CheckConfig:
    return CheckConfig(
        check.get("timeout_seconds", 5),
        check.get("urls", []),
        check.get("clash_api_url"),
        check.get("clash_api_secret"),
        check.get("concurrency", 8),
        check.get("expected_status", 204),
        check.get("socks_proxy_url"),
    )


def _passes_static_filters(proxy: ProxyConfig, config: dict) -> bool:
    """Type/country/protocol filters, evaluated before any network check.

    Applying them up front keeps the verification budget for nodes that can
    actually end up in the subscription.
    """
    allowed_types = config.get("types")
    countries = set(config.get("countries", []))
    protocols = set(config.get("protocols", []))
    return (
        (not allowed_types or proxy.type in allowed_types)
        and (not countries or proxy.country in countries)
        and (not protocols or proxy.protocol in protocols)
    )


def _passes_final_filters(proxy: ProxyConfig, config: dict) -> bool:
    if not _passes_static_filters(proxy, config):
        return False
    minimum = config.get("min_speed_kbps", 0)
    return (
        (config.get("output", {}).get("include_unchecked", True) or proxy.verified)
        and (proxy.speed_kbps is None or proxy.speed_kbps >= minimum)
    )


def _check_proxies(proxies: list[ProxyConfig], check_config: CheckConfig) -> list[ProxyConfig]:
    with ThreadPoolExecutor(max_workers=check_config.concurrency) as pool:
        return list(pool.map(lambda proxy: check_proxy(proxy, check_config), proxies))


def _check_with_pool(candidates: list[ProxyConfig], check_config: CheckConfig, check: dict) -> list[ProxyConfig]:
    """Verify candidates, growing the pool until enough nodes are confirmed.

    Free proxies die within hours, so a single verified node is a fragile
    subscription. When ``min_working_nodes`` is set, checking does not stop at
    the first batch: additional batches are verified until the target pool size
    is reached or the candidates run out. ``max_total_candidates`` caps the
    total work so a dead network cannot stall the run indefinitely.
    """
    max_candidates = int(check.get("max_candidates", 500))
    min_working = int(check.get("min_working_nodes", 0))
    max_total = int(check.get("max_total_candidates", 0)) or max_candidates * 4
    remaining = candidates[:max_total]
    if min_working <= 0:
        return _check_proxies(remaining[:max_candidates], check_config)

    checked: list[ProxyConfig] = []
    batch_size = max(check_config.concurrency * 4, min_working)
    while remaining:
        batch, remaining = remaining[:batch_size], remaining[batch_size:]
        checked.extend(_check_proxies(batch, check_config))
        verified = sum(1 for proxy in checked if proxy.verified)
        LOG.info("Verified %d of %d checked nodes", verified, len(checked))
        if verified >= min_working:
            break
    return checked


def _reverify_before_publish(proxies: list[ProxyConfig], check_config: CheckConfig, check: dict) -> list[ProxyConfig]:
    """Re-run the real handshake on the top nodes right before writing.

    Time passes between the main verification pass and the moment the
    subscription is published, and a node that was alive a minute ago may
    already be dead. Re-checking the fastest nodes as the last step keeps a
    stale node out of the subscription; the survivors keep their fresh
    latency measurements.
    """
    top_n = int(check.get("reverify_top_n", 10))
    if top_n <= 0 or not proxies:
        return proxies
    top, rest = proxies[:top_n], proxies[top_n:]
    rechecked = _check_proxies(top, check_config)
    for proxy in rechecked:
        if not proxy.verified:
            LOG.warning("Node %s:%d died before publication, dropping it", proxy.server, proxy.port)
    return [proxy for proxy in rechecked if proxy.verified] + rest


def build(config_path: str = "config.yaml") -> int:
    config = yaml.safe_load(Path(config_path).read_text(encoding="utf-8"))
    freshness_days = int(config.get("freshness_days", 7))
    fallback_file = config.get("fallback_file")
    proxies = parse_sources(config.get("sources", []), freshness_days=freshness_days, fallback_file=fallback_file)
    output = Path(config.get("output", {}).get("directory", "output"))
    output.mkdir(parents=True, exist_ok=True)
    docs = Path("docs")
    docs.mkdir(parents=True, exist_ok=True)
    (output / "subscription.txt").write_text("", encoding="utf-8")
    (docs / "subscription.txt").write_text("", encoding="utf-8")
    check = config.get("check", {})
    check_config = _build_check_config(check) if check.get("enabled") else None
    if check_config and check_config.clash_api_url:
        load_hiddify_tags()
    # Static filters run first so the verification budget is spent only on
    # candidates that can actually be published.
    candidates = [proxy for proxy in proxies if _passes_static_filters(proxy, config)]
    if check_config:
        candidates = _check_with_pool(candidates, check_config, check)
    proxies = [proxy for proxy in candidates if _passes_final_filters(proxy, config)]
    if config.get("output", {}).get("sort_by_latency"):
        proxies = sort_by_latency(proxies)
        LOG.info("Sorted %d proxies by latency", len(proxies))
    if check_config and check.get("reverify_before_publish", True):
        proxies = _reverify_before_publish(proxies, check_config, check)
        proxies = [proxy for proxy in proxies if _passes_final_filters(proxy, config)]
        if config.get("output", {}).get("sort_by_latency"):
            proxies = sort_by_latency(proxies)
    LOG.info("Publishing %d verified proxies", len([p for p in proxies if p.verified]))
    formats = config.get("output", {}).get("formats", ["plaintext"])
    if "plaintext" in formats:
        lines = to_plaintext_uris(proxies)
        (output / "subscription.txt").write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        if not lines:
            LOG.warning("No valid encrypted proxy URIs found")
        (docs / "subscription.txt").write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    if "clash" in formats:
        (output / "subscription.yaml").write_text(to_clash(proxies), encoding="utf-8")
    if "singbox" in formats:
        (output / "subscription.json").write_text(to_singbox(proxies), encoding="utf-8")
    LOG.info("Wrote %d proxies to %s", len(proxies), output)
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
