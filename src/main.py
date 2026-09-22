"""Run the full parsing, checking and generation pipeline.

Uses a locally running Hiddify (sing-box) instance for proxy verification.
For CI without Hiddify, use :mod:`src.checker.launch_singbox` instead.

All pipeline logic (parsing, filtering, pool growth, re-verify, publication
guard) lives in :mod:`src.checker.pipeline`; this module is a thin wrapper.
"""

from __future__ import annotations

import argparse
import logging
import sys

import yaml

from src.checker.checker import check_proxy
from src.checker.pipeline import HiddifyBackend

# Re-export the pipeline entry point under the historical name.
from src.checker.pipeline import build as _pipeline_build

LOG = logging.getLogger(__name__)


def _build_check_config(check: dict):
    """Backward-compatible alias for HiddifyBackend config construction."""
    from src.checker.checker import CheckConfig
    return CheckConfig(
        check.get("timeout_seconds", 5),
        check.get("urls", []),
        check.get("clash_api_url"),
        check.get("clash_api_secret"),
        check.get("concurrency", 8),
        check.get("expected_status", 204),
        check.get("socks_proxy_url"),
    )


def _check_proxies(proxies, check_config):
    """Backward-compatible stub: verify *proxies* with *check_config*."""
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=check_config.concurrency) as pool:
        return list(pool.map(lambda p: check_proxy(p, check_config), proxies))


def _install_redact_filter() -> None:
    """Redact credentials from all log records in both entry points."""
    from src.checker.pipeline import LOG as _pipeline_log
    from src.checker.pipeline import _RedactFilter
    for logger in (logging.getLogger(), _pipeline_log):
        if not any(isinstance(f, _RedactFilter) for f in logger.filters):
            logger.addFilter(_RedactFilter())


def _build(config_path: str = "config.yaml") -> int:
    """Run the pipeline with a Hiddify backend."""
    with open(config_path, encoding="utf-8") as f:
        config = yaml.safe_load(f)
    check_cfg = config.get("check", {})
    if not check_cfg.get("enabled", True):
        LOG.info("Checking is disabled in config; running without verification")

    backend = HiddifyBackend(check_cfg)
    return _pipeline_build(config_path=config_path, backend=backend)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build proxy subscriptions.")
    parser.add_argument("--config", default="config.yaml", help="Path to the config file")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    _install_redact_filter()
    try:
        count = _build(args.config)
    except FileNotFoundError as exc:
        LOG.error("Config or source not found: %s", exc)
        return 1
    except RuntimeError as exc:
        LOG.error("Build failed: %s", exc)
        return 1
    LOG.info("Built subscription with %d proxies", count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
