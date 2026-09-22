"""Local sing-box check path for CI.

Runs a standalone sing-box process on the CI runner (no Hiddify instance)
and verifies proxies through one dedicated mixed inbound per candidate,
so all nodes in a batch are checked in parallel without switching the
global proxy.

Usage::

    python -m src.checker.launch_singbox --config config.yaml \
        --singbox ./sing-box --wait 30 [--verbose]

The pipeline logic (parsing, filtering, pool growth, re-verify, publication
guard) is shared with the Hiddify backend via :mod:`src.checker.pipeline`.
"""

from __future__ import annotations

import argparse
import logging
import sys

from src.checker.pipeline import LocalSingBoxBackend, build

LOG = logging.getLogger(__name__)


def launch_singbox(
    config_path: str = "config.yaml",
    binary: str = "./sing-box",
    wait_seconds: float = 30.0,
) -> int:
    """Run the full build pipeline with a local sing-box backend.

    Returns the number of proxies written to the subscription.
    """
    import yaml

    with open(config_path, encoding="utf-8") as f:
        config = yaml.safe_load(f)
    singbox_cfg = config.get("check", {}).get("singbox", {})
    check_cfg = config.get("check", {})

    backend = LocalSingBoxBackend(
        check=check_cfg,
        binary=singbox_cfg.get("binary", binary),
        wait_seconds=float(singbox_cfg.get("wait_seconds", wait_seconds)),
    )
    return build(config_path=config_path, backend=backend)


def _install_redact_filter() -> None:
    """Redact credentials from all log records (shared with src.main)."""
    from src.checker.pipeline import LOG as _pipeline_log
    from src.checker.pipeline import _RedactFilter
    for logger in (logging.getLogger(), _pipeline_log):
        if not any(isinstance(f, _RedactFilter) for f in logger.filters):
            logger.addFilter(_RedactFilter())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build subscriptions via local sing-box.")
    parser.add_argument("--config", default="config.yaml", help="Path to config file")
    parser.add_argument("--singbox", default="./sing-box", help="Path to the sing-box binary")
    parser.add_argument("--wait", type=float, default=30.0, help="Seconds to wait for the Clash API port")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    _install_redact_filter()

    try:
        count = launch_singbox(
            config_path=args.config,
            binary=args.singbox,
            wait_seconds=args.wait,
        )
    except FileNotFoundError as exc:
        LOG.error("sing-box binary not found: %s", exc)
        return 1
    except RuntimeError as exc:
        LOG.error("sing-box launch failed: %s", exc)
        return 1

    LOG.info("Built subscription with %d proxies via local sing-box", count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
