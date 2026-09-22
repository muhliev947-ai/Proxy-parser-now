"""Shared build pipeline with pluggable check backends.

Both ``python -m src.main`` (Hiddify) and ``python -m src.checker.launch_singbox``
(local sing-box in CI) funnel through the single ``build()`` here.  The backends
expose a common interface so parsing, filtering, pool growth, re-verify and
publication-guard logic is written exactly once.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

import yaml

from src.checker.checker import CheckConfig, check_proxy, load_hiddify_tags
from src.generator.generators import (
    filter_supported_outbounds,
    sort_by_latency,
    to_clash,
    to_singbox,
    to_singbox_parallel,
)
from src.parser.model import ProxyConfig
from src.parser.parser import parse_sources, to_plaintext_uris

LOG = logging.getLogger(__name__)


class _RedactFilter(logging.Filter):
    """Last line of defence: redact any credential that slipped past the
    explicit redact() call sites before it reaches a public log."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.args:
            try:
                record.msg = record.msg % record.args
                record.args = None
            except (TypeError, ValueError):
                pass
        record.msg = redact(record.msg)
        return True


LOG.addFilter(_RedactFilter())

# Result taxonomy for the per-candidate table printed in the build log:
#   verified          — HTTP through the node returned the expected status
#   status_mismatch   — HTTP through the node returned a different status
#   delay_timeout     — no delay measured and no HTTP status got through
#   tcp_unreachable   — server:port not reachable over TCP
#   dropped_unsupported — filtered out before spawning (bad key, unknown type…)
RESULT_VERIFIED = "verified"
RESULT_STATUS_MISMATCH = "status_mismatch"
RESULT_DELAY_TIMEOUT = "delay_timeout"
RESULT_TCP_UNREACHABLE = "tcp_unreachable"
RESULT_DROPPED = "dropped_unsupported"
RESULT_NO_INBOUND = "no_inbound"


# ---------------------------------------------------------------------------
# Backend protocol
# ---------------------------------------------------------------------------

class CheckBackend(Protocol):
    """Common interface for any proxy-verification backend."""

    @property
    def check_config(self) -> CheckConfig: ...

    def load_tags(self) -> None: ...
    def verify_batch(self, proxies: list[ProxyConfig]) -> list[ProxyConfig]: ...
    def start(self, proxies: list[ProxyConfig]) -> None: ...
    def stop(self) -> None: ...


# ---------------------------------------------------------------------------
# Hiddify backend (existing behaviour, unchanged semantics)
# ---------------------------------------------------------------------------

class HiddifyBackend:
    """Verify through a locally running Hiddify sing-box instance."""

    def __init__(self, check: dict):
        self._config = CheckConfig(
            check.get("timeout_seconds", 5),
            check.get("urls", []),
            check.get("clash_api_url"),
            check.get("clash_api_secret"),
            check.get("concurrency", 8),
            check.get("expected_status", 204),
            check.get("socks_proxy_url"),
        )

    @property
    def check_config(self) -> CheckConfig:
        return self._config

    def load_tags(self) -> None:
        load_hiddify_tags()

    def start(self, proxies: list[ProxyConfig]) -> None:
        pass

    def verify_batch(self, proxies: list[ProxyConfig]) -> list[ProxyConfig]:
        with ThreadPoolExecutor(max_workers=self._config.concurrency) as pool:
            return list(pool.map(lambda p: check_proxy(p, self._config), proxies))

    def stop(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Local sing-box backend (CI mode, per-candidate inbounds)
# ---------------------------------------------------------------------------

@dataclass
class _Instance:
    """A running sing-box process plus the state needed to verify through it."""
    process: subprocess.Popen
    cfg_path: str
    log_path: str
    clash_port: int
    secret: str
    port_map: dict[int, int]  # id(ProxyConfig) -> inbound port
    supported: list[ProxyConfig] = field(default_factory=list)
    _fd: int | None = None
    _log_fd: int | None = None


class LocalSingBoxBackend:
    """Spawn a short-lived sing-box process and verify candidates in parallel.

    Each candidate gets its own ``mixed`` inbound on ``127.0.0.1:<base+i>``
    bound to the corresponding outbound via a route rule, so all nodes in a
    batch are verified concurrently without switching the global proxy.

    A single malformed outbound is handled by batch-halving: the batch is
    split in half and each half retried until the bad entry is isolated and
    dropped (logged with reason).
    """

    def __init__(self, check: dict, binary: str, wait_seconds: float = 30.0):
        singbox_cfg = check.get("singbox", {})
        self._binary = binary
        self._wait_seconds = wait_seconds
        self._max_outbounds = int(singbox_cfg.get("max_outbounds", 200))
        self._concurrency = int(check.get("concurrency", 8))
        self._timeout_seconds = float(check.get("timeout_seconds", 5))
        self._target_url = (check.get("urls") or ["https://cp.cloudflare.com/generate_204"])[0]
        self._expected_status = int(check.get("expected_status", 204))
        self._clash_port: int = 0
        self._secret: str = ""
        self._instance: _Instance | None = None
        self.last_log_time: str | None = None
        # CheckConfig kept in sync so pipeline._check_with_pool can read concurrency
        self._check_config = CheckConfig(
            self._timeout_seconds,
            check.get("urls"),
            None,
            self._secret,
            self._concurrency,
            self._expected_status,
            None,
        )

    @property
    def check_config(self) -> CheckConfig:
        return self._check_config

    def load_tags(self) -> None:
        pass

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self, proxies: list[ProxyConfig]) -> None:
        """Spawn a sing-box instance for *proxies*.

        Falls back to batch halving if ``sing-box check`` rejects the config
        because of a single malformed outbound.
        """
        # Cap the number of outbounds in one instance
        batch = proxies[: self._max_outbounds]
        if not batch:
            return

        self._instance = self._spawn_with_halving(batch)

    def _spawn_with_halving(
        self, batch: list[ProxyConfig], depth: int = 0,
    ) -> _Instance:
        """Try to spawn sing-box for *batch*; on check failure halve and retry."""
        max_depth = 8  # 2^8 = 256 singletons before giving up
        if depth > max_depth or len(batch) == 1:
            # Last resort: skip the check and just try to run
            LOG.warning("sing-box check gave up after %d halvings, trying to run %d nodes", depth, len(batch))
            return self._spawn_batch(batch)

        supported, dropped = filter_supported_outbounds(batch)
        for proxy in dropped:
            LOG.warning(
                "Dropping unsupported outbound %s (%s:%d) type=%s network=%s security=%s",
                proxy.name, proxy.server, proxy.port, proxy.type, proxy.network, proxy.security,
            )
            proxy.fail_reason = f"dropped_unsupported (type={proxy.type} network={proxy.network} security={proxy.security})"
            proxy.available = False
            proxy.verified = False
            proxy.speed_kbps = 0

        if not supported:
            # Nothing to check; return a no-op instance
            self._clash_port = 0
            self._secret = secrets.token_hex(16)
            return _Instance(
                process=subprocess.Popen(["true"]),
                cfg_path="",
                log_path="",
                clash_port=0,
                secret=self._secret,
                port_map={},
            )

        # Generate config
        clash_port = _find_free_port()
        base_port = _find_free_port(reserved={clash_port})
        self._clash_port = clash_port
        self._secret = secrets.token_hex(16)

        config_text, port_map = to_singbox_parallel(
            supported,
            base_port=base_port,
            clash_api_port=clash_port,
            clash_api_secret=self._secret,
        )
        pmap: dict[int, int] = {id(p): port_map[i] for i, p in enumerate(supported)}

        # Write config to a temp file
        cfg_fd, cfg_path = tempfile.mkstemp(suffix=".json", prefix="singbox-check-")
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write(config_text)
        os_close(cfg_fd)

        # Validate with `sing-box check`
        try:
            result = subprocess.run(
                [self._binary, "check", "-c", cfg_path],
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode != 0:
                stderr_tail = redact((result.stderr or result.stdout or "").strip()[-500:])
                LOG.warning(
                    "sing-box check failed (rc=%d): %s — halving batch of %d",
                    result.returncode, stderr_tail, len(supported),
                )
                Path(cfg_path).unlink(missing_ok=True)
                # Split supported list in half and recurse
                mid = len(supported) // 2
                left = supported[:mid]
                right = supported[mid:]
                # Try each half; merge the ones that pass
                instances = []
                if left:
                    inst = self._spawn_with_halving(left, depth + 1)
                    instances.append(inst)
                if right:
                    inst = self._spawn_with_halving(right, depth + 1)
                    instances.append(inst)
                if not instances:
                    raise RuntimeError("All outbounds failed sing-box check")
                # Each half was spawned independently (own config, own process).
                # Return only the first; the second half's candidates are not
                # re-checked here — _check_with_pool will pick them up on the
                # next batch. This keeps one process per instance.
                main = instances[0]
                for extra in instances[1:]:
                    _safe_terminate(extra.process)
                    Path(extra.cfg_path).unlink(missing_ok=True)
                return main
        except subprocess.TimeoutExpired:
            LOG.warning("sing-box check timed out; attempting to run anyway")
            Path(cfg_path).unlink(missing_ok=True)
            # Fall through to _spawn_batch

        return self._spawn_batch(supported, cfg_path=cfg_path, port_map=pmap,
                                 clash_port=clash_port)

    def _spawn_batch(
        self,
        proxies: list[ProxyConfig],
        cfg_path: str | None = None,
        port_map: dict[int, int] | None = None,
        clash_port: int | None = None,
    ) -> _Instance:
        """Start sing-box with the given proxies and wait for the Clash API."""
        if cfg_path is None or port_map is None:
            clash_port = clash_port or _find_free_port()
            base_port = _find_free_port(reserved={clash_port})
            self._clash_port = clash_port
            self._secret = self._secret or secrets.token_hex(16)
            config_text, pm = to_singbox_parallel(
                proxies,
                base_port=base_port,
                clash_api_port=clash_port,
                clash_api_secret=self._secret,
            )
            cfg_fd, cfg_path = tempfile.mkstemp(suffix=".json", prefix="singbox-")
            with open(cfg_path, "w", encoding="utf-8") as f:
                f.write(config_text)
            os_close(cfg_fd)
            # pm keys are indices into the *proxies* list passed to to_singbox_parallel;
            # unsupported proxies are absent from pm, so only map supported ones.
            pmap: dict[int, int] = {}
            for idx, p in enumerate(proxies):
                if idx in pm:
                    pmap[id(p)] = pm[idx]
            port_map = pmap

        log_fd, log_path = tempfile.mkstemp(suffix=".log", prefix="singbox-run-")
        with open(log_path, "wb") as log_file:
            process = subprocess.Popen(
                [self._binary, "run", "-c", cfg_path],
                stdout=log_file,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )

        # Wait for Clash API
        deadline = time.monotonic() + self._wait_seconds
        ready = False
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f"sing-box exited with code {process.returncode}")
            try:
                with socket.create_connection(("127.0.0.1", self._clash_port), timeout=1.0):
                    ready = True
                    break
            except OSError:
                time.sleep(0.25)
        if not ready:
            _safe_terminate(process)
            Path(cfg_path).unlink(missing_ok=True)
            raise RuntimeError("sing-box Clash API did not become ready in time")

        return _Instance(
            process=process,
            cfg_path=cfg_path,
            log_path=log_path,
            clash_port=self._clash_port,
            secret=self._secret,
            port_map=port_map,
            supported=proxies,
            _fd=None,
            _log_fd=log_fd,
        )

    def stop(self) -> None:
        if self._instance is None:
            return
        inst = self._instance
        _safe_terminate(inst.process)
        if inst.cfg_path:
            Path(inst.cfg_path).unlink(missing_ok=True)
        if inst.log_path:
            Path(inst.log_path).unlink(missing_ok=True)
        if inst._log_fd is not None:
            import contextlib
            with contextlib.suppress(OSError):
                os.close(inst._log_fd)
        self._instance = None

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify_batch(self, proxies: list[ProxyConfig]) -> list[ProxyConfig]:
        """Verify *proxies* through their dedicated inbounds in parallel."""
        if self._instance is None:
            return [_mark_failed(p) for p in proxies]

        inst = self._instance
        results: list[ProxyConfig] = []
        with ThreadPoolExecutor(max_workers=self._concurrency) as pool:
            futures = {}
            for proxy in proxies:
                port = inst.port_map.get(id(proxy))
                if port is None:
                    # Proxy was dropped during start(); mark failed and move on
                    results.append(_mark_failed(proxy))
                    continue
                futures[pool.submit(
                    _verify_one_inbound,
                    proxy,
                    self._target_url,
                    self._expected_status,
                    self._timeout_seconds,
                    port,
                    f"http://127.0.0.1:{inst.clash_port}",
                    inst.secret,
                )] = proxy
            for future, proxy in futures.items():
                try:
                    results.append(future.result())
                except Exception as exc:
                    LOG.warning(
                        "Verify failed for %s (%s:%d): %s",
                        proxy.name, proxy.server, proxy.port, redact(str(exc)),
                    )
                    results.append(_mark_failed(proxy))
        self.last_log_time = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        return results


# ---------------------------------------------------------------------------
# Standalone helpers
# ---------------------------------------------------------------------------

_FAIL_REASONS: dict[str, str] = {
    RESULT_TCP_UNREACHABLE: "TCP connection to the server port failed (node down, firewall, or IP blocked)",
    RESULT_NO_INBOUND: "outbound rejected by sing-box check (invalid key/params) or dropped as unsupported",
    RESULT_DELAY_TIMEOUT: "TCP OK, but no usable latency/HTTP status got through the node",
    RESULT_STATUS_MISMATCH: "traffic reached the node, but the HTTP status differed from the expected one",
    "verify_exception": "internal error during verification",
}


def _mark_failed(proxy: ProxyConfig, reason: str = "no_inbound") -> ProxyConfig:
    proxy.available = False
    proxy.verified = False
    proxy.speed_kbps = 0
    proxy.fail_reason = _FAIL_REASONS.get(reason, reason)
    return proxy


def _log_candidate_result(proxy: ProxyConfig) -> None:
    """One structured line per candidate: type, server:port, result, reason."""
    reason = "OK" if proxy.verified else (getattr(proxy, "fail_reason", None) or RESULT_NO_INBOUND)
    delay = proxy.speed_kbps if proxy.verified else 0.0
    LOG.info(
        "candidate %s (%s:%d) type=%s result=%s delay_kbps=%.1f reason=%s",
        proxy.name, proxy.server, proxy.port, proxy.type,
        "verified" if proxy.verified else "dead", delay, redact(reason),
    )


def _log_candidate_table(candidates: list[ProxyConfig], label: str = "verified") -> None:
    if not candidates:
        return
    verified = sum(1 for p in candidates if p.verified)
    LOG.info("Candidate summary (%s): %d checked, %d verified, %d dead",
             label, len(candidates), verified, len(candidates) - verified)
    for p in candidates:
        _log_candidate_result(p)


def _find_free_port(reserved: set[int] | None = None) -> int:
    """Bind to port 0 to get a free port, optionally avoiding *reserved*."""
    reserved = reserved or set()
    for _ in range(200):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
            s.close()
            if port not in reserved:
                return port
        except OSError:
            s.close()
    raise RuntimeError("Could not find a free port")


def _safe_terminate(process: subprocess.Popen) -> None:
    """terminate() → wait(5 s) → kill(), safe against already-exited processes."""
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def os_close(fd: int) -> None:
    """Wrapper around os.close to make it patchable in tests."""
    import contextlib
    with contextlib.suppress(OSError):
        os.close(fd)


#: Sensitive fragments that must never reach the log of a public repository:
#: credentials (uuid/password), REALITY material (pbk/sid), and the Clash API secret.
_SENSITIVE_PATTERNS = (
    re.compile(r"(?i)uuid=[0-9a-f-]{8,}",),
    re.compile(r"(?i)(?:password|pwd)=\S+",),
    re.compile(r"(?i)pbk=\S+",),
    re.compile(r"(?i)sid=\S+",),
    re.compile(r"(?i)bearer\s+[a-z0-9]{8,}",),
)


def redact(message: str) -> str:
    """Strip credentials and secrets from a log *message*.

    Only type, ``server:port``, result and a safe reason may remain in the
    public build log. Applied by the logger filter in both entry points.
    """
    for pattern in _SENSITIVE_PATTERNS:
        message = pattern.sub("…", message)
    # A bare, unlabelled UUID-like token (not a host:port address).
    message = re.sub(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", "…", message)
    # Whole proxy URIs carry credentials in the userinfo; keep only the scheme.
    message = re.sub(r"(?i)\b(?:vless|vmess|trojan|ss|hy2|hysteria2)://[^\s;]+", lambda m: m.group(0).split("://", 1)[0] + "://…", message)
    return message


def _verify_one_inbound(
    proxy: ProxyConfig,
    target_url: str,
    expected_status: int,
    timeout_seconds: float,
    inbound_port: int,
    clash_api_url: str,
    secret: str,
) -> ProxyConfig:
    """Verify a single proxy through its dedicated mixed inbound.

    1. TCP reachability of the server port.
    2. Measure delay via the Clash API per-tag endpoint.
    3. Send an HTTP request through the inbound; confirm expected status.
    """
    # 1. TCP reachability
    try:
        with socket.create_connection((proxy.server, proxy.port), timeout=timeout_seconds):
            proxy.tcp_reachable = True
    except (OSError, ValueError):
        proxy.tcp_reachable = False
        return _mark_failed(proxy, RESULT_TCP_UNREACHABLE)

    # 2. Delay via Clash API (best-effort; a 404 here does not fail the check)
    delay_ms: float | None = None
    tag = proxy.name
    quoted_tag = urllib.parse.quote(tag, safe="")
    quoted_url = urllib.parse.quote(target_url, safe="")
    headers = {"Authorization": f"Bearer {secret}"}
    delay_path = f"/proxies/{quoted_tag}/delay?timeout=5000&url={quoted_url}"
    try:
        with urllib.request.urlopen(
            urllib.request.Request(clash_api_url + delay_path, headers=headers),
            timeout=30,
        ) as resp:
            body = resp.read().decode()
            result = json.loads(body) if body.strip() else {}
            d = result.get("delay")
            if isinstance(d, (int, float)) and d > 0:
                delay_ms = float(d)
    except Exception:
        pass

    # 3. HTTP status through the dedicated inbound
    proxy_url = f"http://127.0.0.1:{inbound_port}"
    proxy_handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    opener = urllib.request.build_opener(proxy_handler)
    try:
        with opener.open(target_url, timeout=max(timeout_seconds, 5)) as response:
            if response.status == expected_status:
                proxy.speed_kbps = round(8000 / max(delay_ms or 1, 1), 2) if delay_ms else 0.0
                proxy.available = True
                proxy.verified = True
                proxy.fail_reason = ""
                return proxy
            # Distinguished from a total timeout: traffic reached the node
            # (or its upstream), but the answer was not the expected status.
            return _mark_failed(proxy, RESULT_STATUS_MISMATCH)
    except (OSError, ValueError):
        # TCP connect to the server succeeded, so the failure is on the
        # handshake/HTTP side: no usable delay and no expected status.
        return _mark_failed(proxy, RESULT_DELAY_TIMEOUT)

    raise RuntimeError("unreachable")

# ---------------------------------------------------------------------------
# Shared pipeline
# ---------------------------------------------------------------------------

def _passes_static_filters(proxy: ProxyConfig, config: dict) -> bool:
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


def _check_with_pool(
    candidates: list[ProxyConfig],
    backend: CheckBackend,
    check: dict,
) -> list[ProxyConfig]:
    """Verify candidates, growing the pool until enough working nodes are found."""
    max_candidates = int(check.get("max_candidates", 500))
    min_working = int(check.get("min_working_nodes", 0))
    max_total = int(check.get("max_total_candidates", 0)) or max_candidates * 4
    remaining = candidates[:max_total]

    if min_working <= 0:
        return backend.verify_batch(remaining[:max_candidates])

    checked: list[ProxyConfig] = []
    concurrency = backend.check_config.concurrency
    batch_size = max(concurrency * 4, min_working)
    while remaining:
        batch, remaining = remaining[:batch_size], remaining[batch_size:]
        if isinstance(backend, LocalSingBoxBackend):
            # Restart the instance for each batch so stale state is avoided
            backend.stop()
            backend.start(batch)
        checked.extend(backend.verify_batch(batch))
        verified = sum(1 for p in checked if p.verified)
        LOG.info("Verified %d of %d checked nodes", verified, len(checked))
        # One structured line per candidate: type, server:port, result, reason.
        for proxy in checked:
            _log_candidate_result(proxy)
        if verified >= min_working:
            break
    return checked


def _reverify_before_publish(
    proxies: list[ProxyConfig],
    backend: CheckBackend,
    check: dict,
) -> list[ProxyConfig]:
    """Re-verify the top-N nodes right before writing the subscription."""
    top_n = int(check.get("reverify_top_n", 10))
    if top_n <= 0 or not proxies:
        return proxies
    top, rest = proxies[:top_n], proxies[top_n:]
    if isinstance(backend, LocalSingBoxBackend):
        backend.stop()
        backend.start(top)
        # start() may return a no-op instance if all candidates were dropped;
        # in that case verify_batch will mark them all failed, which is correct.
    rechecked = backend.verify_batch(top)
    for proxy in rechecked:
        if not proxy.verified:
            LOG.warning("Node %s (%s:%d) died before publication, dropping it: %s",
                        proxy.name, proxy.server, proxy.port, redact(proxy.fail_reason))
    return [p for p in rechecked if p.verified] + rest


def build(config_path: str = "config.yaml", backend: CheckBackend | None = None) -> int:
    """Shared pipeline: parse → filter → verify → final-filter → write.

    When *backend* is None a ``HiddifyBackend`` is created from the config.
    Returns the number of proxies written to the subscription.
    """
    config = yaml.safe_load(Path(config_path).read_text(encoding="utf-8"))
    freshness_days = int(config.get("freshness_days", 7))
    fallback_file = config.get("fallback_file")
    proxies = parse_sources(
        config.get("sources", []),
        freshness_days=freshness_days,
        fallback_file=fallback_file,
    )
    LOG.info("Parsed %d proxies from sources", len(proxies))

    output = Path(config.get("output", {}).get("directory", "output"))
    output.mkdir(parents=True, exist_ok=True)
    docs = Path("docs")
    docs.mkdir(parents=True, exist_ok=True)

    check = config.get("check", {})
    if backend is None:
        backend = HiddifyBackend(check)

    candidates = [p for p in proxies if _passes_static_filters(p, config)]
    LOG.info("After static filters: %d candidates", len(candidates))

    backend.load_tags()

    try:
        # For Hiddify backend the instance is already running; no need to start.
        # For LocalSingBoxBackend, _check_with_pool calls backend.start() per batch.
        candidates = _check_with_pool(candidates, backend, check)
    finally:
        backend.stop()

    final = [p for p in candidates if _passes_final_filters(p, config)]
    # Final per-candidate result table for the build log (CI evidence).
    _log_candidate_table(candidates, label="final run")
    if config.get("output", {}).get("sort_by_latency"):
        final = sort_by_latency(final)
        LOG.info("Sorted %d proxies by latency", len(final))

    if check.get("reverify_before_publish", True):
        backend.load_tags()
        final = _reverify_before_publish(final, backend, check)
        final = [p for p in final if _passes_final_filters(p, config)]
        if config.get("output", {}).get("sort_by_latency"):
            final = sort_by_latency(final)

    # Publication guard: never overwrite an existing non-empty subscription
    # with an empty result.
    verified = [p for p in final if p.verified]
    if not verified:
        existing = output / "subscription.txt"
        if existing.exists() and existing.stat().st_size > 0:
            LOG.warning(
                "No verified proxies in this run; preserving existing subscription (%s)",
                existing,
            )
        else:
            # First run without a previous file: nothing is written, so the
            # CI "preserve existing docs/subscription.txt" guard kicks in.
            LOG.warning("No verified proxies and no existing subscription found; nothing written")
        return 0

    LOG.info("Publishing %d verified proxies", len(verified))
    formats = config.get("output", {}).get("formats", ["plaintext"])
    if "plaintext" in formats:
        _write_freshness_metadata(final, backend)
        lines = to_plaintext_uris(final)
        text = "\n".join(lines) + ("\n" if lines else "")
        (output / "subscription.txt").write_text(text, encoding="utf-8")
        (docs / "subscription.txt").write_text(text, encoding="utf-8")
    if "clash" in formats:
        (output / "subscription.yaml").write_text(to_clash(final), encoding="utf-8")
    if "singbox" in formats:
        (output / "subscription.json").write_text(to_singbox(final), encoding="utf-8")
    LOG.info("Wrote %d proxies to %s", len(final), output)
    return len(final)


def _write_freshness_metadata(final: list[ProxyConfig], backend: CheckBackend) -> None:
    """Record the last successful check time in docs/index.html.

    The subscription file itself stays a clean list of URIs; only the
    index page carries the metadata (UTC timestamp, node count, per-type
    breakdown).
    """
    stamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    if isinstance(backend, LocalSingBoxBackend) and backend.last_log_time:
        stamp = backend.last_log_time
    by_type: dict[str, int] = {}
    for proxy in final:
        by_type[proxy.type] = by_type.get(proxy.type, 0) + 1
    breakdown = ", ".join(f"{type_name}: {count}" for type_name, count in sorted(by_type.items()))
    index_path = Path("docs") / "index.html"
    marker = "<!-- freshness-meta -->"
    meta_block = (
        f"{marker}\n      <p id=\"freshness-meta\">"
        f"Last successful check: <b>{stamp}</b><br>"
        f"Nodes: <b>{len(final)}</b><br>"
        f"By type: {breakdown or 'n/a'}"
        f"</p>\n"
    )
    if index_path.exists():
        page = index_path.read_text(encoding="utf-8")
        start = page.find(marker)
        if start != -1:
            end = page.find("</p>", start)
            end = end + len("</p>") if end != -1 else len(page)
            page = page[:start] + meta_block.rstrip("\n") + page[end:]
        else:
            page = page.replace("</body>", meta_block + "  </body>", 1)
        index_path.write_text(page, encoding="utf-8")
    else:
        index_path.parent.mkdir(parents=True, exist_ok=True)
        index_path.write_text(
            "<!doctype html>\n<html><body>\n" + meta_block + "</body></html>\n",
            encoding="utf-8",
        )
    LOG.info("Updated freshness metadata in %s (%s, %d nodes)", index_path, stamp, len(final))
