"""Read a metrics.json and append a Markdown job summary to a file.

Usage: python3 scripts/metrics_summary.py <summary-path> [metrics-path]

Writes to the summary file a "## Build metrics" section with run counters,
a ⚠️ warning when published < min_working_nodes, and a pool-degradation
alert when the published count has dropped ≥ 50% compared to the previous
committed metrics.json (retrieved via ``git show HEAD:output/metrics.json``).
The metrics path defaults to ``output/metrics.json``.
"""
import json
import subprocess
import sys

DEFAULT_METRICS_PATH = "output/metrics.json"


def _get_previous_metrics() -> dict | None:
    """Read the last-committed metrics.json via git; return None if absent."""
    try:
        result = subprocess.run(
            ["git", "show", "HEAD:output/metrics.json"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return None
        return json.loads(result.stdout)
    except (OSError, json.JSONDecodeError):
        return None


def build_alert(previous: dict | None, current: dict) -> str | None:
    """Return an alert line if the pool has degraded, else None."""
    if previous is None:
        return None
    prev_published = previous.get("published", 0)
    cur_published = current.get("published", 0)
    min_working = current.get("min_working_nodes", 0)
    # Only alert if the pool was previously healthy and has now shrunk ≥ 50%
    if prev_published >= min_working and cur_published < prev_published * 0.5:
        return (
            f"\n🚨 **Pool degradation alert:** published nodes dropped from "
            f"{prev_published} to {cur_published} "
            f"({min_working} required). Review the candidate sources."
        )
    return None


def build_summary(metrics: dict, previous: dict | None = None) -> str:
    """Return the Markdown summary text for a parsed metrics dict."""
    lines = ["## Build metrics", ""]
    lines.append(f"- Checked: **{metrics.get('checked', 0)}**")
    lines.append(f"- Verified: **{metrics.get('verified', 0)}**")
    lines.append(f"- Published: **{metrics.get('published', 0)}**")
    lines.append(f"- Timestamp: {metrics.get('timestamp_utc', 'n/a')}")
    min_working = metrics.get("min_working_nodes", 0)
    if min_working > 0:
        lines.append(f"- Min working nodes: {min_working}")
        if not metrics.get("healthy", True):
            lines.append("")
            lines.append(
                f"⚠️ **Published {metrics.get('published', 0)} nodes — "
                f"below min_working_nodes ({min_working}). Pool may be degrading.**"
            )
    alert = build_alert(previous, metrics)
    if alert:
        lines.append(alert)
    by_source = metrics.get("by_source")
    if by_source:
        lines.append("")
        lines.append("### Per-source")
        lines.append("")
        lines.append("| Source | Checked | Verified |")
        lines.append("| --- | ---: | ---: |")
        for source, counts in sorted(
            by_source.items(), key=lambda item: (item[1].get("verified", 0), item[1].get("checked", 0)), reverse=True
        ):
            lines.append(
                f"| `{source}` | {counts.get('checked', 0)} | {counts.get('verified', 0)} |"
            )
    return "\n".join(lines) + "\n"


def main() -> int:
    summary_path = sys.argv[1]
    metrics_path = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_METRICS_PATH
    try:
        with open(metrics_path, encoding="utf-8") as f:
            m = json.load(f)
        previous = _get_previous_metrics()
        text = build_summary(m, previous)
    except FileNotFoundError:
        text = (
            "## Build metrics\n"
            "metrics.json not found (build may have failed before publishing).\n"
        )
    with open(summary_path, "a", encoding="utf-8") as f:
        f.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
