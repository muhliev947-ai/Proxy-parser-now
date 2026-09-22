"""Read output/metrics.json and append a Markdown job summary to a file.

Usage: python3 scripts/metrics_summary.py <path-to-step-summary>
Writes to the summary file a "## Build metrics" section with run counters
and a ⚠️ warning when published < min_working_nodes.
"""
import json
import sys


def main() -> int:
    summary_path = sys.argv[1]
    try:
        with open("output/metrics.json", encoding="utf-8") as f:
            m = json.load(f)
    except FileNotFoundError:
        with open(summary_path, "a", encoding="utf-8") as f:
            f.write("## Build metrics\nmetrics.json not found (build may have failed before publishing).\n")
        return 0

    lines = ["## Build metrics", ""]
    lines.append(f"- Checked: **{m.get('checked', 0)}**")
    lines.append(f"- Verified: **{m.get('verified', 0)}**")
    lines.append(f"- Published: **{m.get('published', 0)}**")
    lines.append(f"- Timestamp: {m.get('timestamp_utc', 'n/a')}")
    min_working = m.get("min_working_nodes", 0)
    if min_working > 0:
        lines.append(f"- Min working nodes: {min_working}")
        if not m.get("healthy", True):
            lines.append("")
            lines.append(
                f"⚠️ **Published {m.get('published', 0)} nodes — "
                f"below min_working_nodes ({min_working}). Pool may be degrading.**"
            )
    with open(summary_path, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
