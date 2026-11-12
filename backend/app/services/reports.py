"""Build downloadable TXT and CSV analysis reports.

Three kinds of time appear in a report and are kept clearly apart:

* **Report generated** - the moment this report was built (``generated_at``).
* **Analysis created** - when the log data was analyzed and stored.
* **Log period** - the first and last event timestamps *inside* the log.

All are stored/computed in UTC and shown in the display timezone.
"""

from __future__ import annotations

import csv
import io
import re
from datetime import datetime

from project import LOG_LEVELS

from ..models import Analysis, Detection
from ..timeutils import format_local, timezone_label, utc_now

DISCLAIMER = (
    "LogScope uses transparent, rule-based heuristics. Suspicious patterns "
    "deserve review; they are not confirmed attacks."
)

# Analyses created by an earlier version embedded "(... UTC)" in the text; the
# times are shown separately (in local time), so that part is removed here.
_EMBEDDED_UTC = re.compile(r" \(\d{4}-\d{2}-\d{2} [\d:]+ to [\d:]+ UTC\)")


def detection_text(detection: Detection) -> str:
    """The explanation sentence without any embedded UTC timestamps."""
    return _EMBEDDED_UTC.sub("", detection.explanation)


def build_text_report(analysis: Analysis, detections: list[Detection], generated_at: datetime | None = None) -> str:
    generated_at = generated_at or utc_now()
    s = analysis.summary
    total = analysis.total_entries
    lines = [
        "LOGSCOPE ANALYSIS REPORT",
        "=" * 64,
        f"Report generated:   {format_local(generated_at)}",
        f"Times shown in:     {timezone_label(generated_at)}",
        "",
        "ANALYZED DATA",
        "-" * 64,
        f"Dataset:            #{analysis.id} - {analysis.name}",
        f"Source:             {_source_label(analysis)}",
        f"Analysis created:   {format_local(analysis.created_at)}",
        f"Log period:         {format_local(s.get('start_time'))}  to  {format_local(s.get('end_time'))}",
        "                    (first and last event timestamps inside the analyzed log)",
        f"Log times read as:  {s.get('source_timezone', 'UTC')} (for timestamps without a zone)",
        "",
        "SUMMARY",
        "-" * 64,
        f"Log records:         {total}",
        f"Invalid lines:       {analysis.invalid_lines}",
        f"Unique IP addresses: {s.get('unique_ips', 0)}",
        f"Error rate:          {analysis.error_rate}% (ERROR + CRITICAL)",
        f"Suspicious patterns: {len(detections)}",
        "",
        "LOG LEVEL DISTRIBUTION",
        "-" * 64,
    ]
    for level in LOG_LEVELS:
        count = s["level_counts"].get(level, 0)
        lines.append(f"{level:<10} {count:>8}  {_pct(count, total):>6}")

    lines += ["", "HTTP STATUS DISTRIBUTION", "-" * 64]
    status_total = sum(s["status_counts"].values())
    for code, count in s["status_counts"].items():
        lines.append(f"{code:<10} {count:>8}  {_pct(count, status_total):>6}")
    if not s["status_counts"]:
        lines.append("No HTTP status codes in this log.")

    lines += ["", "TOP IP ADDRESSES", "-" * 64]
    lines += [f"{row['ip']:<40} {row['count']:>8}" for row in s.get("top_ips", [])] or ["None"]

    lines += ["", "SUSPICIOUS PATTERNS", "-" * 64]
    if not detections:
        lines.append("No detection rule reached its threshold.")
    for number, d in enumerate(detections, start=1):
        lines += [
            f"[{number}] {d.title}  (severity: {d.severity.upper()})",
            f"    Source:      {d.ip or 'all clients'}",
            f"    Threshold:   {d.count} events in {d.window_seconds} s (limit {d.threshold})",
            f"    Event time:  {format_local(d.first_seen)}  to  {format_local(d.last_seen)}",
            f"    Why flagged: {detection_text(d)}",
            "",
        ]

    lines += ["DETECTION RULES USED", "-" * 64]
    for rule, cfg in analysis.thresholds.items():
        lines.append(f"{rule:<20} {cfg['threshold']:>4} events within {cfg['window_seconds']} s")
    lines += ["", DISCLAIMER, ""]
    return "\n".join(lines)


def build_csv_report(analysis: Analysis, detections: list[Detection], generated_at: datetime | None = None) -> str:
    """A long-format CSV (section, item, value, details) that opens cleanly in spreadsheets."""
    generated_at = generated_at or utc_now()
    s = analysis.summary
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["section", "item", "value", "details"])
    writer.writerow(["report", "generated_at", format_local(generated_at), timezone_label(generated_at)])
    writer.writerow(["analysis", "dataset", analysis.id, analysis.name])
    writer.writerow(["analysis", "created_at", format_local(analysis.created_at), timezone_label(generated_at)])
    writer.writerow(["analysis", "log_period_start", format_local(s.get("start_time")), "first event in the log"])
    writer.writerow(["analysis", "log_period_end", format_local(s.get("end_time")), "last event in the log"])
    writer.writerow(["summary", "log_records", analysis.total_entries, ""])
    writer.writerow(["summary", "invalid_lines", analysis.invalid_lines, ""])
    writer.writerow(["summary", "unique_ips", s.get("unique_ips", 0), ""])
    writer.writerow(["summary", "error_rate_percent", analysis.error_rate, "ERROR + CRITICAL"])
    for level in LOG_LEVELS:
        writer.writerow(["level", level, s["level_counts"].get(level, 0), ""])
    for code, count in s["status_counts"].items():
        writer.writerow(["status", code, count, ""])
    for row in s.get("top_ips", []):
        writer.writerow(["top_ip", row["ip"], row["count"], ""])
    for d in detections:
        writer.writerow([
            "suspicious_pattern", f"{d.title} [{d.severity}]", d.count,
            f"ip={d.ip or 'all'}; window={d.window_seconds}s; threshold={d.threshold}; "
            f"from={format_local(d.first_seen)}; to={format_local(d.last_seen)}; {detection_text(d)}",
        ])
    writer.writerow(["note", "disclaimer", "", DISCLAIMER])
    return buffer.getvalue()


def _source_label(analysis: Analysis) -> str:
    if analysis.source == "upload":
        return f"Uploaded file ({analysis.filename})"
    if analysis.source == "monitor":
        return f"Monitored file ({analysis.summary.get('monitor_path', analysis.filename)})"
    return "Generated sample data (test data, not real events)"


def _pct(part: int, whole: int) -> str:
    return f"{part / whole * 100:.1f}%" if whole else "0.0%"
