
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import pandas as pd

PROJECT_DIR = Path(__file__).resolve().parent.parent
EVENTS_FILE = PROJECT_DIR / "data" / "raw" / "security_logs.json"
ALERTS_FILE = PROJECT_DIR / "data" / "processed" / "security_alerts.csv"
REPORT_DIR = PROJECT_DIR / "reports"


def generate_report():
    if not EVENTS_FILE.exists():
        raise FileNotFoundError(
            f"Events file not found: {EVENTS_FILE}"
        )

    if not ALERTS_FILE.exists():
        raise FileNotFoundError(
            f"Alerts file not found: {ALERTS_FILE}. "
            "Run `python -m src.detect_anomalies` first."
        )

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    with EVENTS_FILE.open("r", encoding="utf-8") as file:
        events = json.load(file)

    alerts = pd.read_csv(ALERTS_FILE)

    # Normalize severity values for reporting.
    if "severity" in alerts.columns:
        alerts["severity"] = alerts["severity"].fillna("UNKNOWN")

    total_events = len(events)
    total_alerts = len(alerts)

    severity_counts = (
        alerts["severity"].value_counts().to_dict()
        if total_alerts
        else {}
    )

    report = {
        "report_title": "Security Log Analytics Report",
        "total_events_analyzed": total_events,
        "total_alerts": total_alerts,
        "alerts_by_severity": severity_counts,
        "generated_at_utc": pd.Timestamp.now(tz="UTC").isoformat(),
    }

    json_output = REPORT_DIR / "security_report.json"
    with json_output.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    # Create a chart of alerts by severity.
    chart_output = REPORT_DIR / "alerts_by_severity.png"

    if severity_counts:
        labels = list(severity_counts.keys())
        values = list(severity_counts.values())

        plt.figure(figsize=(7, 4))
        plt.bar(labels, values)
        plt.title("Security Alerts by Severity")
        plt.xlabel("Severity")
        plt.ylabel("Number of alerts")
        plt.tight_layout()
        plt.savefig(chart_output, dpi=150)
        plt.close()
    else:
        chart_output = None

    # Create a readable text summary.
    text_output = REPORT_DIR / "security_report.txt"

    lines = [
        "SECURITY LOG ANALYTICS REPORT",
        "=" * 32,
        "",
        f"Events analyzed: {total_events}",
        f"Total alerts: {total_alerts}",
        "",
        "Alerts by severity:",
    ]

    if severity_counts:
        for severity, count in sorted(severity_counts.items()):
            lines.append(f"- {severity}: {count}")
    else:
        lines.append("- No alerts detected")

    lines.extend([
        "",
        "Note: Alerts are heuristic indicators and require analyst review.",
        f"Generated at: {report['generated_at_utc']}",
    ])

    text_output.write_text("\n".join(lines), encoding="utf-8")

    print(f"Events analyzed: {total_events}")
    print(f"Total alerts: {total_alerts}")
    print(f"JSON report: {json_output}")
    print(f"Text report: {text_output}")

    if chart_output:
        print(f"Severity chart: {chart_output}")


if __name__ == "__main__":
    generate_report()
