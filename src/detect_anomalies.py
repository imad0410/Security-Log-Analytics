
import pandas as pd
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
INPUT_FILE = PROJECT_DIR / "data" / "raw" / "security_logs.json"
OUTPUT_DIR = PROJECT_DIR / "data" / "processed"
OUTPUT_FILE = OUTPUT_DIR / "security_alerts.csv"


def detect_brute_force(
    df: pd.DataFrame,
    threshold: int = 5,
    window_minutes: int = 5,
) -> pd.DataFrame:
    """Detect repeated failed logins from the same IP within a time window."""
    required_columns = {"timestamp", "source_ip", "event_type"}

    missing = required_columns - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    failures = df[df["event_type"] == "login_failure"].copy()

    if failures.empty:
        return pd.DataFrame(
            columns=[
                "source_ip",
                "window_start",
                "failed_attempts",
                "alert_type",
                "severity",
            ]
        )

    failures["timestamp"] = pd.to_datetime(
        failures["timestamp"], utc=True, errors="coerce"
    )
    failures = failures.dropna(subset=["timestamp", "source_ip"])
    failures = failures.sort_values("timestamp")

    alerts = []

    for source_ip, group in failures.groupby("source_ip"):
        group = group.set_index("timestamp").sort_index()

        counts = group["event_type"].rolling(
            f"{window_minutes}min"
        ).count()

        suspicious = counts[counts >= threshold]

        for timestamp, count in suspicious.items():
            alerts.append({
                "source_ip": source_ip,
                "window_start": timestamp.isoformat(),
                "failed_attempts": int(count),
                "alert_type": "Repeated login failures",
                "severity": "HIGH",
            })

    if not alerts:
        return pd.DataFrame(
            columns=[
                "source_ip",
                "window_start",
                "failed_attempts",
                "alert_type",
                "severity",
            ]
        )

    result = pd.DataFrame(alerts)

    # Keep the first alert per IP to avoid producing one alert per event.
    result = result.drop_duplicates(subset=["source_ip"], keep="first")
    return result.reset_index(drop=True)


def detect_sensitive_access(df: pd.DataFrame) -> pd.DataFrame:
    """Flag access to paths that are designated as sensitive in this lab."""
    required_columns = {"timestamp", "source_ip", "username", "resource"}

    missing = required_columns - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    sensitive = df[
        df["resource"].astype(str).str.startswith("/admin/")
    ].copy()

    if sensitive.empty:
        return pd.DataFrame(
            columns=[
                "source_ip",
                "username",
                "resource",
                "timestamp",
                "alert_type",
                "severity",
            ]
        )

    sensitive["alert_type"] = "Sensitive resource access"
    sensitive["severity"] = "MEDIUM"

    return sensitive[
        [
            "source_ip",
            "username",
            "resource",
            "timestamp",
            "alert_type",
            "severity",
        ]
    ].reset_index(drop=True)


def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Input file not found: {INPUT_FILE}. "
            "Run `python -m src.generate_logs` first."
        )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    df = pd.read_json(INPUT_FILE)

    brute_force_alerts = detect_brute_force(df)
    sensitive_alerts = detect_sensitive_access(df)

    alerts = pd.concat(
        [brute_force_alerts, sensitive_alerts],
        ignore_index=True,
        sort=False,
    )

    alerts.to_csv(OUTPUT_FILE, index=False)

    print(f"Events analyzed: {len(df)}")
    print(f"Brute-force alerts: {len(brute_force_alerts)}")
    print(f"Sensitive-access alerts: {len(sensitive_alerts)}")
    print(f"Alerts saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
