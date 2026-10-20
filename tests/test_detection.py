
import pandas as pd

from src.detect_anomalies import (
    detect_brute_force,
    detect_sensitive_access,
)


def test_detects_repeated_login_failures():
    df = pd.DataFrame({
        "timestamp": [
            "2026-10-20T10:00:00Z",
            "2026-10-20T10:01:00Z",
            "2026-10-20T10:02:00Z",
            "2026-10-20T10:03:00Z",
            "2026-10-20T10:04:00Z",
        ],
        "source_ip": ["198.51.100.23"] * 5,
        "event_type": ["login_failure"] * 5,
    })

    alerts = detect_brute_force(df, threshold=5, window_minutes=5)

    assert len(alerts) == 1
    assert alerts.iloc[0]["source_ip"] == "198.51.100.23"
    assert alerts.iloc[0]["severity"] == "HIGH"


def test_no_alert_for_fewer_failures():
    df = pd.DataFrame({
        "timestamp": [
            "2026-10-20T10:00:00Z",
            "2026-10-20T10:01:00Z",
        ],
        "source_ip": ["192.0.2.10"] * 2,
        "event_type": ["login_failure"] * 2,
    })

    alerts = detect_brute_force(df, threshold=5, window_minutes=5)

    assert alerts.empty


def test_detects_sensitive_resource_access():
    df = pd.DataFrame({
        "timestamp": ["2026-10-20T10:00:00Z"],
        "source_ip": ["203.0.113.45"],
        "username": ["employee02"],
        "resource": ["/admin/export"],
    })

    alerts = detect_sensitive_access(df)

    assert len(alerts) == 1
    assert alerts.iloc[0]["severity"] == "MEDIUM"
    assert alerts.iloc[0]["resource"] == "/admin/export"
