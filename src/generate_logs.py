
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Reproducible synthetic data for testing
random.seed(42)

PROJECT_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PROJECT_DIR / "data" / "raw"
OUTPUT_FILE = OUTPUT_DIR / "security_logs.json"

USERS = [
    "admin",
    "analyst",
    "support",
    "employee01",
    "employee02",
]

# Documentation-only IPv4 addresses; no real systems are targeted.
NORMAL_IPS = [
    "192.0.2.10",
    "192.0.2.11",
    "192.0.2.12",
]

TEST_IPS = [
    "198.51.100.23",
    "203.0.113.45",
]


def generate_logs():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    events = []
    now = datetime.now(timezone.utc)

    # 1. Generate 180 ordinary authentication events.
    for i in range(180):
        timestamp = now - timedelta(
            minutes=random.randint(0, 1440)
        )

        success = random.random() > 0.12

        event = {
            "event_id": f"EVT-{i + 1:04d}",
            "timestamp": timestamp.isoformat(),
            "source_ip": random.choice(NORMAL_IPS),
            "username": random.choice(USERS),
            "event_type": (
                "login_success"
                if success
                else "login_failure"
            ),
            "resource": "/login",
            "status": "success" if success else "failure",
        }

        events.append(event)

    # 2. Generate 12 consecutive failed login attempts.
    for i in range(12):
        timestamp = now - timedelta(minutes=20) + timedelta(
            seconds=i * 20
        )

        event = {
            "event_id": f"EVT-ATTACK-{i + 1:03d}",
            "timestamp": timestamp.isoformat(),
            "source_ip": TEST_IPS[0],
            "username": "admin",
            "event_type": "login_failure",
            "resource": "/login",
            "status": "failure",
        }

        events.append(event)

    # 3. Generate one sensitive-resource access event.
    events.append({
        "event_id": "EVT-SENSITIVE-001",
        "timestamp": now.isoformat(),
        "source_ip": TEST_IPS[1],
        "username": "employee02",
        "event_type": "sensitive_resource_access",
        "resource": "/admin/export",
        "status": "success",
    })

    # Shuffle events to simulate an unsorted log stream.
    random.shuffle(events)

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(events, file, indent=2)

    print(f"Generated {len(events)} security events.")
    print(f"Output file: {OUTPUT_FILE}")


if __name__ == "__main__":
    generate_logs()
