import csv
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


# Detection settings
THRESHOLD = 5
WINDOW_MINUTES = 5

BASE_DIR = Path(__file__).resolve().parent
INPUT_FILE = BASE_DIR / "sample_data" / "auth_logs.csv"
OUTPUT_FILE = BASE_DIR / "reports" / "alerts.csv"

REQUIRED_COLUMNS = {
    "timestamp",
    "username",
    "source_ip",
    "status",
}


def load_failed_logins(file_path):
    """Read the CSV file and return valid failed-login events."""
    failed_events = []
    skipped_rows = 0

    with file_path.open("r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)

        if not reader.fieldnames or not REQUIRED_COLUMNS.issubset(
            set(reader.fieldnames)
        ):
            raise ValueError(
                "CSV must contain: timestamp, username, "
                "source_ip, status"
            )

        for row in reader:
            try:
                timestamp = datetime.strptime(
                    row["timestamp"].strip(),
                    "%Y-%m-%d %H:%M:%S",
                )
                username = row["username"].strip()
                source_ip = row["source_ip"].strip()
                status = row["status"].strip().lower()

                if not username or not source_ip:
                    raise ValueError("Missing username or source IP")

                if status not in {"success", "failed"}:
                    raise ValueError("Unknown login status")

            except (ValueError, AttributeError, KeyError):
                skipped_rows += 1
                continue

            if status == "failed":
                failed_events.append({
                    "timestamp": timestamp,
                    "username": username,
                    "source_ip": source_ip,
                })

    return failed_events, skipped_rows


def detect_suspicious_ips(events):
    """Find the first window of repeated failures for each IP."""
    events_by_ip = defaultdict(list)

    for event in events:
        events_by_ip[event["source_ip"]].append(event)

    alerts = []
    window = timedelta(minutes=WINDOW_MINUTES)

    for source_ip, ip_events in events_by_ip.items():
        # Sort by time in case the CSV is not chronological.
        ip_events.sort(key=lambda event: event["timestamp"])

        # Try every event as the beginning of a time window.
        for start in range(len(ip_events)):
            window_start = ip_events[start]["timestamp"]
            window_end = window_start + window

            matching_events = [
                event
                for event in ip_events[start:]
                if event["timestamp"] <= window_end
            ]

            if len(matching_events) >= THRESHOLD:
                alerts.append({
                    "source_ip": source_ip,
                    "failed_attempts": len(matching_events),
                    "window_start": window_start.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    "window_end": matching_events[-1]["timestamp"].strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    "severity": "MEDIUM",
                    "reason": (
                        f"At least {THRESHOLD} failed logins "
                        f"within {WINDOW_MINUTES} minutes"
                    ),
                })
                break  # One alert per IP in this version.

    return alerts


def save_alerts(alerts, file_path):
    """Save the alerts to a CSV report."""
    fieldnames = [
        "source_ip",
        "failed_attempts",
        "window_start",
        "window_end",
        "severity",
        "reason",
    ]

    file_path.parent.mkdir(parents=True, exist_ok=True)

    with file_path.open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(alerts)


def main():
    if not INPUT_FILE.exists():
        print(f"ERROR: Input file not found: {INPUT_FILE}")
        return

    try:
        events, skipped_rows = load_failed_logins(INPUT_FILE)
    except (OSError, ValueError) as error:
        print(f"ERROR: Could not read the log file: {error}")
        return

    alerts = detect_suspicious_ips(events)
    save_alerts(alerts, OUTPUT_FILE)

    print("=== Failed Login Detection System ===")
    print(f"Failed login events analyzed: {len(events)}")
    print(f"Invalid rows skipped: {skipped_rows}")
    print(f"Alerts generated: {len(alerts)}")

    for alert in alerts:
        print(
            f"[{alert['severity']}] "
            f"IP {alert['source_ip']} | "
            f"{alert['failed_attempts']} failed attempts | "
            f"{alert['window_start']} to {alert['window_end']}"
        )

    print(f"\nReport saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
