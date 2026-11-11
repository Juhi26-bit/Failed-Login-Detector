import unittest
from datetime import datetime, timedelta

from detector import detect_suspicious_ips


# Helper function to create test login events
def make_event(source_ip, timestamp):
    return {
        "source_ip": source_ip,
        "username": "test_user",
        "timestamp": datetime.strptime(
            timestamp, "%Y-%m-%d %H:%M:%S"
        ),
    }


class DetectionTests(unittest.TestCase):

    # TEST 1: Five failures should generate an alert
    def test_five_failures_trigger_alert(self):
        events = [
            make_event(
                "203.0.113.25",
                f"2026-10-21 09:0{i}:00",
            )
            for i in range(5)
        ]

        alerts = detect_suspicious_ips(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["failed_attempts"], 5)

    # TEST 2: Four failures should NOT generate an alert
    def test_four_failures_do_not_trigger_alert(self):
        events = [
            make_event(
                "198.51.100.17",
                f"2026-10-21 09:0{i}:00",
            )
            for i in range(4)
        ]

        alerts = detect_suspicious_ips(events)

        self.assertEqual(len(alerts), 0)

    # TEST 3: Failures outside the time window should NOT alert
    def test_failures_outside_window_do_not_trigger_alert(self):
        start = datetime(2026, 10, 21, 9, 0, 0)

        events = [
            {
                "source_ip": "192.0.2.10",
                "username": "test_user",
                "timestamp": start + timedelta(minutes=10 * i),
            }
            for i in range(5)
        ]

        alerts = detect_suspicious_ips(events)

        self.assertEqual(len(alerts), 0)


if __name__ == "__main__":
    unittest.main()
