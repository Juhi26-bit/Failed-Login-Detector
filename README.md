# Failed Login Detection System

## Overview

A beginner-friendly Python cybersecurity project that analyzes authentication logs and detects repeated failed login attempts within a configurable time window.

The project simulates a basic SOC detection workflow using fictional authentication data.

## Problem Statement

Repeated failed login attempts can indicate a possible brute-force attack, password guessing, or a legitimate user having trouble signing in. Security analysts need a way to identify and investigate these events.

## Detection Logic

- Group failed login events by source IP address.
- Sort events by timestamp.
- Detect at least 5 failed attempts within a 5-minute window.
- Generate a medium-severity alert when the threshold is reached.
- Export alerts to a CSV report.

The threshold is configurable and intended for demonstration, not as a universal security standard.

## Technology Stack

- Python 3
- CSV data processing
- Python `datetime` and `collections` modules
- `unittest` for automated testing

No third-party Python packages are required.

## Project Structure

```text
failed-login-detector/
├── detector.py
├── sample_data/
│   └── auth_logs.csv
├── reports/
│   └── alerts.csv
├── tests/
│   └── test_detector.py
└── README.md
```

## How to Run

1. Install Python 3.
2. Clone or download the repository.
3. Open a terminal in the project directory.
4. Run:

   `py detector.py`

5. View the generated report in `reports/alerts.csv`.

Run automated tests with:

`py -m unittest discover -s tests -v`

## Test Scenarios

- Five failed attempts within the time window.
- Four failed attempts below the threshold.
- Failed attempts spread outside the time window.

## Limitations

- Uses simulated data rather than live authentication logs.
- An alert does not prove malicious activity.
- Detection is based on source IP and may miss distributed attempts across multiple IP addresses.
- The current version reports only the first matching window per IP.
- It does not perform threat-intelligence enrichment or automatic blocking.

## Future Improvements

- Support Windows Security Event Logs.
- Add configurable detection thresholds.
- Improve sliding-window performance.
- Add alert deduplication and richer investigation context.
- Integrate with a SIEM platform such as Wazuh.
- Build a dashboard for reviewing alerts.

## Safety

All sample data is fictional. The project is intended for defensive security analysis and educational use.

## Learning Outcomes

This project demonstrates basic log parsing, timestamp handling, detection-rule implementation, automated testing, and security alert reporting.# Failed Login Detection System

## Overview

A beginner-friendly Python cybersecurity project that analyzes authentication logs and detects repeated failed login attempts within a configurable time window.

The project simulates a basic SOC detection workflow using fictional authentication data.

## Problem Statement

Repeated failed login attempts can indicate a possible brute-force attack, password guessing, or a legitimate user having trouble signing in. Security analysts need a way to identify and investigate these events.

## Detection Logic

- Group failed login events by source IP address.
- Sort events by timestamp.
- Detect at least 5 failed attempts within a 5-minute window.
- Generate a medium-severity alert when the threshold is reached.
- Export alerts to a CSV report.

The threshold is configurable and intended for demonstration, not as a universal security standard.

## Technology Stack

- Python 3
- CSV data processing
- Python `datetime` and `collections` modules
- `unittest` for automated testing

No third-party Python packages are required.

## Project Structure

```text
failed-login-detector/
├── detector.py
├── sample_data/
│   └── auth_logs.csv
├── reports/
│   └── alerts.csv
├── tests/
│   └── test_detector.py
└── README.md
```

## How to Run

1. Install Python 3.
2. Clone or download the repository.
3. Open a terminal in the project directory.
4. Run:

   `py detector.py`

5. View the generated report in `reports/alerts.csv`.

Run automated tests with:

`py -m unittest discover -s tests -v`

## Test Scenarios

- Five failed attempts within the time window.
- Four failed attempts below the threshold.
- Failed attempts spread outside the time window.

## Limitations

- Uses simulated data rather than live authentication logs.
- An alert does not prove malicious activity.
- Detection is based on source IP and may miss distributed attempts across multiple IP addresses.
- The current version reports only the first matching window per IP.
- It does not perform threat-intelligence enrichment or automatic blocking.

## Future Improvements

- Support Windows Security Event Logs.
- Add configurable detection thresholds.
- Improve sliding-window performance.
- Add alert deduplication and richer investigation context.
- Integrate with a SIEM platform such as Wazuh.
- Build a dashboard for reviewing alerts.

## Safety

All sample data is fictional. The project is intended for defensive security analysis and educational use.

## Learning Outcomes

This project demonstrates basic log parsing, timestamp handling, detection-rule implementation, automated testing, and security alert reporting.