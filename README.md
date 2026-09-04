# SOC Failed Login Analyzer

An expert-level Security Operations Center (SOC) project written in Python. It reviews authentication logs, counts failed login attempts by source IP address, and raises a possible brute-force alert when an IP reaches three or more failures.

## What it does

- Filters log entries containing `LOGIN_FAILED`
- Extracts each source IP address
- Counts failed attempts per IP
- Generates an alert at 3 or more failed attempts
- Ignores successful login entries

## Requirements

- Python 3.8 or newer
- No third-party packages

## Run the project

```bash
python soc_log_analyzer.py
```

Example output:

```text
=== Failed Login Report ===
10.0.0.15: 1 failed attempt(s)
192.168.1.10: 4 failed attempt(s)
[ALERT] Possible brute-force attack from 192.168.1.10 (4 failed attempts)
```

## Try your own logs

Edit the `LOG_DATA` list in `soc_log_analyzer.py`. Each entry should include an event type and an IP field, for example:

```text
2026-09-04 10:01:20 LOGIN_FAILED user=admin ip=192.168.1.10
```

The alert threshold is controlled by `ALERT_THRESHOLD`.

## Expert SOC concepts

This project demonstrates log parsing, event filtering, source-IP aggregation, and threshold-based brute-force detection.
