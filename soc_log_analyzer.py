"""Beginner SOC log analyzer for detecting repeated failed logins."""

from collections import Counter

ALERT_THRESHOLD = 3

LOG_DATA = [
    "2026-09-04 10:01:20 LOGIN_FAILED user=admin ip=192.168.1.10",
    "2026-09-04 10:02:10 LOGIN_FAILED user=admin ip=192.168.1.10",
    "2026-09-04 10:03:45 LOGIN_FAILED user=admin ip=192.168.1.10",
    "2026-09-04 10:05:12 LOGIN_SUCCESS user=rahim ip=192.168.1.20",
    "2026-09-04 10:06:30 LOGIN_FAILED user=test ip=10.0.0.15",
    "2026-09-04 10:07:10 LOGIN_FAILED user=admin ip=192.168.1.10",
]


def count_failed_logins(logs):
    """Return failed-login counts grouped by source IP."""
    failed_ips = []

    for log in logs:
        if "LOGIN_FAILED" not in log or "ip=" not in log:
            continue

        ip_address = log.split("ip=", 1)[1].split()[0]
        failed_ips.append(ip_address)

    return Counter(failed_ips)


def print_report(failed_counts):
    """Print failed-login totals and brute-force alerts."""
    print("=== Failed Login Report ===")

    if not failed_counts:
        print("No failed login attempts found.")
        return

    for ip_address, count in sorted(failed_counts.items()):
        print(f"{ip_address}: {count} failed attempt(s)")

        if count >= ALERT_THRESHOLD:
            print(
                f"[ALERT] Possible brute-force attack from {ip_address} "
                f"({count} failed attempts)"
            )


if __name__ == "__main__":
    print_report(count_failed_logins(LOG_DATA))
