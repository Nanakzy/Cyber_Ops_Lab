#!/usr/bin/env python3
"""
log_parser.py – Basic Security Log Parser Template
====================================================
Purpose : Parse system or application log files, identify suspicious
          events (e.g., failed login attempts, error spikes), and
          produce a summary report.

Usage   : python3 log_parser.py --log <path_to_log_file>
          python3 log_parser.py --log /var/log/auth.log

Exit codes:
  0 – No brute-force suspects detected (clean log or below threshold).
  1 – One or more brute-force suspects found; useful for scripted alerting
      (e.g., triggering a notification in a CI/CD pipeline or cron job).

Author  : [Your Name]
Date    : [YYYY-MM-DD]
"""

import re
import argparse
from collections import defaultdict
from datetime import datetime

# ---------------------------------------------------------------------------
# Configuration – adjust these patterns to match your target log format
# ---------------------------------------------------------------------------

# Regex pattern for a failed SSH login (Linux auth.log format)
FAILED_LOGIN_PATTERN = re.compile(
    r"(?P<timestamp>\w{3}\s+\d+\s[\d:]+)\s+\S+\s+sshd.*"
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[\d.]+)"
)

# Regex pattern for a successful SSH login
SUCCESSFUL_LOGIN_PATTERN = re.compile(
    r"(?P<timestamp>\w{3}\s+\d+\s[\d:]+)\s+\S+\s+sshd.*"
    r"Accepted password for (?P<user>\S+) "
    r"from (?P<ip>[\d.]+)"
)

# Threshold: flag IPs with more failed attempts than this value
FAILED_LOGIN_THRESHOLD = 5


# ---------------------------------------------------------------------------
# Core parsing functions
# ---------------------------------------------------------------------------

def parse_log_file(filepath):
    """
    Read a log file line by line and extract security-relevant events.

    Args:
        filepath (str): Path to the log file to analyse.

    Returns:
        tuple: (failed_logins dict, successful_logins list, raw_events list)
    """
    # Track failed attempts per IP address {ip: [list of (timestamp, user)]}
    failed_logins = defaultdict(list)
    successful_logins = []
    raw_events = []

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as log_file:
            for line_number, line in enumerate(log_file, start=1):
                line = line.strip()
                if not line:
                    continue  # Skip blank lines

                # Check for failed login attempts
                failed_match = FAILED_LOGIN_PATTERN.search(line)
                if failed_match:
                    ip = failed_match.group("ip")
                    user = failed_match.group("user")
                    timestamp = failed_match.group("timestamp")
                    failed_logins[ip].append((timestamp, user))
                    raw_events.append({
                        "line": line_number,
                        "type": "FAILED_LOGIN",
                        "ip": ip,
                        "user": user,
                        "timestamp": timestamp,
                    })
                    continue  # No need to check further patterns for this line

                # Check for successful logins
                success_match = SUCCESSFUL_LOGIN_PATTERN.search(line)
                if success_match:
                    ip = success_match.group("ip")
                    user = success_match.group("user")
                    timestamp = success_match.group("timestamp")
                    successful_logins.append({
                        "line": line_number,
                        "type": "SUCCESSFUL_LOGIN",
                        "ip": ip,
                        "user": user,
                        "timestamp": timestamp,
                    })

    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {filepath}")
        raise
    except PermissionError:
        print(f"[ERROR] Permission denied reading: {filepath}")
        raise

    return failed_logins, successful_logins, raw_events


def identify_brute_force(failed_logins, threshold=FAILED_LOGIN_THRESHOLD):
    """
    Identify IP addresses that exceed the failed login threshold.

    Args:
        failed_logins (dict): Dict of {ip: [(timestamp, user), ...]}
        threshold (int): Number of failures before flagging an IP.

    Returns:
        list: Sorted list of (ip, attempt_count, events) tuples.
    """
    suspects = []
    for ip, events in failed_logins.items():
        if len(events) >= threshold:
            suspects.append((ip, len(events), events))
    # Sort by number of attempts, descending
    suspects.sort(key=lambda x: x[1], reverse=True)
    return suspects


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(failed_logins, successful_logins, brute_force_suspects):
    """
    Print a human-readable summary report to stdout.

    Args:
        failed_logins (dict): All failed login events grouped by IP.
        successful_logins (list): All successful login events.
        brute_force_suspects (list): IPs exceeding the failure threshold.
    """
    separator = "=" * 60
    print(f"\n{separator}")
    print("  SECURITY LOG ANALYSIS REPORT")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(separator)

    # Summary counts
    total_failed = sum(len(v) for v in failed_logins.values())
    print(f"\n[SUMMARY]")
    print(f"  Total failed login attempts : {total_failed}")
    print(f"  Unique source IPs (failed)  : {len(failed_logins)}")
    print(f"  Successful logins           : {len(successful_logins)}")
    print(f"  Brute-force suspects        : {len(brute_force_suspects)}")

    # Brute-force suspects
    if brute_force_suspects:
        print(f"\n[BRUTE-FORCE SUSPECTS] (>= {FAILED_LOGIN_THRESHOLD} attempts)")
        print(f"  {'IP Address':<20} {'Attempts':>8}")
        print(f"  {'-'*20} {'-'*8}")
        for ip, count, _ in brute_force_suspects:
            print(f"  {ip:<20} {count:>8}")
    else:
        print(f"\n[BRUTE-FORCE SUSPECTS] None detected above threshold.")

    # Successful logins
    if successful_logins:
        print(f"\n[SUCCESSFUL LOGINS]")
        for event in successful_logins:
            print(f"  {event['timestamp']}  user={event['user']}  ip={event['ip']}")
    else:
        print(f"\n[SUCCESSFUL LOGINS] None found in log.")

    print(f"\n{separator}\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(
        description="Parse security log files and identify suspicious activity."
    )
    parser.add_argument(
        "--log",
        required=True,
        help="Path to the log file to analyse (e.g., /var/log/auth.log)",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=FAILED_LOGIN_THRESHOLD,
        help=f"Failed login threshold for brute-force detection (default: {FAILED_LOGIN_THRESHOLD})",
    )
    args = parser.parse_args()

    print(f"[*] Parsing log file: {args.log}")

    # Parse the log file
    failed_logins, successful_logins, raw_events = parse_log_file(args.log)

    # Identify potential brute-force sources
    brute_force_suspects = identify_brute_force(failed_logins, threshold=args.threshold)

    # Output the report
    print_report(failed_logins, successful_logins, brute_force_suspects)

    # Exit with a non-zero code if suspects were found (useful for automation/alerting)
    if brute_force_suspects:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
