"""
main.py
-------
CLI entry point for the Identity Threat Detector.

Usage:
    python main.py --source okta     --log sample_data/okta_sample.json
    python main.py --source azure_ad --log sample_data/azure_sample.json
    python main.py --source cloudtrail --log sample_data/cloudtrail_sample.json
    python main.py --source okta --log sample_data/okta_sample.json --output report.json
"""

import sys
import json
import argparse
import logging
from pathlib import Path
from datetime import timezone
from collections import Counter

# Allow running from repo root
sys.path.insert(0, str(Path(__file__).parent))

from src.parsers import parse_log_file
from src.analyzer import DetectionEngine

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITY_ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}


def print_summary(alerts) -> None:
    counts = Counter(a.severity for a in alerts)
    print("\n" + "=" * 60)
    print("  IDENTITY THREAT DETECTOR — SCAN REPORT")
    print("=" * 60)
    print(f"  Total alerts : {len(alerts)}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        n = counts.get(sev, 0)
        if n:
            print(f"  {SEVERITY_ICONS[sev]} {sev:<10}: {n}")
    print("=" * 60)

    sorted_alerts = sorted(alerts, key=lambda a: SEVERITY_ORDER.get(a.severity, 9))
    for alert in sorted_alerts:
        icon = SEVERITY_ICONS.get(alert.severity, "⚪")
        print(f"\n{icon} [{alert.severity}] {alert.rule}")
        print(f"   User      : {alert.user}")
        print(f"   Time      : {alert.timestamp}")
        print(f"   Detail    : {alert.description}")
        print(f"   MITRE     : {alert.mitre_tactic} / {alert.mitre_technique}")
        if alert.evidence:
            print(f"   Evidence  : {json.dumps(alert.evidence, indent=14)[1:-1].strip()}")

    print("\n" + "=" * 60 + "\n")


def save_report(alerts, output_path: str) -> None:
    report = {
        "tool":    "Identity Threat Detector",
        "version": "1.0.0",
        "github":  "https://github.com/YOUR-USERNAME/identity-threat-detector",
        "summary": {s: sum(1 for a in alerts if a.severity == s) for s in ["CRITICAL","HIGH","MEDIUM","LOW"]},
        "alerts":  [a.to_dict() for a in alerts],
    }
    Path(output_path).write_text(json.dumps(report, indent=2))
    log.info("Report saved → %s", output_path)


def main():
    parser = argparse.ArgumentParser(
        description="Identity Threat Detector — detect suspicious auth behavior across Okta, Azure AD, and AWS"
    )
    parser.add_argument("--source", required=True,
                        choices=["okta", "azure_ad", "cloudtrail"],
                        help="Log source type")
    parser.add_argument("--log",    required=True,
                        help="Path to JSON log file")
    parser.add_argument("--output", default=None,
                        help="Optional: save JSON report to this path")
    parser.add_argument("--last-seen", default=None,
                        help="Optional: path to JSON file mapping user→last_seen ISO timestamp")
    args = parser.parse_args()

    # Parse logs
    events = parse_log_file(args.log, args.source)
    if not events:
        log.error("No events parsed. Check your log file and source type.")
        sys.exit(1)

    # Optional: load last-seen data for dormant account detection
    last_seen = {}
    if args.last_seen:
        from datetime import datetime
        raw_ls = json.loads(Path(args.last_seen).read_text())
        last_seen = {
            user: datetime.fromisoformat(ts).astimezone(timezone.utc)
            for user, ts in raw_ls.items()
        }

    # Run detection
    engine = DetectionEngine()
    alerts = engine.run_all(events, last_seen=last_seen)

    # Output
    print_summary(alerts)
    if args.output:
        save_report(alerts, args.output)


if __name__ == "__main__":
    main()
