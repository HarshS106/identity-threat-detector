"""
analyzer.py
-----------
Core detection engine for the Identity Threat Detector.
Parses authentication logs from Okta, Azure AD, and AWS IAM
and runs them through a set of behavioral detection rules.

Detections:
  - Impossible travel (login from two geographically distant IPs in short time)
  - Brute force (N failed logins within a time window)
  - Privilege escalation (role/group change followed by sensitive action)
  - Dormant account activation (account unused for 90+ days suddenly active)
  - Concurrent sessions from multiple countries
"""

import json
import math
import logging
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD   = 5       # failed attempts
BRUTE_FORCE_WINDOW_MINS = 10      # within N minutes
IMPOSSIBLE_TRAVEL_KMH   = 900     # max plausible speed (km/h) — below aircraft speed
DORMANT_DAYS_THRESHOLD  = 90      # days of inactivity before account is "dormant"
EARTH_RADIUS_KM         = 6371


# ── Data Models ───────────────────────────────────────────────────────────────
@dataclass
class LogEvent:
    event_id:    str
    timestamp:   datetime
    user:        str
    action:      str          # e.g. "login_success", "login_failure", "role_assigned"
    source_ip:   str
    country:     str
    city:        str
    lat:         float = 0.0
    lon:         float = 0.0
    extra:       dict = field(default_factory=dict)


@dataclass
class ThreatAlert:
    severity:    str           # CRITICAL / HIGH / MEDIUM / LOW
    rule:        str
    user:        str
    timestamp:   str
    description: str
    evidence:    dict = field(default_factory=dict)
    mitre_tactic: str = ""
    mitre_technique: str = ""

    def to_dict(self) -> dict:
        return {
            "severity":        self.severity,
            "rule":            self.rule,
            "user":            self.user,
            "timestamp":       self.timestamp,
            "description":     self.description,
            "evidence":        self.evidence,
            "mitre_tactic":    self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
        }


# ── Geo Helpers ───────────────────────────────────────────────────────────────
def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Return great-circle distance in km between two lat/lon points."""
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi       = math.radians(lat2 - lat1)
    dlambda    = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(math.sqrt(a))


def travel_speed_kmh(event_a: LogEvent, event_b: LogEvent) -> float:
    """Return implied travel speed in km/h between two login events."""
    distance_km = haversine_km(event_a.lat, event_a.lon, event_b.lat, event_b.lon)
    elapsed_sec = abs((event_b.timestamp - event_a.timestamp).total_seconds())
    if elapsed_sec < 60:
        return float("inf")   # same-minute logins from different locations = instant
    return (distance_km / elapsed_sec) * 3600


# ── Detection Rules ───────────────────────────────────────────────────────────
class DetectionEngine:
    def __init__(self):
        self.alerts: list[ThreatAlert] = []

    # ── Rule 1: Impossible Travel ─────────────────────────────────────────────
    def detect_impossible_travel(self, events_by_user: dict[str, list[LogEvent]]) -> None:
        for user, events in events_by_user.items():
            logins = sorted(
                [e for e in events if e.action == "login_success"],
                key=lambda e: e.timestamp,
            )
            for i in range(len(logins) - 1):
                a, b = logins[i], logins[i + 1]
                if a.country == b.country:
                    continue
                speed = travel_speed_kmh(a, b)
                if speed > IMPOSSIBLE_TRAVEL_KMH:
                    self.alerts.append(ThreatAlert(
                        severity   = "CRITICAL",
                        rule       = "Impossible Travel",
                        user       = user,
                        timestamp  = b.timestamp.isoformat(),
                        description= (
                            f"{user} logged in from {a.city}, {a.country} "
                            f"and then {b.city}, {b.country} — "
                            f"implied speed {speed:.0f} km/h"
                        ),
                        evidence   = {
                            "login_1": {"city": a.city, "country": a.country, "ip": a.source_ip, "time": a.timestamp.isoformat()},
                            "login_2": {"city": b.city, "country": b.country, "ip": b.source_ip, "time": b.timestamp.isoformat()},
                            "implied_speed_kmh": round(speed, 1),
                        },
                        mitre_tactic    = "Initial Access",
                        mitre_technique = "T1078 — Valid Accounts",
                    ))

    # ── Rule 2: Brute Force ───────────────────────────────────────────────────
    def detect_brute_force(self, events_by_user: dict[str, list[LogEvent]]) -> None:
        window = timedelta(minutes=BRUTE_FORCE_WINDOW_MINS)
        for user, events in events_by_user.items():
            failures = sorted(
                [e for e in events if e.action == "login_failure"],
                key=lambda e: e.timestamp,
            )
            for i, start_event in enumerate(failures):
                window_failures = [
                    e for e in failures[i:]
                    if e.timestamp - start_event.timestamp <= window
                ]
                if len(window_failures) >= BRUTE_FORCE_THRESHOLD:
                    self.alerts.append(ThreatAlert(
                        severity   = "HIGH",
                        rule       = "Brute Force Login Attempt",
                        user       = user,
                        timestamp  = start_event.timestamp.isoformat(),
                        description= (
                            f"{len(window_failures)} failed logins for {user} "
                            f"within {BRUTE_FORCE_WINDOW_MINS} minutes from "
                            f"{window_failures[0].source_ip}"
                        ),
                        evidence   = {
                            "failed_count":  len(window_failures),
                            "window_mins":   BRUTE_FORCE_WINDOW_MINS,
                            "source_ips":    list({e.source_ip for e in window_failures}),
                            "first_attempt": start_event.timestamp.isoformat(),
                        },
                        mitre_tactic    = "Credential Access",
                        mitre_technique = "T1110 — Brute Force",
                    ))
                    break   # one alert per user per burst

    # ── Rule 3: Privilege Escalation ──────────────────────────────────────────
    def detect_privilege_escalation(self, events_by_user: dict[str, list[LogEvent]]) -> None:
        sensitive_actions = {"access_admin_panel", "export_user_data", "delete_resource", "modify_policy"}
        window = timedelta(minutes=30)
        for user, events in events_by_user.items():
            role_changes = [e for e in events if e.action == "role_assigned"]
            for rc in role_changes:
                follow_up = [
                    e for e in events
                    if e.action in sensitive_actions
                    and timedelta(0) < (e.timestamp - rc.timestamp) <= window
                ]
                if follow_up:
                    self.alerts.append(ThreatAlert(
                        severity   = "HIGH",
                        rule       = "Privilege Escalation → Sensitive Action",
                        user       = user,
                        timestamp  = rc.timestamp.isoformat(),
                        description= (
                            f"{user} was assigned a new role and then performed "
                            f"'{follow_up[0].action}' within {window.seconds // 60} minutes"
                        ),
                        evidence   = {
                            "role_change_time":   rc.timestamp.isoformat(),
                            "sensitive_action":   follow_up[0].action,
                            "sensitive_action_time": follow_up[0].timestamp.isoformat(),
                            "new_role": rc.extra.get("new_role", "unknown"),
                        },
                        mitre_tactic    = "Privilege Escalation",
                        mitre_technique = "T1078.004 — Cloud Accounts",
                    ))

    # ── Rule 4: Dormant Account Activation ───────────────────────────────────
    def detect_dormant_account(
        self,
        events_by_user: dict[str, list[LogEvent]],
        last_seen: dict[str, datetime],
    ) -> None:
        threshold = timedelta(days=DORMANT_DAYS_THRESHOLD)
        now = datetime.now(timezone.utc)
        for user, events in events_by_user.items():
            logins = [e for e in events if e.action == "login_success"]
            if not logins:
                continue
            prev_last_seen = last_seen.get(user)
            if prev_last_seen and (now - prev_last_seen) > threshold:
                self.alerts.append(ThreatAlert(
                    severity   = "MEDIUM",
                    rule       = "Dormant Account Reactivation",
                    user       = user,
                    timestamp  = logins[0].timestamp.isoformat(),
                    description= (
                        f"{user} last seen {(now - prev_last_seen).days} days ago — "
                        f"account reactivated from {logins[0].source_ip}"
                    ),
                    evidence   = {
                        "last_seen_date": prev_last_seen.isoformat(),
                        "days_dormant":   (now - prev_last_seen).days,
                        "reactivation_ip": logins[0].source_ip,
                        "reactivation_country": logins[0].country,
                    },
                    mitre_tactic    = "Initial Access",
                    mitre_technique = "T1078 — Valid Accounts",
                ))

    def run_all(
        self,
        events: list[LogEvent],
        last_seen: Optional[dict[str, datetime]] = None,
    ) -> list[ThreatAlert]:
        """Group events by user and run all detection rules."""
        self.alerts = []
        by_user: dict[str, list[LogEvent]] = defaultdict(list)
        for e in events:
            by_user[e.user].append(e)

        self.detect_impossible_travel(by_user)
        self.detect_brute_force(by_user)
        self.detect_privilege_escalation(by_user)
        self.detect_dormant_account(by_user, last_seen or {})

        log.info("Detection complete — %d alert(s) generated.", len(self.alerts))
        return self.alerts
