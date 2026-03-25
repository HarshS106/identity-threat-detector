"""
parsers.py
----------
Normalizes authentication log formats from Okta, Azure AD, and AWS IAM
into a common LogEvent schema consumed by the detection engine.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional
from .analyzer import LogEvent

log = logging.getLogger(__name__)


def _parse_ts(ts_str: str) -> datetime:
    """Parse an ISO-8601 timestamp string into an aware datetime (UTC)."""
    ts_str = ts_str.replace("Z", "+00:00")
    return datetime.fromisoformat(ts_str).astimezone(timezone.utc)


# ── Okta System Log Parser ────────────────────────────────────────────────────
def parse_okta_log(raw: dict) -> Optional[LogEvent]:
    """
    Parse a single Okta System Log event.
    Relevant eventType values: user.session.start, user.authentication.sso,
    user.account.privilege.grant, user.mfa.factor.deactivate
    """
    try:
        event_type = raw.get("eventType", "")
        actor      = raw.get("actor", {})
        client     = raw.get("client", {})
        geo        = client.get("geographicalContext", {})
        ip         = client.get("ipAddress", "0.0.0.0")
        outcomes   = raw.get("outcome", {})
        result     = outcomes.get("result", "").lower()

        # Map Okta event types to normalized actions
        if "session.start" in event_type or "authentication" in event_type:
            action = "login_success" if result == "success" else "login_failure"
        elif "privilege.grant" in event_type or "group.user_add" in event_type:
            action = "role_assigned"
        elif "mfa" in event_type and "deactivate" in event_type:
            action = "mfa_disabled"
        else:
            action = event_type

        return LogEvent(
            event_id  = raw.get("uuid", ""),
            timestamp = _parse_ts(raw.get("published", "")),
            user      = actor.get("alternateId", actor.get("id", "unknown")),
            action    = action,
            source_ip = ip,
            country   = geo.get("country", "Unknown"),
            city      = geo.get("city", "Unknown"),
            lat       = geo.get("geolocation", {}).get("lat", 0.0),
            lon       = geo.get("geolocation", {}).get("lon", 0.0),
            extra     = {
                "okta_event_type": event_type,
                "display_message": raw.get("displayMessage", ""),
                "new_role": raw.get("target", [{}])[0].get("displayName", "") if raw.get("target") else "",
            },
        )
    except Exception as exc:
        log.warning("Failed to parse Okta event: %s — %s", raw.get("uuid"), exc)
        return None


# ── Azure AD Sign-In Log Parser ───────────────────────────────────────────────
def parse_azure_ad_log(raw: dict) -> Optional[LogEvent]:
    """
    Parse a single Azure AD sign-in log entry (from Log Analytics / Sentinel export).
    """
    try:
        status       = raw.get("status", {})
        error_code   = status.get("errorCode", 0)
        action       = "login_success" if error_code == 0 else "login_failure"
        location     = raw.get("location", {})
        geo          = location.get("geoCoordinates", {})

        return LogEvent(
            event_id  = raw.get("id", ""),
            timestamp = _parse_ts(raw.get("createdDateTime", "")),
            user      = raw.get("userPrincipalName", raw.get("userId", "unknown")),
            action    = action,
            source_ip = raw.get("ipAddress", "0.0.0.0"),
            country   = location.get("countryOrRegion", "Unknown"),
            city      = location.get("city", "Unknown"),
            lat       = float(geo.get("latitude", 0.0)),
            lon       = float(geo.get("longitude", 0.0)),
            extra     = {
                "app_display_name":  raw.get("appDisplayName", ""),
                "device_detail":     raw.get("deviceDetail", {}),
                "conditional_access": raw.get("appliedConditionalAccessPolicies", []),
                "risk_level_signin": raw.get("riskLevelDuringSignIn", "none"),
                "error_code":        error_code,
            },
        )
    except Exception as exc:
        log.warning("Failed to parse Azure AD event: %s — %s", raw.get("id"), exc)
        return None


# ── AWS CloudTrail IAM Event Parser ───────────────────────────────────────────
def parse_cloudtrail_event(raw: dict) -> Optional[LogEvent]:
    """
    Parse a single AWS CloudTrail record for IAM/STS events.
    Maps ConsoleLogin, AssumeRole, CreateAccessKey, etc.
    """
    try:
        event_name = raw.get("eventName", "")
        identity   = raw.get("userIdentity", {})
        user_arn   = identity.get("arn", identity.get("principalId", "unknown"))

        # Normalize action
        if event_name == "ConsoleLogin":
            login_result = raw.get("responseElements", {}).get("ConsoleLogin", "")
            action = "login_success" if login_result == "Success" else "login_failure"
        elif event_name == "AssumeRole":
            action = "role_assigned"
        elif event_name == "CreateAccessKey":
            action = "access_key_created"
        elif event_name in {"AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy"}:
            action = "role_assigned"
        else:
            action = event_name.lower()

        return LogEvent(
            event_id  = raw.get("eventID", ""),
            timestamp = _parse_ts(raw.get("eventTime", "")),
            user      = user_arn,
            action    = action,
            source_ip = raw.get("sourceIPAddress", "0.0.0.0"),
            country   = "Unknown",    # CloudTrail does not include geo — enrich externally
            city      = "Unknown",
            lat       = 0.0,
            lon       = 0.0,
            extra     = {
                "event_source":       raw.get("eventSource", ""),
                "aws_region":         raw.get("awsRegion", ""),
                "request_parameters": raw.get("requestParameters", {}),
                "user_agent":         raw.get("userAgent", ""),
            },
        )
    except Exception as exc:
        log.warning("Failed to parse CloudTrail event: %s — %s", raw.get("eventID"), exc)
        return None


def parse_log_file(path: str, source: str) -> list[LogEvent]:
    """
    Load a JSON log file and parse all records using the appropriate parser.

    Args:
        path:   Path to a JSON file containing a list of log events.
        source: One of 'okta', 'azure_ad', 'cloudtrail'

    Returns:
        List of normalized LogEvent objects.
    """
    import json
    from pathlib import Path

    parser_map = {
        "okta":       parse_okta_log,
        "azure_ad":   parse_azure_ad_log,
        "cloudtrail": parse_cloudtrail_event,
    }
    parser = parser_map.get(source)
    if not parser:
        raise ValueError(f"Unknown source '{source}'. Choose from: {list(parser_map)}")

    raw_records = json.loads(Path(path).read_text())
    if isinstance(raw_records, dict):
        raw_records = raw_records.get("Records", raw_records.get("value", [raw_records]))

    events = [parser(r) for r in raw_records]
    parsed = [e for e in events if e is not None]
    log.info("Parsed %d/%d events from %s (%s)", len(parsed), len(raw_records), path, source)
    return parsed

