# Identity Threat Detector

**Real-time authentication log analyzer** that detects identity-based threats across Okta, Azure AD, and AWS CloudTrail using behavioral detection rules mapped to the MITRE ATT&CK framework.

---

## What It Does

Ingests raw authentication logs and runs them through a detection engine to surface:

| Detection Rule | MITRE Technique | Severity |
|---|---|---|
| Impossible Travel | T1078 — Valid Accounts | CRITICAL |
| Brute Force Login | T1110 — Brute Force | HIGH |
| Privilege Escalation → Sensitive Action | T1078.004 — Cloud Accounts | HIGH |
| Dormant Account Reactivation | T1078 — Valid Accounts | MEDIUM |

---

## Architecture

```
Raw Logs (Okta / Azure AD / CloudTrail)
        │
        ▼
  parsers.py          ← normalizes all log formats into common schema
        │
        ▼
  analyzer.py         ← runs behavioral detection rules
        │
        ▼
  main.py (CLI)       ← prints terminal report + saves JSON output
```

---

## Quick Start

```bash
git clone https://github.com/YOUR-USERNAME/identity-threat-detector
cd identity-threat-detector
pip install -r requirements.txt

# Run against sample Okta log
python main.py --source okta --log sample_data/okta_sample.json

# Save report to JSON
python main.py --source okta --log sample_data/okta_sample.json --output report.json

# Azure AD logs
python main.py --source azure_ad --log sample_data/azure_sample.json

# AWS CloudTrail
python main.py --source cloudtrail --log sample_data/cloudtrail_sample.json
```

---

## Sample Output

```
============================================================
  IDENTITY THREAT DETECTOR — SCAN REPORT
============================================================
  Total alerts : 3
  🔴 CRITICAL   : 1
  🟠 HIGH        : 1
  🟡 MEDIUM      : 1
============================================================

🔴 [CRITICAL] Impossible Travel
   User      : jdoe@company.com
   Time      : 2025-03-24T08:47:00+00:00
   Detail    : jdoe@company.com logged in from New York, United States
               and then Lagos, Nigeria — implied speed 9,842 km/h
   MITRE     : Initial Access / T1078 — Valid Accounts

🟠 [HIGH] Brute Force Login Attempt
   User      : asmith@company.com
   Time      : 2025-03-24T09:10:00+00:00
   Detail    : 5 failed logins for asmith@company.com within 10 minutes
```

---

## Supported Log Sources

| Source | Format | Notes |
|--------|--------|-------|
| Okta | System Log API (JSON) | `eventType`, geolocation included |
| Azure AD | Sign-in Logs (Log Analytics export) | `signInLogs` format |
| AWS CloudTrail | CloudTrail Records JSON | IAM + STS events |

---

## Project Structure

```
identity-threat-detector/
├── main.py                     # CLI entry point
├── src/
│   ├── analyzer.py             # Detection engine + alert data models
│   └── parsers.py              # Log normalizers for each source
├── sample_data/
│   ├── okta_sample.json        # Demo Okta events (includes impossible travel + brute force)
│   ├── azure_sample.json       # Demo Azure AD events
│   └── cloudtrail_sample.json  # Demo CloudTrail events
├── tests/
│   └── test_analyzer.py        # Unit tests for each detection rule
├── requirements.txt
└── README.md
```

---

## Skills Demonstrated

`Python` · `Threat Detection` · `Log Analysis` · `Okta` · `Azure AD` · `AWS CloudTrail` · `MITRE ATT&CK` · `Identity Security` · `UEBA` · `Incident Response`

---

## Author

**Harshith Shiva** — Cybersecurity Engineer  
[LinkedIn](https://linkedin.com/in/YOUR-LINKEDIN) · [Portfolio](https://YOUR-PORTFOLIO-URL)
