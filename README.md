# SOC-Login-Threat-Monitor
### Splunk Enterprise — Authentication Log Analysis & Threat Detection

![Platform](https://img.shields.io/badge/Platform-Splunk%20Enterprise-orange)
![Status](https://img.shields.io/badge/Project%20Status-Complete-brightgreen)
![Alerts](https://img.shields.io/badge/Alerts%20Configured-3-red)
![Dashboard](https://img.shields.io/badge/Dashboard%20Panels-8-blue)
![Events](https://img.shields.io/badge/Events%20Analysed-253-informational)

---

## Overview

A complete SOC (Security Operations Centre) analyst project built on Splunk Enterprise. This project simulates a real-world threat investigation workflow — from raw log ingestion through to attack detection, dashboard visualisation, automated alerting, geolocation enrichment, and full incident documentation.

The dataset contains authentication log events from a simulated corporate environment. Three attack scenarios were injected and successfully detected using custom SPL queries.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      DATA SOURCES                           │
│   CSV Upload ──► lab-splunk01 ──► index: login_logs         │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│               SPL DETECTION ENGINE                          │
│  Brute Force │ Cred Stuffing │ Password Spray │ Insider     │
│  iplocation enrichment │ Impossible travel detection        │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│         SOC LOGIN THREAT MONITOR DASHBOARD (8 panels)       │
│  Login timeline │ Top IPs │ Fail/success │ Geo map          │
│  Attack detection panels (4 SPL-powered tables)             │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│              AUTOMATED ALERT ENGINE                         │
│  Brute Force (5min) │ Unknown Geo (15min) │ Travel (1hr)    │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│           SOC INCIDENT REPORT + GITHUB PORTFOLIO            │
└─────────────────────────────────────────────────────────────┘
```

---

## Dataset

| Field | Description |
|-------|-------------|
| `timestamp` | Event date and time |
| `username` | Account that attempted login |
| `src_ip` | Source IP address |
| `status` | `success` or `failed` |
| `location` | City associated with the event |

**Base dataset:** 210 events · 8 users · 8 IP addresses · March 1, 2026  
**Simulated attacks added:** 43 events (credential stuffing, password spray, insider threat)  
**Total events analysed:** 253

---

## Project Phases

### Phase 1 — Data import & basic search
- Uploaded `splunk_login_dataset.csv` to Splunk Enterprise
- Configured source type `csv`, host `lab-splunk01`, index `login_logs`
- Ran 4 core SPL queries to establish baseline metrics

```spl
index=login_logs status="failed" | stats count
index=login_logs status="failed" | stats count by src_ip | sort -count
index=login_logs | stats count by username | sort -count
index=login_logs status="failed" | stats count by username src_ip location | sort -count
```

**Result:** 92 failed logins (43.8% failure rate) · Top attacker IP: `203.0.113.45` (19 failures) · Most active user: `alice` (36 events)

---

### Phase 2 — Log correlation & pattern detection
- Correlated username, IP, and location fields together
- Identified alice brute-force burst (10 attempts in 9 minutes)
- Flagged `8.8.8.8` (Google DNS) appearing as a login source — impossible in legitimate traffic
- Detected henry logging in from 6 different cities in one day (impossible travel)

---

### Phase 3 — Visualisations & dashboard

Built 4 chart types and assembled into the **SOC Login Threat Monitor** dashboard:

| Panel | SPL Command | Chart Type |
|-------|-------------|------------|
| Login attempts over time | `timechart count by status` | Line chart |
| Failed logins by IP | `top limit=8 src_ip` | Bar chart |
| Failed vs successful | `stats count by status` | Pie chart |
| Failures by username & location | `chart count by username location` | Column chart |

---

### Phase 4 — Alerts & automated detection

Three production-style alerts configured in Splunk:

#### Alert 1 — Brute force login detection
```spl
index=login_logs status="failed"
| bucket _time span=5m
| stats count by src_ip _time
| where count >= 5
```
- Schedule: `*/5 * * * *` (every 5 minutes)
- Severity: **Critical**

#### Alert 2 — Unknown geolocation login
```spl
index=login_logs status="failed" location="Unknown"
| stats count by username src_ip location
```
- Schedule: `*/15 * * * *` (every 15 minutes)
- Severity: **High**

#### Alert 3 — Impossible travel / multiple source IPs
```spl
index=login_logs
| bucket _time span=1h
| stats dc(src_ip) as ip_count by username _time
| where ip_count >= 4
```
- Schedule: `0 * * * *` (every hour)
- Severity: **Medium**

---

### Phase 5 — Geolocation & IP enrichment

Used Splunk's built-in `iplocation` command to resolve IP addresses to geographic data:

```spl
index=login_logs
| iplocation src_ip
| stats count by Country src_ip
| sort -count
```

**Key finding:** `8.8.8.8` resolved to Google LLC, Mountain View, California — confirming this is a spoofed or misconfigured source IP. The `91.108.4.x` password spray range resolved to **Amsterdam, Netherlands** (Telegram server infrastructure), indicating a sophisticated attacker using cloud infrastructure.

Added choropleth world map panel to dashboard showing attack origin by country.

---

### Phase 6 — Attack simulation & detection

Three real-world attack scenarios were simulated by injecting events into the dataset:

#### Scenario 1 — Credential stuffing
**Pattern:** One IP hitting 10 different usernames within seconds

```
45.33.32.156 → admin, root, administrator, test, guest, user, alice, bob, henry, charlie
All failed · All within 10 seconds · Location: Unknown
```

**Detection query:**
```spl
index=login_logs src_ip="45.33.32.156"
| stats dc(username) as unique_users values(username) as usernames count as total_attempts by src_ip
```
**Result:** `unique_users = 10` · Confirmed credential stuffing

---

#### Scenario 2 — Password spray
**Pattern:** One IP slowly targeting all accounts to avoid lockout

```
91.108.4.x → alice, bob, charlie, david, emma, frank, grace, henry
One attempt per user every 5 minutes · Location: Moscow
```

**Detection query:**
```spl
index=login_logs status="failed"
| bucket _time span=1h
| stats dc(username) as targets values(username) as usernames by src_ip _time
| where targets >= 4
| sort -targets
```
**Result:** Both spray IPs detected targeting all 8 users

---

#### Scenario 3 — Insider threat
**Pattern:** Legitimate user accessing system between 2:00–3:00 AM

```
alice · 192.168.1.22 · success · New York · 02:00–03:00
5 successful authentications outside business hours
```

**Detection query:**
```spl
index=login_logs status="success"
| eval hour=strftime(_time,"%H")
| where hour < "06" OR hour >= "22"
| stats count by username src_ip hour
| sort -count
```
**Result:** alice, henry, charlie all flagged for after-hours access

---

## Security Findings Summary

| ID | Finding | Severity | IP/User |
|----|---------|----------|---------|
| F-001 | Brute-force attack on alice | Critical | 203.0.113.45 |
| F-002 | Credential stuffing campaign | Critical | 45.33.32.156 |
| F-003 | Password spray from Netherlands | High | 91.108.4.x |
| F-004 | After-hours insider access | Medium | alice / 192.168.1.22 |
| F-005 | Spoofed source IP (8.8.8.8) | High | 8.8.8.8 |

---

## Recommendations

1. **Block** `203.0.113.45`, `45.33.32.156`, and `91.108.4.0/24` at the perimeter firewall
2. **Lock** alice's account pending investigation
3. **Enable MFA** for all user accounts — would have neutralised all simulated attacks
4. **Implement account lockout** after 5 failed attempts within 10 minutes
5. **Investigate** `8.8.8.8` appearing as a login source — indicates spoofing or misconfiguration
6. **Expand log ingestion** to include firewall, DNS, and endpoint logs for cross-source correlation

---

## Skills Demonstrated

| Skill | Tool / Method |
|-------|--------------|
| Log ingestion & parsing | Splunk CSV upload, source type configuration |
| Search & investigation | SPL — `stats`, `timechart`, `bucket`, `dc()`, `eval`, `strftime` |
| Pattern correlation | Multi-field `stats count by username src_ip location` |
| Data visualisation | Line, bar, pie, column charts + choropleth map |
| Dashboard building | Splunk Classic Dashboards — 8 panels |
| Automated alerting | Saved searches with cron scheduling |
| Geolocation enrichment | `iplocation` command + IP threat classification |
| Attack simulation | Credential stuffing, password spray, insider threat patterns |
| Incident documentation | Professional SOC incident report (PDF) |

---

## Files in This Repository

```
├── README.md                      ← This file
├── splunk_login_dataset.csv       ← Base dataset (210 events)
├── SOC_Incident_Report.pdf        ← Full incident report
└── queries/
    ├── phase1_basic_search.spl
    ├── phase2_correlation.spl
    ├── phase3_visualisations.spl
    ├── phase4_alerts.spl
    ├── phase5_geolocation.spl
    └── phase6_attack_detection.spl
```

---

## Tools & Environment

- **Platform:** Splunk Enterprise
- **Host:** lab-splunk01
- **Index:** login_logs
- **Language:** SPL (Search Processing Language)
- **Alert scheduling:** Cron expressions
- **Geolocation:** Splunk built-in `iplocation`

---

## About

This project was completed as part of a SOC analyst training programme. It covers the complete threat investigation lifecycle from raw log ingestion to documented incident report — the same workflow used in real-world Security Operations Centres.

---

*Classification: Training / Lab Environment · March 2026*
