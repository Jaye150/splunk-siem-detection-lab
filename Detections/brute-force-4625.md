# Brute Force - Multiple Failed Logins

**MITRE ATT&CK:** T1110 - Brute Force
**Log source:** Windows Security log (Event ID 4625 - failed logon)
**Severity:** Medium

## What this detects
An account with 5 or more failed logins within a 15-minute window, which can indicate password guessing or someone trying to  bruteforce the account.

## Detection query (SPL)
```
index=main source="WinEventLog:Security" EventCode=4625
| stats count by Account_Name
| where count>=5
```

## Alert settings
- Type: Scheduled, runs every 5 minutes (cron `*/5 * * * *`)
- Time range: last 15 minutes
- Trigger: number of results greater than 0
- Action: Add to Triggered Alerts

## How I tested it
I ran 6 login attempts against a non-existent user (`fakeuser`) with a wrong password using `net use`. Splunk raised the alert on its next scheduled run.

## Evidence
- `screenshots/01-brute-force-alert-triggered.png`
- `screenshots/02-brute-force-results.png`

## Notes and tuning
Real environments need an allowlist for service accounts and a higher threshold or longer window to reduce false positives.