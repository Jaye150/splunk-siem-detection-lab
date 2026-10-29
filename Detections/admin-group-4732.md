# Persistence - User Added to Administrators Group

**MITRE ATT&CK:** T1136 - Create Account (and T1098 - Account Manipulation)
**Log source:** Windows Security log (Event ID 4732 - member added to a security-enabled local group)
**Severity:** Medium

## What it detects
A user being added to the local Administrators group. Attackers often do this to keep privileged access to a machine.

## Detection query (SPL)
```
index=main source="WinEventLog:Security" EventCode=4732 Group_Name="Administrators"
| table _time, EventCode, Account_Name, Group_Name
```

## Alert settings
- Type: Scheduled, runs every 5 minutes (cron `*/5 * * * *`)
- Time range: last 15 minutes
- Trigger: number of results greater than 0
- Action: Add to Triggered Alerts

## How I tested it
In an administrator PowerShell window I created a test account and added it to the Administrators group with `net user` and `net localgroup`. Windows logged event 4720 (account created) and two 4732 events (added to Users, then to Administrators). I alerted only on the Administrators one, because the Users event happens automatically for every new account and would cause false alarms. I deleted the test accounts afterwards.

## Evidence
- `screenshots/03-admin-group-alert-triggered.png`
- `screenshots/04-admin-group-results.png`

## Notes and tuning
- The 5-minute schedule with a 15-minute window means one event can trigger the alert several times. Adding a throttle would stop the duplicates.
- In a real environment I would exclude approved admin changes (IT staff, deployment tools) to reduce false positives.