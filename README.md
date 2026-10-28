# Splunk SIEM Detection Lab

A home SOC lab where I build and test detection rules in Splunk, mapped to the MITRE ATT&CK framework.

## Lab setup
- **SIEM:** Splunk Enterprise (local install on Windows)
- **Endpoint telemetry:** Windows Security, System and Application event logs, plus Sysmon
- **Approach:** generate safe test activity on my own machine, confirm the logs appear in Splunk, write a detection, then confirm the alert fires

## Detections

| Detection | MITRE ATT&CK | Log source | Status |
|-----------|--------------|------------|--------|
| [Brute Force - Multiple Failed Logins](Detections/brute-force-4625.md) | T1110 | Windows Security (Event ID 4625) | Done |
| New admin account created | T1136 | Windows Security (Event IDs 4720, 4732) | Planned |
| Suspicious PowerShell | T1059.001 | Sysmon (Event ID 1) | Planned |

## Evidence: brute force detection firing

![Alert triggered](screenshots/01-brute-force-alert-triggered.png)

![Detection results](screenshots/02-brute-force-results.png)

## What I learned
- How to get Windows event logs and Sysmon data into Splunk
- How to write SPL searches that count and filter events
- How to turn a search into a scheduled alert and test that it works
- Why alert tuning matters (thresholds, time windows, allowlists)
