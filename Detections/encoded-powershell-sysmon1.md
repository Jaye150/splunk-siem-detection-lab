# Execution - Encoded PowerShell Command

**MITRE ATT&CK:** T1059.001 - PowerShell, T1027 - Obfuscated Files or Information
**Log source:** Sysmon (Event ID 1 - Process Create)
**Severity:** Medium

## What it detects
PowerShell being started with an encoded command (`-EncodedCommand`, or the shorter `-enc`). Attackers encode commands so the real instructions are hard to read and simple keyword checks miss them.

## Detection query (SPL)
```
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" powershell
| rex "Name='CommandLine'>(?<CommandLine>[^<]+)<"
| where like(lower(CommandLine), "%-enc%")
| table _time, host, CommandLine
```

## How the query works
- Line 1 finds Sysmon events that mention PowerShell.
- Line 2 uses `rex` to pull the command line out of the raw XML, because my Splunk setup did not extract Sysmon fields automatically.
- Line 3 keeps only command lines containing `-enc`. `lower()` is needed because `like` is case-sensitive and the flag is often written `-EncodedCommand`.
- Line 4 shows the time, host and command line.

## Alert settings
- Type: Scheduled, runs every 5 minutes (cron `*/5 * * * *`)
- Time range: last 15 minutes
- Trigger: number of results greater than 0
- Action: Add to Triggered Alerts

## How I tested it
I ran a harmless command (`Write-Output "lab test 2"`), encoded it in Base64, and launched it with `powershell.exe -NoProfile -EncodedCommand`. Sysmon logged the process start and the alert fired on its next scheduled run.

## Evidence
- `screenshots/05-encoded-powershell-alert-triggered.png`
- `screenshots/06-encoded-powershell-results.png`

## What went wrong along the way
My first version searched for `-enc` in lowercase and returned no results, because the real command line contained `-EncodedCommand` with a capital E. Wrapping the field in `lower()` fixed it.

## Notes and tuning
- `%-enc%` can also match harmless options such as `-Encoding`, so a real deployment should match more precisely.
- IT admins and software deployment tools sometimes use encoded commands legitimately, so those should be allowlisted.
- Installing the Splunk Add-on for Sysmon would extract the fields automatically and remove the need for `rex`.
- The 15-minute window overlapping a 5-minute schedule creates duplicate alerts, which a throttle would prevent.