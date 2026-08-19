# Authentication Attack Simulation

## Purpose

This document records the authentication-failure activity generated in the Windows 11 SOC laboratory and the validation performed in Splunk.

The project was initially designed as a password-spray detection exercise. During investigation, the collected evidence was analyzed to determine whether the observed behavior actually represented password spraying.

## Lab Target

- Host: `Hacker`
- Operating System: Windows 11
- SIEM: Splunk Enterprise 10.4.2
- Relevant Windows Event: `4625`
- Target Account: `Soc admin`
- Source IP: `127.0.0.1`

## Observed Authentication Activity

The lab generated repeated Windows Event ID 4625 failed-logon events.

The investigation identified:

- 45 total observed Event ID 4625 events
- 1 unique targeted account
- Source IP `127.0.0.1`
- Logon Type `2`
- 40 events with status `0xc000006d`
- 40 events with substatus `0xc000006a`

The `0xc000006a` substatus is consistent with an incorrect-password condition.

## Observed Bursts

The following one-minute windows contained at least three failed authentication attempts:

| Date/Time UTC | Failed Attempts |
|---|---:|
| 2026-08-15 06:21 | 4 |
| 2026-08-15 07:30 | 4 |
| 2026-08-15 07:44 | 3 |
| 2026-08-15 07:56 | 4 |
| 2026-08-16 05:58 | 4 |
| 2026-08-16 06:08 | 3 |
| 2026-08-16 06:16 | 5 |
| 2026-08-16 06:22 | 6 |
| 2026-08-16 06:33 | 4 |
| 2026-08-16 06:48 | 5 |

## Process Investigation

The failed authentication events were associated with:

- Process: `C:\Windows\System32\svchost.exe`
- Process ID: `1496` (`0x5d8`)
- Service: `UserManager`
- Service state: Running
- Service account: `LocalSystem`

`UserManager` is a legitimate Windows service.

## Validation in Splunk

The following analytic was used to detect repeated failed authentication attempts:

```spl
index=main sourcetype="XmlWinEventLog:Security" host="Hacker" "<EventID>4625</EventID>"
| rex field=_raw "<Data Name='TargetUserName'>(?<target_user>[^<]+)"
| rex field=_raw "<Data Name='IpAddress'>(?<src_ip>[^<]+)"
| bin _time span=1m
| stats count as failed_attempts by _time src_ip target_user
| where failed_attempts >= 3
| eval severity=case(
    failed_attempts >= 10,"High",
    failed_attempts >= 5,"Medium",
    failed_attempts >= 3,"Low"
)
| table _time src_ip target_user failed_attempts severity
| sort - failed_attempts
```

## Analyst Assessment

The evidence showed:

- Only one account was targeted: `Soc admin`
- Source IP was `127.0.0.1`
- The activity originated locally in the laboratory
- No successful compromise was demonstrated
- The associated process was `svchost.exe`
- The associated Windows service was `UserManager`

The most accurate classification is:

**Repeated local failed authentication / password-guessing-like activity.**

## MITRE ATT&CK

**T1110.001 — Brute Force: Password Guessing**

Applicable because repeated incorrect-password attempts were observed against a single account.

**T1110.003 — Brute Force: Password Spraying**

Not confirmed because only one account was observed.

## Lessons Learned

The exercise demonstrated that a detection alert is a starting point for investigation rather than proof of a specific attack technique.

An analyst should validate:

- Source IP
- Target accounts
- Authentication result
- Failure status and substatus
- Process and service context
- Successful versus failed authentication
- Whether the observed behavior matches the claimed attack technique

This validation prevented the activity from being incorrectly reported as a confirmed password-spraying incident.
