# Incident Report — Windows Event ID 4625

## Executive Summary

Splunk detected repeated Windows failed authentication events (Event ID 4625) on the Windows 11 SOC lab host `Hacker`.

The investigation identified 45 Event ID 4625 events involving the same target account, `Soc admin`, and the same source address, `127.0.0.1`.

Further analysis identified 40 events with status `0xc000006d` and substatus `0xc000006a`, indicating incorrect-password authentication failures.

The events were associated with:

* Process: `C:\Windows\System32\svchost.exe`
* Process ID: `1496` (`0x5d8`)
* Service: `UserManager`
* Authentication package: `Negotiate`
* Logon Type: `2`

Because only one username was targeted and the source was localhost (`127.0.0.1`), the evidence does not confirm a true password-spraying attack.

**Final assessment:** Repeated local failed authentication / password-guessing-like activity.

## Detection Details

**Detection Name:** Password Spray Detection - Windows 4625

**Platform:** Splunk Enterprise 10.4.2

**Host:** `Hacker`

**Log Source:** Windows Security Event Log

**Event ID:** `4625`

**Schedule:** Every minute

**Time Range:** Last 5 minutes

**Trigger Condition:** Number of Results > 0

**Action:** Add to Triggered Alerts

The alert successfully generated trigger history during testing.

## Detection SPL

```spl
index=main sourcetype="XmlWinEventLog:Security" host="Hacker" "<EventID>4625</EventID>"
| rex field=_raw "<Data Name='TargetUserName'>(?<target_user>[^<]+)"
| rex field=_raw "<Data Name='IpAddress'>(?<src_ip>[^<]+)"
| stats count as failed_attempts by src_ip target_user
| where failed_attempts >= 3
| eval severity=case(
    failed_attempts >= 10,"High",
    failed_attempts >= 5,"Medium",
    failed_attempts >= 3,"Low"
)
| table src_ip target_user failed_attempts severity
| sort - failed_attempts
```

## Key Findings

| Field                     | Finding                           |
| ------------------------- | --------------------------------- |
| Host                      | `Hacker`                          |
| Event ID                  | `4625`                            |
| Total observed events     | 45                                |
| Source IP                 | `127.0.0.1`                       |
| Target account            | `Soc admin`                       |
| Unique targeted users     | 1                                 |
| Logon Type                | `2`                               |
| Process                   | `C:\Windows\System32\svchost.exe` |
| Process ID                | `1496` (`0x5d8`)                  |
| Service                   | `UserManager`                     |
| Authentication            | `Negotiate`                       |
| Status                    | `0xc000006d`                      |
| SubStatus                 | `0xc000006a`                      |
| Incorrect-password events | 40                                |

## Timeline

The investigation identified repeated bursts of Event ID 4625 failures:

| Date/Time UTC    | Failed Attempts |
| ---------------- | --------------: |
| 2026-08-15 06:21 |               4 |
| 2026-08-15 07:30 |               4 |
| 2026-08-15 07:44 |               3 |
| 2026-08-15 07:56 |               4 |
| 2026-08-16 05:58 |               4 |
| 2026-08-16 06:08 |               3 |
| 2026-08-16 06:16 |               5 |
| 2026-08-16 06:22 |               6 |
| 2026-08-16 06:33 |               4 |
| 2026-08-16 06:48 |               5 |

The latest observed burst occurred around **06:48 UTC on August 16, 2026**.

## Process and Service Investigation

The Event ID 4625 events referenced:

`C:\Windows\System32\svchost.exe`

The process ID was `1496`.

Windows investigation identified the associated service as:

```text
SERVICE_NAME: UserManager
DISPLAY_NAME: User Manager
STATE: RUNNING
START_TYPE: AUTO_START
SERVICE_START_NAME: LocalSystem
BINARY_PATH_NAME: C:\Windows\system32\svchost.exe -k netsvcs -p
```

`UserManager` is a legitimate Windows service.

The investigation therefore does not provide evidence that `svchost.exe` or `UserManager` is malicious.

## Authentication Failure Analysis

The dominant authentication failure was:

```text
Status:    0xc000006d
SubStatus: 0xc000006a
Count:     40
```

The substatus `0xc000006a` corresponds to an incorrect-password condition.

This confirms that the observed 4625 events represent repeated failed password authentication attempts.

## Analyst Assessment

The original analytic was named:

**Password Spray Detection - Windows 4625**

However, investigation showed that the observed activity does not meet the strongest definition of password spraying.

Evidence:

* Only one account was targeted.
* Source IP was `127.0.0.1`.
* The authentication attempts were local.
* The associated process was `svchost.exe`.
* The associated Windows service was `UserManager`.
* No successful compromise was demonstrated.

Therefore:

**Confirmed:** Repeated failed authentication / incorrect-password activity.

**Not confirmed:** External password spraying.

## MITRE ATT&CK Mapping

### T1110.001 — Brute Force: Password Guessing

The repeated incorrect-password attempts against a single account are most appropriately mapped to:

**T1110.001 — Password Guessing**

### T1110.003 — Password Spraying

Not confirmed.

The investigation found only one targeted account, so there is insufficient evidence of password spraying across multiple accounts.

### T1078 — Valid Accounts

Not confirmed.

No successful authentication using valid credentials was identified in the investigated dataset.

## Severity

**Lab Severity: Low to Medium**

Reasons:

* Repeated failed authentication attempts were confirmed.
* The activity targeted one account.
* The source was localhost.
* No successful compromise was demonstrated.
* The associated Windows service is legitimate.
* The activity occurred in a controlled SOC laboratory.

In a production environment, repeated failures against a privileged account would require additional investigation.

## Response and Containment

Recommended production actions:

1. Validate whether the repeated authentication attempts are expected.
2. Identify the application, service, or scheduled task generating the failed credentials.
3. Review successful logons for the affected account.
4. Check account lockout events.
5. Review surrounding authentication events for other accounts or source IPs.
6. Reset the account password if unauthorized activity is suspected.
7. Escalate to an account-compromise investigation if a successful logon follows the failed attempts.

No destructive containment action is required for this controlled laboratory exercise.

## Detection Improvements

The detection can be improved by correlating:

* Multiple usernames from one source IP.
* Multiple source IPs targeting one account.
* Failed authentication followed by successful authentication.
* Privileged or sensitive accounts.
* Non-loopback source IPs.
* Account lockout events.
* Time-based thresholds.
* Alert suppression and throttling.

A more accurate name for the current analytic would be:

**Repeated Windows Failed Authentication Detection — Event ID 4625**

A separate analytic should be created for confirmed multi-account password spraying.

## Evidence Collected

The following evidence was collected:

* Splunk detection SPL
* Splunk alert configuration screenshot
* Splunk alert trigger-history screenshot
* Triggered alert result screenshot
* Historical Event ID 4625 search
* One-minute failed-authentication analysis
* Unique-user analysis
* Process investigation
* Windows `UserManager` service verification
* Authentication status/substatus analysis

## Conclusion

The SOC investigation successfully detected and analyzed repeated Windows authentication failures using Splunk.

The evidence identified 45 Event ID 4625 events involving the `Soc admin` account from `127.0.0.1`. Forty events contained the `0xc000006d / 0xc000006a` status combination associated with incorrect-password authentication failures.

The events were associated with the legitimate Windows `UserManager` service hosted by `svchost.exe`.

The investigation demonstrates an important SOC analyst principle:

**An alert name is a detection hypothesis, not the final incident classification.**

**Final classification:** Repeated local failed authentication / password-guessing-like activity; no confirmed external password spray or account compromise demonstrated.

## Lessons Learned

This project demonstrates the SOC workflow:

**Detect → Alert → Investigate → Correlate → Validate → Classify → Document**

The major lesson is to validate the source, targeted accounts, authentication method, process, service, and failure codes before declaring an event to be a password-spray attack.
