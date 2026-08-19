# Windows 4625 Authentication Detection Lab

## Overview

This project demonstrates a SOC detection and investigation workflow for repeated Windows failed authentication events using Windows Security logs and Splunk Enterprise in a VirtualBox-based home lab.

The primary analytic detects repeated **Windows Event ID 4625** failures and generates a Splunk alert when the threshold is reached.

During investigation, the lab produced repeated failed authentication attempts against the `Soc admin` account from `127.0.0.1`. The evidence confirmed incorrect-password authentication failures but did not establish a true multi-account password-spraying attack.

## Objectives

* Build a Windows-based SOC home lab
* Configure Windows Security logging
* Forward Windows events to Splunk
* Detect repeated failed authentication events
* Configure and validate a scheduled Splunk alert
* Investigate Event ID 4625 activity
* Analyze authentication status and substatus codes
* Investigate the responsible Windows process and service
* Map the observed behavior to MITRE ATT&CK
* Document the investigation as a SOC incident report

## Lab Environment

| Component        | Details                   |
| ---------------- | ------------------------- |
| SIEM             | Splunk Enterprise 10.4.2  |
| Endpoint         | Windows 11                |
| Hostname         | `Hacker`                  |
| Virtualization   | VirtualBox                |
| Linux Lab System | Kali Linux                |
| Windows Event    | 4625                      |
| Index            | `main`                    |
| Sourcetype       | `XmlWinEventLog:Security` |

## Detection Logic

The detection searches Windows Security events for Event ID 4625, extracts the source IP and target username, counts failed attempts, and assigns a severity based on the number of failures.

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

## Alert Configuration

**Alert:** Repeated Windows Failed Authentication Detection — Event ID 4625

**Type:** Scheduled

**Schedule:** Every minute

**Search Window:** Last 5 minutes

**Trigger Condition:** Number of Results > 0



**Action:** Add to Triggered Alerts

The alert was successfully validated and generated trigger history during testing.

## Investigation Findings

The historical investigation identified:

| Finding                             | Result                            |
| ----------------------------------- | --------------------------------- |
| Total Event ID 4625 events observed | 45                                |
| Source IP                           | `127.0.0.1`                       |
| Target account                      | `Soc admin`                       |
| Unique targeted accounts            | 1                                 |
| Logon Type                          | `2`                               |
| Process                             | `C:\Windows\System32\svchost.exe` |
| Process ID                          | `1496` (`0x5d8`)                  |
| Associated service                  | `UserManager`                     |
| Authentication package              | `Negotiate`                       |
| Status                              | `0xc000006d`                      |
| SubStatus                           | `0xc000006a`                      |
| Incorrect-password events           | 40                                |

The `0xc000006a` substatus is consistent with an incorrect-password condition.

## Attack Timeline

The investigation identified repeated bursts of failed authentication activity:

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

## Analyst Assessment

The original analytic was named **Password Spray Detection - Windows 4625**.

However, the investigation showed:

* Only one account was targeted.
* The source address was `127.0.0.1`.
* The activity originated locally in the laboratory.
* No successful compromise was demonstrated.
* The associated process was `svchost.exe`.
* The process was hosting the legitimate `UserManager` service.

Therefore, the evidence supports:

**Repeated local failed authentication / password-guessing-like activity.**

It does **not** provide sufficient evidence to claim a confirmed external password-spraying attack.

## MITRE ATT&CK

| Technique                      | ID        | Assessment    |
| ------------------------------ | --------- | ------------- |
| Brute Force: Password Guessing | T1110.001 | Applicable    |
| Brute Force: Password Spraying | T1110.003 | Not confirmed |
| Valid Accounts                 | T1078     | Not confirmed |

## Evidence

Screenshots collected during the investigation:

* Splunk alert configuration
* Splunk investigation results
* Splunk alert trigger history
* Event ID 4625 investigation results

See the `screenshots/` directory.

## Incident Report

The complete investigation report is available at:

[`reports/Incident-Report.md`](reports/Incident-Report.md)

## Repository Structure

```text
SOC-Analyst-Portfolio/
├── architecture/
│   └── Architecture.md
├── attack/
│   └── Password-Spray.md
├── detections/
│   ├── sigma/
│   │   └── Windows-4625-Failed-Logon.yml
│   ├── splunk/
│   │   └── Password-Spray-Detection.spl
│   └── wazuh/
│       └── windows-4625-failed-logon.xml
├── lab/
│   ├── Kali-Setup.md
│   ├── Networking.md
│   ├── VirtualBox-Setup.md
│   └── Windows11-Setup.md
├── reports/
│   └── Incident-Report.md
├── screenshots/
│   ├── splunk-alert-config.png
│   └── splunk-alert-investigation.png
├── LICENSE
└── README.md
```

## Skills Demonstrated

* SOC monitoring
* Detection engineering
* Splunk SIEM
* Windows Event Log analysis
* Alert configuration and validation
* Incident investigation
* Authentication failure analysis
* Process and service investigation
* MITRE ATT&CK mapping
* Incident documentation

## Lessons Learned

This project demonstrates the SOC workflow:

**Detect → Alert → Investigate → Correlate → Validate → Classify → Document**

The key lesson is to validate the evidence behind an alert rather than relying only on the alert name.
