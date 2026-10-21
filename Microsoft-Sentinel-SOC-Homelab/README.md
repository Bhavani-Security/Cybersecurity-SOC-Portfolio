# Microsoft Sentinel SOC Homelab

## Project Overview

This project documents my hands-on cybersecurity lab using Microsoft Azure, Microsoft Sentinel and Log Analytics.

The lab focuses on collecting Windows and Linux security logs, investigating authentication activity, writing KQL queries and learning how security alerts can be detected and investigated.

## Lab Environment

- Microsoft Azure
- Windows 11 virtual machine
- Ubuntu Linux virtual machine
- Log Analytics workspace
- Microsoft Sentinel

## Project Objectives

- Understand how security logs are collected and stored.
- Investigate failed login attempts using KQL.
- Practise detecting potential SSH brute-force activity.
- Troubleshoot log collection and ingestion issues.
- Document investigation steps and security recommendations.

## Investigation Results

Findings and screenshots will be added after verifying the results from my lab.

## Disclaimer

This is a hands-on learning project. All findings will be based on my own lab evidence and observations.

## Lab Architecture

The diagram below illustrates the lab's log collection and security monitoring flow.

![Microsoft Sentinel SOC Homelab Architecture](Microsoft%20Sentinel%20SOC%20Homelab%20Architecture-1.png)


## SSH Failed Login Investigation

### Objective
Investigate failed SSH login attempts recorded in Linux Syslog using Kusto Query Language (KQL).

### Query
```kusto
Syslog
| where TimeGenerated > ago(24h)
| where SyslogMessage contains "Failed password"
| project TimeGenerated, Computer, HostIP, SyslogMessage
| order by TimeGenerated desc
```

### Evidence

![Microsoft Sentinel SSH failed login investigation](./Linux-Brute%20force.png)

### Analysis
The displayed logs contain repeated failed SSH password attempts involving different usernames, including `root`. These events can be indicators of password guessing or brute-force activity and require further investigation.

### Recommended next steps
- Group failed attempts by source IP and time window.
- Check whether any successful SSH logins followed the failures.
- Review the source IPs and authentication history for suspicious activity.
- Consider blocking confirmed malicious sources through the appropriate security controls.

*This is a learning lab. Conclusions should be based on the observed logs and further validation.*


### Windows Failed and Successful Login Investigation

**Objective**

Investigate failed and successful Windows logon events in Microsoft Sentinel using Kusto Query Language (KQL).

**Findings**

- Identified nine failed logon events (Event ID 4625) from source IP `117.20.68.46` targeting `windows-vm`.
- The failed attempts involved the account `MicrosoftAccount\cybercxel`.
- The failure status and substatus indicate invalid logon credentials and an incorrect password.
- Successful logon events (Event ID 4624) were also recorded from the same IP address, including Logon Types 3 and 10.

**Evidence**

![Microsoft Sentinel Windows failed and successful login investigation](./image%2820261021-134717%29.png)
**Analysis**

The combination of repeated failed attempts and successful logons from the same IP warrants further investigation. The available evidence does not establish whether the successful logons were authorised or whether the account was compromised.

**Recommended next steps**

- Verify whether the source IP and successful logons are expected.
- Review the account, authentication details and event timeline.
- Investigate related activity on the Windows VM.
- Escalate or contain the activity according to the organisation's incident response procedures if malicious activity is confirmed.

*This is a hands-on learning lab. Findings are based on observed lab logs and require further validation.*

### Additional Investigation

- Correlated failed logons (Event ID 4625) with successful logons (Event ID 4624) from the same source IP, `117.20.68.46`.
- Identified explicit-credential events (Event ID 4648) and process-creation events (Event ID 4688).
- Observed Windows processes including `svchost.exe`, `winlogon.exe` and `wininit.exe`.
- Process command-line details were unavailable through the query because `ProcessCommandLine` was not present in the current `SecurityEvent` schema.

### Conclusion

The combination of repeated failed logons and successful logons from the same source IP warrants further investigation. The available evidence does not confirm account compromise. Further validation of the source IP, authentication activity and endpoint logs would be required.

*This is a hands-on learning lab based on observed logs. Findings are limited to the available evidence.*
