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

!![Microsoft Sentinel SSH failed login investigation](./Linux-Brute%20force.png)

### Analysis
The displayed logs contain repeated failed SSH password attempts involving different usernames, including `root`. These events can be indicators of password guessing or brute-force activity and require further investigation.

### Recommended next steps
- Group failed attempts by source IP and time window.
- Check whether any successful SSH logins followed the failures.
- Review the source IPs and authentication history for suspicious activity.
- Consider blocking confirmed malicious sources through the appropriate security controls.

*This is a learning lab. Conclusions should be based on the observed logs and further validation.*
