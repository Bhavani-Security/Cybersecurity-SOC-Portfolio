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

  
## Lab Architecture

The diagram below illustrates the lab's log collection and security monitoring flow.

![Microsoft Sentinel SOC Homelab Architecture](Microsoft%20Sentinel%20SOC%20Homelab%20Architecture-1.png)

## Project Objectives

- Understand how security logs are collected and stored.
- Investigate failed login attempts using KQL.
- Practise detecting potential SSH brute-force activity.
- Troubleshoot log collection and ingestion issues.
- Document investigation steps and security recommendations.

## Investigation Results
The following investigations were performed using Microsoft Sentinel and Log Analytics:

- **Windows authentication:** Investigated failed logon events (Event ID 4625) and reviewed repeated failures.
- **Linux SSH monitoring:** Queried Syslog data and reviewed related SSH security incidents.
- **Azure activity monitoring:** Reviewed Azure Activity Logs for resource operations and configuration changes.
- **Identity monitoring:** Queried Microsoft Entra ID sign-in logs to review authentication activity.
- **Detection rules:** Configured Sentinel analytics rules for SSH brute-force activity and RDP failed logons. The RDP-specific query returned no matching results during testing.

**Outcome:** Practised KQL queries, security log analysis, detection-rule configuration, and incident investigation.




## Azure Infrastructure Setup

I built my cybersecurity lab from scratch in Microsoft Azure.

### Resources Created
- Created an Azure Resource Group to organise lab resources.
- Built a Virtual Network and subnet.
- Configured Network Security Group (NSG) rules.
- Deployed a Windows 11 virtual machine.
- Deployed an Ubuntu Linux virtual machine.
- Created a Log Analytics workspace.
- Installed Azure Monitor Agent on Windows and Linux.


### Azure Resources

The Azure resource group contains the infrastructure used for this lab, including the virtual network, network security group, virtual machines, Log Analytics workspace, and data collection rules.

![Azure infrastructure resources](azure-infrastructure.png)


## Log Collection and Verification

I configured and verified log collection in my Log Analytics workspace to support security monitoring and investigation.

### Azure Activity Logs
- Verified that Azure Activity Logs were available for querying.
- Explored Azure control-plane activities, including resource and configuration changes.


#### Evidence

The Azure Activity Log shows control-plane operations performed during the lab setup, including virtual machine operations, deployments, and data collection rule changes.

![Azure Activity Logs](azure-activity-logs.png)


### Azure Resource Logs
- Configured diagnostic settings for relevant resources.
- Verified that resource logs were arriving in the configured destination.

  
#### Log Analytics Table Verification

Queried the Log Analytics workspace to identify tables containing recent events. The results included Azure activity, diagnostic, Windows security, Linux Syslog, and sign-in log tables.

![Log Analytics table ingestion verification](log-analytics-table-ingestion.png)



## Microsoft Defender and Sentinel Configuration

### Microsoft Defender
- Accessed the Microsoft Defender portal and explored its security monitoring capabilities.
- Verified the Windows and Linux lab environments as part of the security monitoring setup.

### Microsoft Sentinel
- Enabled Microsoft Sentinel for the Log Analytics workspace.
- Explored the Sentinel dashboard and workspace features.
- Configured and explored data connectors.
- Queried collected security logs using Kusto Query Language (KQL).


## Microsoft Sentinel Analytic Rules

I explored how Microsoft Sentinel analytic rules can identify potentially suspicious activity from collected security logs.


### Active Analytic Rules — Evidence

The Sentinel Analytics page shows two enabled analytic rules: RDP Brute Force and SSH Brute Force. Both are configured with Low severity.

![Microsoft Sentinel active analytic rules](sentinel-active-analytic-rules.png)


### 1. RDP Failed Login Attempts
- Objective: Identify repeated failed Remote Desktop Protocol (RDP) login attempts.
- Data source: Windows security events, where available.
- Detection approach: Analyse failed login events, source IP addresses, targeted accounts, and event frequency.
- Investigation: Review the results to determine whether the activity requires further investigation.

### 2. Microsoft Entra ID Sign-in Monitoring

**Objective:** Monitor authentication activity and identify potentially suspicious sign-in patterns.

**Data source:** Microsoft Entra ID sign-in logs (`SigninLogs`).

**KQL Query**

```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| project TimeGenerated,
          UserPrincipalName,
          AppDisplayName,
          IPAddress,
          ResultType,
          ResultDescription
| order by TimeGenerated desc
```

**Findings**

- Retrieved sign-in records from the Log Analytics workspace.
- Observed successful sign-ins where `ResultType == 0`.
- Reviewed activity involving Azure Portal and Microsoft 365 Security and Compliance Center.

**Analysis**

The query provides visibility into sign-in timestamps, user accounts, applications, source IP addresses and authentication results. Successful authentication alone does not confirm whether activity is legitimate or suspicious.

**MITRE ATT&CK**

- **T1078 — Valid Accounts:** Relevant when investigating suspected misuse of legitimate accounts. The query alone does not establish this technique occurred.

**Recommended Actions**

- Review unfamiliar source IP addresses and unusual authentication patterns.
- Investigate failed sign-ins and correlate them with successful sign-ins.
- Review related alerts and incidents in Microsoft Defender when available.
- Validate suspicious activity before concluding that an account is compromised.


### 3. Impossible Travel Detection

**Objective:** Identify successful sign-ins from geographically distant locations within a short time period that may indicate compromised credentials.

**Data Source:** Microsoft Entra ID sign-in logs (`SigninLogs`).

**Detection Approach:** Compare consecutive successful sign-ins for the same user, reviewing location differences and timestamps to identify potentially suspicious activity.

#### KQL Query

```kusto
// Identify consecutive successful sign-ins from different locations
// within a short time window for the same user.
SigninLogs
| where TimeGenerated > ago(6h)
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location
| sort by UserPrincipalName asc, TimeGenerated asc
| serialize
| extend PrevLocation = prev(Location),
         PrevTime = prev(TimeGenerated),
         PrevUser = prev(UserPrincipalName)
| where UserPrincipalName == PrevUser
| where Location != PrevLocation
| extend TimeDiffMinutes =
    datetime_diff('minute', TimeGenerated, PrevTime)
| where TimeDiffMinutes > 0 and TimeDiffMinutes < 60
| where isnotempty(Location) and isnotempty(PrevLocation)
| project UserPrincipalName,
          FirstLocation = PrevLocation,
          FirstTime = PrevTime,
          SecondLocation = Location,
          SecondTime = TimeGenerated,
          MinutesBetween = TimeDiffMinutes,
          IPAddress
```

#### Detection Logic

- Review successful sign-ins (`ResultType == 0`).
- Compare consecutive sign-ins for the same user.
- Identify different recorded locations within 60 minutes.
- Review the source IP addresses and timestamps for further investigation.

#### MITRE ATT&CK Mapping

- **T1078 — Valid Accounts:** Relevant when investigating suspected misuse of legitimate accounts. This query does not confirm that the technique occurred.

#### Tuning and Limitations

- A different recorded location within 60 minutes is only a preliminary indicator.
- The query does not calculate geographical distance or actual travel speed.
- VPNs, proxies, mobile networks and inaccurate geolocation can produce misleading results.
- The query compares consecutive records and should be validated against the available sign-in data.

#### Recommended Actions

- Validate the source IP addresses and recorded locations.
- Review related sign-in activity and available identity-risk alerts.
- Consider legitimate explanations such as VPN usage.
- Investigate further before concluding that an account is compromised.

**Result Status:** Detection logic documented. No confirmed impossible-travel incident is claimed.

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

### Windows Failed and Successful Login Investigation

**Objective**

Investigate failed and successful Windows logon events in Microsoft Sentinel using Kusto Query Language (KQL), including explicit-credential use and process-creation activity.

**Query**
```kusto
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4624, 4625, 4648, 4688)
| where Computer contains "windows-vm"
| project TimeGenerated, EventID, Computer,
          Account, IpAddress, LogonType, Activity
| order by TimeGenerated desc


**Findings**

- Identified 106 failed Windows logon events (Event ID 4625) targeting windows-vm over seven days.
- The failed logon events involved the account or accounts recorded in Windows Security logs.
- Failure status and substatus indicated invalid logon credentials or an incorrect password.
- Successful logon events (Event ID 4624) included Logon Types 3 and 10.
- Logon Type 3 represents a network logon.
- Logon Type 10 represents a remote interactive logon, commonly associated with Remote Desktop Protocol (RDP).
- Additional events included explicit-credential use (Event ID 4648) and process creation (Event ID 4688).
- Observed Windows processes included `svchost.exe`, `winlogon.exe` and `wininit.exe`.


**Analysis**

The repeated failed logon events indicate potential password-guessing activity. Successful logons were also recorded in the investigation results, so the authentication timeline requires further review. These findings alone do not confirm unauthorised access or account compromise.


**Recommended Next Steps**

- Verify whether the source IP addresses and successful logons are expected.
- Review the affected accounts and authentication timeline.
- Investigate related activity on the Windows VM.
- Confirm whether process command-line logging is enabled and available.
- Escalate or contain the activity according to incident response procedures if malicious activity is confirmed.


**MITRE ATT&CK Mapping**

- **T1110 — Brute Force:** Relevant when investigating repeated authentication failures.
- **T1078 — Valid Accounts:** Relevant when investigating possible misuse of legitimate accounts.


These mappings describe investigation context; the available events do not confirm that either technique occurred.
## Investigation Approach and Lessons Learned


### Security Investigation Workflow

- **Log validation:** Confirmed that Windows, Linux, Azure Activity and Entra ID sign-in data were available for querying.
- **Evidence-based investigation:** Used KQL to filter events, group failed logons and examine authentication activity.
- **Detection development:** Configured Sentinel analytics rules for selected Windows and Linux authentication scenarios.
- **Incident assessment:** Reviewed available alerts and investigated repeated authentication failures without assuming every failure was malicious.
- **Investigation documentation:** Recorded the query logic, observed findings, limitations and recommended follow-up actions.


### Key Lessons Learned

- A high number of failed logons is a signal to investigate, not proof of an attack.
- Event IDs and logon types must be interpreted correctly before identifying an attack technique.
- Successful sign-ins should be correlated with timestamps, source IPs, account activity and available alerts.
- Detection queries must be tested against actual telemetry; a configured rule does not guarantee that an alert will trigger.
- Troubleshooting log ingestion requires checking each stage, from the data source through collection and workspace ingestion.


### Project Outcome

This hands-on lab provided practical experience with Azure infrastructure, Microsoft Sentinel, Log Analytics, KQL-based investigation, analytics-rule configuration and security troubleshooting.

## Disclaimer

This is a hands-on learning project. All findings will be based on my own lab evidence and observations.
