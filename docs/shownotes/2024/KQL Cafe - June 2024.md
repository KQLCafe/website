# KQL Cafe - June 2024

## Recording and Presentation

- [Recording]()
- [Presentation](/./docs/Presentations/KQL%20Cafe%20-%20June%202024.pdf)

## Hosts

- [Gianni](https://twitter.com/castello_johnny)
- [Alex](https://twitter.com/alexverboon)

## Guests

- [Michalis Michalos](https://www.linkedin.com/in/mmihalos/)

## News

- [Analyze data using Log Analytics Simple mode (Preview)](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/log-analytics-simple-mode)
- [Microsoft Defender for Endpoint Advanced Hunting and Application Control for Business – WDACConfig](https://www.youtube.com/watch?app=desktop&si=tJbFbzRJNy79lUo7&v=oyz0jFzOOGA&feature=youtu.be)
- [Detect suspicious processes running on hidden desktops](https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/detect-suspicious-processes-running-on-hidden-desktops/ba-p/4072322)
- [Audit Defender XDR Activities](https://kqlquery.com/posts/audit-defender-xdr/)

- [Microsoft Employee Submitted Queries](https://github.com/KQLMSPress/definitive-guide-kql/tree/main/Extra%20Microsoft%20Employee%20Submitted%20Queries)

Monitoring Cosmos DB's request unit consumption.
Identifying top N queries by consumption in Cosmos DB.
Checking for requests that are throttled in Cosmos DB.
Checking for antivirus exclusions.
Identifying applications using auto proxy (WPAD).
Detecting changes to evade detection.
Analyzing Microsoft Graph API usage patterns.
Analyzing traffic patterns to Microsoft Graph APIs.
Monitoring ID Governance in Microsoft Entra for usage patterns.
Visualizing authentication method use over time.
Understanding administrative activities.
Monitoring short-lived connections in PostgreSQL.
Monitoring failed login attempts in PostgreSQL.
Resource utilization monitoring in PostgreSQL.
Summarizing sign-ins via iOS and macOS SSO Extensions.
Searching for MFA phone number changes using regex.
Tracking dynamic group membership changes.
Session breakdown by legacy vs modern TLS.
Understanding email authentication patterns for security.
Monitoring token protection impact and managing conditional access.
Analyzing Intune device management events and enrollments.
Monitoring failed operations and sign-in events.
Network traffic monitoring.
Identity governance operations.
Detecting suspicious activities and anomalies.
Identifying vulnerabilities and attack surfaces via IP range and CVE ID tracking.
Detecting administrative actions and user re-enabling.
High-risk sign-in patterns detection.
Reporting on antimalware versions.
Detecting email anomalies.
Performance troubleshooting for SQL servers.
Monitoring conditional access policy applications and failures

## Our Guest

Our guest [Michalis Michalos](https://www.linkedin.com/in/mmihalos/) spoke about Defender for Endpoint and WSL.

[Keeping an eye on WSL through Microsoft Defender for Endpoint](https://www.michalos.net/2024/06/25/keeping-an-eye-on-wsl-through-microsoft-defender-for-endpoint/)

Identify endpoints that run WSL and/or MDE plug-in
First things first, let’s identify endpoints that users run WSL with the following KQL:

```kql
DeviceProcessEvents
| where ActionType has "ProcessCreated"
| where ProcessVersionInfoOriginalFileName has "wsl.exe"
| where ProcessVersionInfoFileDescription has "Windows Subsystem for Linux"
| summarize by DeviceName
```

You can also identify which of your endpoints already have the MDE plug-in:

```kql
DeviceTvmSoftwareInventory
| where SoftwareName has "microsoft_defender_for_endpoint_plug-in_for_wsl"
| summarize by DeviceName
```

Joining forces from the queries above, you can identify endpoints running WSL but don’t have the plug-in installed:

```kql
let WSLDevices = DeviceProcessEvents
| where ActionType has "ProcessCreated"
| where ProcessVersionInfoOriginalFileName has "wsl.exe"
| where ProcessVersionInfoFileDescription has "Windows Subsystem for Linux"
| project DeviceName;
WSLDevices
    | join kind=leftanti (DeviceTvmSoftwareInventory
    | where SoftwareName has "microsoft_defender_for_endpoint_plug-in_for_wsl"
    | project DeviceName
) on DeviceName
```

A simple hunt to begin with could be the following, looking for reconnaissance  activity:

```kql
let WSLSuspicousList = dynamic(["whoami", "uname", "find", "grep", "cron -l", "/etc/shadow", "/etc/passwd", "/etc/sudoers", "w"]); 
let TimeFrame = 30d; // Choose the best timeframe for your investigation
DeviceInfo
    | where RegistryDeviceTag has "WSL2"
    | project DeviceId
| join ( DeviceProcessEvents
    | where Timestamp > ago(TimeFrame)
    | where ActionType == "ProcessCreated"
    | where ProcessCommandLine has_any (WSLSuspicousList)
    | project TimeGenerated, WSLDeviceID = DeviceId, DeviceName, FileName, FolderPath, ProcessId, ProcessCommandLine, AccountDomain, AccountName
    )
on $left.DeviceId == $right.WSLDeviceID
| sort by TimeGenerated desc
```
Check out the above referenced blog post for more KQL for WSL.

## What did you do with KQL this month

### Monitor Azure Automation Account Runbooks

```kql
AzureDiagnostics
| where Category == 'JobLogs'
| extend RunbookName = RunbookName_s
| project TimeGenerated,RunbookName,ResultType,CorrelationId,JobId_g
| summarize StartTime = minif(TimeGenerated,ResultType == 'Started'),EndTime = minif(TimeGenerated,ResultType in ('Completed','Failed','Failed')),
Status = tostring(parse_json(make_list_if(ResultType,ResultType in ('Completed','Failed','Stopped')))[0]) by JobId_g,RunbookName
| extend DurationSec = datetime_diff('second', EndTime,StartTime)
| join kind=leftouter (AzureDiagnostics
| where Category == "JobStreams"
| where StreamType_s == "Error"
| summarize TotalErrors = dcount(StreamType_s) by JobId_g, StreamType_s)
on $left. JobId_g == $right. JobId_g
| extend HasErrors = iff(StreamType_s == 'Error',true,false)
| project StartTime, EndTime, DurationSec,RunbookName,Status,HasErrors,TotalErrors,JobId_g
```

### Defender for Endpoint - internet-facing devices

- [Defender for Endpoint - internet-facing devices](https://github.com/alexverboon/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Endpoint/MDE-InternetFacing.md)
