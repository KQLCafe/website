# KQL Cafe - Month Year

## Recording

- [Recording](https://www.youtube.com/watch?v=19-LwFtm_s4)

## Hosts

- [Gianni](https://twitter.com/castello_johnny)
- [Alex](https://twitter.com/alexverboon)

## Guests

- [Yoan Schinck](https://www.linkedin.com/in/yoan-schinck-740b6a122/)

## KQL News

### Microsoft Vulnerable Driver Block Lists

Mehmet Ergene | @Cyb3rMonk | Blue Raven Academy

Microsoft no longer provides the vulnerable driver block list in a browsable web page; instead, the list is only available as a downloadable ZIP file. 

- [Source](https://github.com/Cyb3r-Monk/Microsoft-Vulnerable-Driver-Block-Lists?tab=readme-ov-file)
- [Microsoft Recommended Driver Block List](https://github.com/Cyb3r-Monk/Threat-Hunting-and-Detection/blob/main/Defense%20Evasion/Microsoft%20Recommended%20Driver%20Block%20List.md)

This project automates the process of downloading the latest VulnerableDriverBlockList ZIP file, extracting and parsing the SiPolicy_Enforced.xml file, and transforming the data into CSV and JSON formats for easy integration with SIEM and other security tools.

### Azure Detection Rules (Azure Arc / VM)

Robbe Van den Daele

- [Source](https://github.com/HybridBrothers/Hunting-Queries-Detection-Rules/tree/main/Azure)

### Must Learn KQL: Advanced Edition

Rod Trent

- [Source](https://rodtrent.substack.com/p/announcing-the-release-of-must-learn)

### Hunt for threats using the hunting graph

Microsoft

The hunting graph provides visualization capabilities in advanced hunting by rendering threat scenarios as interactive graphs. This feature allows security operations center (SOC) analysts, threat hunters, and security researchers conduct threat hunting and incident response easily and more intuitively, improving their efficiency and ability to assess possible security issues.

- [Hunt for threats using the hunting graph (Preview)](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-graph)

### PowerShell | Kusto Schema Tools

Laurie Rhodes (Will join us in the KQL Café Session in March 2026)

A collection of PowerShell based Kusto Schema Tools with the community. The tools are written to managing data interchange between Azure Data Explorer (ADX), EventHouse and Microsoft Sentinel.

- [PowerShell Kusto Schema Tools](https://github.com/LaurieRhodes/Powershell-Kusto-Schema-Tools)

### DisruptionAndResponseEvents (Preview)

Microsoft

- [DisruptionAndResponseEvents (Preview)](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-disruptionandresponseevents-table)

### CloudStorageAggregatedEvents (Preview)

Microsoft

- [CloudStorageAggregatedEvents (Preview)](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudstorageaggregatedevents-table)
- [What's new in Defender for Cloud features](https://docs.azure.cn/en-us/defender-for-cloud/release-notes)

The new CloudStorageAggregatedEvents table is now available in Microsoft Defender XDR’s Advanced Hunting experience. It brings aggregated storage activity logs, such as operations, authentication details, access sources, and success/failure counts, from Defender for Cloud into a single, queryable schema. The aggregation reduces noise, improves performance, and provides a high-level view of storage access patterns to support more effective threat detection and investigation.

This advanced hunting table is populated by records from Microsoft Defender for Cloud. If your organization doesn't have Microsoft Defender for Cloud, queries that use the table aren’t going to work or return any results.

### UserActivityByRevokedTokens Function

Thomas Naunheim

- [UserActivityByRevokedTokens.func](https://github.com/Cloud-Architekt/AzureSentinel/blob/main/Hunting%20Queries/EID-TokenHunting/UserActivityByRevokedTokens.func)

## Guest

- [Yoan Schinck](https://www.linkedin.com/in/yoan-schinck-740b6a122/)
- [SecurityAura GitHub](https://github.com/SecurityAura)

## Learn KQL

### Convert timestamps in KQL

```kql
let Times = datatable(Description:string, String:string)[
    "ISO 8601 (basic)", "20251025T180000Z",
    "ISO 8601 (extended, Z)", "2025-10-25T18:00:00Z",
    "ISO 8601 (extended, +00:00)", "2025-10-25T18:00:00+00:00",
    "ISO 8601 (basic + ms)", "20251025T180000.000Z",
    "ISO 8601 (extended + ms)", "2025-10-25T18:00:00.000Z",
    "RFC 1123 / HTTP-date (GMT)", "Sat, 25 Oct 2025 18:00:00 GMT",
    "RFC 5322 (email, numeric offset)", "Sat, 25 Oct 2025 18:00:00 +0000",
    "RFC 850 (obsolete HTTP-date)", "Saturday, 25-Oct-25 18:00:00 GMT",
    "RFC 822 (2-digit year, GMT)", "Sat, 25 Oct 25 18:00:00 GMT",
    "HTTP-date (RFC 7231)", "Sat, 25 Oct 2025 18:00:00 GMT",
    "POSIX ctime()/asctime()", "Sat Oct 25 18:00:00 2025",
    "Apache/Nginx log", "[25/Oct/2025:18:00:00 +0000]",
    ".NET round-trip (O)", "2025-10-25T18:00:00.0000000Z",
    "Sortable (s)", "2025-10-25T18:00:00",
    "Universal sortable (u)", "2025-10-25 18:00:00Z",
    "Unix epoch (seconds)", "1761415200",
    "Unix epoch (milliseconds)", "1761415200000",
    "Unix epoch (microseconds)", "1761415200000000",
    "Unix epoch (nanoseconds)", "1761415200000000000",
    "Windows FILETIME (100-ns since 1601-01-01)", "134058888000000000",
    "Cisco Syslog", "10/25/2025, 6:00:00.000 PM",
];
Times
| extend Test1 = todatetime(String)
| extend Test1Match = case(Test1 == todatetime("20251025180000"),true,false)
| where Test1Match == false 
```

```kql
let Times = datatable(Description:string, String:real)[
    "Unix epoch (milliseconds)", "1761415200000",
    "Unix epoch (microseconds)", "1761415200000000",
    "Unix epoch (nanoseconds)", "1761415200000000000",
];
Times
| extend UnixMilliseconds = unixtime_milliseconds_todatetime(String)
| extend UnixMicroseconds = unixtime_microseconds_todatetime(String)
| extend UnixNanoseconds = unixtime_nanoseconds_todatetime(String)
| extend Test2 = coalesce(UnixMilliseconds, UnixMicroseconds, UnixNanoseconds)
| extend Test2Match = case(Test2 == todatetime("20251025180000"),true,false)
```

```kql
let Times = datatable(Description:string, String:string)[
    "Cisco Syslog", "10/25/2025, 6:00:00.000 PM",
];
Times
| extend Test3 = todatetime(replace_string(String, ", ", " "))
| extend Test3Match = case(Test3 == todatetime("20251025180000"),true,false)
```

```kql
let Times = datatable(Description:string, String:string)[
    "Apache/Nginx log", "[25/Oct/2025:18:00:00 +0000]"
];
Times
| parse String with "[" Day:string "/" Mon:string "/" Year:string ":" HMS:string " " Offset:string "]"
| extend Test4 = todatetime(strcat(Day, " ", Mon, " ", Year, " ", HMS, " ", Offset))
```

```kql
let Times = datatable(Description:string, String:string)[
"Apache/Nginx log", "[25/Oct/2025:18:00:00 +0000]"
];
Times
| extend Test5 = todatetime(replace_regex(
    String,
    @"^\[(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}:\d{2}:\d{2}) ([+\-]\d{4})\]$",
    @"\1 \2 \3 \4 \5"
  ))
```

## What did you do with KQL this month?

### Entra ID - Microsoft Entra Connect Sync Audit Events

Alex Verboon

- [Entra ID - Microsoft Entra Connect Sync Audit Events](https://github.com/alexverboon/Hunting-Queries-Detection-Rules/blob/main/Entra%20ID/EntraID-EntraConnectSyncAuditEvents.md)
- [Collect Microsoft Entra Connect Sync Audit Events](https://medium.com/@verboonalex/collect-microsoft-entra-connect-sync-audit-events-048c8f331e4c)