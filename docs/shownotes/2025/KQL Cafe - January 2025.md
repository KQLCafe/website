# KQL Cafe - January 2025

## Recording and Presentation

- [Recording](https://www.youtube.com/watch?v=4tZL5sW-Dbo)

## Hosts

- [Gianni](https://twitter.com/castello_johnny)
- [Alex](https://twitter.com/alexverboon)

## Guests

- [Ian Hanley](https://x.com/IanDHanley)

## KQL News

### KQL Sources - 2025 Update Bert-Jan Pals

What started as a single blog is now becoming a yearly trend. More and more KQL related repositories are created, not only with a focus on security but also Intune, Entra and Azure Monitor related queries. Dive in and discover how these new additions can help you tackle challenges or give you new ideas for the new year.

[KQL Sources](https://kqlquery.com/posts/kql-sources-2025/)

### Intune Device Query - KQL Queries - Ugur Koc

This repository contains a comprehensive collection of KQL (Kusto Query Language) queries specifically designed for Microsoft Intune Device Query. These queries are ready to use and cover various aspects of device management, monitoring, and troubleshooting.

[IntuneDeviceQuery](https://github.com/ugurkocde/IntuneDeviceQuery)

### KQL Blog Posts from Morten Thomsen

1. Understanding KQL: The Basics (November 19, 2024)
2. Time-Based Queries and Functions (November 22, 2024)
3. Advanced Filtering Techniques in KQL (November 26, 2024)
4. KQL Variables to Optimize Your Query (November 29, 2024)
5. Visualizing Data with KQL (December 3, 2024)

[Blog Posts](https://www.mtsec.dk/blog)

### Defender XDR – Advanced Hunting Updates - January 2025

(Preview) In advanced hunting, Microsoft Defender portal users can now use the adx() operator to query tables stored in Azure Data Explorer. You no longer need to go to log analytics in Microsoft Sentinel to use this operator if you are already in Microsoft Defender.

(GA) In advanced hunting, you can now add your frequently used schema tables, functions, queries, and detection rules in the Favorites sections under each tab for quicker access.

(Preview) The Link to incident feature in Microsoft Defender advanced hunting now allows linking of Microsoft Sentinel query results. In both the Microsoft Defender unified experience and in Defender XDR advanced hunting, you can now specify whether an entity is an impacted asset or related evidence.

[Reference](https://learn.microsoft.com/en-us/defender-xdr/whats-new#january-2025)

### Defender for Endpoint - Aggregated reporting

Aggregated reporting addresses constraints on event reporting in Microsoft Defender for Endpoint. Aggregated reporting extends signal reporting intervals to significantly reduce the size of reported events while preserving essential event properties.

Defender for Endpoint reduces noise in collected data to improve the signal-to-noise ratio while balancing product performance and efficiency. It limits data collection to maintain this balance.

With aggregated reporting, Defender for Endpoint ensures that all essential event properties valuable to investigation and threat hunting activities are continuously collected. It does this by extended reporting intervals of one hour, which reduces the size of reported events and enables efficient yet valuable data collection.

When aggregated reporting is turned on, you can query for a summary of all supported event types, including low-efficacy telemetry, that you can use for investigation and hunting activities.

[Reference](https://learn.microsoft.com/en-us/defender-endpoint/aggregated-reporting)

```kql
union DeviceFileEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents
| where ActionType contains "Aggregate"
| summarize count() by ActionType
```

### Living Off The Tunnels IOCS - Jay Kerai

[Query](https://www.kqlsearch.com/query/Living%20Off%20The%20Tunnels%20Iocs&cm5bpz7oo00b9tj0f2peo6wm0)

### Successful network connections towards SpamHaus's DROP ranges, excluding common browsers as client - Alex Teixeira

[Query](https://gist.github.com/inodee/dec2550ae15ba7f0aeca7e911c96db90)

### Detecting 'Paste and Run' malware with KQL - Nathan Webb

[Query]( https://www.linkedin.com/pulse/detecting-paste-run-malware-kql-nathan-webb-89ale/)

## Guest

- [Ian Hanley on Twitter](https://x.com/IanDHanley)
- [Ian Hanley on LinkedIn](https://www.linkedin.com/in/ianhanley/)
- [Website](https://hanleycloudsolutions.com/)
- [Website](https://www.hanley.cloud/)

- [Workspace Transformation Rules](https://www.hanley.cloud/2023-05-10-Workspace-Transformation-Rules/)
- [Powerbi & Log Analytics Workspace](https://www.hanley.cloud/2024-01-19-PowerBI-&-Log-Analytics-Workspace/)

You will find many of the queries demonstrated here: [KQL Repository](https://github.com/EEN421/KQL-Queries)

## Learn KQL

### Parse_Url & Parse_Path

## What did you do with KQL this month?

### Azure DevOps Security - Code Scanning Recommendations

[Query](https://github.com/alexverboon/Hunting-Queries-Detection-Rules/blob/main/AzureDevOps/AzureDevOps%20-%20CodeRecommendations.md)

### Vulnerability Management from TVM to Graph

```kql
let SeverityTable = datatable(Severity:string,ZeroDay:bool,HasExploit:bool,ExploitVerified:bool,DueDate:timespan,Score:int)
[
    "Critical",1,1,1,24h,23,  // Critical (10) + ZeroDay (5) + HasExploit (3) + ExploitVerified (5)
    "Critical",0,1,1,24h,18,  // Critical (10) + HasExploit (3) + ExploitVerified (5)
    "Critical",1,0,1,24h,20,  // Critical (10) + ZeroDay (5) + ExploitVerified (5)
    "Critical",0,0,1,24h,15,  // Critical (10) + ExploitVerified (5)
    "Critical",1,1,0,24h,18,  // Critical (10) + ZeroDay (5) + HasExploit (3)
    "Critical",0,1,0,24h,13,  // Critical (10) + HasExploit (3)
    "Critical",1,0,0,24h,15,  // Critical (10) + ZeroDay (5)
    "Critical",0,0,0,48h,10,  // Critical (10)
    "High",1,1,1,3d,21,       // High (8) + ZeroDay (5) + HasExploit (3) + ExploitVerified (5)
    "High",0,1,1,3d,16,       // High (8) + HasExploit (3) + ExploitVerified (5)
    "High",1,0,1,3d,18,       // High (8) + ZeroDay (5) + ExploitVerified (5)
    "High",0,0,1,5d,13,       // High (8) + ExploitVerified (5)
    "High",1,1,0,5d,16,       // High (8) + ZeroDay (5) + HasExploit (3)
    "High",0,1,0,7d,11,       // High (8) + HasExploit (3)
    "High",1,0,0,7d,13,       // High (8) + ZeroDay (5)
    "High",0,0,0,10d,8,       // High (8)
    "Medium",1,1,1,15d,18,    // Medium (5) + ZeroDay (5) + HasExploit (3) + ExploitVerified (5)
    "Medium",0,1,1,15d,13,    // Medium (5) + HasExploit (3) + ExploitVerified (5)
    "Medium",1,0,1,20d,15,    // Medium (5) + ZeroDay (5) + ExploitVerified (5)
    "Medium",0,0,1,20d,10,    // Medium (5) + ExploitVerified (5)
    "Medium",1,1,0,30d,13,    // Medium (5) + ZeroDay (5) + HasExploit (3)
    "Medium",0,1,0,45d,8,     // Medium (5) + HasExploit (3)
    "Medium",1,0,0,45d,10,    // Medium (5) + ZeroDay (5)
    "Medium",0,0,0,60d,5,     // Medium (5)
    "Low",1,1,1,30d,14,       // Low (3) + ZeroDay (5) + HasExploit (3) + ExploitVerified (3)
    "Low",0,1,1,45d,9,        // Low (3) + HasExploit (3) + ExploitVerified (3)
    "Low",1,0,1,60d,11,       // Low (3) + ZeroDay (5) + ExploitVerified (3)
    "Low",0,0,1,90d,6,        // Low (3) + ExploitVerified (3)
    "Low",1,1,0,90d,11,       // Low (3) + ZeroDay (5) + HasExploit (3)
    "Low",0,1,0,90d,6,        // Low (3) + HasExploit (3)
    "Low",1,0,0,90d,8,        // Low (3) + ZeroDay (5)
    "Low",0,0,0,120d,3,       // Low (3)
    "None",1,1,1,60d,12,      // None (1) + ZeroDay (5) + HasExploit (3) + ExploitVerified (3)
    "None",0,1,1,90d,7,       // None (1) + HasExploit (3) + ExploitVerified (3)
    "None",1,0,1,120d,9,      // None (1) + ZeroDay (5) + ExploitVerified (3)
    "None",0,0,1,180d,4,      // None (1) + ExploitVerified (3)
    "None",1,1,0,180d,9,      // None (1) + ZeroDay (5) + HasExploit (3)
    "None",0,1,0,180d,4,      // None (1) + HasExploit (3)
    "None",1,0,0,180d,6,      // None (1) + ZeroDay (5)
    "None",0,0,0,365d,1       // None (1)
];
ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
| graph-match cycles=none (CVE)-[affecting]->(Device)-[loggedonusers*1..3]->(User)
    where CVE.NodeLabel == "Cve" and 
    affecting.EdgeLabel == "affecting" and
//    not (Device.NodeProperties.rawData.sensorHealthState in("InactiveGoneDark","InactiveRecent")) and
    loggedonusers.EdgeLabel in("has credentials of", "frequently logged in by") and
    User.NodeLabel in("user","serviceprincipal")
    project 
        CveId = CVE.NodeName, 
            Severity = tostring(CVE.NodeProperties.rawData.severity),
            ZeroDay = tobool(CVE.NodeProperties.rawData.isZeroDay),
            HasExploit = tobool(CVE.NodeProperties.rawData.hasExploit),
            ExploitVerified = tobool(CVE.NodeProperties.rawData.isExploitVerified),
            LastModifiedDate = todatetime(CVE.NodeProperties.rawData.lastModifiedDate),
            CvssScore = todouble(tostring(CVE.NodeProperties.rawData.cvssScore)),
        DeviceName = Device.NodeName,
            FirstSeenByInventory = todatetime(Device.NodeProperties.rawData.firstSeenByInventory),
            LastSeen = todatetime(Device.NodeProperties.rawData.lastSeen),
            EntityIds = Device.EntityIds,
            SensorHealthState = tostring(Device.NodeProperties.rawData.sensorHealthState),
            MachineGroup = tostring(Device.NodeProperties.rawData.machineGroup),
            OsPlatformFriendlyName = tostring(Device.NodeProperties.rawData.osPlatformFriendlyName),
            OsVersionFriendlyName = tostring(Device.NodeProperties.rawData.osVersionFriendlyName),
            PublicIP = tostring(Device.NodeProperties.rawData.publicIP),
            IsInternetFacing = tobool(Device.NodeProperties.rawData.isInternetFacing),
            ManualCriticalityLevel = tostring(Device.NodeProperties.rawData.manualCriticalityLevel),
            DeviceRegistryTags = tostring(Device.NodeProperties.rawData.deviceRegistryTags),
        User = User.NodeName
| lookup SeverityTable on Severity, ZeroDay, HasExploit, ExploitVerified
| extend RemeditationExpired = iif(LastModifiedDate + DueDate < now(),1,0)
| where RemeditationExpired == 1
| parse EntityIds with * 'SenseDeviceId","id":"' DeviceId '"' *
| project-away EntityIds
| join hint.shufflekey=DeviceId kind=inner (DeviceTvmSoftwareVulnerabilities | project-keep DeviceId, CveId, SoftwareVendor, SoftwareName, SoftwareVersion) on DeviceId, CveId
| project-away *1
| join hint.shufflekey=DeviceId kind=leftouter (DeviceTvmSoftwareEvidenceBeta) on DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion
| project-away *1
| extend Information = bag_pack_columns(CvssScore, SoftwareVendor, SoftwareName, SoftwareVersion, RegistryPaths, DiskPaths)
| summarize hint.shufflekey=DeviceId Score = sum(Score), CVEs = dcount(CveId), ImportantCVEs = countif(Score >= 13), Evidence = make_set(Information) by FirstSeenByInventory, LastSeen, DeviceId, DeviceName, ManualCriticalityLevel, SensorHealthState, MachineGroup, OsPlatformFriendlyName, OsVersionFriendlyName, PublicIP, IsInternetFacing, DeviceRegistryTags
| extend EvidenceCount = array_length(Evidence)
```

### MFA Fraud Alert Retirement -> Report Suspicious Activity

Microsoft is retiring the MFA Fraud alert in favor of the replacement feature "Report Suspicious Activity" here's a KQL query to detect these events.

[Query](https://github.com/alexverboon/Hunting-Queries-Detection-Rules/blob/main/Entra%20ID/EntraID%20-%20Suspicious%20activity%20reported.md)

### Entra ID - Self Service Password Reset - Configuration Changes

Microsoft has introduced enhanced logging capabilities for Self-Service Password Reset (SSPR) policy configurations. With this update, any change made to the SSPR policy configuration—including enablement, disablement, or modifications—will generate an audit log entry detailing the change.

[Query](https://github.com/alexverboon/Hunting-Queries-Detection-Rules/blob/main/Entra%20ID/EntraID%20-%20SSPR%20Configuration%20Changes.md)
