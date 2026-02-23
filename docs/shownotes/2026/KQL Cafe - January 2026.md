# KQL Cafe - January 2026

## Recording

- [Recording](https://www.youtube.com/watch?v=D9gmDFHRJcU)

## Hosts

- [Gianni](https://twitter.com/castello_johnny)
- [Alex](https://twitter.com/alexverboon)

## Guests

- [Simon Scharschinger](https://www.linkedin.com/in/simonscharschinger/)

## KQL News

### KQL Toolbox Series

[Ian Hanley](https://www.linkedin.com/in/ianhanley/)

- [KQL Toolbox #1 — Track & Price Your Microsoft Sentinel Ingest Costs](https://www.hanley.cloud/2025-12-14-KQL-Toolbox-1-Track-&-Price-Your-Microsoft-Sentinel-Ingest-Costs/)
- [KQL Toolbox #2 — Find Your Noisiest Log Sources (with Cost)](https://www.hanley.cloud/2026-01-05-KQL-Toolbox-2-Find-Your-Noisiest-Log-Sources-(with-Cost-)/)
- [KQL Toolbox #3 — Which Event ID Noises Up Your Logs (and Who's Causing It)](https://www.hanley.cloud/2026-01-10-KQL-Toolbox-3-Which-Event-ID-Noises-Up-Your-Logs-(and-Who-s-Causing-It)/)
- [KQL Toolbox #4 — What Changed? Finding Log Sources with the Biggest Delta in Volume & Cost](https://www.hanley.cloud/2026-01-18-KQL-Toolbox-4-What-Changed-Finding-Log-Sources-with-the-Biggest-Delta-in-Volume-&-Cost/)

### ASIM December 2025 Update Is Now Live

[Ofer Shezaf](https://www.linkedin.com/in/oshezaf/)

Following ASIM reaching General Availability in September, I’m excited to share the completion of the ASIM schema refresh — a major milestone that strengthens Microsoft Sentinel’s normalization framework and sets the stage for next wave of ASIM-driven innovation.

🔗 https://www.linkedin.com/posts/oshezaf_asim-december-2025-update-is-now-live-share-7406309569976705024-YOw1/?utm_source=social_share_send&utm_medium=ios_app&rcm=ACoAAAC3QkMBbeDK3KuZDfKocgA2reApbZVXz2A&utm_campaign=share_via

### Defender XDR – Advanced Hunting

***Microsoft***

The following advanced hunting schema tables are now available for preview:

- **CampaignInfo** table contains information about email campaigns identified by Microsoft Defender for Office 365  
- **FileMaliciousContentInfo** table contains information about files that were processed by Microsoft Defender for Office 365 in SharePoint Online, OneDrive, and Microsoft Teams

### 50+ New Microsoft Teams Protection KQL Queries Available

[Daniel Moses](https://www.linkedin.com/in/daniel-m-b4201664/)

50+ new Microsoft Teams protection-specific KQL queries are now available directly in the Microsoft Defender XDR portal under **Advanced Hunting → Community queries**.

With this update, there are now over **260 Microsoft Defender for Office 365-specific KQL queries** available for threat hunting, custom detections, reporting, and more — all accessible with just a few simple clicks.

🔗 https://www.linkedin.com/posts/daniel-m-b4201664_defenderforoffice365-defenderxdr-kql-activity-7404515404871524355-Ipyd?utm_source=share&utm_medium=member_desktop&rcm=ACoAAAC3QkMBbeDK3KuZDfKocgA2reApbZVXz2A

### Getting to Know MDE

[Kostas Koutroumpouchos](https://www.linkedin.com/in/kkoutrou/)

These blog posts focus on how to use KQL in Advanced Hunting with Microsoft Defender for Endpoint to surface detections and protection events across layers such as ASR, MDAV, exploit protection, and network/web protection. They explain how to interpret the resulting events, map them to the underlying capability that raised them, and use queries to investigate security outcomes and operational behaviors. They also touch on troubleshooting scenarios where KQL helps correlate detections with performance or configuration issues.

- [What is MDE](https://kostaskoutrou.github.io/2025/12/17/what-is-mde.html)
- [Using KQL for MDE](https://kostaskoutrou.github.io/2026/01/06/using-kql-for-mde.html)
- [Performance Troubleshooting MDE](https://kostaskoutrou.github.io/2026/01/17/performance-troubleshooting-mde.html)

### Approximate, partial and combined lookups in Azure Sentinel

[Ofer Shezaf](https://www.linkedin.com/in/oshezaf/)

- [Approximate, Partial, and Combined Lookups in Azure Sentinel](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/approximate-partial-and-combined-lookups-in-azure-sentinel/1393795)

## Guest

- [Simon Scharschinger](https://www.linkedin.com/in/simonscharschinger/)
- [Presentation](/docs/Attachments/KQLCafe%20-%20Jan%202026%20-%20KQL%20as%20a%20Forensic%20Tool.pdf)

## Learn KQL

### max_of

- [max_of](https://learn.microsoft.com/en-us/kusto/query/max-of-function?view=microsoft-fabric)

```kql
Usage
| where TimeGenerated between (startofday(ago(730d)) .. startofday(now()))
| where IsBillable == true
| extend Bytes = toreal(round(Quantity * 1000 * 1000, 0))
| project-rename Tabs = DataType
| where Tabs in (P2)
| summarize TotalIngestedP2GB = round(sum(Bytes) / 1e9, 1) by TimeGenerated = startofday(TimeGenerated)
| join kind=leftouter LakeP2PerDay on TimeGenerated
| extend LakeP2GB = coalesce(LakeP2GB, 0.0)
| extend IngestedP2GB = round(max_of(TotalIngestedP2GB - LakeP2GB, 0.0), 1);
```

## What did you do with KQL this month?

### Calculate Defender for Cloud / Defender for Server Plan 2 ingestion benefits

```kql
let P2Subs = materialize(
    arg("").securityresources
    | where type == "microsoft.security/pricings"
    | where name == "VirtualMachines"
    | where properties.pricingTier == "Standard" and properties.subPlan == "P2"
    | project subscriptionId
);
arg("").resources
| where subscriptionId in (P2Subs)
| where type =~ "microsoft.compute/virtualmachines" or type =~ "microsoft.hybridcompute/machines"
| extend OS = tolower(tostring(properties.storageProfile.osDisk.osType)) // For Azure VMs
| extend ArcOS = tolower(tostring(properties.osName)) // For Arc Servers
| extend OSType = coalesce(OS, ArcOS)
| summarize 
    Total_Servers = count(), 
    Azure_VMs = countif(type =~ "microsoft.compute/virtualmachines"), 
    Arc_Servers = countif(type =~ "microsoft.hybridcompute/machines") 
    by subscriptionId//, OSType
```

### Microsoft Defender for Endpoint - Certificates - DigiCert Global Root G2

- [Query](Microsoft Defender for Endpoint - Certificates - DigiCert Global Root G2)

### Defender for Endpoint - Data Collection Scripts

- [Query](https://github.com/alexverboon/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Endpoint/DataCollection/MDE-DataCollection.md)

### Microsoft Defender for Endpoint - Device Groups

- [Query](https://github.com/alexverboon/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Endpoint/MDE-DeviceGroups.md)
