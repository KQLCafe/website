# KQL Cafe - June 2025

## Recording

<!-- Embedded video: script-injected responsive YouTube iframe -->
<div id="ytembed-goiF5qVfV4g" style="position:relative;padding-bottom:56.25%;height:0;overflow:hidden;max-width:100%;">
    <noscript>
        <!-- Fallback for users with JavaScript disabled -->
        <iframe src="https://www.youtube.com/embed/goiF5qVfV4g" title="KQL Cafe - June 2025" style="position:absolute;top:0;left:0;width:100%;height:100%;border:0;" allowfullscreen allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"></iframe>
    </noscript>
</div>

[Watch on YouTube](https://www.youtube.com/watch?v=goiF5qVfV4g)

## Hosts

- [Gianni](https://twitter.com/castello_johnny)
- [Alex](https://twitter.com/alexverboon)

## Guests

- [Thomas Naunheim](https://www.linkedin.com/in/thomasnaunheim/)

## KQL News

### Microsoft Defender for Office 365: Two new data tables in Advanced hunting (preview)

Microsoft Defender for Office 365 is introducing two new data tables, CampaignInfo and FileMaliciousContentInfo, in Advanced hunting. Public Preview starts in early June 2025, with General Availability in early July 2025. These tables will help SOC teams investigate email campaigns and malicious files. No admin action is required.

[Reference](https://admin.cloud.microsoft/?login_hint=alex.verboon%40basevision.ch&source=applauncher&ref=MessageCenter/:/messages/MC1088729)

### KQL Benchmark Dashboard

Comprehensive AI evaluation framework testing large language models' ability to generate cybersecurity detection rules using real-world attack scenarios

- [KQLBench](https://kqlbench.com/)

### Detecting Vulnerable Drivers (a.k.a. LOLDrivers) the Right Way Using Microsoft Defender for Endpoint

[Blog](https://academy.bluraven.io/blog/detecting-vulnerable-drivers-using-defender-for-endpoint-kql)

### Top 10 KQL Queries Every Detection Engineer Should Know

By Sergio Albea

1. Detecting Potential DLL Hijacking Cases
2. Identify differences between EntraID user phone number & its MFA authentication number
3. Identify communication at risk due to encryption algorithm ciphers in use
4. Anonymous access to files by Suspicious IP Addresses
5. Identifying methods used to establish secure communication over insecure channels
6. Suspicious SSH connection inspections
7. Detect PnP devices connected to your endpoint machines
8. Classifying HTTP status codes pivot table query
9. Spotting malicious ISPs through activity monitoring
10. Devices with External RDP Connections

[Blog](https://www.anvilogic.com/detection-voyagers/top-10-kql-queries-every-detection-engineer-should-know#suspicious-ssh-connection-inspections)

### Understanding Query Performance in Kusto: Beyond Results to Resource Insights

By Henning Rauch

[Blog](https://www.linkedin.com/pulse/understanding-query-performance-kusto-beyond-results-resource-rauch-fg69c/)

## Guest Thomas Naunheim

[Thomas Naunheim](https://www.linkedin.com/in/thomasnaunheim/)

***EntraOps Classification and Automation***

- [EntraOps Classification Files](https://github.com/cloud-architekt/azureprivilegediam)
- [Community Project “EntraOps”](https://www.entraops.com)

***Session about Thomas’ Enterprise Access Model***

- [“Defending Tier 0: Taking Control of Your Cloud's Control Plane”](https://www.youtube.com/watch?v=pVPEieHtOVM)

***KQL Functions***

- [PrivilegedIdentityInfo](https://github.com/Cloud-Architekt/AzureSentinel/blob/main/Functions/PrivilegedIdentityInfo.yaml)
- [WorkloadIdentityInfoXdr](https://github.com/Cloud-Architekt/AzureSentinel/blob/main/Functions/WorkloadIdentityInfoXdr.yaml)
- [UnifiedIdentityInfoXdr](https://github.com/Cloud-Architekt/AzureSentinel/blob/main/Functions/UnifiedIdentityInfoXdr.yaml)

***Hunting Queries***

- [SensitiveMicrosoftGraphDelegatedPermissionAccess](https://github.com/Cloud-Architekt/AzureSentinel/blob/main/Hunting%20Queries/EID-PrivilegedIdentities/SensitiveMicrosoftGraphDelegatedPermissionAccess.kusto)
- [SummaryOfPrivilegedOperationsByDirectoryRoleMember](https://github.com/Cloud-Architekt/AzureSentinel/blob/main/Hunting%20Queries/EID-PrivilegedIdentities/SummaryOfPrivilegedOperationsByDirectoryRoleMember.kusto)
- [RecentAddedPrivileges](https://github.com/Cloud-Architekt/AzureSentinel/blob/main/Functions/RecentAddedPrivileges.yaml)

## Learn KQL

## What did you do with KQL this month?

### Microsoft Office 365 - Version History Information

By [Alex](https://twitter.com/alexverboon)

Use this KQL query to retreive information about your Microsoft Office installations across MDE managed devices. The query joins endpoint inventory data with public Office update history feed data. The query extend the MDE Software Inventory data with the following information:

- Office deployment Channel
- Release Date
- The total # of months the release was supported until its EOS date
- The total of months since the release of the appropriate version.

```kql
let officeversionhistory = (externaldata(ReleaseDate:datetime , Channel:string, Version:string,Build:string)[@'https://raw.githubusercontent.com/alexverboon/Feeds/refs/heads/main/data/office_update_history_2018-present.csv']
with (format="csv", ignoreFirstRecord=true));
DeviceTvmSoftwareInventory
| where SoftwareVendor contains "microsoft"
| where SoftwareName == 'office'
| project DeviceName, SoftwareName, SoftwareVersion, EndOfSupportDate, EndOfSupportStatus
| extend Shortbuild = strcat_array(array_slice(split(SoftwareVersion, "."), 2, -1), ".")
| extend EndOfSupportDate = todatetime(format_datetime(EndOfSupportDate, 'yyyy-MM-dd'))
| join kind=leftouter (officeversionhistory
| extend ReleaseDate = todatetime(format_datetime(ReleaseDate, 'yyyy-MM-dd'))
)
on $left. Shortbuild == $right.Build
| extend MnthsSupported = datetime_diff('month', EndOfSupportDate, ReleaseDate)
| extend MonthsSinceRelease = datetime_diff('month',now(),ReleaseDate)
| summarize TotalDevices = dcount(DeviceName,4) by SoftwareName, SoftwareVersion, EndOfSupportDate,EndOfSupportStatus, Shortbuild, ReleaseDate,Channel, Version, Build,MnthsSupported,MonthsSinceRelease
```

[Reference](https://github.com/alexverboon/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Endpoint/TVM/MDE-Office365VersionHistory.md)

### EntraID - Privileged Identity Management - Role Settings Changes

By [Alex](https://twitter.com/alexverboon)

Use the below query to retrieve EntraID - Privileged Identity Management - Role & Group Settings Changes

```kql
AuditLogs
| where Category == "RoleManagement" or Category == "GroupManagement"
| where OperationName == "Update role setting in PIM"
| extend userPrincipalName = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend Role = case(
    Category == 'RoleManagement',tostring(TargetResources[0].displayName),
    "")
| extend Group = case(
    Category  == "GroupManagement", tostring(TargetResources[2].displayName),
    "")
| mv-apply item = AdditionalDetails on (
    where tostring(item.key) == "ipaddr"
    | extend ipaddr = tostring(item.value)
    )
| extend geo_ip = tostring(geo_info_from_ip_address(ipaddr))
| sort by TimeGenerated asc 
| sort by TimeGenerated asc 
| extend ChangedSettings = replace("Setting changes in this session: ", "", tostring(ResultReason))
| extend ModifiedSettings = extract_all(@"(.*?)\.", ChangedSettings)
| project-away ChangedSettings
| project
    TimeGenerated,
    Role,
    Group,
    ResultReason,
    ModifiedSettings,
    userPrincipalName,
    Identity,
    ipaddr,
    geo_ip,
    CorrelationId
```

[Reference](https://github.com/alexverboon/Hunting-Queries-Detection-Rules/blob/main/Entra%20ID/EntraID-PIMRoleSettingChanges.md)
