
# Hello from Down Under

Date: 22. February 2022

**Hosts**
- [Gianni](https://twitter.com/castello_johnny)
- [Alex](https://twitter.com/alexverboon)

**Guest**
[Matt Zorich](https://twitter.com/reprise_99)

**Show Content**
- [Show Presentation](https://github.com/KQLCafe/website/blob/gh-pages/Presentations/KQL%20Cafe%20-%20February%202022.pdf)
- [Show Recording](https://www.youtube.com/watch?v=HTCuh-tYLho)

[![Recording](https://img.youtube.com/vi/HTCuh-tYLho/1.jpg)](https://www.youtube.com/watch?v=HTCuh-tYLho)

## Agenda

- Hello again
- KQL Tables | What's new in KQL
- KQL Tools
- Todays guest speaker: Matt Zorich 
- What did you do with KQL this month?
- KQL Challenge of the month

## Hello Again

After our first show in January 2022 we received a lot of positive feedback from the community and Microsoft. 
We welcome everyone to actively participate in the community. We therefore have created KQL Cafe presence across various platforms:

- [Discord Channel](https://discord.gg/V4JWfycSkU)
- [LinkedIn group](https://www.linkedin.com/groups/14053778/)
- [Twitter Community](https://twitter.com/i/communities/1496809036393730050)


## KQL Tables | What's new in KQL

### DeviceTvmSoftwareEvidenceBeta
The DeviceTvmSoftwareEvidenceBeta table in the advanced hunting schema contains data from Threat & Vulnerability Management related to the software evidence section. This table allows you to view evidence of where a specific software was detected on a device. You can use this table, for example, to identify the file paths of specific software. Use this reference to construct queries that return information from the table.

- [DeviceTvmSoftwareEvidenceBeta](https://docs.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicetvmsoftwareevidencebeta-table?view=o365-worldwide)

- [Guidance for preventing, detecting, and hunting for exploitation of the Log4j 2 vulnerability - Microsoft Security Blog](https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/)

```kusto
//  DeviceTvmSoftwareEvidenceBeta
DeviceTvmSoftwareEvidenceBeta
| mv-expand DiskPaths, RegistryPaths
| project DeviceId, SoftwareName, SoftwareVendor, SoftwareVersion, DiskPaths, RegistryPaths, LastSeenTime
```

```kusto
DeviceInfo
| summarize arg_max(Timestamp,*) by DeviceName
| where DeviceName contains "workstation16"
| join 
//  DeviceTvmSoftwareEvidenceBeta
DeviceTvmSoftwareEvidenceBeta
on $left.DeviceId ==  $right.DeviceId
| mv-expand DiskPaths, RegistryPaths
| project DeviceId, SoftwareName, SoftwareVendor, SoftwareVersion, DiskPaths, RegistryPaths, LastSeenTime
```

### AADSignInEventsBeta

The AADSignInEventsBeta table in the advanced hunting schema contains information about Azure Active Directory interactive and non-interactive sign-ins

- [AADSignInEventsBeta](https://docs.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-aadsignineventsbeta-table?view=o365-worldwide)

- [Hunt for Azure Active Directory sign-in events](https://www.drware.com/hunt-for-azure-active-directory-sign-in-events/)


```kusto
// AADSignInEventsBeta 
// Users with multiple cities 
// Gets a list of users that signed in from multiple locations in the last 30 days
AADSignInEventsBeta 
| where  Timestamp >= ago(30d)
| summarize CountPerCity = dcount(City), citySet = makeset(City) by AccountUpn 
| where CountPerCity > 1
| order by CountPerCity desc 
```
### DeviceNetworkEvents – ActionType – NetworkSignatureInspected

We discovered a new ***ActionType** within the DeviceNetworkEvents table. ***NetworkSignatureInspected***

// DeviceNetworkEvents
DeviceNetworkEvents
| where ActionType == 'NetworkSignatureInspected'
| extend signaturename = tostring(parse_json(AdditionalFields).SignatureName)
| distinct signaturename

Gianni prepared the following KQL queries for identifying DNS traffic.

```
// Do we have DNS Traffic
DeviceNetworkEvents
| where RemotePort == 53
| where ActionType in ("ConnectionSuccess","ConnectionFound")
```

```
// Which servers receive DNS Traffic
DeviceNetworkEvents
| where RemotePort == 53
| where ActionType in ("ConnectionSuccess","ConnectionFound")
| summarize Total = count(), Devices = dcount(DeviceId)  by RemoteIP
```

```
// Introducing Network Signatures
DeviceNetworkEvents
| where ActionType == "NetworkSignatureInspected"
| extend AF = parse_json(AdditionalFields)
| extend SignatureName = AF.SignatureName
```

```
// hunting for DNS servers
DeviceNetworkEvents
| where ActionType == "NetworkSignatureInspected"
| extend AF = parse_json(AdditionalFields)
| extend SignatureName = AF.SignatureName
| where SignatureName == "DNS_Request"
| summarize Total = count(), Servers = dcount(DeviceId) by RemoteIP
```

```
// hunting for DNS on different ports
let DNSPorts = dynamic([53]);
DeviceNetworkEvents
| where ActionType == "NetworkSignatureInspected"
| extend AF = parse_json(AdditionalFields)
| extend SignatureName = AF.SignatureName
| where SignatureName == "DNS_Request"
| where RemotePort !in(DNSPorts)
```

## KQL Tools

If you use Visual Studio Code for editing KQL queries, you want to look at the following Visual Studio Code extensions.

- [Kuskus Kusto Syntax Highlighting](https://marketplace.visualstudio.com/items?itemName=rosshamish.kuskus-kusto-syntax-highlighting)

- [Kuskus Kusto Language Server](https://marketplace.visualstudio.com/items?itemName=rosshamish.kuskus-kusto-language-server)


## What did you do with KQL this month?

Last year the Microsoft Defender for Identity team wrote a blog post about [Microsoft Defender for Identity and Npcap](https://techcommunity.microsoft.com/t5/microsoft-defender-for-identity/microsoft-defender-for-identity-and-npcap/m-p/2584151)

To identify the current state of npap / winpcap deployments across MDI Agents, Alex started to write a KQL query, shared this with Gianni who added a few refinements to it. This is a great example of how the community can help each other. 

```Kusto
DeviceNetworkEvents
| where LocalPort == "88"
| distinct DeviceId
| join kind=inner (
    DeviceInfo
    | where OSPlatform hasprefix "windowsserver"
    | summarize  arg_max(Timestamp,*) by DeviceId
) on DeviceId
| project Timestamp, DeviceId, OSPlatform, OSVersionInfo
| join kind=leftouter (
    DeviceProcessEvents
    | where FileName =~ "Microsoft.Tri.Sensor.exe"
    | summarize arg_max(Timestamp,*) by DeviceId
    | distinct DeviceId, ProcessVersionInfoProductName, ProcessVersionInfoProductVersion
) on DeviceId
| project-away DeviceId1
| join kind=inner (
    DeviceTvmSoftwareInventory
    | where SoftwareName contains "pcap"
    | distinct DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion
) on DeviceId
| project-away DeviceId1
```

## Guest Speaker Matt Zorich

This month our guest speaker is [Matt Zorich](https://twitter.com/reprise_99). Matt is well known within the KQL Commnity for his 365 days of KQL chellange he gave himself with the objective to release a KQL query every day. Matt's KQL work can be found here: https://github.com/reprise99/Sentinel-Queries

During his presentation Matt walked us through a number of interesting KQL queries

```
SigninLogs
| Take 10
```

```
SigninLogs
| count 
```

```
SigninLogs
| where TimeGenerated > ago (90d)
| summarize appcount=count() by AppDisplayName
```

```
SigninLogs
| where TimeGenerated > ago (90d)
| summarize appcount=count() by AppDisplayName
| sort by appcount desc 
```

```
SigninLogs
| where TimeGenerated > ago (90d)
| summarize UserCount=count() by UserPrincipalName
```

```
SigninLogs
| where TimeGenerated > ago (90d)
| summarize UserCount=count() by IPAddress
```

```
SigninLogs
| where TimeGenerated > ago (14d)
| summarize count() by AuthenticationRequirement
```

```
SigninLogs
| where TimeGenerated > ago (14d)
| summarize Signlefactor=countif(AuthenticationRequirement == "singleFactorAuthentication"), Multifactor =countif(AuthenticationRequirement  == "multiFactorAuthentication") by AppDisplayName
```

```
SigninLogs
| where TimeGenerated > ago (14d)
| summarize Guest=countif(UserType == 'Guest'), Members=countif(UserType == 'Member') by AppDisplayName
```

```
SigninLogs
| where TimeGenerated > ago (14d)
| summarize IPAddresses = make_list(IPAddress) by UserPrincipalName
```

```
SigninLogs
| where TimeGenerated > ago (14d)
| summarize IPAddresses = make_set(IPAddress) by UserPrincipalName
```

```
SigninLogs
| where TimeGenerated > ago (14d)
| summarize Applications = make_set(AppDisplayName) by UserPrincipalName
```

```
SigninLogs
| where TimeGenerated > ago (14d)
| summarize Applications = make_set(AppDisplayName) by UserPrincipalName
| extend Appcount = array_length(Applications)
```

```
SigninLogs
| where TimeGenerated > ago (14d)
| summarize arg_max(TimeGenerated,*) by AppId
```

```
SigninLogs
| where TimeGenerated > ago (90d)
| summarize arg_max(TimeGenerated,*) by AppId
| project AppDisplayName, ['LastLogonTime']=TimeGenerated,['Days since last logon']=datetime_diff("Day",now(),TimeGenerated)
```

```
SigninLogs
| where TimeGenerated > ago (90d)
| summarize count() by AppDisplayName,bin(TimeGenerated,8h)
| render timechart 
```

```
SigninLogs
| where TimeGenerated > ago (14d)
| summarize Signlefactor=countif(AuthenticationRequirement == "singleFactorAuthentication"), Multifactor =countif(AuthenticationRequirement  == "multiFactorAuthentication") by bin(TimeGenerated,1d)
| render timechart 
```

```
SigninLogs
| where TimeGenerated > ago (14d)
| summarize GuestSingleFactor=countif(AuthenticationRequirement == "singleFactorAuthentication" and UserType == "Guest"),
GuestMultiFactor = countif(AuthenticationRequirement == "multiFactorAuthentication" and UserType == "Guest"),
MemberSingleFactor=countif(AuthenticationRequirement == "singleFactorAuthentication" and UserType == "Member"),
MemberMultiFactor = countif(AuthenticationRequirement == "multiFactorAuthentication" and UserType == "Member")
by bin(TimeGenerated,1d)
| render timechart 
```

## KQL Challenge of the month

The winner of lasts months challenge is @shviammalaviya With his submission:
https://github.com/KQLCafe/kqlcafecommunity/issues/1

For this months KQL Challenge of the month, we invite the community to write queries. Further instructions can be found [here](https://github.com/KQLCafe/kqlcafecommunity/blob/main/Challenge%20of%20the%20Month/February%202022/Challenge.txt)

