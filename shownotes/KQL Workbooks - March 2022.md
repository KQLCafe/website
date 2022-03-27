
# KQL Workbooks

Date: 22. March 2022

**Hosts**
- [Gianni](https://twitter.com/castello_johnny)
- [Alex](https://twitter.com/alexverboon)

**Guest**
[Matthew Lowe](https://www.linkedin.com/in/matthew-lowe-13b61990/)

**Show Content**
- [Show Presentation](https://github.com/KQLCafe/website/blob/gh-pages/Presentations/KQL%20Cafe%20March%2022.pdf)
- [![Recording](https://img.youtube.com/vi/_EHYIRbRHeU/1.jpg)](https://youtu.be/_EHYIRbRHeU)

## Agenda

- Hello again
- What's new in KQL
- IOCs
- Learn KQL
- KQL Tools
- Todays guest speaker: Matthew Lowe
- What did you do with KQL this month?
- KQL Challenge of the month

## What's new in KQL

### Creating large watchlists

You can now create large watchlists with up to 500 MB file size by storing the files in an Azure Blob Storage account.

### Examples

```// when the CNSArmyList is stored in an Azure blog storage Account
// The CINS Army List
// https://cinsscore.com/#list
let cinsarmylist = (externaldata(ip:string)
[@"<PASTE YOUR BLOB SAS URL HERE>"]
with (format="txt",IgnoreFirstRecord=true));
DeviceNetworkEvents
| where TimeGenerated > ago(30d)
| where RemoteIP in (cinsarmylist)
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, LocalIP, LocalPort, ActionType

```

```
// when the CNSArmylist is imported as a watchlist
let CNSArmyList = _GetWatchlist('CNSArmylist') | project IP;
DeviceNetworkEvents
| where TimeGenerated > ago(30d)
| where RemoteIP in (CNSArmyList)
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, LocalIP, LocalPort, ActionType
```

- [Large Watchlist using SAS key is in Public Preview!](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/large-watchlist-using-sas-key-is-in-public-preview/ba-p/3242370)

### DeviceTvmSoftwareInventory

the ***ProductCodeCpe*** column within the [DeviceTvmSoftwareInventory](https://docs.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicetvmsoftwareinventory-table?view=o365-worldwide) table can now be filtered to also identify software for which there is not a CPE.

```
DeviceTvmSoftwareInventory
| where ProductCodeCpe == @"Not Available"
| project SoftwareVendor, SoftwareName, SoftwareVersion
```

## IOCs

This month [Gianni](https://twitter.com/castello_johnny) talked about IOCs related to the Conti Leaks

***Vulnerability management***
https://pastebin.com/raw/pv1mDGYC 
kudos to @c3rb3ru5d3d53c 

***Advanced hunting***
https://ddanchev.blogspot.com/2022/02/exposing-conti-ransomware-gang-osint_28.html
kudos to @dancho_danchev

```
let CVE = datatable(CVE:string)["cve-2015-2546","cve-2016-3309","cve-2017-0101","cve-2018-8120","cve-2019-0543","cve-2019-0841","cve-2019-1064","cve-2019-1069","cve-2019-1129","cve-2019-1130","cve-2019-1215","cve-2019-1253","cve-2019-1315","cve-2019-1322","cve-2019-1385","cve-2019-1388","cve-2019-1405","cve-2019-1458","cve-2020-0609","cve-2020-0638","cve-2020-0688","cve-2020-0787","cve-2020-0796","cve-2020-1472","cve-2021-1675","cve-2021-1732","cve-2021-21972","cve-2021-21985","cve-2021-22005","cve-2021-26855","cve-2021-34527","cve-2021-44847"];
DeviceTvmSoftwareVulnerabilities
| where CveId in~(CVE)
| summarize ["Missing Patch Count"] = count(), ["Missing Patches"] = make_set(RecommendedSecurityUpdate) by DeviceId, DeviceName
```

```
let ContiMail = externaldata(Email:string)
[
    @"https://raw.githubusercontent.com/KustoKing/ExternalData/main/Conti-Email"
];
EmailEvents
| where SenderFromAddress in~(ContiMail) or SenderMailFromAddress in~(ContiMail) or RecipientEmailAddress in~(ContiMail)

let ContiIP = externaldata(IP:string)
[
    @"https://raw.githubusercontent.com/KustoKing/ExternalData/main/Conti-IP"
];
DeviceNetworkEvents
| where RemoteIP in~(ContiIP) or LocalIP  in~(ContiIP)
```

## Learn KQL
[Gianni](https://twitter.com/castello_johnny) talked about the use of [Externaldata](https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/externaldata-operator?pivots=azuredataexplorer) operator in KQL queries. 

```
let lookBack = ago(30d);
let list = (externaldata(Netblock:string, ASN:string, Company:string) [@"https://raw.githubusercontent.com/KustoKing/SentinelWatchlists/main/ASN-of-CloudProviders.csv"] with (ignoreFirstRecord=true, format="SCsv"));
let successResults = dynamic([0, 50055, 50057, 50011, 50155, 50105, 50129, 50133, 50140, 50005, 50074, 50076, 50079, 50155, 50173, 50158, 50072, 50074, 50097, 50125, 53003, 53000, 53001, 50129, 65001, 70043, 70044, 500121,700016]);
let aadFunc = (tableName:string){
table(tableName)
| where TimeGenerated > lookBack
| where ResultType in(successResults)
| evaluate ipv4_lookup(list, IPAddress, Netblock)
;
};
let aadSignin = aadFunc("SigninLogs");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
let aadSPN = aadFunc("AADServicePrincipalSignInLogs");
let officeLogs = OfficeActivity
| where TimeGenerated > lookBack
| evaluate ipv4_lookup(list, ClientIP, Netblock)
;
union isfuzzy=true aadSignin, aadNonInt, aadSPN, officeLogs
| summarize count(), Applications = make_set(AppDisplayName), IPAddresses = make_set(IPAddress), Days=dcount(bin(TimeGenerated, 1d)), Locations = make_set(Location) by Identity, ASN, Company
```

## KQL Tools

### Uncoder CTI

Use [Uncoder CTI](https://cti.uncoder.io/) to generate IOC queries on the fly for Microsoft Sentinel and Microsoft Defender for Endpoint. 



## Guest Speaker Matthew Lowe

This month our guest speaker was [Matthew Lowe](https://www.linkedin.com/in/matthew-lowe-13b61990/). 

During his presentation Matthew  walked us through the following Microsoft Sentinel Workbooks:

- Intro to KQL
- Advanced KQL for Microsoft Sentinel

For more information watch the KQL Cafe session video or read the following blogs on Microsoft Tech Community. 

- [Get Hands-On KQL](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/get-hands-on-kql-practice-with-this-microsoft-sentinel-workbook/ba-p/3055600)
-   [Feedback Form](https://aka.ms/introtokqlsurvey)
- [Advanced KQL Framework](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/advanced-kql-framework-workbook-empowering-you-to-become-kql/ba-p/3033766)
-   [Feedback Form](https://forms.office.com/r/qNS7cRmPWS)


## What did you do with KQL this month?

### Patch Management

This month - [Alex](https://twitter.com/alexverboon) worked on a query to identify the number of missing patches a device that's onboarded into Microsoft Defender for Endpoint.

Below is the query that was used to identify the number of missing patches for Windows Servers. You can easily adjust the querie to look for missing patches on Windows 10 devices. 

```
// Overview Missing KBs Windows Server
DeviceTvmSoftwareVulnerabilities
| where SoftwareName startswith 'windows_server'
| where isnotempty(RecommendedSecurityUpdate)
| distinct DeviceId, RecommendedSecurityUpdate, RecommendedSecurityUpdateId, SoftwareName
| join kind=leftouter (
    DeviceInfo
    | where isnotempty(OSPlatform)
    | where OnboardingStatus == 'Onboarded'
    | where isnotempty(OSVersionInfo)
    | summarize arg_max(Timestamp, *) by DeviceId)
    on $left.DeviceId == $right.DeviceId
| summarize MissingDevices = make_set(DeviceName) by SoftwareName, RecommendedSecurityUpdate, RecommendedSecurityUpdateId, OSVersionInfo, OSDistribution
| extend TotalMissingKBDevice = array_length(MissingDevices)
| project ['Bulletin'] = RecommendedSecurityUpdate, ['ID'] = RecommendedSecurityUpdateId, ['Total Exposed devices'] = TotalMissingKBDevice, ['Exposed devices'] = MissingDevices, OSVersionInfo, OSDistribution
// | where OSDistribution == @"WindowsServer2019"
// | where ['Exposed devices'] contains "(device name)"
```

### Check last AzureAD sign-in date from users that are member of a sepcific AzureAD Group. 

This month - [Alex](https://twitter.com/alexverboon) worked on a query to identify the users last sign-in date into AzureAD based on a specific AzureAD Group.

Scenario: You are deploying MFA and created an exclude group, after a while you want to cleanup that group, i.e. start removing users. To identify users that haven't logged on to AzureAD for a while, use the following query.

```
let AzGroup = "CA_ExcludeAllUsers";
let timerange=180d;
let timeframe=180d;
IdentityInfo
| where TimeGenerated > ago(timerange)
| summarize arg_max(TimeGenerated,*) by AccountUPN
| mv-expand GroupMembership
| where GroupMembership == AzGroup
| extend AccountUPN = tolower(AccountUPN)
| join kind = leftouter // leftanti
(
SigninLogs
| where TimeGenerated > ago(timeframe)
| where ResultType == 0
| summarize arg_max(TimeGenerated, *) by UserPrincipalName
| extend LastLogon = TimeGenerated
| extend UserPrincipalName = tolower(UserPrincipalName)
)
on $left.AccountUPN == $right.UserPrincipalName
| project TimeGenerated, AccountUPN, UserPrincipalName, LastLogon
```

## KQL Challenge of the month

This month we invite you to join the #365DaysofKQL Scavenger Hunt 1 created by [Matt Zorich](https://twitter.com/reprise_99)

[#365DaysofKQL Scavenger Hunt 1](https://t.co/kl35p0Pj58)

> Entries will close midnight April 8th (UTC time)






