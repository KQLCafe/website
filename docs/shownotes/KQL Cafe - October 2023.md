# KQL Cafe October 2023

## MicrosoftGraphActivityLogs

```kql
// Total ingestion in GB
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(90d)
| where _IsBillable == true
| summarize TotalVolumeGBLog = round(sum(_BilledSize/1024/1024/1024),2)  by bin(TimeGenerated, 1d)
// Sum all
| summarize sum(TotalVolumeGBLog)
```

```kql
// Combine Usage and Log Data
let ingestionprice = 5.59;
let logsource = "MicrosoftGraphActivityLogs";
let xusage = Usage
| where TimeGenerated > ago (30d)
| where IsBillable == true
| summarize TotalVolumeGBUsage = round(sum(Quantity/1024),2) by bin(TimeGenerated, 1d), DataType
| where DataType == (logsource);
MicrosoftGraphActivityLogs
| where TimeGenerated > ago  (30d)
| where _IsBillable == true
| summarize TotalVolumeGBLog = round(sum(_BilledSize/1024/1024/1024),2)  by bin(TimeGenerated, 1d)
| join xusage
on $left.TimeGenerated ==  $right.TimeGenerated
| extend ['Estimated cost'] = TotalVolumeGBLog * ingestionprice
| summarize sum(TotalVolumeGBUsage), sum(TotalVolumeGBLog)
```

```kql
MicrosoftGraphActivityLogs
| take 10
```

```kql
let AllApps = union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs 
| where TimeGenerated > ago(90d)
| distinct AppDisplayName, AppId;
MicrosoftGraphActivityLogs
| join kind=leftouter AllApps
on $left. AppId == $right.AppId
| distinct AppId, AppId1, AppDisplayName
```

## App Governance - Entra ID Consented Apps Cleanup

```kql
// Activiries with User consented Apps
let UserConsentedApps = datatable(AppName:string) ["Adobe Acrobat", "Adobe Acrobat Reader", "Adobe Acrobat Reader for PDF", "Adobe Sign for Office365"];
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs 
| where TimeGenerated > ago(90d)
| where AppDisplayName in (UserConsentedApps)
| project TimeGenerated, UserPrincipalName, AppDisplayName, AppId
| summarize Count = count(), Users  = make_set(UserPrincipalName) by AppDisplayName,AppId
| project AppDisplayName,AppId, Count, TotalUsers = array_length(Users), Users
```

```kql
// User Consented apps not found in logs
let UserConsentedApps = datatable(AppName:string) ["Adobe Acrobat", "Adobe Acrobat Reader", "Adobe Acrobat Reader for PDF", "Adobe Sign for Office365"];
let AllApps = union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs 
| where TimeGenerated > ago(90d)
| distinct AppDisplayName;
UserConsentedApps
| join kind= leftanti   AllApps
on $left. AppName == $right. AppDisplayName
```

## Client Inspector

- [ClientInspector](https://github.com/KnudsenMorten/ClientInspectorV2#introduction-to-clientinspector-v2)

### Hunting for Curl

- [Hunting for the Curl vulnerability](https://www.kustoking.com/hunting-for-curl/)

## Zeek SMTP

inspect SMTP related traffic from MDE Zeek logs

```kql
// SMTP traffic
let lookback = 90d;
DeviceNetworkEvents
| where TimeGenerated > ago(lookback)
| where ActionType == "SmtpConnectionInspected"
| extend json = todynamic(AdditionalFields)
| extend from = tostring(json.from)
| extend direction= tostring(json.direction)
| extend helo = tostring(json.helo)
| extend last_reply = tostring(json.last_reply)
| extend mailfrom = tostring(json.mailfrom)
| extend rcptto= tostring(json.rcptto)
| extend subject = tostring(json.subject)
| extend tls = tostring(json.tls)
| extend rcpttolenght = array_length(parse_json(rcptto))
| extend fromemail = extract(@"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}\b",0,tostring(from))
| project TimeGenerated, DeviceName, LocalIP, RemoteIP, RemotePort, direction, from  mailfrom,fromemail, helo, last_reply, tls, rcptto, rcpttolenght, subject
```
