# KQL Cafe September 2023

## Zeek

- [Enrich your advanced hunting experience using network layer signals from Zeek](https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/enrich-your-advanced-hunting-experience-using-network-layer/ba-p/3794693)

### InboundInternetScanInspected

```kql
DeviceNetworkEvents
| where ActionType == "InboundInternetScanInspected"
| project TimeGenerated, DeviceName, LocalIP, LocalPort, RemoteIP, RemotePort, RemoteIPType
| extend geoinfo = geo_info_from_ip_address(LocalIP)
| extend country = tostring(geoinfo.country)
| extend city = tostring(geoinfo.city)
| extend state = tostring(geoinfo.state)
| project-away geoinfo
```

### FTP

```kql
DeviceNetworkEvents
| where ActionType == "FtpConnectionInspected"
| extend json = todynamic(AdditionalFields)
| extend command = tostring(json.command)
| extend reply_code = tostring(json.reply_code)
| extend reply_msg = tostring(json.reply_msg)
| extend direction = tostring(json.direction)
| extend user = tostring(json.user)
| extend arg = tostring(json.arg)
| extend cwd = tostring(json.cwd)
```

## Azure Resource Graph

- [Query Azure Resource Graph from Azure Monitor](https://techcommunity.microsoft.com/t5/azure-observability-blog/query-azure-resource-graph-from-azure-monitor/ba-p/3918298)
- [Query data in Azure Data Explorer and Azure Resource Graph from Azure Monitor](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/azure-monitor-data-explorer-proxy)
- [Azure Resource Graph table and resource type reference](https://learn.microsoft.com/en-us/azure/governance/resource-graph/reference/supported-tables-resources)


### Show all Resource Types

```kql
arg("").Resources
| distinct type
```

### Log Analytics Workspace Info

```kql
arg("").Resources
| where type == "microsoft.operationalinsights/workspaces"
| extend SKUName = tostring(parse_json(tostring(properties.sku)).name)
| extend dailyQuotaGb = tostring(parse_json(tostring(properties.workspaceCapping)).dailyQuotaGb)
| extend quotaNextResetTime = todatetime(tostring(parse_json(tostring(properties.workspaceCapping)).quotaNextResetTime))
| extend retentionInDays = tostring(properties.retentionInDays)
| project name, location, resourceGroup, retentionInDays,SKUName, dailyQuotaGb, quotaNextResetTime

```


### Identify Azure Subscriptions that are not monitored by the Azure Activity Data Connector in Sentinel

```kql
// Identify Azure Subscriptions that are not monitored by the Azure Activity Data Connector in Sentinel
let allsubscriptions = 
arg("").resourcecontainers
| where type == "microsoft.resources/subscriptions"
| distinct subscriptionId, name;
allsubscriptions
| join kind=leftouter  (AzureActivity
| extend AzureActivitySyubscriptionId = SubscriptionId
| distinct AzureActivitySyubscriptionId)
on $left. subscriptionId == $right.AzureActivitySyubscriptionId
| extend IsMonitored = iff(isempty(AzureActivitySyubscriptionId),"No","Yes")
| project subscriptionId, name, AzureActivitySyubscriptionId, IsMonitored
```



## KQLQuery.com

- [kqlquery.com](https://kqlquery.com/)


## Beta KQL Search.com

- [Beta KQL Search](beta.kqlsearch.com)



## Graph Operators

- [Graph operators (Preview) - Azure Data Explorer | Microsoft Learn](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/graph-operators)


## IdentityInfo 

- [IdentityInfo](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-identityinfo-table?view=o365-worldwide)
- [Identity hunting with an enhanced IdentityInfo table](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/identity-hunting-with-an-enhanced-identityinfo-table/ba-p/3912561)




## MDI Disabling Accounts (Automatic Attack Disruption)


```kql
let AllDomainControllers =
        DeviceNetworkEvents
        | where TimeGenerated > ago(7d)
        | where LocalPort == 88
        | where LocalIPType == "FourToSixMapping"
        | extend DCDevicename = tostring(split(DeviceName,".")[0])
        | distinct DCDevicename;
IdentityDirectoryEvents
| where TimeGenerated > ago(190d)
| where ActionType == "Account disabled"
| extend ACTOR_DEVICE = tolower(tostring(AdditionalFields.["ACTOR.DEVICE"]))
| where isnotempty( ACTOR_DEVICE)
| where ACTOR_DEVICE in (AllDomainControllers)
| project TimeGenerated, TargetAccountDisplayName, ACTOR_DEVICE
```



## Set query now

```kql
set query_now = datetime('2023-08-04T14:46:34.3319494Z');
SigninLogs
| where TimeGenerated between (ago(1d) .. now())
```




















