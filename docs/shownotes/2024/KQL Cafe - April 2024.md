# KQL Cafe - April 2024

## Recording and Presentation

- [Recording](https://www.youtube.com/watch?v=o-PKZks9NI4)

## Hosts

- [Gianni](https://twitter.com/castello_johnny)
- [Alex](https://twitter.com/alexverboon)

## Guests

- [Henning Rauch](https://www.linkedin.com/in/henning-rauch-adx/)

## News

- [Introduction to KQL for Security Analysis](https://academy.bluraven.io/)
- [Hands-On KQL for Security Analysts](https://academy.bluraven.io/)
- [Slim's Elite KQL Detection & Cyber Defense Tips](https://www.linkedin.com/pulse/slims-elite-kql-detection-cyber-defense-tips-steven-lim-wujbc/?trackingId=kmHuitogSda6wj0lk%2FtV%2Bg%3D%3D)
- [The Definitive Guide to KQL: Using Kusto Query Language for Operations, Defending and Threat Hunting](https://github.com/KQLMSPress/definitive-guide-kql)
- [Strategies to monitor and prevent vulnerable driver attacksUseful MDE queries](https://techcommunity.microsoft.com/t5/microsoft-security-experts-blog/strategies-to-monitor-and-prevent-vulnerable-driver-attacks/ba-p/4103985)
- [Defender for Cloud (CSPM) (Jarkko Kinnunen) KQL for Pricing](https://github.com/Jaekk0/Sentinel/blob/main/Random_Kql/az-resource-graph-list-cspm-enable-%26-price.kql)
- [CloudAppEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table?view=o365-worldwide)
    New columns
    LastSeenForUser - Shows how many days back the attribute was recently in use by the user in days (i.e. ISP, ActionType etc.)
    UncommonForUser - Lists the attributes in the event that are uncommon for the user, using this data to help rule out false positives and find out anomalies

## Our Guest

- [Kusto Query Language (KQL) graph semantics overview (Preview)](https://learn.microsoft.com/en-us/azure/data-explorer/graph-overview)
- [Graph Operators](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/graph-operators)
- [How Kusto graph semantics can help solve a classic graph problem: the Seven Bridges of Königsberg](https://techcommunity.microsoft.com/t5/azure-data-explorer-blog/how-kusto-graph-semantics-can-help-solve-a-classic-graph-problem/ba-p/4025946)
- [Manufacturing Ontologies](https://github.com/digitaltwinconsortium/ManufacturingOntologies)

## Learn KQL - Series

```kql
SigninLogs
| make-series Logons=count() default=0 on TimeGenerated from ago(14d) to now() step 1h
| extend series_sum=series_sum(Logons)
```

```kql
SigninLogs
| make-series Logons=count() default=0 on TimeGenerated from ago(14d) to now() step 1h
| project series_stats(Logons)
```

```kql
SigninLogs
| make-series Logons=count() default=0 on TimeGenerated from ago(14d) to now() step 1h
| extend series_decompose(Logons)
```

```kql
SigninLogs
| make-series Logons=count() default=0 on TimeGenerated from ago(14d) to now() step 1h
| extend series_decompose(Logons)
| render timechart 
```

```kql
SigninLogs
| make-series Logons=count() default=0 on TimeGenerated from ago(14d) to now() step 1h
| extend outliers=series_outliers(Logons)
| render timechart 
```

```kql
SigninLogs
| where TimeGenerated > ago(14d)
| make-series Logons=count() default=0 on TimeGenerated from ago(14d) to now() step 1h
| extend series_decompose_anomalies(Logons)
```

```kql
SigninLogs
| make-series Logons=count() default=0 on TimeGenerated from ago(14d) to now() step 1h
| extend series_decompose(Logons)
| render timechart 
```

```kql
SigninLogs
| where TimeGenerated > ago(14d)
| make-series Logons=count() default=0 on TimeGenerated from ago(14d) to now() step 1h
| extend series_decompose_anomalies(Logons)
```

```kql
SigninLogs
| where TimeGenerated > ago(14d)
| make-series Logons=count() default=0 on TimeGenerated from ago(14d) to now() step 1h
| extend (AnomaliesDetected, AnomaliesScore, AnomaliesBaseline) = series_decompose_anomalies(Logons)
| mv-expand Logons to typeof(double), TimeGenerated to typeof(datetime), AnomaliesDetected to typeof(double), AnomaliesScore to typeof(double), AnomaliesBaseline to typeof(long)
| render timechart  
```

```kql
SigninLogs
| where TimeGenerated > ago(14d)
| make-series Logons=count() default=0 on TimeGenerated from ago(14d) to now() step 1h
| extend (AnomaliesDetected, AnomaliesScore, AnomaliesBaseline) = series_decompose_anomalies(Logons)
| mv-expand Logons to typeof(double), TimeGenerated to typeof(datetime), AnomaliesDetected to typeof(double), AnomaliesScore to typeof(double), AnomaliesBaseline to typeof(long)
| extend AnomaliesDetected = AnomaliesDetected * (AnomaliesBaseline*2)
| render timechart  
```

```kql
SigninLogs
| where TimeGenerated > ago(14d)
| make-series Logons=count() default=0 on TimeGenerated from ago(14d) to now() step 1h
| extend (AnomaliesDetected, AnomaliesScore, AnomaliesBaseline) = series_decompose_anomalies(Logons, 1.5, 24, "linefit",0,"tukey")
| mv-expand Logons to typeof(double), TimeGenerated to typeof(datetime), AnomaliesDetected to typeof(double), AnomaliesScore to typeof(double), AnomaliesBaseline to typeof(long)
| extend AnomaliesDetected = AnomaliesDetected * (AnomaliesBaseline*2)
| render timechart  
```

```kql
SigninLogs
| where TimeGenerated > ago(14d)
| make-series Logons=count() default=0 on TimeGenerated from ago(14d) to now() step 1h
| extend (AnomaliesDetected, AnomaliesScore, AnomaliesBaseline) = series_decompose_anomalies(Logons, 1.5, 24, "linefit",0,"ctukey",0.6)
| mv-expand Logons to typeof(double), TimeGenerated to typeof(datetime), AnomaliesDetected to typeof(double), AnomaliesScore to typeof(double), AnomaliesBaseline to typeof(long)
| extend AnomaliesDetected = AnomaliesDetected * (AnomaliesBaseline*2)
| render timechart 
```

## What did you do with KQL this month

- [Defender for Endpoint - Azure Information Protection Client](https://github.com/alexverboon/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Endpoint/MDE-AIPClient.md)
- [Defender for IoT](https://github.com/alexverboon/Hunting-Queries-Detection-Rules/tree/main/Defender4IoT)
- [EntraID - Microsoft Defender for Endpoint - Security Settings Management - Device Registrations](https://github.com/alexverboon/Hunting-Queries-Detection-Rules/blob/main/Azure%20Active%20Directory/EntraID-MDEDeviceRegistrations.md)

### Azure Files

```kql
StorageFileLogs
| where Uri contains “SuspiciousFilename.txt"
| where Category == "StorageWrite" and
    OperationName == "Write" and 
    StatusCode == "0"
| project-reorder TimeGenerated, LastModifiedTime, SmbPrimarySID, CallerIpAddress
```

```kql
StorageFileLogs
| where TimeGenerated > ago(90d)
| where _IsBillable == true
| summarize TotalVolumeGBLog = round(sum(_BilledSize/1024/1024/1024),2)  by bin(TimeGenerated, 1d) 
// Sum all
| summarize sum(TotalVolumeGBLog)
```
