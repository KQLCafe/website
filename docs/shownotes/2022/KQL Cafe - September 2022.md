
# KQL Cafe September 2022

Date: 30. September 2022

***Hosts***

- [Gianni](https://twitter.com/castello_johnny)
- [Alex](https://twitter.com/alexverboon)


***Guest***

- [Mattias Borg](https://twitter.com/MattiasBorg82)


***Show Content***

- [![Recording](https://img.youtube.com/vi/.jpg)](https://www.youtube.com/watch?v=)

## Agenda


## Kusto Detective

Kusto Detective Agency is looking for new recruits. Do you want to be a certified as a Kusto Detective? To become a detective, you need to complete some Kusto assignments. 
Those who complete the journey will become full-fledged detectives and be awarded special badges!

Join Now
https://detective.kusto.io/


## Scan Operator Revisited

Gianni shared kql queries using the scan-operator

```kql
// Find Evil
search "ntdsutil"

// Find Evil
DeviceImageLoadEvents
| where InitiatingProcessFileName =~ "ntdsutil.exe" 

// Step one samlib.dll
DeviceImageLoadEvents
| where InitiatingProcessFileName =~ "ntdsutil.exe" 
| sort by Timestamp asc
| scan with_match_id=funnel_id declare(Step:string, Delta:timespan) with
(
    step Authentication: InitiatingProcessFileName =~ "ntdsutil.exe" 
        and FileName =~ "samlib.dll" 
            => Step = "Authenticated";
)

// Step two add vss_ps.dll
DeviceImageLoadEvents
| where InitiatingProcessFileName =~ "ntdsutil.exe" 
| sort by Timestamp asc
| scan with_match_id=funnel_id declare(Step:string, Delta:timespan) with
(
    step Authentication: InitiatingProcessFileName =~ "ntdsutil.exe" 
        and FileName =~ "samlib.dll" 
            => Step = "Authenticated";
    step NTDSExport: InitiatingProcessFileName =~ "ntdsutil.exe" 
        and FileName =~ "vss_ps.dll" 
        and Authentication.Timestamp > 10m 
            => Step = "NTDS export"
            , Delta = Timestamp - Authentication.Timestamp;
)
| project-reorder Timestamp, DeviceId, DeviceName, funnel_id, FileName, Step

// Step three finalize all
DeviceImageLoadEvents
| where InitiatingProcessFileName =~ "ntdsutil.exe" 
| sort by Timestamp asc
| scan with_match_id=funnel_id declare(Step:string, Delta:timespan) with
(
    step Authentication: InitiatingProcessFileName =~ "ntdsutil.exe" 
        and FileName =~ "samlib.dll" 
            => Step = "Authenticated";
    step NTDSExport: InitiatingProcessFileName =~ "ntdsutil.exe" 
        and FileName =~ "vss_ps.dll" 
        and Authentication.Timestamp > 10m 
            => Step = "NTDS export"
            , Delta = Timestamp - Authentication.Timestamp;
)
| where Step == "NTDS export"
| project-reorder Timestamp, DeviceId, DeviceName, funnel_id, FileName, Step
```

## [Mattias Borg](https://twitter.com/MattiasBorg82)




## What did you do with KQL this month?

### Microsoft Defender for Cloud Apps

Alex shared some KQL queries for Defender for Cloud Apps shadow reporting. 


```kql
// mcas shadown reporting - report by app
McasShadowItReporting
| where TimeGenerated > ago (90d)
| where StreamName == "Win10 Endpoint Users"
| summarize Totalbytes = sum(TotalBytes), UploadBytes = sum( UploadedBytes), DownloadBytes = sum(DownloadedBytes), Users = make_set(EnrichedUserName), Devices = make_set(MachineName), IPAddresses = make_set(IpAddress)  by AppName, AppScore
| extend TotalDevices = array_length(Devices)
| extend TotalIPAddresses = array_length(IPAddresses)
| extend Totalusers = array_length(Users)
| extend UploadMB = format_bytes(UploadBytes,0,"MB")
| extend TotalTraffic = format_bytes(Totalbytes,0,"MB")
| extend DownloadMB = format_bytes(DownloadBytes,0,"MB")
| project AppName,AppScore, TotalDevices, TotalIPAddresses, Totalusers, TotalTraffic, UploadMB, DownloadMB, IPAddresses, Devices, Users
```

```kql
// mcas shadown reporting - report by user
McasShadowItReporting
| where TimeGenerated > ago (90d)
| where StreamName == "Win10 Endpoint Users"
| summarize Totalbytes = sum(TotalBytes), UploadBytes = sum( UploadedBytes), DownloadBytes = sum(DownloadedBytes), Users = make_set(EnrichedUserName), Devices = make_set(MachineName), IPAddresses = make_set(IpAddress) , Apps = make_set(AppName) by EnrichedUserName, AppScore
| extend TotalDevices = array_length(Devices)
| extend TotalIPAddresses = array_length(IPAddresses)
| extend Totalusers = array_length(Users)
| extend TotalApps = array_length(Apps)
| extend UploadMB = format_bytes(UploadBytes,0,"MB")
| extend TotalTraffic = format_bytes(Totalbytes,0,"MB")
| extend DownloadMB = format_bytes(DownloadBytes,0,"MB")
| project EnrichedUserName, TotalDevices, TotalIPAddresses, Totalusers,TotalApps, TotalTraffic, UploadMB, DownloadMB, IPAddresses, Devices, Users, Apps, AppScore
```