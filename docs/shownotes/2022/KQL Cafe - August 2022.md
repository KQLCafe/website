
# KQL Cafe August 2022

Date: 30. August 2022

***Hosts***

- [Gianni](https://twitter.com/castello_johnny)
- [Alex](https://twitter.com/alexverboon)


***Guest***

- [Ashwin Patil](https://twitter.com/ashwinpatil)


***Show Content***

- [![Recording](https://img.youtube.com/vi/j0kUiW_Ip7A/0.jpg)](https://www.youtube.com/watch?v=j0kUiW_Ip7A)

## Agenda

```
0:00 Welcome to KQL Cafe
What's new in KQL:
1:37 Sentinel Data Retention, Archive and Restore
14:03 Guided Hunting in Microsoft 365 Defender
Working with IOCs:
17:10 ASN in SigninLogs
Learning KQL:
20:21 parse-kv
32:17 Microsoft Learn
Our KQL Guest:
32:48 Ashwin Patil - Blue teaming with KQL
What did you do with KQL this month?
1:16:32 Watchlists and IP Ranges
1:22:58 Azure Threat Matrix 
1:27:30 ASIM Parsers
```


## Show content references

### Sentinel Data Ingestion, Retetnion, Archiving

During our last show we briefly touched on Data Ingestion, retention, archive and restore, if you're interested in the details, I recommend watching the following videos and content

[Leverage new and existing features to optimize cost in Microsoft Sentinel](https://youtu.be/0cIYB92Qb60)
[Manage Your Log Lifecycle with New Methods for Ingestion, Archival, Search, and Restoration](https://youtu.be/LgGpSJxUGoc)

More videos and slides available on the Secuirty Webinars [page](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/recordings-security-community-webinars/ba-p/2865990)

### Guided Hunting in Microsoft 365 Defender

[Hunt in Microsoft 365 Defender without KQL!](https://techcommunity.microsoft.com/t5/microsoft-365-defender-blog/hunt-in-microsoft-365-defender-without-kql/ba-p/3607989)
[Build hunting queries using guided mode in Microsoft 365 Defender](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-query-builder?view=o365-worldwide)



### The parse-kv operator

```
Syslog
| where SyslogMessage has "duration"
| where TimeGenerated between (startofday(datetime("20220701")) .. endofday(datetime("20220701")))
| take 10
| project SyslogMessage
```

```
// Lets get the Duration, Send Bytes and Received bytes (The slow way 'extract')
Syslog
| where TimeGenerated between (startofday(datetime("20220501")) .. endofday(datetime("20220901")))
| extend NetworkDuration = extract(@'\sduration="(\d+)"', 1, SyslogMessage)
| extend Send = extract(@'\ssent_bytes="(\d+)"', 1, SyslogMessage)
| extend Received = extract(@'\srcvd_bytes="(\d+)"', 1, SyslogMessage)
| where isnotempty(NetworkDuration)
```

```
// The faster way (parse)
Syslog
| where TimeGenerated between (startofday(datetime("20220501")) .. endofday(datetime("20220901")))
| parse SyslogMessage with * @'duration="' NetworkDuration '" sent_bytes="' Send '" rcvd_bytes="' Received '"' *
| where isnotempty(NetworkDuration)
```

```
// The Next Generation way (parse-kv)
Syslog
| where TimeGenerated between (startofday(datetime("20220501")) .. endofday(datetime("20220901")))
| parse-kv SyslogMessage as (duration:int
    , sent_bytes:long 
    , rcvd_bytes:long) with (pair_delimiter=' ', kv_delimiter='=', quote='"')
```

```
// Now lets rename the columns (parse-kv)
Syslog
| where TimeGenerated between (startofday(datetime("20220501")) .. endofday(datetime("20220901")))
| parse-kv SyslogMessage as (duration:int
    , sent_bytes:long 
    , rcvd_bytes:long) with (pair_delimiter=' ', kv_delimiter='=', quote='"')    
| project-rename NetworkDuration = duration
    , SrcBytes = sent_bytes
    , DstBytes = rcvd_bytes
| where isnotempty(NetworkDuration)
```

```
// And now all posible ways (parse-kv)
Syslog
| where TimeGenerated between (startofday(datetime("20220501")) .. endofday(datetime("20220901")))
| parse-kv SyslogMessage as (geo_src:string
    , geo_dst:string
    , src_user:string
    , dst_user:string
    , duration:int
    , sent_bytes:long
    , rcvd_bytes:long
    , msg_id:string
    , fqdn_src_match:string
    , fqdn_dst_match:string) with (pair_delimiter=' ', kv_delimiter='=', quote='"')
| project-rename SrcGeoCountry = geo_src
    , DstGeoCountry = geo_dst
    , SrcUsername = src_user
    , DstUsername = dst_user
    , NetworkDuration = duration
    , SrcBytes = sent_bytes
    , DstBytes = rcvd_bytes
    , MessageId = msg_id
    , SrcDomain = fqdn_src_match
    , DstDomain = fqdn_dst_match
```


### Presentation from [Ashwin Patil](https://twitter.com/ashwinpatil)

https://github.com/ashwin-patil/blue-teaming-with-kql/blob/main/KQLCafe-BlueTeamingwithKQL-2022.pdf


### IP Ranges

Below are the KQL queries I demonstrated while talking about hunting for IP range related data. 

```kql
let MySubnetsList =  _GetWatchlist('NetworkAddresses');
SigninLogs
| extend city_ = tostring(LocationDetails.city)
| extend state_ = tostring(LocationDetails.state)
| project TimeGenerated,CorrelationId, UserPrincipalName, IPAddress, Location, AppDisplayName, ClientAppUsed, city_, state_
| evaluate ipv4_lookup(MySubnetsList, IPAddress,SearchKey, return_unmatched = true)
| extend IsMatch = iff(isempty(SearchKey),"No","Yes")
| project-reorder IsMatch
```

```kql
// network range mapping with sign-in logs
let MySubnetsList =  _GetWatchlist('NetworkAddresses');
SigninLogs
| extend city_ = tostring(LocationDetails.city)
| extend state_ = tostring(LocationDetails.state)
| project TimeGenerated,CorrelationId, UserPrincipalName, IPAddress, Location, AppDisplayName, ClientAppUsed, city_, state_
| evaluate ipv4_lookup(MySubnetsList, IPAddress,SearchKey, return_unmatched = true)
// | where isempty(["Range Name"])
| summarize count() by IPAddress, Location, Tags, ["Range Name"]
```

```kql
let MySubnets = toscalar ( _GetWatchlist('NetworkAddresses')
| summarize make_set((SearchKey)));
SigninLogs
| extend ismatch = ipv4_is_in_any_range(IPAddress,MySubnets)
| extend city_ = tostring(LocationDetails.city)
| extend state_ = tostring(LocationDetails.state)
| project TimeGenerated,CorrelationId, UserPrincipalName, IPAddress, Location, ismatch, AppDisplayName, ClientAppUsed, city_, state_
```

### Azure-Threat-Research-Matrix-KQL - AZT403.1 - Local Resource Hijack: Cloud Shell .IMG

[AZT403.1 - Local Resource Hijack: Cloud Shell .IMG](https://github.com/alexverboon/Azure-Threat-Research-Matrix-KQL/blob/main/Privilige%20Escalation/AZT403-1%20-%20Local%20Resource%20Hijack%20-%20Cloud%20Shell_IMG.md)


### Questions

Q: can you explain the "isfuzzy=true" ?
A: isfuzzy==true  // skip if you find an error to next command

Q: any difference between <> and == ?
A: they are the polar opposite
Q: so <> is the same as !=. ?
A: Correct



## KQL Community Contribution

The following code was shared by Mike Fernandez

```
//////////////////////////////////////////////////////////////////////////////////////////////////////////
// Name: Emotet Malware Process Search - Time window join - v1
// =======================================================================================================
// References:
// - KQL Time window join - https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/join-timewindow
// - FILE 08072022.xls - https://tria.ge/220708-q7h7fsfbf2/behavioral1 <- commandline usage example
// - DOCUMENT 625.xls - https://tria.ge/220707-r2743ahcgp/behavioral1 <- commandline usage example
//////////////////////////////////////////////////////////////////////////////////////////////////////////
let lookupWindow = 3min;
let lookupBin = lookupWindow / 2.0; // lookup bin = equal to 1/2 of the lookup window
let timeframe = 1d;
DeviceProcessEvents
| where Timestamp > ago(timeframe)
| where (FileName == "systeminfo.exe"
        and ProcessCommandLine == "systeminfo")
    or (FileName has "ipconfig"
        and ProcessCommandLine has_any ("/all","-all"))
    or (FileName == "nltest.exe"
        and ProcessCommandLine has "/dclist:")
| project Timestamp, ReportId, DeviceId, DeviceName, AccountName, AccountDomain, FileName, ProcessCommandLine,
    Process1_EventTime=Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName,
    TimeKey = bin(Timestamp, lookupBin)
| join kind=inner
    (
    DeviceProcessEvents
    | where Timestamp > ago(timeframe)
    | where (FileName == "systeminfo.exe"
            and ProcessCommandLine == "systeminfo")
        or (FileName has "ipconfig"
          and ProcessCommandLine has_any ("/all","-all"))
        or (FileName == "nltest.exe"
          and ProcessCommandLine has "/dclist:")
    | project ReportId, DeviceId, DeviceName, FileName, ProcessCommandLine, Process2_EventTime=Timestamp,
        InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName,
              TimeKey = range(bin(Timestamp-lookupWindow, lookupBin),
                              bin(Timestamp, lookupBin),
                              lookupBin)
    | mv-expand TimeKey to typeof(datetime)
    ) on DeviceName, TimeKey
| where FileName != FileName1
| join kind=inner
    (
    DeviceProcessEvents
    | where Timestamp > ago(timeframe)
| where (FileName == "systeminfo.exe"
        and ProcessCommandLine == "systeminfo")
    or (FileName has "ipconfig"
        and ProcessCommandLine has_any ("/all","-all"))
    or (FileName == "nltest.exe"
        and ProcessCommandLine has "/dclist:")
| project ReportId, DeviceId, DeviceName, FileName, ProcessCommandLine, Process3_EventTime=Timestamp,
    InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName,
              TimeKey = range(bin(Timestamp-lookupWindow, lookupBin),
                              bin(Timestamp, lookupBin),
                              lookupBin)
    | mv-expand TimeKey to typeof(datetime)
    ) on DeviceName, TimeKey
| where (FileName1 != FileName and FileName1 != FileName2 and FileName != FileName1 and FileName != FileName2)
| where (Process2_EventTime - Process1_EventTime) between (0min .. lookupWindow)
    and (Process3_EventTime - Process2_EventTime) between (0min .. lookupWindow)
| project Timestamp, ReportId, DeviceId, DeviceName, AccountName, AccountDomain,
    Process1=FileName, Process2=FileName1, Process3=FileName2,
    Process1_EventTime, Process2_EventTime,  Process3_EventTime,
    Process1_CommandLine = ProcessCommandLine, Process1_InitiatingProcessFileName=InitiatingProcessFileName,
    Process1_InitiatingProcessCommandLine=InitiatingProcessCommandLine, Process1_InitiatingProcessParentFileName=InitiatingProcessParentFileName,
    Process2_CommandLine = ProcessCommandLine1, Process2_InitiatingProcessFileName=InitiatingProcessFileName,
    Process2_InitiatingProcessCommandLine=InitiatingProcessCommandLine, Process2_InitiatingProcessParentFileName=InitiatingProcessParentFileName,
    Process3_CommandLine = ProcessCommandLine2, Process3_InitiatingProcessFileName=InitiatingProcessFileName,  
    Process3_InitiatingProcessCommandLine=InitiatingProcessCommandLine, Process3_InitiatingProcessParentFileName=InitiatingProcessParentFileName
| sort by Process1_EventTime
```
