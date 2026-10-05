# KQL Cafe - February 2026

## Recording

- [Recording](https://www.youtube.com/watch?v=b56RoyaFsb8&t=659s)

## Hosts

- [Gianni](https://twitter.com/castello_johnny)
- [Alex](https://twitter.com/alexverboon)

## Guests

-  [Ian Hanley](https://www.linkedin.com/in/ianhanley) 

## KQL News


## Guest

[Ian Hanley](https://www.linkedin.com/in/ianhanley) 

[Presentation Slides](https://github.com/EEN421/speaking/tree/Main/KQL%20Cafe/2026/09-29)

## Learn KQL

- [Partition Operator](https://learn.microsoft.com/en-us/kusto/query/partition-operator?view=azure-data-explorer&preserve-view=true)

Most contacted remote IPs per device

```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where isnotempty(RemoteIP)
| summarize Connections=count()
    by DeviceId, DeviceName, RemoteIP
| partition hint.strategy=native by DeviceId
(
    top 5 by Connections desc
)
| project DeviceName, RemoteIP, Connections
```





