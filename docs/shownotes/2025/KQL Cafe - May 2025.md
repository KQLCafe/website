# KQL Cafe - May 2025

## Recording

- [Recording](https://www.youtube.com/watch?v=Yna97PlIX18)

## Hosts

- [Gianni](https://twitter.com/castello_johnny)
- [Alex](https://twitter.com/alexverboon)

## Guests

- [Michalis Michalos](https://www.linkedin.com/in/mmihalos/)
- [Christos Galanopoulos](https://www.linkedin.com/in/christos-galanopoulos/)

## KQL News

### Introducing new Advanced Hunting Tables to hunt on Teams messages and URLs

Microsoft introduces three new Advaned Hunting tables designed to hunt for Teams messages containing URLs within the organization.

| Table Name                    | Description |
| ----------------------------- | ----------------------------- |
| **MessageEvents** | The `MessageEvents` table enables hunting across Teams messages **containing URLs** within your tenant. This includes both **known-malicious messages blocked immediately after delivery** and messages with no malicious content. Each message is uniquely identified by the `TeamsMessageId`, which you can use to join across tables. Because only a single copy of each message exists—even if it was delivered to multiple recipients—only one instance is shown in Advanced Hunting. |
| **MessagePostDeliveryEvents** | The `MessagePostDeliveryEvents` table lets you **analyze Teams messages containing URLs** that are **identified as malicious after delivery**. If Zero-hour Auto Purge (ZAP) is enabled for Teams, messages blocked post-delivery appear in this table. Each message is uniquely identified by the `TeamsMessageId`. |
| **MessageURLInfo** | The `MessageURLInfo` table supports hunting across **URLs embedded within Teams messages** in your organization.  |

- [Message Center](https://admin.microsoft.com/AdminPortal/home?ref=MessageCenter/:/messages/MC1048617)

## Guest

- [Michalis Michalos](https://www.linkedin.com/in/mmihalos/)
- [Blog](https://www.michalos.net/)
- [Christos Galanopoulos](https://www.linkedin.com/in/christos-galanopoulos/)

### sKaleQL

Michalis & Christos presented their [sKaleQL](https://github.com/christosgalano/sKaleQL) project.

## What did you do with KQL this month?

### Pack in Defender

```kql
AlertEvidence
| where EntityType == "Ip"
| extend IPObject = pack("Title", Title, "RemoteIP", RemoteIP)
| summarize ListIPs = make_list(IPObject), Records = count() by AlertId, Timestamp
| project Timestamp, AlertId, ListIPs, Records
```

```kql
AlertEvidence
| where EntityType == "Process"
| extend FileObject = pack("Title", Title, "FileName", FileName, "SHA1", SHA1, "ProcessCommandLine", ProcessCommandLine)
| summarize ListFiles = make_list(FileObject), Records = count() by AlertId, Timestamp
| project Timestamp, AlertId, ListFiles, Records
```

### Detecting malicious PowerShell

```kql
DeviceNetworkEvents
| where not(ActionType == "ConnectionFailed")
| where not(ipv4_is_private(RemoteIP) and ipv6_is_in_any_range(RemoteIP, @"::1/128",@"ff00::/8","fe80::/10", "fc00::/7"))
| where InitiatingProcessParentFileName =~ "powershell.exe"
| join kind=inner (DeviceProcessEvents) on DeviceId, $left.InitiatingProcessParentFileName == $right.InitiatingProcessFileName, $left.InitiatingProcessParentId == $right.InitiatingProcessId
| where InitiatingProcessCommandLine1 has_any (
    "-w h","-w hi","-w hid","-w hidd","-w hidde","-w hidden",
    "-wi h","-wi hi","-wi hid","-wi hidd","-wi hidde","-wi hidden",
    "-win h","-win hi","-win hid","-win hidd","-win hidde","-win hidden",
    "-wind h","-wind hi","-wind hid","-wind hidd","-wind hidde","-wind hidden",
    "-windo h","-windo hi","-windo hid","-windo hidd","-windo hidde","-windo hidden",
    "-window h","-window hi","-window hid","-window hidd","-window hidde","-window hidden",
    "-windows h","-windows hi","-windows hid","-windows hidd","-windows hidde","-windows hidden",
    "-windowst h","-windowst hi","-windowst hid","-windowst hidd","-windowst hidde","-windowst hidden",
    "-windowsty h","-windowsty hi","-windowsty hid","-windowsty hidd","-windowsty hidde","-windowsty hidden",
    "-windowstyl h","-windowstyl hi","-windowstyl hid","-windowstyl hidd","-windowstyl hidde","-windowstyl hidden",
    "-windowstyle h","-windowstyle hi","-windowstyle hid","-windowstyle hidd","-windowstyle hidde","-windowstyle hidden"
)
DeviceNetworkEvents
| where not(ActionType == "ConnectionFailed")
| where not(ipv4_is_private(RemoteIP) and ipv6_is_in_any_range(RemoteIP, @"::1/128",@"ff00::/8","fe80::/10", "fc00::/7"))
| where InitiatingProcessParentFileName =~ "powershell.exe"
| join kind=inner (DeviceProcessEvents) on DeviceId, $left.InitiatingProcessParentFileName == $right.InitiatingProcessFileName, $left.InitiatingProcessParentId == $right.InitiatingProcessId
| where InitiatingProcessCommandLine1 matches regex @"(?i)-wi?n?d?o?w?s?t?y?l?e? hi?d?d?e?n?"
```
