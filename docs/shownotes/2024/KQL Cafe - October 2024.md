# KQL Cafe - October 2024

## Recording and Presentation

- [Recording](https://www.youtube.com/watch?v=vD9gsQzIZnI) 
- [Presentation](/docs/Presentations/KQL%20Cafe%20-%20October%202024.pdf)

## Hosts

- [Gianni](https://twitter.com/castello_johnny)
- [Alex](https://twitter.com/alexverboon)

## Guests

- [Koos Goosens](https://x.com/KoosGoossens)

## News

### KustoCon

- [KustoCon Online Conference](https://www.kustocon.com)

### MC906487 - Microsoft Defender XDR: InitiatingProcessFolderPath changes to include file names

Microsoft Defender for Endpoint will update the InitiatingProcessFolderPath to include file names in all tables, affecting Windows activity. This change will be globally available on November 4, 2024, requiring updates to custom detection rules and queries.

Before this rollout, the InitiatingProcessFolderPath column is inconsistent across action types. Some columns include the file name, and other columns do not include the file name.
After the rollout, all Microsoft Defender for Endpoint action types across all tables will report the full path including the file name of the initiating process in the InitiatingProcessFolderPath column.

Consider the following example to be the new normal, InitiatingProcessFolderPath == c:\temp\file.exe
An example of a possible current implementation that will be retired with this change: InitiatingProcessFolderPath == c:\temp\
Custom detection rules and queries considering the InitiatingProcessFolderPath may be affected.

- Source: [Details](https://mc.merill.net/message/MC906487)

#### Unleash The Power Of DeviceTvmInfoGathering

- [Blogpost from Bet-Jan Cyber](https://kqlquery.com/posts/devicetvminfogathering/)

### Rod Trent shared his session content from the Midwest Management Summit Flamingo Edition 2024

- [Slides and Presentation](https://github.com/rod-trent/JunkDrawer/tree/main/MMSFlamingo2024)

### KQL Threathunting with JohnDCyber

Explore a collection of KQL queries crafted for dynamic threat hunting across a diverse range of topics, techniques, and use cases!  These queries are designed as your launchpad - ready to be tailored to your unique environment and evolving threat landscape.  

- [Source](https://github.com/johdcyber/KQL_threathunting_with_john_d_cyber)

### Azure MFA Enforcement

[Nicola Suter](https://twitter.com/nicolonsky) wrote some KQL queries regarding the mandatory multifactor authentication for Azure and other admin portals by Microsoft.

- [Source](https://github.com/nicolonsky/ITDR/blob/main/Queries/Azure-MFA-Enforcement.md#check-the-current-mfa-requirement-provider-for-portals)

- [Planning for mandatory multifactor authentication for Azure and other admin portals](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mandatory-multifactor-authentication)

### Defender for Cloud Apps – Shadow Reporting

If you have queries on McasShadowItReporting note the value change for the StreamName for MDE data

Possible vlaues in StreamName for MDE are:

- Defender-managed-endpoints
- Win10 Endpoint Users

Defender-managed-endpoints refers to all Windows and Mac devices onboarded in MDE that gather network data and share this with Defender for Cloud Apps for Shadow IT discovery.
Win10 Endpoint Users is the old name of the stream

## Our Guest

- [Koos Goosens](https://x.com/KoosGoossens)
- [Koos Blog](https://aka.ms/koos)
- [Koos GitHub](https://github.com/TheCloudScout?tab=repositories)

- [Unlimited Advanced Hunting for Microsoft 365 Defender with Azure Data Explorer](https://github.com/TheCloudScout/m365defender-adx)
- [Split up your logs with $pl1tR](https://github.com/TheCloudScout/log-splitr)

## What did you do with KQL This month?

### MDE - Defender Antivirus Exclusion Enumeration activities

- [Source](https://github.com/alexverboon/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Endpoint/MDE-DefenderExclusionsEnumerations.md)

### Mitigations for CVE-2024-38124 - Implement monitoring for any suspicious renaming activities of computers within the network

- [Source](https://github.com/alexverboon/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Endpoint/MDE-DeviceRename.md)

### MDE-DefaultLocalAdmin-Logon

Contribution from [Loris Ambrozzo](https://x.com/LorisAmbrozzo)

This KQL query identifies logon events for the default local administrator (.\Administrator) with SID starting with S-1-5 and ending with 500 (according well-know SIDs). As the default domain administrator also starts with S-1-5 and ends with -500, the query includes a table containing the default domain administrator's SID of the domain to exclude these logons.

- [Source](https://github.com/lorisAmbrozzo/KQL-Queries/blob/main/Defender%20For%20Endpoint/MDE-DefaultLocalAdmin-Logon.md)

### Defender deployment Rings

Gianni shared a few queries to gather Defender Antivirus deployment Ring information.

- [Deploy Microsoft Defender Antivirus in rings](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-ring-deployment)

```kql
DeviceTvmInfoGathering
| extend AF = parse_json(AdditionalFields)
```

```kql
DeviceTvmInfoGathering
| extend AF = parse_json(AdditionalFields)
| evaluate bag_unpack(AF)
```

```kql
DeviceTvmInfoGathering
| extend AF = parse_json(AdditionalFields)
| evaluate bag_unpack(AF)
| project-keep *Signature*
```

```kql
DeviceTvmInfoGathering
| extend AF = parse_json(AdditionalFields)
| evaluate bag_unpack(AF)
| project-keep *Signature*, LastSeenTime
```

```kql
DeviceTvmInfoGathering
| extend AF = parse_json(AdditionalFields)
| evaluate bag_unpack(AF)
| project-keep *Signature*, LastSeenTime, DeviceId
| join kind=inner (DeviceInfo | summarize arg_max(Timestamp,*) by DeviceId) on DeviceId
```