# KQL Cafe - February 2023

## Recording and Presentation

- [Recording](https://youtu.be/JGyyyhESsz4)
- [Presentation](/docs/Presentations/KQL%20Cafe%20-%20February%202023.pdf)

## Hosts

- [Gianni](https://twitter.com/castello_johnny)
- [Alex](https://twitter.com/alexverboon)

## Guests

- [Ugur Koc](https://twitter.com/UgurKocDe)

## News

- [Interactive KQL Cheatsheet](https://blog.amestofortytwo.com/kqlcheat/)
- [KQL Baby](https://github.com/davidnx/baby-kusto-csharp)

## What did you do with KQL this month?

### Tampering Events

- [Tampering Events](https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/introducing-tamper-protection-for-exclusions/ba-p/3713761)

```kql
DeviceEvents
| where TimeGenerated > ago (30d)
| where ActionType == @"TamperingAttempt"
| extend AF = parse_json(AdditionalFields)
| evaluate bag_unpack(AF)
```

```kql
DeviceEvents
| where TimeGenerated > ago (30d)
| where ActionType == @"TamperingAttempt"
| extend AF = parse_json(AdditionalFields)
| evaluate bag_unpack(AF,columnsConflict='keep_source') : (DeviceName:string,TimeGenerated:datetime,ActionType:string,Status:string, TamperingAction:long,Target:string)
```

### Parse Commandline

```kql
DeviceEvents
| where ActionType contains "PowerShell"
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine
| extend Cmd1 = parse_command_line(InitiatingProcessCommandLine,"windows")
| mv-expand Cmd1
| summarize count() by tostring(Cmd1)
```

```kql
DeviceNetworkEvents
| extend Cmd1 = parse_command_line(InitiatingProcessCommandLine,"windows")
| where Cmd1 contains "Download"
| mv-expand Cmd1
| project Cmd1, RemoteUrl
```

### Go HUnt - ABC of threat hunting

- [ABC of threat hunting](https://www.microsoft.com/en-us/security/business/security-insider/wp-content/uploads/2023/01/ABCs_of_Threat_Hunting.pdf)

#### A

```kql
// Was there a new sign-on using the credential?​
let AccountDomainToResearch = '';// leave blank for local accounts​
let AccountNameToResearch = ''; ​
DeviceLogonEvents​
| where iff(isempty(AccountDomainToResearch), AccountDomain == DeviceName, AccountDomain =~ AccountDomainToResearch) and AccountName =~ AccountNameToResearch​
| summarize EarliestTimestamp = min(Timestamp), LatestTimestamp = max(Timestamp), Attempts = count() by ActionType, DeviceId, DeviceName, RemoteIP, Protocol​
| order by EarliestTimestamp desc ​
```
​
```kql
let AccountDomainToResearch = '';​
let AccountNameToResearch = ''; ​
IdentityLogonEvents​
| where ​
    AccountName =~ AccountNameToResearch and ​
    AccountDomain =~ AccountDomainToResearch​
| summarize EarliestTimestamp = min(Timestamp), LatestTimestamp = max(Timestamp), Attempts = count() by ActionType, Application, LogonType,DeviceName, IPAddress, DestinationDeviceName, DestinationIPAddress, DestinationPort​
| project-reorder EarliestTimestamp, LatestTimestamp​
| order by EarliestTimestamp desc​
```

```kql
​​// Were any other credentials potentially compromised?​
AlertInfo​
| where AttackTechniques contains "T1557" // Adversary-in-the-Middle​
    or AttackTechniques contains "T1110" // Brute Force​
    or AttackTechniques contains "T1555" // Credentials from Password Stores​
    or AttackTechniques contains "T1212" // Exploitation for Credential Access​
    or AttackTechniques contains "T1187" // Forced Authentication​
    or AttackTechniques contains "T1606" // Forge Web Credentials​
    or AttackTechniques contains "T1056" // Input Capture​
    or AttackTechniques contains "T1556" // Modify Authentication Process​
    or AttackTechniques contains "T1111" // Multi-Factor Authentication Interception​
    or AttackTechniques contains "T1621" // Multi-Factor Authentication Request generation​
    or AttackTechniques contains "T1040" // Network Sniffing​
    or AttackTechniques contains "T1003" // OS Credential Dumping​
    or AttackTechniques contains "T1528" // Steal Application Access Token​
    or AttackTechniques contains "T1558" // Steal or Forge Kerberos Tickets​
    or AttackTechniques contains "T1539" // Steal Web Session Cookie​
    or AttackTechniques contains "T1552" // Unsecured Credentials​
| join kind=leftouter AlertEvidence on AlertId​
```

```kql
// Did the identity have administrator or root permissions to the device? ​
let AccountNameToResearch = '';​
let AccountDomainToResearch = ''; // Leave blank if local​
DeviceInfo​
| where OSPlatform startswith "Windows" and OnboardingStatus == 'Onboarded'​
| join kind=rightsemi DeviceProcessEvents on DeviceId​
//| where AccountName =~ AccountNameToResearch and iff(isempty(AccountDomainToResearch), AccountDomain =~ DeviceId, AccountDomain =~ AccountDomainToResearch)​
| extend IsElevated = (ProcessTokenElevation != 'None')​
| summarize IsAdmin = max(IsElevated) by AccountDomain, AccountName​
```

```kql
// Does the identity have administrator or root permissions to other devices or to your authentication service​
let AccountNameToResearch = '';​
let AccountDomainToResearch = ''; // Leave blank if local​
DeviceInfo​
| where OSPlatform startswith "Windows" and OnboardingStatus == 'Onboarded'​
| join kind=rightsemi DeviceProcessEvents on DeviceId​
//| where AccountName =~ AccountNameToResearch and iff(isempty(AccountDomainToResearch), AccountDomain =~ DeviceId, AccountDomain =~ AccountDomainToResearch)​
| extend IsElevated = (ProcessTokenElevation != 'None')​
| summarize IsAdmin = max(IsElevated) by DeviceId, DeviceName​
| order by IsAdmin desc
```

#### B

```kql
// Was the suspicious activity associated with any known malware?​
let DeviceIdToResearch = ''; ​
DeviceEvents​
| where DeviceId =~ DeviceIdToResearch and ​
    ActionType startswith "AntivirusDetection"​
| extend AdditionalFields = parse_json(AdditionalFields)​
| extend ThreatName = tostring(AdditionalFields.ThreatName), ​
    WasExecutingWhileDetected = tobool(AdditionalFields.WasExecutingWhileDetected),​
    WasRemediated = tobool(AdditionalFields.WasRemediated)​
| project-reorder Timestamp, ThreatName, WasExecutingWhileDetected, WasRemediated, FolderPath, SHA256, InitiatingProcessAccountDomain, InitiatingProcessAccountName​
```​

```kql
// Were any suspicious auto-start entries created by the identity?​
let AccountNameToResearch = '';​
let AccountDomainToResearch = ''; // leave blank for local accounts​
let DeviceIdToResearch = ''; // leave blank for all devices​
union DeviceRegistryEvents,​
(​
    DeviceEvents​
    | where ActionType in ('ServiceInstalled','DriverLoad','ScheduledTaskCreated','ScheduledTaskUpdated')​
)​
| where (isempty(DeviceIdToResearch) or DeviceId =~ DeviceIdToResearch) and ​
    InitiatingProcessAccountName =~ AccountNameToResearch and ​
    iff(isempty(AccountDomainToResearch), InitiatingProcessAccountDomain =~ DeviceName, InitiatingProcessAccountDomain =~ AccountDomainToResearch)
```

```kql
// Were any new accounts created?​
let DeviceIdToResearch = ''; ​
DeviceEvents​
| where DeviceId =~ DeviceIdToResearch and ​
    ActionType == 'UserAccountCreated'
```​

```kql
// Is the backdoor associated with any other alerts?​
let BackdoorSha256 = '';​
AlertEvidence​
| where SHA256 =~ BackdoorSha256​
| join kind=rightsemi AlertInfo on AlertId​
```

```kql
// Is the backdoor present on any other devices?​
let BackdoorSha256 = '';​
union (​
    DeviceProcessEvents​
    | where SHA256 =~ BackdoorSha256​
), (​
    DeviceFileEvents​
    | where InitiatingProcessSHA256 =~ BackdoorSha256​
)​
```
​
```kql
// What network connections were made by the backdoor?​
let BackdoorSha256 = '';​
DeviceNetworkEvents​
| where InitiatingProcessSHA256 =~ BackdoorSha256​
```

#### C

```kql
// Did the communication occur with an intended capability, an unintended capability, or an attacker installed backdoor?​
// Was the communication inbound, outbound, or did it use a proxy or other intermediary?​
let RemoteIpToResearch = '';​
DeviceNetworkEvents​
| where RemoteIP == RemoteIpToResearch​
```​

```kql
// Was authentication performed during the communication?​
let RemoteIpToResearch = '';​
DeviceLogonEvents​
| where RemoteIP == RemoteIpToResearch​
```​

```kql
// What is the earliest and latest timeframe associated with the communication?​
let RemoteIpToResearch = '';​
DeviceNetworkEvents​
| where RemoteIP == RemoteIpToResearch​
| summarize EarliestCommunication = min(Timestamp), LatestCommunication = max(Timestamp) by DeviceId, DeviceName, LocalIP, LocalPort​
| order by EarliestCommunication asc​
```

```kql
​// Are there any other potential backdoors associated with the communication?​
let RemoteIpToResearch = '';​
DeviceNetworkEvents​
| where RemoteIP == RemoteIpToResearch​
| summarize DistinctDevices = dcount(DeviceId), Events = count() by InitiatingProcessFolderPath, InitiatingProcessSHA256​
```
