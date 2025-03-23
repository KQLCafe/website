# KQL Cafe - March 2025

## Recording and Presentation

- [Recording](https://www.youtube.com/watch?v=znT_gdYi5Tw)

## Hosts

- [Gianni](https://twitter.com/castello_johnny)
- [Alex](https://twitter.com/alexverboon)

## Guests

- [Sergio Albea](https://www.linkedin.com/in/sergioalbea/)

## KQL News

### Documenting KQL Queries

Here's a blog post from [Sarah](https://bsky.app/profile/techielass.bsky.social?ref=techielass.com) about documeting KQL queries.

Read [here](https://www.techielass.com/documenting-your-kql-queries/)

### KQL Detection Template

If you're creating detections, and are looking for a template, check out Bert-Jan Pals template [here](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/DetectionTemplate.md)

### Kusto Detective Agency S03

The Kusto Detective Agency is back with a new challenge.
Start [here](https://detective.kusto.io/inbox?season=Fabric)

### IdentityInfo Table – Entra ID – eligible Roles

The [IdentityInfo table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identityinfo-table) in hashtag#MicrosoftDefender XDR has been expanded to include eligible roles from hashtag#MicrosoftEntra managed by Privileged Identity Management (PIM).

[Thomas Naunheim](https://bsky.app/profile/naunheim.cloud) has developed a hashtag#KQL function that generates a summarized overview of all directory role assignments, enriched with details from his #EntraOps classification and role definitions. This function is available from his [GitHub repo](https://github.com/Cloud-Architekt/AzureSentinel/blob/main/Functions/PrivilegedIdentityInfo.yaml)

### New Cybersecurity Functions

Over the past weeks, we've seen the following functions added.

| Function Name                   | Description                                                                                   |
|--------------------------------|-----------------------------------------------------------------------------------------------|
| [**detect_anomalous_new_entity_fl()**](https://learn.microsoft.com/en-us/kusto/functions-library/detect-anomalous-new-entity-fl?view=microsoft-fabric&tabs=query-defined) | Detect the appearance of anomalous new entities in timestamped data.                         |
| [**detect_anomalous_spike_fl()**](https://learn.microsoft.com/en-us/kusto/functions-library/detect-anomalous-spike-fl?view=microsoft-fabric&tabs=query-defined)  | Detect the appearance of anomalous spikes in numeric variables in timestamped data.         |
| [**graph_blast_radius_fl()**](https://learn.microsoft.com/en-us/kusto/functions-library/graph-blast-radius-fl?view=microsoft-fabric&tabs=query-defined) | Calculate the Blast Radius (list and score) of source nodes over path or edge data.         |
| [**graph_exposure_perimeter_fl()**](https://learn.microsoft.com/en-us/kusto/functions-library/graph-exposure-perimeter-fl?view=microsoft-fabric&tabs=query-defined) | Calculate the Exposure Perimeter (list and score) of target nodes over path or edge data.   |
| [**graph_path_discovery_fl()**](https://learn.microsoft.com/en-us/kusto/functions-library/graph-path-discovery-fl?view=microsoft-fabric&tabs=query-defined) | Discover valid paths between relevant endpoints (sources and targets) over graph data.      |

### Confgratulations - 𝗦𝗹𝗶𝗺𝗞𝗤𝗟 𝗛𝘂𝗻𝘁𝗶𝗻𝗴 𝗤𝘂𝗲𝗿𝗶𝗲𝘀 𝗮𝗻𝗱 𝗗𝗲𝘁𝗲𝗰𝘁𝗶𝗼𝗻 𝗥𝘂𝗹𝗲𝘀

[Steven Limm](https://www.linkedin.com/in/0x534c/) [GitHub repository](https://github.com/SlimKQL/Hunting-Queries-Detection-Rules), launched in August 2024, has officially achieved "𝗦𝗶𝗹𝘃𝗲𝗿" starstruck status!

***Congratulations!!!***

## Guest

### Detecting Suspicious ISPs with KQL* – Understanding ISP behavior for better **threat detection**

- [Sergio Albea](https://www.linkedin.com/in/sergioalbea/)
- [SCKIPT](https://github.com/Sergio-Albea-Git/SCKIPT)
- [Threat Hunting Queries](https://github.com/Sergio-Albea-Git/Threat-Hunting-KQL-Queries)

ISP/ASN Detection

```kql
let CIDRASN = 
    externaldata(CIDR:string, CIDRASN:int, CIDRASNName:string)
    ["https://firewalliplists.gypthecat.com/lists/kusto/kusto-cidr-asn.csv.zip"]
    with (ignoreFirstRecord=true);
let Malicious_ASN = 
    externaldata(asn:string)
    ["https://www.spamhaus.org/drop/asndrop.json"]
    with (format="multijson");
EmailEvents
| evaluate ipv4_lookup(CIDRASN, SenderIPv4, CIDR, return_unmatched=true)
| extend GeoIPData = geo_info_from_ip_address(SenderIPv4)
| where isnotempty(CIDR)
| extend asn_info = tostring(CIDRASN)
| where DeliveryLocation has "Inbox"
| join kind=inner (Malicious_ASN) on $left.asn_info == $right.asn
| project Timestamp,
          SenderFromAddress,
          SenderMailFromAddress,
          SenderDisplayName,
          SenderMailFromDomain,
          SenderIPv4,
          RecipientEmailAddress,
          Subject,
          DeliveryAction,
          DeliveryLocation,
          ThreatTypes,
          CIDR,
          CIDRASNName,
          asn_info,
          asn
```

ISP Activity based on sign-in attemps

```kql
IdentityLogonEvents
| where Timestamp > ago(30d)
| project ISP, Location, IPAddress, FailureReason
| summarize 
    Different_IPs = dcount(IPAddress),
    valid         = countif(isempty(FailureReason) or FailureReason contains "Success"),
    failure       = countif(isnotempty(FailureReason) and FailureReason !contains "Success"),
    IPs           = make_set(IPAddress)
  by ISP, Location
| order by failure
| where valid == 0 and failure > 5
```

ISP Activity Detection using email threats

```kql
let CIDRASN = 
    externaldata(CIDR:string, CIDRASN:int, CIDRASNName:string)
    [ 
        "https://firewalliplists.gypthecat.com/lists/kusto/kusto-cidr-asn.csv.zip" 
    ]
    with (ignoreFirstRecord=true);
EmailEvents
| evaluate ipv4_lookup(CIDRASN, SenderIPv4, CIDR, return_unmatched=true)
| extend GeoIPData = tostring(geo_info_from_ip_address(SenderIPv4).country)
| summarize
    Different_IPs          = make_set(SenderIPv4),
    Countries              = make_set(GeoIPData),
    set_CIDR               = make_set(CIDR),
    set_SenderFromDomain   = make_set(SenderFromDomain),
    Distinct_IPs           = dcount(SenderIPv4),
    set_ThreatTypes        = make_set(ThreatTypes),
    Delivered_on_Inbox     = countif(DeliveryLocation has "Inbox/folder"),
    Email_Threat           = countif(isnotempty(ThreatTypes)),
    Total_emails           = count(),
    Email_Valid            = countif(isempty(ThreatTypes))
  by CIDR, CIDRASNName, CIDRASN
| extend 
    SuspiciousRatio        = Email_Threat * 1.0 / Total_emails,
    SuspiciousPercentage   = SuspiciousRatio * 100,
    ValidRatio             = Email_Valid * 1.0 / Total_emails,
    ValidPercentage        = ValidRatio * 100
| where SuspiciousPercentage == 100
| project
    CIDRASNName,
    set_SenderFromDomain,
    Countries,
    Distinct_IPs,
    set_ThreatTypes,
    Total_emails,
    Delivered_on_Inbox,
    Email_Threat,
    Email_Valid,
    SuspiciousPercentage,
    ValidPercentage
```

## Learn KQL

### set_intersect and set_difference

Learn from a practical example how to use [set_intersect](https://learn.microsoft.com/en-us/kusto/query/set-intersect-function?view=microsoft-fabric) and [set_difference](https://learn.microsoft.com/en-us/kusto/query/set-difference-function?view=microsoft-fabric)

```kql
set query_now = datetime("Mar 17, 2025 6:00:25 PM");
IdentityLogonEvents
| where ActionType == "LogonSuccess"
| where isnotempty(TargetDeviceName)
| summarize Sources = make_set(DeviceName), Destinations = make_set(TargetDeviceName) by AccountSid, bin(Timestamp, 1d)
| extend JumpHost = set_intersect(Sources, Destinations)
| extend Source = set_difference(Sources, JumpHost)[0]
| extend Destination = set_difference(Destinations, JumpHost)[0]
| extend Path = strcat(Source, " => ", JumpHost[0],  " => ", Destination)
```

## What did you do with KQL this month?

### Command lines by incident

[Gianni's](https://twitter.com/castello_johnny) kql query for extracting commandlines

```kql
SecurityIncident
| where ProviderIncidentId == "1013"
| join kind=inner (
    SecurityAlert
    | extend EP = parse_json(ExtendedProperties)
    | extend ProviderIncidentId = tostring(EP.IncidentId)
    | where isnotempty(ProviderIncidentId)
    | summarize arg_max(TimeGenerated, *) by VendorOriginalId
    )
    on ProviderIncidentId
| extend ET = parse_json(Entities)
| mv-expand ET
| where ET contains "CommandLine"
| extend CommandLine = tostring(ET.CommandLine)
| extend parse_path(CommandLine)
| evaluate bag_unpack(Column1)
| summarize make_set(CommandLine) by ProviderIncidentId, Title, Severity
```

### Azure DevOps - Repositories

[Alex's](https://twitter.com/alexverboon) query to identify Azure DevOps repositories.

```kql
ExposureGraphNodes 
| where NodeLabel == @"azuredevopsrepository"
| extend Subscription = parse_json(EntityIds)[0]["id"]
| extend URL = parse_json(EntityIds)[1]["id"]
| parse Subscription with 
    "/subscriptions/" subscription_id 
    "/resourcegroups/" resource_group 
    "/providers/microsoft.security/securityconnectors/" * 
    "/devops/default/azuredevopsorgs/" azure_devops_org 
       "/projects/" project_name "/repos/" repo_name
| project NodeName, Subscription, URL,subscription_id, resource_group, azure_devops_org, project_name, repo_name
```
