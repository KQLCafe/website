# KQL Cafe - September 2024

## Recording and Presentation

- [Recording](https://www.youtube.com/watch?v=lcN4LBtPKPk)
- [Presetnation](/docs/Presentations/KQL%20Cafe%20-%20November%202024.pdf)

## Hosts

- [Gianni](https://twitter.com/castello_johnny)
- [Alex](https://twitter.com/alexverboon)

## Guests

- [Mehmet Ergene](https://twitter.com/Cyb3rMonk)

## KQL News

### KustoCon Recap

We had a great first KustoCon conference. Check out the session recordings [here](/docs/KustoCon/KustoCon%202024.md)

### Add icons to our KQL query results

Idea from [Sergio Albea](https://www.linkedin.com/in/sergioalbea/)

This one is actually pretty handy,  we can add icons to our KQL query results! They bring a more visual (and dare I say, 'fancy') way to tell different results apart.

```kql
DeviceEvents
| where ActionType == "TamperingAttempt"
| extend OriginalRegistryValue = tostring(parse_json(AdditionalFields).OriginalValue)
| extend Status = tostring(parse_json(AdditionalFields).Status)
| extend TamperingAction = tostring(parse_json(AdditionalFields).TamperingAction)
| extend AttemptedRegistryValue = tostring(parse_json(AdditionalFields).TamperingAttemptedValue)
| where TamperingAction == "RegistryModification"
| extend TamperingAttemptStatus = case(
 Status contains "Blocked", 0,
 Status contains "Ignored", 1,
 -1 )// Default value if neither "Blocked" nor "Ignored" is found)
| extend Status_Result = iif(TamperingAttemptStatus == 0,'🟩💡','🟥🚨')
| distinct DeviceName, TamperingAction, Status_Result,Status, OriginalRegistryValue, AttemptedRegistryValue
```

### Save money on your Sentinel ingestion costs with Data Collection Rules

This blog post explores an effective strategy to optimize data management by reducing log data volume while retaining critical information. It explains how to use Data Collection Rules (DCRs) to filter out less valuable log information, saving costs on data ingress and long-term storage while minimizing analyst fatigue. The post covers the decision-making process for identifying essential log data and provides step-by-step examples of applying DCRs to streamline log collection efficiently.

[blog](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/save-money-on-your-sentinel-ingestion-costs-with-data-collection-rules/4270256)

### Country and Region Information in current_principal_details

Kusto has introduced a new feature that allows users to access information about the country of a user and their tenant region or country as provided by Microsoft Entra ID through the current_principal_details() function. This addition provides enhanced granularity and control in data security and accessibility.

[Blog](https://techcommunity.microsoft.com/blog/azuredataexplorer/country-and-region-information-in-current-principal-details/4275454)
[current_principal_details()](https://learn.microsoft.com/en-us/kusto/query/current-principal-details-function?view=microsoft-fabric)

### Defender XDR – arg() Operator

(GA) The arg() operator in advanced hunting in Microsoft Defender portal is now generally available. Users can now use the arg() operator for Azure Resource Graph queries to search over Azure resources, and no longer need to go to Log Analytics in Microsoft Sentinel to use this operator if already in Microsoft Defender.

[Release Notes](https://learn.microsoft.com/en-us/defender-xdr/whats-new#november-2024)

### Defender XDR - CloudProcessEvents

(Preview) The CloudProcessEvents table is now available for preview in advanced hunting. It contains information about process events in multicloud hosted environments such as Azure Kubernetes Service, Amazon Elastic Kubernetes Service, and Google Kubernetes Engine.
You can use it to discover threats that can be observed through process details, like malicious processes or command-line signatures.

[CloudProcessEvents (Preview)](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudprocessevents-table)

## Guest

- [Mehmet Ergene](https://twitter.com/Cyb3rMonk)

## What did you do with KQL this month?

### Azure DevOps – Organization Policy Change Monitoring

[Alex](https://twitter.com/alexverboon) prepared some additional queries to detect Azure DevOps Organization / Project policy chnages:

- AzureDevOps - Additional Protection when using public package registries
- AzureDevOps - Allow Public Projects
- AzureDevOps - Enable IP Conditional Access policy validation
- AzureDevOps - External Guest Access
- AzureDevOps - Log Audit Events
- AzureDevOps - SSH Authentication
--AzureDevOps - Third-Party application Access via OAuth

[Queries](https://github.com/alexverboon/Hunting-Queries-Detection-Rules/tree/main/AzureDevOps)
