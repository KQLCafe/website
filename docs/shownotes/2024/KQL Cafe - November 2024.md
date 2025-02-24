# KQL Cafe - November 2024

## Recording and Presentation

- [Recording](https://www.youtube.com/watch?v=lcN4LBtPKPk)

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

### Time Travel in KQL

The basics

```kql
// must set the datetimescope_column
// set query_datetimescope_column = "TimeGenerated";
// set query_datetimescope_from = datetime(2024-09-01 19:16:00);
// set query_datetimescope_to = datetime(2024-09-14 19:16:00);
// set query_now = datetime(2023-09-14 19:16:00);
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(30d)
| summarize min(TimeGenerated), max(TimeGenerated), count()
```

Testing the query as of certain dates in the past without modifying the now() and ago() parts.

```kql
// Author: MattZorich (reprise_99)
//Detect anomalies in the amount of conditional access failures by users in your tenant, then visualize those conditional access failures
//Data connector required for this query - Azure Active Directory - Signin Logs
//Starttime and endtime = which period of data to look at, i.e from 21 days ago until today.
set query_datetimescope_column = "TimeGenerated";
set query_datetimescope_from = datetime(2024-07-01 19:16:00);
set query_datetimescope_to = datetime(2024-11-24 19:16:00);
set query_now = datetime(2024-11-24 19:16:00);
let startdate=21d;
let enddate=1d;
//Timeframe = time period to break the data up into, i.e 1 hour blocks.
let timeframe=1h;
//Sensitivity = the lower the number the more sensitive the anomaly detection is, i.e it will find more anomalies, default is 1.5
let sensitivity=0;
//Threshold = set this to tune out low count anomalies, i.e when total failures for a user doubles from 1 to 2
let threshold=5;
let outlierusers=
    SigninLogs
    | where TimeGenerated between (startofday(ago(startdate))..startofday(ago(enddate)))
    | where ResultType == 53003
    | project TimeGenerated, ResultType, UserPrincipalName
    | make-series CAFailureCount=count() on TimeGenerated from startofday(ago(startdate)) to startofday(ago(enddate)) step timeframe by UserPrincipalName 
    | extend outliers=series_decompose_anomalies(CAFailureCount, sensitivity)
    | mv-expand TimeGenerated, CAFailureCount, outliers
    | where outliers == 1 and CAFailureCount > threshold
    | distinct UserPrincipalName
    ;
//Optionally visualize the anomalies
SigninLogs
| where TimeGenerated between (startofday(ago(startdate))..startofday(ago(enddate)))
| where ResultType == "53003"
| project TimeGenerated, ResultType, UserPrincipalName
| where UserPrincipalName in (outlierusers)
| summarize CAFailures=count()by UserPrincipalName, bin(TimeGenerated, timeframe)
| render timechart with (ytitle="Failure Count",title="Anomalous Conditional Access Failures")
```

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
