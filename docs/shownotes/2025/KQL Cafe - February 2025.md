# KQL Cafe - February 2025

## Recording and Presentation

- [Recording]()

## Hosts

- [Gianni](https://twitter.com/castello_johnny)
- [Alex](https://twitter.com/alexverboon)

## Guests

- [Name](http://example.url)

## KQL News

### KQL.HOW

- [kql.how](https://kql.how/)

This KQL reference contains information on the KQL language. The Guide is updated regularly to reflect the latest changes in Microsoft products. Each documentation part is presented with a syntax, supporting articles and often with examples.

While this KQL Guide is a ProBI project created and maintained by Brian Bønk, it also incorporates official Microsoft documentation to provide you with the most accurate and up-to-date information.

### Monitor For New Actions In Sentinel And MDE

[Bert-Jan Pals](https://www.linkedin.com/in/bert-janpals/) shared a blog post explaining how to monitor new actions in Microsoft Sentinel and Defender for Endpoint by using a Logic App to generate weekly reports. This proactive solution helps identify potential threats, anomalies, and patterns in the data. The author provides a step-by-step guide to deploying the Logic App, configuring necessary permissions, and adjusting settings for different environments. The solution ensures that organizations stay updated on new actions and maintain robust security monitoring.

- [Monitor For New Actions In Sentinel And MDE](https://kqlquery.com/posts/monitor-new-actions/)

### 100 Days of KQL

New Year, new challenge? Taking inspiration from [Matt Zorich](https://x.com/reprise_99), [SecurityAura](https://x.com/SecurityAura) has started
a #100DaysOfKQL. You can find the KQL queries in this [GitHub Repo](https://github.com/SecurityAura/DE-TH-Aura/tree/main/100DaysOfKQL)

## Guest

- [Uri Barash](https://www.linkedin.com/in/uribarash/)
Product Management: Kusto, Fabric Real Time Analytics, Azure Data Explorer

Uri provided an introduction with live demos on [Microsoft Fabric](https://www.microsoft.com/en-us/microsoft-fabric)

## Learn KQL

### SC-200: Create queries for Microsoft Sentinel using Kusto Query Language (KQL)

- Construct KQL Statements for Microsoft Sentinel
- Analyze Query Results Using KQL
- Build Multi-Table Statements Using KQL
- Work with Data in Microsoft Sentinel Using Kusto Query Language

[Reference](https://learn.microsoft.com/en-us/training/paths/sc-200-utilize-kql-for-azure-sentinel/)

### Basics for SOC Analysts from Thomas Bründl

[Thomas Bründl](https://x.com/TBrundl) wrote a series of blog posts:

- [KQL - Basics for SOC - Analysts #1 - Take](https://it-infrastructure.solutions/kql-basics-for-soc-analysts-1-take/)
- [KQL - Basics for SOC - Analysts #2 – Search](https://it-infrastructure.solutions/kql-basics-for-soc-analysts-2-search/)
- [KQL - Basics for SOC - Analysts #3 – Where](https://it-infrastructure.solutions/kql-basics-for-soc-analysts-3-where/)
- [KQL - Basics for SOC - Analysts #4 – Distinct](https://it-infrastructure.solutions/kql-basics-for-soc-analysts-4-distinct/)

### Understanding KQL Functions

[Sarah Lean](https://x.com/techielass?ref=techielass.com) wrote a blog post about various Kusto Query Language (KQL) functions used to manipulate and analyze data.

- [Understanding KQL Functions](https://www.techielass.com/understanding-kql-functions/)

### Regex

[Gianni](https://twitter.com/castello_johnny) talked about [RegEx](https://learn.microsoft.com/en-us/kusto/query/regex?view=microsoft-fabric). Below are the kql query examples.

```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath matches regex "WindowsApps"
```

```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath matches regex @"^C:\\" // StartsWith ^
```

```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath matches regex ".exe$" // EndsWith $ 
```

```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath matches regex @"C:\\Users\\*\\" // 0 or more
```

```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath matches regex @"C:\\Users\\\w*\\" // 0 or more
```

```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath matches regex @"C:\\Users\\[[:alpha:]]*\\" // 0 or more
```

```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath matches regex @"C:\\Users\\[a-zA-Z]*\\" // 0 or more
```

```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath matches regex @"C:\\Users\\[a-zA-Z]?\\" // 0 or 1
```

```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath matches regex @"C:\\Users\\[a-zA-Z]+\\" // 1 or more
```

```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath matches regex @"C:\\Users\\[a-zA-Z0-9]+\\" // 1 or more
```

```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath matches regex @"C:\\Users\\[[:alnum:]]+\\" // 1 or more
```

```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath matches regex @"C:\\Users\\[A-Za-z0-9._\s@&!\\\-',À-ÿ():\-|а-яА-ЯёЁ]+\\" // 1 or more
```

```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath matches regex @"(?i)c:\\users\\[a-z]+\\(documents|pictures|video|musics|favorites)" // Case insensitive and multiple options
```

## What did you do with KQL this month?

### Finding GitHub repos used

[Alex](https://twitter.com/alexverboon) shared the below query. The purpose of this query is to use Defender for Endpoint telemtry data to identify the repositories users have in use.
The inspiration for this query came from a customer who had no overview of the repositories in use within their company.

```kql
DeviceProcessEvents
| where ProcessCommandLine contains "git "
| extend GitRepo = extract(@"(https?:\/\/[^\s]+\.git|https?:\/\/[^\s]+_git\/[^\s]+)", 0, ProcessCommandLine)
| where isnotempty(GitRepo)
| project GitRepo, FileName, InitiatingProcessFileName, ProcessCommandLine, AccountUpn, DeviceName
| summarize Devices = make_set(DeviceName), TotalDevices = dcount(DeviceName), Users = make_set(AccountUpn), TotalUsers = dcount(AccountUpn) by GitRepo
```
