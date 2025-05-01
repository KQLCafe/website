# KQL Cafe - April 2025

## Recording

- [Recording]()

## Hosts

- [Gianni](https://twitter.com/castello_johnny)
- [Alex](https://twitter.com/alexverboon)

## Guests

- [Bert-Jan](https://twitter.com/BertJanCyber)

## KQL News

### Just another Kusto hacker (JAKH)

Your challenge is to write a Kusto query that outputs the string "Just another Kusto hacker". The query can be as simple or as complex as you like, as long as it is self-contained and can run on any Fabric EventHouse or Azure Data Explorer cluster.

[Source](https://github.com/microsoft/just-another-kusto-hacker)

### KustoCon 2025 Anouncement

KustoCon will run on November 6th, 2025

This year the KustoCon Conference will run in Hybrid Mode. With exclusive Workshops in the morning for those attending onsite and KustoCon sessions in the afternoon for both onsite and online participants.

We will share more details soon on [KustoCon.com](https://www.kustocon.com)

### The Ultimate Kusto Detective Challenge - Call of the Cyber Duty

There's a new Kusto Detective Agency challenge comming. This time you play in a team.

Your mission, should you choose to accept it: uncover the truth hidden in the data — and maybe, just maybe, save the world.
Our headquarters are in Digitown — the world’s first fully observable city, where data isn’t just stored... it’s alive..........

[Intro Video](https://youtu.be/sPmTvXOZrnE?si=9ULwcAhMHqBaKdKH)
[Register](https://detective.kusto.io/register)
[Cyber Duty Rules](https://detective.kusto.io/CyberDutyRules)

### OAuthAppInfo

The OAuthAppInfo table in the advanced hunting schema contains information about Microsoft 365-connected OAuth applications in the organization that are registered with Microsoft Entra ID and available in the Microsoft Defender for Cloud Apps app governance capability.

[Source](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-oauthappinfo-table)

### Changes to the IdentityInfo table in Advanced Hunting

[Microsoft Defender XDR services: Changes to the IdentityInfo table in Advanced Hunting](https://admin.microsoft.com/Adminportal/Home?ref=MessageCenter/:/messages/MC1052160)
[IdentityInfo](ttps://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identityinfo-table)
[Microsoft Sentinel UEBA reference](https://learn.microsoft.com/en-us/azure/sentinel/ueba-reference)

## Guest

[Bert-Jan](https://twitter.com/BertJanCyber)

This month we had Bert-Jan back on the show. Bert-Jan gave an inspiring talk on automation, using the various Microsoft Security APIs and creating reports.

References:

- [CISA KEV](https://github.com/Bert-JanP/Sentinel-Automation/tree/main/CISA-KEV-Weekly-Report)
- [Device Enrichment](https://github.com/Bert-JanP/Sentinel-Automation/tree/main/Device%20Enrichment)
- [SLA](https://github.com/Bert-JanP/Sentinel-Automation/tree/main/SLA%20Reporting%20Mail%20Report)
- [New actions: Sentinel-Automation/Report](https://github.com/Bert-JanP/Sentinel-Automation/tree/7bb4ce23259eec14060e4b60048b4d0131979836/Report%20New%20Actions)
- [Sentinel Automation](https://github.com/Bert-JanP/Sentinel-Automation)
- [Audit Defender XDR Activities](https://kqlquery.com/posts/audit-defender-xdr/)
- [Defender XDR Hunting and Detection Rules](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/tree/7f90eba1d0ba356f3247bf1c622dedff346e29c2/Defender%20XDR)

## What did you do with KQL this month?

### Defender for Endpoint - Identify Portable Apps

Auhtor: [Alex](https://twitter.com/alexverboon)

```kql
DeviceFileEvents
| where parse_json( AdditionalFields).FileType has_any ("PortableExecutable")
| extend FileExtension = parse_path(FolderPath).Extension
| where FileExtension == "exe"
| project FileName, FolderPath, FileOriginUrl, FileOriginReferrerUrl, AdditionalFields
| where isnotempty( FileOriginUrl)
```

```kql
DeviceFileEvents
| where parse_json( AdditionalFields).FileType has_any ("PortableExecutable")
| extend FileExtension = parse_path(FolderPath).Extension
| where FileExtension == "exe"
| project FileName, FolderPath, FileOriginUrl, FileOriginReferrerUrl, AdditionalFields
| where isnotempty( FileOriginUrl)
| summarize  Files = make_set(FileName), count() by FileOriginReferrerUrl
```

```kql
DeviceFileEvents
| where FileOriginReferrerUrl == "https://portableapps.com/"
```

```kql
DeviceProcessEvents
| where AccountName <> "system"
| where FolderPath matches regex @"^[A-Z]:\\.*$" // Any drive letter
    or FolderPath startswith @"\\" // Network shares
    or FolderPath matches regex @"^C:\\Users\\[^\\]+\\Downloads\\.*$" // Include C:\Users\*\Downloads
    or FolderPath matches regex @"^C:\\Users\\[^\\]+\\Desktop\\.*$" // Include C:\Users\*\Desktop
| where not(FolderPath matches regex @"^C:\\Windows\\.*$") // Exclude C:\Windows and subfolders
| where not(FolderPath matches regex @"^C:\\Program Files( \(x86\))?\\.*$") // Exclude C:\Program Files and Program Files (x86)
| where not(FolderPath matches regex @"^C:\\ProgramData\\.*$") // Exclude C:\ProgramData
| where not(AccountSid startswith "S-1-5-18") // Exclude Local System Account
| where not(AccountSid startswith "S-1-5-20") // Exclude Network Service Account
| project TimeGenerated, FileName, FolderPath, AccountName, AccountUpn, ProcessVersionInfoProductName
```

```kql
DeviceProcessEvents
| project TimeGenerated, FileName, FolderPath, AccountName, AccountUpn, ProcessVersionInfoInternalFileName, ProcessVersionInfoOriginalFileName, ProcessVersionInfoProductName
| where ProcessVersionInfoProductName has "portable"
```

[Source](https://github.com/alexverboon/Hunting-Queries-Detection-Rules/blob/edb701e7221ab59576bbc7349d70fc34a40a852a/Defender%20For%20Endpoint/MDE-PortableApps.md)

### Defender for Office 365 - Identify Non-RFC Compliant Emails

Author: [Alex](https://twitter.com/alexverboon)

```kql
EmailEvents
| where Timestamp >= ago(90d)
| where not(SenderFromAddress matches regex @"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*$")
| project Timestamp,
          SenderMailFromAddress,
          SenderFromAddress,
          Subject,
          RecipientEmailAddress,
          DeliveryAction,
          NetworkMessageId
| order by Timestamp desc
| summarize count() by SenderFromAddress
```

[Source](https://github.com/alexverboon/Hunting-Queries-Detection-Rules/blob/edb701e7221ab59576bbc7349d70fc34a40a852a/Defender%20For%20Office%20365/MDO-Non-RFC%20Compliant%20Emails.md)
