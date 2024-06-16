# KQL Cafe 28. November 2023

- [Recording](https://youtu.be/gM4C4RpEDqA?si=lmL8TfGBTOCRNuR5)
- [Presentation](../Presentations/KQL%20Cafe%20-%20November%202023.pdf)

## Hosts

- [Gianni](https://twitter.com/castello_johnny)
- [Alex](https://twitter.com/alexverboon)

## Guests

 [Ugur Koc](https://twitter.com/UgurKocDe)

## News

- [Detect malware communication using SSL inspection](https://github.com/cyb3rmik3/KQL-threat-hunting-queries/blob/main/02.ThreatDetection/ssl-inspection-for-malware-cnc.md)
- [Analyzing MITRE ATT&CK Detection with KQL](https://github.com/LearningKijo/KQL/blob/main/KQL-Effective-Use/17-kql-MITRE-ATTCK-Detection.md)
- [KQL Functions For Network Operations](https://kqlquery.com/posts/kql-for-network-operations/)
- [DNS requests to suspicious TLDs](https://github.com/cyb3rmik3/KQL-threat-hunting-queries/blob/main/01.ThreatHunting/dns-requests-to-suspicious-tlds.md)
- [The KQL Mysteries: Prologue](https://rodtrent.substack.com/p/the-kql-mysteries-prologue)
- [Public Preview: Azure Log Alerts support for Azure Resource Graph (ARG)](https://azure.microsoft.com/en-us/updates/public-preview-azure-log-alerts-support-for-azure-resource-graph-arg/)
- [Azure Monitor Data Collection API Retirement](https://azure.microsoft.com/en-us/updates/azure-monitor-data-collection-api-retirement/)

## Tools

- [KQL Query Helper](https://chat.openai.com/g/g-bE8NlTPzO-kql-query-helper)

## Training

- [Hands-On Kusto Query Language (KQL) for Security Analysts](https://academy.bluraven.io/)

## Learning KQL

### AS operator

run queries at

- [Log Analytics Demo](https://aka.ms/lademo)

```kql
Perf
| take 10
```

```kql
Perf
| count
```

```kql
let Totals = Perf
| summarize count() by ObjectName, CounterName;
Totals
```

```kql
let Totals = Perf
| summarize count() by ObjectName, CounterName;
Totals
```

```kql
let Totals = Perf
| project TimeGenerated, Computer, ObjectName, CounterName
;
Totals
```

```kql
Perf
| project TimeGenerated, Computer, ObjectName, CounterName
| as tPerf
| summarize count() by ObjectName, CounterName
| join kind=inner tPerf on ObjectName, CounterName
```

```kql
let tPerf =  Perf
| project TimeGenerated, Computer, ObjectName, CounterName
| summarize count() by ObjectName, CounterName;
Perf
| join kind=inner tPerf on ObjectName, CounterName
```

## Guest

- [Ugur Koc](https://twitter.com/UgurKocDe)
- [kqlsearch.com](https://kqlsearch.com)
