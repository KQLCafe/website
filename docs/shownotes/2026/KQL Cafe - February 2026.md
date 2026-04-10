# KQL Cafe - February 2026

## Recording

- [Recording](https://www.youtube.com/watch?v=3XexqnAowQ4)

## Hosts

- [Gianni](https://twitter.com/castello_johnny)
- [Alex](https://twitter.com/alexverboon)

## Guests

- [Michael Krane](https://www.linkedin.com/in/michael-crane-70b44539/)

## KQL News

The news section highlighted recent updates and community contributions in the KQL and Microsoft security space. There were changes to the BehaviorInfo and BehaviorEntities tables, including new columns, updated descriptions, and added MITRE ATT&CK references, which are particularly relevant for users working with UEBA in Microsoft Sentinel.

[Reference](https://github.com/MicrosoftDocs/defender-docs/commit/17e199c94cb03d6e9ba5c9505c9ace7d71b6a504)

A new course, Practical Threat Hunting for Beginners by Mehmet, was mentioned as a valuable learning resource for both new and experienced KQL users.

[Reference](https://academy.bluraven.io/course/practical-threat-hunting-for-beginners)

The hosts also referenced community work from Bert-Jan, including tooling to track Defender action types and a new detection engineering blog series covering best practices like handling ingestion delays and data normalization.

[Reference](https://kqlquery.com/posts/monitor-new-actions-sentinel-defender-xdr/)

Additionally, research by Thomas Kurth was highlighted, focusing on potential attack scenarios involving Microsoft Intune misuse, along with related detection queries shared publicly.

[Reference](https://medium.com/@kurtli_thomas/detecting-threats-when-attackers-exploit-management-tools-microsoft-intune-71823956630d)

Other updates included Rod Trent’s beta “Must Learn KQL” app and new community contributors sharing KQL queries on GitHub and social platforms, reflecting continued growth and collaboration in the KQL ecosystem.

[Reference](https://testflight.apple.com/join/cyAUvWyw)
[Reference](https://x.com/Valhguard)
[Reference](https://github.com/NVISOsecurity/Detection-and-Hunting-Queries)

## Guest

- [Michael Krane](https://www.linkedin.com/in/michael-crane-70b44539/)

This month’s guest was Michael Crane from Microsoft, and he spoke about using KQL far beyond simple hunting queries. His session focused on how KQL can support identity threat detection and response, digital forensics, governance, compliance, and cost-aware security operations.

He explained that one of the biggest challenges in Microsoft Sentinel is deciding what telemetry to collect without driving costs too high. Rather than logging everything, he emphasized collecting the right data, transforming it where needed, and using different storage tiers strategically. A major example was reducing noisy non-interactive sign-in log data by filtering unnecessary Conditional Access details, which can significantly lower ingestion costs while keeping the important signals.

Michael also showed how KQL can be mapped to security and compliance controls. He demonstrated an approach where specific KQL queries are tied to control requirements, data sources, and MITRE ATT&CK techniques. This makes it easier for analysts to investigate activity, for auditors to validate evidence, and for organizations to prove that the required telemetry is actually being collected.

A particularly interesting part of the session was his workbook-based solution that combines KQL, Logic Apps, managed identities, and Azure OpenAI. With this setup, users can select a control area, see the related KQL queries, review the event results, and even get AI-generated summaries and MITRE mappings. He described this as a practical way to bridge compliance, operations, and threat hunting.

He also touched on MCP and AI-assisted development, showing how these tools can help accelerate the creation of workbooks and detections. At the same time, he was clear that AI does not replace KQL knowledge. Strong grounding in KQL, data structure, and security use cases is still essential to build reliable and useful solutions.

## Learn KQL

In the Learn KQL section, Gianni introduced the column_ifexists() operator, which helps make detections more resilient when working with inconsistent or incomplete datasets. By checking whether a column exists and assigning a default value if it doesn’t, queries and detection rules can run reliably even when data structures vary.

He also shared a practical approach to optimizing DNS log ingestion in Microsoft Sentinel. By analyzing DNS query data over time, identifying high-volume and commonly queried domains, and correlating them with client activity and data size, it becomes easier to decide which domains can be safely excluded.

These insights can then be applied in Data Collection Rules (DCRs) to filter out low-value or noisy DNS traffic, reducing ingestion costs while keeping relevant security data.



