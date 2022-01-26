# Hello KQL 

Date: 25. January 2022

**Hosts**
- [Gianni](https://twitter.com/castello_johnny)
- [Alex](https://twitter.com/alexverboon)
- [Show Presentation](https://github.com/KQLCafe/website/blob/gh-pages/Presentations/KQL%20Cafe%20-%20January%202022.pdf)
- [Show Recording]() comming soon!

**Guest**
- [@rodtrent](https://twitter.com/rodtrent)


This was the very first show of the **KQL Cafe**. where we first shared our mission with the community and explained how we plan to run the show. 

## Our Mission for KQL Cafe

- A Community to make the world a better place with KQL
- Learn, share and practice the KQL language 

## Agenda

- Where do we KQL?
- Your Playground Options
- KQL Basics | Top 8 Operators
- KQL Tables | How to find new things
- Working with IOCs
- Features worth mentioning
- Todays guest speaker: Rod Trent
- What did you do with KQL this month?
- KQL Challenge of the month

## Where do we KQL

Alex and Gianni provided an overview of the Microsoft Products where we can use KQL

- Microsoft 365 Defender
- Microsoft Sentinel
- Log Analytics 
- Data Explorer
- Microsoft Endpoint Configuration Manager (CMPivot)

## KQL Playground options

If you don't have access to Azure, don't worry, you can learn KQL for **free** using the publicely available [Log Analytics demo environment](https://aka.ms/lademo). 


## KQL Basics

To get you started, Gianni provided an overview on the Top 8 KQL operators

- [search](https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/searchoperator?pivots=azuredataexplorer)
- [project](https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/projectoperator)
- [has](https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/has-operator) <> [contains](https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/contains-operator)
- [distinct](https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/distinctoperator)
- [summarize](https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/summarizeoperator)
- [extend](https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/extendoperator)
- [take](https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/takeoperator) <> [limit](https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/limitoperator)
- [join](https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/joinoperator?pivots=azuredataexplorer)

The sample queries used by Gianni can be found [here](<ADD-LINK>)

## KQL how to find new things

Alex provided some examples how to find new tables or attributes stored within Microsoft Sentinel or Microsoft Defender 365. No rocked sciense here, just look around, take a table of interest and first look at the attributes, then find out what data is in these tables. As an example take the the [DeviceEvents](https://docs.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceevents-table?view=o365-worldwide) table from Microsoft Defender for Endpoint and run the following KQL query to find all **ActionTypes**

```kusto
DeviceEvents
| Distinct ActionType
```

## Working with IOCs

Gianni demonstrated a KQL query where he uses the [externaldata](https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/externaldata-operator?pivots=azuredataexplorer) operator to fetch ASN information from a file stored on GitHub and then uses that data to find possible matches within the AzureAD sign-in logs. 

You can find the script [here](<....gianni kql script....>)


## Features worth mentioning

The Query Explorer in Log Analytics has been replaced by [Azure QueryPacks](https://techcommunity.microsoft.com/t5/azure-monitor-blog/log-analytics-query-packs/ba-p/2314721), Alex basically explained what's described in the above referenced Tech Community Article. 


## Todays guest speaker: [Rod Trent](https://twitter.com/rodtrent)

We were very pleased to have Rod Trent as our very first guest speaker. Rod Trent is a Senior Cloud Security Advocate @ Microsoft and he's as crazy about KQL as we are. 

Rod Trent talked with us about the importance of KQL and the impact it can make on your IT career. It's like with PowerShell, these day, when using any of the above mentioned technologies, you must learn KQL. In fact that's why Rod started the [Must Learn KQL series](https://github.com/rod-trent/MustLearnKQL)

And we're happy that Rod has made available the KQL Cafe Edition of the [Must Learn KQL Coffee Mug](https://must-learn-kql.creator-spring.com/listing/kql-cafe-edition?product=1565) that we will send to our upcomming guest speakers at the KQL Cafe show.

[Presentation](https://github.com/KQLCafe/website/blob/gh-pages/Presentations/Rod%20Trend%20KQL%20is%20Life%202%20Podcast%2025012022.pdf)


Rod Trent blog: https://aka.ms/RodsBlog 
Must Learn KQL series: https://aka.ms/MustLearnKQL 
GitHub: https://github.com/rod-trent 
LinkedIn Profile: https://www.linkedin.com/in/rodtrent/ 
Twitter: https://twitter.com/rodtrent 


## What did you do with KQL this month?

In this part of the episode we inite the community to talk about what did with KQL recently. To get things started, Alex demonstrated his query to pull Windows OS End of Service information from the Threat and Vulnerability tables in Microsoft Defender for Endpoint. 
You can find the query here: [MDE - EOS Windows versions](https://github.com/alexverboon/MDATP/blob/master/AdvancedHunting/MDE%20-%20EOS%20Windows%20versions.md)

Rod shared these links:

- Common Security Log Costs by Vendor: https://cda.ms/3HF
- Data Per Computer: https://cda.ms/3HG
- Data Per Syslog Server: https://cda.ms/3HH


## KQL Challenge of the month


## References:

- SQL to KQL cheat sheet: https://aka.ms/SQL2KQL 
- Must Learn KQL:  https://aka.ms/MustLearnKQL
- KQL Playground: https://aka.ms/LADemo 
- The “merch” store:  https://cda.ms/3Dy 
- The tie fighter KQL query:  https://cda.ms/3HD
 



