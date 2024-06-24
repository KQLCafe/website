# KQL Cafe - June 2024

## Recording and Presentation

- [Recording]()
- [Presentation](../Presentations/)

## Hosts

- [Gianni](https://twitter.com/castello_johnny)
- [Alex](https://twitter.com/alexverboon)

## Guests

- [Michalis Michalos](https://www.linkedin.com/in/mmihalos/) 

## News

- [Microsoft Employee Submitted Queries](https://github.com/KQLMSPress/definitive-guide-kql/tree/main/Extra%20Microsoft%20Employee%20Submitted%20Queries)
- [Microsoft Defender for Endpoint Advanced Hunting and Application Control for Business – WDACConfig](https://www.youtube.com/watch?app=desktop&si=tJbFbzRJNy79lUo7&v=oyz0jFzOOGA&feature=youtu.be)
- [Detect suspicious processes running on hidden desktops](https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/detect-suspicious-processes-running-on-hidden-desktops/ba-p/4072322)

## Our Guest

## What did you do with KQL this month

```kql
AzureDiagnostics
| where Category == 'JobLogs'
| extend RunbookName = RunbookName_s
| project TimeGenerated,RunbookName,ResultType,CorrelationId,JobId_g
| summarize StartTime = minif(TimeGenerated,ResultType == 'Started'),EndTime = minif(TimeGenerated,ResultType in ('Completed','Failed','Failed')),
Status = tostring(parse_json(make_list_if(ResultType,ResultType in ('Completed','Failed','Stopped')))[0]) by JobId_g,RunbookName
| extend DurationSec = datetime_diff('second', EndTime,StartTime)
| join kind=leftouter (AzureDiagnostics
| where Category == "JobStreams"
| where StreamType_s == "Error"
| summarize TotalErrors = dcount(StreamType_s) by JobId_g, StreamType_s)
on $left. JobId_g == $right. JobId_g
| extend HasErrors = iff(StreamType_s == 'Error',true,false)
| project StartTime, EndTime, DurationSec,RunbookName,Status,HasErrors,TotalErrors,JobId_g
```

