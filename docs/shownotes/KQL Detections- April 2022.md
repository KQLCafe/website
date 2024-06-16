
# KQL Detections - Time

Date: 22. April 2022

***Hosts***

- [Gianni](https://twitter.com/castello_johnny)
- [Alex](https://twitter.com/alexverboon)

***Guest***

- [Olaf Hartong](https://twitter.com/olafhartong)

***Show Content***

- [Show Presentation](https://github.com/KQLCafe/website/blob/gh-pages/Presentations/KQL%20Cafe%20April%202022.pdf)
- [![Recording](https://img.youtube.com/vi/ianz3iCsRJI/0.jpg)](https://www.youtube.com/watch?v=ianz3iCsRJI)


Topics:

- 0:00 Welcome to KQL Cafe + Poll
- What's new in KQL:
- 3:16 Microsoft 365 Defender Connector
- 8:31 Extend Columns Microsoft Sentinel
- Working with IOCs:
- 10:18 BlackCat Ransomware IoC
- Learning KQL:
- 16:18 mv-expand
- KQL Tools:
- 25:06 Get PowerShell cmdlets from a PowerShell module
- Our KQL Guest:
- 26:58 Olaf Hartong KQL detection times
- What did you do with KQL this month?
- 1:15:05 Defender Threat and Vulnerability Management
- 1:18:06 Microsoft Sentinel Connector Health

## Agenda

- Hello again
- What's new in KQL
- IOCs
- Learn KQL
- KQL Tools
- Todays guest speaker: Olaf Hartong
- What did you do with KQL this month?
- KQL Challenge of the month

## What's new in KQL

### Microsoft 365 Defender Connector in Microsoft Sentinel

Additional tables can now be ingested the from Microsoft 365 Defender Connector into Microsoft Sentinel.

- Microsoft Defender for Identity
  - IdentityLogonEvents
  - IdentityQueryEvents
  - IdentityDirectoryEvents
- MIcrosoft Defender for Cloud Apps
  - CloudAppEvents
- Microsoft 365 Defender
  - AlertEvidence

## IOCs

- [FBI Releases IOCs Associated with BlackCat/ALPHV Ransomware](https://www.cisa.gov/uscert/ncas/current-activity/2022/04/22/fbi-releases-iocs-associated-blackcatalphv-ransomware)

## Learn KQL

```kql
//Expand JSON
SecurityAlert
| where TimeGenerated > ago(30d)
| where ProviderName == "MDATP"
| extend ParsedEnties = parse_json(Entities)
| mv-expand ParsedEnties
| where ParsedEnties contains "MdatpDeviceId"
| extend DeviceID = tostring(ParsedEnties.MdatpDeviceId)
```

```kql
SecurityAlert
| where TimeGenerated > ago(30d)
| where ProviderName == "MDATP"
| extend ParsedEnties = parse_json(Entities)
| mv-expand todynamic(ParsedEnties)
| extend DeviceID = ParsedEnties.MdatpDeviceId
```

```kql
//Expand Series
let lookBack_long = 30d;
let TimeFrame = 3h;
SigninLogs
| where TimeGenerated > ago(lookBack_long)
| make-series SignIn = count() on TimeGenerated in range(startofday(ago(lookBack_long)),now(), TimeFrame) by UserPrincipalName
| extend (AnomaliesDetected, AnomaliesScore, AnomaliesBaseline) = series_decompose_anomalies(SignIn, 3, -1, 'linefit')
| mv-expand TimeGenerated, AnomaliesScore, SignIn, AnomaliesDetected, AnomaliesScore, AnomaliesBaseline
| where SignIn > 5
```

```kql
//Expand List
SigninLogs
| where TimeGenerated > ago(7d)
| summarize make_list(UserPrincipalName)
| mv-expand list_UserPrincipalName
```

## KQL Tools

### Generate a KQL query that includes PowerShell cmdlets from a specific Module

```PowerShell
function New-KQPSModuleFunctions
{
<#
.Synopsis
   New-KQPSModulecmdlets
.DESCRIPTION
   New-KQPSModulecmdlets creates kusto query to search for PowerShell commands
   included in the specified PowerShell module name
.PARAMETER ModuleName
    The name of the PowerShell module

.PARAMETER ImportPsd
    The path to the PowerShell module psd file

.PARAMETER Path
    The path where the generated kql query is saved

.EXAMPLE
    New-KQPSModuleFunctions -ImportPsd C:\temp\powersploit.psd1 

    This command creates a kql query including all functions included in the Powersploit 
    module and saves the query to the clipboard

.EXAMPLE
    New-KQPSModuleFunctions -ImportPsd C:\temp\powersploit.psd1 -Path C:\Temp

    This command creates a kql query including all functions included in the powersploit 
    module and saves the query to c:\temp\ps_powersploit.kql

.EXAMPLE
    New-KQPSModuleFunctions -ModuleName netsecurity

    This command creates a kql query including all functions included in the netsecurity 
    module and saves the query to the clipboard

.EXAMPLE
    New-KQPSModuleFunctions -ModuleName netsecurity -Path c:\temp

    This command creates a kql query including all functions included in the netsecurity 
    module and saves the query to c:\temp\ps_netsecurity.kql

.NOTES
    Author: Alex Verboon
    Date: 11.07.2020
    Version 1.0
#>
    [CmdletBinding()]
    Param
    (
        # PowerShell Module
        [Parameter(ParameterSetName='Module',Mandatory=$true)]
        $ModuleName,
        # The path to the PowerShell module psd1 file
        [Parameter(ParameterSetName='Import',mandatory=$true)]
        $ImportPsd,
         # The path where the kql query is saved
        [Parameter(mandatory=$false)]
        $Path
    )

    Begin{}
    Process
    {
    If ($ImportPsd){
        $psdcontent = Import-PowerShellDataFile -Path $ImportPsd
        $PsCmds = ($psdcontent.FunctionsToExport) -join '","' 
        $ModuleVersion = $psdcontent.ModuleVersion
        $ModuleName = (Split-Path $ImportPsd -Leaf).Split(".")[0]
    }
    Else{
        if (-not (Get-Module -ListAvailable -Name $ModuleName)){
        Write-Error "Specified Module $ModuleName not found"
        break} 
        $PsCmds = (get-command -Module "$ModuleName").Name -join '","' 
        $ModuleInfo = Get-Module -Name "$ModuleName"
        $ModuleVersion = $ModuleInfo.Version
    }
    $let = 'let pscommands = dynamic ([' + '"' + $PsCmds + '"' + ']);'
$kqlquery = @"
// Search for PowerShell commands included in the PowerShell module: $ModuleName Version:$ModuleVersion)
$let
DeviceEvents
| where ActionType contains "PowerShellCommand"
| where AdditionalFields has_any (pscommands)
"@
    }
    End{
        If($Path){
        If (Test-Path $Path){
            Write-Output "Saving KQL query to $path\kql_$ModuleName.kql"
            Set-Content -Path "$path\ps_$ModuleName.kql" -Value $kqlquery -Force
            }
        }
        Else{
            Write-Output "KQL query saved to clipboard"
            $kqlquery | clip
        }
   }
}
```

## Guest Speaker Olaf Hartong

This month our guest speaker was [Olaf Hartong](https://twitter.com/olafhartong).

A blog post will be published soon.

## What did you do with KQL this month?

### Defender for Endpoint - Software Vulnerabilities

```kql
// Software Vulnerability Overview
DeviceTvmSoftwareVulnerabilities
| summarize make_list(VulnerabilitySeverityLevel), make_set(DeviceId), make_set(CveId), make_set(SoftwareVersion) 
    , Critical = make_set_if(CveId, VulnerabilitySeverityLevel == 'Critical'),
    High = make_set_if(CveId, VulnerabilitySeverityLevel == 'High'),
    Medium = make_set_if(CveId, VulnerabilitySeverityLevel == 'Medium'),
    Low = make_set_if(CveId, VulnerabilitySeverityLevel == 'Low')
    by SoftwareName, SoftwareVendor
| extend ExposedDevices = array_length(set_DeviceId)
| extend TotalVulnerabilities = array_length(set_CveId)
| extend VersionDistribution = array_length(set_SoftwareVersion)
| extend Critical = array_length(Critical)
| extend High = array_length(High)
| extend Medium = array_length(Medium)
| extend Low = array_length(Low)
| project SoftwareVendor, SoftwareName, ExposedDevices, TotalVulnerabilities, Critical, High, Medium, Low

```

### Connector Health

```kql
let connectortable = datatable (Connector: string, LogTable: string) [
    "Azure Active Directory", "SigninLogs",
    "Azure Active Diretory", "AuditLogs",
    "Azure Active Directory", "AADManagedIdentitySignInLogs",
    "Azure Active Directory", "AADServicePrincipalSignInLogs",
    "Azure Active Directory", "AADNonInteractiveUserSignInLogs",
    "Azure Active Directory", "AADProvisioningLogs",
    "Sentinel", "ThreatIntelligenceIndicator",
    "Office 365", "OfficeActivity",
    "Azure", "AzureActivity",
    "Microsoft Defender for Endpoint", "DeviceLogonEvents",
    "Microsoft Defender for Endpoint", "DeviceProcessEvents",
    "Microsoft Defender for Endpoint", "DeviceRegistryEvents",
    "Microsoft Defender for Endpoint", "DeviceInfo",
    "Microsoft Defender for Endpoint", "DeviceFileEvents",
    "Microsoft Defender for Endpoint", "DeviceNetworkEvents",
    "Microsoft Defender for Endpoint", "DeviceNetworkInfo",
    "Microsoft Defender for Endpoint", "DeviceImageLoadEvents",
    "Microsoft Defender for Endpoint", "DeviceEvents",
    "Microsoft Defender for Endpoint", "DeviceFileCertificateInfo",
    "Microsoft Defender for Cloud Apps", "CloudAppEvents",
    "Microsoft Defender for Cloud Apps", "McasShadowItReporting",
    "Microsoft Defender for Office 365", "EmailEvents",
    "Microsoft Defender for Office 365", "EmailAttachmentInfo",
    "Microsoft Defender for Office 365", "EmailUrlInfo",
    "Microsoft Defender for Office 365", "EmailPostDeliveryEvents",
    "Microsoft Defender for Identity", "IdentityLogonEvents",
    "Microsoft Defender for Identity", "IdentityQueryEvents",
    "Microsoft Defender for Identity", "IdentityDirectoryEvents",
    "Microsoft Defender for Identity","Azure Advanced Threat Protection",
    "Azure Firewall","AZUREFIREWALLS",
    "Azure Key Vault","VAULTS",
    "Azure Web Application Firewall (WAF)","APPLICATIONGATEWAYS"
];
union 
// Defender for Endpoint
DeviceEvents, DeviceFileEvents, DeviceProcessEvents, DeviceRegistryEvents, DeviceImageLoadEvents,DeviceNetworkEvents, DeviceNetworkInfo, DeviceLogonEvents, DeviceInfo, DeviceFileCertificateInfo,
// Azure AD
SigninLogs,AuditLogs, AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs, AADManagedIdentitySignInLogs,
// Azure
AzureActivity,
// Defender for Identity
IdentityDirectoryEvents, IdentityLogonEvents, IdentityQueryEvents,
// Microsoft Defender for Cloud Apps
CloudAppEvents, // McasShadowItReporting
// Defender for Office 365
EmailEvents, EmailAttachmentInfo, EmailUrlInfo, EmailPostDeliveryEvents, 
// Office 365
OfficeActivity,
// Sentinel
ThreatIntelligenceIndicator,
// Azure Firewall
AzureDiagnostics
| summarize
    Entries = count(),
    last_log_minute = datetime_diff("minute", now(), max(TimeGenerated)),
    last_log_hours = datetime_diff("hour", now(), max(TimeGenerated)),
    last_log_days = datetime_diff("day", now(), max(TimeGenerated)),
    last_logdate = max(TimeGenerated) by Type, ResourceType
    | project ['TableName'] = Type,
    ['Table Entries'] = Entries,
    ['Last Record Minutes'] =  last_log_minute,
    ['Last Record Hours'] =  last_log_hours,
    ['Last Record Days'] =  last_log_days,
    last_logdate, ResourceType 
| order by ['Last Record Minutes']  desc
| join kind=leftouter connectortable
    on $left.['TableName'] == $right.LogTable 
| join kind=leftouter connectortable
    on $left.ResourceType == $right. LogTable
| extend Connector = strcat(Connector, Connector1)
| where isnotempty( Connector)
| project last_logdate,Connector, ['TableName'], ['Table Entries'], ['Last Record Minutes'], ['Last Record Hours'], ['Last Record Days'] //, ResourceType
//| where ['Last Record Days'] > 0
| where ['Last Record Hours'] > 4
```
