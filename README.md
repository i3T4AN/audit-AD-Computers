AD-Computer-Query
PowerShell script for querying Active Directory computer objects with stale detection and CSV export capabilities.
Description
Retrieves domain-joined computers from Active Directory using LDAP filters. Supports filtering by enabled status, last logon activity, and organizational unit. Outputs computer names to console and optionally exports detailed information to CSV.
Requirements

Windows PowerShell 5.1 or PowerShell 7
Active Directory module (RSAT-AD-PowerShell)
Domain-joined computer or domain credentials
Read access to Active Directory computer objects

Installation
Windows Server
powershellInstall-WindowsFeature -Name RSAT-AD-PowerShell
Windows 10/11
powershellAdd-WindowsFeature RSAT.ActiveDirectory.DS-LDS.Tools
Usage
Basic Usage
powershell# Query all enabled computers
.\Get-ADDomainComputers.ps1

# Include disabled computers
.\Get-ADDomainComputers.ps1 -IncludeDisabled

# Find computers inactive for 90 days
.\Get-ADDomainComputers.ps1 -StaleDays 90
Advanced Usage
powershell# Query specific OU
.\Get-ADDomainComputers.ps1 -SearchBase "OU=Workstations,DC=contoso,DC=com"

# Export to CSV
.\Get-ADDomainComputers.ps1 -OutputFile "C:\Reports\computers.csv"

# Query different domain
.\Get-ADDomainComputers.ps1 -Domain "child.contoso.com"

# Combined parameters
.\Get-ADDomainComputers.ps1 -SearchBase "OU=Servers,DC=contoso,DC=com" -StaleDays 60 -OutputFile "servers.csv"
Parameters
ParameterTypeDefaultDescriptionDomainStringCurrent domainTarget domain DNS nameSearchBaseStringDomain rootDistinguished name of OU to searchIncludeDisabledSwitchFalseInclude disabled computer accountsStaleDaysInteger180Days of inactivity before considering staleOutputFileStringNonePath for CSV export
CSV Output Format
When exported to CSV, the following columns are included:

Name
DNSHostName
Enabled
OperatingSystem
LastLogonDate
PasswordLastSet
CanonicalName
