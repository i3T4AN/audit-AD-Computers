[CmdletBinding()]
param(
    [Parameter()]
    [string]$Domain = (Get-ADDomain -ErrorAction SilentlyContinue).DNSRoot,
    
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$SearchBase,
    
    [Parameter()]
    [switch]$IncludeDisabled,
    
    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$StaleDays = 180,
    
    [Parameter()]
    [ValidateScript({
        if ($_ -eq '') { return $true }
        $parent = Split-Path $_ -Parent
        if ($parent -and !(Test-Path $parent)) {
            throw "Directory '$parent' does not exist"
        }
        return $true
    })]
    [string]$OutputFile
)

# Check for ActiveDirectory module
try {
    if (!(Get-Module -Name ActiveDirectory -ListAvailable)) {
        throw @"
ActiveDirectory module is not available. Please install RSAT AD PowerShell module:
- Windows Server: Install-WindowsFeature -Name RSAT-AD-PowerShell
- Windows 10/11: Enable RSAT via Windows Features or Settings
"@
    }
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Error "Failed to load ActiveDirectory module: $_"
    exit 1
}

# Validate domain parameter
if (!$Domain) {
    Write-Error "Unable to determine domain. Please specify -Domain parameter."
    exit 1
}

# Build LDAP filter
$ldapFilter = "(&(objectCategory=computer)(dNSHostName=*))"

# Calculate stale date
$staleDate = (Get-Date).AddDays(-$StaleDays)

# Build Get-ADComputer parameters
$getADComputerParams = @{
    LDAPFilter = $ldapFilter
    Server     = $Domain
    Properties = @('DNSHostName', 'Enabled', 'OperatingSystem', 'LastLogonTimestamp', 'PasswordLastSet', 'CanonicalName')
}

if ($SearchBase) {
    $getADComputerParams['SearchBase'] = $SearchBase
}

# Query Active Directory
try {
    Write-Verbose "Querying domain: $Domain"
    if ($SearchBase) {
        Write-Verbose "SearchBase: $SearchBase"
    }
    
    $allComputers = Get-ADComputer @getADComputerParams | ForEach-Object {
        # Convert LastLogonTimestamp (already a FileTime Int64)
        $lastLogon = if ($_.LastLogonTimestamp -and $_.LastLogonTimestamp -ne 0) {
            [DateTime]::FromFileTimeUtc([int64]$_.LastLogonTimestamp)
        } else {
            $null
        }
        
        # PasswordLastSet is already DateTime, just pass through
        $passwordLastSet = if ($_.PasswordLastSet) {
            $_.PasswordLastSet
        } else {
            $null
        }
        
        [PSCustomObject]@{
            Name            = $_.Name
            DNSHostName     = $_.DNSHostName
            Enabled         = $_.Enabled
            OperatingSystem = $_.OperatingSystem
            LastLogonDate   = $lastLogon
            PasswordLastSet = $passwordLastSet
            CanonicalName   = $_.CanonicalName
        }
    }
}
catch {
    Write-Error "Failed to query Active Directory: $_"
    exit 1
}

# Filter based on enabled status and stale days
if (!$IncludeDisabled) {
    Write-Verbose "Filtering for enabled computers only"
    $computers = $allComputers | Where-Object { $_.Enabled -eq $true }
    
    Write-Verbose "Filtering out stale computers (inactive for $StaleDays+ days)"
    $computers = $computers | Where-Object {
        ($null -ne $_.LastLogonDate -and $_.LastLogonDate -ge $staleDate) -or
        ($null -eq $_.LastLogonDate -and $null -ne $_.PasswordLastSet -and $_.PasswordLastSet -ge $staleDate)
    }
} else {
    $computers = $allComputers
}

# Output computer names to console
Write-Verbose "Found $($computers.Count) computer(s) matching criteria"
$computers | ForEach-Object { Write-Output $_.Name }

# Export to CSV if OutputFile specified
if ($OutputFile) {
    try {
        $exportData = $computers | Select-Object @(
            'Name'
            'DNSHostName'
            'Enabled'
            'OperatingSystem'
            @{Name='LastLogonDate'; Expression={ if ($_.LastLogonDate) { $_.LastLogonDate.ToString('yyyy-MM-dd HH:mm:ss') } else { 'Never' } }}
            @{Name='PasswordLastSet'; Expression={ if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString('yyyy-MM-dd HH:mm:ss') } else { 'Never' } }}
            'CanonicalName'
        )
        
        $exportData | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
        Write-Verbose "Exported results to: $OutputFile"
    }
    catch {
        Write-Warning "Failed to export to CSV: $_"
    }
}
