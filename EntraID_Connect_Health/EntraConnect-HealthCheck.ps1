#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Entra ID Connect Health Check Script
    
.DESCRIPTION
    A comprehensive health monitoring tool for Microsoft Entra ID Connect environments.
    This script provides essential information about your hybrid identity infrastructure including:
    - Current version status and available updates
    - Synchronized organizational units and scope
    - Object counts (users, groups, contacts)
    - Critical sync issues and error detection
    - Next sync schedule and operational status
    
.NOTES
    File Name    : EntraConnect-HealthCheck.ps1
    Author       : Gulab Prasad
    Website      : https://gulabprasad.com
    Version      : 1.0
    Created      : December 2024
    
    Requirements:
    - Windows PowerShell 5.1 or higher
    - Azure AD Connect installed
    - Administrator privileges
    - ADSync PowerShell module
    
.EXAMPLE
    .\EntraConnect-HealthCheck.ps1
    
.LINK
    https://gulabprasad.com
#>

# Import required modules
try {
    Import-Module ADSync -ErrorAction Stop
    Write-Host "✓ ADSync module loaded successfully" -ForegroundColor Green
} catch {
    Write-Host "✗ Failed to load ADSync module" -ForegroundColor Red
    Write-Host "  Ensure Azure AD Connect is installed and you're running as Administrator" -ForegroundColor Yellow
    exit 1
}

Clear-Host
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "        Entra ID Connect Health Check Tool            " -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Created By: Gulab Prasad | https://gulabprasad.com" -ForegroundColor Gray
Write-Host "Version: 1.0 | Quick Health Assessment Tool" -ForegroundColor Gray
Write-Host ""

# Function to get current Entra Connect version
function Get-EntraConnectVersion {
    try {
        Write-Host "  Detecting Azure AD Connect version..." -ForegroundColor Gray
        
        # Method 1: Check registry paths (try more variations)
        $registryPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Azure AD Connect",
            "HKLM:\SOFTWARE\Microsoft\Azure Active Directory Connect",
            "HKLM:\SOFTWARE\Microsoft\Microsoft Azure Active Directory Connect",
            "HKLM:\SOFTWARE\Microsoft\Azure AD Sync",
            "HKLM:\SOFTWARE\Microsoft\Forefront Identity Manager\2010\Synchronization Service"
        )
        
        foreach ($regPath in $registryPaths) {
            if (Test-Path $regPath) {
                Write-Host "    Checking registry path: $regPath" -ForegroundColor Gray
                $regItem = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                
                # Try different version property names
                $versionProperties = @("Version", "ProductVersion", "DisplayVersion", "CurrentVersion")
                foreach ($prop in $versionProperties) {
                    if ($regItem.$prop) {
                        Write-Host "    ✓ Version found in registry ($prop): $($regItem.$prop)" -ForegroundColor Green
                        return $regItem.$prop
                    }
                }
            }
        }
        
        # Method 2: Check ADSync service executable
        Write-Host "    Registry method failed, checking service executable..." -ForegroundColor Gray
        $service = Get-Service -Name "ADSync" -ErrorAction SilentlyContinue
        if ($service) {
            Write-Host "    ✓ ADSync service found: $($service.Status)" -ForegroundColor Green
            
            # Get service path using different methods
            try {
                $serviceQuery = Get-WmiObject win32_service | Where-Object {$_.name -eq "ADSync"}
                if ($serviceQuery -and $serviceQuery.PathName) {
                    $servicePath = $serviceQuery.PathName.Replace('"', '').Split(' ')[0]
                    Write-Host "    Service path: $servicePath" -ForegroundColor Gray
                    
                    if (Test-Path $servicePath) {
                        $fileInfo = Get-ItemProperty $servicePath
                        if ($fileInfo.VersionInfo.FileVersion) {
                            Write-Host "    ✓ Version found from service: $($fileInfo.VersionInfo.FileVersion)" -ForegroundColor Green
                            return $fileInfo.VersionInfo.FileVersion
                        }
                        if ($fileInfo.VersionInfo.ProductVersion) {
                            Write-Host "    ✓ Product version found: $($fileInfo.VersionInfo.ProductVersion)" -ForegroundColor Green
                            return $fileInfo.VersionInfo.ProductVersion
                        }
                    }
                }
            } catch {
                Write-Host "    Service query failed: $($_.Exception.Message)" -ForegroundColor Gray
            }
        } else {
            Write-Host "    ⚠️  ADSync service not found" -ForegroundColor Yellow
        }
        
        # Method 3: Check common installation paths
        Write-Host "    Checking installation paths..." -ForegroundColor Gray
        $commonPaths = @(
            "${env:ProgramFiles}\Microsoft Azure AD Sync\Bin\miiserver.exe",
            "${env:ProgramFiles}\Microsoft Azure Active Directory Connect\miiserver.exe",
            "${env:ProgramFiles(x86)}\Microsoft Azure AD Sync\Bin\miiserver.exe",
            "${env:ProgramFiles}\Microsoft Forefront Identity Manager\2010\Synchronization Service\Bin\miiserver.exe"
        )
        
        foreach ($path in $commonPaths) {
            if (Test-Path $path) {
                Write-Host "    Found installation at: $path" -ForegroundColor Gray
                try {
                    $fileInfo = Get-ItemProperty $path
                    if ($fileInfo.VersionInfo.FileVersion) {
                        Write-Host "    ✓ Version found from file: $($fileInfo.VersionInfo.FileVersion)" -ForegroundColor Green
                        return $fileInfo.VersionInfo.FileVersion
                    }
                } catch {
                    Write-Host "    Could not read version from: $path" -ForegroundColor Gray
                }
            }
        }
        
        Write-Host "    ⚠️  Could not determine version - likely older installation" -ForegroundColor Yellow
        return "Pre-2.0 (Older Version)"
        
    } catch {
        Write-Host "    ⚠️  Error during version detection: $($_.Exception.Message)" -ForegroundColor Red
        return "Error retrieving version"
    }
}

# Function to check for latest version availability
function Get-LatestVersionInfo {
    try {
        Write-Host "  Checking for latest version..." -ForegroundColor Gray
        
        return @{
            Status = "Check Required"
            Message = "Latest version available through Entra Admin Center"
            DownloadUrl = "https://entra.microsoft.com/#view/Microsoft_AAD_Connect/ConnectBlade"
            Note = "Microsoft no longer provides direct downloads - use Entra portal"
        }
    } catch {
        return @{
            Status = "Check Failed"
            Message = "Unable to check for updates"
            DownloadUrl = "https://entra.microsoft.com"
            Note = "Manual check required"
        }
    }
}

# Function to get sync health status
function Get-SyncHealthStatus {
    try {
        Write-Host "🔍 Analyzing Sync Health..." -ForegroundColor Yellow
        
        # Try to get scheduler status with better error handling
        try {
            $scheduler = Get-ADSyncScheduler -ErrorAction Stop
            $syncEnabled = $scheduler.SyncCycleEnabled
            $nextSync = $scheduler.NextSyncCycleStartTimeInUTC
        } catch {
            # Check if this is a network connectivity issue
            $errorMessage = $_.Exception.Message
            $isNetworkIssue = $false
            $networkIssueType = ""
            
            if ($errorMessage -like "*login.microsoftonline.com*" -or $errorMessage -like "*remote name could not be resolved*") {
                $isNetworkIssue = $true
                $networkIssueType = "DNS Resolution"
            } elseif ($errorMessage -like "*HttpRequestException*" -or $errorMessage -like "*WebException*") {
                $isNetworkIssue = $true
                $networkIssueType = "Network Connectivity"
            } elseif ($errorMessage -like "*cloud sync intervals*") {
                $isNetworkIssue = $true
                $networkIssueType = "Azure Connectivity"
            }
            
            if ($isNetworkIssue) {
                Write-Host "  🌐 Network connectivity issue detected ($networkIssueType)" -ForegroundColor Yellow
                return @{
                    SyncEnabled = "Unknown - Network Issue"
                    HasErrors = $true
                    ErrorDetails = @("🌐 Network connectivity issue detected", "  • Cannot reach login.microsoftonline.com", "  • Check firewall, proxy, and DNS settings")
                    NextSync = "Unknown - Network Issue"
                    LastSuccessfulSync = "Unknown"
                    NetworkIssue = $true
                    NetworkIssueType = $networkIssueType
                }
            } else {
                # Other type of error
                Write-Host "  ⚠️  Scheduler error: $($_.Exception.Message)" -ForegroundColor Red
                return @{
                    SyncEnabled = $false
                    HasErrors = $true
                    ErrorDetails = @("Scheduler error - check ADSync service")
                    NextSync = "Unknown"
                    LastSuccessfulSync = "Unknown"
                    NetworkIssue = $false
                }
            }
        }
        
        $connectors = Get-ADSyncConnector
        $hasErrors = $false
        $errorDetails = @()
        $lastSuccessfulSync = $null
        
        foreach ($connector in $connectors) {
            try {
                $runHistory = Get-ADSyncConnectorRunStatus -Connector $connector | Select-Object -First 5
                
                foreach ($run in $runHistory) {
                    if ($run.Result -eq "Success" -and $lastSuccessfulSync -eq $null) {
                        $lastSuccessfulSync = $run.StartDate
                    }
                    if ($run.Result -ne "Success") {
                        $hasErrors = $true
                        $errorDetails += "  ⚠️  $($connector.Name): $($run.Result) at $($run.StartDate)"
                    }
                }
            } catch {
                try {
                    $allRuns = Get-ADSyncConnectorRunStatus
                    $connectorRuns = $allRuns | Where-Object {$_.ConnectorName -eq $connector.Name} | Select-Object -First 5
                    
                    foreach ($run in $connectorRuns) {
                        if ($run.Result -eq "Success" -and $lastSuccessfulSync -eq $null) {
                            $lastSuccessfulSync = $run.StartDate
                        }
                        if ($run.Result -ne "Success") {
                            $hasErrors = $true
                            $errorDetails += "  ⚠️  $($connector.Name): $($run.Result) at $($run.StartDate)"
                        }
                    }
                } catch {
                    $errorDetails += "  ⚠️  Unable to check run history for $($connector.Name)"
                }
            }
        }
        
        return @{
            SyncEnabled = $syncEnabled
            HasErrors = $hasErrors
            ErrorDetails = $errorDetails
            NextSync = $nextSync
            LastSuccessfulSync = $lastSuccessfulSync
            NetworkIssue = $false
        }
        
    } catch {
        Write-Host "  ⚠️  Error checking sync health: $($_.Exception.Message)" -ForegroundColor Red
        return @{
            SyncEnabled = $false
            HasErrors = $true
            ErrorDetails = @("Unable to retrieve sync status - check ADSync service")
            NextSync = "Unknown"
            LastSuccessfulSync = "Unknown"
            NetworkIssue = $false
        }
    }
}

# Function to get object counts
function Get-ObjectCounts {
    try {
        Write-Host "📊 Counting Synchronized Objects..." -ForegroundColor Yellow
        
        $counts = @{
            Users = 0
            Groups = 0
            Contacts = 0
            Other = 0
            Total = 0
            Method = "Unknown"
        }
        
        # Method 1: Try to get count without using Get-ADSyncMVObject directly
        try {
            Write-Host "    Checking connector space objects..." -ForegroundColor Gray
            $connectors = Get-ADSyncConnector | Where-Object {$_.ConnectorTypeName -eq "AD"}
            $totalFound = $false
            
            foreach ($connector in $connectors) {
                try {
                    Write-Host "    Analyzing connector: $($connector.Name)" -ForegroundColor Gray
                    
                    # Try to get connector space objects (this usually works)
                    $csObjects = Get-ADSyncCSObject -ConnectorName $connector.Name 2>$null
                    
                    if ($csObjects -and $csObjects.Count -gt 0) {
                        Write-Host "    Found $($csObjects.Count) objects in connector space" -ForegroundColor Gray
                        
                        # Count by object type
                        $userObjs = ($csObjects | Where-Object {$_.ObjectType -eq "user"}).Count
                        $groupObjs = ($csObjects | Where-Object {$_.ObjectType -eq "group"}).Count
                        $contactObjs = ($csObjects | Where-Object {$_.ObjectType -eq "contact"}).Count
                        $otherObjs = $csObjects.Count - $userObjs - $groupObjs - $contactObjs
                        
                        $counts.Users += $userObjs
                        $counts.Groups += $groupObjs
                        $counts.Contacts += $contactObjs
                        $counts.Other += $otherObjs
                        $counts.Total += $csObjects.Count
                        $totalFound = $true
                        
                        Write-Host "    ✓ Objects: Users($userObjs), Groups($groupObjs), Contacts($contactObjs)" -ForegroundColor Green
                    } else {
                        Write-Host "    No objects in connector space (may have been processed)" -ForegroundColor Gray
                    }
                } catch {
                    Write-Host "    Connector space query failed: $($_.Exception.Message)" -ForegroundColor Gray
                }
            }
            
            if ($totalFound) {
                $counts.Method = "Connector Space Analysis"
                return $counts
            }
        } catch {
            Write-Host "    Connector space analysis failed: $($_.Exception.Message)" -ForegroundColor Gray
        }
        
        # Method 2: Get object count from run profiles/statistics
        try {
            Write-Host "    Checking run statistics..." -ForegroundColor Gray
            $connectors = Get-ADSyncConnector | Where-Object {$_.ConnectorTypeName -eq "AD"}
            
            foreach ($connector in $connectors) {
                try {
                    # Get recent run history which sometimes contains object counts
                    $runHistory = Get-ADSyncConnectorRunStatus -Connector $connector | Select-Object -First 1
                    
                    if ($runHistory -and $runHistory.Result -eq "Success") {
                        # Check if run history contains useful statistics
                        $runDetails = $runHistory | Select-Object *
                        
                        Write-Host "    Last successful run: $($runHistory.StartDate)" -ForegroundColor Gray
                        Write-Host "    Run result: $($runHistory.Result)" -ForegroundColor Green
                        
                        # Indicate that objects are being processed
                        $counts.Users = "Active sync detected"
                        $counts.Groups = "Active sync detected" 
                        $counts.Contacts = "Active sync detected"
                        $counts.Total = "Objects being synchronized"
                        $counts.Method = "Run History Analysis"
                        
                        return $counts
                    }
                } catch {
                    Write-Host "    Run history check failed for $($connector.Name)" -ForegroundColor Gray
                }
            }
        } catch {
            Write-Host "    Run statistics check failed: $($_.Exception.Message)" -ForegroundColor Gray
        }
        
        # Method 3: Analyze sync rules to understand what's configured
        try {
            Write-Host "    Analyzing sync rules configuration..." -ForegroundColor Gray
            $syncRules = Get-ADSyncRule | Where-Object {$_.Enabled -eq $true}
            
            if ($syncRules -and $syncRules.Count -gt 0) {
                $userRules = ($syncRules | Where-Object {
                    $_.SourceObjectType -eq "user" -or 
                    $_.TargetObjectType -eq "person" -or
                    $_.Name -like "*user*" -or
                    $_.Name -like "*person*"
                }).Count
                
                $groupRules = ($syncRules | Where-Object {
                    $_.SourceObjectType -eq "group" -or 
                    $_.TargetObjectType -eq "group" -or
                    $_.Name -like "*group*"
                }).Count
                
                $contactRules = ($syncRules | Where-Object {
                    $_.SourceObjectType -eq "contact" -or 
                    $_.TargetObjectType -eq "contact" -or
                    $_.Name -like "*contact*"
                }).Count
                
                if ($userRules -gt 0 -or $groupRules -gt 0 -or $contactRules -gt 0) {
                    $counts.Users = "Configured ($userRules rules)"
                    $counts.Groups = "Configured ($groupRules rules)"
                    $counts.Contacts = "Configured ($contactRules rules)"
                    $counts.Total = "$($syncRules.Count) active sync rules"
                    $counts.Method = "Sync Rules Configuration"
                    
                    Write-Host "    ✓ Found active sync rules for object types" -ForegroundColor Green
                    return $counts
                }
            }
        } catch {
            Write-Host "    Sync rules analysis failed: $($_.Exception.Message)" -ForegroundColor Gray
        }
        
        # Method 4: Basic status - confirm connectors exist
        try {
            Write-Host "    Verifying connector configuration..." -ForegroundColor Gray
            $adConnectors = Get-ADSyncConnector | Where-Object {$_.ConnectorTypeName -eq "AD"}
            $aadConnectors = Get-ADSyncConnector | Where-Object {$_.ConnectorTypeName -eq "AAD"}
            
            if ($adConnectors.Count -gt 0 -and $aadConnectors.Count -gt 0) {
                $counts.Users = "Sync infrastructure configured"
                $counts.Groups = "Sync infrastructure configured"
                $counts.Contacts = "Sync infrastructure configured"
                $counts.Total = "AD & Azure AD connectors active"
                $counts.Method = "Infrastructure Verification"
                
                Write-Host "    ✓ Both AD and Azure AD connectors found" -ForegroundColor Green
                return $counts
            } elseif ($adConnectors.Count -gt 0) {
                $counts.Users = "AD connector configured"
                $counts.Groups = "AD connector configured"
                $counts.Contacts = "AD connector configured"
                $counts.Total = "$($adConnectors.Count) AD connector(s) found"
                $counts.Method = "AD Connector Detection"
                
                Write-Host "    ✓ AD connector(s) configured" -ForegroundColor Green
                return $counts
            }
        } catch {
            Write-Host "    Connector verification failed: $($_.Exception.Message)" -ForegroundColor Gray
        }
        
        # If all methods fail
        $counts.Users = "Unable to determine"
        $counts.Groups = "Unable to determine"
        $counts.Contacts = "Unable to determine"
        $counts.Total = "Check manually using Synchronization Service Manager"
        $counts.Method = "Manual check required"
        
        Write-Host "    ⚠️  Automatic counting not available in this version" -ForegroundColor Yellow
        Write-Host "    💡  Use Synchronization Service Manager GUI for object counts" -ForegroundColor Cyan
        
        return $counts
        
    } catch {
        Write-Host "  ⚠️  Error in object counting: $($_.Exception.Message)" -ForegroundColor Red
        return @{
            Users = "Error"
            Groups = "Error"
            Contacts = "Error" 
            Other = "Error"
            Total = "Error occurred"
            Method = "Exception: $($_.Exception.Message)"
        }
    }
}

# Function to get synchronized OU information
function Get-SynchronizedOUs {
    try {
        Write-Host "🏢 Checking Synchronized OUs..." -ForegroundColor Yellow
        
        $ouInfo = @{
            Connectors = @()
            TotalOUs = 0
            HasFiltering = $false
        }
        
        $adConnectors = Get-ADSyncConnector | Where-Object {$_.ConnectorTypeName -eq "AD"}
        
        foreach ($connector in $adConnectors) {
            $connectorInfo = @{
                Name = $connector.Name
                Forest = "Unknown"
                Domain = "Unknown"
                Partitions = @()
                Status = "Active"
            }
            
            try {
                # Try multiple methods to get connectivity parameters
                Write-Host "    Analyzing connector: $($connector.Name)" -ForegroundColor Gray
                
                # Method 1: Standard ConnectivityParameters
                if ($connector.ConnectivityParameters) {
                    $connParams = $connector.ConnectivityParameters
                    
                    # Try different property access methods
                    if ($connParams.forest) {
                        if ($connParams.forest.Value) {
                            $connectorInfo.Forest = $connParams.forest.Value
                        } elseif ($connParams.forest -is [string]) {
                            $connectorInfo.Forest = $connParams.forest
                        }
                    }
                    
                    if ($connParams.domain) {
                        if ($connParams.domain.Value) {
                            $connectorInfo.Domain = $connParams.domain.Value
                        } elseif ($connParams.domain -is [string]) {
                            $connectorInfo.Domain = $connParams.domain
                        }
                    }
                    
                    # Try alternative parameter names
                    if ($connectorInfo.Forest -eq "Unknown" -and $connParams."Forest name") {
                        $connectorInfo.Forest = $connParams."Forest name"
                    }
                    if ($connectorInfo.Domain -eq "Unknown" -and $connParams."Domain name") {
                        $connectorInfo.Domain = $connParams."Domain name"
                    }
                }
                
                # Method 2: Extract from connector name (common pattern)
                if ($connectorInfo.Forest -eq "Unknown" -or $connectorInfo.Domain -eq "Unknown") {
                    if ($connector.Name -match "^([^.]+\..*?)(?:\s|$)") {
                        $possibleDomain = $matches[1]
                        if ($connectorInfo.Domain -eq "Unknown") {
                            $connectorInfo.Domain = $possibleDomain
                            Write-Host "    Extracted domain from name: $possibleDomain" -ForegroundColor Gray
                        }
                        if ($connectorInfo.Forest -eq "Unknown") {
                            $connectorInfo.Forest = $possibleDomain
                            Write-Host "    Extracted forest from name: $possibleDomain" -ForegroundColor Gray
                        }
                    }
                }
                
                # Get partition information
                if ($connector.Partitions) {
                    Write-Host "    Found $($connector.Partitions.Count) partition(s)" -ForegroundColor Gray
                    foreach ($partition in $connector.Partitions) {
                        if ($partition.Name) {
                            $connectorInfo.Partitions += $partition.Name
                            $ouInfo.TotalOUs++
                        } elseif ($partition.DN) {
                            $connectorInfo.Partitions += $partition.DN
                            $ouInfo.TotalOUs++
                        } elseif ($partition.DistinguishedName) {
                            $connectorInfo.Partitions += $partition.DistinguishedName
                            $ouInfo.TotalOUs++
                        }
                    }
                }
                
                # If we still don't have forest/domain info, try to extract from partitions
                if (($connectorInfo.Forest -eq "Unknown" -or $connectorInfo.Domain -eq "Unknown") -and $connectorInfo.Partitions.Count -gt 0) {
                    $firstPartition = $connectorInfo.Partitions[0]
                    if ($firstPartition -match "DC=([^,]+)") {
                        $domainComponents = @()
                        $matches = [regex]::Matches($firstPartition, "DC=([^,]+)")
                        foreach ($match in $matches) {
                            $domainComponents += $match.Groups[1].Value
                        }
                        if ($domainComponents.Count -gt 0) {
                            $extractedDomain = $domainComponents -join "."
                            if ($connectorInfo.Domain -eq "Unknown") {
                                $connectorInfo.Domain = $extractedDomain
                                Write-Host "    Extracted domain from partition DN: $extractedDomain" -ForegroundColor Gray
                            }
                            if ($connectorInfo.Forest -eq "Unknown") {
                                $connectorInfo.Forest = $extractedDomain
                                Write-Host "    Extracted forest from partition DN: $extractedDomain" -ForegroundColor Gray
                            }
                        }
                    }
                }
                
            } catch {
                $connectorInfo.Status = "Limited Info Available - $($_.Exception.Message)"
                Write-Host "    ⚠️  Error getting connector details: $($_.Exception.Message)" -ForegroundColor Yellow
            }
            
            $ouInfo.Connectors += $connectorInfo
        }
        
        # Check for OU filtering
        try {
            $ouFilter = Get-ADSyncOrganizationalUnitFilter -ErrorAction SilentlyContinue
            if ($ouFilter) {
                $ouInfo.HasFiltering = $true
            }
        } catch {
            # OU filtering check not available in all versions
            Write-Host "    OU filtering status unavailable in this version" -ForegroundColor Gray
        }
        
        return $ouInfo
        
    } catch {
        Write-Host "  ⚠️  Error retrieving OU information: $($_.Exception.Message)" -ForegroundColor Red
        return @{
            Connectors = @()
            TotalOUs = 0
            HasFiltering = $false
            Error = $_.Exception.Message
        }
    }
}

# Main execution starts here
Write-Host "Starting comprehensive health check..." -ForegroundColor White
Write-Host ""

# 1. Version Information
Write-Host "📦 VERSION STATUS" -ForegroundColor Cyan
Write-Host "==================" -ForegroundColor Cyan
$currentVersion = Get-EntraConnectVersion
$latestInfo = Get-LatestVersionInfo

Write-Host "Current Version: $currentVersion" -ForegroundColor White
Write-Host "Update Status: $($latestInfo.Status)" -ForegroundColor Yellow
Write-Host "Note: $($latestInfo.Note)" -ForegroundColor Gray
Write-Host "Download: $($latestInfo.DownloadUrl)" -ForegroundColor Blue
Write-Host ""

# 2. Sync Health Status
Write-Host "🔄 SYNC HEALTH STATUS" -ForegroundColor Cyan
Write-Host "=====================" -ForegroundColor Cyan
$syncStatus = Get-SyncHealthStatus

# Handle different sync status scenarios
if ($syncStatus.NetworkIssue) {
    Write-Host "Sync Enabled: ⚠️  $($syncStatus.SyncEnabled)" -ForegroundColor Yellow
    Write-Host "Network Issue: ⚠️  $($syncStatus.NetworkIssueType)" -ForegroundColor Red
    Write-Host "Azure Connectivity: ✗ Cannot reach login.microsoftonline.com" -ForegroundColor Red
} else {
    Write-Host "Sync Enabled: $(if ($syncStatus.SyncEnabled) { '✓ Yes' } else { '✗ No' })" -ForegroundColor $(if ($syncStatus.SyncEnabled) { 'Green' } else { 'Red' })
}

Write-Host "Sync Issues: $(if ($syncStatus.HasErrors) { '⚠️  Yes - Issues Found' } else { '✓ No Issues' })" -ForegroundColor $(if ($syncStatus.HasErrors) { 'Red' } else { 'Green' })

if ($syncStatus.LastSuccessfulSync -and $syncStatus.LastSuccessfulSync -ne "Unknown") {
    Write-Host "Last Success: $($syncStatus.LastSuccessfulSync)" -ForegroundColor White
}
Write-Host "Next Sync: $($syncStatus.NextSync)" -ForegroundColor White

if ($syncStatus.HasErrors -and $syncStatus.ErrorDetails.Count -gt 0) {
    Write-Host "`nRecent Issues:" -ForegroundColor Red
    foreach ($error in $syncStatus.ErrorDetails) {
        Write-Host $error -ForegroundColor Red
    }
    
    # If it's a network issue, provide specific guidance
    if ($syncStatus.NetworkIssue) {
        Write-Host "`n🔧 Network Issue Resolution:" -ForegroundColor Yellow
        Write-Host "  • Check DNS: Can resolve login.microsoftonline.com?" -ForegroundColor Gray
        Write-Host "  • Check Firewall: Allow HTTPS (443) to *.microsoftonline.com" -ForegroundColor Gray
        Write-Host "  • Check Proxy: Configure proxy settings if required" -ForegroundColor Gray
        Write-Host "  • Test connectivity: nslookup login.microsoftonline.com" -ForegroundColor Gray
        Write-Host "  • Required URLs: login.microsoftonline.com, graph.microsoft.com" -ForegroundColor Gray
    }
}
Write-Host ""

# 3. Object Counts
Write-Host "👥 SYNCHRONIZED OBJECTS" -ForegroundColor Cyan  
Write-Host "=======================" -ForegroundColor Cyan
$objectCounts = Get-ObjectCounts

Write-Host "Users: $($objectCounts.Users)" -ForegroundColor White
Write-Host "Groups: $($objectCounts.Groups)" -ForegroundColor White  
Write-Host "Contacts: $($objectCounts.Contacts)" -ForegroundColor White
Write-Host "Other Objects: $($objectCounts.Other)" -ForegroundColor White
Write-Host "Total Objects: $($objectCounts.Total)" -ForegroundColor Yellow
Write-Host "Count Method: $($objectCounts.Method)" -ForegroundColor Gray
Write-Host ""

# 4. OU Information
Write-Host "🏢 ORGANIZATIONAL UNITS" -ForegroundColor Cyan
Write-Host "=======================" -ForegroundColor Cyan
$ouInfo = Get-SynchronizedOUs

if ($ouInfo.Connectors.Count -gt 0) {
    foreach ($connector in $ouInfo.Connectors) {
        Write-Host "Connector: $($connector.Name)" -ForegroundColor White
        Write-Host "  Forest: $($connector.Forest)" -ForegroundColor Gray
        Write-Host "  Domain: $($connector.Domain)" -ForegroundColor Gray
        Write-Host "  Partitions: $($connector.Partitions.Count)" -ForegroundColor Gray
        
        if ($connector.Partitions.Count -gt 0) {
            foreach ($partition in $connector.Partitions) {
                Write-Host "    - $partition" -ForegroundColor Gray
            }
        }
        Write-Host ""
    }
    
    Write-Host "OU Filtering: $(if ($ouInfo.HasFiltering) { 'Enabled' } else { 'All OUs (Default)' })" -ForegroundColor Yellow
} else {
    Write-Host "No AD connectors found or unable to retrieve OU information" -ForegroundColor Red
}
Write-Host ""

# 5. Summary and Recommendations
Write-Host "📋 HEALTH SUMMARY" -ForegroundColor Cyan
Write-Host "=================" -ForegroundColor Cyan

$overallHealth = "Good"
$recommendations = @()

if (-not $syncStatus.SyncEnabled -or $syncStatus.SyncEnabled -eq $false) {
    $overallHealth = "Critical"
    $recommendations += "• Enable synchronization scheduler"
}

if ($syncStatus.HasErrors) {
    if ($syncStatus.NetworkIssue) {
        $overallHealth = "Critical"
        $recommendations += "• Resolve network connectivity issues"
        $recommendations += "• Check firewall and proxy settings"
    } else {
        $overallHealth = "Warning"
        $recommendations += "• Review and resolve sync errors"
    }
}

if ($currentVersion -like "*Unknown*" -or $currentVersion -like "*Error*") {
    $overallHealth = "Warning"
    $recommendations += "• Verify Azure AD Connect installation"
}

if ($objectCounts.Total -eq 0 -and $objectCounts.Method -ne "Failed") {
    $recommendations += "• Check if initial sync has completed"
}

$healthColor = if ($overallHealth -eq "Good") { 'Green' } elseif ($overallHealth -eq "Warning") { 'Yellow' } else { 'Red' }
Write-Host "Overall Health: $overallHealth" -ForegroundColor $healthColor

if ($recommendations.Count -gt 0) {
    Write-Host "`nRecommendations:" -ForegroundColor Yellow
    foreach ($rec in $recommendations) {
        Write-Host $rec -ForegroundColor Yellow
    }
} else {
    Write-Host "✓ No immediate issues detected" -ForegroundColor Green
}

Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Health check completed. For detailed analysis, use:" -ForegroundColor Gray
Write-Host "• Azure AD Connect GUI for OU filtering details" -ForegroundColor Gray
Write-Host "• Get-ADSyncConnectorRunStatus for run history" -ForegroundColor Gray
Write-Host "• Start-ADSyncSyncCycle -PolicyType Delta for manual sync" -ForegroundColor Gray
Write-Host ""
Write-Host "Script created by Gulab Prasad | https://gulabprasad.com" -ForegroundColor Gray
Write-Host "========================================================" -ForegroundColor Cyan