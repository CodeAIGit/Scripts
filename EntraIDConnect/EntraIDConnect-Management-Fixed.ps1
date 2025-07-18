#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Entra ID Connect Management Script - Clean Version
.DESCRIPTION
    Shows current version, enabled sync rules only, and synchronized OUs
    A PowerShell automation tool designed to streamline the management, monitoring, and maintenance of Microsoft Entra ID Connect (formerly Azure AD Connect) environments. 
    This script transforms routine administrative tasks into secure, efficient workflows while providing enterprise-grade visibility and control over hybrid identity infrastructure.
.NOTES
    Requires Administrator privileges and Azure AD Connect
    Version: 1.2 - All Syntax Issues Fixed
    Created By: Gulab Prasad
    Version: 1.2
    License: MIT
#>

# Import required modules
try {
    Import-Module ADSync -ErrorAction Stop
    Write-Host "ADSync module loaded successfully" -ForegroundColor Green
} catch {
    Write-Host "Failed to load ADSync module. Ensure Azure AD Connect is installed." -ForegroundColor Red
    exit 1
}

# Function to get current Azure AD Connect version
function Get-AADConnectVersion {
    try {
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Azure AD Connect"
        if (Test-Path $registryPath) {
            $version = Get-ItemProperty -Path $registryPath -Name "Version" -ErrorAction SilentlyContinue
            return $version.Version
        } else {
            $service = Get-Service -Name "ADSync" -ErrorAction SilentlyContinue
            if ($service) {
                $servicePath = (Get-WmiObject win32_service | Where-Object {$_.name -eq "ADSync"}).PathName
                if ($servicePath) {
                    $filePath = $servicePath.Replace('"', '').Split(' ')[0]
                    $fileVersion = (Get-ItemProperty $filePath).VersionInfo.FileVersion
                    return $fileVersion
                }
            }
        }
        return "Unknown"
    } catch {
        return "Error retrieving version"
    }
}

# Function to get latest available version
function Get-LatestAADConnectVersion {
    try {
        $sources = @(
            "https://www.microsoft.com/en-us/download/details.aspx?id=47594",
            "https://docs.microsoft.com/en-us/azure/active-directory/hybrid/reference-connect-version-history"
        )
        
        foreach ($source in $sources) {
            try {
                $page = Invoke-WebRequest -Uri $source -UseBasicParsing -TimeoutSec 10
                $versionPattern = "Version ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"
                $matches = [regex]::Matches($page.Content, $versionPattern)
                if ($matches.Count -gt 0) {
                    return $matches[0].Groups[1].Value
                }
            } catch {
                continue
            }
        }
        return "Check Entra Portal"
    } catch {
        return "Check Entra Portal"
    }
}

# Function to display enabled synchronization rules only
function Show-EnabledSyncRules {
    param([string]$Direction)
    
    Write-Host "`n=== $Direction Synchronization Rules (Enabled Only) ===" -ForegroundColor Cyan
    
    try {
        $allRules = Get-ADSyncRule | Where-Object { $_.Direction -eq $Direction }
        $enabledRules = $allRules | Where-Object { $_.Enabled -eq $true } | Sort-Object Name
        $disabledCount = ($allRules | Where-Object { $_.Enabled -eq $false }).Count
        
        if ($enabledRules.Count -eq 0) {
            Write-Host "No enabled $Direction rules found." -ForegroundColor Yellow
            if ($disabledCount -gt 0) {
                Write-Host "($disabledCount disabled rules hidden)" -ForegroundColor Gray
            }
            return
        }
        
        foreach ($rule in $enabledRules) {
            Write-Host "`nRule Name: $($rule.Name)" -ForegroundColor White
            Write-Host "Connector: $($rule.Connector)" -ForegroundColor Gray
            Write-Host "Precedence: $($rule.Precedence)" -ForegroundColor Yellow
            Write-Host "Enabled: Yes" -ForegroundColor Green
            Write-Host "Description: $($rule.Description)" -ForegroundColor Gray
            Write-Host ("-" * 50)
        }
        
        Write-Host "`nEnabled $Direction Rules: $($enabledRules.Count)" -ForegroundColor Green
        if ($disabledCount -gt 0) {
            Write-Host "Disabled $Direction Rules: $disabledCount (hidden)" -ForegroundColor Gray
        }
        
    } catch {
        Write-Host "Error retrieving $Direction rules: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to show synchronized OUs
function Show-SynchronizedOUs {
    Write-Host "`n=== Synchronized Organizational Units ===" -ForegroundColor Cyan
    
    try {
        $adConnectors = Get-ADSyncConnector | Where-Object { $_.ConnectorTypeName -eq "AD" }
        
        if ($adConnectors.Count -eq 0) {
            Write-Host "No Active Directory connectors found." -ForegroundColor Yellow
            return
        }
        
        foreach ($connector in $adConnectors) {
            Write-Host "`nAD Connector: $($connector.Name)" -ForegroundColor White
            
            try {
                # Try to get connector space objects to understand sync scope
                $connectorSpace = Get-ADSyncCSObject -ConnectorName $connector.Name -MaximumObjectCount 1
                Write-Host "Connector Status: Active" -ForegroundColor Green
                
                # Get basic connector information
                Write-Host "Connector Type: $($connector.ConnectorTypeName)" -ForegroundColor Gray
                Write-Host "Connector ID: $($connector.ConnectorId)" -ForegroundColor Gray
                
                # Try to get some sample objects to show what's being synced
                Write-Host "`nSample Synchronized Objects:" -ForegroundColor Cyan
                $sampleObjects = Get-ADSyncCSObject -ConnectorName $connector.Name -MaximumObjectCount 5
                
                if ($sampleObjects) {
                    foreach ($obj in $sampleObjects) {
                        $objectType = $obj.ObjectType
                        $dn = $obj.DistinguishedName
                        Write-Host "  Type: $objectType" -ForegroundColor Gray
                        Write-Host "  DN: $dn" -ForegroundColor Gray
                        Write-Host ""
                    }
                } else {
                    Write-Host "  No objects found in connector space." -ForegroundColor Yellow
                }
                
            } catch {
                Write-Host "Unable to retrieve detailed connector information." -ForegroundColor Yellow
                Write-Host "Connector appears to be configured but may need a sync cycle." -ForegroundColor Gray
            }
            
            Write-Host ("-" * 60)
        }
        
        # Show additional filtering information
        Write-Host "`nFiltering Information:" -ForegroundColor Cyan
        try {
            # Check if we can get any filtering info
            $globalSettings = Get-ADSyncGlobalSettings -ErrorAction SilentlyContinue
            if ($globalSettings) {
                Write-Host "Global settings retrieved successfully." -ForegroundColor Green
            }
            
            Write-Host "Tip: Use Azure AD Connect GUI to view detailed OU filtering settings." -ForegroundColor Yellow
            
        } catch {
            Write-Host "Additional filtering information not available via PowerShell." -ForegroundColor Gray
        }
        
    } catch {
        Write-Host "Error retrieving connector information: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to check sync status
function Get-SyncStatus {
    try {
        Write-Host "`n=== Synchronization Status ===" -ForegroundColor Cyan
        
        $syncStatus = Get-ADSyncScheduler
        Write-Host "Sync Enabled: $(if ($syncStatus.SyncCycleEnabled) { 'Yes' } else { 'No' })" -ForegroundColor $(if ($syncStatus.SyncCycleEnabled) { 'Green' } else { 'Red' })
        Write-Host "Current Sync Policy: $($syncStatus.CurrentlyEffectiveType)" -ForegroundColor Yellow
        Write-Host "Next Sync Time: $($syncStatus.NextSyncCycleStartTimeInUTC)" -ForegroundColor White
        
        $connectors = Get-ADSyncConnector
        foreach ($connector in $connectors) {
            $runHistory = Get-ADSyncConnectorRunStatus -ConnectorName $connector.Name | Select-Object -First 1
            if ($runHistory) {
                Write-Host "`nConnector: $($connector.Name)" -ForegroundColor White
                Write-Host "Last Run: $($runHistory.StartDate)" -ForegroundColor Gray
                Write-Host "Result: $($runHistory.Result)" -ForegroundColor $(if ($runHistory.Result -eq "Success") { 'Green' } else { 'Red' })
            }
        }
        
    } catch {
        Write-Host "Error retrieving sync status: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to backup configuration
function Backup-AADConnectConfig {
    Write-Host "`n=== Configuration Backup ===" -ForegroundColor Cyan
    
    try {
        $backupPath = "$env:USERPROFILE\Desktop\AADConnect_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
        
        Write-Host "Creating configuration backup..." -ForegroundColor Yellow
        
        Write-Host "Exporting synchronization rules..." -ForegroundColor Gray
        $rules = Get-ADSyncRule
        $rules | Export-Clixml -Path "$backupPath\SyncRules.xml"
        
        Write-Host "Exporting connector configuration..." -ForegroundColor Gray
        $connectors = Get-ADSyncConnector
        $connectors | Export-Clixml -Path "$backupPath\Connectors.xml"
        
        Write-Host "Exporting global settings..." -ForegroundColor Gray
        $globalSettings = Get-ADSyncGlobalSettings
        $globalSettings | Export-Clixml -Path "$backupPath\GlobalSettings.xml"
        
        $summary = @"
Azure AD Connect Configuration Backup
Created: $(Get-Date)
Backup Location: $backupPath

Components Backed Up:
- Synchronization Rules: $($rules.Count) rules
- Connectors: $($connectors.Count) connectors
- Global Settings: Exported

To restore:
1. Install Azure AD Connect
2. Stop ADSync service
3. Import configuration using PowerShell
4. Start ADSync service
"@
        
        $summary | Out-File "$backupPath\BackupSummary.txt"
        
        Write-Host "Backup completed successfully!" -ForegroundColor Green
        Write-Host "Backup location: $backupPath" -ForegroundColor White
        
        return $backupPath
        
    } catch {
        Write-Host "Error creating backup: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# Function to handle updates
function Update-AADConnect {
    param(
        [string]$CurrentVersion,
        [string]$LatestVersion
    )
    
    if ($CurrentVersion -eq $LatestVersion -and $LatestVersion -ne "Check Entra Portal") {
        Write-Host "`nAzure AD Connect is already up to date (Version: $CurrentVersion)" -ForegroundColor Green
        return
    }
    
    Write-Host "`nCurrent Version: $CurrentVersion" -ForegroundColor Yellow
    Write-Host "Latest Version: $LatestVersion" -ForegroundColor Green
    
    Write-Host "`n=== Download Instructions ===" -ForegroundColor Cyan
    Write-Host "Azure AD Connect downloads are available through the Entra Admin Center." -ForegroundColor Yellow
    Write-Host "`nTo download the latest version:" -ForegroundColor White
    Write-Host "1. Go to: https://entra.microsoft.com" -ForegroundColor Gray
    Write-Host "2. Navigate to: Identity > Hybrid management > Azure AD Connect" -ForegroundColor Gray
    Write-Host "3. Click on 'Download Azure AD Connect'" -ForegroundColor Gray
    Write-Host "4. Download the latest version" -ForegroundColor Gray
    
    $choice = Read-Host "`nChoose an option:`n[1] Open Entra portal in browser`n[2] Install from local file`n[3] Skip update`nEnter choice (1-3)"
    
    switch ($choice) {
        "1" {
            Write-Host "`nOpening Entra Admin Center..." -ForegroundColor Yellow
            Start-Process "https://entra.microsoft.com/#view/Microsoft_AAD_Connect/ConnectBlade"
            Write-Host "Please download the installer manually." -ForegroundColor Yellow
        }
        "2" {
            $filePath = Read-Host "`nEnter the full path to the Azure AD Connect installer"
            if (Test-Path $filePath) {
                Write-Host "`nStarting installation..." -ForegroundColor Yellow
                Write-Host "WARNING: This will restart the Azure AD Connect service!" -ForegroundColor Red
                
                $installConfirm = Read-Host "Continue with installation? (Y/N)"
                if ($installConfirm -eq 'Y' -or $installConfirm -eq 'y') {
                    try {
                        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$filePath`" /quiet /norestart" -Wait -PassThru
                        
                        if ($process.ExitCode -eq 0) {
                            Write-Host "Installation completed successfully." -ForegroundColor Green
                            Write-Host "Please restart the server if prompted." -ForegroundColor Yellow
                        } else {
                            Write-Host "Installation failed with exit code: $($process.ExitCode)" -ForegroundColor Red
                        }
                    } catch {
                        Write-Host "Error during installation: $($_.Exception.Message)" -ForegroundColor Red
                    }
                } else {
                    Write-Host "Installation cancelled by user." -ForegroundColor Yellow
                }
            } else {
                Write-Host "File not found: $filePath" -ForegroundColor Red
            }
        }
        "3" {
            Write-Host "Update skipped by user." -ForegroundColor Yellow
        }
        default {
            Write-Host "Invalid choice. Update cancelled." -ForegroundColor Red
        }
    }
}

# Main script execution
Clear-Host
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "    Entra ID Connect Management       " -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan

Write-Host "`nChecking current Azure AD Connect version..." -ForegroundColor Yellow
$currentVersion = Get-AADConnectVersion
Write-Host "Current Version: $currentVersion" -ForegroundColor White

Write-Host "`nChecking latest available version..." -ForegroundColor Yellow
$latestVersion = Get-LatestAADConnectVersion
Write-Host "Latest Version: $latestVersion" -ForegroundColor White

Get-SyncStatus
Show-SynchronizedOUs
Show-EnabledSyncRules -Direction "Inbound"
Show-EnabledSyncRules -Direction "Outbound"

Write-Host "`n======================================" -ForegroundColor Cyan
Write-Host "           Update Options              " -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan

$backupChoice = Read-Host "`nWould you like to backup your current configuration before updating? (Y/N)"
if ($backupChoice -eq 'Y' -or $backupChoice -eq 'y') {
    $backupPath = Backup-AADConnectConfig
    if ($backupPath) {
        Write-Host "`nConfiguration backed up to: $backupPath" -ForegroundColor Green
    }
}

Update-AADConnect -CurrentVersion $currentVersion -LatestVersion $latestVersion

Write-Host "`n======================================" -ForegroundColor Cyan
Write-Host "         Script Completed             " -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan

Write-Host "`nUseful Commands:" -ForegroundColor Cyan
Write-Host "Start-ADSyncSyncCycle -PolicyType Delta    # Run delta synchronization" -ForegroundColor Gray
Write-Host "Start-ADSyncSyncCycle -PolicyType Initial  # Run full synchronization" -ForegroundColor Gray
Write-Host "Get-ADSyncConnectorRunStatus               # Check run history" -ForegroundColor Gray
Write-Host "Get-ADSyncScheduler                        # Check sync schedule" -ForegroundColor Gray
Write-Host "Get-ADSyncRule | Where-Object {\$_.Enabled -eq \$false} # Show disabled rules" -ForegroundColor Gray

Write-Host "`nUpdate Resources:" -ForegroundColor Cyan
Write-Host "Entra Admin Center: https://entra.microsoft.com" -ForegroundColor Gray
Write-Host "Azure AD Connect Download: https://entra.microsoft.com/#view/Microsoft_AAD_Connect/ConnectBlade" -ForegroundColor Gray

Write-Host "`nImportant Notes:" -ForegroundColor Yellow
Write-Host "Always backup configuration before updating" -ForegroundColor Gray
Write-Host "Test updates in a staging environment first" -ForegroundColor Gray
Write-Host "Review release notes for breaking changes" -ForegroundColor Gray
Write-Host "Schedule updates during maintenance windows" -ForegroundColor Gray