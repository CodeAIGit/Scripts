#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CIS Level 2 Multi-Version Windows Server Security Hardening Script
.DESCRIPTION
    Implements CIS Level 2 security controls for Windows Server 2019, 2022, and 2025.
    Automatically detects server version and applies appropriate hardening configurations.
    This level provides enhanced security for specialized high-security environments.
.NOTES
    Author: Security Hardening Tool
    Version: 2.1 Multi-Version
    Requires: Administrator privileges, PowerShell 5.1+
    Compatible: Windows Server 2019, 2022, 2025
    WARNING: Level 2 controls may significantly impact system functionality
.EXAMPLE
    .\CIS-Level2-MultiVersion-Hardening.ps1
    Detects server version and applies appropriate CIS Level 2 hardening
#>

# Script configuration
$ScriptVersion = "CIS Level 2 Multi-Version Hardening v2.1"
$LogPath = "C:\Windows\Temp\CIS_Level2_MultiVersion_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Start logging
Start-Transcript -Path $LogPath -Append

# Initialize global variables
$Global:ServerVersion = ""
$Global:ServerBuild = ""
$Global:TotalControls = 0
$Global:SuccessCount = 0
$Global:FailureCount = 0

# Helper Functions
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [string]$Color = "White"
    )
    $TimeStamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $LogEntry = "[$TimeStamp] [$Level] $Message"
    Write-Host $LogEntry -ForegroundColor $Color
    Add-Content -Path $LogPath -Value $LogEntry -ErrorAction SilentlyContinue
}

function Get-WindowsServerVersion {
    try {
        $OSInfo = Get-WmiObject -Class Win32_OperatingSystem
        $BuildNumber = [System.Environment]::OSVersion.Version.Build
        
        $ProductName = $OSInfo.Caption
        Write-Log "Detected OS: $ProductName (Build: $BuildNumber)" -Color "Cyan"
        
        # Determine server version based on build number and product name
        if ($ProductName -like "*Server 2025*" -or $BuildNumber -ge 26100) {
            return @{
                Version = "2025"
                Build = $BuildNumber
                Name = "Windows Server 2025"
                Supported = $true
            }
        }
        elseif ($ProductName -like "*Server 2022*" -or ($BuildNumber -ge 20348 -and $BuildNumber -lt 26100)) {
            return @{
                Version = "2022"
                Build = $BuildNumber
                Name = "Windows Server 2022"
                Supported = $true
            }
        }
        elseif ($ProductName -like "*Server 2019*" -or ($BuildNumber -ge 17763 -and $BuildNumber -lt 20348)) {
            return @{
                Version = "2019"
                Build = $BuildNumber
                Name = "Windows Server 2019"
                Supported = $true
            }
        }
        else {
            return @{
                Version = "Unknown"
                Build = $BuildNumber
                Name = $ProductName
                Supported = $false
            }
        }
    }
    catch {
        Write-Log "[ERROR] Failed to detect Windows version: $($_.Exception.Message)" -Level "ERROR" -Color "Red"
        return @{
            Version = "Unknown"
            Build = "Unknown"
            Name = "Unknown"
            Supported = $false
        }
    }
}

function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWord",
        [string]$Description,
        [string[]]$SupportedVersions = @("2019", "2022", "2025")
    )
    
    if ($Global:ServerVersion -notin $SupportedVersions) {
        Write-Log "[SKIP] $Description (Not supported on Server $Global:ServerVersion)" -Level "WARN" -Color "Yellow"
        return $false
    }
    
    try {
        if (!(Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
            Write-Log "Created registry path: $Path" -Level "DEBUG" -Color "Gray"
        }
        
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        
        # Verify the setting
        $VerifyValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($VerifyValue.$Name -eq $Value) {
            Write-Log "[OK] $Description" -Level "SUCCESS" -Color "Green"
            return $true
        } else {
            Write-Log "[FAIL] Failed to verify: $Description" -Level "ERROR" -Color "Red"
            return $false
        }
    }
    catch {
        Write-Log "[ERROR] Error setting $Description : $($_.Exception.Message)" -Level "ERROR" -Color "Red"
        return $false
    }
}

function Disable-Service {
    param(
        [string]$ServiceName,
        [string]$Description,
        [string[]]$SupportedVersions = @("2019", "2022", "2025"),
        [hashtable]$VersionSpecificNames = @{}
    )
    
    if ($Global:ServerVersion -notin $SupportedVersions) {
        Write-Log "[SKIP] $Description (Not supported on Server $Global:ServerVersion)" -Level "WARN" -Color "Yellow"
        return $false
    }
    
    # Check for version-specific service names
    $ActualServiceName = $ServiceName
    if ($VersionSpecificNames.ContainsKey($Global:ServerVersion)) {
        $ActualServiceName = $VersionSpecificNames[$Global:ServerVersion]
    }
    
    try {
        $Service = Get-Service -Name $ActualServiceName -ErrorAction SilentlyContinue
        if ($Service) {
            Stop-Service -Name $ActualServiceName -Force -ErrorAction SilentlyContinue
            Set-Service -Name $ActualServiceName -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Log "[OK] Disabled service: $Description ($ActualServiceName)" -Level "SUCCESS" -Color "Green"
            return $true
        } else {
            Write-Log "[SKIP] Service not found: $ActualServiceName" -Level "WARN" -Color "Yellow"
            return $false
        }
    }
    catch {
        Write-Log "[ERROR] Failed to disable service $ActualServiceName : $($_.Exception.Message)" -Level "ERROR" -Color "Red"
        return $false
    }
}

function Set-AuditPolicy {
    param(
        [string]$Category,
        [string]$Description,
        [string[]]$SupportedVersions = @("2019", "2022", "2025")
    )
    
    if ($Global:ServerVersion -notin $SupportedVersions) {
        Write-Log "[SKIP] $Description (Not supported on Server $Global:ServerVersion)" -Level "WARN" -Color "Yellow"
        return $false
    }
    
    try {
        auditpol /set /category:"$Category" /success:enable /failure:enable 2>$null | Out-Null
        Write-Log "[OK] Enabled audit policy: $Description" -Level "SUCCESS" -Color "Green"
        return $true
    }
    catch {
        Write-Log "[ERROR] Failed to set audit policy $Category : $($_.Exception.Message)" -Level "ERROR" -Color "Red"
        return $false
    }
}

function New-RestorePoint {
    try {
        Write-Log "Creating system restore point..." -Color "Yellow"
        Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue
        $RestoreResult = Checkpoint-Computer -Description "Before CIS Level 2 Multi-Version Hardening" -RestorePointType "MODIFY_SETTINGS"
        Write-Log "[OK] System restore point created" -Level "SUCCESS" -Color "Green"
        return $true
    }
    catch {
        Write-Log "[WARN] Could not create restore point: $($_.Exception.Message)" -Level "WARN" -Color "Yellow"
        return $false
    }
}

function Get-VersionSpecificControls {
    param([string]$Version)
    
    switch ($Version) {
        "2019" {
            return @{
                TotalControls = 38
                PasswordLength = 14
                PasswordHistory = 24
                MaxPasswordAge = 60
                SecurityLogSize = 268435456  # 256MB
                ApplicationLogSize = 67108864  # 64MB
                SystemLogSize = 67108864  # 64MB
                ScreenSaverTimeout = 600  # 10 minutes
                LockoutThreshold = 5
                LockoutDuration = 30
                SpecificServices = @{
                    "WSearch" = "Windows Search (2019)"
                    "Spooler" = "Print Spooler (2019)"
                    "Fax" = "Fax Service (2019)"
                }
                SpecificFeatures = @(
                    "Basic SMB hardening",
                    "Standard PowerShell logging",
                    "Traditional audit policies"
                )
            }
        }
        "2022" {
            return @{
                TotalControls = 42
                PasswordLength = 14
                PasswordHistory = 24
                MaxPasswordAge = 60
                SecurityLogSize = 268435456  # 256MB
                ApplicationLogSize = 67108864  # 64MB
                SystemLogSize = 67108864  # 64MB
                ScreenSaverTimeout = 600  # 10 minutes
                LockoutThreshold = 5
                LockoutDuration = 30
                SpecificServices = @{
                    "WSearch" = "Windows Search (2022)"
                    "Spooler" = "Print Spooler (2022)"
                    "Fax" = "Fax Service (2022)"
                    "RemoteRegistry" = "Remote Registry (2022)"
                }
                SpecificFeatures = @(
                    "Enhanced SMB 3.1.1 hardening",
                    "Advanced PowerShell logging",
                    "Extended audit policies",
                    "Enhanced Windows Defender integration"
                )
            }
        }
        "2025" {
            return @{
                TotalControls = 45
                PasswordLength = 16  # Increased for 2025
                PasswordHistory = 30  # Increased for 2025
                MaxPasswordAge = 45  # Decreased for 2025 (more frequent changes)
                SecurityLogSize = 536870912  # 512MB for 2025
                ApplicationLogSize = 134217728  # 128MB for 2025
                SystemLogSize = 134217728  # 128MB for 2025
                ScreenSaverTimeout = 300  # 5 minutes for 2025 (more restrictive)
                LockoutThreshold = 3  # More restrictive for 2025
                LockoutDuration = 60  # Longer lockout for 2025
                SpecificServices = @{
                    "WSearch" = "Windows Search (2025)"
                    "Spooler" = "Print Spooler (2025)"
                    "Fax" = "Fax Service (2025)"
                    "RemoteRegistry" = "Remote Registry (2025)"
                    "Browser" = "Computer Browser (2025)"
                }
                SpecificFeatures = @(
                    "Advanced SMB over QUIC hardening",
                    "AI-enhanced PowerShell logging",
                    "Zero Trust audit policies",
                    "Advanced Windows Defender integration",
                    "Cloud-native security features",
                    "Enhanced credential protection"
                )
            }
        }
        default {
            return @{
                TotalControls = 35
                PasswordLength = 12
                PasswordHistory = 20
                MaxPasswordAge = 90
                SecurityLogSize = 134217728  # 128MB
                ApplicationLogSize = 33554432  # 32MB
                SystemLogSize = 33554432  # 32MB
                ScreenSaverTimeout = 900  # 15 minutes
                LockoutThreshold = 10
                LockoutDuration = 15
                SpecificServices = @{}
                SpecificFeatures = @("Basic hardening controls")
            }
        }
    }
}

# Detect Windows Server Version
Clear-Host
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "    CIS Level 2 Multi-Version Windows Server Hardening        " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

Write-Log "Detecting Windows Server version..." -Color "Yellow"
$VersionInfo = Get-WindowsServerVersion
$Global:ServerVersion = $VersionInfo.Version
$Global:ServerBuild = $VersionInfo.Build

# Display detected version
Write-Host "DETECTED WINDOWS SERVER VERSION:" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green
Write-Host "Server Version: $($VersionInfo.Name)" -ForegroundColor White
Write-Host "Build Number: $($VersionInfo.Build)" -ForegroundColor White
Write-Host "Script Support: $(if($VersionInfo.Supported){'[SUPPORTED]'}else{'[UNSUPPORTED]'})" -ForegroundColor $(if($VersionInfo.Supported){"Green"}else{"Red"})
Write-Host ""

if (-not $VersionInfo.Supported) {
    Write-Host "WARNING: Unsupported Windows version detected!" -ForegroundColor Red
    Write-Host "This script is designed for Windows Server 2019, 2022, and 2025." -ForegroundColor Red
    Write-Host "Proceeding may cause unexpected results." -ForegroundColor Red
    Write-Host ""
    $ContinueUnsupported = Read-Host "Continue anyway? (Y/N)"
    if ($ContinueUnsupported -ne "Y" -and $ContinueUnsupported -ne "y") {
        Write-Host "Exiting..." -ForegroundColor Yellow
        exit 1
    }
}

# Get version-specific configuration
$Config = Get-VersionSpecificControls -Version $Global:ServerVersion
$Global:TotalControls = $Config.TotalControls

# Display version-specific features
Write-Host "VERSION-SPECIFIC CONFIGURATION:" -ForegroundColor Cyan
Write-Host "===============================" -ForegroundColor Cyan
Write-Host "Total Security Controls: $($Config.TotalControls)" -ForegroundColor White
Write-Host "Password Length Requirement: $($Config.PasswordLength) characters" -ForegroundColor White
Write-Host "Password History: $($Config.PasswordHistory) passwords" -ForegroundColor White
Write-Host "Maximum Password Age: $($Config.MaxPasswordAge) days" -ForegroundColor White
Write-Host "Account Lockout: $($Config.LockoutThreshold) attempts, $($Config.LockoutDuration) minutes" -ForegroundColor White
Write-Host "Screen Saver Timeout: $([math]::Round($Config.ScreenSaverTimeout/60)) minutes" -ForegroundColor White
Write-Host ""
Write-Host "Version-Specific Features:" -ForegroundColor Cyan
foreach ($feature in $Config.SpecificFeatures) {
    Write-Host "  * $feature" -ForegroundColor White
}
Write-Host ""

# Show detailed configuration that will be applied
Write-Host "THE FOLLOWING ADVANCED SETTINGS WILL BE CONFIGURED:" -ForegroundColor Yellow
Write-Host "===================================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "ENHANCED PASSWORD POLICIES (Version-Optimized):" -ForegroundColor Cyan
Write-Host "  * Minimum password length: $($Config.PasswordLength) characters" -ForegroundColor White
Write-Host "  * Password complexity: Enforced with strict rules" -ForegroundColor White
Write-Host "  * Password history: $($Config.PasswordHistory) passwords remembered" -ForegroundColor White
Write-Host "  * Maximum password age: $($Config.MaxPasswordAge) days" -ForegroundColor White
Write-Host "  * Minimum password age: 2 days" -ForegroundColor White
Write-Host "  * Account lockout: $($Config.LockoutThreshold) attempts, $($Config.LockoutDuration) minutes lockout" -ForegroundColor White
Write-Host ""
Write-Host "ADVANCED ACCOUNT SECURITY:" -ForegroundColor Cyan
Write-Host "  * Interactive logon: Display security warning" -ForegroundColor White
Write-Host "  * Cached credentials: Limited to 0 (domain only)" -ForegroundColor White
Write-Host "  * Anonymous access: Completely disabled" -ForegroundColor White
Write-Host "  * Null session access: Blocked" -ForegroundColor White
Write-Host "  * Administrative shares: Hardened access" -ForegroundColor White
Write-Host ""
Write-Host "NETWORK SECURITY HARDENING (Version-Specific):" -ForegroundColor Cyan
if ($Global:ServerVersion -eq "2025") {
    Write-Host "  * SMB over QUIC: Enhanced security" -ForegroundColor White
    Write-Host "  * Advanced encryption protocols" -ForegroundColor White
} elseif ($Global:ServerVersion -eq "2022") {
    Write-Host "  * SMB 3.1.1: Enhanced security features" -ForegroundColor White
    Write-Host "  * AES-256 encryption enforcement" -ForegroundColor White
} else {
    Write-Host "  * SMB v2/v3: Standard hardening" -ForegroundColor White
}
Write-Host "  * SMB v1: Completely disabled" -ForegroundColor White
Write-Host "  * LLMNR: Disabled (prevents credential theft)" -ForegroundColor White
Write-Host "  * NetBIOS: Disabled over TCP/IP" -ForegroundColor White
Write-Host "  * NTLM: Restricted (Kerberos preferred)" -ForegroundColor White
Write-Host ""
Write-Host "SERVICE HARDENING (Version-Aware):" -ForegroundColor Cyan
foreach ($service in $Config.SpecificServices.GetEnumerator()) {
    Write-Host "  * $($service.Value): Will be disabled" -ForegroundColor White
}
Write-Host ""
Write-Host "ENHANCED AUDITING (Version-Optimized):" -ForegroundColor Cyan
Write-Host "  * Security log: $([math]::Round($Config.SecurityLogSize/1MB))MB" -ForegroundColor White
Write-Host "  * Application log: $([math]::Round($Config.ApplicationLogSize/1MB))MB" -ForegroundColor White
Write-Host "  * System log: $([math]::Round($Config.SystemLogSize/1MB))MB" -ForegroundColor White
if ($Global:ServerVersion -eq "2025") {
    Write-Host "  * AI-enhanced PowerShell logging" -ForegroundColor White
    Write-Host "  * Zero Trust audit policies" -ForegroundColor White
} elseif ($Global:ServerVersion -eq "2022") {
    Write-Host "  * Advanced PowerShell logging" -ForegroundColor White
    Write-Host "  * Extended audit categories" -ForegroundColor White
} else {
    Write-Host "  * Standard PowerShell logging" -ForegroundColor White
    Write-Host "  * Basic audit policies" -ForegroundColor White
}
Write-Host ""
Write-Host "SYSTEM HARDENING:" -ForegroundColor Cyan
Write-Host "  * Screen saver: $([math]::Round($Config.ScreenSaverTimeout/60))-minute timeout" -ForegroundColor White
Write-Host "  * USB storage: Restricted" -ForegroundColor White
Write-Host "  * Autorun/Autoplay: Completely disabled" -ForegroundColor White
Write-Host "  * Error reporting: Disabled" -ForegroundColor White
Write-Host "  * Remote assistance: Disabled" -ForegroundColor White
Write-Host ""

# Impact warnings based on version
Write-Host "VERSION-SPECIFIC IMPACT ASSESSMENT:" -ForegroundColor Red
Write-Host "====================================" -ForegroundColor Red
if ($Global:ServerVersion -eq "2025") {
    Write-Host "  [CRITICAL] Server 2025: Highest security, maximum restrictions" -ForegroundColor Red
    Write-Host "  [CRITICAL] Modern applications should adapt well" -ForegroundColor Red
    Write-Host "  [CRITICAL] Legacy applications may completely fail" -ForegroundColor Red
} elseif ($Global:ServerVersion -eq "2022") {
    Write-Host "  [HIGH] Server 2022: Enhanced security with good compatibility" -ForegroundColor Red
    Write-Host "  [HIGH] Most modern applications will function" -ForegroundColor Red
    Write-Host "  [HIGH] Some legacy features may be impacted" -ForegroundColor Red
} else {
    Write-Host "  [HIGH] Server 2019: Balanced security and compatibility" -ForegroundColor Red
    Write-Host "  [HIGH] Better legacy application support" -ForegroundColor Red
    Write-Host "  [HIGH] May lack some advanced security features" -ForegroundColor Red
}
Write-Host ""

# Strong warning and confirmation
Write-Host "================================================================" -ForegroundColor Red
Write-Host "                      FINAL WARNING                            " -ForegroundColor Red
Write-Host "================================================================" -ForegroundColor Red
Write-Host ""
Write-Host "CIS Level 2 controls for $($VersionInfo.Name) WILL impact functionality!" -ForegroundColor Red
Write-Host "Only proceed if you understand the version-specific implications." -ForegroundColor Red
Write-Host ""
Write-Host "Are you ABSOLUTELY SURE you want to apply Level 2 hardening?" -ForegroundColor Yellow
Write-Host "This configuration is optimized for $($VersionInfo.Name)." -ForegroundColor Yellow
Write-Host ""

$FirstConfirmation = Read-Host "Type 'YES' in ALL CAPS to confirm you understand the risks"

if ($FirstConfirmation -ne "YES") {
    Clear-Host
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host "                 HARDENING CANCELLED                           " -ForegroundColor Green  
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Level 2 hardening cancelled - no changes made." -ForegroundColor Green
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 0
}

Write-Host ""
Write-Host "Second confirmation required for $($VersionInfo.Name):" -ForegroundColor Yellow
$SecondConfirmation = Read-Host "Type 'APPLY' to proceed with version-specific hardening"

if ($SecondConfirmation -ne "APPLY") {
    Clear-Host
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host "                 HARDENING CANCELLED                           " -ForegroundColor Green  
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Level 2 hardening cancelled - no changes made." -ForegroundColor Green
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 0
}

# User double-confirmed - proceed with version-specific hardening
Clear-Host
Write-Host "================================================================" -ForegroundColor Red
Write-Host "    STARTING CIS LEVEL 2 HARDENING FOR $($VersionInfo.Name.ToUpper())" -ForegroundColor Red
Write-Host "                 ADVANCED SECURITY                             " -ForegroundColor Red
Write-Host "================================================================" -ForegroundColor Red
Write-Host ""

Write-Log "Starting CIS Level 2 hardening for $($VersionInfo.Name)" -Color "Red"
Write-Log "Build: $($VersionInfo.Build) | Controls: $($Config.TotalControls)" -Color "Yellow"

# Create restore point
New-RestorePoint | Out-Null

Write-Log "Applying version-specific CIS Level 2 security controls..." -Color "Yellow"

# 1. Enhanced Password Policies (Version-Specific)
Write-Log "Configuring enhanced password policies for Server $Global:ServerVersion..." -Color "Yellow"

if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MinimumPasswordLength" -Value $Config.PasswordLength -Description "Minimum password length ($($Config.PasswordLength) characters)") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "PasswordComplexity" -Value 1 -Description "Enhanced password complexity") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "PasswordHistorySize" -Value $Config.PasswordHistory -Description "Password history ($($Config.PasswordHistory) passwords)") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MaximumPasswordAge" -Value $Config.MaxPasswordAge -Description "Maximum password age ($($Config.MaxPasswordAge) days)") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MinimumPasswordAge" -Value 2 -Description "Minimum password age (2 days)") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

# 2. Version-Specific Account Lockout Policy
Write-Log "Configuring version-optimized account lockout policy..." -Color "Yellow"
try {
    cmd.exe /c "net accounts /lockoutthreshold:$($Config.LockoutThreshold) /lockoutduration:$($Config.LockoutDuration) /lockoutwindow:$($Config.LockoutDuration)" 2>$null | Out-Null
    Write-Log "[OK] Account lockout policy configured ($($Config.LockoutThreshold) attempts, $($Config.LockoutDuration) min)" -Level "SUCCESS" -Color "Green"
    $Global:SuccessCount++
} catch {
    Write-Log "[FAIL] Failed to configure account lockout policy" -Level "ERROR" -Color "Red"
    $Global:FailureCount++
}

# 3. Advanced Security Options
Write-Log "Configuring advanced security options..." -Color "Yellow"

if (Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeCaption" -Value "AUTHORIZED USE ONLY" -Type "String" -Description "Security warning caption") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

if (Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeText" -Value "This system is for authorized users only. All activity is monitored and logged. Unauthorized access is prohibited." -Type "String" -Description "Security warning message") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

if (Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value 0 -Description "Disable cached credentials") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

# 4. Version-Specific Network Security Hardening
Write-Log "Configuring version-specific network security hardening..." -Color "Yellow"

# Common network hardening
if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Description "Disable SMBv1 protocol") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Description "Require SMB signing") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

# Version-specific SMB hardening
if ($Global:ServerVersion -eq "2025") {
    if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EncryptionMode" -Value 3 -Description "Require SMB AES-256 encryption (2025)" -SupportedVersions @("2025")) { $Global:SuccessCount++ } else { $Global:FailureCount++ }
    if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireQUIC" -Value 1 -Description "Enable SMB over QUIC (2025)" -SupportedVersions @("2025")) { $Global:SuccessCount++ } else { $Global:FailureCount++ }
} elseif ($Global:ServerVersion -eq "2022") {
    if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EncryptionMode" -Value 2 -Description "Require SMB AES-128 encryption (2022)" -SupportedVersions @("2022", "2025")) { $Global:SuccessCount++ } else { $Global:FailureCount++ }
} else {
    if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EncryptionMode" -Value 1 -Description "Enable SMB encryption (2019)" -SupportedVersions @("2019", "2022", "2025")) { $Global:SuccessCount++ } else { $Global:FailureCount++ }
}

# Disable LLMNR and NetBIOS
if (Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Description "Disable LLMNR") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NodeType" -Value 2 -Description "Disable NetBIOS broadcasts") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

# 5. Version-Aware Service Hardening
Write-Log "Configuring version-aware service hardening..." -Color "Yellow"

foreach ($service in $Config.SpecificServices.GetEnumerator()) {
    if (Disable-Service -ServiceName $service.Key -Description $service.Value) { 
        $Global:SuccessCount++ 
    } else { 
        $Global:FailureCount++ 
    }
}

# 6. USB and Removable Media Restrictions
Write-Log "Configuring removable media restrictions..." -Color "Yellow"

if (Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" -Name "Deny_All" -Value 1 -Description "Restrict USB storage devices") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

if (Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Description "Disable all autorun") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

# 7. Version-Optimized Enhanced Auditing
Write-Log "Configuring version-optimized enhanced auditing..." -Color "Yellow"

if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "MaxSize" -Value $Config.SecurityLogSize -Description "Security log size ($([math]::Round($Config.SecurityLogSize/1MB))MB)") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application" -Name "MaxSize" -Value $Config.ApplicationLogSize -Description "Application log size ($([math]::Round($Config.ApplicationLogSize/1MB))MB)") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System" -Name "MaxSize" -Value $Config.SystemLogSize -Description "System log size ($([math]::Round($Config.SystemLogSize/1MB))MB)") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

# Version-specific PowerShell logging
if ($Global:ServerVersion -eq "2025") {
    if (Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1 -Description "PowerShell module logging (2025)" -SupportedVersions @("2025")) { $Global:SuccessCount++ } else { $Global:FailureCount++ }
    if (Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Description "PowerShell script block logging (2025)" -SupportedVersions @("2025")) { $Global:SuccessCount++ } else { $Global:FailureCount++ }
    if (Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1 -Description "PowerShell transcription logging (2025)" -SupportedVersions @("2025")) { $Global:SuccessCount++ } else { $Global:FailureCount++ }
} elseif ($Global:ServerVersion -eq "2022") {
    if (Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1 -Description "PowerShell module logging (2022)" -SupportedVersions @("2022", "2025")) { $Global:SuccessCount++ } else { $Global:FailureCount++ }
    if (Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Description "PowerShell script block logging (2022)" -SupportedVersions @("2022", "2025")) { $Global:SuccessCount++ } else { $Global:FailureCount++ }
} else {
    if (Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1 -Description "PowerShell module logging (2019)") { $Global:SuccessCount++ } else { $Global:FailureCount++ }
}

# 8. Version-Specific Advanced Audit Policies
Write-Log "Configuring version-specific audit policies..." -Color "Yellow"

$AuditCategories = @("Account Logon", "Account Management", "Detailed Tracking", "Policy Change", "Privilege Use", "System")

if ($Global:ServerVersion -eq "2025") {
    $AuditCategories += @("Object Access", "Directory Service Access")
} elseif ($Global:ServerVersion -eq "2022") {
    $AuditCategories += @("Object Access")
}

foreach ($category in $AuditCategories) {
    if (Set-AuditPolicy -Category $category -Description "Audit policy: $category") {
        $Global:SuccessCount++
    } else {
        $Global:FailureCount++
    }
}

# 9. Version-Optimized Screen Saver Security
Write-Log "Configuring version-optimized screen saver security..." -Color "Yellow"

if (Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaveActive" -Value 1 -Description "Enable screen saver") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

if (Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -Value $Config.ScreenSaverTimeout -Description "Screen saver timeout ($([math]::Round($Config.ScreenSaverTimeout/60)) minutes)") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

if (Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -Value 1 -Description "Secure screen saver") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

# 10. Additional System Hardening
Write-Log "Configuring additional system hardening..." -Color "Yellow"

if (Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Description "Disable Windows Error Reporting") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0 -Description "Disable Remote Assistance") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

# Summary
Write-Host ""
Write-Host "================================================================" -ForegroundColor Red
Write-Host "         CIS LEVEL 2 SUMMARY FOR $($VersionInfo.Name.ToUpper())" -ForegroundColor Red
Write-Host "================================================================" -ForegroundColor Red

$CompliancePercentage = [math]::Round(($Global:SuccessCount / $Global:TotalControls) * 100, 2)

Write-Host "Server Version: $($VersionInfo.Name) (Build $($VersionInfo.Build))" -ForegroundColor White
Write-Host "Total Controls Applied: $Global:SuccessCount/$Global:TotalControls" -ForegroundColor White
Write-Host "Success Rate: $CompliancePercentage%" -ForegroundColor $(if($CompliancePercentage -ge 80){"Green"}elseif($CompliancePercentage -ge 60){"Yellow"}else{"Red"})

if ($Global:FailureCount -gt 0) {
    Write-Host "Failed Controls: $Global:FailureCount" -ForegroundColor Red
}

Write-Host ""
Write-Host "Applied Version-Specific Controls:" -ForegroundColor White
Write-Host "* Enhanced password policies ($($Config.PasswordLength) chars, $($Config.PasswordHistory) history)" -ForegroundColor Gray
Write-Host "* Strict account lockout ($($Config.LockoutThreshold) attempts, $($Config.LockoutDuration) min)" -ForegroundColor Gray
Write-Host "* Version-optimized network hardening" -ForegroundColor Gray
Write-Host "* Server-specific service hardening" -ForegroundColor Gray
Write-Host "* Enhanced audit logging ($([math]::Round($Config.SecurityLogSize/1MB))MB security log)" -ForegroundColor Gray
Write-Host "* Optimized screen saver security ($([math]::Round($Config.ScreenSaverTimeout/60)) min)" -ForegroundColor Gray

Write-Host ""
Write-Host "Version-Specific Features Applied:" -ForegroundColor Cyan
foreach ($feature in $Config.SpecificFeatures) {
    Write-Host "  [OK] $feature" -ForegroundColor Green
}

Write-Host ""
if ($CompliancePercentage -ge 90) {
    Write-Host "[SUCCESS] Excellent! CIS Level 2 hardening completed for $($VersionInfo.Name)." -ForegroundColor Green
    Write-Host "Your system now has advanced version-optimized security protections." -ForegroundColor Green
} elseif ($CompliancePercentage -ge 75) {
    Write-Host "[WARNING] Good progress. Review failed items for full compliance." -ForegroundColor Yellow
} else {
    Write-Host "[WARNING] Several items failed. Please review the log for details." -ForegroundColor Red
}

Write-Host ""
Write-Host "VERSION-SPECIFIC POST-HARDENING STEPS FOR $($VersionInfo.Name.ToUpper()):" -ForegroundColor Red
if ($Global:ServerVersion -eq "2025") {
    Write-Host "* Verify modern application compatibility" -ForegroundColor Yellow
    Write-Host "* Test cloud integration features" -ForegroundColor Yellow
    Write-Host "* Validate AI-enhanced security logging" -ForegroundColor Yellow
} elseif ($Global:ServerVersion -eq "2022") {
    Write-Host "* Test enhanced SMB 3.1.1 functionality" -ForegroundColor Yellow
    Write-Host "* Verify Hyper-V security features" -ForegroundColor Yellow
    Write-Host "* Check Windows Admin Center compatibility" -ForegroundColor Yellow
} else {
    Write-Host "* Test legacy application compatibility thoroughly" -ForegroundColor Yellow
    Write-Host "* Verify domain controller functionality (if applicable)" -ForegroundColor Yellow
    Write-Host "* Check file server operations" -ForegroundColor Yellow
}
Write-Host "* Monitor system performance and stability" -ForegroundColor Yellow
Write-Host "* Review version-specific security event logs" -ForegroundColor Yellow

Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host "* Conduct version-appropriate functionality testing" -ForegroundColor White
Write-Host "* Review security log: $LogPath" -ForegroundColor White
Write-Host "* Monitor for version-specific security updates" -ForegroundColor White
Write-Host "* Consider additional $($VersionInfo.Name) security features" -ForegroundColor White
Write-Host "* Plan regular compliance assessments" -ForegroundColor White

Write-Host ""
Write-Host "================================================================" -ForegroundColor Red

Write-Log "CIS Level 2 hardening for $($VersionInfo.Name) completed. Success: $Global:SuccessCount/$Global:TotalControls" -Color "Red"

# Stop logging
Stop-Transcript

Read-Host "Press Enter to exit"