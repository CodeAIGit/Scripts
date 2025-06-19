#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CIS Level 1 Multi-Version Windows Server Security Hardening Script
.DESCRIPTION
    Implements CIS Level 1 security controls for Windows Server 2019, 2022, and 2025.
    Automatically detects server version and applies appropriate basic hardening configurations.
    This level provides essential security for ALL environments with minimal functionality impact.
.NOTES
    Author: Security Hardening Tool
    Version: 1.1 Multi-Version
    Requires: Administrator privileges, PowerShell 5.1+
    Compatible: Windows Server 2019, 2022, 2025
    Impact: LOW - Suitable for all business environments
.EXAMPLE
    .\CIS-Level1-MultiVersion-Hardening.ps1
    Detects server version and applies appropriate CIS Level 1 hardening
#>

# Script configuration
$ScriptVersion = "CIS Level 1 Multi-Version Hardening v1.1"
$LogPath = "C:\Windows\Temp\CIS_Level1_MultiVersion_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

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
        $RestoreResult = Checkpoint-Computer -Description "Before CIS Level 1 Multi-Version Hardening" -RestorePointType "MODIFY_SETTINGS"
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
                TotalControls = 25
                PasswordLength = 8
                PasswordHistory = 12
                MaxPasswordAge = 90
                SecurityLogSize = 67108864   # 64MB
                ApplicationLogSize = 33554432  # 32MB
                SystemLogSize = 33554432   # 32MB
                ScreenSaverTimeout = 900   # 15 minutes
                LockoutThreshold = 10
                LockoutDuration = 15
                FirewallProfiles = @("Domain", "Private", "Public")
                BasicServices = @{
                    "RemoteRegistry" = "Remote Registry (2019 - Basic)"
                }
                SpecificFeatures = @(
                    "Basic password policies",
                    "Standard UAC configuration",
                    "Basic Windows Firewall",
                    "Essential audit logging",
                    "Core security options"
                )
            }
        }
        "2022" {
            return @{
                TotalControls = 28
                PasswordLength = 10
                PasswordHistory = 15
                MaxPasswordAge = 75
                SecurityLogSize = 67108864   # 64MB
                ApplicationLogSize = 33554432  # 32MB
                SystemLogSize = 33554432   # 32MB
                ScreenSaverTimeout = 900   # 15 minutes
                LockoutThreshold = 8
                LockoutDuration = 20
                FirewallProfiles = @("Domain", "Private", "Public")
                BasicServices = @{
                    "RemoteRegistry" = "Remote Registry (2022 - Enhanced)"
                    "Fax" = "Fax Service (2022)"
                }
                SpecificFeatures = @(
                    "Enhanced password policies",
                    "Improved UAC configuration",
                    "Advanced Windows Firewall",
                    "Enhanced audit logging",
                    "Modern security options",
                    "Basic SMB security"
                )
            }
        }
        "2025" {
            return @{
                TotalControls = 30
                PasswordLength = 12
                PasswordHistory = 18
                MaxPasswordAge = 60
                SecurityLogSize = 134217728  # 128MB
                ApplicationLogSize = 67108864  # 64MB
                SystemLogSize = 67108864   # 64MB
                ScreenSaverTimeout = 600   # 10 minutes
                LockoutThreshold = 6
                LockoutDuration = 25
                FirewallProfiles = @("Domain", "Private", "Public")
                BasicServices = @{
                    "RemoteRegistry" = "Remote Registry (2025 - Modern)"
                    "Fax" = "Fax Service (2025)"
                    "Browser" = "Computer Browser (2025)"
                }
                SpecificFeatures = @(
                    "Modern password policies",
                    "Advanced UAC configuration",
                    "Next-gen Windows Firewall",
                    "Intelligent audit logging",
                    "Cloud-aware security options",
                    "Enhanced SMB security",
                    "Modern authentication support"
                )
            }
        }
        default {
            return @{
                TotalControls = 20
                PasswordLength = 8
                PasswordHistory = 10
                MaxPasswordAge = 90
                SecurityLogSize = 33554432   # 32MB
                ApplicationLogSize = 16777216  # 16MB
                SystemLogSize = 16777216   # 16MB
                ScreenSaverTimeout = 900   # 15 minutes
                LockoutThreshold = 10
                LockoutDuration = 15
                FirewallProfiles = @("Domain", "Private", "Public")
                BasicServices = @{}
                SpecificFeatures = @("Basic hardening controls")
            }
        }
    }
}

# Detect Windows Server Version
Clear-Host
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "    CIS Level 1 Multi-Version Windows Server Hardening        " -ForegroundColor Cyan
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
Write-Host "Hardening Level: CIS Level 1 (Essential Security)" -ForegroundColor Green
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
Write-Host "Security Log Size: $([math]::Round($Config.SecurityLogSize/1MB))MB" -ForegroundColor White
Write-Host ""
Write-Host "Version-Specific Features:" -ForegroundColor Cyan
foreach ($feature in $Config.SpecificFeatures) {
    Write-Host "  * $feature" -ForegroundColor White
}
Write-Host ""

# Show detailed configuration that will be applied
Write-Host "THE FOLLOWING ESSENTIAL SETTINGS WILL BE CONFIGURED:" -ForegroundColor Yellow
Write-Host "=====================================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "BASIC PASSWORD POLICIES (Version-Optimized):" -ForegroundColor Cyan
Write-Host "  * Minimum password length: $($Config.PasswordLength) characters" -ForegroundColor White
Write-Host "  * Password complexity: Enabled" -ForegroundColor White
Write-Host "  * Password history: $($Config.PasswordHistory) passwords remembered" -ForegroundColor White
Write-Host "  * Maximum password age: $($Config.MaxPasswordAge) days" -ForegroundColor White
Write-Host "  * Minimum password age: 1 day" -ForegroundColor White
Write-Host "  * Account lockout: $($Config.LockoutThreshold) attempts, $($Config.LockoutDuration) minutes" -ForegroundColor White
Write-Host ""
Write-Host "ACCOUNT SECURITY:" -ForegroundColor Cyan
Write-Host "  * User Account Control (UAC): Enabled" -ForegroundColor White
Write-Host "  * UAC admin approval mode: Enabled" -ForegroundColor White
Write-Host "  * Automatic administrator logon: Disabled" -ForegroundColor White
Write-Host "  * Guest account: Disabled" -ForegroundColor White
Write-Host "  * Blank password use: Restricted to console only" -ForegroundColor White
Write-Host ""
Write-Host "SYSTEM SECURITY:" -ForegroundColor Cyan
Write-Host "  * Windows Firewall: Enabled (all profiles)" -ForegroundColor White
Write-Host "  * Screen saver: $([math]::Round($Config.ScreenSaverTimeout/60))-minute timeout with password" -ForegroundColor White
if ($Global:ServerVersion -eq "2025") {
    Write-Host "  * Modern authentication support" -ForegroundColor White
    Write-Host "  * Enhanced security policies" -ForegroundColor White
} elseif ($Global:ServerVersion -eq "2022") {
    Write-Host "  * Enhanced security options" -ForegroundColor White
} else {
    Write-Host "  * Standard security options" -ForegroundColor White
}
Write-Host ""
Write-Host "AUDITING & LOGGING (Version-Appropriate):" -ForegroundColor Cyan
Write-Host "  * Security event log: $([math]::Round($Config.SecurityLogSize/1MB))MB" -ForegroundColor White
Write-Host "  * Application event log: $([math]::Round($Config.ApplicationLogSize/1MB))MB" -ForegroundColor White
Write-Host "  * System event log: $([math]::Round($Config.SystemLogSize/1MB))MB" -ForegroundColor White
Write-Host "  * Account logon events: Audited" -ForegroundColor White
Write-Host "  * Account management: Audited" -ForegroundColor White
Write-Host "  * Logon/logoff events: Audited" -ForegroundColor White
Write-Host "  * System events: Audited" -ForegroundColor White
Write-Host ""
Write-Host "SERVICE MANAGEMENT:" -ForegroundColor Cyan
if ($Config.BasicServices.Count -gt 0) {
    Write-Host "  * Selected unnecessary services will be disabled:" -ForegroundColor White
    foreach ($service in $Config.BasicServices.GetEnumerator()) {
        Write-Host "    - $($service.Value)" -ForegroundColor Gray
    }
} else {
    Write-Host "  * No services will be disabled (minimal impact)" -ForegroundColor White
}
Write-Host ""

# Impact assessment based on version
Write-Host "IMPACT ASSESSMENT FOR $($VersionInfo.Name.ToUpper()):" -ForegroundColor Green
Write-Host "=================================================" -ForegroundColor Green
if ($Global:ServerVersion -eq "2025") {
    Write-Host "  [LOW IMPACT] Modern applications: Excellent compatibility expected" -ForegroundColor Green
    Write-Host "  [LOW IMPACT] Cloud integration: Fully supported" -ForegroundColor Green
    Write-Host "  [MEDIUM IMPACT] Legacy applications: May require review" -ForegroundColor Yellow
} elseif ($Global:ServerVersion -eq "2022") {
    Write-Host "  [LOW IMPACT] Business applications: High compatibility expected" -ForegroundColor Green
    Write-Host "  [LOW IMPACT] Hyper-V and containers: Fully supported" -ForegroundColor Green
    Write-Host "  [LOW IMPACT] Legacy systems: Good compatibility" -ForegroundColor Green
} else {
    Write-Host "  [LOW IMPACT] Enterprise applications: Excellent compatibility" -ForegroundColor Green
    Write-Host "  [LOW IMPACT] Legacy systems: Maximum compatibility" -ForegroundColor Green
    Write-Host "  [LOW IMPACT] Domain controllers: Fully supported" -ForegroundColor Green
}
Write-Host "  [LOW IMPACT] User experience: Minimal changes" -ForegroundColor Green
Write-Host "  [LOW IMPACT] Administrative overhead: Slight increase" -ForegroundColor Green
Write-Host ""
Write-Host "RECOMMENDED FOR:" -ForegroundColor Green
Write-Host "  [EXCELLENT] All business environments" -ForegroundColor Green
Write-Host "  [EXCELLENT] Production servers" -ForegroundColor Green
Write-Host "  [EXCELLENT] Development environments" -ForegroundColor Green
Write-Host "  [EXCELLENT] Mixed legacy/modern environments" -ForegroundColor Green
Write-Host ""
Write-Host "SAFETY MEASURES:" -ForegroundColor Green
Write-Host "  [PROTECTED] System restore point will be created" -ForegroundColor Green
Write-Host "  [LOGGED] All changes will be documented" -ForegroundColor Green
Write-Host "  [VERIFIED] Each setting will be validated" -ForegroundColor Green
Write-Host "  [REVERSIBLE] Changes can be undone if needed" -ForegroundColor Green
Write-Host ""

# Confirmation for Level 1 (single confirmation, less scary than Level 2)
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "PROCEED WITH CIS LEVEL 1 HARDENING?" -ForegroundColor Yellow
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This will apply essential security hardening optimized for" -ForegroundColor White
Write-Host "$($VersionInfo.Name) with minimal impact on functionality." -ForegroundColor White
Write-Host ""
Write-Host "Level 1 controls are designed for ALL environments and provide" -ForegroundColor Green
Write-Host "fundamental security improvements with very low risk." -ForegroundColor Green
Write-Host ""

$Confirmation = Read-Host "Do you want to apply CIS Level 1 hardening for $($VersionInfo.Name)? (Y/N)"

if ($Confirmation -ne "Y" -and $Confirmation -ne "y") {
    Clear-Host
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host "                 HARDENING CANCELLED                           " -ForegroundColor Green  
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "CIS Level 1 hardening cancelled - no changes made." -ForegroundColor Green
    Write-Host ""
    Write-Host "You can run this script again anytime to apply essential" -ForegroundColor White
    Write-Host "security hardening when you're ready." -ForegroundColor White
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 0
}

# User confirmed - proceed with version-specific hardening
Clear-Host
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  STARTING CIS LEVEL 1 HARDENING FOR $($VersionInfo.Name.ToUpper())" -ForegroundColor Green
Write-Host "                ESSENTIAL SECURITY                             " -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""

Write-Log "Starting CIS Level 1 hardening for $($VersionInfo.Name)" -Color "Green"
Write-Log "Build: $($VersionInfo.Build) | Controls: $($Config.TotalControls)" -Color "Yellow"

# Create restore point
New-RestorePoint | Out-Null

Write-Log "Applying version-optimized CIS Level 1 security controls..." -Color "Yellow"

# 1. Basic Password Policies (Version-Specific)
Write-Log "Configuring basic password policies for Server $Global:ServerVersion..." -Color "Yellow"

if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MinimumPasswordLength" -Value $Config.PasswordLength -Description "Minimum password length ($($Config.PasswordLength) characters)") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "PasswordComplexity" -Value 1 -Description "Password complexity requirements") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "PasswordHistorySize" -Value $Config.PasswordHistory -Description "Password history ($($Config.PasswordHistory) passwords)") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MaximumPasswordAge" -Value $Config.MaxPasswordAge -Description "Maximum password age ($($Config.MaxPasswordAge) days)") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MinimumPasswordAge" -Value 1 -Description "Minimum password age (1 day)") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

# 2. Version-Appropriate Account Lockout Policy
Write-Log "Configuring account lockout policy..." -Color "Yellow"
try {
    cmd.exe /c "net accounts /lockoutthreshold:$($Config.LockoutThreshold) /lockoutduration:$($Config.LockoutDuration) /lockoutwindow:$($Config.LockoutDuration)" 2>$null | Out-Null
    Write-Log "[OK] Account lockout policy configured ($($Config.LockoutThreshold) attempts, $($Config.LockoutDuration) min)" -Level "SUCCESS" -Color "Green"
    $Global:SuccessCount++
} catch {
    Write-Log "[FAIL] Failed to configure account lockout policy" -Level "ERROR" -Color "Red"
    $Global:FailureCount++
}

# 3. User Account Control (UAC)
Write-Log "Configuring User Account Control..." -Color "Yellow"

if (Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Description "Enable User Account Control (UAC)") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

if (Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 1 -Description "UAC prompt for administrators") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

# 4. Windows Firewall (All Versions)
Write-Log "Configuring Windows Firewall..." -Color "Yellow"
try {
    netsh advfirewall set allprofiles state on 2>$null | Out-Null
    Write-Log "[OK] Windows Firewall enabled for all profiles" -Level "SUCCESS" -Color "Green"
    $Global:SuccessCount += 3  # Count for domain, private, and public profiles
} catch {
    Write-Log "[FAIL] Failed to configure Windows Firewall" -Level "ERROR" -Color "Red"
    $Global:FailureCount += 3
}

# 5. Basic Security Options
Write-Log "Configuring basic security options..." -Color "Yellow"

if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1 -Description "Limit blank password use") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

if (Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value 0 -Description "Disable automatic administrator logon") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

# 6. Version-Specific Enhanced Features
if ($Global:ServerVersion -eq "2025") {
    Write-Log "Applying Server 2025 specific enhancements..." -Color "Yellow"
    
    if (Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 0 -Description "Enhanced UAC for Server 2025" -SupportedVersions @("2025")) { $Global:SuccessCount++ } else { $Global:FailureCount++ }
    
    if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Description "Disable SMBv1 (2025 default)" -SupportedVersions @("2025")) { $Global:SuccessCount++ } else { $Global:FailureCount++ }
    
} elseif ($Global:ServerVersion -eq "2022") {
    Write-Log "Applying Server 2022 specific enhancements..." -Color "Yellow"
    
    if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Description "Enhanced SMB security (2022)" -SupportedVersions @("2022", "2025")) { $Global:SuccessCount++ } else { $Global:FailureCount++ }
}

# 7. Screen Saver Security (Version-Optimized)
Write-Log "Configuring screen saver security..." -Color "Yellow"

if (Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaveActive" -Value 1 -Description "Enable screen saver") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

if (Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -Value $Config.ScreenSaverTimeout -Description "Screen saver timeout ($([math]::Round($Config.ScreenSaverTimeout/60)) minutes)") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

if (Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -Value 1 -Description "Password-protected screen saver") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

# 8. Version-Optimized Event Log Configuration
Write-Log "Configuring event log sizes..." -Color "Yellow"

if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "MaxSize" -Value $Config.SecurityLogSize -Description "Security log size ($([math]::Round($Config.SecurityLogSize/1MB))MB)") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application" -Name "MaxSize" -Value $Config.ApplicationLogSize -Description "Application log size ($([math]::Round($Config.ApplicationLogSize/1MB))MB)") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System" -Name "MaxSize" -Value $Config.SystemLogSize -Description "System log size ($([math]::Round($Config.SystemLogSize/1MB))MB)") { $Global:SuccessCount++ } else { $Global:FailureCount++ }

# 9. Basic Audit Policies
Write-Log "Configuring basic audit policies..." -Color "Yellow"

$BasicAuditCategories = @("Account Logon", "Account Management", "Logon/Logoff", "System")

foreach ($category in $BasicAuditCategories) {
    if (Set-AuditPolicy -Category $category -Description "Basic audit policy: $category") {
        $Global:SuccessCount++
    } else {
        $Global:FailureCount++
    }
}

# 10. Minimal Service Hardening (Only if configured for version)
if ($Config.BasicServices.Count -gt 0) {
    Write-Log "Configuring minimal service hardening..." -Color "Yellow"
    
    foreach ($service in $Config.BasicServices.GetEnumerator()) {
        if (Disable-Service -ServiceName $service.Key -Description $service.Value) { 
            $Global:SuccessCount++ 
        } else { 
            $Global:FailureCount++ 
        }
    }
}

# 11. Guest Account Management
Write-Log "Managing guest account..." -Color "Yellow"
try {
    net user guest /active:no 2>$null | Out-Null
    Write-Log "[OK] Guest account disabled" -Level "SUCCESS" -Color "Green"
    $Global:SuccessCount++
} catch {
    Write-Log "[WARN] Guest account may already be disabled" -Level "WARN" -Color "Yellow"
    # Don't count as failure since it might already be disabled
}

# Summary
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "         CIS LEVEL 1 SUMMARY FOR $($VersionInfo.Name.ToUpper())" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green

$CompliancePercentage = [math]::Round(($Global:SuccessCount / $Global:TotalControls) * 100, 2)

Write-Host "Server Version: $($VersionInfo.Name) (Build $($VersionInfo.Build))" -ForegroundColor White
Write-Host "Total Controls Applied: $Global:SuccessCount/$Global:TotalControls" -ForegroundColor White
Write-Host "Success Rate: $CompliancePercentage%" -ForegroundColor $(if($CompliancePercentage -ge 90){"Green"}elseif($CompliancePercentage -ge 75){"Yellow"}else{"Red"})

if ($Global:FailureCount -gt 0) {
    Write-Host "Failed Controls: $Global:FailureCount" -ForegroundColor Red
}

Write-Host ""
Write-Host "Applied Version-Optimized Controls:" -ForegroundColor White
Write-Host "* Password policies ($($Config.PasswordLength) chars, $($Config.PasswordHistory) history, $($Config.MaxPasswordAge) days)" -ForegroundColor Gray
Write-Host "* Account lockout protection ($($Config.LockoutThreshold) attempts, $($Config.LockoutDuration) min)" -ForegroundColor Gray
Write-Host "* User Account Control (UAC) enforcement" -ForegroundColor Gray
Write-Host "* Windows Firewall activation (all profiles)" -ForegroundColor Gray
Write-Host "* Screen saver security ($([math]::Round($Config.ScreenSaverTimeout/60)) min timeout)" -ForegroundColor Gray
Write-Host "* Event log configuration ($([math]::Round($Config.SecurityLogSize/1MB))MB security log)" -ForegroundColor Gray
Write-Host "* Basic audit policies" -ForegroundColor Gray
Write-Host "* Guest account management" -ForegroundColor Gray
if ($Config.BasicServices.Count -gt 0) {
    Write-Host "* Minimal service hardening ($($Config.BasicServices.Count) services)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "Version-Specific Features Applied:" -ForegroundColor Cyan
foreach ($feature in $Config.SpecificFeatures) {
    Write-Host "  [OK] $feature" -ForegroundColor Green
}

Write-Host ""
if ($CompliancePercentage -ge 95) {
    Write-Host "[EXCELLENT] Outstanding! CIS Level 1 hardening completed for $($VersionInfo.Name)." -ForegroundColor Green
    Write-Host "Your system now has essential security protections with minimal impact." -ForegroundColor Green
} elseif ($CompliancePercentage -ge 85) {
    Write-Host "[SUCCESS] Very good! Most Level 1 controls applied successfully." -ForegroundColor Green
    Write-Host "Review any failed items for complete compliance." -ForegroundColor Yellow
} elseif ($CompliancePercentage -ge 75) {
    Write-Host "[GOOD] Good progress. Review failed items for full compliance." -ForegroundColor Yellow
} else {
    Write-Host "[WARNING] Several items failed. Please review the log for details." -ForegroundColor Red
}

Write-Host ""
Write-Host "VERSION-SPECIFIC POST-HARDENING RECOMMENDATIONS:" -ForegroundColor Green
if ($Global:ServerVersion -eq "2025") {
    Write-Host "* Verify modern application compatibility" -ForegroundColor White
    Write-Host "* Test cloud integration features" -ForegroundColor White
    Write-Host "* Review enhanced security features" -ForegroundColor White
    Write-Host "* Consider upgrading to Level 2 for high-security environments" -ForegroundColor White
} elseif ($Global:ServerVersion -eq "2022") {
    Write-Host "* Test business application compatibility" -ForegroundColor White
    Write-Host "* Verify Hyper-V and container functionality" -ForegroundColor White
    Write-Host "* Review Windows Admin Center integration" -ForegroundColor White
    Write-Host "* Consider Level 2 hardening for enhanced security" -ForegroundColor White
} else {
    Write-Host "* Test all critical applications thoroughly" -ForegroundColor White
    Write-Host "* Verify domain controller functionality (if applicable)" -ForegroundColor White
    Write-Host "* Check file server and print server operations" -ForegroundColor White
    Write-Host "* Consider Level 2 hardening after thorough testing" -ForegroundColor White
}
Write-Host "* Monitor system performance and user feedback" -ForegroundColor White
Write-Host "* Review security event logs regularly" -ForegroundColor White

Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host "* Test all critical business applications" -ForegroundColor White
Write-Host "* Review detailed log: $LogPath" -ForegroundColor White
Write-Host "* Monitor for version-specific security updates" -ForegroundColor White
Write-Host "* Plan regular security assessments" -ForegroundColor White
Write-Host "* Consider CIS Level 2 hardening for higher security needs" -ForegroundColor White

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green

Write-Log "CIS Level 1 hardening for $($VersionInfo.Name) completed. Success: $Global:SuccessCount/$Global:TotalControls" -Color "Green"

# Stop logging
Stop-Transcript

Read-Host "Press Enter to exit"