#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CIS Security Assessment Tool for Windows Server 2019/2022
.DESCRIPTION
    Performs a comprehensive security assessment against CIS benchmarks
    without making any changes to the system. Provides detailed compliance
    reporting for Level 1, 2, and 3 controls.
.NOTES
    Author: Security Assessment Tool
    Version: 1.0
    Requires: Administrator privileges, PowerShell 5.1+
    Compatible: Windows Server 2019, Windows Server 2022
.EXAMPLE
    .\CIS-Security-Assessment.ps1
    Performs read-only security assessment
#>

# Script configuration
$ScriptVersion = "CIS Security Assessment v1.0"
$LogPath = "C:\Windows\Temp\CIS_Security_Assessment_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Start logging
Start-Transcript -Path $LogPath -Append

# Initialize assessment results
$AssessmentResults = @()
$Level1Compliant = 0
$Level2Compliant = 0
$Level3Compliant = 0
$Level1Total = 0
$Level2Total = 0
$Level3Total = 0

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

function Test-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$ExpectedValue,
        [string]$Description,
        [string]$Level
    )
    
    try {
        if (Test-Path $Path) {
            $CurrentValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if ($null -ne $CurrentValue -and $CurrentValue.$Name -eq $ExpectedValue) {
                $Status = "COMPLIANT"
                $Current = $CurrentValue.$Name
            } elseif ($null -ne $CurrentValue) {
                $Status = "NON_COMPLIANT"
                $Current = $CurrentValue.$Name
            } else {
                $Status = "NOT_SET"
                $Current = "Not Set"
            }
        } else {
            $Status = "PATH_NOT_FOUND"
            $Current = "Path Not Found"
        }
    }
    catch {
        $Status = "ERROR"
        $Current = "Error: $($_.Exception.Message)"
    }
    
    return @{
        Level = $Level
        Description = $Description
        Status = $Status
        Current = $Current
        Expected = $ExpectedValue
        Type = "Registry"
    }
}

function Test-ServiceStatus {
    param(
        [string]$ServiceName,
        [string]$ExpectedStatus,
        [string]$Description,
        [string]$Level
    )
    
    try {
        $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($Service) {
            if ($Service.Status -eq $ExpectedStatus) {
                $Status = "COMPLIANT"
            } else {
                $Status = "NON_COMPLIANT"
            }
            $Current = $Service.Status
        } else {
            $Status = "NOT_FOUND"
            $Current = "Service Not Found"
        }
    }
    catch {
        $Status = "ERROR"
        $Current = "Error: $($_.Exception.Message)"
    }
    
    return @{
        Level = $Level
        Description = $Description
        Status = $Status
        Current = $Current
        Expected = $ExpectedStatus
        Type = "Service"
    }
}

function Test-WindowsFeature {
    param(
        [string]$FeatureName,
        [string]$ExpectedState,
        [string]$Description,
        [string]$Level
    )
    
    try {
        $Feature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction SilentlyContinue
        if ($Feature) {
            if ($Feature.State -eq $ExpectedState) {
                $Status = "COMPLIANT"
            } else {
                $Status = "NON_COMPLIANT"
            }
            $Current = $Feature.State
        } else {
            $Status = "NOT_FOUND"
            $Current = "Feature Not Found"
        }
    }
    catch {
        $Status = "ERROR"
        $Current = "Error: $($_.Exception.Message)"
    }
    
    return @{
        Level = $Level
        Description = $Description
        Status = $Status
        Current = $Current
        Expected = $ExpectedState
        Type = "Feature"
    }
}

function Test-AuditPolicy {
    param(
        [string]$Category,
        [string]$ExpectedSetting,
        [string]$Description,
        [string]$Level
    )
    
    try {
        $AuditOutput = auditpol /get /category:$Category 2>$null
        if ($AuditOutput -like "*Success and Failure*" -and $ExpectedSetting -eq "Success and Failure") {
            $Status = "COMPLIANT"
            $Current = "Success and Failure"
        } elseif ($AuditOutput -like "*Success*" -and $ExpectedSetting -eq "Success") {
            $Status = "COMPLIANT"
            $Current = "Success"
        } elseif ($AuditOutput -like "*Failure*" -and $ExpectedSetting -eq "Failure") {
            $Status = "COMPLIANT"
            $Current = "Failure"
        } else {
            $Status = "NON_COMPLIANT"
            $Current = "Not Properly Configured"
        }
    }
    catch {
        $Status = "ERROR"
        $Current = "Error: $($_.Exception.Message)"
    }
    
    return @{
        Level = $Level
        Description = $Description
        Status = $Status
        Current = $Current
        Expected = $ExpectedSetting
        Type = "Audit Policy"
    }
}

# Display header
Clear-Host
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "           CIS Security Assessment Tool                        " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This tool performs a comprehensive read-only assessment of" -ForegroundColor White
Write-Host "your Windows Server security configuration against CIS" -ForegroundColor White
Write-Host "benchmarks Level 1, 2, and 3." -ForegroundColor White
Write-Host ""
Write-Host "No changes will be made to your system" -ForegroundColor Green
Write-Host "Detailed compliance report will be generated" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

Write-Log "Starting CIS Security Assessment" -Color "Cyan"

# ===============================
# CIS LEVEL 1 ASSESSMENTS
# ===============================
Write-Log "Assessing CIS Level 1 controls..." -Color "Yellow"

# Password Policy Assessments
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MinimumPasswordLength" -ExpectedValue 8 -Description "Minimum password length (8+ characters)" -Level "Level 1"
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "PasswordComplexity" -ExpectedValue 1 -Description "Password complexity requirements enabled" -Level "Level 1"
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "PasswordHistorySize" -ExpectedValue 12 -Description "Password history (12+ passwords)" -Level "Level 1"
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MaximumPasswordAge" -ExpectedValue 90 -Description "Maximum password age (90 days or less)" -Level "Level 1"
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MinimumPasswordAge" -ExpectedValue 1 -Description "Minimum password age (1+ days)" -Level "Level 1"

# Account Security
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ExpectedValue 1 -Description "User Account Control (UAC) enabled" -Level "Level 1"
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -ExpectedValue 1 -Description "UAC prompt for administrator operations" -Level "Level 1"
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -ExpectedValue 1 -Description "Blank password use restricted" -Level "Level 1"
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -ExpectedValue 0 -Description "Automatic administrator logon disabled" -Level "Level 1"

# Screen Saver Security
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaveActive" -ExpectedValue 1 -Description "Screen saver enabled" -Level "Level 1"
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -ExpectedValue 900 -Description "Screen saver timeout (15 minutes)" -Level "Level 1"
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -ExpectedValue 1 -Description "Password-protected screen saver" -Level "Level 1"

# Event Log Configuration
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "MaxSize" -ExpectedValue 67108864 -Description "Security log size (64MB minimum)" -Level "Level 1"
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application" -Name "MaxSize" -ExpectedValue 33554432 -Description "Application log size (32MB minimum)" -Level "Level 1"
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System" -Name "MaxSize" -ExpectedValue 33554432 -Description "System log size (32MB minimum)" -Level "Level 1"

# Audit Policies
$AssessmentResults += Test-AuditPolicy -Category "Account Logon" -ExpectedSetting "Success and Failure" -Description "Audit account logon events" -Level "Level 1"
$AssessmentResults += Test-AuditPolicy -Category "Account Management" -ExpectedSetting "Success and Failure" -Description "Audit account management" -Level "Level 1"
$AssessmentResults += Test-AuditPolicy -Category "Logon/Logoff" -ExpectedSetting "Success and Failure" -Description "Audit logon/logoff events" -Level "Level 1"
$AssessmentResults += Test-AuditPolicy -Category "System" -ExpectedSetting "Success and Failure" -Description "Audit system events" -Level "Level 1"

# ===============================
# CIS LEVEL 2 ASSESSMENTS
# ===============================
Write-Log "Assessing CIS Level 2 controls..." -Color "Yellow"

# Enhanced Password Policies
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MinimumPasswordLength" -ExpectedValue 14 -Description "Strong password length (14+ characters)" -Level "Level 2"
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MaximumPasswordAge" -ExpectedValue 60 -Description "Enhanced password age (60 days)" -Level "Level 2"
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "PasswordHistorySize" -ExpectedValue 24 -Description "Extended password history (24 passwords)" -Level "Level 2"

# SMB Security
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -ExpectedValue 1 -Description "SMB server signing required" -Level "Level 2"
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -ExpectedValue 1 -Description "SMB server signing enabled" -Level "Level 2"
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -ExpectedValue 1 -Description "SMB client signing required" -Level "Level 2"

# Network Security
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -ExpectedValue 1 -Description "Anonymous access restricted" -Level "Level 2"
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -ExpectedValue 1 -Description "Anonymous SAM access restricted" -Level "Level 2"
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -ExpectedValue 1 -Description "LM hash storage disabled" -Level "Level 2"
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ExpectedValue 5 -Description "NTLMv2 only authentication" -Level "Level 2"

# Enhanced UAC and AutoRun
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -ExpectedValue 2 -Description "Enhanced UAC prompt behavior" -Level "Level 2"
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -ExpectedValue 1 -Description "AutoRun disabled" -Level "Level 2"
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ExpectedValue 255 -Description "AutoPlay disabled for all drives" -Level "Level 2"

# Network Protocols
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ExpectedValue 0 -Description "LLMNR disabled" -Level "Level 2"
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NodeType" -ExpectedValue 2 -Description "NetBIOS over TCP/IP disabled" -Level "Level 2"

# Enhanced Auditing
$AssessmentResults += Test-AuditPolicy -Category "Detailed Tracking" -ExpectedSetting "Success and Failure" -Description "Audit detailed tracking" -Level "Level 2"
$AssessmentResults += Test-AuditPolicy -Category "Object Access" -ExpectedSetting "Success and Failure" -Description "Audit object access" -Level "Level 2"
$AssessmentResults += Test-AuditPolicy -Category "Policy Change" -ExpectedSetting "Success and Failure" -Description "Audit policy changes" -Level "Level 2"

# Services and Features
$AssessmentResults += Test-ServiceStatus -ServiceName "RemoteRegistry" -ExpectedStatus "Stopped" -Description "Remote Registry service stopped" -Level "Level 2"
$AssessmentResults += Test-WindowsFeature -FeatureName "SMB1Protocol" -ExpectedState "Disabled" -Description "SMBv1 protocol disabled" -Level "Level 2"

# ===============================
# CIS LEVEL 3 ASSESSMENTS
# ===============================
Write-Log "Assessing CIS Level 3 controls..." -Color "Yellow"

# Ultra-Strong Security
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MinimumPasswordLength" -ExpectedValue 20 -Description "Ultra-strong password length (20+ characters)" -Level "Level 3"
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MaximumPasswordAge" -ExpectedValue 30 -Description "Ultra-short password age (30 days)" -Level "Level 3"
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "PasswordHistorySize" -ExpectedValue 50 -Description "Maximum password history (50 passwords)" -Level "Level 3"

# Maximum Security Settings
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -ExpectedValue 2 -Description "Maximum anonymous restriction" -Level "Level 3"
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -ExpectedValue 0 -Description "Everyone excludes anonymous" -Level "Level 3"
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "AuditBaseObjects" -ExpectedValue 1 -Description "Audit base objects enabled" -Level "Level 3"
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "FullPrivilegeAuditing" -ExpectedValue 1 -Description "Full privilege auditing enabled" -Level "Level 3"

# Insecure Protocol Disabling
$InsecureProtocols = @(
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client"; Desc="SSL 2.0 Client disabled"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client"; Desc="SSL 3.0 Client disabled"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"; Desc="TLS 1.0 Client disabled"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"; Desc="TLS 1.1 Client disabled"}
)

foreach ($Protocol in $InsecureProtocols) {
    $AssessmentResults += Test-RegistryValue -Path $Protocol.Path -Name "Enabled" -ExpectedValue 0 -Description $Protocol.Desc -Level "Level 3"
}

# Maximum UAC Security
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -ExpectedValue 4 -Description "Maximum UAC security level" -Level "Level 3"
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ValidateAdminCodeSignatures" -ExpectedValue 1 -Description "Admin code signature validation" -Level "Level 3"
$AssessmentResults += Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableSecureUIAPaths" -ExpectedValue 1 -Description "Secure UIAP paths enabled" -Level "Level 3"

# Legacy Features
$AssessmentResults += Test-WindowsFeature -FeatureName "MicrosoftWindowsPowerShellV2Root" -ExpectedState "Disabled" -Description "PowerShell v2 disabled" -Level "Level 3"
$AssessmentResults += Test-WindowsFeature -FeatureName "TelnetClient" -ExpectedState "Disabled" -Description "Telnet client disabled" -Level "Level 3"
$AssessmentResults += Test-WindowsFeature -FeatureName "TFTP" -ExpectedState "Disabled" -Description "TFTP client disabled" -Level "Level 3"

# ===============================
# CALCULATE RESULTS
# ===============================
Write-Log "Calculating compliance statistics..." -Color "Yellow"

$Level1Results = $AssessmentResults | Where-Object {$_.Level -eq "Level 1"}
$Level2Results = $AssessmentResults | Where-Object {$_.Level -eq "Level 2"}
$Level3Results = $AssessmentResults | Where-Object {$_.Level -eq "Level 3"}

$Level1Total = $Level1Results.Count
$Level2Total = $Level2Results.Count
$Level3Total = $Level3Results.Count

$Level1Compliant = ($Level1Results | Where-Object {$_.Status -eq "COMPLIANT"}).Count
$Level2Compliant = ($Level2Results | Where-Object {$_.Status -eq "COMPLIANT"}).Count
$Level3Compliant = ($Level3Results | Where-Object {$_.Status -eq "COMPLIANT"}).Count

$Level1Percentage = if($Level1Total -gt 0) { [math]::Round(($Level1Compliant / $Level1Total) * 100, 2) } else { 0 }
$Level2Percentage = if($Level2Total -gt 0) { [math]::Round(($Level2Compliant / $Level2Total) * 100, 2) } else { 0 }
$Level3Percentage = if($Level3Total -gt 0) { [math]::Round(($Level3Compliant / $Level3Total) * 100, 2) } else { 0 }

$TotalCompliant = $Level1Compliant + $Level2Compliant + $Level3Compliant
$TotalAssessments = $Level1Total + $Level2Total + $Level3Total
$OverallPercentage = if($TotalAssessments -gt 0) { [math]::Round(($TotalCompliant / $TotalAssessments) * 100, 2) } else { 0 }

# ===============================
# DISPLAY RESULTS
# ===============================
Clear-Host
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "                CIS SECURITY ASSESSMENT REPORT                " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Assessment Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host "Server: $env:COMPUTERNAME" -ForegroundColor White
Write-Host "Domain: $env:USERDOMAIN" -ForegroundColor White
Write-Host ""

# Overall Summary
Write-Host "OVERALL COMPLIANCE SUMMARY" -ForegroundColor Cyan
Write-Host "-------------------------------------------------------------" -ForegroundColor Gray
Write-Host "Total Compliance: $OverallPercentage% ($TotalCompliant/$TotalAssessments)" -ForegroundColor $(if($OverallPercentage -ge 80){"Green"}elseif($OverallPercentage -ge 60){"Yellow"}else{"Red"})
Write-Host ""

# Level-by-Level Results
Write-Host "CIS LEVEL 1 (Basic Security)" -ForegroundColor Green
Write-Host "Compliance: $Level1Percentage% ($Level1Compliant/$Level1Total)" -ForegroundColor $(if($Level1Percentage -ge 80){"Green"}elseif($Level1Percentage -ge 60){"Yellow"}else{"Red"})
Write-Host ""

Write-Host "CIS LEVEL 2 (Advanced Security)" -ForegroundColor Yellow
Write-Host "Compliance: $Level2Percentage% ($Level2Compliant/$Level2Total)" -ForegroundColor $(if($Level2Percentage -ge 80){"Green"}elseif($Level2Percentage -ge 60){"Yellow"}else{"Red"})
Write-Host ""

Write-Host "CIS LEVEL 3 (Maximum Security)" -ForegroundColor Red
Write-Host "Compliance: $Level3Percentage% ($Level3Compliant/$Level3Total)" -ForegroundColor $(if($Level3Percentage -ge 80){"Green"}elseif($Level3Percentage -ge 60){"Yellow"}else{"Red"})
Write-Host ""

# Recommendations
Write-Host "RECOMMENDATIONS" -ForegroundColor Cyan
Write-Host "-------------------------------------------------------------" -ForegroundColor Gray

if ($Level1Percentage -lt 80) {
    Write-Host "Priority: Implement CIS Level 1 hardening" -ForegroundColor Red
    Write-Host "  Level 1 controls are essential for ALL environments" -ForegroundColor Yellow
}
elseif ($Level2Percentage -lt 80 -and $Level1Percentage -ge 80) {
    Write-Host "Good Level 1 compliance" -ForegroundColor Green
    Write-Host "Consider: CIS Level 2 hardening for enhanced security" -ForegroundColor Yellow
}
elseif ($Level3Percentage -lt 80 -and $Level2Percentage -ge 80) {
    Write-Host "Excellent Level 1 & 2 compliance" -ForegroundColor Green
    Write-Host "Optional: CIS Level 3 for maximum security (high impact)" -ForegroundColor Cyan
}
else {
    Write-Host "Outstanding security posture across all levels!" -ForegroundColor Green
}

Write-Host ""

# Failed Controls Summary
$FailedControls = $AssessmentResults | Where-Object {$_.Status -ne "COMPLIANT"}
if ($FailedControls.Count -gt 0) {
    Write-Host "NON-COMPLIANT CONTROLS ($($FailedControls.Count))" -ForegroundColor Red
    Write-Host "-------------------------------------------------------------" -ForegroundColor Gray
    
    $FailedByLevel = $FailedControls | Group-Object Level
    foreach ($LevelGroup in $FailedByLevel) {
        # Determine color based on level
        $LevelColor = "White"  # Default color
        if ($LevelGroup.Name -like "*1*") { $LevelColor = "Red" }
        elseif ($LevelGroup.Name -like "*2*") { $LevelColor = "Yellow" }
        elseif ($LevelGroup.Name -like "*3*") { $LevelColor = "Cyan" }
        
        Write-Host "$($LevelGroup.Name): $($LevelGroup.Count) issues" -ForegroundColor $LevelColor
        
        $LevelGroup.Group | Select-Object -First 3 | ForEach-Object {
            Write-Host "  * $($_.Description)" -ForegroundColor Gray
            Write-Host "    Current: $($_.Current) | Expected: $($_.Expected)" -ForegroundColor DarkGray
        }
        if ($LevelGroup.Count -gt 3) {
            Write-Host "  ... and $($LevelGroup.Count - 3) more items" -ForegroundColor DarkGray
        }
        Write-Host ""
    }
}

Write-Host "NEXT STEPS" -ForegroundColor Cyan
Write-Host "-------------------------------------------------------------" -ForegroundColor Gray
Write-Host "1. Review detailed log: $LogPath" -ForegroundColor White
Write-Host "2. Apply appropriate CIS hardening script:" -ForegroundColor White
Write-Host "   * CIS-Level1-Hardening.ps1 (recommended for all)" -ForegroundColor Gray
Write-Host "   * CIS-Level2-Hardening.ps1 (high-security environments)" -ForegroundColor Gray
Write-Host "   * CIS-Level3-Hardening.ps1 (maximum security, high impact)" -ForegroundColor Gray
Write-Host "3. Re-run this assessment after hardening" -ForegroundColor White
Write-Host "4. Implement regular security monitoring" -ForegroundColor White

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan

# Export detailed results
$ReportPath = "C:\Windows\Temp\CIS_Assessment_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$AssessmentResults | Export-Csv -Path $ReportPath -NoTypeInformation
Write-Log "Detailed report exported to: $ReportPath" -Color "Cyan"

Write-Log "CIS Security Assessment completed. Overall compliance: $OverallPercentage%" -Color "Cyan"

# Stop logging
Stop-Transcript

Read-Host "`nPress Enter to exit"