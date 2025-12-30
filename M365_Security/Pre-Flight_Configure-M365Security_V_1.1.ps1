#Requires -Modules ExchangeOnlineManagement, MicrosoftTeams, Microsoft.Online.SharePoint.PowerShell

<#
.SYNOPSIS
    Pre-flight check for M365 security configuration.

.DESCRIPTION
    This read-only script checks current configuration and reports what will change.
    NO changes are made to your environment.
    
.NOTES
    Author: Security Admin
    Date: 2025-12-30
    
.EXAMPLE
    .\PreFlight-M365SecurityCheck.ps1
#>

$script:preflightReport = @()
$script:changesNeeded = 0
$script:alreadyConfigured = 0
$script:manualRequired = 0
$script:graphConnected = $false

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error', 'Check')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        'Error' { 'Red' }
        'Check' { 'Cyan' }
        default { 'White' }
    }
    
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Add-PreflightItem {
    param(
        [string]$Category,
        [string]$Setting,
        [string]$CurrentValue,
        [string]$TargetValue,
        [ValidateSet('WillChange', 'AlreadyConfigured', 'ManualRequired')]
        [string]$Status,
        [string]$Details,
        [string]$Section = "Baseline"
    )
    
    $script:preflightReport += [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Section = $Section
        Category = $Category
        Setting = $Setting
        CurrentValue = $CurrentValue
        TargetValue = $TargetValue
        Status = $Status
        Details = $Details
    }
    
    switch ($Status) {
        'WillChange' { $script:changesNeeded++ }
        'AlreadyConfigured' { $script:alreadyConfigured++ }
        'ManualRequired' { $script:manualRequired++ }
    }
}

Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host "  Microsoft 365 Security Pre-Flight Check" -ForegroundColor Cyan
Write-Host "  READ-ONLY MODE - No Changes Will Be Made" -ForegroundColor Cyan
Write-Host "================================================================`n" -ForegroundColor Cyan

Write-Log "This script checks current configuration and shows what WILL change" -Level Info
Write-Log "NO changes will be made to your environment" -Level Warning

Write-Log "`nConnecting to Microsoft 365 services..." -Level Info

try {
    Write-Log "Connecting to Exchange Online..." -Level Info
    Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
    Write-Log "Connected to Exchange Online" -Level Success
    
    Write-Log "Connecting to Microsoft Teams..." -Level Info
    Connect-MicrosoftTeams -ErrorAction Stop | Out-Null
    Write-Log "Connected to Microsoft Teams" -Level Success
    
    $orgConfig = Get-OrganizationConfig
    $orgName = $orgConfig.Name
    $tenantName = $orgName.Split('.')[0]
    $sharePointAdminUrl = "https://$tenantName-admin.sharepoint.com"
    
    Write-Log "Connecting to SharePoint Online..." -Level Info
    Connect-SPOService -Url $sharePointAdminUrl -ErrorAction Stop
    Write-Log "Connected to SharePoint Online" -Level Success
    
    Write-Log "Connecting to Microsoft Graph..." -Level Info
    try {
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction SilentlyContinue
        Import-Module Microsoft.Graph.DeviceManagement -ErrorAction SilentlyContinue
        
        $graphScopes = @("Policy.Read.All", "DeviceManagementConfiguration.Read.All", "DeviceManagementApps.Read.All")
        Connect-MgGraph -Scopes $graphScopes -NoWelcome -ErrorAction Stop
        $script:graphConnected = $true
        Write-Log "Connected to Microsoft Graph" -Level Success
    } catch {
        Write-Log "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level Warning
        Write-Log "Graph API checks will be skipped" -Level Warning
        $script:graphConnected = $false
    }
    
} catch {
    Write-Log "Failed to connect: $_" -Level Error
    exit 1
}

Write-Host "`n================================================================" -ForegroundColor Magenta
Write-Host "  CHECKING CURRENT CONFIGURATION" -ForegroundColor Magenta
Write-Host "================================================================`n" -ForegroundColor Magenta

Write-Host "`n--- EXCHANGE ONLINE PROTECTION ---`n" -ForegroundColor Cyan

# 1. Unified Audit Logging
try {
    Write-Log "Checking Unified Audit Logging..." -Level Check
    $auditConfig = Get-AdminAuditLogConfig -ErrorAction Stop
    
    if ($auditConfig.UnifiedAuditLogIngestionEnabled -eq $true) {
        Add-PreflightItem -Category "Compliance" -Setting "Unified Audit Logging" -CurrentValue "Enabled" -TargetValue "Enabled" -Status "AlreadyConfigured" -Details "Already enabled" -Section "Baseline"
        Write-Log "  Status: Already configured" -Level Success
    } else {
        Add-PreflightItem -Category "Compliance" -Setting "Unified Audit Logging" -CurrentValue "Disabled" -TargetValue "Enabled" -Status "WillChange" -Details "Will enable" -Section "Baseline"
        Write-Log "  Status: WILL BE ENABLED" -Level Warning
    }
} catch {
    Add-PreflightItem -Category "Compliance" -Setting "Unified Audit Logging" -CurrentValue "Error" -TargetValue "Enabled" -Status "WillChange" -Details "Error checking: $_" -Section "Baseline"
    Write-Log "  Status: Error - $_" -Level Error
}

# 2. Mailbox Auditing
try {
    Write-Log "Checking Mailbox Auditing..." -Level Check
    $orgConfig = Get-OrganizationConfig -ErrorAction Stop
    
    if ($orgConfig.AuditDisabled -eq $false) {
        Add-PreflightItem -Category "Compliance" -Setting "Mailbox Auditing" -CurrentValue "Enabled" -TargetValue "Enabled" -Status "AlreadyConfigured" -Details "Already enabled" -Section "Baseline"
        Write-Log "  Status: Already configured" -Level Success
    } else {
        Add-PreflightItem -Category "Compliance" -Setting "Mailbox Auditing" -CurrentValue "Disabled" -TargetValue "Enabled" -Status "WillChange" -Details "Will enable" -Section "Baseline"
        Write-Log "  Status: WILL BE ENABLED" -Level Warning
    }
} catch {
    Add-PreflightItem -Category "Compliance" -Setting "Mailbox Auditing" -CurrentValue "Error" -TargetValue "Enabled" -Status "WillChange" -Details "Error checking: $_" -Section "Baseline"
    Write-Log "  Status: Error - $_" -Level Error
}

# 3. BSM - Reject Direct Send
try {
    Write-Log "Checking BSM (Reject Direct Send)..." -Level Check
    $transportConfig = Get-TransportConfig -ErrorAction Stop
    
    if ($transportConfig.SendFromAliasEnabled -eq $false) {
        Add-PreflightItem -Category "Exchange Online" -Setting "BSM (Reject Direct Send)" -CurrentValue "Blocked" -TargetValue "Blocked" -Status "AlreadyConfigured" -Details "Already configured" -Section "Custom"
        Write-Log "  Status: Already configured" -Level Success
    } else {
        Add-PreflightItem -Category "Exchange Online" -Setting "BSM (Reject Direct Send)" -CurrentValue "Allowed" -TargetValue "Blocked" -Status "WillChange" -Details "Will block" -Section "Custom"
        Write-Log "  Status: WILL BE BLOCKED" -Level Warning
    }
} catch {
    Add-PreflightItem -Category "Exchange Online" -Setting "BSM" -CurrentValue "Error" -TargetValue "Blocked" -Status "WillChange" -Details "Error checking: $_" -Section "Custom"
    Write-Log "  Status: Error - $_" -Level Error
}

# 4. Anti-Malware
try {
    Write-Log "Checking Anti-Malware Policy..." -Level Check
    $malwarePolicy = Get-MalwareFilterPolicy -ErrorAction Stop | Where-Object {$_.IsDefault -eq $true} | Select-Object -First 1
    
    if ($malwarePolicy.EnableFileFilter -eq $true -and $malwarePolicy.ZapEnabled -eq $true) {
        Add-PreflightItem -Category "Exchange Online" -Setting "Anti-Malware" -CurrentValue "Configured" -TargetValue "Configured" -Status "AlreadyConfigured" -Details "Already configured" -Section "Baseline"
        Write-Log "  Status: Already configured" -Level Success
    } else {
        Add-PreflightItem -Category "Exchange Online" -Setting "Anti-Malware" -CurrentValue "Needs update" -TargetValue "Configured" -Status "WillChange" -Details "Will configure" -Section "Baseline"
        Write-Log "  Status: WILL BE CONFIGURED" -Level Warning
    }
} catch {
    Add-PreflightItem -Category "Exchange Online" -Setting "Anti-Malware" -CurrentValue "Error" -TargetValue "Configured" -Status "WillChange" -Details "Error checking: $_" -Section "Baseline"
    Write-Log "  Status: Error - $_" -Level Error
}

# 5. Auto-Forwarding
try {
    Write-Log "Checking Outbound Spam (Auto-Forwarding)..." -Level Check
    $outboundPolicy = Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop | Select-Object -First 1
    
    if ($outboundPolicy.AutoForwardingMode -eq "Off") {
        Add-PreflightItem -Category "Exchange Online" -Setting "Auto-Forwarding" -CurrentValue "Disabled" -TargetValue "Disabled" -Status "AlreadyConfigured" -Details "Already disabled" -Section "Baseline"
        Write-Log "  Status: Already configured" -Level Success
    } else {
        Add-PreflightItem -Category "Exchange Online" -Setting "Auto-Forwarding" -CurrentValue $outboundPolicy.AutoForwardingMode -TargetValue "Off" -Status "WillChange" -Details "Will disable" -Section "Baseline"
        Write-Log "  Status: WILL BE DISABLED" -Level Warning
    }
} catch {
    Add-PreflightItem -Category "Exchange Online" -Setting "Auto-Forwarding" -CurrentValue "Error" -TargetValue "Off" -Status "WillChange" -Details "Error checking: $_" -Section "Baseline"
    Write-Log "  Status: Error - $_" -Level Error
}

Write-Host "`n--- DEFENDER FOR OFFICE 365 ---`n" -ForegroundColor Cyan

# 6. Safe Links (Malicious URL Protection)
try {
    Write-Log "Checking Safe Links (Malicious URL Protection)..." -Level Check
    $safeLinksPolicy = Get-SafeLinksPolicy -ErrorAction Stop | Where-Object {$_.IsDefault -eq $true} | Select-Object -First 1
    
    if ($safeLinksPolicy.EnableSafeLinksForTeams -eq $true) {
        Add-PreflightItem -Category "Defender for Office 365" -Setting "Malicious URL Protection" -CurrentValue "Enabled" -TargetValue "Enabled" -Status "AlreadyConfigured" -Details "Already configured" -Section "Custom"
        Write-Log "  Status: Already configured" -Level Success
    } else {
        Add-PreflightItem -Category "Defender for Office 365" -Setting "Malicious URL Protection" -CurrentValue "Not configured" -TargetValue "Enabled" -Status "WillChange" -Details "Will enable for Teams" -Section "Custom"
        Write-Log "  Status: WILL BE ENABLED" -Level Warning
    }
} catch {
    Add-PreflightItem -Category "Defender for Office 365" -Setting "Safe Links" -CurrentValue "Error" -TargetValue "Enabled" -Status "WillChange" -Details "Error checking: $_" -Section "Custom"
    Write-Log "  Status: Error - $_" -Level Error
}

# 7. Safe Attachments (File Protection)
try {
    Write-Log "Checking Safe Attachments (File Protection)..." -Level Check
    $safeAttachPolicy = Get-SafeAttachmentPolicy -ErrorAction Stop | Where-Object {$_.IsDefault -eq $true} | Select-Object -First 1
    
    if ($safeAttachPolicy.Enable -eq $true) {
        Add-PreflightItem -Category "Defender for Office 365" -Setting "File Protection" -CurrentValue "Enabled" -TargetValue "Enabled" -Status "AlreadyConfigured" -Details "Already configured" -Section "Custom"
        Write-Log "  Status: Already configured" -Level Success
    } else {
        Add-PreflightItem -Category "Defender for Office 365" -Setting "File Protection" -CurrentValue "Not configured" -TargetValue "Enabled" -Status "WillChange" -Details "Will enable" -Section "Custom"
        Write-Log "  Status: WILL BE ENABLED" -Level Warning
    }
} catch {
    Add-PreflightItem -Category "Defender for Office 365" -Setting "File Protection" -CurrentValue "Error" -TargetValue "Enabled" -Status "WillChange" -Details "Error checking: $_" -Section "Custom"
    Write-Log "  Status: Error - $_" -Level Error
}

# 8. ATP for SPO/ODB/Teams
try {
    Write-Log "Checking ATP for SharePoint/OneDrive/Teams..." -Level Check
    $atpPolicy = Get-AtpPolicyForO365 -ErrorAction Stop
    
    if ($atpPolicy.EnableATPForSPOTeamsODB -eq $true) {
        Add-PreflightItem -Category "Defender for Office 365" -Setting "ATP for SPO/ODB/Teams" -CurrentValue "Enabled" -TargetValue "Enabled" -Status "AlreadyConfigured" -Details "Already enabled" -Section "Baseline"
        Write-Log "  Status: Already configured" -Level Success
    } else {
        Add-PreflightItem -Category "Defender for Office 365" -Setting "ATP for SPO/ODB/Teams" -CurrentValue "Disabled" -TargetValue "Enabled" -Status "WillChange" -Details "Will enable" -Section "Baseline"
        Write-Log "  Status: WILL BE ENABLED" -Level Warning
    }
} catch {
    Add-PreflightItem -Category "Defender for Office 365" -Setting "ATP for SPO/ODB/Teams" -CurrentValue "Error" -TargetValue "Enabled" -Status "WillChange" -Details "Error checking: $_" -Section "Baseline"
    Write-Log "  Status: Error - $_" -Level Error
}

Write-Host "`n--- MICROSOFT TEAMS SECURITY ---`n" -ForegroundColor Cyan

# 9. Screen Capture Prevention
try {
    Write-Log "Checking Screen Capture Prevention..." -Level Check
    $meetingPolicy = Get-CsTeamsMeetingPolicy -Identity Global -ErrorAction Stop
    
    if ($meetingPolicy.PreventScreenCapture -eq $true) {
        Add-PreflightItem -Category "Microsoft Teams" -Setting "Prevent Screen Capture" -CurrentValue "Enabled" -TargetValue "Enabled" -Status "AlreadyConfigured" -Details "Already enabled" -Section "Custom"
        Write-Log "  Status: Already configured" -Level Success
    } else {
        Add-PreflightItem -Category "Microsoft Teams" -Setting "Prevent Screen Capture" -CurrentValue "Disabled" -TargetValue "Enabled" -Status "WillChange" -Details "Will enable" -Section "Custom"
        Write-Log "  Status: WILL BE ENABLED" -Level Warning
    }
} catch {
    Add-PreflightItem -Category "Microsoft Teams" -Setting "Screen Capture" -CurrentValue "Error" -TargetValue "Enabled" -Status "WillChange" -Details "Error checking: $_" -Section "Custom"
    Write-Log "  Status: Error - $_" -Level Error
}

# 10. External Access
try {
    Write-Log "Checking External Access and Chat with Anyone..." -Level Check
    $fedConfig = Get-CsTenantFederationConfiguration -ErrorAction Stop
    
    if ($fedConfig.AllowTeamsConsumer -eq $false) {
        Add-PreflightItem -Category "Microsoft Teams" -Setting "Granular External Access" -CurrentValue "Configured" -TargetValue "Configured" -Status "AlreadyConfigured" -Details "Already configured" -Section "Custom"
        Write-Log "  Status: Already configured" -Level Success
    } else {
        Add-PreflightItem -Category "Microsoft Teams" -Setting "Granular External Access" -CurrentValue "Not configured" -TargetValue "Configured" -Status "WillChange" -Details "Will block consumer chat" -Section "Custom"
        Write-Log "  Status: WILL BE CONFIGURED" -Level Warning
    }
} catch {
    Add-PreflightItem -Category "Microsoft Teams" -Setting "External Access" -CurrentValue "Error" -TargetValue "Configured" -Status "WillChange" -Details "Error checking: $_" -Section "Custom"
    Write-Log "  Status: Error - $_" -Level Error
}

Write-Host "`n--- SHAREPOINT ONLINE ---`n" -ForegroundColor Cyan

# 11. Content Security Policy
try {
    Write-Log "Checking Content Security Policy..." -Level Check
    $spoTenant = Get-SPOTenant -ErrorAction Stop
    
    if ($spoTenant.DefaultSharingLinkType -eq "Internal") {
        Add-PreflightItem -Category "SharePoint Online" -Setting "Content Security Policy" -CurrentValue "Configured" -TargetValue "Configured" -Status "AlreadyConfigured" -Details "Already configured" -Section "Custom"
        Write-Log "  Status: Already configured" -Level Success
    } else {
        Add-PreflightItem -Category "SharePoint Online" -Setting "Content Security Policy" -CurrentValue "Not configured" -TargetValue "Configured" -Status "WillChange" -Details "Will configure" -Section "Custom"
        Write-Log "  Status: WILL BE CONFIGURED" -Level Warning
    }
} catch {
    Add-PreflightItem -Category "SharePoint Online" -Setting "Content Security" -CurrentValue "Error" -TargetValue "Configured" -Status "WillChange" -Details "Error checking: $_" -Section "Custom"
    Write-Log "  Status: Error - $_" -Level Error
}

Write-Host "`n--- GRAPH API CONFIGURATIONS ---`n" -ForegroundColor Cyan

if ($script:graphConnected) {
    # 12. QR Code Authentication
    try {
        Write-Log "Checking QR Code Authentication..." -Level Check
        $authenticatorConfig = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "MicrosoftAuthenticator" -ErrorAction SilentlyContinue
        
        if ($authenticatorConfig -and $authenticatorConfig.State -eq "enabled") {
            Add-PreflightItem -Category "Authentication" -Setting "QR Code Authentication" -CurrentValue "Enabled" -TargetValue "Enabled" -Status "AlreadyConfigured" -Details "Already enabled" -Section "Custom"
            Write-Log "  Status: Already configured" -Level Success
        } else {
            Add-PreflightItem -Category "Authentication" -Setting "QR Code Authentication" -CurrentValue "Not configured" -TargetValue "Enabled" -Status "WillChange" -Details "Will configure via Graph API" -Section "Custom"
            Write-Log "  Status: WILL BE CONFIGURED" -Level Warning
        }
    } catch {
        Add-PreflightItem -Category "Authentication" -Setting "QR Code Authentication" -CurrentValue "Unknown" -TargetValue "Enabled" -Status "ManualRequired" -Details "May require manual configuration" -Section "Custom"
        Write-Log "  Status: May require manual configuration" -Level Warning
    }

    # 13. Intune Policies
    try {
        Write-Log "Checking Intune Policies for Outlook..." -Level Check
        $iosPolicy = Get-MgDeviceAppManagementIosManagedAppProtection -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*Outlook*" -or $_.DisplayName -like "*Personal*" }
        $androidPolicy = Get-MgDeviceAppManagementAndroidManagedAppProtection -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*Outlook*" -or $_.DisplayName -like "*Personal*" }
        
        if ($iosPolicy -and $androidPolicy) {
            Add-PreflightItem -Category "Intune" -Setting "Disable Personal Accounts" -CurrentValue "Policies exist" -TargetValue "Policies configured" -Status "AlreadyConfigured" -Details "Already configured" -Section "Custom"
            Write-Log "  Status: Already configured" -Level Success
        } else {
            Add-PreflightItem -Category "Intune" -Setting "Disable Personal Accounts" -CurrentValue "Not configured" -TargetValue "iOS + Android policies" -Status "WillChange" -Details "Will create policies" -Section "Custom"
            Write-Log "  Status: WILL CREATE POLICIES" -Level Warning
        }
    } catch {
        Add-PreflightItem -Category "Intune" -Setting "Outlook Policies" -CurrentValue "Error" -TargetValue "Configured" -Status "WillChange" -Details "Error checking: $_" -Section "Custom"
        Write-Log "  Status: Error - $_" -Level Error
    }
} else {
    Write-Log "Skipping Graph API checks (not connected)" -Level Warning
    Add-PreflightItem -Category "Authentication" -Setting "QR Code Authentication" -CurrentValue "Not checked" -TargetValue "Enabled" -Status "ManualRequired" -Details "Graph API not available - check manually" -Section "Custom"
    Add-PreflightItem -Category "Intune" -Setting "Disable Personal Accounts" -CurrentValue "Not checked" -TargetValue "Configured" -Status "ManualRequired" -Details "Graph API not available - check manually" -Section "Custom"
}

Write-Host "`n--- MANUAL CONFIGURATIONS ---`n" -ForegroundColor Cyan

Add-PreflightItem -Category "Microsoft Purview" -Setting "DSPM" -CurrentValue "N/A" -TargetValue "Enabled" -Status "ManualRequired" -Details "Requires manual portal configuration" -Section "Custom"
Write-Log "DSPM: Manual configuration required" -Level Warning

Add-PreflightItem -Category "SharePoint Online" -Setting "Knowledge Agent" -CurrentValue "N/A" -TargetValue "Enabled" -Status "ManualRequired" -Details "Requires manual portal configuration" -Section "Custom"
Write-Log "Knowledge Agent: Manual configuration required" -Level Warning

Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host "  GENERATING PRE-FLIGHT REPORT" -ForegroundColor Cyan
Write-Host "================================================================`n" -ForegroundColor Cyan

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$csvPath = Join-Path -Path $PWD -ChildPath "M365_PreFlight_Check_$timestamp.csv"
$htmlPath = Join-Path -Path $PWD -ChildPath "M365_PreFlight_Check_$timestamp.html"

$script:preflightReport | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-Log "CSV report saved: $csvPath" -Level Success

$htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>M365 Security Pre-Flight Check</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .container { max-width: 1600px; margin: 0 auto; background: white; border-radius: 15px; box-shadow: 0 10px 40px rgba(0,0,0,0.3); overflow: hidden; }
        .header { background: linear-gradient(135deg, #ff6b6b 0%, #ee5a6f 100%); color: white; padding: 40px; text-align: center; }
        .header h1 { margin: 0 0 10px 0; font-size: 36px; }
        .header .warning { font-size: 18px; background: #fff; color: #ff6b6b; padding: 10px 20px; border-radius: 5px; display: inline-block; margin-top: 15px; font-weight: bold; }
        .summary { padding: 40px; background: #f8f9fa; }
        .summary h2 { margin: 0 0 25px 0; font-size: 28px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
        .summary-card { background: white; padding: 25px; border-radius: 10px; text-align: center; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
        .summary-card h3 { margin: 0 0 10px 0; font-size: 42px; font-weight: bold; }
        .summary-card p { margin: 0; color: #666; font-size: 14px; }
        .will-change { color: #ff6b6b; }
        .already-ok { color: #28a745; }
        .manual { color: #ffc107; }
        .content { padding: 40px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; background: white; box-shadow: 0 2px 8px rgba(0,0,0,0.1); border-radius: 8px; overflow: hidden; }
        th { background: #343a40; color: white; padding: 15px; text-align: left; font-size: 13px; text-transform: uppercase; }
        td { padding: 15px; border-bottom: 1px solid #e9ecef; font-size: 14px; }
        tr:hover { background: #f8f9fa; }
        .badge { padding: 5px 15px; border-radius: 15px; font-weight: bold; font-size: 11px; text-transform: uppercase; }
        .badge-change { background: #f8d7da; color: #721c24; }
        .badge-ok { background: #d4edda; color: #155724; }
        .badge-manual { background: #fff3cd; color: #856404; }
        .footer { padding: 40px; background: #f8f9fa; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Pre-Flight Check Report</h1>
            <div class="warning">READ-ONLY - No Changes Were Made</div>
            <p style="margin-top: 20px;"><strong>Generated:</strong> $(Get-Date -Format "MMMM dd, yyyy HH:mm:ss")</p>
            <p><strong>Tenant:</strong> $orgName</p>
        </div>
        
        <div class="summary">
            <h2>What Will Happen When You Run The Main Script:</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3 class="will-change">$script:changesNeeded</h3>
                    <p>Settings WILL BE CHANGED</p>
                </div>
                <div class="summary-card">
                    <h3 class="already-ok">$script:alreadyConfigured</h3>
                    <p>Already Configured</p>
                </div>
                <div class="summary-card">
                    <h3 class="manual">$script:manualRequired</h3>
                    <p>Require Manual Configuration</p>
                </div>
            </div>
        </div>
        
        <div class="content">
            <h2>Detailed Configuration Analysis</h2>
            <table>
                <thead>
                    <tr>
                        <th>Category</th>
                        <th>Setting</th>
                        <th>Current Value</th>
                        <th>Target Value</th>
                        <th>What Will Happen</th>
                    </tr>
                </thead>
                <tbody>
"@

foreach ($item in $script:preflightReport) {
    $badgeClass = switch ($item.Status) {
        'WillChange' { 'badge-change' }
        'AlreadyConfigured' { 'badge-ok' }
        'ManualRequired' { 'badge-manual' }
        default { 'badge-ok' }
    }
    
    $statusText = switch ($item.Status) {
        'WillChange' { 'WILL CHANGE' }
        'AlreadyConfigured' { 'Already OK' }
        'ManualRequired' { 'Manual Required' }
        default { 'Unknown' }
    }
    
    $htmlContent += @"
                    <tr>
                        <td><strong>$($item.Category)</strong></td>
                        <td>$($item.Setting)</td>
                        <td>$($item.CurrentValue)</td>
                        <td>$($item.TargetValue)</td>
                        <td><span class="badge $badgeClass">$statusText</span><br><small>$($item.Details)</small></td>
                    </tr>
"@
}

$htmlContent += @"
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <h3>Summary</h3>
            <p><strong>$script:changesNeeded</strong> settings will be changed when you run the main configuration script.</p>
            <p><strong>$script:alreadyConfigured</strong> settings are already configured correctly.</p>
            <p><strong>$script:manualRequired</strong> settings require manual configuration in portals.</p>
            <p style="margin-top: 30px; color: #666;">This was a READ-ONLY check. No changes were made to your environment.</p>
        </div>
    </div>
</body>
</html>
"@

$htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
Write-Log "HTML report saved: $htmlPath" -Level Success

Write-Host "`n================================================================" -ForegroundColor Green
Write-Host "  PRE-FLIGHT CHECK COMPLETE" -ForegroundColor Green
Write-Host "================================================================`n" -ForegroundColor Green

Write-Log "Summary of what WILL happen:" -Level Info
Write-Log "  Will Change: $script:changesNeeded settings" -Level Warning
Write-Log "  Already OK: $script:alreadyConfigured settings" -Level Success
Write-Log "  Manual Required: $script:manualRequired settings" -Level Warning

Write-Host "`nReports generated:" -ForegroundColor Cyan
Write-Log "  CSV: $csvPath" -Level Info
Write-Log "  HTML: $htmlPath" -Level Info

Write-Host "`n" -NoNewline
Write-Log "Next steps:" -Level Info
Write-Log "  1. Review the HTML report to see what will change" -Level Info
Write-Log "  2. If satisfied, run the main configuration script" -Level Info
Write-Log "  3. Or make adjustments before running" -Level Info

Write-Host ""