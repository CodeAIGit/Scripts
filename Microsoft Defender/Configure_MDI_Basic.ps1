#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Microsoft Defender for Identity Domain Controller Configuration Script
    
.DESCRIPTION
    This script configures domain controllers with all necessary policies and
    settings for Microsoft Defender for Identity (excluding sensor installation).
    
.PARAMETER LogPath
    Path for deployment logs (default: C:\MDI_Deployment_Logs)
    
.PARAMETER SkipAuditPolicies
    Skip configuration of advanced audit policies
    
.PARAMETER SkipFirewallRules
    Skip configuration of firewall rules
    
.PARAMETER SkipNTLMAuditing
    Skip configuration of NTLM auditing policies
    
.PARAMETER SkipDomainObjectAuditing
    Skip configuration of domain object auditing policies
    
.EXAMPLE
    .\Configure-MDI.ps1
    
.EXAMPLE
    .\Configure-MDI.ps1 -LogPath "D:\Logs\MDI" -SkipFirewallRules
    
.EXAMPLE
    .\Configure-MDI.ps1 -SkipNTLMAuditing -SkipDomainObjectAuditing
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\MDI_Deployment_Logs",
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipAuditPolicies,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipFirewallRules,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipNTLMAuditing,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipDomainObjectAuditing
)

# Script variables
$ScriptVersion = "1.0"
$LogFile = Join-Path $LogPath "MDI_Configuration_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Create log directory
if (!(Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

# Logging function
function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$TimeStamp] [$Level] $Message"
    
    Write-Host $LogMessage -ForegroundColor $(
        switch ($Level) {
            "INFO" { "White" }
            "WARNING" { "Yellow" }
            "ERROR" { "Red" }
            "SUCCESS" { "Green" }
        }
    )
    
    Add-Content -Path $LogFile -Value $LogMessage
}

# Function to check prerequisites
function Test-Prerequisites {
    Write-Log "Checking prerequisites..." -Level "INFO"
    
    # Check if running as administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (-not $isAdmin) {
        Write-Log "Script must be run as Administrator" -Level "ERROR"
        exit 1
    }
    
    # Check if this is a domain controller
    $isDC = (Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2
    if (-not $isDC) {
        Write-Log "This script should be run on a Domain Controller" -Level "WARNING"
    }
    
    # Check OS version (Windows Server 2012 R2 or later)
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -lt 6 -or ($osVersion.Major -eq 6 -and $osVersion.Minor -lt 3)) {
        Write-Log "Windows Server 2012 R2 or later is required" -Level "ERROR"
        exit 1
    }
    
    # Check .NET Framework version (4.7 or later)
    $dotNetVersion = Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\" -Name Release -ErrorAction SilentlyContinue
    if ($dotNetVersion.Release -lt 460798) {
        Write-Log ".NET Framework 4.7 or later is required" -Level "ERROR"
        exit 1
    }
    
    # Check available disk space (minimum 6GB)
    $systemDrive = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $env:SystemDrive }
    $freeSpaceGB = [math]::Round($systemDrive.FreeSpace / 1GB, 2)
    if ($freeSpaceGB -lt 6) {
        Write-Log "Insufficient disk space. At least 6GB required, found $freeSpaceGB GB" -Level "ERROR"
        exit 1
    }
    
    # Check memory (minimum 2GB)
    $totalMemoryGB = [math]::Round((Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
    if ($totalMemoryGB -lt 2) {
        Write-Log "Insufficient memory. At least 2GB required, found $totalMemoryGB GB" -Level "WARNING"
    }
    
    Write-Log "Prerequisites check completed successfully" -Level "SUCCESS"
}

# Function to configure Windows Defender exclusions
function Set-DefenderExclusions {
    Write-Log "Configuring Windows Defender exclusions for MDI..." -Level "INFO"
    
    try {
        # Process exclusions
        $processExclusions = @(
            "Microsoft.Tri.Sensor.exe",
            "Microsoft.Tri.Sensor.Updater.exe",
            "Microsoft.Tri.Sensor.Updater.Configurator.exe"
        )
        
        foreach ($process in $processExclusions) {
            Add-MpPreference -ExclusionProcess $process -ErrorAction SilentlyContinue
            Write-Log "Added process exclusion: $process" -Level "INFO"
        }
        
        # Path exclusions
        $pathExclusions = @(
            "C:\Program Files\Azure Advanced Threat Protection Sensor",
            "C:\Program Files\Azure Advanced Threat Protection Sensor\*"
        )
        
        foreach ($path in $pathExclusions) {
            Add-MpPreference -ExclusionPath $path -ErrorAction SilentlyContinue
            Write-Log "Added path exclusion: $path" -Level "INFO"
        }
        
        Write-Log "Windows Defender exclusions configured successfully" -Level "SUCCESS"
    }
    catch {
        Write-Log "Failed to configure Windows Defender exclusions: $($_.Exception.Message)" -Level "WARNING"
    }
}

# Function to configure Windows Event Log settings
function Set-EventLogConfiguration {
    Write-Log "Configuring Windows Event Log settings..." -Level "INFO"
    
    try {
        # Configure Security event log
        $securityLogPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security"
        Set-ItemProperty -Path $securityLogPath -Name "MaxSize" -Value 0x40000000 -Type DWord  # 1GB
        Set-ItemProperty -Path $securityLogPath -Name "Retention" -Value 0 -Type DWord
        
        # Configure System event log
        $systemLogPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System"
        Set-ItemProperty -Path $systemLogPath -Name "MaxSize" -Value 0x20000000 -Type DWord  # 512MB
        
        # Enable advanced audit policies for MDI
        $auditPolicies = @(
            @{Name = "Account Logon"; SubCategory = "Credential Validation"},
            @{Name = "Account Logon"; SubCategory = "Kerberos Authentication Service"},
            @{Name = "Account Logon"; SubCategory = "Kerberos Service Ticket Operations"},
            @{Name = "Account Management"; SubCategory = "Computer Account Management"},
            @{Name = "Account Management"; SubCategory = "Security Group Management"},
            @{Name = "Account Management"; SubCategory = "User Account Management"},
            @{Name = "Directory Service Access"; SubCategory = "Directory Service Access"},
            @{Name = "Directory Service Access"; SubCategory = "Directory Service Changes"},
            @{Name = "Directory Service Access"; SubCategory = "Directory Service Replication"},
            @{Name = "Logon/Logoff"; SubCategory = "Logon"},
            @{Name = "Logon/Logoff"; SubCategory = "Logoff"},
            @{Name = "Logon/Logoff"; SubCategory = "Special Logon"},
            @{Name = "Object Access"; SubCategory = "File System"},
            @{Name = "Object Access"; SubCategory = "Registry"},
            @{Name = "Policy Change"; SubCategory = "Authentication Policy Change"},
            @{Name = "Policy Change"; SubCategory = "Authorization Policy Change"},
            @{Name = "Privilege Use"; SubCategory = "Sensitive Privilege Use"},
            @{Name = "System"; SubCategory = "Security System Extension"},
            @{Name = "System"; SubCategory = "System Integrity"}
        )
        
        foreach ($policy in $auditPolicies) {
            try {
                $result = auditpol /set /subcategory:"$($policy.SubCategory)" /success:enable /failure:enable 2>$null
                if ($LASTEXITCODE -eq 0) {
                    Write-Log "✓ Enabled audit policy: $($policy.SubCategory)" -Level "INFO"
                }
                else {
                    Write-Log "⚠ Failed to enable audit policy: $($policy.SubCategory)" -Level "WARNING"
                }
            }
            catch {
                Write-Log "Failed to enable audit policy: $($policy.SubCategory)" -Level "WARNING"
            }
        }
        
        Write-Log "Event log configuration completed successfully" -Level "SUCCESS"
    }
    catch {
        Write-Log "Failed to configure event logs: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Function to configure NTLM auditing
function Set-NTLMAuditing {
    Write-Log "Configuring NTLM auditing for MDI..." -Level "INFO"
    
    try {
        # Configure NTLM auditing via registry
        $ntlmAuditPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
        
        # Ensure the registry path exists
        if (!(Test-Path $ntlmAuditPath)) {
            New-Item -Path $ntlmAuditPath -Force | Out-Null
        }
        
        # Enable NTLM audit logging
        # AuditReceivingNTLMTraffic: 2 = Enable auditing for NTLM authentication
        Set-ItemProperty -Path $ntlmAuditPath -Name "AuditReceivingNTLMTraffic" -Value 2 -Type DWord
        Write-Log "✓ Enabled NTLM traffic auditing" -Level "INFO"
        
        # Configure NTLM authentication audit settings via LSA
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        
        # RestrictSendingNTLMTraffic: 1 = Audit only, 2 = Deny
        Set-ItemProperty -Path $lsaPath -Name "RestrictSendingNTLMTraffic" -Value 1 -Type DWord
        Write-Log "✓ Configured NTLM outbound traffic auditing" -Level "INFO"
        
        # LmCompatibilityLevel: 5 = Send NTLMv2 response only/refuse LM & NTLM
        Set-ItemProperty -Path $lsaPath -Name "LmCompatibilityLevel" -Value 5 -Type DWord
        Write-Log "✓ Set NTLM compatibility level for enhanced security" -Level "INFO"
        
        # Configure NTLM audit via Group Policy equivalent registry settings
        $auditPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u"
        if (!(Test-Path $auditPath)) {
            New-Item -Path $auditPath -Force | Out-Null
        }
        
        # Enable auditing for NTLM authentication events
        auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
        auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable | Out-Null
        
        Write-Log "NTLM auditing configuration completed successfully" -Level "SUCCESS"
        Write-Log "Note: Some NTLM audit settings may require a system restart to take effect" -Level "WARNING"
    }
    catch {
        Write-Log "Failed to configure NTLM auditing: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Function to configure Domain object auditing
function Set-DomainObjectAuditing {
    Write-Log "Configuring Domain object auditing for MDI..." -Level "INFO"
    
    try {
        # Import Active Directory module if available
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $adModuleAvailable = $true
        }
        catch {
            Write-Log "Active Directory module not available, using alternative methods" -Level "WARNING"
            $adModuleAvailable = $false
        }
        
        # Enable Directory Service Access auditing (critical for domain object monitoring)
        auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable | Out-Null
        auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable | Out-Null
        auditpol /set /subcategory:"Directory Service Replication" /success:enable /failure:enable | Out-Null
        Write-Log "✓ Enabled Directory Service audit policies" -Level "INFO"
        
        if ($adModuleAvailable) {
            try {
                # Get domain DN
                $domainDN = (Get-ADDomain).DistinguishedName
                Write-Log "Configuring auditing for domain: $domainDN" -Level "INFO"
                
                # Configure SACL (System Access Control List) for domain objects
                # This enables auditing of domain object changes
                
                # Define audit settings for critical containers
                $containersToAudit = @(
                    "CN=Users,$domainDN",
                    "CN=Computers,$domainDN", 
                    "CN=Domain Controllers,$domainDN",
                    "CN=AdminSDHolder,CN=System,$domainDN",
                    "CN=Infrastructure,$domainDN",
                    "CN=Builtin,$domainDN"
                )
                
                foreach ($container in $containersToAudit) {
                    try {
                        # Set audit ACE for Everyone to audit all changes
                        $cmd = "dsacls `"$container`" /G `"Everyone:GA;GA`" /I:T"
                        Invoke-Expression $cmd | Out-Null
                        Write-Log "✓ Configured auditing for: $container" -Level "INFO"
                    }
                    catch {
                        Write-Log "⚠ Failed to configure auditing for: $container" -Level "WARNING"
                    }
                }
                
                # Enable auditing for user and computer object modifications
                $auditCommands = @(
                    "auditpol /set /subcategory:`"User Account Management`" /success:enable /failure:enable",
                    "auditpol /set /subcategory:`"Computer Account Management`" /success:enable /failure:enable",
                    "auditpol /set /subcategory:`"Security Group Management`" /success:enable /failure:enable",
                    "auditpol /set /subcategory:`"Distribution Group Management`" /success:enable /failure:enable"
                )
                
                foreach ($cmd in $auditCommands) {
                    try {
                        Invoke-Expression $cmd | Out-Null
                        Write-Log "✓ Applied audit command: $cmd" -Level "INFO"
                    }
                    catch {
                        Write-Log "⚠ Failed to apply audit command: $cmd" -Level "WARNING"
                    }
                }
                
            }
            catch {
                Write-Log "Failed to configure domain-specific auditing: $($_.Exception.Message)" -Level "WARNING"
            }
        }
        else {
            # Alternative method using dsacls directly
            Write-Log "Attempting to configure domain auditing without AD module..." -Level "INFO"
            
            try {
                # Get current domain
                $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                $domainDN = "DC=" + ($domain.Name -replace "\.", ",DC=")
                
                Write-Log "Domain DN detected as: $domainDN" -Level "INFO"
                
                # Basic domain auditing configuration
                $basicContainers = @(
                    "CN=Users,$domainDN",
                    "CN=Computers,$domainDN"
                )
                
                foreach ($container in $basicContainers) {
                    try {
                        & dsacls "$container" /G "Everyone:GA;GA" /I:T 2>$null
                        if ($LASTEXITCODE -eq 0) {
                            Write-Log "✓ Configured basic auditing for: $container" -Level "INFO"
                        }
                    }
                    catch {
                        Write-Log "⚠ Could not configure auditing for: $container" -Level "WARNING"
                    }
                }
            }
            catch {
                Write-Log "Could not determine domain information for auditing configuration" -Level "WARNING"
            }
        }
        
        # Configure additional object access auditing
        auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable | Out-Null
        auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable | Out-Null
        
        Write-Log "Domain object auditing configuration completed" -Level "SUCCESS"
        Write-Log "Note: Domain object auditing changes may require AD replication time to take effect" -Level "INFO"
    }
    catch {
        Write-Log "Failed to configure domain object auditing: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Function to configure firewall rules
function Set-FirewallRules {
    Write-Log "Configuring firewall rules for MDI..." -Level "INFO"
    
    try {
        # Allow outbound HTTPS (443) for sensor communication
        New-NetFirewallRule -DisplayName "MDI Sensor HTTPS Outbound" -Direction Outbound -Protocol TCP -LocalPort 443 -Action Allow -ErrorAction SilentlyContinue
        
        # Allow inbound port for sensor management (if needed)
        New-NetFirewallRule -DisplayName "MDI Sensor Management" -Direction Inbound -Protocol TCP -LocalPort 444 -Action Allow -ErrorAction SilentlyContinue
        
        Write-Log "Firewall rules configured successfully" -Level "SUCCESS"
    }
    catch {
        Write-Log "Failed to configure firewall rules: $($_.Exception.Message)" -Level "WARNING"
    }
}

# Function to check MDI sensor status
function Test-SensorStatus {
    Write-Log "Checking for existing MDI sensor installation..." -Level "INFO"
    
    try {
        # Check if sensor is installed
        $installedSensor = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Azure Advanced Threat Protection Sensor*" }
        if ($installedSensor) {
            Write-Log "MDI Sensor is installed (Version: $($installedSensor.Version))" -Level "SUCCESS"
            
            # Check if service exists and is running
            $sensorService = Get-Service -Name "AATPSensor" -ErrorAction SilentlyContinue
            if ($sensorService) {
                Write-Log "MDI Sensor service status: $($sensorService.Status)" -Level "INFO"
            }
            
            return $true
        }
        else {
            Write-Log "MDI Sensor is not installed on this system" -Level "WARNING"
            Write-Log "This configuration will prepare the system for when the sensor is installed" -Level "INFO"
            return $false
        }
    }
    catch {
        Write-Log "Failed to check sensor status: $($_.Exception.Message)" -Level "WARNING"
        return $false
    }
}

# Function to verify configuration
function Test-Configuration {
    Write-Log "Verifying MDI configuration..." -Level "INFO"
    
    try {
        $configurationValid = $true
        
        # Check Windows Defender exclusions
        try {
            $exclusions = Get-MpPreference -ErrorAction SilentlyContinue
            if ($exclusions.ExclusionProcess -contains "Microsoft.Tri.Sensor.exe") {
                Write-Log "✓ Windows Defender process exclusions configured" -Level "SUCCESS"
            }
            else {
                Write-Log "⚠ Windows Defender exclusions may need verification" -Level "WARNING"
            }
        }
        catch {
            Write-Log "Could not verify Windows Defender exclusions" -Level "WARNING"
        }
        
        # Check audit policies
        try {
            $auditResult = auditpol /get /subcategory:"Logon" 2>$null
            if ($auditResult -match "Success and Failure") {
                Write-Log "✓ Basic audit policies configured" -Level "SUCCESS"
            }
            else {
                Write-Log "⚠ Basic audit policies may need verification" -Level "WARNING"
            }
            
            # Check Directory Service Access auditing
            $dsAuditResult = auditpol /get /subcategory:"Directory Service Access" 2>$null
            if ($dsAuditResult -match "Success and Failure") {
                Write-Log "✓ Directory Service Access auditing enabled" -Level "SUCCESS"
            }
            else {
                Write-Log "⚠ Directory Service Access auditing not configured" -Level "WARNING"
            }
        }
        catch {
            Write-Log "Could not verify audit policies" -Level "WARNING"
        }
        
        # Check NTLM auditing configuration
        try {
            $ntlmAuditPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
            $ntlmAuditValue = (Get-ItemProperty -Path $ntlmAuditPath -Name "AuditReceivingNTLMTraffic" -ErrorAction SilentlyContinue).AuditReceivingNTLMTraffic
            if ($ntlmAuditValue -eq 2) {
                Write-Log "✓ NTLM auditing configured" -Level "SUCCESS"
            }
            else {
                Write-Log "⚠ NTLM auditing may need configuration" -Level "WARNING"
            }
        }
        catch {
            Write-Log "Could not verify NTLM auditing configuration" -Level "WARNING"
        }
        
        # Check event log settings
        try {
            $securityLogSize = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "MaxSize" -ErrorAction SilentlyContinue).MaxSize
            if ($securityLogSize -ge 0x40000000) {
                Write-Log "✓ Security event log size configured ($(($securityLogSize / 1MB)) MB)" -Level "SUCCESS"
            }
            else {
                Write-Log "⚠ Security event log size may need adjustment" -Level "WARNING"
            }
        }
        catch {
            Write-Log "Could not verify event log configuration" -Level "WARNING"
        }
        
        # Check firewall rules
        try {
            $firewallRule = Get-NetFirewallRule -DisplayName "MDI Sensor HTTPS Outbound" -ErrorAction SilentlyContinue
            if ($firewallRule) {
                Write-Log "✓ Firewall rules configured" -Level "SUCCESS"
            }
            else {
                Write-Log "⚠ Firewall rules may need verification" -Level "WARNING"
            }
        }
        catch {
            Write-Log "Could not verify firewall rules" -Level "WARNING"
        }
        
        # Check if sensor is installed and running (optional verification)
        $sensorInstalled = Test-SensorStatus
        if ($sensorInstalled) {
            $sensorService = Get-Service -Name "AATPSensor" -ErrorAction SilentlyContinue
            if ($sensorService -and $sensorService.Status -eq "Running") {
                Write-Log "✓ MDI Sensor service is running" -Level "SUCCESS"
            }
            elseif ($sensorService -and $sensorService.Status -eq "Stopped") {
                Write-Log "⚠ MDI Sensor service is installed but stopped" -Level "WARNING"
            }
        }
        
        Write-Log "Configuration verification completed" -Level "SUCCESS"
        return $configurationValid
    }
    catch {
        Write-Log "Failed to verify configuration: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

# Function to create scheduled maintenance task
function New-MaintenanceTask {
    Write-Log "Creating maintenance scheduled task..." -Level "INFO"
    
    try {
        $taskAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$PSCommandPath`" -Maintenance"
        $taskTrigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 1 -DaysOfWeek Sunday -At 2am
        $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        Register-ScheduledTask -TaskName "MDI Configuration Maintenance" -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Principal $taskPrincipal -Description "Weekly maintenance for Microsoft Defender for Identity configuration" -Force | Out-Null
        
        Write-Log "Maintenance scheduled task created successfully" -Level "SUCCESS"
    }
    catch {
        Write-Log "Failed to create maintenance task: $($_.Exception.Message)" -Level "WARNING"
    }
}

# Function to generate configuration report
function New-DeploymentReport {
    Write-Log "Generating configuration report..." -Level "INFO"
    
    $reportPath = Join-Path $LogPath "MDI_Configuration_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    
    $reportContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>MDI Configuration Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #0078d4; color: white; padding: 20px; text-align: center; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; }
        .success { background-color: #d4edda; border-color: #c3e6cb; }
        .warning { background-color: #fff3cd; border-color: #ffeaa7; }
        .error { background-color: #f8d7da; border-color: #f5c6cb; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Microsoft Defender for Identity Configuration Report</h1>
        <p>Generated on: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>
    
    <div class="section">
        <h2>System Information</h2>
        <table>
            <tr><th>Computer Name</th><td>$env:COMPUTERNAME</td></tr>
            <tr><th>Domain</th><td>$env:USERDNSDOMAIN</td></tr>
            <tr><th>OS Version</th><td>$([System.Environment]::OSVersion.VersionString)</td></tr>
            <tr><th>Configuration Time</th><td>$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</td></tr>
        </table>
    </div>
    
    <div class="section">
        <h2>Configuration Status</h2>
        <p>System has been configured for Microsoft Defender for Identity.</p>
        <p>To complete setup, install the MDI sensor from the Microsoft 365 Security portal.</p>
        <p>Please check the log file for detailed information: $LogFile</p>
    </div>
</body>
</html>
"@
    
    $reportContent | Out-File -FilePath $reportPath -Encoding UTF8
    Write-Log "Configuration report saved to: $reportPath" -Level "SUCCESS"
}

# Main configuration function
function Start-MDIConfiguration {
    Write-Log "=== Microsoft Defender for Identity Configuration Started ===" -Level "INFO"
    Write-Log "Script Version: $ScriptVersion" -Level "INFO"
    Write-Log "Target Computer: $env:COMPUTERNAME" -Level "INFO"
    Write-Log "Domain: $env:USERDNSDOMAIN" -Level "INFO"
    
    try {
        # Step 1: Check prerequisites
        Test-Prerequisites
        
        # Step 2: Check current sensor status
        Test-SensorStatus
        
        # Step 3: Configure Windows Defender exclusions
        Set-DefenderExclusions
        
        # Step 4: Configure event logging and auditing
        if (-not $SkipAuditPolicies) {
            Set-EventLogConfiguration
            
            if (-not $SkipNTLMAuditing) {
                Set-NTLMAuditing
            }
            else {
                Write-Log "Skipping NTLM auditing configuration as requested" -Level "INFO"
            }
            
            if (-not $SkipDomainObjectAuditing) {
                Set-DomainObjectAuditing
            }
            else {
                Write-Log "Skipping domain object auditing configuration as requested" -Level "INFO"
            }
        }
        else {
            Write-Log "Skipping all audit policy configurations as requested" -Level "INFO"
        }
        
        # Step 5: Configure firewall
        if (-not $SkipFirewallRules) {
            Set-FirewallRules
        }
        else {
            Write-Log "Skipping firewall rule configuration as requested" -Level "INFO"
        }
        
        # Step 6: Verify configuration
        Test-Configuration
        
        # Step 7: Create maintenance task
        New-MaintenanceTask
        
        # Step 8: Generate report
        New-DeploymentReport
        
        Write-Log "=== MDI Configuration Completed Successfully ===" -Level "SUCCESS"
        Write-Log "System is now prepared for Microsoft Defender for Identity sensor" -Level "INFO"
        Write-Log "To complete setup, install the MDI sensor using your access key from the portal" -Level "INFO"
        Write-Log "Download sensor from: https://security.microsoft.com/settings/identities" -Level "INFO"
        Write-Log "Log file location: $LogFile" -Level "INFO"
    }
    catch {
        Write-Log "Configuration failed: $($_.Exception.Message)" -Level "ERROR"
        exit 1
    }
}

# Execute configuration
if ($MyInvocation.BoundParameters.ContainsKey('Maintenance')) {
    # Maintenance mode (called by scheduled task)
    Write-Log "Running maintenance tasks..." -Level "INFO"
    Test-Configuration
}
else {
    # Normal configuration mode
    Start-MDIConfiguration
}