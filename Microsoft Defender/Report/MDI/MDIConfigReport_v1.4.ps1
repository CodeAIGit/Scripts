# ================================================================================================
# MICROSOFT DEFENDER FOR IDENTITY ULTRA-DETAILED ENTERPRISE REPORTING SCRIPT
# ================================================================================================
# Purpose: Generate ultra-detailed enterprise-wide MDI audit configuration reports with specific recommendations
# Author: Enterprise Security Team - Enhanced Edition
# Version: 4.0 - Ultra-Detailed Comprehensive Edition
# Requirements: PowerShell 5.1+, AD Module, PS Remoting enabled on all DCs
# ================================================================================================

function New-MDIUltraDetailedEnterpriseReport {
    <#
    .SYNOPSIS
    Generates ultra-detailed enterprise-wide Microsoft Defender for Identity audit configuration reports.
    
    .DESCRIPTION
    This function collects comprehensive MDI configuration data from all domain controllers in the environment
    and generates ultra-detailed reports showing configuration specifics, security implications, and remediation steps.
    
    .PARAMETER OutputPath
    Directory where reports will be saved. Default: C:\Reports\Enterprise
    
    .PARAMETER ReportName
    Base name for report files. Default: MDI-UltraDetailed-Enterprise-Report
    
    .PARAMETER OpenReport
    Whether to automatically open the HTML report after generation. Default: $true
    
    .PARAMETER Format
    Report format(s) to generate. Options: HTML, Text, JSON, All. Default: All
    
    .PARAMETER ExcludeDCs
    Array of domain controller names to exclude from assessment
    
    .PARAMETER IncludeRemediationSteps
    Include detailed PowerShell remediation commands in the report. Default: $true
    
    .EXAMPLE
    New-MDIUltraDetailedEnterpriseReport
    Generates ultra-detailed report for all domain controllers with remediation steps
    
    .EXAMPLE
    New-MDIUltraDetailedEnterpriseReport -ExcludeDCs 'TestDC01','MaintenanceDC02' -Format HTML
    Generates HTML report excluding specified DCs
    #>
    
    param(
        [string]$OutputPath = "C:\Reports\Enterprise",
        [string]$ReportName = "MDI-UltraDetailed-Enterprise-Report",
        [switch]$OpenReport = $true,
        [ValidateSet("HTML", "Text", "JSON", "All")]
        [string]$Format = "All",
        [string[]]$ExcludeDCs = @(),
        [switch]$IncludeRemediationSteps = $true
    )
    
    # ================================================================================================
    # INITIALIZATION AND SETUP
    # ================================================================================================
    
    Write-Host "`n🔍 Generating Ultra-Detailed Enterprise MDI Report..." -ForegroundColor Yellow
    Write-Host "=================================================================" -ForegroundColor Yellow
    
    # Create output directory if it doesn't exist
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        Write-Host "✅ Created report directory: $OutputPath" -ForegroundColor Green
    }
    
    # Generate unique timestamp for report naming
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportBaseName = "$ReportName-$timestamp"
    
    # ================================================================================================
    # ACTIVE DIRECTORY DISCOVERY
    # ================================================================================================
    
    # Connect to Active Directory and get comprehensive domain information
    try {
        $domain = Get-ADDomain
        $forest = Get-ADForest
        $domainFunctionalLevel = $domain.DomainMode
        $forestFunctionalLevel = $forest.ForestMode
        Write-Host "✅ Connected to domain: $($domain.DNSRoot) (FL: $domainFunctionalLevel)" -ForegroundColor Green
        Write-Host "🌲 Forest: $($forest.Name) (FL: $forestFunctionalLevel)" -ForegroundColor Green
    } catch {
        Write-Error "Cannot connect to Active Directory. Ensure AD PowerShell module is installed and you have appropriate permissions."
        return
    }
    
    # Discover all domain controllers with detailed information
    Write-Host "🔍 Discovering domain controllers with detailed information..." -ForegroundColor Cyan
    try {
        $allDCs = Get-ADDomainController -Filter *
        $targetDCs = $allDCs | Where-Object { $_.Name -notin $ExcludeDCs }
        
        Write-Host "📊 Found $($allDCs.Count) domain controllers total" -ForegroundColor White
        if ($ExcludeDCs.Count -gt 0) {
            Write-Host "⚠️  Excluding $($ExcludeDCs.Count) DCs: $($ExcludeDCs -join ', ')" -ForegroundColor Yellow
        }
        Write-Host "🎯 Will assess $($targetDCs.Count) domain controllers" -ForegroundColor Green
    } catch {
        Write-Error "Failed to discover domain controllers: $($_.Exception.Message)"
        return
    }
    
    # ================================================================================================
    # CONNECTIVITY TESTING WITH DETAILED DIAGNOSTICS
    # ================================================================================================
    
    # Test PowerShell remoting connectivity with detailed diagnostics
    Write-Host "🔌 Testing PowerShell remoting connectivity with diagnostics..." -ForegroundColor Cyan
    $reachableDCs = @()
    $unreachableDCs = @()
    $connectivityDetails = @{}
    
    foreach ($dc in $targetDCs) {
        Write-Host "   Testing $($dc.Name)..." -ForegroundColor Gray
        try {
            # Test multiple connectivity aspects
            $pingResult = Test-Connection -ComputerName $dc.Name -Count 1 -Quiet -ErrorAction SilentlyContinue
            $wsmanResult = Test-WSMan -ComputerName $dc.Name -ErrorAction SilentlyContinue
            $portTest = Test-NetConnection -ComputerName $dc.Name -Port 5985 -InformationLevel Quiet -ErrorAction SilentlyContinue
            
            $connectivityDetails[$dc.Name] = @{
                PingSuccess = $pingResult
                WSManSuccess = $wsmanResult -ne $null
                Port5985Open = $portTest
                OverallStatus = $pingResult -and ($wsmanResult -ne $null) -and $portTest
            }
            
            if ($connectivityDetails[$dc.Name].OverallStatus) {
                $reachableDCs += $dc
                Write-Host "   ✅ $($dc.Name) - Fully Reachable" -ForegroundColor Green
            } else {
                $unreachableDCs += $dc.Name
                $issues = @()
                if (-not $pingResult) { $issues += "Ping Failed" }
                if (-not $connectivityDetails[$dc.Name].WSManSuccess) { $issues += "WS-Management Failed" }
                if (-not $portTest) { $issues += "Port 5985 Closed" }
                Write-Host "   ❌ $($dc.Name) - Issues: $($issues -join ', ')" -ForegroundColor Red
            }
        } catch {
            $unreachableDCs += $dc.Name
            $connectivityDetails[$dc.Name] = @{
                PingSuccess = $false
                WSManSuccess = $false
                Port5985Open = $false
                OverallStatus = $false
                Error = $_.Exception.Message
            }
            Write-Host "   ❌ $($dc.Name) - Error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    # Verify we have at least one reachable DC to proceed
    if ($reachableDCs.Count -eq 0) {
        Write-Error "No domain controllers are reachable via PowerShell remoting. Enable PS remoting with: Enable-PSRemoting -Force"
        return
    }
    
    Write-Host "✅ Successfully connected to $($reachableDCs.Count) of $($targetDCs.Count) domain controllers" -ForegroundColor Green
    
    # ================================================================================================
    # ULTRA-DETAILED DATA COLLECTION SCRIPT BLOCK
    # ================================================================================================
    
    # This script block runs on each domain controller to collect ultra-detailed MDI configuration data
    $ultraDetailedDataCollection = {
        # Initialize comprehensive results hashtable
        $results = @{}
        
        # ============================================================================================
        # ULTRA-DETAILED AUDIT POLICY CONFIGURATION ANALYSIS
        # ============================================================================================
        
        Write-Host "   📋 Analyzing audit policies..." -ForegroundColor Gray
        $auditPolicies = @{}
        
        # Define all MDI-related audit policies with detailed descriptions and security implications
        $allMDIPolicies = @{
            "Credential Validation" = @{
                Description = "Logs NTLM and Kerberos authentication attempts"
                SecurityImplication = "Critical for detecting credential attacks, pass-the-hash, and authentication anomalies"
                RequiredSetting = "Success and Failure"
                MDIEventIDs = @(4776, 4777)
                ThreatDetection = @("Pass-the-Hash", "Brute Force", "Credential Stuffing")
            }
            "Computer Account Management" = @{
                Description = "Logs computer account creation, deletion, and modification"
                SecurityImplication = "Detects unauthorized computer account manipulation and potential lateral movement"
                RequiredSetting = "Success and Failure"
                MDIEventIDs = @(4741, 4742, 4743)
                ThreatDetection = @("Rogue Computer Accounts", "Machine Account Compromise")
            }
            "Distribution Group Management" = @{
                Description = "Logs distribution group membership and property changes"
                SecurityImplication = "Monitors for unauthorized group modifications that could affect email security"
                RequiredSetting = "Success and Failure"
                MDIEventIDs = @(4749, 4750, 4751, 4752, 4753)
                ThreatDetection = @("Email Group Manipulation", "Information Disclosure")
            }
            "Security Group Management" = @{
                Description = "Logs security group membership and property changes"
                SecurityImplication = "Critical for detecting privilege escalation through group membership changes"
                RequiredSetting = "Success and Failure"
                MDIEventIDs = @(4728, 4729, 4732, 4733, 4756, 4757)
                ThreatDetection = @("Privilege Escalation", "Unauthorized Access", "Golden Ticket")
            }
            "User Account Management" = @{
                Description = "Logs user account creation, deletion, modification, and password changes"
                SecurityImplication = "Detects account manipulation, password attacks, and unauthorized user creation"
                RequiredSetting = "Success and Failure"
                MDIEventIDs = @(4720, 4722, 4724, 4725, 4726, 4738, 4767)
                ThreatDetection = @("Account Creation", "Password Attacks", "Account Takeover")
            }
            "Directory Service Changes" = @{
                Description = "Logs modifications to Active Directory objects and their attributes"
                SecurityImplication = "Essential for detecting unauthorized AD schema or object modifications"
                RequiredSetting = "Success and Failure"
                MDIEventIDs = @(5136, 5137, 5138, 5139, 5141)
                ThreatDetection = @("AD Object Manipulation", "Schema Changes", "DACL Modifications")
            }
            "Directory Service Access" = @{
                Description = "Logs LDAP queries and directory access operations"
                SecurityImplication = "Critical for MDI to detect reconnaissance activities and LDAP attacks"
                RequiredSetting = "Success and Failure"
                MDIEventIDs = @(4662)
                ThreatDetection = @("LDAP Reconnaissance", "Directory Enumeration", "Data Exfiltration")
            }
            "Security System Extension" = @{
                Description = "Logs security service and driver installations"
                SecurityImplication = "Detects potentially malicious security extensions and rootkits"
                RequiredSetting = "Success and Failure"
                MDIEventIDs = @(4610, 4611, 4614, 4622)
                ThreatDetection = @("Rootkit Installation", "Security Bypass", "Malicious Extensions")
            }
            "Kerberos Authentication Service" = @{
                Description = "Logs Kerberos AS-REQ and AS-REP ticket requests"
                SecurityImplication = "Essential for detecting Kerberos attacks including ASREPRoasting"
                RequiredSetting = "Success and Failure"
                MDIEventIDs = @(4768, 4771)
                ThreatDetection = @("ASREPRoasting", "Kerberos Brute Force", "Golden Ticket")
            }
            "Kerberos Service Ticket Operations" = @{
                Description = "Logs Kerberos TGS-REQ and TGS-REP service ticket operations"
                SecurityImplication = "Critical for detecting Kerberoasting and service ticket attacks"
                RequiredSetting = "Success and Failure"
                MDIEventIDs = @(4769, 4770)
                ThreatDetection = @("Kerberoasting", "Silver Ticket", "Service Account Compromise")
            }
            "Other Account Logon Events" = @{
                Description = "Logs other authentication methods and logon events"
                SecurityImplication = "Captures alternative authentication methods and logon anomalies"
                RequiredSetting = "Success and Failure"
                MDIEventIDs = @(4648, 4649)
                ThreatDetection = @("Alternative Authentication", "Logon Anomalies")
            }
        }
        
        # Check each audit policy subcategory with detailed analysis
        foreach ($policyName in $allMDIPolicies.Keys) {
            try {
                # Use auditpol.exe to get current audit policy configuration
                $result = auditpol.exe /get /subcategory:"$policyName" 2>$null
                
                # Determine compliance status
                $complianceStatus = "Unknown"
                $currentSetting = "Unknown"
                $riskLevel = "High"
                
                if ($result -match "Success and Failure") {
                    $complianceStatus = "Fully Compliant"
                    $currentSetting = "Success and Failure"
                    $riskLevel = "Low"
                } elseif ($result -match "Success") {
                    $complianceStatus = "Partially Compliant"
                    $currentSetting = "Success Only"
                    $riskLevel = "Medium"
                } elseif ($result -match "Failure") {
                    $complianceStatus = "Partially Compliant"
                    $currentSetting = "Failure Only"
                    $riskLevel = "Medium"
                } elseif ($result -match "No Auditing") {
                    $complianceStatus = "Non-Compliant"
                    $currentSetting = "No Auditing"
                    $riskLevel = "Critical"
                }
                
                # Build comprehensive policy information
                $auditPolicies[$policyName] = @{
                    ComplianceStatus = $complianceStatus
                    CurrentSetting = $currentSetting
                    RequiredSetting = $allMDIPolicies[$policyName].RequiredSetting
                    Description = $allMDIPolicies[$policyName].Description
                    SecurityImplication = $allMDIPolicies[$policyName].SecurityImplication
                    MDIEventIDs = $allMDIPolicies[$policyName].MDIEventIDs
                    ThreatDetection = $allMDIPolicies[$policyName].ThreatDetection
                    RiskLevel = $riskLevel
                    RemediationCommand = "auditpol.exe /set /subcategory:`"$policyName`" /success:enable /failure:enable"
                }
            } catch {
                $auditPolicies[$policyName] = @{
                    ComplianceStatus = "Error"
                    CurrentSetting = "Error retrieving setting"
                    Error = $_.Exception.Message
                    RiskLevel = "Unknown"
                }
            }
        }
        $results["AuditPolicies"] = $auditPolicies
        
        # ============================================================================================
        # ULTRA-DETAILED NTLM CONFIGURATION ANALYSIS
        # ============================================================================================
        
        Write-Host "   🔐 Analyzing NTLM configurations..." -ForegroundColor Gray
        $ntlmSettings = @{}
        
        # Define comprehensive NTLM settings with detailed explanations
        $ntlmConfigurations = @{
            "AuditReceivingNTLMTraffic" = @{
                Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
                Expected = 2
                Description = "Controls auditing of NTLM authentication traffic received by this server"
                SecurityImplication = "Required for MDI Event 8004 generation to detect NTLM attacks"
                PossibleValues = @{
                    0 = "Disable - No NTLM auditing (Critical Risk)"
                    1 = "Enable auditing for domain accounts (Medium Risk)"
                    2 = "Enable auditing for all accounts (Recommended)"
                }
                ThreatDetection = "Pass-the-Hash, NTLM Relay, Credential Stuffing"
                MDIRequirement = "Essential for comprehensive NTLM attack detection"
            }
            "RestrictReceivingNTLMTraffic" = @{
                Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
                Expected = 1
                Description = "Controls restrictions on NTLM authentication traffic received by this server"
                SecurityImplication = "Provides visibility into NTLM usage patterns for gradual restriction"
                PossibleValues = @{
                    0 = "Allow all (High Risk)"
                    1 = "Audit all - Recommended for monitoring"
                    2 = "Audit and restrict domain accounts (Very Restrictive)"
                }
                ThreatDetection = "NTLM Relay Prevention, Authentication Monitoring"
                MDIRequirement = "Recommended for NTLM visibility and gradual restriction"
            }
            "RestrictSendingNTLMTraffic" = @{
                Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
                Expected = 1
                Description = "Controls restrictions on NTLM authentication traffic sent by this server"
                SecurityImplication = "Monitors outbound NTLM authentication attempts"
                PossibleValues = @{
                    0 = "Allow all (High Risk)"
                    1 = "Audit all - Recommended for monitoring"
                    2 = "Audit and restrict domain accounts (Very Restrictive)"
                }
                ThreatDetection = "Outbound NTLM Attack Detection, Lateral Movement"
                MDIRequirement = "Important for detecting lateral movement patterns"
            }
            "AuditNTLMInDomain" = @{
                Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
                Expected = 7
                Description = "Controls auditing of NTLM authentication events in the domain"
                SecurityImplication = "Critical for domain-wide NTLM attack visibility"
                PossibleValues = @{
                    0 = "Disable domain NTLM auditing (Critical Risk)"
                    1 = "Enable for domain controller accounts"
                    2 = "Enable for domain accounts"
                    4 = "Enable for domain trust accounts"
                    7 = "Enable for all accounts (Recommended)"
                }
                ThreatDetection = "Domain-wide NTLM Attacks, Cross-Domain Attacks"
                MDIRequirement = "Essential for comprehensive domain NTLM monitoring"
            }
            "SCENoApplyLegacyAuditPolicy" = @{
                Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                Expected = 1
                Description = "Forces use of advanced audit policy subcategory settings"
                SecurityImplication = "Ensures audit policy subcategories are not overridden by legacy settings"
                PossibleValues = @{
                    0 = "Allow legacy audit policies to override (Risk)"
                    1 = "Force advanced audit subcategory settings (Recommended)"
                }
                ThreatDetection = "Ensures consistent audit policy enforcement"
                MDIRequirement = "Critical for reliable audit policy configuration"
            }
        }
        
        # Check each NTLM configuration setting with detailed analysis
        foreach ($settingName in $ntlmConfigurations.Keys) {
            try {
                $config = $ntlmConfigurations[$settingName]
                $currentValue = Get-ItemProperty -Path $config.Path -Name $settingName -ErrorAction SilentlyContinue
                
                # Determine compliance and risk status
                $complianceStatus = "Unknown"
                $riskLevel = "High"
                $currentValueDescription = "Not Set"
                
                if ($currentValue) {
                    $actualValue = $currentValue.$settingName
                    if ($actualValue -eq $config.Expected) {
                        $complianceStatus = "Fully Compliant"
                        $riskLevel = "Low"
                    } else {
                        $complianceStatus = "Non-Compliant"
                        $riskLevel = "High"
                    }
                    
                    # Get description for current value
                    if ($config.PossibleValues.ContainsKey($actualValue)) {
                        $currentValueDescription = $config.PossibleValues[$actualValue]
                    } else {
                        $currentValueDescription = "Value: $actualValue (Unexpected)"
                    }
                } else {
                    $complianceStatus = "Not Configured"
                    $riskLevel = "Critical"
                    $currentValueDescription = "Registry value not found"
                }
                
                # Build comprehensive setting information
                $ntlmSettings[$settingName] = @{
                    ComplianceStatus = $complianceStatus
                    CurrentValue = if ($currentValue) { $currentValue.$settingName } else { "Not Set" }
                    CurrentValueDescription = $currentValueDescription
                    ExpectedValue = $config.Expected
                    ExpectedValueDescription = $config.PossibleValues[$config.Expected]
                    RegistryPath = "$($config.Path)\$settingName"
                    Description = $config.Description
                    SecurityImplication = $config.SecurityImplication
                    ThreatDetection = $config.ThreatDetection
                    MDIRequirement = $config.MDIRequirement
                    RiskLevel = $riskLevel
                    RemediationCommand = "Set-ItemProperty -Path `"$($config.Path)`" -Name `"$settingName`" -Value $($config.Expected)"
                    VerificationCommand = "Get-ItemProperty -Path `"$($config.Path)`" -Name `"$settingName`""
                }
            } catch {
                $ntlmSettings[$settingName] = @{
                    ComplianceStatus = "Error"
                    CurrentValue = "Error"
                    Error = $_.Exception.Message
                    RiskLevel = "Unknown"
                }
            }
        }
        $results["NTLMSettings"] = $ntlmSettings
        
        # ============================================================================================
        # ULTRA-DETAILED SECURITY EVENT ANALYSIS (EXTENDED TIMEFRAME)
        # ============================================================================================
        
        Write-Host "   📊 Analyzing security events..." -ForegroundColor Gray
        $eventAnalysis = @{}
        
        # Define comprehensive MDI event analysis with detailed explanations
        $mdiSecurityEvents = @{
            4662 = @{
                Name = "Directory Service Access"
                Description = "An operation was performed on an object in Active Directory"
                MDIRelevance = "Critical - Primary event for LDAP reconnaissance and data access detection"
                ThreatIndicators = @("Unusual LDAP queries", "Bulk directory enumeration", "Privilege escalation attempts")
                NormalFrequency = "High - Hundreds to thousands per hour in active environments"
                AlertThresholds = @{
                    Low = "< 100 events/hour"
                    Normal = "100-1000 events/hour"
                    High = "> 1000 events/hour"
                    Critical = "> 10000 events/hour"
                }
            }
            4776 = @{
                Name = "NTLM Authentication"
                Description = "The computer attempted to validate the credentials for an account"
                MDIRelevance = "High - Essential for detecting NTLM-based attacks"
                ThreatIndicators = @("Brute force attempts", "Pass-the-hash attacks", "Unusual source IPs")
                NormalFrequency = "Medium - Varies based on NTLM usage in environment"
                AlertThresholds = @{
                    Low = "< 10 events/hour"
                    Normal = "10-100 events/hour"
                    High = "> 100 events/hour"
                    Critical = "> 1000 events/hour"
                }
            }
            8004 = @{
                Name = "NTLM Authentication (Detailed)"
                Description = "An NTLM authentication occurred with detailed audit information"
                MDIRelevance = "Critical - Provides detailed NTLM attack visibility for MDI"
                ThreatIndicators = @("NTLM downgrade attacks", "Pass-the-hash patterns", "Credential replay")
                NormalFrequency = "Depends on NTLM auditing configuration"
                AlertThresholds = @{
                    Low = "Event should be present if NTLM auditing is configured"
                    Normal = "Correlates with 4776 events"
                    High = "Unusual patterns indicate attacks"
                }
            }
            4768 = @{
                Name = "Kerberos TGT Request"
                Description = "A Kerberos authentication ticket (TGT) was requested"
                MDIRelevance = "High - Detects Kerberos authentication patterns and anomalies"
                ThreatIndicators = @("Golden ticket usage", "Unusual authentication times", "Service account abuse")
                NormalFrequency = "High - Should see regular TGT requests during business hours"
                AlertThresholds = @{
                    Low = "< 50 events/hour"
                    Normal = "50-500 events/hour"
                    High = "> 500 events/hour"
                }
            }
            4769 = @{
                Name = "Kerberos Service Ticket"
                Description = "A Kerberos service ticket was requested"
                MDIRelevance = "High - Critical for detecting Kerberoasting attacks"
                ThreatIndicators = @("Kerberoasting attempts", "Service account enumeration", "Silver ticket usage")
                NormalFrequency = "Very High - Most common Kerberos event"
                AlertThresholds = @{
                    Low = "< 100 events/hour"
                    Normal = "100-2000 events/hour"
                    High = "> 2000 events/hour"
                }
            }
            4771 = @{
                Name = "Kerberos Pre-authentication Failed"
                Description = "Kerberos pre-authentication failed"
                MDIRelevance = "Medium - Indicates potential brute force or ASREPRoasting"
                ThreatIndicators = @("Password spray attacks", "ASREPRoasting attempts", "Account lockout evasion")
                NormalFrequency = "Low - Should be infrequent in healthy environments"
                AlertThresholds = @{
                    Low = "< 5 events/hour"
                    Normal = "5-20 events/hour"
                    High = "> 20 events/hour (Potential Attack)"
                }
            }
            4624 = @{
                Name = "Account Logon"
                Description = "An account was successfully logged on"
                MDIRelevance = "Medium - Provides context for authentication patterns"
                ThreatIndicators = @("Unusual logon times", "Suspicious source IPs", "Service account abuse")
                NormalFrequency = "Very High - Constant during business hours"
                AlertThresholds = @{
                    Low = "< 50 events/hour"
                    Normal = "50-1000 events/hour"
                    High = "> 1000 events/hour"
                }
            }
            4625 = @{
                Name = "Account Logon Failed"
                Description = "An account failed to log on"
                MDIRelevance = "Medium - Indicates potential brute force attacks"
                ThreatIndicators = @("Brute force attempts", "Password spray", "Account enumeration")
                NormalFrequency = "Low to Medium - Depends on user behavior"
                AlertThresholds = @{
                    Low = "< 10 events/hour"
                    Normal = "10-50 events/hour"
                    High = "> 50 events/hour (Potential Attack)"
                }
            }
            4728 = @{
                Name = "Global Group Member Added"
                Description = "A member was added to a security-enabled global group"
                MDIRelevance = "High - Critical for detecting privilege escalation"
                ThreatIndicators = @("Unauthorized privilege escalation", "Admin group manipulation")
                NormalFrequency = "Very Low - Should be rare and authorized"
                AlertThresholds = @{
                    Low = "< 1 event/day"
                    Normal = "1-5 events/day"
                    High = "> 5 events/day (Investigate)"
                }
            }
            4732 = @{
                Name = "Local Group Member Added"
                Description = "A member was added to a security-enabled local group"
                MDIRelevance = "High - Indicates local privilege changes"
                ThreatIndicators = @("Local administrator abuse", "Persistence techniques")
                NormalFrequency = "Low - Should be infrequent and authorized"
                AlertThresholds = @{
                    Low = "< 1 event/day"
                    Normal = "1-3 events/day"
                    High = "> 3 events/day (Investigate)"
                }
            }
            5136 = @{
                Name = "Directory Object Modified"
                Description = "A directory service object was modified"
                MDIRelevance = "Medium - Tracks AD object changes"
                ThreatIndicators = @("Unauthorized object modifications", "Persistence through AD changes")
                NormalFrequency = "Medium - Varies based on AD activity"
                AlertThresholds = @{
                    Low = "< 20 events/hour"
                    Normal = "20-200 events/hour"
                    High = "> 200 events/hour"
                }
            }
        }
        
        # Analyze each event type for multiple timeframes
        foreach ($eventId in $mdiSecurityEvents.Keys) {
            try {
                $eventInfo = $mdiSecurityEvents[$eventId]
                
                # Collect events for different timeframes
                $last24Hours = Get-WinEvent -FilterHashtable @{
                    LogName='Security'
                    ID=$eventId
                    StartTime=(Get-Date).AddHours(-24)
                } -MaxEvents 1000 -ErrorAction SilentlyContinue
                
                $last7Days = Get-WinEvent -FilterHashtable @{
                    LogName='Security'
                    ID=$eventId
                    StartTime=(Get-Date).AddDays(-7)
                } -MaxEvents 5000 -ErrorAction SilentlyContinue
                
                # Calculate frequency analysis
                $count24h = ($last24Hours | Measure-Object).Count
                $count7d = ($last7Days | Measure-Object).Count
                $hourlyAverage = if ($count24h -gt 0) { [math]::Round($count24h / 24, 2) } else { 0 }
                $dailyAverage = if ($count7d -gt 0) { [math]::Round($count7d / 7, 2) } else { 0 }
                
                # Determine frequency assessment
                $frequencyAssessment = "Normal"
                if ($eventId -eq 4662) {
                    if ($hourlyAverage -lt 50) { $frequencyAssessment = "Low (Potential Issue)" }
                    elseif ($hourlyAverage -gt 5000) { $frequencyAssessment = "Very High (Monitor)" }
                } elseif ($eventId -eq 4771 -or $eventId -eq 4625) {
                    if ($hourlyAverage -gt 50) { $frequencyAssessment = "High (Potential Attack)" }
                } elseif ($eventId -eq 4728 -or $eventId -eq 4732) {
                    if ($count24h -gt 10) { $frequencyAssessment = "High (Investigate)" }
                }
                
                # Get recent event samples for pattern analysis
                $recentSamples = @()
                if ($last24Hours) {
                    $recentSamples = $last24Hours | Select-Object -First 5 | ForEach-Object {
                        @{
                            TimeCreated = $_.TimeCreated
                            Message = $_.Message.Substring(0, [Math]::Min(200, $_.Message.Length))
                        }
                    }
                }
                
                # Build comprehensive event analysis
                $eventAnalysis[$eventId] = @{
                    EventName = $eventInfo.Name
                    Description = $eventInfo.Description
                    MDIRelevance = $eventInfo.MDIRelevance
                    ThreatIndicators = $eventInfo.ThreatIndicators
                    Count24Hours = $count24h
                    Count7Days = $count7d
                    HourlyAverage = $hourlyAverage
                    DailyAverage = $dailyAverage
                    FrequencyAssessment = $frequencyAssessment
                    NormalFrequency = $eventInfo.NormalFrequency
                    AlertThresholds = $eventInfo.AlertThresholds
                    LastEvent = if ($last24Hours) { $last24Hours[0].TimeCreated } else { "No recent events" }
                    RecentSamples = $recentSamples
                    Status = if ($count24h -gt 0) { "Active" } else { "No Events (Potential Issue)" }
                    Recommendation = if ($count24h -eq 0 -and $eventId -in @(4662, 4776)) { 
                        "Critical: This event should be generating regularly. Check audit policy configuration." 
                    } else { "Monitor for unusual patterns" }
                }
            } catch {
                $eventAnalysis[$eventId] = @{
                    EventName = $mdiSecurityEvents[$eventId].Name
                    Status = "Error"
                    Error = $_.Exception.Message
                    Recommendation = "Unable to analyze events - check event log access permissions"
                }
            }
        }
        $results["EventAnalysis"] = $eventAnalysis
        
        # ============================================================================================
        # COMPREHENSIVE SYSTEM INFORMATION COLLECTION
        # ============================================================================================
        
        Write-Host "   💻 Collecting system information..." -ForegroundColor Gray
        try {
            $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
            $computerInfo = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
            $networkInfo = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } -ErrorAction SilentlyContinue
            
            $sysInfo = @{
                ComputerName = $env:COMPUTERNAME
                OSVersion = $osInfo.Caption
                OSBuild = $osInfo.BuildNumber
                OSArchitecture = $osInfo.OSArchitecture
                ServicePackMajorVersion = $osInfo.ServicePackMajorVersion
                LastBootTime = $osInfo.LastBootUpTime
                InstallDate = $osInfo.InstallDate
                TotalRAM = [math]::Round($computerInfo.TotalPhysicalMemory / 1GB, 2)
                Domain = $computerInfo.Domain
                DomainRole = switch ($computerInfo.DomainRole) {
                    0 { "Standalone Workstation" }
                    1 { "Member Workstation" }
                    2 { "Standalone Server" }
                    3 { "Member Server" }
                    4 { "Backup Domain Controller" }
                    5 { "Primary Domain Controller" }
                    default { "Unknown" }
                }
                TimeZone = (Get-TimeZone -ErrorAction SilentlyContinue).DisplayName
                PowerScheme = (powercfg /getactivescheme 2>$null | Select-String "Power Scheme").ToString().Split('(')[1].Replace(')', '')
                IPAddresses = ($networkInfo | ForEach-Object { $_.IPAddress } | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }) -join ', '
                DefaultGateway = ($networkInfo | ForEach-Object { $_.DefaultIPGateway } | Where-Object { $_ }) -join ', '
                DNSServers = ($networkInfo | ForEach-Object { $_.DNSServerSearchOrder } | Where-Object { $_ }) -join ', '
            }
        } catch {
            $sysInfo = @{
                Status = "Error collecting system information"
                Error = $_.Exception.Message
            }
        }
        $results["SystemInfo"] = $sysInfo
        
        # ============================================================================================
        # EVENT LOG CONFIGURATION ANALYSIS WITH RECOMMENDATIONS
        # ============================================================================================
        
        Write-Host "   📋 Analyzing event log configurations..." -ForegroundColor Gray
        $eventLogAnalysis = @{}
        $criticalEventLogs = @{
            "Security" = @{
                RecommendedMaxSizeMB = 2048
                Description = "Contains all security events including authentication and audit events"
                MDIImportance = "Critical - Primary source for MDI events"
                RetentionRecommendation = "Minimum 30 days, preferably 90 days"
            }
            "System" = @{
                RecommendedMaxSizeMB = 512
                Description = "Contains system events including service and driver information"
                MDIImportance = "Medium - Provides context for system changes"
                RetentionRecommendation = "Minimum 14 days"
            }
            "Application" = @{
                RecommendedMaxSizeMB = 512
                Description = "Contains application events and errors"
                MDIImportance = "Low - Limited MDI relevance"
                RetentionRecommendation = "Minimum 7 days"
            }
            "Microsoft-Windows-NTLM/Operational" = @{
                RecommendedMaxSizeMB = 256
                Description = "Contains detailed NTLM authentication events"
                MDIImportance = "High - Critical for NTLM attack detection"
                RetentionRecommendation = "Minimum 30 days"
            }
        }
        
        foreach ($logName in $criticalEventLogs.Keys) {
            try {
                $log = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
                $logConfig = $criticalEventLogs[$logName]
                
                if ($log) {
                    $currentSizeMB = [math]::Round($log.MaximumSizeInBytes / 1MB, 2)
                    $sizeCompliance = if ($currentSizeMB -ge $logConfig.RecommendedMaxSizeMB) { "Compliant" } else { "Too Small" }
                    $enabledCompliance = if ($log.IsEnabled) { "Enabled" } else { "Disabled (Critical Issue)" }
                    
                    # Calculate estimated retention based on current event rate
                    $recentEvents = Get-WinEvent -LogName $logName -MaxEvents 100 -ErrorAction SilentlyContinue
                    $estimatedRetentionDays = "Unknown"
                    if ($recentEvents -and $recentEvents.Count -ge 2) {
                        $timeSpan = $recentEvents[0].TimeCreated - $recentEvents[-1].TimeCreated
                        if ($timeSpan.TotalMinutes -gt 0) {
                            $eventsPerDay = ($recentEvents.Count / $timeSpan.TotalDays)
                            $estimatedRetentionDays = [math]::Round(($log.MaximumSizeInBytes / 1KB) / $eventsPerDay, 1)
                        }
                    }
                    
                    $eventLogAnalysis[$logName] = @{
                        IsEnabled = $log.IsEnabled
                        EnabledCompliance = $enabledCompliance
                        RecordCount = $log.RecordCount
                        CurrentMaxSizeMB = $currentSizeMB
                        RecommendedMaxSizeMB = $logConfig.RecommendedMaxSizeMB
                        SizeCompliance = $sizeCompliance
                        LogFilePath = $log.LogFilePath
                        LastWriteTime = $log.LastWriteTime
                        EstimatedRetentionDays = $estimatedRetentionDays
                        Description = $logConfig.Description
                        MDIImportance = $logConfig.MDIImportance
                        RetentionRecommendation = $logConfig.RetentionRecommendation
                        RemediationCommand = if ($sizeCompliance -eq "Too Small") {
                            "wevtutil sl `"$logName`" /ms:$($logConfig.RecommendedMaxSizeMB * 1024 * 1024)"
                        } else { "No action required" }
                    }
                } else {
                    $eventLogAnalysis[$logName] = @{
                        Status = "Log not found or accessible"
                        MDIImportance = $logConfig.MDIImportance
                        Recommendation = "Verify log exists and permissions are correct"
                    }
                }
            } catch {
                $eventLogAnalysis[$logName] = @{
                    Status = "Error analyzing log"
                    Error = $_.Exception.Message
                    MDIImportance = $criticalEventLogs[$logName].MDIImportance
                }
            }
        }
        $results["EventLogAnalysis"] = $eventLogAnalysis
        
        # ============================================================================================
        # MDI SENSOR PREREQUISITES CHECK
        # ============================================================================================
        
        Write-Host "   🔍 Checking MDI sensor prerequisites..." -ForegroundColor Gray
        $mdiPrerequisites = @{}
        
        # Check .NET Framework version
        try {
            $dotNetVersion = Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\" -Name Release -ErrorAction SilentlyContinue
            $dotNetVersionNumber = switch ($dotNetVersion.Release) {
                461814 { "4.7.2" }
                528040 { "4.8" }
                528049 { "4.8" }
                528372 { "4.8" }
                533320 { "4.8.1" }
                default { "Unknown ($($dotNetVersion.Release))" }
            }
            
            $mdiPrerequisites["DotNetFramework"] = @{
                Version = $dotNetVersionNumber
                Status = if ($dotNetVersion.Release -ge 461814) { "Compliant" } else { "Requires Update" }
                Requirement = ".NET Framework 4.7.2 or higher"
                Recommendation = if ($dotNetVersion.Release -lt 461814) { 
                    "Install .NET Framework 4.7.2 or higher" 
                } else { "Meets requirements" }
            }
        } catch {
            $mdiPrerequisites["DotNetFramework"] = @{
                Status = "Error checking .NET version"
                Error = $_.Exception.Message
            }
        }
        
        # Check available disk space
        try {
            $systemDrive = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 -and $_.DeviceID -eq $env:SystemDrive }
            $freeSpaceGB = [math]::Round($systemDrive.FreeSpace / 1GB, 2)
            
            $mdiPrerequisites["DiskSpace"] = @{
                FreeSpaceGB = $freeSpaceGB
                Status = if ($freeSpaceGB -ge 6) { "Sufficient" } else { "Insufficient" }
                Requirement = "Minimum 6 GB free space"
                Recommendation = if ($freeSpaceGB -lt 6) { 
                    "Free up disk space before installing MDI sensor" 
                } else { "Sufficient disk space available" }
            }
        } catch {
            $mdiPrerequisites["DiskSpace"] = @{
                Status = "Error checking disk space"
                Error = $_.Exception.Message
            }
        }
        
        # Check Windows Defender exclusions (if Windows Defender is present)
        try {
            $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
            if ($defenderStatus) {
                $exclusionPaths = Get-MpPreference -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ExclusionPath
                $mdiPath = "C:\Program Files\Azure Advanced Threat Protection Sensor"
                $hasExclusion = $exclusionPaths -contains $mdiPath
                
                $mdiPrerequisites["WindowsDefender"] = @{
                    DefenderEnabled = $defenderStatus.AntivirusEnabled
                    MDIPathExcluded = $hasExclusion
                    Status = if ($hasExclusion -or -not $defenderStatus.AntivirusEnabled) { "Configured" } else { "Needs Configuration" }
                    Recommendation = if ($defenderStatus.AntivirusEnabled -and -not $hasExclusion) {
                        "Add MDI sensor path to Windows Defender exclusions"
                    } else { "Windows Defender properly configured for MDI" }
                    RemediationCommand = "Add-MpPreference -ExclusionPath `"$mdiPath`""
                }
            } else {
                $mdiPrerequisites["WindowsDefender"] = @{
                    Status = "Windows Defender not detected"
                    Recommendation = "Verify antivirus exclusions for MDI sensor path"
                }
            }
        } catch {
            $mdiPrerequisites["WindowsDefender"] = @{
                Status = "Error checking Windows Defender"
                Error = $_.Exception.Message
            }
        }
        
        $results["MDIPrerequisites"] = $mdiPrerequisites
        
        # ============================================================================================
        # NETWORK CONFIGURATION ANALYSIS
        # ============================================================================================
        
        Write-Host "   🌐 Analyzing network configuration..." -ForegroundColor Gray
        $networkAnalysis = @{}
        
        try {
            # Check DNS configuration
            $dnsServers = (Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses }).ServerAddresses
            $networkAnalysis["DNS"] = @{
                ConfiguredServers = $dnsServers -join ', '
                Status = if ($dnsServers) { "Configured" } else { "Not Configured" }
                Recommendation = "Ensure DNS points to domain controllers for proper name resolution"
            }
            
            # Check network connectivity to common MDI endpoints
            $mdiEndpoints = @(
                "*.atp.azure.com",
                "*.atp.azure.cn", 
                "*.atp.azure.us"
            )
            
            $networkAnalysis["MDIConnectivity"] = @{
                RequiredEndpoints = $mdiEndpoints
                Status = "Manual verification required"
                Recommendation = "Verify firewall allows HTTPS (443) to MDI cloud endpoints"
                FirewallNote = "Check corporate firewall for *.atp.azure.com access"
            }
            
        } catch {
            $networkAnalysis["Error"] = $_.Exception.Message
        }
        $results["NetworkAnalysis"] = $networkAnalysis
        
        return $results
    }
    
    # ================================================================================================
    # DATA COLLECTION FROM DOMAIN CONTROLLERS
    # ================================================================================================
    
    # Execute ultra-detailed data collection on each reachable domain controller
    Write-Host "`n🔄 Collecting ultra-detailed data from domain controllers..." -ForegroundColor Cyan
    $dcConfigurationData = @{}
    
    foreach ($dc in $reachableDCs) {
        Write-Host "📡 Collecting comprehensive data from $($dc.Name)..." -ForegroundColor White
        try {
            # Execute data collection script on remote DC via PowerShell remoting
            $dcData = Invoke-Command -ComputerName $dc.Name -ScriptBlock $ultraDetailedDataCollection -ErrorAction Stop
            
            # Store collected data
            $dcConfigurationData[$dc.Name] = $dcData
            
            # Add domain controller specific information
            $dcConfigurationData[$dc.Name]["DCInfo"] = @{
                Site = $dc.Site
                IPv4Address = $dc.IPv4Address
                IPv6Address = $dc.IPv6Address
                OperationMasterRoles = ($dc.OperationMasterRoles -join ", ")
                IsGlobalCatalog = $dc.IsGlobalCatalog
                IsReadOnly = $dc.IsReadOnly
                LdapPort = $dc.LdapPort
                SslPort = $dc.SslPort
                ConnectivityStatus = $connectivityDetails[$dc.Name]
                ForestName = $forest.Name
                DomainName = $domain.Name
                DomainFunctionalLevel = $domainFunctionalLevel
                ForestFunctionalLevel = $forestFunctionalLevel
            }
            
            Write-Host "✅ Successfully collected comprehensive data from $($dc.Name)" -ForegroundColor Green
        } catch {
            Write-Host "❌ Failed to collect data from $($dc.Name): $($_.Exception.Message)" -ForegroundColor Red
            $dcConfigurationData[$dc.Name] = @{
                Status = "Failed"
                Error = $_.Exception.Message
                ConnectivityStatus = $connectivityDetails[$dc.Name]
            }
        }
    }
    
    # ================================================================================================
    # ULTRA-DETAILED ENTERPRISE COMPLIANCE ANALYSIS
    # ================================================================================================
    
    # Perform comprehensive enterprise-wide compliance analysis with detailed scoring
    Write-Host "`n📊 Performing ultra-detailed enterprise analysis..." -ForegroundColor Cyan
    
    $enterpriseAnalysis = @{}
    $successfulDCs = $dcConfigurationData.Keys | Where-Object { -not $dcConfigurationData[$_].ContainsKey("Status") }
    
    # Detailed compliance scoring system
    $complianceScoring = @{}
    $maxPossibleScore = 100
    
    # Evaluate each DC for detailed compliance scoring
    foreach ($dcName in $successfulDCs) {
        $dcData = $dcConfigurationData[$dcName]
        $dcScore = 0
        $dcDetails = @{}
        
        # Audit Policy Compliance (40 points maximum)
        $auditCompliantPolicies = ($dcData.AuditPolicies.Values | Where-Object { $_.ComplianceStatus -eq "Fully Compliant" }).Count
        $totalAuditPolicies = $dcData.AuditPolicies.Count
        $auditScore = if ($totalAuditPolicies -gt 0) { 
            [math]::Round(($auditCompliantPolicies / $totalAuditPolicies) * 40, 1) 
        } else { 0 }
        $dcScore += $auditScore
        $dcDetails["AuditPolicyScore"] = @{
            Score = $auditScore
            MaxScore = 40
            CompliantPolicies = $auditCompliantPolicies
            TotalPolicies = $totalAuditPolicies
            Details = "Critical audit policies for MDI functionality"
        }
        
        # NTLM Configuration Compliance (30 points maximum)
        $ntlmCompliantSettings = ($dcData.NTLMSettings.Values | Where-Object { $_.ComplianceStatus -eq "Fully Compliant" }).Count
        $totalNtlmSettings = $dcData.NTLMSettings.Count
        $ntlmScore = if ($totalNtlmSettings -gt 0) { 
            [math]::Round(($ntlmCompliantSettings / $totalNtlmSettings) * 30, 1) 
        } else { 0 }
        $dcScore += $ntlmScore
        $dcDetails["NTLMConfigScore"] = @{
            Score = $ntlmScore
            MaxScore = 30
            CompliantSettings = $ntlmCompliantSettings
            TotalSettings = $totalNtlmSettings
            Details = "NTLM auditing and restriction settings"
        }
        
        # Event Generation Health (20 points maximum)
        $criticalEvents = @(4662, 4776)  # Most critical for MDI
        $activeEventsScore = 0
        foreach ($eventId in $criticalEvents) {
            if ($dcData.EventAnalysis[$eventId].Count24Hours -gt 0) {
                $activeEventsScore += 10  # 10 points per critical event type
            }
        }
        $dcScore += $activeEventsScore
        $dcDetails["EventGenerationScore"] = @{
            Score = $activeEventsScore
            MaxScore = 20
            CriticalEventsActive = ($criticalEvents | Where-Object { $dcData.EventAnalysis[$_].Count24Hours -gt 0 }).Count
            TotalCriticalEvents = $criticalEvents.Count
            Details = "Active generation of critical MDI events"
        }
        
        # System Prerequisites (10 points maximum)
        $prereqScore = 0
        if ($dcData.MDIPrerequisites.DotNetFramework.Status -eq "Compliant") { $prereqScore += 5 }
        if ($dcData.MDIPrerequisites.DiskSpace.Status -eq "Sufficient") { $prereqScore += 5 }
        $dcScore += $prereqScore
        $dcDetails["PrerequisitesScore"] = @{
            Score = $prereqScore
            MaxScore = 10
            Details = "System prerequisites for MDI sensor installation"
        }
        
        # Calculate overall compliance percentage
        $compliancePercentage = [math]::Round(($dcScore / $maxPossibleScore) * 100, 1)
        
        # Determine compliance tier
        $complianceTier = if ($compliancePercentage -ge 95) { "EXCELLENT" }
                         elseif ($compliancePercentage -ge 85) { "GOOD" }
                         elseif ($compliancePercentage -ge 70) { "ACCEPTABLE" }
                         elseif ($compliancePercentage -ge 50) { "NEEDS IMPROVEMENT" }
                         else { "CRITICAL ISSUES" }
        
        $complianceScoring[$dcName] = @{
            TotalScore = $dcScore
            MaxPossibleScore = $maxPossibleScore
            CompliancePercentage = $compliancePercentage
            ComplianceTier = $complianceTier
            DetailedScores = $dcDetails
        }
    }
    
    # Calculate enterprise-wide metrics
    $overallEnterpriseScore = if ($successfulDCs.Count -gt 0) {
        ($complianceScoring.Values | ForEach-Object { $_.CompliancePercentage } | Measure-Object -Average).Average
    } else { 0 }
    
    $fullyCompliantDCs = ($complianceScoring.Values | Where-Object { $_.CompliancePercentage -ge 95 }).Count
    $goodDCs = ($complianceScoring.Values | Where-Object { $_.CompliancePercentage -ge 85 -and $_.CompliancePercentage -lt 95 }).Count
    $acceptableDCs = ($complianceScoring.Values | Where-Object { $_.CompliancePercentage -ge 70 -and $_.CompliancePercentage -lt 85 }).Count
    $problematicDCs = ($complianceScoring.Values | Where-Object { $_.CompliancePercentage -lt 70 }).Count
    
    # ================================================================================================
    # CONFIGURATION DRIFT ANALYSIS WITH DETAILED REMEDIATION
    # ================================================================================================
    
    # Enhanced configuration drift analysis with specific remediation steps
    $driftAnalysis = @{}
    
    if ($successfulDCs.Count -gt 1) {
        # Analyze audit policy drift with detailed remediation
        $auditDrift = @{}
        $allPolicies = $dcConfigurationData[$successfulDCs[0]].AuditPolicies.Keys
        
        foreach ($policy in $allPolicies) {
            $configurations = @{}
            $remediationSteps = @()
            
            # Check configuration of this policy across all DCs
            foreach ($dcName in $successfulDCs) {
                $policyData = $dcConfigurationData[$dcName].AuditPolicies[$policy]
                $config = $policyData.ComplianceStatus
                if (-not $configurations.ContainsKey($config)) {
                    $configurations[$config] = @()
                }
                $configurations[$config] += $dcName
                
                # Collect remediation steps for non-compliant DCs
                if ($config -ne "Fully Compliant") {
                    $remediationSteps += @{
                        DC = $dcName
                        CurrentSetting = $policyData.CurrentSetting
                        RequiredSetting = $policyData.RequiredSetting
                        Command = $policyData.RemediationCommand
                    }
                }
            }
            
            # If more than one configuration exists, we have drift
            if ($configurations.Keys.Count -gt 1) {
                $auditDrift[$policy] = @{
                    Configurations = $configurations
                    RemediationSteps = $remediationSteps
                    Impact = "Inconsistent audit logging may lead to blind spots in security monitoring"
                    Priority = "High"
                }
            }
        }
        if ($auditDrift.Count -gt 0) {
            $driftAnalysis["AuditPolicies"] = $auditDrift
        }
        
        # Analyze NTLM configuration drift with detailed remediation
        $ntlmDrift = @{}
        $ntlmSettings = $dcConfigurationData[$successfulDCs[0]].NTLMSettings.Keys
        
        foreach ($setting in $ntlmSettings) {
            $configurations = @{}
            $remediationSteps = @()
            
            # Check configuration of this NTLM setting across all DCs
            foreach ($dcName in $successfulDCs) {
                $ntlmData = $dcConfigurationData[$dcName].NTLMSettings[$setting]
                $config = $ntlmData.ComplianceStatus
                if (-not $configurations.ContainsKey($config)) {
                    $configurations[$config] = @()
                }
                $configurations[$config] += $dcName
                
                # Collect remediation steps for non-compliant DCs
                if ($config -ne "Fully Compliant") {
                    $remediationSteps += @{
                        DC = $dcName
                        CurrentValue = $ntlmData.CurrentValue
                        ExpectedValue = $ntlmData.ExpectedValue
                        RegistryPath = $ntlmData.RegistryPath
                        Command = $ntlmData.RemediationCommand
                    }
                }
            }
            
            # If more than one configuration exists, we have drift
            if ($configurations.Keys.Count -gt 1) {
                $ntlmDrift[$setting] = @{
                    Configurations = $configurations
                    RemediationSteps = $remediationSteps
                    Impact = "Inconsistent NTLM settings may prevent proper attack detection"
                    Priority = "Critical"
                }
            }
        }
        if ($ntlmDrift.Count -gt 0) {
            $driftAnalysis["NTLMSettings"] = $ntlmDrift
        }
    }
    
    # Build comprehensive enterprise analysis
    $enterpriseAnalysis = @{
        OverallScore = [math]::Round($overallEnterpriseScore, 1)
        ComplianceDistribution = @{
            Excellent = $fullyCompliantDCs
            Good = $goodDCs
            Acceptable = $acceptableDCs
            Problematic = $problematicDCs
        }
        DetailedScoring = $complianceScoring
        ConfigurationDrift = $driftAnalysis
        TotalDCs = $successfulDCs.Count
        UnreachableDCs = $unreachableDCs.Count
        TotalEvents24h = if ($successfulDCs.Count -gt 0) {
            ($dcConfigurationData[$successfulDCs[0]].EventAnalysis.Values | ForEach-Object { $_.Count24Hours } | Measure-Object -Sum).Sum * $successfulDCs.Count
        } else { 0 }
        EnterpriseStatus = if ($overallEnterpriseScore -ge 95) { "ENTERPRISE READY" }
                          elseif ($overallEnterpriseScore -ge 85) { "MOSTLY READY" }
                          elseif ($overallEnterpriseScore -ge 70) { "NEEDS ATTENTION" }
                          else { "CRITICAL ISSUES" }
    }
    
    # ================================================================================================
    # ULTRA-DETAILED REPORT GENERATION
    # ================================================================================================
    
    # Generate ultra-detailed HTML report
    if ($Format -eq "HTML" -or $Format -eq "All") {
        $htmlFile = Join-Path $OutputPath "$reportBaseName.html"
        
        # Generate comprehensive HTML content
        $htmlContent = Generate-UltraDetailedEnterpriseHTML -Domain $domain -Forest $forest -DCData $dcConfigurationData -SuccessfulDCs $successfulDCs -Analysis $enterpriseAnalysis -UnreachableDCs $unreachableDCs -ConnectivityDetails $connectivityDetails -IncludeRemediation $IncludeRemediationSteps
        
        # Save with UTF-8 encoding
        $htmlContent | Out-File -FilePath $htmlFile -Encoding UTF8
        Write-Host "✅ Ultra-detailed enterprise HTML report generated: $htmlFile" -ForegroundColor Green
        
        # Open report if requested
        if ($OpenReport) {
            try {
                Start-Process $htmlFile
                Write-Host "🚀 Opening ultra-detailed report: $htmlFile" -ForegroundColor Green
            } catch {
                Write-Host "📄 Report saved to: $htmlFile" -ForegroundColor Cyan
            }
        }
    }
    
    # ================================================================================================
    # COMPLETION AND EXECUTIVE SUMMARY
    # ================================================================================================
    
    Write-Host "`n🎉 Ultra-Detailed Enterprise Assessment Complete!" -ForegroundColor Green
    Write-Host "====================================================" -ForegroundColor Green
    Write-Host "🏆 Enterprise Status: $($enterpriseAnalysis.EnterpriseStatus)" -ForegroundColor $(if($enterpriseAnalysis.OverallScore -ge 85){"Green"}else{"Yellow"})
    Write-Host "📊 Overall Score: $($enterpriseAnalysis.OverallScore)% ($(if($enterpriseAnalysis.OverallScore -ge 85){"Ready for MDI"}else{"Needs Remediation"}))" -ForegroundColor $(if($enterpriseAnalysis.OverallScore -ge 85){"Green"}else{"Yellow"})
    Write-Host "🎯 DC Distribution:" -ForegroundColor Cyan
    Write-Host "   • Excellent (95%+): $($enterpriseAnalysis.ComplianceDistribution.Excellent) DCs" -ForegroundColor Green
    Write-Host "   • Good (85-94%): $($enterpriseAnalysis.ComplianceDistribution.Good) DCs" -ForegroundColor Yellow
    Write-Host "   • Acceptable (70-84%): $($enterpriseAnalysis.ComplianceDistribution.Acceptable) DCs" -ForegroundColor Orange
    Write-Host "   • Problematic (<70%): $($enterpriseAnalysis.ComplianceDistribution.Problematic) DCs" -ForegroundColor Red
    
    if ($enterpriseAnalysis.ConfigurationDrift.Count -gt 0) {
        Write-Host "⚠️  Configuration drift detected across $($enterpriseAnalysis.ConfigurationDrift.Count) setting types" -ForegroundColor Yellow
        Write-Host "   📋 See detailed remediation steps in the report" -ForegroundColor Cyan
    }
    
    Write-Host "`n📈 Key Recommendations:" -ForegroundColor Cyan
    if ($enterpriseAnalysis.OverallScore -lt 85) {
        Write-Host "   1. Review and implement audit policy recommendations" -ForegroundColor White
        Write-Host "   2. Configure NTLM auditing settings on all DCs" -ForegroundColor White
        Write-Host "   3. Verify event generation for critical MDI events" -ForegroundColor White
    }
    if ($enterpriseAnalysis.ConfigurationDrift.Count -gt 0) {
        Write-Host "   4. Standardize configurations across all domain controllers" -ForegroundColor White
    }
    Write-Host "   5. Review detailed report for specific remediation commands" -ForegroundColor White
    
    return @{
        EnterpriseStatus = $enterpriseAnalysis.EnterpriseStatus
        OverallScore = $enterpriseAnalysis.OverallScore
        ComplianceDistribution = $enterpriseAnalysis.ComplianceDistribution
        ConfigurationDrift = $enterpriseAnalysis.ConfigurationDrift
        ReportFile = $htmlFile
        DetailedResults = $enterpriseAnalysis
    }
}

# ================================================================================================
# ULTRA-DETAILED HTML REPORT GENERATION FUNCTION
# ================================================================================================

function Generate-UltraDetailedEnterpriseHTML {
    <#
    .SYNOPSIS
    Generates ultra-detailed HTML report with comprehensive analysis and remediation steps
    
    .DESCRIPTION
    Creates an ultra-detailed HTML report with enterprise overview, per-DC analysis, 
    detailed explanations, security implications, and specific remediation commands
    #>
    
    param($Domain, $Forest, $DCData, $SuccessfulDCs, $Analysis, $UnreachableDCs, $ConnectivityDetails, $IncludeRemediation)
    
    # Determine overall styling class based on enterprise score
    $overallClass = switch ($Analysis.EnterpriseStatus) {
        "ENTERPRISE READY" { "excellent" }
        "MOSTLY READY" { "good" }
        "NEEDS ATTENTION" { "warning" }
        "CRITICAL ISSUES" { "critical" }
        default { "warning" }
    }
    
    # Generate comprehensive HTML content
    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MDI Ultra-Detailed Enterprise Report - $($Domain.DNSRoot)</title>
    <style>
        /* =========================================================================================== */
        /* ULTRA-DETAILED ENTERPRISE REPORT STYLING */
        /* =========================================================================================== */
        
        body { 
            font-family: 'Segoe UI', 'Roboto', Arial, sans-serif; 
            margin: 0; 
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            line-height: 1.6;
            color: #333;
        }
        
        .container { 
            max-width: 1600px; 
            margin: 0 auto; 
            background-color: white; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.1); 
            border-radius: 10px;
            overflow: hidden;
        }
        
        .header { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; 
            padding: 40px; 
            text-align: center;
        }
        
        .header h1 { 
            margin: 0; 
            font-size: 36px; 
            font-weight: 300;
        }
        
        .header .subtitle {
            font-size: 18px;
            opacity: 0.9;
            margin-top: 10px;
        }
        
        .header .enterprise-info {
            background: rgba(255,255,255,0.1);
            padding: 20px;
            border-radius: 10px;
            margin-top: 20px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
        }
        
        .header .info-item {
            text-align: center;
        }
        
        .header .info-item .label {
            font-size: 12px;
            opacity: 0.8;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .header .info-item .value {
            font-size: 18px;
            font-weight: 600;
            margin-top: 5px;
        }
        
        .section { 
            margin: 0; 
            padding: 30px; 
            border-bottom: 1px solid #e0e0e0; 
        }
        
        .section:last-child { 
            border-bottom: none; 
        }
        
        .section h2 { 
            color: #667eea; 
            margin-top: 0; 
            margin-bottom: 25px; 
            font-size: 28px;
            font-weight: 300;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        
        .section h3 { 
            color: #333; 
            margin-top: 25px; 
            margin-bottom: 15px; 
            font-size: 20px;
            font-weight: 500;
        }
        
        .section h4 {
            color: #555;
            margin-top: 20px;
            margin-bottom: 10px;
            font-size: 16px;
            font-weight: 600;
        }
        
        /* Enhanced status indicator classes */
        .status-excellent { color: #27ae60; font-weight: bold; }
        .status-good { color: #2ecc71; font-weight: bold; }
        .status-warning { color: #f39c12; font-weight: bold; }
        .status-critical { color: #e74c3c; font-weight: bold; }
        .status-error { color: #c0392b; font-weight: bold; }
        
        /* Enhanced table styling */
        table { 
            border-collapse: collapse; 
            width: 100%; 
            margin-bottom: 25px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }
        
        th, td { 
            border: 1px solid #ddd; 
            padding: 15px; 
            text-align: left; 
        }
        
        th { 
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            font-weight: 600;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        tr:nth-child(even) { 
            background-color: #f8f9ff; 
        }
        
        tr:hover {
            background-color: #e8f0fe;
            transition: background-color 0.3s ease;
        }
        
        /* Enhanced compliance dashboard */
        .enterprise-dashboard { 
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 25px; 
            margin-bottom: 30px; 
        }
        
        .dashboard-card { 
            padding: 25px; 
            border-radius: 15px; 
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }
        
        .dashboard-card:hover {
            transform: translateY(-5px);
        }
        
        .excellent { 
            background: linear-gradient(135deg, #a8e6cf, #7fcdcd);
            border: 2px solid #27ae60; 
        }
        
        .good { 
            background: linear-gradient(135deg, #dcedc1, #a8e6cf);
            border: 2px solid #2ecc71; 
        }
        
        .warning { 
            background: linear-gradient(135deg, #ffd93d, #ff6b6b);
            border: 2px solid #f39c12; 
        }
        
        .critical { 
            background: linear-gradient(135deg, #ff6b6b, #ee5a24);
            border: 2px solid #e74c3c; 
        }
        
        .card-title {
            font-weight: 600;
            font-size: 16px;
            margin-bottom: 10px;
            color: #2c3e50;
        }
        
        .card-value {
            font-size: 32px;
            font-weight: 700;
            margin: 10px 0;
            color: #2c3e50;
        }
        
        .card-subtitle {
            font-size: 14px;
            opacity: 0.8;
            color: #2c3e50;
        }
        
        /* Enhanced DC section styling */
        .dc-section { 
            margin: 30px 0; 
            border: 2px solid #667eea; 
            border-radius: 15px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .dc-header { 
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white; 
            padding: 20px; 
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .dc-title {
            font-size: 24px;
            font-weight: 300;
        }
        
        .dc-score {
            background: rgba(255,255,255,0.2);
            padding: 10px 20px;
            border-radius: 25px;
            font-size: 18px;
            font-weight: 600;
        }
        
        .dc-content {
            padding: 25px;
        }
        
        .subsection { 
            margin: 25px 0;
            padding: 20px;
            background: #f8f9ff;
            border-radius: 10px;
            border-left: 4px solid #667eea;
        }
        
        .drift-alert { 
            background: linear-gradient(135deg, #fff3cd, #fce4a6);
            border: 2px solid #f39c12; 
            border-radius: 10px; 
            padding: 20px; 
            margin: 15px 0;
            box-shadow: 0 3px 10px rgba(243, 156, 18, 0.2);
        }
        
        .remediation-section {
            background: linear-gradient(135deg, #e8f5e8, #c8e6c9);
            border: 2px solid #4caf50;
            border-radius: 10px;
            padding: 20px;
            margin: 15px 0;
        }
        
        .code-block {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 14px;
            margin: 10px 0;
            overflow-x: auto;
        }
        
        .explanation-box {
            background: linear-gradient(135deg, #e3f2fd, #bbdefb);
            border-left: 4px solid #2196f3;
            padding: 15px;
            margin: 15px 0;
            border-radius: 0 5px 5px 0;
        }
        
        .security-impact {
            background: linear-gradient(135deg, #ffebee, #ffcdd2);
            border-left: 4px solid #f44336;
            padding: 15px;
            margin: 15px 0;
            border-radius: 0 5px 5px 0;
        }
        
        .progress-bar {
            background: #ecf0f1;
            border-radius: 10px;
            height: 20px;
            margin: 10px 0;
            overflow: hidden;
        }
        
        .progress-fill {
            height: 100%;
            border-radius: 10px;
            transition: width 0.3s ease;
        }
        
        .progress-excellent { background: linear-gradient(90deg, #27ae60, #2ecc71); }
        .progress-good { background: linear-gradient(90deg, #f39c12, #e67e22); }
        .progress-warning { background: linear-gradient(90deg, #e74c3c, #c0392b); }
        
        .footer { 
            background: linear-gradient(135deg, #34495e, #2c3e50);
            color: white;
            padding: 30px; 
            text-align: center; 
        }
        
        .footer a {
            color: #3498db;
            text-decoration: none;
        }
        
        .footer a:hover {
            text-decoration: underline;
        }
        
        /* Responsive design */
        @media (max-width: 768px) {
            .enterprise-dashboard {
                grid-template-columns: 1fr;
            }
            
            .header .enterprise-info {
                grid-template-columns: 1fr;
            }
            
            .dc-header {
                flex-direction: column;
                text-align: center;
            }
            
            .dc-score {
                margin-top: 10px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- =========================================================================================== -->
        <!-- ENHANCED HEADER SECTION -->
        <!-- =========================================================================================== -->
        <div class="header">
            <h1>🛡️ MDI Ultra-Detailed Enterprise Report</h1>
            <div class="subtitle">Comprehensive Microsoft Defender for Identity Configuration Analysis</div>
            <div class="enterprise-info">
                <div class="info-item">
                    <div class="label">Domain</div>
                    <div class="value">$($Domain.DNSRoot)</div>
                </div>
                <div class="info-item">
                    <div class="label">Forest</div>
                    <div class="value">$($Forest.Name)</div>
                </div>
                <div class="info-item">
                    <div class="label">Report Generated</div>
                    <div class="value">$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div>
                </div>
                <div class="info-item">
                    <div class="label">Domain Controllers</div>
                    <div class="value">$(($SuccessfulDCs.Count + $UnreachableDCs.Count)) Total</div>
                </div>
                <div class="info-item">
                    <div class="label">Overall Score</div>
                    <div class="value">$($Analysis.OverallScore)%</div>
                </div>
                <div class="info-item">
                    <div class="label">Enterprise Status</div>
                    <div class="value">$($Analysis.EnterpriseStatus)</div>
                </div>
            </div>
        </div>
        
        <!-- =========================================================================================== -->
        <!-- ENHANCED ENTERPRISE DASHBOARD -->
        <!-- =========================================================================================== -->
        <div class="section">
            <h2>🎯 Enterprise Compliance Dashboard</h2>
            <div class="enterprise-dashboard">
                <div class="dashboard-card $overallClass">
                    <div class="card-title">Overall Enterprise Score</div>
                    <div class="card-value">$($Analysis.OverallScore)%</div>
                    <div class="card-subtitle">$($Analysis.EnterpriseStatus)</div>
                    <div class="progress-bar">
                        <div class="progress-fill progress-$(if($Analysis.OverallScore -ge 85){"excellent"}elseif($Analysis.OverallScore -ge 70){"good"}else{"warning"})" style="width: $($Analysis.OverallScore)%"></div>
                    </div>
                </div>
                <div class="dashboard-card excellent">
                    <div class="card-title">Excellent DCs (95%+)</div>
                    <div class="card-value">$($Analysis.ComplianceDistribution.Excellent)</div>
                    <div class="card-subtitle">Fully MDI Ready</div>
                </div>
                <div class="dashboard-card good">
                    <div class="card-title">Good DCs (85-94%)</div>
                    <div class="card-value">$($Analysis.ComplianceDistribution.Good)</div>
                    <div class="card-subtitle">Minor Issues</div>
                </div>
                <div class="dashboard-card warning">
                    <div class="card-title">Needs Attention (70-84%)</div>
                    <div class="card-value">$($Analysis.ComplianceDistribution.Acceptable)</div>
                    <div class="card-subtitle">Moderate Issues</div>
                </div>
                <div class="dashboard-card critical">
                    <div class="card-title">Critical Issues (<70%)</div>
                    <div class="card-value">$($Analysis.ComplianceDistribution.Problematic)</div>
                    <div class="card-subtitle">Immediate Action Required</div>
                </div>
                <div class="dashboard-card">
                    <div class="card-title">Configuration Drift</div>
                    <div class="card-value">$($Analysis.ConfigurationDrift.Count)</div>
                    <div class="card-subtitle">Inconsistencies Detected</div>
                </div>
                <div class="dashboard-card">
                    <div class="card-title">Reachable DCs</div>
                    <div class="card-value">$($SuccessfulDCs.Count)</div>
                    <div class="card-subtitle">of $(($SuccessfulDCs.Count + $UnreachableDCs.Count)) Total</div>
                </div>
            </div>
        </div>
"@

    # Add configuration drift section if any drift detected
    if ($Analysis.ConfigurationDrift.Count -gt 0) {
        $htmlContent += @"
        <!-- =========================================================================================== -->
        <!-- ENHANCED CONFIGURATION DRIFT ANALYSIS -->
        <!-- =========================================================================================== -->
        <div class="section">
            <h2>⚠️ Configuration Drift Analysis</h2>
            <div class="drift-alert">
                <h3>🔍 Configuration Inconsistencies Detected</h3>
                <p><strong>Impact:</strong> Configuration drift can lead to security blind spots and inconsistent threat detection capabilities across your domain controllers.</p>
                <p><strong>Resolution Priority:</strong> High - Standardize configurations to ensure consistent MDI functionality.</p>
            </div>
"@
        
        foreach ($driftType in $Analysis.ConfigurationDrift.Keys) {
            $htmlContent += "<h3>📊 $driftType Configuration Drift</h3>"
            
            foreach ($setting in $Analysis.ConfigurationDrift[$driftType].Keys) {
                $driftInfo = $Analysis.ConfigurationDrift[$driftType][$setting]
                
                $htmlContent += @"
                <div class="subsection">
                    <h4>Setting: $setting</h4>
                    <div class="security-impact">
                        <strong>Security Impact:</strong> $($driftInfo.Impact)
                    </div>
                    <p><strong>Priority:</strong> $($driftInfo.Priority)</p>
                    
                    <h5>Current Configuration Distribution:</h5>
                    <ul>
"@
                foreach ($configType in $driftInfo.Configurations.Keys) {
                    $dcList = $driftInfo.Configurations[$configType] -join ', '
                    $htmlContent += "<li><strong>${configType}:</strong> $dcList</li>"
                }
                
                $htmlContent += "</ul>"
                
                # Add remediation steps if available and requested
                if ($IncludeRemediation -and $driftInfo.RemediationSteps.Count -gt 0) {
                    $htmlContent += @"
                    <div class="remediation-section">
                        <h5>🔧 Remediation Steps:</h5>
"@
                    foreach ($step in $driftInfo.RemediationSteps) {
                        $htmlContent += @"
                        <p><strong>DC: $($step.DC)</strong></p>
                        <p>Current: $($step.CurrentValue) → Expected: $($step.ExpectedValue)</p>
                        <div class="code-block">$($step.Command)</div>
"@
                    }
                    $htmlContent += "</div>"
                }
                
                $htmlContent += "</div>"
            }
        }
        
        $htmlContent += "</div>"
    }

    # Add detailed DC sections
    $htmlContent += @"
        <!-- =========================================================================================== -->
        <!-- ULTRA-DETAILED DOMAIN CONTROLLER ANALYSIS -->
        <!-- =========================================================================================== -->
        <div class="section">
            <h2>🔍 Ultra-Detailed Domain Controller Analysis</h2>
            <div class="explanation-box">
                <h4>📋 Analysis Overview</h4>
                <p>This section provides comprehensive analysis of each domain controller's MDI readiness, including detailed configuration status, security implications, and specific remediation steps.</p>
                <p><strong>Scoring System:</strong> Each DC is scored out of 100 points across four critical areas: Audit Policies (40 pts), NTLM Configuration (30 pts), Event Generation (20 pts), and System Prerequisites (10 pts).</p>
            </div>
"@

    # Generate ultra-detailed section for each domain controller
    foreach ($dcName in $SuccessfulDCs) {
        $dcData = $DCData[$dcName]
        $dcScoring = $Analysis.DetailedScoring[$dcName]
        
        # Determine DC status class based on score
        $dcStatusClass = if ($dcScoring.CompliancePercentage -ge 95) { "excellent" }
                        elseif ($dcScoring.CompliancePercentage -ge 85) { "good" }
                        elseif ($dcScoring.CompliancePercentage -ge 70) { "warning" }
                        else { "critical" }
        
        $htmlContent += @"
            <!-- Domain Controller: $dcName -->
            <div class="dc-section">
                <div class="dc-header">
                    <div class="dc-title">🖥️ $dcName</div>
                    <div class="dc-score">Score: $($dcScoring.CompliancePercentage)% ($($dcScoring.ComplianceTier))</div>
                </div>
                <div class="dc-content">
                    
                    <!-- Enhanced System Information -->
                    <div class="subsection">
                        <h3>🔧 System Configuration Details</h3>
                        <table>
                            <tr><th>Property</th><th>Value</th><th>Assessment</th></tr>
                            <tr><td>Site</td><td>$($dcData.DCInfo.Site)</td><td>Network Location</td></tr>
                            <tr><td>IP Address</td><td>$($dcData.DCInfo.IPv4Address)</td><td>Primary Network Interface</td></tr>
                            <tr><td>Operating System</td><td>$($dcData.SystemInfo.OSVersion) (Build $($dcData.SystemInfo.OSBuild))</td><td>$(if($dcData.SystemInfo.OSBuild -ge 17763){"✅ Modern OS"}else{"⚠️ Consider Upgrade"})</td></tr>
                            <tr><td>Last Boot</td><td>$($dcData.SystemInfo.LastBootTime)</td><td>System Uptime</td></tr>
                            <tr><td>Total RAM</td><td>$($dcData.SystemInfo.TotalRAM) GB</td><td>$(if($dcData.SystemInfo.TotalRAM -ge 8){"✅ Sufficient"}else{"⚠️ Consider Upgrade"})</td></tr>
                            <tr><td>Domain Role</td><td>$($dcData.SystemInfo.DomainRole)</td><td>Active Directory Role</td></tr>
                            <tr><td>FSMO Roles</td><td>$($dcData.DCInfo.OperationMasterRoles)</td><td>$(if($dcData.DCInfo.OperationMasterRoles -ne ""){"🎯 FSMO Holder"}else{"Standard DC"})</td></tr>
                            <tr><td>Global Catalog</td><td>$($dcData.DCInfo.IsGlobalCatalog)</td><td>$(if($dcData.DCInfo.IsGlobalCatalog){"🌐 Global Catalog Server"}else{"Local Catalog Only"})</td></tr>
                            <tr><td>Functional Level</td><td>Domain: $($dcData.DCInfo.DomainFunctionalLevel) | Forest: $($dcData.DCInfo.ForestFunctionalLevel)</td><td>Compatibility Level</td></tr>
                        </table>
                    </div>
                    
                    <!-- Ultra-Detailed Audit Policy Analysis -->
                    <div class="subsection">
                        <h3>📋 Ultra-Detailed Audit Policy Configuration</h3>
                        <div class="explanation-box">
                            <h4>🎯 Audit Policy Importance for MDI</h4>
                            <p>Audit policies are the foundation of MDI's detection capabilities. Each policy enables specific security events that MDI analyzes to detect threats and suspicious activities.</p>
                            <p><strong>Score: $($dcScoring.DetailedScores.AuditPolicyScore.Score)/$($dcScoring.DetailedScores.AuditPolicyScore.MaxScore) points</strong> ($($dcScoring.DetailedScores.AuditPolicyScore.CompliantPolicies) of $($dcScoring.DetailedScores.AuditPolicyScore.TotalPolicies) policies compliant)</p>
                        </div>
                        <table>
                            <tr><th>Policy</th><th>Current Setting</th><th>Status</th><th>Risk Level</th><th>MDI Events</th><th>Threat Detection</th></tr>
"@
        
        # Add ultra-detailed audit policy rows
        foreach ($policyName in $dcData.AuditPolicies.Keys | Sort-Object) {
            $policy = $dcData.AuditPolicies[$policyName]
            $statusClass = switch ($policy.ComplianceStatus) {
                "Fully Compliant" { "status-excellent" }
                "Partially Compliant" { "status-warning" }
                "Non-Compliant" { "status-critical" }
                default { "status-error" }
            }
            $riskClass = switch ($policy.RiskLevel) {
                "Low" { "status-excellent" }
                "Medium" { "status-warning" }
                "High" { "status-critical" }
                "Critical" { "status-critical" }
                default { "status-error" }
            }
            
            $eventIds = if ($policy.MDIEventIDs) { ($policy.MDIEventIDs -join ', ') } else { "N/A" }
            $threats = if ($policy.ThreatDetection) { ($policy.ThreatDetection -join ', ') } else { "N/A" }
            
            $htmlContent += "<tr><td><strong>$policyName</strong><br><small>$($policy.Description)</small></td><td>$($policy.CurrentSetting)</td><td class='$statusClass'>$($policy.ComplianceStatus)</td><td class='$riskClass'>$($policy.RiskLevel)</td><td>$eventIds</td><td>$threats</td></tr>"
            
            # Add remediation command if available and requested
            if ($IncludeRemediation -and $policy.ComplianceStatus -ne "Fully Compliant" -and $policy.RemediationCommand) {
                $htmlContent += "<tr><td colspan='6'><div class='remediation-section'><strong>🔧 Remediation Command:</strong><div class='code-block'>$($policy.RemediationCommand)</div></div></td></tr>"
            }
        }
        
        $htmlContent += @"
                        </table>
                        
                        <!-- Security Implications Box -->
                        <div class="security-impact">
                            <h4>🛡️ Security Implications</h4>
                            <p>Non-compliant audit policies significantly impact MDI's ability to detect advanced threats. Missing events can create blind spots in your security monitoring, allowing attackers to operate undetected.</p>
                            <ul>
                                <li><strong>Directory Service Access (4662):</strong> Critical for detecting LDAP-based reconnaissance and data exfiltration</li>
                                <li><strong>Credential Validation (4776):</strong> Essential for identifying credential-based attacks like Pass-the-Hash</li>
                                <li><strong>Kerberos Events (4768/4769):</strong> Required for detecting Kerberoasting and Golden/Silver ticket attacks</li>
                            </ul>
                        </div>
                    </div>
                    
                    <!-- Ultra-Detailed NTLM Configuration Analysis -->
                    <div class="subsection">
                        <h3>🔐 Ultra-Detailed NTLM Configuration Analysis</h3>
                        <div class="explanation-box">
                            <h4>🎯 NTLM Configuration Importance for MDI</h4>
                            <p>NTLM auditing configurations are crucial for MDI to detect NTLM-based attacks including Pass-the-Hash, NTLM Relay, and credential stuffing attacks.</p>
                            <p><strong>Score: $($dcScoring.DetailedScores.NTLMConfigScore.Score)/$($dcScoring.DetailedScores.NTLMConfigScore.MaxScore) points</strong> ($($dcScoring.DetailedScores.NTLMConfigScore.CompliantSettings) of $($dcScoring.DetailedScores.NTLMConfigScore.TotalSettings) settings compliant)</p>
                        </div>
                        <table>
                            <tr><th>Setting</th><th>Current</th><th>Expected</th><th>Status</th><th>Registry Path</th><th>MDI Impact</th></tr>
"@
        
        # Add ultra-detailed NTLM configuration rows
        foreach ($settingName in $dcData.NTLMSettings.Keys | Sort-Object) {
            $ntlmSetting = $dcData.NTLMSettings[$settingName]
            $statusClass = switch ($ntlmSetting.ComplianceStatus) {
                "Fully Compliant" { "status-excellent" }
                "Non-Compliant" { "status-critical" }
                "Not Configured" { "status-critical" }
                default { "status-error" }
            }
            
            $htmlContent += @"
            <tr>
                <td><strong>$settingName</strong><br><small>$($ntlmSetting.Description)</small></td>
                <td>$($ntlmSetting.CurrentValueDescription)</td>
                <td>$($ntlmSetting.ExpectedValueDescription)</td>
                <td class='$statusClass'>$($ntlmSetting.ComplianceStatus)</td>
                <td><code>$($ntlmSetting.RegistryPath)</code></td>
                <td>$($ntlmSetting.MDIRequirement)</td>
            </tr>
"@
            
            # Add remediation command if available and requested
            if ($IncludeRemediation -and $ntlmSetting.ComplianceStatus -ne "Fully Compliant" -and $ntlmSetting.RemediationCommand) {
                $htmlContent += @"
                <tr><td colspan='6'>
                    <div class='remediation-section'>
                        <strong>🔧 Remediation Commands:</strong>
                        <div class='code-block'>$($ntlmSetting.RemediationCommand)</div>
                        <strong>Verification:</strong>
                        <div class='code-block'>$($ntlmSetting.VerificationCommand)</div>
                        <div class="security-impact">
                            <strong>Security Impact:</strong> $($ntlmSetting.SecurityImplication)<br>
                            <strong>Threat Detection:</strong> $($ntlmSetting.ThreatDetection)
                        </div>
                    </div>
                </td></tr>
"@
            }
        }
        
        $htmlContent += @"
                        </table>
                    </div>
                    
                    <!-- Ultra-Detailed Event Analysis -->
                    <div class="subsection">
                        <h3>📊 Ultra-Detailed Security Event Analysis</h3>
                        <div class="explanation-box">
                            <h4>📈 Event Generation Assessment</h4>
                            <p>Active security event generation is the lifeblood of MDI threat detection. This analysis shows event frequency patterns and identifies potential issues.</p>
                            <p><strong>Score: $($dcScoring.DetailedScores.EventGenerationScore.Score)/$($dcScoring.DetailedScores.EventGenerationScore.MaxScore) points</strong> ($($dcScoring.DetailedScores.EventGenerationScore.CriticalEventsActive) of $($dcScoring.DetailedScores.EventGenerationScore.TotalCriticalEvents) critical events active)</p>
                        </div>
                        <table>
                            <tr><th>Event ID</th><th>Description</th><th>24h Count</th><th>7d Average</th><th>Frequency Assessment</th><th>MDI Relevance</th><th>Status</th></tr>
"@
        
        # Add ultra-detailed event analysis rows
        foreach ($eventId in ($dcData.EventAnalysis.Keys | Sort-Object)) {
            $eventData = $dcData.EventAnalysis[$eventId]
            $statusClass = switch ($eventData.Status) {
                "Active" { "status-excellent" }
                "No Events (Potential Issue)" { "status-critical" }
                "Error" { "status-error" }
                default { "status-warning" }
            }
            
            $frequencyClass = switch ($eventData.FrequencyAssessment) {
                { $_ -match "Normal" } { "status-excellent" }
                { $_ -match "High.*Attack" } { "status-critical" }
                { $_ -match "Low.*Issue" } { "status-warning" }
                default { "status-good" }
            }
            
            $htmlContent += @"
            <tr>
                <td><strong>$eventId</strong></td>
                <td>$($eventData.EventName)<br><small>$($eventData.Description)</small></td>
                <td>$($eventData.Count24Hours)</td>
                <td>$($eventData.DailyAverage)</td>
                <td class='$frequencyClass'>$($eventData.FrequencyAssessment)</td>
                <td>$($eventData.MDIRelevance)</td>
                <td class='$statusClass'>$($eventData.Status)</td>
            </tr>
"@
            
            # Add detailed analysis for critical events
            if ($eventId -in @(4662, 4776, 8004) -and $eventData.RecentSamples.Count -gt 0) {
                $htmlContent += @"
                <tr><td colspan='7'>
                    <div class="explanation-box">
                        <strong>🔍 Detailed Analysis for Event ${eventId}:</strong><br>
                        <strong>Normal Frequency:</strong> $($eventData.NormalFrequency)<br>
                        <strong>Threat Indicators:</strong> $($eventData.ThreatIndicators -join ', ')<br>
                        <strong>Recommendation:</strong> $($eventData.Recommendation)
"@
                if ($eventData.RecentSamples.Count -gt 0) {
                    $htmlContent += "<br><strong>Recent Event Sample:</strong> $($eventData.RecentSamples[0].TimeCreated)"
                }
                $htmlContent += "</div></td></tr>"
            }
        }
        
        $htmlContent += @"
                        </table>
                    </div>
                    
                    <!-- MDI Prerequisites Analysis -->
                    <div class="subsection">
                        <h3>🔧 MDI Sensor Prerequisites Analysis</h3>
                        <div class="explanation-box">
                            <h4>📋 System Readiness for MDI Sensor Installation</h4>
                            <p>These prerequisites ensure successful MDI sensor deployment and optimal performance.</p>
                            <p><strong>Score: $($dcScoring.DetailedScores.PrerequisitesScore.Score)/$($dcScoring.DetailedScores.PrerequisitesScore.MaxScore) points</strong></p>
                        </div>
                        <table>
                            <tr><th>Prerequisite</th><th>Current Status</th><th>Requirement</th><th>Assessment</th><th>Recommendation</th></tr>
"@
        
        # Add MDI prerequisites analysis
        foreach ($prereqName in $dcData.MDIPrerequisites.Keys | Sort-Object) {
            $prereq = $dcData.MDIPrerequisites[$prereqName]
            $statusClass = switch ($prereq.Status) {
                { $_ -match "Compliant|Sufficient|Configured" } { "status-excellent" }
                { $_ -match "Requires|Needs|Insufficient" } { "status-warning" }
                default { "status-critical" }
            }
            
            $htmlContent += @"
            <tr>
                <td><strong>$prereqName</strong></td>
                <td>$(if($prereq.Version){$prereq.Version}elseif($prereq.FreeSpaceGB){"$($prereq.FreeSpaceGB) GB"}elseif($prereq.DefenderEnabled -ne $null){"Defender: $($prereq.DefenderEnabled)"}else{$prereq.Status})</td>
                <td>$($prereq.Requirement)</td>
                <td class='$statusClass'>$($prereq.Status)</td>
                <td>$($prereq.Recommendation)</td>
            </tr>
"@
            
            # Add remediation command if available
            if ($IncludeRemediation -and $prereq.RemediationCommand) {
                $htmlContent += "<tr><td colspan='5'><div class='remediation-section'><strong>🔧 Remediation:</strong><div class='code-block'>$($prereq.RemediationCommand)</div></div></td></tr>"
            }
        }
        
        $htmlContent += @"
                        </table>
                    </div>
                    
                    <!-- Event Log Configuration Analysis -->
                    <div class="subsection">
                        <h3>📋 Event Log Configuration Analysis</h3>
                        <div class="explanation-box">
                            <h4>📊 Event Log Capacity and Retention Analysis</h4>
                            <p>Proper event log sizing ensures adequate retention of security events for MDI analysis and forensic investigations.</p>
                        </div>
                        <table>
                            <tr><th>Log Name</th><th>Status</th><th>Records</th><th>Size (MB)</th><th>Recommended (MB)</th><th>Estimated Retention</th><th>MDI Importance</th></tr>
"@
        
        # Add event log configuration analysis
        foreach ($logName in $dcData.EventLogAnalysis.Keys | Sort-Object) {
            $logData = $dcData.EventLogAnalysis[$logName]
            
            if ($logData.Status -and $logData.Status -match "Error|not found") {
                $htmlContent += "<tr><td>$logName</td><td class='status-error' colspan='6'>$($logData.Status)</td></tr>"
            } else {
                $enabledClass = if ($logData.IsEnabled) { "status-excellent" } else { "status-critical" }
                $sizeClass = if ($logData.SizeCompliance -eq "Compliant") { "status-excellent" } else { "status-warning" }
                
                $htmlContent += @"
                <tr>
                    <td><strong>$logName</strong></td>
                    <td class='$enabledClass'>$($logData.EnabledCompliance)</td>
                    <td>$($logData.RecordCount)</td>
                    <td class='$sizeClass'>$($logData.CurrentMaxSizeMB)</td>
                    <td>$($logData.RecommendedMaxSizeMB)</td>
                    <td>$($logData.EstimatedRetentionDays) days</td>
                    <td>$($logData.MDIImportance)</td>
                </tr>
"@
                
                # Add remediation if log size is insufficient
                if ($IncludeRemediation -and $logData.SizeCompliance -eq "Too Small") {
                    $htmlContent += "<tr><td colspan='7'><div class='remediation-section'><strong>🔧 Increase Log Size:</strong><div class='code-block'>$($logData.RemediationCommand)</div><strong>Retention Recommendation:</strong> $($logData.RetentionRecommendation)</div></td></tr>"
                }
            }
        }
        
        $htmlContent += @"
                        </table>
                    </div>
                    
                    <!-- Network Configuration Analysis -->
                    <div class="subsection">
                        <h3>🌐 Network Configuration Analysis</h3>
                        <table>
                            <tr><th>Component</th><th>Configuration</th><th>Status</th><th>Recommendation</th></tr>
"@
        
        # Add network configuration analysis
        foreach ($component in $dcData.NetworkAnalysis.Keys | Sort-Object) {
            $netData = $dcData.NetworkAnalysis[$component]
            if ($component -eq "DNS") {
                $htmlContent += "<tr><td>DNS Servers</td><td>$($netData.ConfiguredServers)</td><td class='status-excellent'>$($netData.Status)</td><td>$($netData.Recommendation)</td></tr>"
            } elseif ($component -eq "MDIConnectivity") {
                $htmlContent += "<tr><td>MDI Cloud Endpoints</td><td>$($netData.RequiredEndpoints -join '<br>')</td><td class='status-warning'>$($netData.Status)</td><td>$($netData.Recommendation)<br><strong>Note:</strong> $($netData.FirewallNote)</td></tr>"
            }
        }
        
        $htmlContent += @"
                        </table>
                    </div>
                </div>
            </div>
"@
    }

    # Add unreachable DCs section if any exist
    if ($UnreachableDCs.Count -gt 0) {
        $htmlContent += @"
        <!-- =========================================================================================== -->
        <!-- UNREACHABLE DOMAIN CONTROLLERS ANALYSIS -->
        <!-- =========================================================================================== -->
        <div class="section">
            <h2>❌ Unreachable Domain Controllers Analysis</h2>
            <div class="drift-alert">
                <h3>🔍 Connectivity Issues Detected</h3>
                <p><strong>Impact:</strong> Unreachable domain controllers cannot be assessed for MDI readiness and may have configuration gaps.</p>
                <p><strong>Total Unreachable:</strong> $($UnreachableDCs.Count) of $(($SuccessfulDCs.Count + $UnreachableDCs.Count)) domain controllers</p>
            </div>
            
            <table>
                <tr><th>Domain Controller</th><th>Ping Test</th><th>WS-Management</th><th>Port 5985</th><th>Overall Status</th><th>Recommended Action</th></tr>
"@
        
        foreach ($dcName in $UnreachableDCs) {
            $connDetails = $ConnectivityDetails[$dcName]
            $pingClass = if ($connDetails.PingSuccess) { "status-excellent" } else { "status-critical" }
            $wsmanClass = if ($connDetails.WSManSuccess) { "status-excellent" } else { "status-critical" }
            $portClass = if ($connDetails.Port5985Open) { "status-excellent" } else { "status-critical" }
            
            $recommendation = @()
            if (-not $connDetails.PingSuccess) { $recommendation += "Check network connectivity" }
            if (-not $connDetails.WSManSuccess) { $recommendation += "Enable WS-Management (winrm quickconfig)" }
            if (-not $connDetails.Port5985Open) { $recommendation += "Open WinRM port 5985" }
            
            $htmlContent += @"
            <tr>
                <td><strong>$dcName</strong></td>
                <td class='$pingClass'>$(if($connDetails.PingSuccess){"✅ Success"}else{"❌ Failed"})</td>
                <td class='$wsmanClass'>$(if($connDetails.WSManSuccess){"✅ Available"}else{"❌ Unavailable"})</td>
                <td class='$portClass'>$(if($connDetails.Port5985Open){"✅ Open"}else{"❌ Closed"})</td>
                <td class='status-critical'>Unreachable</td>
                <td>$($recommendation -join '; ')</td>
            </tr>
"@
        }
        
        $htmlContent += @"
            </table>
            
            <div class="remediation-section">
                <h4>🔧 General Remediation Steps for Unreachable DCs:</h4>
                <ol>
                    <li><strong>Enable PowerShell Remoting:</strong> <div class="code-block">Enable-PSRemoting -Force</div></li>
                    <li><strong>Configure WinRM:</strong> <div class="code-block">winrm quickconfig -force</div></li>
                    <li><strong>Check Firewall Rules:</strong> <div class="code-block">netsh advfirewall firewall add rule name="WinRM-HTTP" dir=in localport=5985 protocol=TCP action=allow</div></li>
                    <li><strong>Verify Network Connectivity:</strong> Test ping and port connectivity from management workstation</li>
                </ol>
            </div>
        </div>
"@
    }

    # Add comprehensive recommendations section
    $htmlContent += @"
        <!-- =========================================================================================== -->
        <!-- COMPREHENSIVE RECOMMENDATIONS -->
        <!-- =========================================================================================== -->
        <div class="section">
            <h2>📋 Comprehensive Enterprise Recommendations</h2>
            
            <div class="explanation-box">
                <h3>🎯 Executive Summary</h3>
                <p>Your enterprise achieved an overall MDI readiness score of <strong>$($Analysis.OverallScore)%</strong> with status: <strong>$($Analysis.EnterpriseStatus)</strong></p>
                <p>This assessment evaluated $($Analysis.TotalDCs) domain controllers across four critical areas essential for Microsoft Defender for Identity deployment.</p>
            </div>
"@

    # Add specific recommendations based on enterprise score
    if ($Analysis.OverallScore -ge 95) {
        $htmlContent += @"
            <div class="remediation-section">
                <h3>🏆 Excellent - Enterprise Ready</h3>
                <p>Your environment is excellently configured for MDI deployment. All critical settings are properly configured.</p>
                <h4>Next Steps:</h4>
                <ul>
                    <li>Proceed with MDI sensor installation on all domain controllers</li>
                    <li>Configure MDI workspace in Microsoft 365 Defender portal</li>
                    <li>Establish baseline behavioral patterns during initial learning period</li>
                    <li>Configure alert notifications and integration with SIEM systems</li>
                </ul>
            </div>
"@
    } elseif ($Analysis.OverallScore -ge 85) {
        $htmlContent += @"
            <div class="drift-alert">
                <h3>✅ Good - Minor Issues to Address</h3>
                <p>Your environment is well-configured for MDI with minor issues that should be addressed for optimal functionality.</p>
                <h4>Priority Actions:</h4>
                <ul>
                    <li>Address the remaining non-compliant configurations identified in detailed analysis</li>
                    <li>Standardize settings across all domain controllers to eliminate configuration drift</li>
                    <li>Increase event log sizes where recommended</li>
                    <li>Proceed with MDI deployment while monitoring for any detection gaps</li>
                </ul>
            </div>
"@
    } elseif ($Analysis.OverallScore -ge 70) {
        $htmlContent += @"
            <div class="drift-alert">
                <h3>⚠️ Acceptable - Significant Issues Require Attention</h3>
                <p>Your environment has several configuration issues that will impact MDI effectiveness and should be addressed before deployment.</p>
                <h4>Critical Actions Required:</h4>
                <ul>
                    <li>Implement all recommended audit policy configurations</li>
                    <li>Configure NTLM auditing settings on all domain controllers</li>
                    <li>Resolve configuration drift across domain controllers</li>
                    <li>Verify event generation for critical MDI events (4662, 4776)</li>
                    <li>Address system prerequisites on affected domain controllers</li>
                </ul>
            </div>
"@
    } else {
        $htmlContent += @"
            <div class="security-impact">
                <h3>🚨 Critical Issues - Immediate Action Required</h3>
                <p>Your environment has significant configuration gaps that will severely impact MDI functionality. Immediate remediation is required before MDI deployment.</p>
                <h4>Immediate Actions Required:</h4>
                <ul>
                    <li><strong>Critical:</strong> Configure all required audit policies immediately</li>
                    <li><strong>Critical:</strong> Enable NTLM auditing on all domain controllers</li>
                    <li><strong>High:</strong> Resolve all connectivity issues with unreachable domain controllers</li>
                    <li><strong>High:</strong> Increase event log sizes to prevent event loss</li>
                    <li><strong>Medium:</strong> Address system prerequisites for MDI sensor installation</li>
                    <li>Delay MDI deployment until critical issues are resolved</li>
                </ul>
            </div>
"@
    }

    # Add configuration drift recommendations
    if ($Analysis.ConfigurationDrift.Count -gt 0) {
        $htmlContent += @"
            <div class="drift-alert">
                <h3>⚠️ Configuration Drift Remediation</h3>
                <p>Configuration inconsistencies detected across domain controllers. Standardization is required for consistent MDI functionality.</p>
                <h4>Standardization Plan:</h4>
                <ol>
                    <li>Review detailed drift analysis above for specific affected settings</li>
                    <li>Choose the most secure configuration as the standard</li>
                    <li>Apply configurations using provided PowerShell commands</li>
                    <li>Verify changes using verification commands</li>
                    <li>Re-run this assessment to confirm standardization</li>
                </ol>
            </div>
"@
    }

    # Add implementation timeline
    $htmlContent += @"
            <div class="explanation-box">
                <h3>📅 Recommended Implementation Timeline</h3>
                <table>
                    <tr><th>Phase</th><th>Activities</th><th>Estimated Duration</th><th>Prerequisites</th></tr>
                    <tr><td><strong>Phase 1: Preparation</strong></td><td>• Address critical configuration issues<br>• Resolve connectivity problems<br>• Standardize settings across DCs</td><td>1-2 weeks</td><td>• Administrative access to all DCs<br>• Change management approval</td></tr>
                    <tr><td><strong>Phase 2: Validation</strong></td><td>• Re-run this assessment<br>• Verify event generation<br>• Test connectivity</td><td>1 week</td><td>• Completion of Phase 1<br>• 24-48 hours for event validation</td></tr>
                    <tr><td><strong>Phase 3: MDI Deployment</strong></td><td>• Install MDI sensors<br>• Configure MDI workspace<br>• Establish baselines</td><td>2-3 weeks</td><td>• 95%+ readiness score<br>• MDI licensing</td></tr>
                    <tr><td><strong>Phase 4: Optimization</strong></td><td>• Fine-tune detection rules<br>• Configure integrations<br>• Train security team</td><td>2-4 weeks</td><td>• Successful MDI deployment<br>• Initial learning period completion</td></tr>
                </table>
            </div>
        </div>
"@

    # Add footer
    $htmlContent += @"
        <!-- =========================================================================================== -->
        <!-- ENHANCED REPORT FOOTER -->
        <!-- =========================================================================================== -->
        <div class="footer">
            <h3>📊 Report Information</h3>
            <p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | <strong>Version:</strong> Ultra-Detailed Enterprise Edition v4.0</p>
            <p><strong>Assessment Coverage:</strong> $($SuccessfulDCs.Count) of $(($SuccessfulDCs.Count + $UnreachableDCs.Count)) Domain Controllers Successfully Analyzed</p>
            <p><strong>Total Events Analyzed:</strong> $($Analysis.TotalEvents24h) security events in last 24 hours</p>
            <hr style="border: 1px solid #555; margin: 20px 0;">
            <p><strong>Microsoft Defender for Identity Ultra-Detailed Assessment</strong></p>
            <p>Created By: <a href="https://gulabprasad.com">Gulab Prasad</a> | Enhanced Enterprise Security Assessment Tool</p>
            <p><em>This report provides comprehensive analysis for MDI deployment readiness. For questions or support, visit the creator's website.</em></p>
        </div>
    </div>
</body>
</html>
"@
    
    return $htmlContent
}

# ================================================================================================
# SCRIPT COMPLETION MESSAGE WITH ENHANCED FEATURES
# ================================================================================================

Write-Host ""
Write-Host "🎉======================================🎉" -ForegroundColor Green
Write-Host "   ULTRA-DETAILED MDI REPORTING LOADED   " -ForegroundColor Green
Write-Host "🎉======================================🎉" -ForegroundColor Green
Write-Host ""
Write-Host "🚀 ENHANCED FEATURES:" -ForegroundColor Cyan
Write-Host "   📊 Ultra-detailed scoring system (0-100 points)" -ForegroundColor White
Write-Host "   🔍 Comprehensive security implications analysis" -ForegroundColor White
Write-Host "   🛠️  Specific PowerShell remediation commands" -ForegroundColor White
Write-Host "   📈 Advanced event frequency analysis" -ForegroundColor White
Write-Host "   🎯 MDI sensor prerequisites assessment" -ForegroundColor White
Write-Host "   🌐 Network connectivity diagnostics" -ForegroundColor White
Write-Host "   📋 Configuration drift detection with remediation" -ForegroundColor White
Write-Host "   ⏱️  Implementation timeline recommendations" -ForegroundColor White
Write-Host "   🎨 Modern, responsive HTML report design" -ForegroundColor White
Write-Host ""
Write-Host "🎯 STARTING ULTRA-DETAILED MDI ENTERPRISE ASSESSMENT..." -ForegroundColor Yellow
Write-Host ""

# ================================================================================================
# AUTOMATIC EXECUTION - Run the assessment immediately
# ================================================================================================

# Execute the ultra-detailed enterprise assessment automatically
try {
    $results = New-MDIUltraDetailedEnterpriseReport
    
    # Display completion summary
    Write-Host ""
    Write-Host "✅ ASSESSMENT COMPLETED SUCCESSFULLY!" -ForegroundColor Green
    Write-Host "📊 Enterprise Status: $($results.EnterpriseStatus)" -ForegroundColor Cyan
    Write-Host "🎯 Overall Score: $($results.OverallScore)%" -ForegroundColor $(if($results.OverallScore -ge 85){"Green"}else{"Yellow"})
    Write-Host "📄 Report File: $($results.ReportFile)" -ForegroundColor White
    Write-Host ""
} catch {
    Write-Host ""
    Write-Host "❌ ERROR DURING ASSESSMENT:" -ForegroundColor Red
    Write-Host "   $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "🔧 MANUAL EXECUTION OPTION:" -ForegroundColor Cyan
    Write-Host "   If automatic execution failed, you can run manually with:" -ForegroundColor White
    Write-Host "   New-MDIUltraDetailedEnterpriseReport" -ForegroundColor Green
    Write-Host ""
}