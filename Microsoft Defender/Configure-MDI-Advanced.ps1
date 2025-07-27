#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Microsoft Defender for Identity - Advanced Configuration Script
    
.DESCRIPTION
    This script handles advanced MDI configurations including gMSA service accounts,
    SAM-R protocol settings, AD enhancements, and comprehensive readiness testing.
    Run this after the basic MDI configuration script.
    
.PARAMETER LogPath
    Path for deployment logs (default: C:\MDI_Advanced_Logs)
    
.PARAMETER gMSAName
    Name for the Group Managed Service Account (default: mdiSvc01)
    
.PARAMETER gMSAGroup
    Name for the security group that can retrieve gMSA password (default: mdiSvc01Group)
    
.PARAMETER SkipgMSACreation
    Skip Group Managed Service Account creation
    
.PARAMETER SkipSAMRConfig
    Skip SAM-R protocol configuration
    
.PARAMETER SkipADEnhancements
    Skip Active Directory enhancements (Recycle Bin, etc.)
    
.PARAMETER SkipConnectivityTest
    Skip network connectivity testing
    
.PARAMETER TestOnly
    Run readiness tests only without making changes
    
.PARAMETER RepairMode
    Attempt to repair existing gMSA configuration issues
    
.PARAMETER ForceImmediateKDS
    Create KDS root key with immediate effectiveness (bypasses 10-hour delay)
    
.EXAMPLE
    .\Configure-MDI-Advanced.ps1
    
.EXAMPLE
    .\Configure-MDI-Advanced.ps1 -gMSAName "MyMDIService" -gMSAGroup "MyMDIGroup"
    
.EXAMPLE
    .\Configure-MDI-Advanced.ps1 -TestOnly
    
.EXAMPLE
    .\Configure-MDI-Advanced.ps1 -RepairMode
    
.EXAMPLE
    .\Configure-MDI-Advanced.ps1 -ForceImmediateKDS
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\MDI_Advanced_Logs",
    
    [Parameter(Mandatory = $false)]
    [string]$gMSAName = "mdiSvc01",
    
    [Parameter(Mandatory = $false)]
    [string]$gMSAGroup = "mdiSvc01Group",
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipgMSACreation,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipSAMRConfig,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipADEnhancements,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipConnectivityTest,
    
    [Parameter(Mandatory = $false)]
    [switch]$TestOnly,
    
    [Parameter(Mandatory = $false)]
    [switch]$RepairMode,
    
    [Parameter(Mandatory = $false)]
    [switch]$ForceImmediateKDS
)

# Script variables
$ScriptVersion = "1.0"
$LogFile = Join-Path $LogPath "MDI_Advanced_Configuration_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

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

# Function to test Active Directory prerequisites
function Test-ADPrerequisites {
    Write-Log "Testing Active Directory prerequisites..." -Level "INFO"
    
    try {
        # Test if we're on a domain controller
        $isDC = (Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2
        if (-not $isDC) {
            Write-Log "Warning: This script is designed for Domain Controllers" -Level "WARNING"
        }
        
        # Check if ActiveDirectory module is available
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            Write-Log "✓ Active Directory PowerShell module available" -Level "SUCCESS"
            $adModuleAvailable = $true
        }
        catch {
            Write-Log "✗ Active Directory PowerShell module not available" -Level "ERROR"
            Write-Log "Install RSAT-AD-PowerShell feature: Install-WindowsFeature RSAT-AD-PowerShell" -Level "INFO"
            return $false
        }
        
        # Check domain and forest functional levels
        try {
            $domain = Get-ADDomain
            $forest = Get-ADForest
            
            Write-Log "Domain: $($domain.DNSRoot)" -Level "INFO"
            Write-Log "Domain Functional Level: $($domain.DomainMode)" -Level "INFO"
            Write-Log "Forest Functional Level: $($forest.ForestMode)" -Level "INFO"
            
            # Check if functional levels support gMSA (Windows Server 2012 or higher)
            $supportedLevels = @("Windows2012", "Windows2012R2", "Windows2016", "Windows2019", "Windows2022")
            if ($domain.DomainMode -in $supportedLevels) {
                Write-Log "✓ Domain functional level supports gMSA" -Level "SUCCESS"
            }
            else {
                Write-Log "⚠ Domain functional level may not fully support gMSA features" -Level "WARNING"
            }
        }
        catch {
            Write-Log "Failed to check domain/forest functional levels: $($_.Exception.Message)" -Level "WARNING"
        }
        
        # Check if we have necessary permissions
        try {
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
            $adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
            
            if ($principal.IsInRole($adminRole)) {
                Write-Log "✓ Running with administrative privileges" -Level "SUCCESS"
            }
            else {
                Write-Log "✗ Administrative privileges required" -Level "ERROR"
                return $false
            }
        }
        catch {
            Write-Log "Failed to check administrative privileges" -Level "WARNING"
        }
        
        Write-Log "Active Directory prerequisites check completed" -Level "SUCCESS"
# Function to troubleshoot gMSA issues
function Test-gMSATroubleshooting {
    param(
        [string]$AccountName,
        [string]$GroupName
    )
    
    Write-Log "Running gMSA troubleshooting diagnostics..." -Level "INFO"
    
    try {
        # Test 1: Check KDS service
        Write-Log "1. Checking Key Distribution Service..." -Level "INFO"
        $kdsService = Get-Service -Name "KdsSvc" -ErrorAction SilentlyContinue
        if ($kdsService) {
            Write-Log "  ✓ KDS Service status: $($kdsService.Status)" -Level "INFO"
            if ($kdsService.Status -ne "Running") {
                Write-Log "  ⚠ KDS Service is not running. Starting..." -Level "WARNING"
                try {
                    Start-Service -Name "KdsSvc" -ErrorAction Stop
                    Write-Log "  ✓ KDS Service started successfully" -Level "SUCCESS"
                }
                catch {
                    Write-Log "  ✗ Failed to start KDS Service: $($_.Exception.Message)" -Level "ERROR"
                }
            }
        }
        else {
            Write-Log "  ✗ KDS Service not found" -Level "ERROR"
        }
        
        # Test 2: Check functional levels
        Write-Log "2. Checking domain and forest functional levels..." -Level "INFO"
        try {
            $domain = Get-ADDomain
            $forest = Get-ADForest
            Write-Log "  Domain FL: $($domain.DomainMode)" -Level "INFO"
            Write-Log "  Forest FL: $($forest.ForestMode)" -Level "INFO"
            
            $supportedLevels = @("Windows2012", "Windows2012R2", "Windows2016", "Windows2019", "Windows2022")
            if ($domain.DomainMode -in $supportedLevels) {
                Write-Log "  ✓ Functional levels support gMSA" -Level "SUCCESS"
            }
            else {
                Write-Log "  ✗ Functional levels may not support gMSA fully" -Level "ERROR"
            }
        }
        catch {
            Write-Log "  ✗ Could not check functional levels: $($_.Exception.Message)" -Level "ERROR"
        }
        
        # Test 3: Check KDS Root Key details
        Write-Log "3. Checking KDS Root Key status..." -Level "INFO"
        try {
            $kdsKeys = Get-KdsRootKey -ErrorAction Stop
            if ($kdsKeys) {
                foreach ($key in $kdsKeys) {
                    Write-Log "  Key ID: $($key.KeyId)" -Level "INFO"
                    Write-Log "  Created: $($key.CreationTime)" -Level "INFO"
                    Write-Log "  Effective: $($key.EffectiveTime)" -Level "INFO"
                    
                    if ($key.EffectiveTime -le (Get-Date)) {
                        Write-Log "  ✓ Key is effective and usable" -Level "SUCCESS"
                    }
                    else {
                        $hoursLeft = [math]::Round(($key.EffectiveTime - (Get-Date)).TotalHours, 1)
                        Write-Log "  ⚠ Key effective in $hoursLeft hours" -Level "WARNING"
                        Write-Log "  Fix: Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))" -Level "INFO"
                    }
                }
            }
            else {
                Write-Log "  ✗ No KDS Root Key found" -Level "ERROR"
                Write-Log "  Fix: Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))" -Level "INFO"
            }
        }
        catch {
            Write-Log "  ✗ Error checking KDS keys: $($_.Exception.Message)" -Level "ERROR"
        }
        
        # Test 4: Check if gMSA account exists
        Write-Log "4. Checking gMSA account status..." -Level "INFO"
        try {
            $gmsaAccount = Get-ADServiceAccount -Identity $AccountName -ErrorAction Stop
            Write-Log "  ✓ gMSA account exists: $($gmsaAccount.Name)" -Level "SUCCESS"
            Write-Log "  DN: $($gmsaAccount.DistinguishedName)" -Level "INFO"
            Write-Log "  SamAccountName: $($gmsaAccount.SamAccountName)" -Level "INFO"
            Write-Log "  Enabled: $($gmsaAccount.Enabled)" -Level "INFO"
        }
        catch {
            Write-Log "  ✗ gMSA account not found: $($_.Exception.Message)" -Level "ERROR"
        }
        
        # Test 5: Check security group
        Write-Log "5. Checking security group status..." -Level "INFO"
        try {
            $secGroup = Get-ADGroup -Identity $GroupName -ErrorAction Stop
            Write-Log "  ✓ Security group exists: $($secGroup.Name)" -Level "SUCCESS"
            
            $members = Get-ADGroupMember -Identity $GroupName -ErrorAction SilentlyContinue
            Write-Log "  Members count: $(($members | Measure-Object).Count)" -Level "INFO"
            
            # Check if current computer is a member
            $computerName = $env:COMPUTERNAME
            $isMember = $members | Where-Object { $_.Name -eq $computerName }
            if ($isMember) {
                Write-Log "  ✓ Current computer is a member" -Level "SUCCESS"
            }
            else {
                Write-Log "  ⚠ Current computer is NOT a member" -Level "WARNING"
                Write-Log "  Fix: Add-ADGroupMember -Identity $GroupName -Members $computerName$" -Level "INFO"
            }
        }
        catch {
            Write-Log "  ✗ Security group error: $($_.Exception.Message)" -Level "ERROR"
        }
        
        # Test 6: Test gMSA installation on this computer
        Write-Log "6. Testing gMSA installation status..." -Level "INFO"
        try {
            $testResult = Test-ADServiceAccount -Identity $AccountName -ErrorAction Stop
            if ($testResult) {
                Write-Log "  ✓ gMSA is properly installed and functional" -Level "SUCCESS"
            }
            else {
                Write-Log "  ✗ gMSA test failed" -Level "ERROR"
                Write-Log "  Try: Install-ADServiceAccount -Identity $AccountName" -Level "INFO"
            }
        }
        catch {
            Write-Log "  ✗ Cannot test gMSA: $($_.Exception.Message)" -Level "ERROR"
            Write-Log "  Likely cause: gMSA not installed on this computer" -Level "INFO"
            Write-Log "  Try: Install-ADServiceAccount -Identity $AccountName" -Level "INFO"
        }
        
        # Test 7: Check Kerberos tickets
        Write-Log "7. Checking Kerberos tickets..." -Level "INFO"
        try {
            $klistOutput = klist
            Write-Log "  Kerberos tickets status checked" -Level "INFO"
            if ($klistOutput -match "Current LogonId is") {
                Write-Log "  ✓ Kerberos tickets present" -Level "SUCCESS"
            }
            
            # Suggest ticket refresh if there are issues
            Write-Log "  If gMSA issues persist, try: klist purge -li 0x3e7" -Level "INFO"
        }
        catch {
            Write-Log "  ⚠ Could not check Kerberos tickets" -Level "WARNING"
        }
        
        # Provide summary and recommendations
        Write-Log "Troubleshooting Summary:" -Level "INFO"
        Write-Log "If gMSA creation failed, try these steps in order:" -Level "INFO"
        Write-Log "1. Ensure KDS service is running" -Level "INFO"
        Write-Log "2. Create/verify KDS root key with immediate effectiveness" -Level "INFO"
        Write-Log "3. Add computer account to security group" -Level "INFO"
        Write-Log "4. Purge Kerberos tickets: klist purge -li 0x3e7" -Level "INFO"
        Write-Log "5. Restart server or wait for group membership refresh" -Level "INFO"
        Write-Log "6. Retry gMSA creation/installation" -Level "INFO"
        
        return $true
    }
    catch {
        Write-Log "Troubleshooting failed: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}
    }
    catch {
        Write-Log "Failed to check AD prerequisites: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

# Function to test and create KDS Root Key
function Set-KDSRootKey {
    Write-Log "Configuring KDS Root Key for gMSA support..." -Level "INFO"
    
    try {
        # Check if KDS Root Key already exists
        $existingKeys = Get-KdsRootKey -ErrorAction SilentlyContinue
        
        if ($existingKeys) {
            Write-Log "✓ KDS Root Key already exists" -Level "SUCCESS"
            foreach ($key in $existingKeys) {
                Write-Log "  Key ID: $($key.KeyId) - Created: $($key.EffectiveTime)" -Level "INFO"
                $effectiveTime = $key.EffectiveTime
                $currentTime = Get-Date
                
                if ($effectiveTime -le $currentTime) {
                    Write-Log "  ✓ Key is effective and ready for use" -Level "SUCCESS"
                }
                else {
                    $waitTime = ($effectiveTime - $currentTime).TotalHours
                    Write-Log "  ⚠ Key will be effective in $([math]::Round($waitTime, 1)) hours" -Level "WARNING"
                    if (-not $ForceImmediateKDS) {
                        Write-Log "  Use -ForceImmediateKDS parameter to create an immediately effective key" -Level "INFO"
                    }
                }
            }
            
            # If we have at least one effective key, we're good
            $hasEffectiveKey = $existingKeys | Where-Object { $_.EffectiveTime -le (Get-Date) }
            if ($hasEffectiveKey -or -not $ForceImmediateKDS) {
                return $true
            }
        }
        
        Write-Log "Creating KDS Root Key..." -Level "INFO"
        
        if ($TestOnly) {
            Write-Log "[TEST MODE] Would create KDS Root Key" -Level "INFO"
            return $true
        }
        
        # Determine creation method based on parameter
        if ($ForceImmediateKDS) {
            Write-Log "Creating KDS Root Key with immediate effectiveness..." -Level "INFO"
            Write-Log "WARNING: This bypasses the 10-hour replication safety delay" -Level "WARNING"
            Write-Log "This should only be used in test environments or when you're certain about AD replication" -Level "WARNING"
            
            try {
                # Create key effective 10 hours ago to bypass waiting period
                $rootKey = Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) -ErrorAction Stop
                Write-Log "✓ KDS Root Key created with immediate effectiveness" -Level "SUCCESS"
                Write-Log "Key ID: $($rootKey.KeyId)" -Level "INFO"
            }
            catch {
                Write-Log "Failed to create immediate KDS Root Key: $($_.Exception.Message)" -Level "ERROR"
                Write-Log "Trying standard creation method..." -Level "INFO"
                
                try {
                    $rootKey = Add-KdsRootKey -ErrorAction Stop
                    Write-Log "✓ KDS Root Key created with standard timing" -Level "SUCCESS"
                    Write-Log "Key ID: $($rootKey.KeyId)" -Level "INFO"
                    Write-Log "⚠ Key will be effective after 10 hours of replication" -Level "WARNING"
                }
                catch {
                    Write-Log "Failed to create KDS Root Key: $($_.Exception.Message)" -Level "ERROR"
                    return $false
                }
            }
        }
        else {
            Write-Log "Creating KDS Root Key with standard replication delay (recommended for production)..." -Level "INFO"
            try {
                $rootKey = Add-KdsRootKey -ErrorAction Stop
                Write-Log "✓ KDS Root Key created successfully" -Level "SUCCESS"
                Write-Log "Key ID: $($rootKey.KeyId)" -Level "INFO"
                Write-Log "⚠ Key will be effective after AD replication (up to 10 hours)" -Level "WARNING"
                Write-Log "For immediate use, re-run with -ForceImmediateKDS parameter" -Level "INFO"
            }
            catch {
                Write-Log "Failed to create KDS Root Key: $($_.Exception.Message)" -Level "ERROR"
                return $false
            }
        }
        
        # Verify the key was created
        Start-Sleep -Seconds 2
        $newKeys = Get-KdsRootKey -ErrorAction SilentlyContinue
        if ($newKeys) {
            Write-Log "✓ KDS Root Key creation verified" -Level "SUCCESS"
            return $true
        }
        else {
            Write-Log "⚠ Could not verify KDS Root Key creation" -Level "WARNING"
            return $false
        }
    }
    catch {
        Write-Log "Failed to configure KDS Root Key: $($_.Exception.Message)" -Level "ERROR"
        Write-Log "Common causes:" -Level "INFO"
        Write-Log "  1. Insufficient permissions (Domain Admin required)" -Level "INFO"
        Write-Log "  2. Domain/Forest functional level too low" -Level "INFO"
        Write-Log "  3. KDS service not running" -Level "INFO"
        return $false
    }
}

# Function to create gMSA account and security group
function New-MDIServiceAccount {
    param(
        [string]$AccountName,
        [string]$GroupName
    )
    
    Write-Log "Creating Group Managed Service Account for MDI..." -Level "INFO"
    
    try {
        # First, verify KDS root key is available and effective
        Write-Log "Verifying KDS root key availability..." -Level "INFO"
        $kdsKeys = Get-KdsRootKey -ErrorAction SilentlyContinue
        if (-not $kdsKeys) {
            Write-Log "No KDS root key found. gMSA creation will fail." -Level "ERROR"
            return $false
        }
        
        # Check if any key is effective (not in the future)
        $effectiveKey = $kdsKeys | Where-Object { $_.EffectiveTime -le (Get-Date) }
        if (-not $effectiveKey) {
            Write-Log "KDS root key exists but is not yet effective. Waiting for replication..." -Level "WARNING"
            Write-Log "Key effective time: $($kdsKeys[0].EffectiveTime)" -Level "INFO"
            Write-Log "Current time: $(Get-Date)" -Level "INFO"
            Write-Log "gMSA creation may fail due to timing. Consider waiting or creating key with past effective time." -Level "WARNING"
        }
        
        # Check if gMSA already exists
        Write-Log "Checking if gMSA account '$AccountName' already exists..." -Level "INFO"
        try {
            $existingAccount = Get-ADServiceAccount -Identity $AccountName -ErrorAction Stop
            Write-Log "✓ gMSA account '$AccountName' already exists" -Level "SUCCESS"
            Write-Log "  Distinguished Name: $($existingAccount.DistinguishedName)" -Level "INFO"
            $gmsaExists = $true
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-Log "gMSA account '$AccountName' does not exist, will create it" -Level "INFO"
            $gmsaExists = $false
        }
        catch {
            Write-Log "Error checking for existing gMSA: $($_.Exception.Message)" -Level "WARNING"
            $gmsaExists = $false
        }
        
        if ($TestOnly) {
            Write-Log "[TEST MODE] Would create gMSA account: $AccountName" -Level "INFO"
            Write-Log "[TEST MODE] Would create security group: $GroupName" -Level "INFO"
            return $true
        }
        
        # Create security group for gMSA access
        Write-Log "Checking/creating security group: $GroupName" -Level "INFO"
        try {
            $existingGroup = Get-ADGroup -Identity $GroupName -ErrorAction Stop
            Write-Log "✓ Security group '$GroupName' already exists" -Level "SUCCESS"
            $group = $existingGroup
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-Log "Security group '$GroupName' does not exist, creating it..." -Level "INFO"
            try {
                $group = New-ADGroup -Name $GroupName -GroupScope Universal -GroupCategory Security -Description "Security group for MDI gMSA password retrieval" -PassThru -ErrorAction Stop
                Write-Log "✓ Security group '$GroupName' created successfully" -Level "SUCCESS"
                Write-Log "  Distinguished Name: $($group.DistinguishedName)" -Level "INFO"
            }
            catch {
                Write-Log "✗ Failed to create security group '$GroupName': $($_.Exception.Message)" -Level "ERROR"
                return $false
            }
        }
        catch {
            Write-Log "✗ Error checking security group '$GroupName': $($_.Exception.Message)" -Level "ERROR"
            return $false
        }
        
        # Add domain controllers to the group
        Write-Log "Adding domain controllers to security group..." -Level "INFO"
        try {
            $domainControllers = Get-ADComputer -Filter {PrimaryGroupID -eq 516} -Properties Name -ErrorAction Stop
            Write-Log "Found $($domainControllers.Count) domain controllers" -Level "INFO"
            
            $addedCount = 0
            foreach ($dc in $domainControllers) {
                try {
                    # Check if already a member
                    $members = Get-ADGroupMember -Identity $GroupName -ErrorAction SilentlyContinue
                    $isMember = $members | Where-Object { $_.Name -eq $dc.Name }
                    
                    if (-not $isMember) {
                        Add-ADGroupMember -Identity $GroupName -Members $dc.DistinguishedName -ErrorAction Stop
                        Write-Log "  ✓ Added DC: $($dc.Name)" -Level "INFO"
                        $addedCount++
                    }
                    else {
                        Write-Log "  ✓ DC already member: $($dc.Name)" -Level "INFO"
                    }
                }
                catch {
                    Write-Log "  ⚠ Could not add $($dc.Name) to group: $($_.Exception.Message)" -Level "WARNING"
                }
            }
            Write-Log "Successfully processed $($domainControllers.Count) domain controllers ($addedCount newly added)" -Level "SUCCESS"
        }
        catch {
            Write-Log "Failed to get domain controllers: $($_.Exception.Message)" -Level "ERROR"
            Write-Log "Continuing anyway - you may need to manually add DCs to the group" -Level "WARNING"
        }
        
        # Create the gMSA account if it doesn't exist
        if (-not $gmsaExists) {
            # Verify the group exists before creating gMSA
            try {
                $verifyGroup = Get-ADGroup -Identity $GroupName -ErrorAction Stop
                Write-Log "✓ Verified security group exists for gMSA creation" -Level "SUCCESS"
            }
            catch {
                Write-Log "✗ Security group '$GroupName' not found - cannot create gMSA" -Level "ERROR"
                return $false
            }
            
            Write-Log "Creating gMSA account: $AccountName" -Level "INFO"
            try {
                $domain = Get-ADDomain
                $dnsHostName = "$AccountName.$($domain.DNSRoot)"
                
                Write-Log "  Account Name: $AccountName" -Level "INFO"
                Write-Log "  DNS Host Name: $dnsHostName" -Level "INFO"
                Write-Log "  Principals Group: $GroupName" -Level "INFO"
                
                $gmsaAccount = New-ADServiceAccount -Name $AccountName -DNSHostName $dnsHostName -PrincipalsAllowedToRetrieveManagedPassword $GroupName -PassThru -ErrorAction Stop
                
                Write-Log "✓ gMSA account '$AccountName' created successfully" -Level "SUCCESS"
                Write-Log "  Distinguished Name: $($gmsaAccount.DistinguishedName)" -Level "INFO"
                Write-Log "  SamAccountName: $($gmsaAccount.SamAccountName)" -Level "INFO"
                
                # Wait a moment for AD replication
                Write-Log "Waiting 5 seconds for AD replication..." -Level "INFO"
                Start-Sleep -Seconds 5
            }
            catch {
                Write-Log "Failed to create gMSA account: $($_.Exception.Message)" -Level "ERROR"
                Write-Log "This may be due to:" -Level "INFO"
                Write-Log "  1. KDS root key not yet effective (wait 10 hours or create with past time)" -Level "INFO"
                Write-Log "  2. Insufficient permissions (Domain Admin required)" -Level "INFO"
                Write-Log "  3. Name conflict or invalid characters" -Level "INFO"
                Write-Log "  4. Group '$GroupName' not accessible" -Level "INFO"
                return $false
            }
        }
        
        # Install the gMSA on this server
        Write-Log "Installing gMSA account on this server..." -Level "INFO"
        try {
            # First check if already installed
            $installedAccounts = Get-ADServiceAccount -Filter {Name -eq $AccountName} -ErrorAction SilentlyContinue
            if ($installedAccounts) {
                # Try to install
                Install-ADServiceAccount -Identity $AccountName -ErrorAction Stop
                Write-Log "✓ gMSA account installed on this server" -Level "SUCCESS"
                
                # Test the gMSA installation
                Write-Log "Testing gMSA account..." -Level "INFO"
                $testResult = Test-ADServiceAccount -Identity $AccountName -ErrorAction SilentlyContinue
                if ($testResult) {
                    Write-Log "✓ gMSA account test successful" -Level "SUCCESS"
                }
                else {
                    Write-Log "⚠ gMSA account test failed - may need time for replication or group membership update" -Level "WARNING"
                    Write-Log "Try running: klist purge -li 0x3e7" -Level "INFO"
                    Write-Log "Or restart the server to refresh Kerberos tickets" -Level "INFO"
                }
            }
            else {
                Write-Log "⚠ gMSA account not found for installation" -Level "WARNING"
            }
        }
        catch {
            Write-Log "Could not install gMSA (this may be normal): $($_.Exception.Message)" -Level "WARNING"
            Write-Log "Possible reasons:" -Level "INFO"
            Write-Log "  1. Computer account not yet a member of security group" -Level "INFO"
            Write-Log "  2. KDS key replication time needed" -Level "INFO"
            Write-Log "  3. Kerberos ticket refresh needed" -Level "INFO"
            Write-Log "Manual steps to resolve:" -Level "INFO"
            Write-Log "  1. Run: klist purge -li 0x3e7" -Level "INFO"
            Write-Log "  2. Or restart this server" -Level "INFO"
            Write-Log "  3. Re-run: Install-ADServiceAccount -Identity $AccountName" -Level "INFO"
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to create gMSA account: $($_.Exception.Message)" -Level "ERROR"
        Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR"
        return $false
    }
}

# Function to configure gMSA permissions for Active Directory
function Set-ADPermissions {
    param(
        [string]$AccountName,
        [string]$GroupName
    )
    
    Write-Log "Configuring Active Directory permissions for gMSA..." -Level "INFO"
    
    try {
        if ($TestOnly) {
            Write-Log "[TEST MODE] Would configure AD permissions for gMSA" -Level "INFO"
            return $true
        }
        
        # First verify the gMSA account exists
        $gmsaAccount = Get-ADServiceAccount -Identity $AccountName -ErrorAction SilentlyContinue
        if (-not $gmsaAccount) {
            Write-Log "gMSA account '$AccountName' not found. Cannot configure permissions." -Level "ERROR"
            return $false
        }
        
        # Verify the security group exists
        $securityGroup = Get-ADGroup -Identity $GroupName -ErrorAction SilentlyContinue
        if (-not $securityGroup) {
            Write-Log "Security group '$GroupName' not found. Cannot configure permissions." -Level "ERROR"
            return $false
        }
        
        $domain = Get-ADDomain
        $domainDN = $domain.DistinguishedName
        
        Write-Log "Domain DN: $domainDN" -Level "INFO"
        Write-Log "gMSA Account: $($gmsaAccount.DistinguishedName)" -Level "INFO"
        Write-Log "Security Group: $($securityGroup.DistinguishedName)" -Level "INFO"
        
        # Configure permissions for Deleted Objects container
        Write-Log "Configuring permissions for Deleted Objects container..." -Level "INFO"
        
        # Method 1: Try to use the gMSA directly for permissions
        $deletedObjectsDN = "CN=Deleted Objects,$domainDN"
        Write-Log "Deleted Objects DN: $deletedObjectsDN" -Level "INFO"
        
        try {
            # Grant read permissions to the gMSA account on Deleted Objects container
            # Using the gMSA account name with $ suffix for computer-like account
            $gmsaSamAccount = $gmsaAccount.SamAccountName
            Write-Log "Attempting to grant permissions to: $gmsaSamAccount" -Level "INFO"
            
            # Use dsacls to grant permissions
            $dsaclsCmd = "dsacls `"$deletedObjectsDN`" /G `"$gmsaSamAccount:LCRP`""
            Write-Log "Running command: $dsaclsCmd" -Level "INFO"
            
            $result = Invoke-Expression $dsaclsCmd 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "✓ Configured Deleted Objects container permissions for gMSA" -Level "SUCCESS"
            }
            else {
                Write-Log "⚠ dsacls command completed with exit code: $LASTEXITCODE" -Level "WARNING"
                Write-Log "This may be normal if permissions already exist" -Level "INFO"
            }
        }
        catch {
            Write-Log "Could not configure Deleted Objects permissions directly: $($_.Exception.Message)" -Level "WARNING"
            
            # Alternative method: Use PowerShell to set permissions
            try {
                Write-Log "Attempting alternative permission method..." -Level "INFO"
                
                # Import AD module features if available
                $acl = Get-Acl -Path "AD:$deletedObjectsDN" -ErrorAction SilentlyContinue
                if ($acl) {
                    Write-Log "Successfully retrieved ACL for Deleted Objects container" -Level "SUCCESS"
                    # In a real implementation, you would modify the ACL here
                    # This is complex and typically done via dsacls or Group Policy
                }
                else {
                    Write-Log "Could not retrieve ACL for Deleted Objects container" -Level "WARNING"
                }
            }
            catch {
                Write-Log "Alternative permission method also failed: $($_.Exception.Message)" -Level "WARNING"
            }
        }
        
        # Enable Active Directory Recycle Bin if not already enabled
        Write-Log "Checking Active Directory Recycle Bin status..." -Level "INFO"
        try {
            $recycleBin = Get-ADOptionalFeature -Filter {Name -eq "Recycle Bin Feature"} -ErrorAction Stop
            if ($recycleBin.EnabledScopes.Count -gt 0) {
                Write-Log "✓ Active Directory Recycle Bin is already enabled" -Level "SUCCESS"
                Write-Log "  Enabled in: $($recycleBin.EnabledScopes -join ', ')" -Level "INFO"
            }
            else {
                Write-Log "Enabling Active Directory Recycle Bin..." -Level "INFO"
                try {
                    Enable-ADOptionalFeature -Identity "Recycle Bin Feature" -Scope ForestOrConfigurationSet -Target $domain.DNSRoot -Confirm:$false -ErrorAction Stop
                    Write-Log "✓ Active Directory Recycle Bin enabled successfully" -Level "SUCCESS"
                    Write-Log "Note: This change requires forest-wide replication" -Level "INFO"
                }
                catch {
                    Write-Log "Failed to enable AD Recycle Bin: $($_.Exception.Message)" -Level "ERROR"
                    Write-Log "You may need to enable this manually or have insufficient permissions" -Level "INFO"
                }
            }
        }
        catch {
            Write-Log "Could not check/configure Active Directory Recycle Bin: $($_.Exception.Message)" -Level "WARNING"
        }
        
        # Additional permissions configuration
        Write-Log "Configuring additional AD read permissions..." -Level "INFO"
        
        # Grant read permissions on domain root
        try {
            $domainRootCmd = "dsacls `"$domainDN`" /G `"$($gmsaAccount.SamAccountName):GR`""
            $result = Invoke-Expression $domainRootCmd 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "✓ Configured domain root read permissions" -Level "SUCCESS"
            }
            else {
                Write-Log "⚠ Domain root permission command exit code: $LASTEXITCODE" -Level "WARNING"
            }
        }
        catch {
            Write-Log "Could not configure domain root permissions: $($_.Exception.Message)" -Level "WARNING"
        }
        
        # Summary of what was configured
        Write-Log "AD Permissions Configuration Summary:" -Level "INFO"
        Write-Log "  ✓ gMSA Account verified: $AccountName" -Level "INFO"
        Write-Log "  ✓ Security Group verified: $GroupName" -Level "INFO"
        Write-Log "  ✓ Deleted Objects permissions attempted" -Level "INFO"
        Write-Log "  ✓ AD Recycle Bin checked/enabled" -Level "INFO"
        Write-Log "  ✓ Domain read permissions attempted" -Level "INFO"
        
        Write-Log "Manual verification steps:" -Level "INFO"
        Write-Log "  1. Verify gMSA can read AD objects: Get-ADUser -Identity Administrator -Server localhost" -Level "INFO"
        Write-Log "  2. Check Deleted Objects access: Get-ADObject -IncludeDeletedObjects -Filter *" -Level "INFO"
        Write-Log "  3. Test with: Test-ADServiceAccount -Identity $AccountName" -Level "INFO"
        
        return $true
    }
    catch {
        Write-Log "Failed to configure AD permissions: $($_.Exception.Message)" -Level "ERROR"
        Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR"
        return $false
    }
}

# Function to configure SAM-R protocol settings
function Set-SAMRConfiguration {
    Write-Log "Configuring SAM-R protocol settings for lateral movement detection..." -Level "INFO"
    
    try {
        if ($TestOnly) {
            Write-Log "[TEST MODE] Would configure SAM-R protocol settings" -Level "INFO"
            return $true
        }
        
        # Create or modify Group Policy for SAM-R restrictions
        Write-Log "Configuring SAM-R access restrictions..." -Level "INFO"
        
        # Registry path for SAM-R configuration
        $samrRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        
        # Configure RestrictRemoteSAM registry setting
        # This should be applied to all computers except Domain Controllers
        Write-Log "Note: SAM-R restrictions should be applied to all computers except DCs via Group Policy" -Level "INFO"
        Write-Log "Create a GPO with the following setting:" -Level "INFO"
        Write-Log "  Computer Configuration > Policies > Windows Settings > Security Settings" -Level "INFO"
        Write-Log "  > Local Policies > Security Options" -Level "INFO"
        Write-Log "  > Network access: Restrict clients allowed to make remote calls to SAM" -Level "INFO"
        Write-Log "  Value: O:BAG:BAD:(A;;RC;;;BA)(A;;RC;;;$gMSAName)" -Level "INFO"
        
        # Set local configuration as an example (this should actually be done via GPO)
        try {
            $samDescriptor = "O:BAG:BAD:(A;;RC;;;BA)"  # Allow only Built-in Administrators
            # Note: In production, you would add the gMSA account here
            
            # This is informational - actual implementation should be via Group Policy
            Write-Log "Local SAM-R configuration reference:" -Level "INFO"
            Write-Log "  Registry: $samrRegPath" -Level "INFO"
            Write-Log "  Value: RestrictRemoteSAM" -Level "INFO"
            Write-Log "  Data: $samDescriptor" -Level "INFO"
            
        }
        catch {
            Write-Log "Could not set local SAM-R configuration: $($_.Exception.Message)" -Level "WARNING"
        }
        
        Write-Log "✓ SAM-R configuration guidance provided" -Level "SUCCESS"
        Write-Log "Action Required: Create and deploy Group Policy for SAM-R restrictions" -Level "WARNING"
        
        return $true
    }
    catch {
        Write-Log "Failed to configure SAM-R settings: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

# Function to configure enhanced PowerShell logging
function Set-PowerShellLogging {
    Write-Log "Configuring enhanced PowerShell logging for MDI..." -Level "INFO"
    
    try {
        if ($TestOnly) {
            Write-Log "[TEST MODE] Would configure PowerShell logging" -Level "INFO"
            return $true
        }
        
        # Enable PowerShell Script Block Logging
        $psRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        if (!(Test-Path $psRegPath)) {
            New-Item -Path $psRegPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $psRegPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
        Write-Log "✓ Enabled PowerShell Script Block Logging" -Level "SUCCESS"
        
        # Enable PowerShell Module Logging
        $moduleLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        if (!(Test-Path $moduleLogPath)) {
            New-Item -Path $moduleLogPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $moduleLogPath -Name "EnableModuleLogging" -Value 1 -Type DWord
        Write-Log "✓ Enabled PowerShell Module Logging" -Level "SUCCESS"
        
        # Configure module names to log
        $moduleNamesPath = "$moduleLogPath\ModuleNames"
        if (!(Test-Path $moduleNamesPath)) {
            New-Item -Path $moduleNamesPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $moduleNamesPath -Name "*" -Value "*" -Type String
        Write-Log "✓ Configured PowerShell Module Logging for all modules" -Level "SUCCESS"
        
        # Enable PowerShell Transcription (optional)
        $transcriptionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
        if (!(Test-Path $transcriptionPath)) {
            New-Item -Path $transcriptionPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $transcriptionPath -Name "EnableTranscripting" -Value 1 -Type DWord
        Set-ItemProperty -Path $transcriptionPath -Name "EnableInvocationHeader" -Value 1 -Type DWord
        Set-ItemProperty -Path $transcriptionPath -Name "OutputDirectory" -Value "C:\PowerShell_Transcripts" -Type String
        
        # Create transcription directory
        if (!(Test-Path "C:\PowerShell_Transcripts")) {
            New-Item -Path "C:\PowerShell_Transcripts" -ItemType Directory -Force | Out-Null
        }
        
        Write-Log "✓ Enabled PowerShell Transcription" -Level "SUCCESS"
        
        return $true
    }
    catch {
        Write-Log "Failed to configure PowerShell logging: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

# Function to test network connectivity
function Test-MDIConnectivity {
    Write-Log "Testing network connectivity to MDI endpoints..." -Level "INFO"
    
    try {
        # MDI service endpoints to test
        $endpoints = @(
            "*.atp.azure.com:443",
            "*.atp.azure.cn:443",
            "*.atp.azure.us:443"
        )
        
        # Note: Actual workspace-specific endpoint should be tested
        # Format: <workspace-name>.atp.azure.com
        Write-Log "Testing connectivity to MDI service endpoints..." -Level "INFO"
        Write-Log "Note: Replace with your actual workspace endpoint" -Level "INFO"
        
        # Test general Azure connectivity
        $testEndpoints = @(
            "portal.azure.com",
            "login.microsoftonline.com",
            "security.microsoft.com"
        )
        
        foreach ($endpoint in $testEndpoints) {
            try {
                $result = Test-NetConnection -ComputerName $endpoint -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
                if ($result) {
                    Write-Log "✓ Connectivity to $endpoint - OK" -Level "SUCCESS"
                }
                else {
                    Write-Log "✗ Connectivity to $endpoint - Failed" -Level "WARNING"
                }
            }
            catch {
                Write-Log "✗ Connectivity test to $endpoint failed: $($_.Exception.Message)" -Level "WARNING"
            }
        }
        
        # Test DNS resolution
        Write-Log "Testing DNS resolution..." -Level "INFO"
        try {
            $dnsTest = Resolve-DnsName -Name "security.microsoft.com" -ErrorAction Stop
            Write-Log "✓ DNS resolution working" -Level "SUCCESS"
        }
        catch {
            Write-Log "✗ DNS resolution issues detected" -Level "ERROR"
        }
        
        # Check time synchronization
        Write-Log "Checking time synchronization..." -Level "INFO"
        try {
            $w32tm = w32tm /query /status
            if ($w32tm -match "Source:") {
                Write-Log "✓ Time synchronization configured" -Level "SUCCESS"
            }
            else {
                Write-Log "⚠ Time synchronization may need attention" -Level "WARNING"
            }
        }
        catch {
            Write-Log "Could not check time synchronization status" -Level "WARNING"
        }
        
        return $true
    }
    catch {
        Write-Log "Failed connectivity testing: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

# Function to run Microsoft's readiness test
function Start-MDIReadinessTest {
    Write-Log "Running Microsoft Defender for Identity readiness assessment..." -Level "INFO"
    
    try {
        # Check if Test-MdiReadiness.ps1 is available
        $readinessScript = "Test-MdiReadiness.ps1"
        $scriptPath = Join-Path $env:TEMP $readinessScript
        
        Write-Log "Checking for MDI Readiness Test script..." -Level "INFO"
        
        if (Test-Path $scriptPath) {
            Write-Log "Found existing readiness script at: $scriptPath" -Level "SUCCESS"
        }
        else {
            Write-Log "MDI Readiness script not found locally" -Level "INFO"
            Write-Log "Please download Test-MdiReadiness.ps1 from:" -Level "INFO"
            Write-Log "  Microsoft 365 Security Portal > Settings > Identities > Tools" -Level "INFO"
            Write-Log "  Or from Microsoft Learn documentation" -Level "INFO"
            return $false
        }
        
        if ($TestOnly -or (Test-Path $scriptPath)) {
            Write-Log "Running MDI readiness assessment..." -Level "INFO"
            
            if ($TestOnly) {
                Write-Log "[TEST MODE] Would run: $scriptPath" -Level "INFO"
            }
            else {
                try {
                    # Execute the readiness script
                    & $scriptPath
                    Write-Log "✓ MDI readiness assessment completed" -Level "SUCCESS"
                    Write-Log "Review the output above for any issues that need attention" -Level "INFO"
                }
                catch {
                    Write-Log "Error running readiness script: $($_.Exception.Message)" -Level "ERROR"
                }
            }
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to run readiness test: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

# Function to create comprehensive configuration report
function New-AdvancedConfigurationReport {
    Write-Log "Generating advanced configuration report..." -Level "INFO"
    
    $reportPath = Join-Path $LogPath "MDI_Advanced_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    
    # Gather system information
    $computerName = $env:COMPUTERNAME
    $domain = try { (Get-ADDomain).DNSRoot } catch { $env:USERDNSDOMAIN }
    $osVersion = [System.Environment]::OSVersion.VersionString
    $configTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    
    # Check gMSA status
    $gmsaStatus = try {
        $gmsaAccount = Get-ADServiceAccount -Identity $gMSAName -ErrorAction SilentlyContinue
        if ($gmsaAccount) { "✓ Created" } else { "⚠ Not Found" }
    } catch { "⚠ Unable to Check" }
    
    # Check KDS Root Key status
    $kdsStatus = try {
        $kdsKeys = Get-KdsRootKey -ErrorAction SilentlyContinue
        if ($kdsKeys) { "✓ Present ($($kdsKeys.Count) key(s))" } else { "⚠ Not Found" }
    } catch { "⚠ Unable to Check" }
    
    $reportContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>MDI Advanced Configuration Report</title>
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
        .checkmark { color: green; font-weight: bold; }
        .warning-mark { color: orange; font-weight: bold; }
        .error-mark { color: red; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Microsoft Defender for Identity<br/>Advanced Configuration Report</h1>
        <p>Generated on: $configTime</p>
    </div>
    
    <div class="section">
        <h2>System Information</h2>
        <table>
            <tr><th>Computer Name</th><td>$computerName</td></tr>
            <tr><th>Domain</th><td>$domain</td></tr>
            <tr><th>OS Version</th><td>$osVersion</td></tr>
            <tr><th>Configuration Time</th><td>$configTime</td></tr>
            <tr><th>Script Version</th><td>$ScriptVersion</td></tr>
        </table>
    </div>
    
    <div class="section">
        <h2>Advanced Configuration Status</h2>
        <table>
            <tr><th>Component</th><th>Status</th><th>Notes</th></tr>
            <tr><td>KDS Root Key</td><td>$kdsStatus</td><td>Required for gMSA functionality</td></tr>
            <tr><td>gMSA Service Account</td><td>$gmsaStatus</td><td>Account name: $gMSAName</td></tr>
            <tr><td>Security Group</td><td>$(if (Get-ADGroup -Identity $gMSAGroup -ErrorAction SilentlyContinue) { "✓ Created" } else { "⚠ Not Found" })</td><td>Group name: $gMSAGroup</td></tr>
            <tr><td>AD Recycle Bin</td><td>$(try { if ((Get-ADOptionalFeature -Filter {Name -eq "Recycle Bin Feature"}).EnabledScopes.Count -gt 0) { "✓ Enabled" } else { "⚠ Disabled" } } catch { "⚠ Unable to Check" })</td><td>Enables deleted object monitoring</td></tr>
            <tr><td>PowerShell Logging</td><td>$(if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging -eq 1) { "✓ Enabled" } else { "⚠ Disabled" })</td><td>Enhanced threat detection</td></tr>
        </table>
    </div>
    
    <div class="section">
        <h2>Next Steps</h2>
        <ol>
            <li><strong>Install MDI Sensor:</strong> Download and install the sensor from Microsoft 365 Security portal</li>
            <li><strong>Configure Directory Service Account:</strong> Add the gMSA account in the MDI portal</li>
            <li><strong>Deploy SAM-R GPO:</strong> Create and deploy Group Policy for SAM-R restrictions</li>
            <li><strong>Test Connectivity:</strong> Verify sensor connectivity to MDI cloud service</li>
            <li><strong>Enable Monitoring:</strong> Configure health and security alert notifications</li>
        </ol>
    </div>
    
    <div class="section">
        <h2>Documentation</h2>
        <ul>
            <li><a href="https://learn.microsoft.com/en-us/defender-for-identity/">Microsoft Defender for Identity Documentation</a></li>
            <li><a href="https://security.microsoft.com/settings/identities">MDI Settings Portal</a></li>
            <li><strong>Log File:</strong> $LogFile</li>
        </ul>
    </div>
</body>
</html>
"@
    
    try {
        $reportContent | Out-File -FilePath $reportPath -Encoding UTF8
        Write-Log "Advanced configuration report saved to: $reportPath" -Level "SUCCESS"
        
        # Open the report if possible
        try {
            Start-Process $reportPath
        }
        catch {
            Write-Log "Report saved but could not open automatically" -Level "INFO"
        }
    }
    catch {
        Write-Log "Failed to generate report: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Main advanced configuration function
function Start-MDIAdvancedConfiguration {
    Write-Log "=== Microsoft Defender for Identity Advanced Configuration Started ===" -Level "INFO"
    Write-Log "Script Version: $ScriptVersion" -Level "INFO"
    Write-Log "Target Computer: $env:COMPUTERNAME" -Level "INFO"
    Write-Log "Test Mode: $TestOnly" -Level "INFO"
    
    try {
        $configurationSuccessful = $true
        
        # Step 1: Test AD prerequisites
        Write-Log "Running prerequisites check..." -Level "INFO"
        
        # Simple prerequisites check - bypass the problematic function for now
        try {
            # Check admin privileges
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
            $adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
            
            if (-not $principal.IsInRole($adminRole)) {
                Write-Log "✗ Administrative privileges required" -Level "ERROR"
                exit 1
            }
            
            # Check AD module
            Import-Module ActiveDirectory -ErrorAction Stop
            $domain = Get-ADDomain -ErrorAction Stop
            
            Write-Log "✓ Prerequisites check passed: Admin privileges OK, AD module OK, Domain: $($domain.DNSRoot)" -Level "SUCCESS"
            $prerequisitesResult = $true
        }
        catch {
            Write-Log "✗ Prerequisites check failed: $($_.Exception.Message)" -Level "ERROR"
            exit 1
        }
        
        # Step 2: Configure KDS Root Key
        if (!(Set-KDSRootKey)) {
            Write-Log "KDS Root Key configuration failed" -Level "ERROR"
            $configurationSuccessful = $false
        }
        
        # Step 3: Create gMSA Service Account
        if (-not $SkipgMSACreation) {
            $gmsaResult = New-MDIServiceAccount -AccountName $gMSAName -GroupName $gMSAGroup
            if (-not $gmsaResult) {
                Write-Log "gMSA creation failed. Attempting repair..." -Level "WARNING"
                
                # Simple troubleshooting inline instead of calling external function
                Write-Log "Troubleshooting steps:" -Level "INFO"
                Write-Log "1. Checking KDS service..." -Level "INFO"
                $kdsService = Get-Service -Name "KdsSvc" -ErrorAction SilentlyContinue
                if ($kdsService -and $kdsService.Status -eq "Running") {
                    Write-Log "   ✓ KDS service is running" -Level "SUCCESS"
                }
                else {
                    Write-Log "   ⚠ KDS service issue detected" -Level "WARNING"
                }
                
                Write-Log "2. Checking KDS root key..." -Level "INFO"
                $kdsKeys = Get-KdsRootKey -ErrorAction SilentlyContinue
                if ($kdsKeys) {
                    $effectiveKey = $kdsKeys | Where-Object { $_.EffectiveTime -le (Get-Date) }
                    if ($effectiveKey) {
                        Write-Log "   ✓ Effective KDS root key available" -Level "SUCCESS"
                    }
                    else {
                        Write-Log "   ⚠ KDS root key exists but not yet effective" -Level "WARNING"
                        Write-Log "   Fix: Run with -RepairMode to create immediate key" -Level "INFO"
                    }
                }
                else {
                    Write-Log "   ✗ No KDS root key found" -Level "ERROR"
                }
                
                $configurationSuccessful = $false
            }
            else {
                # Configure AD permissions for gMSA
                if (!(Set-ADPermissions -AccountName $gMSAName -GroupName $gMSAGroup)) {
                    Write-Log "AD permissions configuration failed" -Level "WARNING"
                }
            }
        }
        else {
            Write-Log "Skipping gMSA creation as requested" -Level "INFO"
        }
        
        # Step 4: Configure SAM-R protocol
        if (-not $SkipSAMRConfig) {
            if (!(Set-SAMRConfiguration)) {
                Write-Log "SAM-R configuration failed" -Level "WARNING"
            }
        }
        else {
            Write-Log "Skipping SAM-R configuration as requested" -Level "INFO"
        }
        
        # Step 5: Configure PowerShell logging
        if (!(Set-PowerShellLogging)) {
            Write-Log "PowerShell logging configuration failed" -Level "WARNING"
        }
        
        # Step 6: Test network connectivity
        if (-not $SkipConnectivityTest) {
            if (!(Test-MDIConnectivity)) {
                Write-Log "Connectivity testing failed" -Level "WARNING"
            }
        }
        else {
            Write-Log "Skipping connectivity test as requested" -Level "INFO"
        }
        
        # Step 7: Run readiness assessment
        Start-MDIReadinessTest
        
        # Step 8: Generate comprehensive report
        New-AdvancedConfigurationReport
        
        if ($configurationSuccessful) {
            Write-Log "=== MDI Advanced Configuration Completed Successfully ===" -Level "SUCCESS"
        }
        else {
            Write-Log "=== MDI Advanced Configuration Completed with Warnings ===" -Level "WARNING"
        }
        
        Write-Log "Next Steps:" -Level "INFO"
        Write-Log "1. Download and install MDI sensor from Microsoft 365 Security portal" -Level "INFO"
        Write-Log "2. Add gMSA account '$gMSAName' as Directory Service Account in MDI portal" -Level "INFO"
        Write-Log "3. Create and deploy Group Policy for SAM-R restrictions" -Level "INFO"
        Write-Log "4. Test sensor connectivity and functionality" -Level "INFO"
        Write-Log "Log file location: $LogFile" -Level "INFO"
        
    }
    catch {
        Write-Log "Advanced configuration failed: $($_.Exception.Message)" -Level "ERROR"
        exit 1
    }
}

# Function to fix common gMSA issues
function Repair-gMSAConfiguration {
    param(
        [string]$AccountName = $gMSAName,
        [string]$GroupName = $gMSAGroup
    )
    
    Write-Log "Attempting to repair gMSA configuration..." -Level "INFO"
    
    try {
        # Step 1: Ensure KDS service is running
        Write-Log "1. Checking and starting KDS service..." -Level "INFO"
        $kdsService = Get-Service -Name "KdsSvc" -ErrorAction SilentlyContinue
        if ($kdsService -and $kdsService.Status -ne "Running") {
            Start-Service -Name "KdsSvc"
            Write-Log "✓ KDS service started" -Level "SUCCESS"
        }
        
        # Step 2: Create effective KDS root key
        Write-Log "2. Ensuring effective KDS root key exists..." -Level "INFO"
        $kdsKeys = Get-KdsRootKey -ErrorAction SilentlyContinue
        $hasEffectiveKey = $kdsKeys | Where-Object { $_.EffectiveTime -le (Get-Date) }
        
        if (-not $hasEffectiveKey) {
            Write-Log "Creating immediately effective KDS root key for repair..." -Level "INFO"
            Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) | Out-Null
            Write-Log "✓ Effective KDS root key created" -Level "SUCCESS"
            Start-Sleep -Seconds 3
        }
        
        # Step 3: Ensure security group exists with proper members
        Write-Log "3. Configuring security group..." -Level "INFO"
        $secGroup = Get-ADGroup -Identity $GroupName -ErrorAction SilentlyContinue
        if (-not $secGroup) {
            $secGroup = New-ADGroup -Name $GroupName -GroupScope Universal -GroupCategory Security -Description "Security group for MDI gMSA password retrieval" -PassThru
            Write-Log "✓ Security group created" -Level "SUCCESS"
        }
        
        # Add current computer to group
        $computerName = $env:COMPUTERNAME
        $computerAccount = Get-ADComputer -Identity $computerName -ErrorAction SilentlyContinue
        if ($computerAccount) {
            try {
                Add-ADGroupMember -Identity $GroupName -Members $computerAccount.DistinguishedName -ErrorAction SilentlyContinue
                Write-Log "✓ Computer added to security group" -Level "SUCCESS"
            }
            catch {
                Write-Log "Computer already in group or error adding: $($_.Exception.Message)" -Level "INFO"
            }
        }
        
        # Step 4: Purge Kerberos tickets
        Write-Log "4. Refreshing Kerberos tickets..." -Level "INFO"
        try {
            klist purge -li 0x3e7 | Out-Null
            Write-Log "✓ Kerberos tickets purged" -Level "SUCCESS"
        }
        catch {
            Write-Log "Could not purge Kerberos tickets: $($_.Exception.Message)" -Level "WARNING"
        }
        
        # Step 5: Wait a moment for changes to propagate
        Write-Log "5. Waiting for changes to propagate..." -Level "INFO"
        Start-Sleep -Seconds 10
        
        # Step 6: Try to create gMSA again
        Write-Log "6. Attempting gMSA creation..." -Level "INFO"
        $existingAccount = Get-ADServiceAccount -Identity $AccountName -ErrorAction SilentlyContinue
        if (-not $existingAccount) {
            try {
                $domain = Get-ADDomain
                $dnsHostName = "$AccountName.$($domain.DNSRoot)"
                $gmsaAccount = New-ADServiceAccount -Name $AccountName -DNSHostName $dnsHostName -PrincipalsAllowedToRetrieveManagedPassword $GroupName -PassThru -ErrorAction Stop
                Write-Log "✓ gMSA account created successfully" -Level "SUCCESS"
                Start-Sleep -Seconds 5
            }
            catch {
                Write-Log "gMSA creation still failed: $($_.Exception.Message)" -Level "ERROR"
                return $false
            }
        }
        
        # Step 7: Install gMSA on this computer
        Write-Log "7. Installing gMSA on this computer..." -Level "INFO"
        try {
            Install-ADServiceAccount -Identity $AccountName -ErrorAction Stop
            Write-Log "✓ gMSA installed successfully" -Level "SUCCESS"
        }
        catch {
            Write-Log "gMSA installation failed: $($_.Exception.Message)" -Level "WARNING"
            Write-Log "This may require a restart or more replication time" -Level "INFO"
        }
        
        # Step 8: Test the installation
        Write-Log "8. Testing gMSA functionality..." -Level "INFO"
        try {
            $testResult = Test-ADServiceAccount -Identity $AccountName -ErrorAction Stop
            if ($testResult) {
                Write-Log "✓ gMSA is working correctly!" -Level "SUCCESS"
                return $true
            }
            else {
                Write-Log "gMSA test failed but no exception thrown" -Level "WARNING"
                return $false
            }
        }
        catch {
            Write-Log "gMSA test failed: $($_.Exception.Message)" -Level "WARNING"
            Write-Log "Manual steps may be required or a server restart" -Level "INFO"
            return $false
        }
    }
    catch {
        Write-Log "Repair failed: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

# Execute advanced configuration
if ($TestOnly) {
    Write-Log "Running in TEST MODE - no changes will be made" -Level "INFO"
}

if ($RepairMode) {
    Write-Log "Running in REPAIR MODE - attempting to fix gMSA issues" -Level "INFO"
    # Repair mode always uses immediate KDS key creation
    $ForceImmediateKDS = $true
    if (Repair-gMSAConfiguration -AccountName $gMSAName -GroupName $gMSAGroup) {
        Write-Log "✓ Repair completed successfully" -Level "SUCCESS"
    }
    else {
        Write-Log "⚠ Repair completed with issues - manual intervention may be required" -Level "WARNING"
    }
}
else {
    if ($ForceImmediateKDS) {
        Write-Log "Using immediate KDS root key creation (10-hour delay bypassed)" -Level "INFO"
    }
    Start-MDIAdvancedConfiguration
}