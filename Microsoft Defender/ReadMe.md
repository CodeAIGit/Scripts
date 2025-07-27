# Microsoft Defender for Identity (MDI) Configuration Scripts

PowerShell scripts for configuring domain controllers with all necessary policies, auditing, and service accounts for Microsoft Defender for Identity deployment.

## 👨‍💻 Author Information

**Author**: Gulab Prasad  
**Website**: [gulabprasad.com](https://gulabprasad.com/)  
**Contact**: [GitHub Profile](https://github.com/CodeAIGit)  
**License**: MIT License  

## 📋 Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Script Components](#script-components)
- [Quick Start](#quick-start)
- [Basic Configuration](#basic-configuration)
- [Advanced Configuration](#advanced-configuration)
- [MDI Sensor Installation](#mdi-sensor-installation)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)

## 🎯 Overview

This repository contains two PowerShell scripts designed to prepare Windows Server domain controllers for Microsoft Defender for Identity:

1. **Basic Configuration Script** (`Configure-MDI-Basic.ps1`) - Core auditing and logging setup
2. **Advanced Configuration Script** (`Configure-MDI-Advanced.ps1`) - Service accounts, enhanced security, and connectivity testing

Both scripts follow Microsoft best practices and automate the complex configuration process required for optimal MDI deployment.

## ⚙️ Prerequisites

### System Requirements
- **Operating System**: Windows Server 2012 R2 or later
- **Role**: Domain Controller (recommended)
- **Permissions**: Domain Administrator privileges
- **PowerShell**: Version 5.1 or later
- **Memory**: Minimum 2GB RAM
- **Disk Space**: Minimum 6GB free space
- **.NET Framework**: 4.7 or later

### Active Directory Requirements
- **Domain Functional Level**: Windows Server 2012 or higher (for gMSA support)
- **Forest Functional Level**: Windows Server 2012 or higher
- **Time Synchronization**: Domain controllers synchronized within 5 minutes
- **RSAT**: Active Directory PowerShell module installed

### Network Requirements
- **Outbound HTTPS (443)**: Access to `*.atp.azure.com`
- **DNS Resolution**: Functional DNS for domain and internet
- **Firewall**: Configured per script recommendations

## 📦 Script Components

### Basic Configuration Script (`Configure-MDI-Basic.ps1`)
**Author**: Gulab Prasad

**Features:**
- ✅ **Windows Defender exclusions** for MDI processes
- ✅ **Advanced audit policies** (18 critical subcategories)
- ✅ **NTLM auditing** configuration
- ✅ **Domain object auditing** with SACL settings
- ✅ **Event log sizing** and retention policies
- ✅ **Firewall rules** for MDI communication
- ✅ **Prerequisites validation**
- ✅ **Configuration verification**
- ✅ **Scheduled maintenance tasks**
- ✅ **HTML reporting**

### Advanced Configuration Script (`Configure-MDI-Advanced.ps1`)
**Author**: Gulab Prasad

**Features:**
- ✅ **KDS Root Key** creation and management
- ✅ **Group Managed Service Account (gMSA)** setup
- ✅ **Security group management** for gMSA
- ✅ **Active Directory permissions** configuration
- ✅ **SAM-R protocol** restrictions (GPO guidance)
- ✅ **PowerShell enhanced logging**
- ✅ **Active Directory Recycle Bin** enablement
- ✅ **Network connectivity testing**
- ✅ **Microsoft readiness assessment**
- ✅ **Comprehensive troubleshooting**

## 🚀 Quick Start

### 1. Download Scripts
```powershell
# Clone repository or download scripts
git clone https://github.com/your-repo/mdi-configuration-scripts.git
cd mdi-configuration-scripts
```

### 2. Run Basic Configuration
```powershell
# Execute with administrative privileges
.\Configure-MDI-Basic.ps1
```

### 3. Run Advanced Configuration
```powershell
# Full advanced setup with immediate KDS key
.\Configure-MDI-Advanced.ps1 -ForceImmediateKDS
```

### 4. Install MDI Sensor
Follow the [MDI Sensor Installation](#mdi-sensor-installation) section below.

## 🔧 Basic Configuration

### Script: `Configure-MDI-Basic.ps1`
**Author**: Gulab Prasad

#### Basic Usage
```powershell
# Standard configuration
.\Configure-MDI-Basic.ps1

# Custom log location
.\Configure-MDI-Basic.ps1 -LogPath "D:\MDI_Logs"

# Skip specific components
.\Configure-MDI-Basic.ps1 -SkipAuditPolicies
.\Configure-MDI-Basic.ps1 -SkipFirewallRules
.\Configure-MDI-Basic.ps1 -SkipNTLMAuditing
.\Configure-MDI-Basic.ps1 -SkipDomainObjectAuditing
```

#### Key Configurations Applied

**Audit Policies Enabled:**
- Credential Validation
- Kerberos Authentication Service
- Kerberos Service Ticket Operations
- Computer Account Management
- Security Group Management
- User Account Management
- Directory Service Access
- Directory Service Changes
- Directory Service Replication
- Logon/Logoff events
- Special Logon
- Sensitive Privilege Use
- Authentication Policy Change
- Authorization Policy Change
- System Integrity

**NTLM Auditing Settings:**
- `AuditReceivingNTLMTraffic` = 2
- `RestrictSendingNTLMTraffic` = 1
- `LmCompatibilityLevel` = 5

**Event Log Configuration:**
- Security Log: 1GB maximum size
- System Log: 512MB maximum size
- Retention: Overwrite as needed

### Output Files
- **Log File**: `C:\MDI_Deployment_Logs\MDI_Configuration_[timestamp].log`
- **Report**: `C:\MDI_Deployment_Logs\MDI_Configuration_Report_[timestamp].html`

## 🚀 Advanced Configuration

### Script: `Configure-MDI-Advanced.ps1`
**Author**: Gulab Prasad

#### Advanced Usage
```powershell
# Full configuration with immediate KDS
.\Configure-MDI-Advanced.ps1 -ForceImmediateKDS

# Custom gMSA and group names
.\Configure-MDI-Advanced.ps1 -gMSAName "MyMDIService" -gMSAGroup "MyMDIGroup"

# Test mode (no changes)
.\Configure-MDI-Advanced.ps1 -TestOnly

# Repair existing configuration
.\Configure-MDI-Advanced.ps1 -RepairMode

# Skip specific components
.\Configure-MDI-Advanced.ps1 -SkipgMSACreation
.\Configure-MDI-Advanced.ps1 -SkipSAMRConfig
.\Configure-MDI-Advanced.ps1 -SkipADEnhancements
.\Configure-MDI-Advanced.ps1 -SkipConnectivityTest
```

#### Key Components Created

**Service Accounts:**
- **gMSA Account**: `mdiSvc01$` (default)
- **Security Group**: `mdiSvc01Group` (default)
- **Permissions Group**: `mdiSvc01Group_Permissions`

**Active Directory Enhancements:**
- KDS Root Key with immediate or delayed effectiveness
- AD Recycle Bin enablement
- Deleted Objects container permissions
- Domain root read permissions

**Security Configurations:**
- PowerShell Script Block Logging
- PowerShell Module Logging
- PowerShell Transcription
- Enhanced audit trail

### KDS Root Key Management

**Production Mode (Recommended):**
```powershell
# Standard 10-hour replication delay
.\Configure-MDI-Advanced.ps1
```

**Development/Testing Mode:**
```powershell
# Immediate effectiveness (bypass 10-hour delay)
.\Configure-MDI-Advanced.ps1 -ForceImmediateKDS
```

**Manual KDS Key Creation:**
```powershell
# For production
Add-KdsRootKey

# For immediate testing
Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))
```

### Output Files
- **Log File**: `C:\MDI_Advanced_Logs\MDI_Advanced_Configuration_[timestamp].log`
- **Report**: `C:\MDI_Advanced_Logs\MDI_Advanced_Report_[timestamp].html`

## 📥 MDI Sensor Installation

### Step 1: Download Sensor
1. Navigate to **Microsoft 365 Security Portal**: https://security.microsoft.com
2. Go to **Settings** > **Identities** > **Sensors**
3. Click **"Add sensor"**
4. Click **"Download installer"**
5. **Copy the Access Key** (required for installation)

### Step 2: Install Sensor
```powershell
# Basic installation
.\Azure\ ATP\ Sensor\ Setup.exe /quiet AccessKey="your-access-key-from-portal"

# Installation with proxy
.\Azure\ ATP\ Sensor\ Setup.exe /quiet AccessKey="your-access-key" ProxyUrl="http://proxy:8080"
```

### Step 3: Verify Installation
```powershell
# Check service status
Get-Service AATPSensor

# Verify installation
Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Azure Advanced Threat Protection*" }
```

### Step 4: Configure gMSA in Portal
1. **Navigate to**: **Settings** > **Identities** > **Directory service accounts**
2. **Click**: **"Add account"**
3. **Configure**:
   - **Username**: `mdiSvc01$` (note the $ suffix)
   - **Domain**: `yourdomain.com`
   - **Account type**: **Group Managed Service Account**
4. **Save** configuration

### Step 5: Install gMSA on Domain Controller
```powershell
# Install gMSA locally
Install-ADServiceAccount -Identity mdiSvc01

# Test gMSA functionality
Test-ADServiceAccount -Identity mdiSvc01
# Should return: True
```

### Step 6: Final Verification
```powershell
# Check sensor connectivity in portal
# Settings > Identities > Sensors
# Your DC should show as "Connected"

# Check for health issues
# Settings > Identities > Health issues
# Should show no critical errors
```
<img width="3454" height="1124" alt="image" src="https://github.com/user-attachments/assets/b2da8f45-c2f9-4616-8bdd-6c0ea26f897e" />

<img width="1758" height="1044" alt="image" src="https://github.com/user-attachments/assets/f11a8ef6-e816-4e55-a3ce-28d4feadb95c" />

## 🛠️ Troubleshooting

### Common Issues and Solutions

#### gMSA Installation Fails
**Problem**: `Access Denied` when installing gMSA
```powershell
# Solution 1: Refresh Kerberos tickets
klist purge -li 0x3e7
Install-ADServiceAccount -Identity mdiSvc01

# Solution 2: Restart server
Restart-Computer
# After restart, retry installation
```

#### KDS Root Key Not Effective
**Problem**: Key created but not yet usable
```powershell
# Check key status
Get-KdsRootKey

# Create immediate key for testing
Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))
```

#### Sensor Not Connecting
**Problem**: Sensor installed but not connecting to cloud
```powershell
# Check network connectivity
Test-NetConnection -ComputerName "yourworkspace.atp.azure.com" -Port 443

# Check sensor service
Get-Service AATPSensor
Restart-Service AATPSensor

# Check firewall rules
Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*MDI*" }
```

#### Prerequisites Check Failing
**Problem**: Script prerequisites not passing
```powershell
# Install AD PowerShell module
Install-WindowsFeature RSAT-AD-PowerShell

# Verify domain connectivity
Get-ADDomain

# Check permissions
Get-ADUser $env:USERNAME -Properties MemberOf
```

### Repair Mode
For automatic troubleshooting and repair:
```powershell
.\Configure-MDI-Advanced.ps1 -RepairMode
```

### Manual Verification Commands
```powershell
# Check gMSA status
Get-ADServiceAccount -Identity mdiSvc01 -Properties *

# Verify security group membership
Get-ADGroupMember -Identity mdiSvc01Group

# Test AD permissions
Get-ADUser -Filter * -SearchBase "CN=Deleted Objects,DC=yourdomain,DC=com" -IncludeDeletedObjects

# Check audit policies
auditpol /get /category:*

# Verify KDS service
Get-Service KdsSvc
```

## 🔒 Security Considerations

### Service Account Security
- **gMSA accounts** provide automatic password management
- **Principle of least privilege** - read-only AD access
- **Group-based permissions** for easier management
- **No manual password management** required

### Audit Policy Impact
- **Increased log volume** - monitor disk space
- **Performance considerations** - test in non-production first
- **Retention policies** - configure log archival
- **Compliance alignment** - meets security frameworks

### Network Security
- **Encrypted communications** to MDI cloud service
- **Certificate validation** for secure connections
- **Firewall rules** for minimal required access
- **Proxy support** for restricted environments

### Monitoring and Maintenance
- **Weekly maintenance tasks** scheduled automatically
- **Health monitoring** through MDI portal
- **Log rotation** to prevent disk exhaustion
- **Regular updates** for sensor software

## 📋 SAM-R Configuration (Manual Step)

The scripts provide guidance for SAM-R configuration, which requires Group Policy:

### Create SAM-R GPO
1. **Open Group Policy Management Console**
2. **Create new GPO**: "MDI SAM-R Restrictions"
3. **Navigate to**:
   - Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
4. **Configure**:
   - Policy: "Network access: Restrict clients allowed to make remote calls to SAM"
   - Value: `O:BAG:BAD:(A;;RC;;;BA)(A;;RC;;;[gMSA-SID])`
5. **Link to all computers** except Domain Controllers
6. **Test and deploy** in phases

### Get gMSA SID
```powershell
# Get SID for gMSA account
$gMSA = Get-ADServiceAccount -Identity mdiSvc01
$gMSA.SID
```

## 🤝 Contributing

We welcome contributions to improve these MDI configuration scripts!

### Reporting Issues
- Use GitHub Issues for bug reports
- Include log files and error messages
- Specify OS version and domain functional level
- Provide script parameters used

### Feature Requests
- Describe the use case
- Explain the business justification
- Consider security implications
- Provide implementation suggestions

### Code Contributions
- Follow PowerShell best practices
- Include comprehensive error handling
- Add appropriate logging
- Update documentation
- Test in multiple environments
- **Maintain attribution** to original author (Gulab Prasad)
- **Keep the MIT license intact**

### Attribution Guidelines
When forking or modifying these scripts:
- Maintain original author credit: [Gulab Prasad](https://gulabprasad.com/)
- Add your contributions to documentation
- Keep the MIT license intact

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Gulab Prasad** - Script author and MDI security specialist
- Microsoft Defender for Identity team for excellent documentation
- PowerShell community for best practices and guidance
- Security professionals who provided feedback and testing
- Active Directory and gMSA community contributions

## 📞 Support

For issues and questions:
1. Check the [Troubleshooting](#troubleshooting) section
2. Review [Microsoft's official MDI documentation](https://learn.microsoft.com/en-us/defender-for-identity/)
3. Contact the author: **Gulab Prasad** via [Website](https://gulabprasad.com/) or [GitHub Issues](https://github.com/gulabprasad)
4. For Microsoft support: https://support.microsoft.com

---

**👨‍💻 Created by**: [Gulab Prasad](https://gulabprasad.com/) | **🔗 Website**: [gulabprasad.com](https://gulabprasad.com/)

**⚠️ Important**: Always test these scripts in a non-production environment first. Ensure you have proper backups and rollback procedures before implementing in production.

**📋 Compatibility**: Tested on Windows Server 2016/2019/2022 with various domain functional levels. Results may vary in older environments.

**🔄 Updates**: Check for script updates regularly as Microsoft may change MDI requirements or best practices.

**🌐 More Resources**: Visit [gulabprasad.com](https://gulabprasad.com/) for additional cybersecurity tools and guides.
