# Entra ID Connect Health Check Script

A PowerShell script for monitoring and analyzing Entra ID Connect (Azure AD Connect) health, configuration, and synchronization status.

## 👨‍💻 Author

**Gulab Prasad**
- GitHub: [@CodeAIGit](https://github.com/CodeAIGit)
- LinkedIn: [Gulab Prasad](https://linkedin.com/in/gulab)
- Email: contact@gulabprasad.com
- Blog: [Gulab Prasad](https://gulabprasad.com)

![image](https://github.com/user-attachments/assets/3f9038e3-5812-443c-b219-84ed35831a43)

## 🎯 Overview

This script provides enterprise-level health monitoring and detailed reporting for Azure AD Connect installations. It analyzes synchronization status, connector health, sync rules configuration, object counts, and generates both console output and professional HTML reports.

**Perfect for:** System administrators, identity engineers, compliance teams, and anyone managing Azure AD Connect infrastructure.

## ✨ Features

### 🔍 Health Monitoring
- **Real-time sync status** - Current synchronization state and scheduler status
- **Connector analysis** - Detailed information about AD and Azure AD connectors
- **Object count verification** - Users, groups, and contacts synchronized
- **Error detection** - Network issues, connectivity problems, and sync errors
- **Version tracking** - Azure AD Connect version and update recommendations

### ⚙️ Sync Rules Analysis
- **Complete rule inventory** - All inbound and outbound synchronization rules
- **Enabled rules details** - Names, precedence, and full configuration
- **Custom vs out-of-box** - Identify modifications and customizations
- **Precedence conflicts** - Detect rules with same priority levels
- **Transformation mapping** - Attribute flows and business logic
- **Scope and join filters** - Object filtering and matching criteria

### 🏢 Organizational Units
- **OU filtering status** - Which organizational units are synchronized
- **Connector partitions** - Domain and forest information
- **Filtering detection** - Multiple methods to identify OU scope

### 📊 Professional Reporting
- **Console output** - Color-coded, real-time status information
- **HTML reports** - Professional, detailed documentation
- **Audit compliance** - Complete configuration documentation
- **Trend analysis** - Recently modified rules and change tracking

## 🔧 Prerequisites

### Required Software
- **Windows PowerShell 5.1** (Required - PowerShell 7+ not supported)
- **Azure AD Connect** installed and configured
- **Administrative privileges** on the Azure AD Connect server

### Required Modules
The script automatically checks for and uses:
- **ADSync module** (installed with Azure AD Connect)
- **ActiveDirectory module** (for enhanced object counting)

### Supported Versions
- ✅ **Azure AD Connect 1.0+** (Basic functionality)
- ✅ **Azure AD Connect 1.3+** (Enhanced features)
- ✅ **Azure AD Connect 2.0+** (Full feature support)

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/CodeAIGit/azure-ad-connect-health-check.git
cd azure-ad-connect-health-check
```

### 2. Run the Health Check
```powershell
# Navigate to script directory
cd azure-ad-connect-health-check

# Run the health check
.\EntraConnect-HealthCheck.ps1
```

### 3. View the Results
- **Console Output** - Real-time colored status information
- **HTML Report** - Professional report saved to your Desktop

## 📋 Usage

### Basic Usage
```powershell
# Basic health check
.\EntraConnect-HealthCheck.ps1
```

### Advanced Usage
```powershell
# Run with verbose output
.\EntraConnect-HealthCheck.ps1 -Verbose

# Run in Windows PowerShell 5.1 from PowerShell 7
powershell.exe -File ".\EntraConnect-HealthCheck.ps1"
```

### Automated Execution
```powershell
# Create scheduled task for daily health checks
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File C:\Scripts\Azure\EntraConnect-HealthCheck.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At "08:00AM"
Register-ScheduledTask -TaskName "Azure AD Connect Health Check" -Action $action -Trigger $trigger
```

## 📊 Sample Output

### Console Output
```
🌐 AZURE AD CONNECT HEALTH CHECK
================================
Report generated: December 21, 2024 10:30:45 AM

🔧 AZURE AD CONNECT VERSION
===========================
Version: 2.0.2.182
Status: ✓ Supported version
Location: C:\Program Files\Microsoft Azure AD Sync\Bin

⚡ SYNCHRONIZATION STATUS
========================
Sync Enabled: ✓ Yes
Sync Cycle: Enabled
Last Sync: 2024-12-21 10:25:33 AM (5 minutes ago)
Status: ✓ Healthy - Recent successful sync

👥 SYNCHRONIZED OBJECTS
======================
Users: 1,247
Groups: 156
Contacts: 23
Total: 1,426 objects

⚙️ SYNCHRONIZATION RULES
========================
📋 Rules Summary: 127 total rules

📥 Inbound Rules: 89 (85 enabled)
📤 Outbound Rules: 38 (37 enabled)
Custom Rules: 17
✓ No sync rule issues detected

📜 ENABLED SYNC RULES DETAILS
==============================
🔹 In from AD - User Common [OUT-OF-BOX]
   Precedence: 100
   Source: user → Target: person
   Key Transformations:
     • userPrincipalName → userPrincipalName (Direct)
     • mail → mail (Direct)
```

### HTML Report Features
- **Executive Summary** - Overall health status and key metrics
- **Detailed Tables** - Professional formatting with sortable columns
- **Color Coding** - Visual indicators for status and rule types
- **Configuration Details** - Complete sync rules with transformations
- **Audit Trail** - Recently modified rules and change history

## 🛠️ Installation & Setup

### Method 1: GitHub Download
1. Download the repository as ZIP
2. Extract to your preferred location (e.g., `C:\Scripts\Azure`)
3. Set execution policy: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine`

### Method 2: Git Clone
```bash
git clone https://github.com/CodeAIGit/Scripts.git
cd azure-ad-connect-health-check
```

### Method 3: Direct Download
```powershell
# Download script directly
$scriptPath = "C:\Scripts\Azure"
New-Item -Path $scriptPath -ItemType Directory -Force
Invoke-WebRequest -Uri "https://github.com/CodeAIGit/Scripts/blob/main/EntraID_Connect_Health/EntraConnect-HealthCheck.ps1" -OutFile "$scriptPath\EntraConnect-HealthCheck.ps1"
```

## 🔍 Understanding the Output

### Sync Rule Types
- **📥 Inbound Rules** - Control data flow from on-premises AD to metaverse
- **📤 Outbound Rules** - Control data flow from metaverse to Azure AD
- **[CUSTOM]** - Rules created or modified by administrators
- **[OUT-OF-BOX]** - Default Microsoft-provided rules

### Health Status Indicators
- **✅ Good** - All systems operating normally
- **⚠️ Warning** - Minor issues that should be addressed
- **❌ Critical** - Serious problems requiring immediate attention

### Rule Configuration
- **Precedence** - Lower numbers = higher priority (0 is highest)
- **Object Types** - user, group, contact, device, etc.
- **Link Types** - Join (match existing) or Provision (create new)
- **Scope Filters** - Conditions that determine which objects are processed
- **Transformations** - How attributes are mapped and modified

## 🐛 Troubleshooting

### Common Issues

#### PowerShell 7 Compatibility Error
```
Error: Could not load type 'System.Web.Util.Utf16StringValidator'
```
**Solution:** Use Windows PowerShell 5.1 instead of PowerShell 7
```powershell
# Use this instead of pwsh.exe
powershell.exe -File ".\EntraConnect-HealthCheck.ps1"
```

#### Module Not Found
```
Error: The ADSync module is not available
```
**Solution:** Run on the Azure AD Connect server where ADSync module is installed

#### Access Denied
```
Error: Access to the path is denied
```
**Solution:** Run PowerShell as Administrator

#### No Connectors Found
```
Warning: No AD connectors found
```
**Solution:** Verify Azure AD Connect is properly configured and connectors are created

## 📅 Best Practices

### Regular Health Checks
- **Daily** - Automated health monitoring
- **Weekly** - Review sync rule changes
- **Monthly** - Analyze object count trends
- **Quarterly** - Version update planning

### Report Management
- **Archive reports** - Keep historical data for trend analysis
- **Share with team** - Distribution for change management
- **Compliance storage** - Retain for audit requirements

## 📊 Roadmap

### Upcoming Features
- [ ] **Multi-forest support** - Enhanced support for complex AD topologies
- [ ] **Cloud sync integration** - Azure AD Cloud Sync compatibility
- [ ] **REST API integration** - Microsoft Graph API integration
- [ ] **Performance metrics** - Sync performance analysis
- [ ] **Email notifications** - Automated alerting system
- [ ] **PowerBI integration** - Advanced reporting and dashboards

### Version History
- **v2.0** (Current) - Complete sync rules analysis, enhanced reporting
- **v1.0** - Initial release with basic health monitoring


## 🎯 Why This Script?

Born from real-world enterprise experience managing complex Azure AD Connect environments, this script addresses the common challenges faced by identity engineers:

- **Manual health checks** taking hours to complete
- **Lack of detailed sync rules documentation**
- **Difficulty identifying configuration drift**
- **Time-consuming troubleshooting processes**
- **Compliance reporting requirements**

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

### What this means:
- ✅ **Free to use** - Personal and commercial use
- ✅ **Modify freely** - Adapt to your needs
- ✅ **Share and distribute** - Help others in the community
- ⚠️ **No warranty** - Use at your own risk

## 🙏 Acknowledgments

- **Microsoft Azure AD Connect Team** - For the excellent ADSync PowerShell module
- **PowerShell Community** - For continuous inspiration and best practices
- **Enterprise customers** - For real-world feedback and requirements
- **Open source community** - For making knowledge sharing possible

## 📞 Support & Community

### 💬 Getting Help
- **GitHub Issues** - [Report bugs or request features](https://github.com/gulabprasad/azure-ad-connect-health-check/issues)
- **Discussions** - [Community Q&A and discussions](https://github.com/gulabprasad/azure-ad-connect-health-check/discussions)
- **Documentation** - Check this README and script comments

### 🌟 Show Your Support
If this script helps you, please:
- ⭐ **Star the repository**
- 🍴 **Fork and contribute**
- 📢 **Share with colleagues**
- 💬 **Provide feedback**

### 📈 Project Stats
![GitHub contributors](https://img.shields.io/github/contributors/gulabprasad/azure-ad-connect-health-check.svg)
![GitHub last commit](https://img.shields.io/github/last-commit/gulabprasad/azure-ad-connect-health-check.svg)
![GitHub repo size](https://img.shields.io/github/repo-size/gulabprasad/azure-ad-connect-health-check.svg)

## 🏷️ Tags

`Azure AD Connect` `Entra ID` `PowerShell` `Monitoring` `Health Check` `Sync Rules` `Reporting` `Active Directory` `Identity Management` `Automation` `DevOps` `Infrastructure` `Compliance` `Enterprise`

---

**Made by [Gulab Prasad](https://github.com/gulabprasad) for the Azure AD Connect community**

*Empowering identity professionals with better tools and insights*

---

### 📋 Quick Links
- [🚀 Quick Start](#-quick-start)
- [📊 Sample Output](#-sample-output)
- [🛠️ Troubleshooting](#-troubleshooting)
- [🤝 Contributing](#-contributing)
- [👨‍💻 Author](#-author)
- [📄 License](#-license)

## ✨ Features

### 🔍 Health Monitoring
- **Real-time sync status** - Current synchronization state and scheduler status
- **Connector analysis** - Detailed information about AD and Azure AD connectors
- **Object count verification** - Users, groups, and contacts synchronized
- **Error detection** - Network issues, connectivity problems, and sync errors
- **Version tracking** - Azure AD Connect version and update recommendations

### ⚙️ Sync Rules Analysis
- **Complete rule inventory** - All inbound and outbound synchronization rules
- **Enabled rules details** - Names, precedence, and full configuration
- **Custom vs out-of-box** - Identify modifications and customizations
- **Precedence conflicts** - Detect rules with same priority levels
- **Transformation mapping** - Attribute flows and business logic
- **Scope and join filters** - Object filtering and matching criteria

### 🏢 Organizational Units
- **OU filtering status** - Which organizational units are synchronized
- **Connector partitions** - Domain and forest information
- **Filtering detection** - Multiple methods to identify OU scope

### 📊 Professional Reporting
- **Console output** - Color-coded, real-time status information
- **HTML reports** - Professional, detailed documentation
- **Audit compliance** - Complete configuration documentation
- **Trend analysis** - Recently modified rules and change tracking

## 🔧 Prerequisites

### Required Software
- **Windows PowerShell 5.1** (Required - PowerShell 7+ not supported)
- **Azure AD Connect** installed and configured
- **Administrative privileges** on the Azure AD Connect server

### Required Modules
The script automatically checks for and uses:
- **ADSync module** (installed with Azure AD Connect)
- **ActiveDirectory module** (for enhanced object counting)

### Supported Versions
- ✅ **Azure AD Connect 1.0+** (Basic functionality)
- ✅ **Azure AD Connect 1.3+** (Enhanced features)
- ✅ **Azure AD Connect 2.0+** (Full feature support)

## 🚀 Installation & Setup

### 1. Download the Script
```powershell
# Download to your scripts directory
$scriptPath = "C:\Scripts\Azure"
New-Item -Path $scriptPath -ItemType Directory -Force
# Copy EntraConnect-HealthCheck.ps1 to this directory
```

### 2. Set Execution Policy (if needed)
```powershell
# Allow script execution (run as Administrator)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
```

### 3. Verify Prerequisites
```powershell
# Check PowerShell version (must be 5.1)
$PSVersionTable.PSVersion

# Verify Azure AD Connect installation
Get-Module ADSync -ListAvailable

# Check if running on Azure AD Connect server
Get-Service ADSync -ErrorAction SilentlyContinue
```

## 📋 Usage

### Basic Usage
```powershell
# Navigate to script directory
cd "C:\Scripts\Azure"

# Run the health check
.\EntraConnect-HealthCheck.ps1
```

### Advanced Usage
```powershell
# Run with verbose output
.\EntraConnect-HealthCheck.ps1 -Verbose

# Run in Windows PowerShell 5.1 from PowerShell 7
powershell.exe -File ".\EntraConnect-HealthCheck.ps1"
```

### Automated Execution
```powershell
# Create scheduled task for daily health checks
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File C:\Scripts\Azure\EntraConnect-HealthCheck.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At "08:00AM"
Register-ScheduledTask -TaskName "Azure AD Connect Health Check" -Action $action -Trigger $trigger
```

## 📊 Output Examples

### Console Output
```
🌐 AZURE AD CONNECT HEALTH CHECK
================================
Report generated: December 21, 2024 10:30:45 AM

🔧 AZURE AD CONNECT VERSION
===========================
Version: 2.0.2.182
Status: ✓ Supported version
Location: C:\Program Files\Microsoft Azure AD Sync\Bin

⚡ SYNCHRONIZATION STATUS
========================
Sync Enabled: ✓ Yes
Sync Cycle: Enabled
Last Sync: 2024-12-21 10:25:33 AM (5 minutes ago)
Status: ✓ Healthy - Recent successful sync

👥 SYNCHRONIZED OBJECTS
======================
Users: 1,247
Groups: 156
Contacts: 23
Total: 1,426 objects

⚙️ SYNCHRONIZATION RULES
========================
📋 Rules Summary: 127 total rules

📥 Inbound Rules: 89 (85 enabled)
📤 Outbound Rules: 38 (37 enabled)
Custom Rules: 17
✓ No sync rule issues detected
```

### HTML Report Features
- **Executive Summary** - Overall health status and key metrics
- **Detailed Tables** - Professional formatting with sortable columns
- **Color Coding** - Visual indicators for status and rule types
- **Configuration Details** - Complete sync rules with transformations
- **Audit Trail** - Recently modified rules and change history
- **Recommendations** - Actionable items for optimization

## 🔍 Understanding the Output

### Sync Rule Types
- **📥 Inbound Rules** - Control data flow from on-premises AD to metaverse
- **📤 Outbound Rules** - Control data flow from metaverse to Azure AD
- **[CUSTOM]** - Rules created or modified by administrators
- **[OUT-OF-BOX]** - Default Microsoft-provided rules

### Health Status Indicators
- **✅ Good** - All systems operating normally
- **⚠️ Warning** - Minor issues that should be addressed
- **❌ Critical** - Serious problems requiring immediate attention

### Rule Configuration
- **Precedence** - Lower numbers = higher priority (0 is highest)
- **Object Types** - user, group, contact, device, etc.
- **Link Types** - Join (match existing) or Provision (create new)
- **Scope Filters** - Conditions that determine which objects are processed
- **Transformations** - How attributes are mapped and modified

## 🛠️ Troubleshooting

### Common Issues

#### PowerShell 7 Compatibility Error
```
Error: Could not load type 'System.Web.Util.Utf16StringValidator'
```
**Solution:** Use Windows PowerShell 5.1 instead of PowerShell 7
```powershell
# Use this instead of pwsh.exe
powershell.exe -File ".\EntraConnect-HealthCheck.ps1"
```

#### Module Not Found
```
Error: The ADSync module is not available
```
**Solution:** Run on the Azure AD Connect server where ADSync module is installed

#### Access Denied
```
Error: Access to the path is denied
```
**Solution:** Run PowerShell as Administrator

#### No Connectors Found
```
Warning: No AD connectors found
```
**Solution:** Verify Azure AD Connect is properly configured and connectors are created

### Debug Mode
Add debug output to troubleshoot issues:
```powershell
# Enable debug mode (modify script)
$DebugPreference = "Continue"
.\EntraConnect-HealthCheck.ps1
```

## 📅 Maintenance & Best Practices

### Regular Health Checks
- **Daily** - Automated health monitoring
- **Weekly** - Review sync rule changes
- **Monthly** - Analyze object count trends
- **Quarterly** - Version update planning

### Report Management
- **Archive reports** - Keep historical data for trend analysis
- **Share with team** - Distribution for change management
- **Compliance storage** - Retain for audit requirements

### Monitoring Integration
```powershell
# Example: Send email alerts for critical issues
if ($overallHealth -eq "Critical") {
    Send-MailMessage -To "admin@company.com" -Subject "Azure AD Connect Critical Issue" -Body "Health check detected critical issues. See attached report." -Attachments $htmlReportPath
}
```

## 🔄 Version History

### Version 2.0 (Current)
- ✅ Complete sync rules analysis with detailed configuration
- ✅ Enhanced connector discovery with multiple detection methods
- ✅ Professional HTML reports with advanced formatting
- ✅ PowerShell 7 compatibility detection and auto-restart
- ✅ Comprehensive error handling and troubleshooting guidance

### Version 1.0
- ✅ Basic health check functionality
- ✅ Sync status and object counts
- ✅ Simple HTML reporting

## 🤝 Contributing

### Reporting Issues
Please provide the following information:
- Azure AD Connect version
- PowerShell version (`$PSVersionTable.PSVersion`)
- Error messages (full text)
- Expected vs actual behavior

### Feature Requests
- Describe the business need
- Provide use case examples
- Suggest implementation approach

## 📄 License

This script is provided "as is" without warranty. Use at your own risk and test thoroughly in non-production environments before deploying.

## 📞 Support

### Self-Help Resources
- **Microsoft Docs** - [Azure AD Connect documentation](https://docs.microsoft.com/en-us/azure/active-directory/hybrid/)
- **PowerShell Help** - `Get-Help Get-ADSyncConnector -Full`
- **Event Logs** - Check Application and System logs for Azure AD Connect events

### Professional Support
For enterprise support and customization:
- Contact your Microsoft support representative
- Engage Azure AD Connect specialists
- Consider Microsoft Premier Support

## 🏷️ Tags

`Azure AD Connect` `Entra ID` `PowerShell` `Monitoring` `Health Check` `Sync Rules` `Reporting` `Active Directory` `Identity Management` `Automation`

---


*Last updated: June 2025*
