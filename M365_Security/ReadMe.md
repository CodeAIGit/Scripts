# Microsoft 365 Security Configuration Toolkit

**A comprehensive PowerShell-based security configuration suite for Microsoft 365 environments**

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![M365](https://img.shields.io/badge/Microsoft%20365-E5-orange.svg)](https://www.microsoft.com/microsoft-365)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Scripts Overview](#scripts-overview)
- [Configuration Coverage](#configuration-coverage)
- [Usage Guide](#usage-guide)
- [Reports](#reports)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)
- [Author](#author)
- [Acknowledgments](#acknowledgments)

---

## 🎯 Overview

This toolkit provides enterprise-grade automation for implementing Microsoft's recommended security baseline plus custom organizational requirements across your Microsoft 365 tenant. It combines traditional PowerShell cmdlets with Microsoft Graph API to deliver comprehensive security configuration with minimal manual intervention.

### Key Capabilities

- **92% Automation Rate**: Automatically configures 23 out of 25 security settings
- **Pre-Flight Analysis**: Shows exactly what will change before making any modifications
- **Comprehensive Validation**: Verifies all configurations post-deployment
- **Detailed Reporting**: Generates professional HTML and CSV reports for audit and compliance
- **Zero Downtime**: Maintains connected sessions for additional work
- **Error Resilient**: Graceful handling of failures with detailed error reporting

---

## ✨ Features

### Security Baseline Implementation

- ✅ **Exchange Online Protection (EOP)**
  - Unified Audit Logging
  - Mailbox Auditing
  - Anti-Malware with ZAP (Zero-hour Auto Purge)
  - Anti-Spam (Inbound & Outbound)
  - Anti-Phishing with mailbox intelligence
  - DKIM/DMARC/SPF configuration support

- ✅ **Microsoft Defender for Office 365**
  - Safe Links (Email, Teams, Office apps)
  - Safe Attachments
  - ATP for SharePoint/OneDrive/Teams
  - Advanced threat protection policies

- ✅ **Microsoft Teams Security**
  - Screen capture prevention
  - Granular external access control
  - Messaging policy configuration
  - App permission management
  - Consumer chat blocking

- ✅ **SharePoint & OneDrive Security**
  - Content security policies
  - Sharing restrictions
  - OneDrive retention policies
  - External sharing controls

- ✅ **Authentication & Identity**
  - Modern authentication enforcement
  - Legacy authentication blocking
  - QR code authentication (Graph API)
  - Conditional access readiness

- ✅ **Data Protection**
  - Information Rights Management (IRM)
  - Azure RMS integration
  - DLP policy framework

- ✅ **Intune App Protection**
  - iOS app protection policies
  - Android app protection policies
  - Personal account blocking in Outlook

### Custom Requirements Supported

- 🔒 Baseline Security Mode (BSM) - Reject direct send
- 📱 QR code authentication method
- 🚫 Screen capture prevention in Teams
- 🌐 Granular external access control
- 📁 File protection in Teams
- 🔗 Malicious URL protection
- 🛡️ Content security policy in SharePoint
- ⛔ Disable chat with anyone in Teams
- 📧 Block personal accounts in Outlook
- 📦 Selective auto-archive disabling
- 🚷 External publisher app blocking

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    User Workflow                            │
└─────────────────────────────────────────────────────────────┘
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │Pre-Flight│    │  Unified │    │Validation│
    │  Check   │───▶│  Config  │───▶│  Script  │
    │ (Read)   │    │ (Write)  │    │ (Verify) │
    └──────────┘    └──────────┘    └──────────┘
          │                │                │
          └────────────────┴────────────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │  HTML + CSV     │
                  │    Reports      │
                  └─────────────────┘
```

### Script Dependencies

```
PowerShell Modules:
├── ExchangeOnlineManagement (Required)
├── MicrosoftTeams (Required)
├── Microsoft.Online.SharePoint.PowerShell (Required)
├── MSOnline (Required)
├── Microsoft.Graph.Authentication (Optional - for Graph API features)
├── Microsoft.Graph.Identity.SignIns (Optional)
└── Microsoft.Graph.DeviceManagement (Optional)
```

---

## 📦 Prerequisites

### Required Licenses

- Microsoft 365 E3/E5 or Business Premium
- Microsoft Defender for Office 365 P1 or P2
- Microsoft Intune (for mobile app protection)
- Azure AD Premium P1 (for advanced authentication)

### Required Permissions

Your admin account must have one of the following role combinations:

**Option 1: Global Administrator** (Recommended for initial setup)
- Grants all necessary permissions across all services

**Option 2: Granular Roles** (Principle of least privilege)
- Exchange Administrator
- Teams Administrator
- SharePoint Administrator
- Security Administrator
- Intune Administrator (if using Graph API features)

### PowerShell Requirements

- **PowerShell Version**: 5.1 or PowerShell 7.x
- **Execution Policy**: RemoteSigned or Unrestricted
- **Internet Connection**: Required for module downloads and M365 connectivity

### System Requirements

- **Operating System**: Windows 10/11 or Windows Server 2016+
- **RAM**: 4GB minimum (8GB recommended)
- **Disk Space**: 500MB for modules and reports
- **.NET Framework**: 4.7.2 or higher

---

## 🚀 Installation

### Step 1: Install Required PowerShell Modules

Open PowerShell as Administrator and run:

```powershell
# Install core modules
Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force
Install-Module -Name MicrosoftTeams -Scope CurrentUser -Force
Install-Module -Name Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser -Force
Install-Module -Name MSOnline -Scope CurrentUser -Force

# Optional: Install Graph API modules for enhanced features
Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Force
Install-Module -Name Microsoft.Graph.Identity.SignIns -Scope CurrentUser -Force
Install-Module -Name Microsoft.Graph.DeviceManagement -Scope CurrentUser -Force
```

### Step 2: Verify Module Installation

```powershell
# Check installed modules
Get-Module -ListAvailable | Where-Object {
    $_.Name -match "ExchangeOnline|MicrosoftTeams|SharePoint|MSOnline|Microsoft.Graph"
}
```

### Step 3: Download the Toolkit

```powershell
# Clone from GitHub
git clone https://github.com/yourusername/m365-security-toolkit.git
cd m365-security-toolkit

# Or download ZIP and extract
# https://github.com/yourusername/m365-security-toolkit/archive/main.zip
```

### Step 4: Set Execution Policy (if needed)

```powershell
# Check current policy
Get-ExecutionPolicy

# Set to RemoteSigned (recommended)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## 🎬 Quick Start

### Basic Workflow

```powershell
# Navigate to toolkit directory
cd C:\Path\To\m365-security-toolkit

# Step 1: Run pre-flight check (READ-ONLY)
.\PreFlight-M365SecurityCheck.ps1

# Step 2: Review the HTML report
.\M365_PreFlight_Check_YYYYMMDD_HHMMSS.html

# Step 3: If satisfied, run main configuration
.\Configure-M365UnifiedSecurity.ps1

# Step 4: Validate the configuration
.\Validate-M365Security.ps1

# Step 5: Review validation report
.\M365_Security_Validation_Report_YYYYMMDD_HHMMSS.html
```

### One-Liner Quick Test

```powershell
# Test connectivity only (no configuration)
.\PreFlight-M365SecurityCheck.ps1
```

---

## 📜 Scripts Overview

### 1. PreFlight-M365SecurityCheck.ps1

**Purpose**: Read-only analysis of current configuration

**What it does**:
- Connects to Exchange, Teams, SharePoint, and Graph API
- Checks current state of all security settings
- Compares current vs. target configuration
- Generates detailed "before" report
- **Makes ZERO changes** to your environment

**Output**:
- `M365_PreFlight_Check_YYYYMMDD_HHMMSS.html` - Visual dashboard
- `M365_PreFlight_Check_YYYYMMDD_HHMMSS.csv` - Data export

**Runtime**: 5-10 minutes

**Example Output**:
```
Will Change: 12 settings
Already OK: 8 settings
Manual Required: 2 settings
```

### 2. Configure-M365UnifiedSecurity.ps1

**Purpose**: Complete security baseline implementation

**What it does**:
- Configures Exchange Online Protection
- Implements Defender for Office 365 policies
- Sets up Teams security controls
- Configures SharePoint and OneDrive security
- Enables authentication controls
- Creates Intune app protection policies (via Graph API)
- Tracks manual configuration requirements

**Output**:
- `M365_Unified_Security_Report_YYYYMMDD_HHMMSS.html` - Comprehensive results
- `M365_Unified_Security_Report_YYYYMMDD_HHMMSS.csv` - Detailed log

**Runtime**: 10-20 minutes (depending on tenant size)

**User Interaction**:
- Prompts for mailboxes to disable auto-archive (optional)

### 3. Validate-M365Security.ps1

**Purpose**: Post-configuration verification

**What it does**:
- Validates all automated configurations
- Checks manual configuration status
- Identifies configuration drift
- Provides remediation recommendations
- Generates compliance report

**Output**:
- `M365_Security_Validation_Report_YYYYMMDD_HHMMSS.html` - Validation dashboard
- `M365_Security_Validation_Report_YYYYMMDD_HHMMSS.csv` - Audit trail

**Runtime**: 5-10 minutes

**Validation Criteria**:
- ✅ Pass: Configuration matches baseline
- ❌ Fail: Configuration missing or incorrect
- ⚠️ Warning: Requires manual verification

### 4. Manual Configuration Guide (PDF/Markdown)

**Purpose**: Step-by-step instructions for portal configurations

**Covers**:
- QR Code Authentication setup in Azure Portal
- DSPM enablement in Microsoft Purview
- Knowledge Agent configuration in SharePoint
- Outlook personal account blocking via Intune

---

## 🔧 Configuration Coverage

### Automated via PowerShell (18 configurations)

| Category | Setting | Status |
|----------|---------|--------|
| **Compliance** | Unified Audit Logging | ✅ Automated |
| **Compliance** | Mailbox Auditing | ✅ Automated |
| **Exchange** | Anti-Spoofing (BSM) | ✅ Automated |
| **Exchange** | Anti-Malware | ✅ Automated |
| **Exchange** | Anti-Spam | ✅ Automated |
| **Exchange** | Outbound Spam | ✅ Automated |
| **Exchange** | Anti-Phishing | ✅ Automated |
| **Defender** | Safe Links | ✅ Automated |
| **Defender** | Safe Attachments | ✅ Automated |
| **Defender** | ATP for SPO/ODB/Teams | ✅ Automated |
| **Authentication** | Modern Auth | ✅ Automated |
| **Authentication** | Block Legacy Auth | ✅ Automated |
| **Teams** | Screen Capture Prevention | ✅ Automated |
| **Teams** | Messaging Policy | ✅ Automated |
| **Teams** | External Access | ✅ Automated |
| **Teams** | Block External Apps | ✅ Automated |
| **SharePoint** | Content Security | ✅ Automated |
| **OneDrive** | Retention Policy | ✅ Automated |

### Automated via Graph API (5 configurations)

| Category | Setting | Status |
|----------|---------|--------|
| **Authentication** | QR Code Auth | ✅ Automated (Graph) |
| **Intune** | iOS App Protection | ✅ Automated (Graph) |
| **Intune** | Android App Protection | ✅ Automated (Graph) |
| **Exchange** | DKIM Configuration | ⚠️ DNS Required |
| **Data Protection** | IRM | ✅ Automated |

### Manual Configuration Required (2 configurations)

| Category | Setting | Portal | Guide Available |
|----------|---------|--------|-----------------|
| **Purview** | DSPM | Microsoft Purview | ✅ Yes |
| **SharePoint** | Knowledge Agent | SharePoint Admin | ✅ Yes |

### Automation Rate

- **Total Configurations**: 25
- **Fully Automated**: 23 (92%)
- **Manual Required**: 2 (8%)

---

## 📖 Usage Guide

### Scenario 1: First-Time Deployment

```powershell
# 1. Review what will change (no modifications)
.\PreFlight-M365SecurityCheck.ps1

# 2. Open the HTML report in browser
Start-Process .\M365_PreFlight_Check_*.html

# 3. If satisfied with planned changes, deploy
.\Configure-M365UnifiedSecurity.ps1

# 4. When prompted, enter mailboxes for archive disabling (or press Enter to skip)
# Example: user1@contoso.com, user2@contoso.com

# 5. Wait for completion (10-20 minutes)

# 6. Validate the deployment
.\Validate-M365Security.ps1

# 7. Review validation report
Start-Process .\M365_Security_Validation_Report_*.html

# 8. Complete manual configurations using the guide
# - Configure DSPM in Purview portal
# - Enable Knowledge Agent in SharePoint admin center
```

### Scenario 2: Audit Current Configuration

```powershell
# Run validation script to check current state
.\Validate-M365Security.ps1

# Review the report to identify gaps
Start-Process .\M365_Security_Validation_Report_*.html

# Address any failed validations
# Re-run specific configurations as needed
```

### Scenario 3: Incremental Updates

```powershell
# Check current state
.\PreFlight-M365SecurityCheck.ps1

# If only specific settings need updating, edit the main script
# Comment out sections you don't want to run (lines starting with #)

# Run modified configuration
.\Configure-M365UnifiedSecurity.ps1

# Validate
.\Validate-M365Security.ps1
```

### Scenario 4: Scheduled Compliance Checks

```powershell
# Create scheduled task to run validation weekly
$action = New-ScheduledTaskAction -Execute 'PowerShell.exe' `
    -Argument '-File "C:\Path\To\Validate-M365Security.ps1"'

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 9am

Register-ScheduledTask -Action $action -Trigger $trigger `
    -TaskName "M365 Security Validation" -Description "Weekly security audit"
```

---

## 📊 Reports

### HTML Reports

All scripts generate professional HTML dashboards with:

- **Executive Summary**: High-level statistics with color-coded cards
- **Detailed Tables**: Configuration-by-configuration breakdown
- **Status Badges**: Visual indicators (Success/Failed/Manual/Warning)
- **Method Tags**: Shows whether PowerShell, Graph API, or Manual
- **Responsive Design**: Mobile-friendly viewing
- **Print-Ready**: Formatted for PDF export

### CSV Reports

Structured data exports include:

- **Timestamp**: When the configuration was applied
- **Section**: Baseline or Custom
- **Method**: PowerShell, Graph API, or Manual
- **Category**: Service (Exchange, Teams, etc.)
- **Setting**: Specific configuration item
- **Action**: Enable, Disable, Configure
- **Status**: Success, Failed, Manual, Info, Skipped
- **Details**: Explanation of what happened
- **Value**: Actual configuration values

### Report Locations

All reports are saved in the same directory as the scripts:

```
m365-security-toolkit/
├── PreFlight-M365SecurityCheck.ps1
├── Configure-M365UnifiedSecurity.ps1
├── Validate-M365Security.ps1
├── M365_PreFlight_Check_20251230_143022.html
├── M365_PreFlight_Check_20251230_143022.csv
├── M365_Unified_Security_Report_20251230_150045.html
├── M365_Unified_Security_Report_20251230_150045.csv
├── M365_Security_Validation_Report_20251230_152110.html
└── M365_Security_Validation_Report_20251230_152110.csv
```

---

## 🔍 Troubleshooting

### Common Issues and Solutions

#### Issue 1: Module Not Found

**Error**: `The term 'Connect-ExchangeOnline' is not recognized...`

**Solution**:
```powershell
Install-Module -Name ExchangeOnlineManagement -Force
Import-Module ExchangeOnlineManagement
```

#### Issue 2: Connection Failed

**Error**: `Connect-ExchangeOnline : The term is not recognized...`

**Solution**:
```powershell
# Check module installation
Get-Module -ListAvailable ExchangeOnlineManagement

# Reconnect manually
Connect-ExchangeOnline -UserPrincipalName admin@contoso.com
```

#### Issue 3: Insufficient Permissions

**Error**: `Access Denied` or `Insufficient permissions`

**Solution**:
- Verify your account has Global Administrator role
- Or ensure you have all required granular roles
- Check in Azure AD: Roles and administrators

#### Issue 4: MFA Loop

**Error**: Repeated MFA prompts

**Solution**:
```powershell
# Use modern authentication
Connect-ExchangeOnline -ShowProgress $true
```

#### Issue 5: Graph API Connection Failed

**Error**: `Could not load type 'Microsoft.Identity.Client.IMsalSFHttpClientFactory'`

**Solution**:
```powershell
# Update Microsoft.Graph modules
Uninstall-Module Microsoft.Graph -AllVersions -Force
Install-Module Microsoft.Graph -Force

# Script will gracefully skip Graph API features if connection fails
```

#### Issue 6: Script Execution Blocked

**Error**: `File cannot be loaded because running scripts is disabled`

**Solution**:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### Issue 7: Reports Not Generated

**Error**: `Out-File: Cannot bind argument to parameter 'FilePath'`

**Solution**:
- Check you have write permissions to the directory
- Ensure no other process has the file open
- Run PowerShell as Administrator

---

## 🎓 Best Practices

### Before Running Scripts

1. ✅ **Test in Non-Production**: Always test in a dev/test tenant first
2. ✅ **Take Backups**: Export current configurations for rollback
3. ✅ **Review Reports**: Always run pre-flight check before configuration
4. ✅ **Notify Users**: Communicate changes that may affect end users
5. ✅ **Schedule Maintenance Window**: Run during low-usage periods

### During Deployment

1. ✅ **Monitor Progress**: Watch console output for errors
2. ✅ **Don't Interrupt**: Let scripts complete fully
3. ✅ **Document**: Keep generated reports for audit trail
4. ✅ **Verify Connections**: Ensure all services connect successfully

### After Deployment

1. ✅ **Run Validation**: Always validate with the validation script
2. ✅ **Complete Manual Steps**: Follow the manual configuration guide
3. ✅ **Test User Impact**: Verify users can still perform normal tasks
4. ✅ **Monitor Alerts**: Check for any security alerts or issues
5. ✅ **Update Documentation**: Record what was changed and when

### Security Considerations

- 🔒 **Protect Admin Credentials**: Never share admin passwords
- 🔒 **Use MFA**: Always enable MFA for admin accounts
- 🔒 **Limit Access**: Follow principle of least privilege
- 🔒 **Audit Regularly**: Run validation script quarterly
- 🔒 **Keep Reports Secure**: Reports may contain sensitive info

---

## 📅 Maintenance

### Recommended Schedule

| Task | Frequency | Script |
|------|-----------|--------|
| Configuration Validation | Weekly | Validate-M365Security.ps1 |
| Pre-Flight Check | Before Changes | PreFlight-M365SecurityCheck.ps1 |
| Full Baseline Review | Quarterly | All scripts |
| Security Score Review | Monthly | Manual (Portal) |
| Module Updates | Monthly | See below |

### Updating PowerShell Modules

```powershell
# Update all M365 modules
Update-Module ExchangeOnlineManagement -Force
Update-Module MicrosoftTeams -Force
Update-Module Microsoft.Online.SharePoint.PowerShell -Force
Update-Module MSOnline -Force
Update-Module Microsoft.Graph -Force
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

### How to Contribute

1. **Fork the Repository**
   ```bash
   git clone https://github.com/yourusername/m365-security-toolkit.git
   ```

2. **Create a Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make Your Changes**
   - Follow existing code style
   - Add comments for complex logic
   - Update documentation

4. **Test Thoroughly**
   - Test in dev/test tenant
   - Verify all scripts still work
   - Check report generation

5. **Submit Pull Request**
   - Describe changes clearly
   - Reference any issues
   - Include test results

### Contribution Ideas

- 🔧 Add support for additional M365 services
- 📊 Enhance reporting with charts/graphs
- 🌍 Add multi-language support
- 🔄 Implement rollback functionality
- 📱 Create mobile-friendly reports
- 🤖 Add automated remediation

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 Gulab Prasad

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 👤 Author

**Gulab Prasad**

- 🌐 Website: [https://gulabprasad.com](https://gulabprasad.com)
- 💼 LinkedIn: [https://www.linkedin.com/in/gulab/](https://www.linkedin.com/in/gulab/)
- 📧 Email: contact@gulabprasad.com
- 🐙 GitHub: [@CodeAIGit](https://github.com/CodeAIGit)

### About the Author

Gulab Prasad is a Digital Workplace Architect and Technology Consultant with extensive experience in identity and access management, device management, and cloud migrations. With a focus on automation and security, Gulab has helped numerous organizations implement robust Microsoft 365 security baselines and streamline their IT operations.

**Expertise:**
- Microsoft 365 Administration (Exchange, Teams, SharePoint, Intune)
- Azure Active Directory / Entra ID
- PowerShell Automation
- Security & Compliance
- Enterprise Migrations
- Identity & Access Management

---

## 🙏 Acknowledgments

- **Microsoft Documentation Team**: For comprehensive M365 security guidance
- **PowerShell Community**: For module development and support
- **Microsoft Security Team**: For security baseline recommendations
- **Early Testers**: For valuable feedback and bug reports
- **Contributors**: Everyone who has contributed to improving this toolkit

### Special Thanks

- Microsoft 365 Security Best Practices documentation
- PowerShell Gallery for module hosting
- GitHub for repository hosting and collaboration tools

---

## 📚 Additional Resources

### Official Microsoft Documentation

- [Microsoft 365 Security Documentation](https://docs.microsoft.com/microsoft-365/security/)
- [Exchange Online Protection](https://docs.microsoft.com/microsoft-365/security/office-365-security/exchange-online-protection-overview)
- [Microsoft Defender for Office 365](https://docs.microsoft.com/microsoft-365/security/office-365-security/defender-for-office-365)
- [Teams Security Guide](https://docs.microsoft.com/microsoftteams/security-compliance-overview)
- [SharePoint Security](https://docs.microsoft.com/sharepoint/security-for-sharepoint-server)

### PowerShell Resources

- [Exchange Online PowerShell](https://docs.microsoft.com/powershell/exchange/exchange-online-powershell)
- [Microsoft Teams PowerShell](https://docs.microsoft.com/microsoftteams/teams-powershell-overview)
- [SharePoint Online PowerShell](https://docs.microsoft.com/powershell/sharepoint/sharepoint-online/connect-sharepoint-online)
- [Microsoft Graph PowerShell SDK](https://docs.microsoft.com/graph/powershell/get-started)

### Security Baselines

- [Microsoft Security Baselines](https://docs.microsoft.com/windows/security/threat-protection/windows-security-baselines)
- [Zero Trust Deployment Guide](https://docs.microsoft.com/security/zero-trust/)
- [Microsoft Secure Score](https://docs.microsoft.com/microsoft-365/security/defender/microsoft-secure-score)

---

## 🔖 Version History

### Version 1.1 (2025-12-30)

**Initial Release**

**Features:**
- Pre-flight check script (read-only analysis)
- Unified configuration script (PowerShell + Graph API)
- Validation script (post-deployment verification)
- Manual configuration guide (PDF/Markdown)
- HTML and CSV reporting
- Support for 25 security configurations
- 92% automation rate

**Tested On:**
- Windows 10/11
- PowerShell 5.1 and 7.x
- Microsoft 365 E3/E5
- Defender for Office 365 P1/P2

---

## 🐛 Known Issues

### Current Limitations

1. **Graph API Connection**: Some environments may experience Graph API connection issues due to module version conflicts. The script will gracefully skip Graph API features if connection fails.

2. **MFA Prompts**: Multiple MFA prompts may occur when connecting to different services. This is expected behavior.

3. **Large Tenant Performance**: In very large tenants (50,000+ users), the scripts may take longer to complete.

4. **DKIM DNS Records**: Automated DKIM configuration requires manual DNS record creation.

### Workarounds

See [Troubleshooting](#troubleshooting) section for solutions to known issues.

---

## 💡 FAQ

**Q: Do I need to run all three scripts?**  
A: For best results, yes. Pre-flight check shows what will change, unified config applies changes, and validation verifies everything worked.

**Q: Can I run this on a production tenant?**  
A: Yes, but always test in dev/test first. Run pre-flight check to see what will change before applying.

**Q: What if Graph API connection fails?**  
A: The script will continue with PowerShell configurations. Graph API features (QR auth, Intune policies) will need manual configuration.

**Q: How long do scripts take to run?**  
A: Pre-flight: 5-10 min, Configuration: 10-20 min, Validation: 5-10 min

**Q: Can I customize which settings to apply?**  
A: Yes, you can comment out sections you don't want to run using `#` in the script.

**Q: Will this affect end users?**  
A: Most changes are transparent. Screen capture prevention and external access controls may be noticeable.

**Q: How do I rollback changes?**  
A: Manual rollback is required. Keep your pre-flight report as a reference for original settings.

**Q: Do sessions stay connected after scripts run?**  
A: Yes, by design. This allows you to perform additional manual configurations.

---

## 📞 Support

### Getting Help

1. **Documentation**: Check this README and the manual configuration guide
2. **Issues**: Submit issues on GitHub with detailed error messages
3. **Discussions**: Use GitHub Discussions for questions and community support
4. **Contact**: Reach out via LinkedIn or website for consulting inquiries

### Reporting Bugs

When reporting bugs, please include:
- PowerShell version (`$PSVersionTable`)
- Module versions (`Get-Module -ListAvailable`)
- Error messages (full text)
- Steps to reproduce
- Screenshots (if applicable)

---

## 🔐 Security

### Responsible Disclosure

If you discover a security vulnerability, please email contact@gulabprasad.com instead of using the issue tracker.

### Security Best Practices

- Never commit credentials or API keys to the repository
- Review all scripts before running in production
- Keep PowerShell modules updated
- Use MFA for all admin accounts
- Follow principle of least privilege

---

## ⭐ Star History

If you find this toolkit useful, please consider giving it a star on GitHub!

[![Star History Chart](https://api.star-history.com/svg?repos=yourusername/m365-security-toolkit&type=Date)](https://star-history.com/#yourusername/m365-security-toolkit&Date)

---

## 📢 Stay Updated

- **Watch** this repository for updates
- **Star** to show your support
- **Fork** to contribute
- **Share** with your network

---

<div align="center">

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=for-the-badge&logo=linkedin)](https://www.linkedin.com/in/gulab/)
[![Website](https://img.shields.io/badge/Website-Visit-green?style=for-the-badge&logo=google-chrome)](https://gulabprasad.com)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-black?style=for-the-badge&logo=github)](https://github.com/gulabprasad)

**© 2025 Gulab Prasad
