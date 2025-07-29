# 🛡️ Microsoft Defender for Identity (MDI) Ultra-Detailed Enterprise Assessment Tool

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-4.0-brightgreen.svg)](CHANGELOG.md)
[![Domain Controllers](https://img.shields.io/badge/Supports-Multiple%20DCs-orange.svg)](#features)

> **Enterprise-grade PowerShell tool for comprehensive Microsoft Defender for Identity readiness assessment across entire Active Directory environments.**

## 📋 Overview

The **MDI Ultra-Detailed Enterprise Assessment Tool** is a comprehensive PowerShell script designed to evaluate your entire Active Directory environment's readiness for Microsoft Defender for Identity deployment. This tool provides detailed analysis, security implications, and specific remediation steps to ensure optimal MDI functionality.

### 🎯 Key Benefits

- **🔍 Comprehensive Analysis**: 100-point scoring system across 4 critical assessment areas
- **🛠️ Actionable Insights**: Specific PowerShell remediation commands for every issue
- **📊 Enterprise Overview**: Real-time assessment of all domain controllers
- **🎨 Professional Reporting**: Modern, responsive HTML reports with executive summaries
- **⚡ Automated Execution**: One-click assessment with detailed results

## ✨ Features

### 🔧 Ultra-Detailed Assessment Areas

| Assessment Area | Points | Description |
|----------------|--------|-------------|
| **Audit Policies** | 40 pts | Critical MDI audit policy configurations |
| **NTLM Configuration** | 30 pts | NTLM auditing and restriction settings |
| **Event Generation** | 20 pts | Active security event monitoring |
| **System Prerequisites** | 10 pts | MDI sensor installation requirements |

### 📈 Advanced Capabilities

- **🔍 Configuration Drift Detection**: Identifies inconsistencies across domain controllers
- **📊 Event Frequency Analysis**: Multi-timeframe security event pattern analysis
- **🌐 Network Connectivity Diagnostics**: Comprehensive connectivity testing
- **🎯 Threat Detection Mapping**: Links configurations to specific threat detection capabilities
- **📋 Implementation Timeline**: Phased deployment recommendations
- **🔧 Prerequisites Validation**: .NET Framework, disk space, and antivirus exclusions

### 🎨 Modern HTML Reporting

- **📱 Responsive Design**: Works on desktop, tablet, and mobile devices
- **🎯 Executive Dashboard**: High-level compliance overview with score cards
- **📊 Detailed Analysis**: Per-DC breakdown with remediation steps
- **🔍 Security Implications**: Clear explanations of configuration impact
- **💻 Copy-Paste Commands**: Ready-to-use PowerShell remediation scripts

## 🚀 Quick Start

### Prerequisites

- **PowerShell 5.1+** (Windows PowerShell or PowerShell Core)
- **Active Directory PowerShell Module**
- **Domain Administrator privileges** (or equivalent)
- **PowerShell Remoting enabled** on all target domain controllers

### Installation

1. **Download the script:**
   ```powershell
   # Option 1: Download directly
   Invoke-WebRequest -Uri "https://github.com/[username]/mdi-enterprise-assessment/raw/main/MDIConfigReport_v1.4.ps1" -OutFile "MDIConfigReport_v1.4.ps1"
   
   # Option 2: Clone the repository
   git clone https://github.com/[username]/mdi-enterprise-assessment.git
   cd mdi-enterprise-assessment
   ```

2. **Set execution policy (if needed):**
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

3. **Run the assessment:**
   ```powershell
   .\MDIConfigReport_v1.4.ps1
   ```
<img width="1102" height="633" alt="image" src="https://github.com/user-attachments/assets/432a3012-e0a7-470e-ae76-753e5c3a8f6c" />


That's it! The script will automatically:
- ✅ Discover all domain controllers
- ✅ Test connectivity and collect data
- ✅ Perform comprehensive analysis
- ✅ Generate detailed HTML report
- ✅ Open the report in your browser

## 📊 Usage Examples

### Basic Assessment
```powershell
# Run assessment on all domain controllers
.\MDIConfigReport_v1.4.ps1
```

### Advanced Options
```powershell
# Exclude specific domain controllers
New-MDIUltraDetailedEnterpriseReport -ExcludeDCs 'TestDC01','MaintenanceDC02'

# Custom output location
New-MDIUltraDetailedEnterpriseReport -OutputPath "C:\MDI-Reports"

# Generate only HTML report
New-MDIUltraDetailedEnterpriseReport -Format HTML

# Disable remediation commands in report
New-MDIUltraDetailedEnterpriseReport -IncludeRemediationSteps:$false
```

### Automated Scheduling
```powershell
# Create scheduled task for monthly assessment
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\MDIConfigReport_v1.4.ps1"
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6AM
Register-ScheduledTask -TaskName "MDI Monthly Assessment" -Action $action -Trigger $trigger
```

## 📋 Assessment Criteria

### 🔍 Audit Policies (40 Points)
The script evaluates 11 critical audit policies required for MDI:

- **Credential Validation** - Detects Pass-the-Hash, brute force attacks
- **Directory Service Access** - Critical for LDAP reconnaissance detection
- **Kerberos Authentication Service** - Essential for ASREPRoasting detection
- **Security Group Management** - Monitors privilege escalation attempts
- **User Account Management** - Tracks account manipulation
- And 6 additional policies...

### 🔐 NTLM Configuration (30 Points)
Validates 5 essential NTLM settings:

- **AuditReceivingNTLMTraffic** - Enables Event 8004 for detailed NTLM analysis
- **RestrictReceivingNTLMTraffic** - Provides NTLM usage visibility
- **AuditNTLMInDomain** - Domain-wide NTLM attack monitoring
- **SCENoApplyLegacyAuditPolicy** - Ensures consistent audit policy enforcement
- And more...

### 📊 Event Generation (20 Points)
Analyzes critical security events:

- **Event 4662** - Directory Service Access (Primary MDI event)
- **Event 4776** - NTLM Authentication attempts
- **Event 8004** - Detailed NTLM authentication data
- Frequency analysis and pattern detection

### 🔧 System Prerequisites (10 Points)
Validates MDI sensor requirements:

- **.NET Framework 4.7.2+** compatibility
- **Minimum 6GB disk space** availability
- **Windows Defender exclusions** configuration
- **Network connectivity** to MDI cloud endpoints

## 📊 Sample Output

### Console Output
```
🎉 Ultra-Detailed Enterprise Assessment Complete!
🏆 Enterprise Status: MOSTLY READY
📊 Overall Score: 87% (Ready for MDI)
🎯 DC Distribution:
   • Excellent (95%+): 2 DCs
   • Good (85-94%): 1 DCs
   • Acceptable (70-84%): 0 DCs
   • Problematic (<70%): 0 DCs
📄 Report File: C:\Reports\Enterprise\MDI-UltraDetailed-Enterprise-Report-20241201_143022.html
```

### HTML Report Sections
- **🎯 Executive Dashboard** - High-level compliance overview
- **⚠️ Configuration Drift Analysis** - Inconsistency detection and remediation
- **🔍 Ultra-Detailed DC Analysis** - Per-server breakdown with scoring
- **📋 Comprehensive Recommendations** - Prioritized action items
- **📅 Implementation Timeline** - Phased deployment plan

## 🔧 Configuration Options

### Script Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `OutputPath` | String | `C:\Reports\Enterprise` | Directory for report output |
| `ReportName` | String | `MDI-UltraDetailed-Enterprise-Report` | Base name for report files |
| `OpenReport` | Switch | `$true` | Automatically open HTML report |
| `Format` | String | `All` | Report format: HTML, Text, JSON, All |
| `ExcludeDCs` | Array | `@()` | Domain controllers to exclude |
| `IncludeRemediationSteps` | Switch | `$true` | Include PowerShell remediation commands |

### Environment Requirements

```powershell
# Required PowerShell modules
Import-Module ActiveDirectory

# Required permissions
# - Domain Administrator (recommended)
# - Or custom permissions:
#   - Read access to AD
#   - Local administrator on all DCs
#   - PowerShell remoting permissions

# Network requirements
# - PowerShell Remoting (WinRM) enabled on all DCs
# - Port 5985 (HTTP) or 5986 (HTTPS) accessible
# - DNS resolution for all DC names
```

## 🛠️ Troubleshooting

### Common Issues

#### ❌ "No domain controllers are reachable"
```powershell
# Solution: Enable PowerShell Remoting on DCs
Enable-PSRemoting -Force
winrm quickconfig -force

# Check firewall rules
netsh advfirewall firewall add rule name="WinRM-HTTP" dir=in localport=5985 protocol=TCP action=allow
```

#### ❌ "Cannot connect to Active Directory"
```powershell
# Solution: Install AD PowerShell module
Install-WindowsFeature -Name RSAT-AD-PowerShell
# Or on Windows 10/11:
Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
```

#### ❌ "Access denied" errors
```powershell
# Solution: Run as domain administrator or add specific permissions
# Required permissions:
# - Domain Admins group membership (easiest)
# - Or custom delegation for audit policy management
```

#### ❌ Script execution policy errors
```powershell
# Solution: Set appropriate execution policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
# Or bypass for single execution:
PowerShell.exe -ExecutionPolicy Bypass -File .\MDIConfigReport_v1.4.ps1
```

### Debugging Options

```powershell
# Enable verbose logging
$VerbosePreference = "Continue"
.\MDIConfigReport_v1.4.ps1

# Test connectivity manually
Test-WSMan -ComputerName "DC01.domain.com"
Test-NetConnection -ComputerName "DC01.domain.com" -Port 5985

# Verify AD module
Get-Module -ListAvailable ActiveDirectory
```

## 📊 Compliance Scoring

### Overall Enterprise Scoring
- **95-100%**: 🏆 **ENTERPRISE READY** - Proceed with MDI deployment
- **85-94%**: ✅ **MOSTLY READY** - Address minor issues
- **70-84%**: ⚠️ **NEEDS ATTENTION** - Significant remediation required
- **<70%**: 🚨 **CRITICAL ISSUES** - Immediate action required

### Per-DC Scoring Breakdown
- **Audit Policies** (40 pts): Foundation of MDI detection capabilities
- **NTLM Configuration** (30 pts): Essential for NTLM attack detection
- **Event Generation** (20 pts): Active monitoring of critical events
- **Prerequisites** (10 pts): System readiness for sensor installation

## 🔄 Integration Options

### SIEM Integration
```powershell
# Export results as JSON for SIEM consumption
New-MDIUltraDetailedEnterpriseReport -Format JSON

# Example: Send results to Splunk
$results = New-MDIUltraDetailedEnterpriseReport -Format JSON
Invoke-RestMethod -Uri "https://splunk.company.com/services/collector" -Method POST -Body $results
```

### Automation Pipeline
```powershell
# Azure DevOps pipeline example
trigger:
  schedule:
    cron: "0 6 * * 1"  # Every Monday at 6 AM
    branches:
      include:
      - main

steps:
- task: PowerShell@2
  inputs:
    filePath: 'scripts/MDIConfigReport_v1.4.ps1'
    arguments: '-OutputPath $(Build.ArtifactStagingDirectory)'
```

## 📈 Roadmap

### Upcoming Features (v5.0)
- [ ] **PowerBI Dashboard Integration**
- [ ] **Email Report Distribution**
- [ ] **Azure AD Connect Health Integration**
- [ ] **Custom Compliance Frameworks**
- [ ] **Historical Trend Analysis**
- [ ] **API Endpoints for Automation**

### Enhancement Requests
- [ ] Support for Azure AD Domain Services
- [ ] Integration with Microsoft 365 Defender
- [ ] Custom remediation script generation
- [ ] Multi-language support

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
```bash
# Clone the repository
git clone https://github.com/[username]/mdi-enterprise-assessment.git
cd mdi-enterprise-assessment

# Create feature branch
git checkout -b feature/your-feature-name

# Make changes and test
# Submit pull request
```

### Reporting Issues
Please use the [GitHub Issues](https://github.com/[username]/mdi-enterprise-assessment/issues) page to report bugs or request features.

## 📝 Changelog

### v4.0 (Current)
- ✨ Ultra-detailed 100-point scoring system
- ✨ Comprehensive security implications analysis
- ✨ Specific PowerShell remediation commands
- ✨ Advanced event frequency analysis
- ✨ Modern responsive HTML design
- ✨ Automatic execution capabilities

### v3.0
- 🔍 Configuration drift detection
- 📊 Multi-timeframe event analysis
- 🎨 Enhanced HTML reporting

### v2.0
- 🌐 Network connectivity diagnostics
- 🔧 MDI prerequisites validation
- 📋 Implementation timeline recommendations

See [CHANGELOG.md](CHANGELOG.md) for complete version history.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author & Support

**Created by:** [Gulab Prasad](https://gulabprasad.com)
- 🌐 **Website:** [https://gulabprasad.com](https://gulabprasad.com)
- 💼 **LinkedIn:** [Connect with Gulab](https://linkedin.com/in/gulab)
- 📧 **Support:** Create an issue on GitHub for questions or support

### Professional Services
- **MDI Implementation Consulting**
- **Enterprise Security Assessments**
- **Active Directory Health Checks**
- **Custom PowerShell Development**

## ⭐ Show Your Support

If this tool has helped you assess your MDI readiness, please consider:
- ⭐ **Starring this repository**
- 🐛 **Reporting issues** you encounter
- 💡 **Suggesting improvements**
- 🤝 **Contributing** to the project
- 📢 **Sharing** with your network

---

## 🔗 Related Projects

- [Microsoft Defender for Identity Documentation](https://docs.microsoft.com/en-us/defender-for-identity/)
- [Active Directory Security Assessment Tools](https://github.com/Microsoft/AaronLocker)
- [PowerShell Security Best Practices](https://github.com/PowerShell/PowerShell/tree/master/docs/security)

---

<div align="center">

**⚡ Ready to assess your MDI readiness? Download and run the script today! ⚡**

[![Download](https://img.shields.io/badge/Download-Latest%20Release-success.svg)](https://github.com/[username]/mdi-enterprise-assessment/releases/latest)
[![Documentation](https://img.shields.io/badge/Documentation-Wiki-blue.svg)](https://github.com/[username]/mdi-enterprise-assessment/wiki)


</div>
