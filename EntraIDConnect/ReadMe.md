# Entra ID Connect Management Script

A comprehensive PowerShell tool for managing, monitoring, and updating Microsoft Entra ID Connect (Azure AD Connect) installations.

**Created By:** [Gulab Prasad](https://gulabprasad.com)  
**Version:** 1.2  
**License:** MIT

## 🚀 Features

### ✅ **System Assessment**
- Current version detection and comparison
- Latest version checking from Microsoft sources
- Version gap analysis and update recommendations

### ✅ **Synchronization Monitoring**
- Real-time sync status and health checks
- Enabled synchronization rules display (inbound/outbound)
- Connector status and run history
- Synchronized organizational units overview

### ✅ **Configuration Management**
- Automated configuration backup with timestamps
- Synchronization rules export
- Connector settings backup
- Global settings preservation

### ✅ **Secure Update Management**
- Multi-stage user confirmations
- Entra Admin Center integration
- Support for manual and automatic installations
- Pre-update backup workflows

### ✅ **Security & Compliance**
- Administrator privilege validation
- Comprehensive audit logging
- Change tracking and documentation
- Safe execution with approval gates

## 📋 Prerequisites

### System Requirements
- **Operating System:** Windows Server 2012 R2 or later
- **PowerShell:** Version 5.1 or higher
- **Azure AD Connect:** Installed and configured
- **Privileges:** Local Administrator rights
- **Network:** Internet access for version checking

### Module Dependencies
- `ADSync` (automatically installed with Azure AD Connect)
- `ActiveDirectory` (for enhanced functionality)

## 🛠️ Installation

### Method 1: Direct Download
1. Download the script file: `EntraIDConnect-Management.ps1`
2. Save to a secure location (e.g., `C:\Scripts\Azure\`)
3. Ensure proper file permissions (Administrators only)

### Method 2: Git Clone
```powershell
# Clone the repository
git clone https://github.com/gulabprasad/entra-id-connect-management.git
cd entra-id-connect-management
```

### File Structure
```
C:\Scripts\Azure\
├── EntraIDConnect-Management.ps1    # Main script
├── README.md                        # This file
├── LICENSE                          # License information
└── docs/
    ├── SECURITY.md                  # Security guidelines
    └── TROUBLESHOOTING.md           # Common issues and solutions
```

## 🚀 Usage

### Basic Execution
```powershell
# Navigate to script directory
cd C:\Scripts\Azure\

# Run with administrator privileges
.\EntraIDConnect-Management.ps1
```

### Advanced Usage
```powershell
# Check execution policy (should be RemoteSigned or AllSigned)
Get-ExecutionPolicy

# Set execution policy if needed
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

# Run script with transcript logging
Start-Transcript -Path "C:\Logs\AADConnect-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
.\EntraIDConnect-Management.ps1
Stop-Transcript
```

## 📊 Script Output

### Version Information
```
======================================
    Entra ID Connect Management       
======================================

Current Version: 1.6.25.0
Latest Version: 1.6.28.0
```

### Synchronization Status
```
=== Synchronization Status ===
Sync Enabled: Yes
Current Sync Policy: Scheduled
Next Sync Time: 12/15/2024 14:30:00

Connector: contoso.com
Last Run: 12/15/2024 14:00:15
Result: Success
```

### Enabled Sync Rules
```
=== Inbound Synchronization Rules (Enabled Only) ===

Rule Name: In from AD - User Join
Connector: contoso.com
Precedence: 100
Enabled: Yes
Description: Join users from AD to AAD

Enabled Inbound Rules: 15
Disabled Inbound Rules: 3 (hidden)
```

### Synchronized OUs
```
=== Synchronized Organizational Units ===

AD Connector: contoso.com
Connector Status: Active

Sample Synchronized Objects:
  Type: user
  DN: CN=John Doe,OU=Users,DC=contoso,DC=com
  
  Type: group
  DN: CN=IT Team,OU=Groups,DC=contoso,DC=com
```

## 🔒 Security Considerations

### Execution Requirements
- **Administrator Rights:** Script requires local administrator privileges
- **Code Signing:** Consider signing the script for production environments
- **Execution Policy:** Use `RemoteSigned` or `AllSigned` policies

### Data Protection
- **Backup Encryption:** Consider encrypting backup files
- **Access Control:** Restrict script access to authorized personnel
- **Audit Logging:** Enable PowerShell transcript logging

### Network Security
- **Firewall Rules:** Ensure outbound HTTPS (443) access for version checking
- **Proxy Settings:** Configure PowerShell proxy if required

## 🔧 Configuration

### Customization Options
Edit the script to modify these parameters:

```powershell
# Backup location (default: Desktop)
$backupPath = "$env:USERPROFILE\Desktop\AADConnect_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

# Version check timeout (default: 10 seconds)
$page = Invoke-WebRequest -Uri $source -UseBasicParsing -TimeoutSec 10

# Log file retention (implement custom logic)
# Add log rotation based on your requirements
```

### Environment Variables
```powershell
# Optional: Set custom backup location
$env:AADCONNECT_BACKUP_PATH = "D:\Backups\AADConnect"

# Optional: Set custom log location
$env:AADCONNECT_LOG_PATH = "C:\Logs\AADConnect"
```

## 🐛 Troubleshooting

### Common Issues

#### 1. Module Import Failure
```
Error: Failed to load ADSync module
```
**Solution:**
- Verify Azure AD Connect is installed
- Restart PowerShell as Administrator
- Check service status: `Get-Service ADSync`

#### 2. Version Check Timeout
```
Latest Version: Check Entra Portal
```
**Solution:**
- Check internet connectivity
- Verify proxy settings
- Use manual download option

#### 3. Access Denied Errors
```
Error: Access denied
```
**Solution:**
- Run PowerShell as Administrator
- Check file permissions
- Verify user account privileges

#### 4. Backup Creation Failure
```
Error creating backup
```
**Solution:**
- Check available disk space
- Verify folder permissions
- Ensure ADSync service is running

### Debug Mode
```powershell
# Enable verbose output
$VerbosePreference = "Continue"
.\EntraIDConnect-Management.ps1

# Enable debug output
$DebugPreference = "Continue"
.\EntraIDConnect-Management.ps1
```

### Log Analysis
```powershell
# Check Windows Event Logs
Get-EventLog -LogName Application -Source "ADSync*" -Newest 10

# Check PowerShell transcript logs
Get-Content "C:\Logs\AADConnect-*.log" | Select-String "Error"
```

## 📝 Useful Commands

### Manual Synchronization
```powershell
# Delta synchronization
Start-ADSyncSyncCycle -PolicyType Delta

# Full synchronization
Start-ADSyncSyncCycle -PolicyType Initial

# Check sync history
Get-ADSyncConnectorRunStatus
```

### Configuration Analysis
```powershell
# View all sync rules
Get-ADSyncRule | Format-Table Name, Direction, Enabled

# View disabled rules only
Get-ADSyncRule | Where-Object {$_.Enabled -eq $false}

# Check scheduler settings
Get-ADSyncScheduler

# View connectors
Get-ADSyncConnector | Format-Table Name, ConnectorTypeName
```

### Backup Management
```powershell
# Manual backup creation
$rules = Get-ADSyncRule
$rules | Export-Clixml -Path "C:\Backup\SyncRules-$(Get-Date -Format 'yyyyMMdd').xml"

# Backup validation
$backup = Import-Clixml -Path "C:\Backup\SyncRules-20241215.xml"
Write-Host "Backup contains $($backup.Count) rules"
```

## 🔄 Update Process

### Automated Update Workflow
1. **Pre-Update Assessment**
   - Current version identification
   - Latest version checking
   - Change impact analysis

2. **Backup Creation**
   - Configuration export
   - Rule preservation
   - Settings documentation

3. **Update Execution**
   - Download verification
   - Installation with user approval
   - Service restart coordination

4. **Post-Update Validation**
   - Version verification
   - Service status check
   - Sync functionality test

### Manual Update Steps
1. Visit [Entra Admin Center](https://entra.microsoft.com)
2. Navigate to Identity → Hybrid management → Azure AD Connect
3. Download latest installer
4. Run script and choose "Install from local file"
5. Follow prompts and confirmations

## 📊 Monitoring & Maintenance

### Regular Health Checks
- **Daily:** Sync status monitoring
- **Weekly:** Rule configuration review
- **Monthly:** Version update assessment
- **Quarterly:** Full configuration backup

### Performance Metrics
- Sync cycle completion time
- Error rates and patterns
- Connector performance
- Object synchronization counts

### Alerting Integration
Consider integrating with:
- Azure Monitor
- PowerShell-based alerting scripts
- Custom monitoring solutions

## 🤝 Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add appropriate tests
5. Submit a pull request

### Development Guidelines
- Follow PowerShell best practices
- Include error handling
- Add comprehensive comments
- Test on multiple environments
- Update documentation

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Community Support
- **GitHub Issues:** Report bugs and request features
- **Discussions:** Share experiences and best practices
- **Wiki:** Additional documentation and examples

### Professional Support
For enterprise support and custom implementations:
- **Website:** [gulabprasad.com](https://gulabprasad.com)
- **Email:** Available through website contact form

### Resources
- [Microsoft Entra ID Connect Documentation](https://docs.microsoft.com/en-us/azure/active-directory/hybrid/)
- [PowerShell Gallery](https://www.powershellgallery.com/)

## 📈 Roadmap

### Version 1.3 (Planned)
- Enhanced security features
- Automated scheduling capabilities
- REST API integration
- Advanced reporting

### Version 2.0 (Future)
- GUI interface development
- Cloud-based configuration management
- Machine learning insights
- Multi-tenant support

---

**Created by [Gulab Prasad](https://gulabprasad.com)**
