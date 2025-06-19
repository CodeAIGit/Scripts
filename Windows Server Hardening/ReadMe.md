# CIS Security Hardening Scripts

Comprehensive PowerShell scripts for implementing CIS (Center for Internet Security) benchmarks on Windows systems to enhance security posture and compliance.

## Overview

The Center for Internet Security (CIS) Controls are a prioritized set of actions that collectively form a defense-in-depth set of best practices that mitigate the most common attack vectors. These scripts automate the implementation of CIS benchmarks for Windows environments.

## Scripts Included

### CIS Level 1 Hardening Script
- **Purpose**: Implements essential security configurations with minimal impact on functionality
- **Target**: Basic security hardening suitable for most environments
- **Compatibility**: Designed for general enterprise use with broad compatibility

### CIS Level 2 Hardening Script  
- **Purpose**: Applies advanced security configurations for high-security environments
- **Target**: Enhanced security for sensitive or high-risk environments
- **Compatibility**: May impact some applications - thorough testing recommended

## System Requirements

- **Operating System**: Windows 10/11 or Windows Server 2016/2019/2022
- **PowerShell**: Version 5.1 or higher
- **Privileges**: Administrator rights required
- **Memory**: Minimum 4GB RAM recommended
- **Disk Space**: At least 1GB free space for logs and restore points

## Installation & Usage

### Pre-Execution Checklist
1. Create full system backup
2. Test in non-production environment first
3. Review organizational policies and requirements
4. Schedule maintenance window for implementation

### Execution Steps

1. **Open PowerShell as Administrator**
   ```powershell
   # Right-click PowerShell and select "Run as Administrator"
   ```

2. **Navigate to script directory**
   ```powershell
   cd C:\Path\To\Scripts
   ```

3. **Set execution policy (if needed)**
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

4. **Run the desired script**
   ```powershell
   # For Level 1 hardening
   .\CIS-Level1-Hardening.ps1
   
   # For Level 2 hardening (run after Level 1)
   .\CIS-Level2-Hardening.ps1
   ```

## Features

### Security Configurations
- ✅ Password policy enforcement
- ✅ Account lockout policies
- ✅ User Access Control (UAC) optimization
- ✅ Audit policy configuration
- ✅ Security options hardening
- ✅ Service configuration management
- ✅ Registry security settings
- ✅ Network security enhancements

### Script Capabilities
- ✅ Automated CIS benchmark implementation
- ✅ System restore point creation before changes
- ✅ Detailed logging and progress tracking
- ✅ Comprehensive error handling
- ✅ Real-time status reporting
- ✅ Rollback capabilities via restore points
- ✅ Compliance validation checks

### Logging & Monitoring
- Detailed execution logs stored in `C:\Windows\Temp\`
- Progress tracking with colored output
- Error reporting and troubleshooting information
- Summary reports of applied configurations

## Security Controls Implemented

### Level 1 Controls
- Password complexity requirements
- Account lockout threshold settings
- Audit policy configurations
- User rights assignments
- Security option modifications
- Service hardening (disabling unnecessary services)
- Registry security enhancements

### Level 2 Controls (Additional)
- Advanced audit policies
- Enhanced user account controls
- Network security protocols
- Additional service restrictions
- Advanced registry protections
- Extended security monitoring

## Important Considerations

### Before Implementation
- **Backup**: Always create full system backup
- **Testing**: Test in isolated environment first
- **Documentation**: Document current system state
- **Planning**: Schedule appropriate maintenance window
- **Team Communication**: Notify relevant teams of changes

### During Implementation  
- Monitor system performance
- Check for application compatibility issues
- Verify critical services remain functional
- Document any unexpected behaviors

### After Implementation
- **Restart Required**: System restart recommended after completion
- **Testing**: Thoroughly test all critical applications
- **Monitoring**: Monitor system stability for 24-48 hours
- **Documentation**: Update system documentation with changes made

## Compatibility Notes

### Known Compatible Environments
- Standard Windows 10/11 Enterprise environments
- Windows Server 2016/2019/2022 standard configurations
- Domain-joined and standalone systems
- Virtual and physical machines

### Potential Compatibility Issues
- Legacy applications with specific security requirements
- Custom enterprise applications
- Third-party security software conflicts
- Specialized industrial or embedded systems

## Troubleshooting

### Common Issues
- **Access Denied**: Ensure running as Administrator
- **Execution Policy**: May need to adjust PowerShell execution policy
- **System Compatibility**: Verify Windows version compatibility
- **Service Dependencies**: Some applications may require service adjustments

### Recovery Options
- Use System Restore points created before execution
- Review detailed logs for specific failure points
- Consult CIS documentation for manual configuration steps
- Contact system administrator for enterprise environments

## Support & Documentation

### Additional Resources
- [CIS Official Website](https://www.cisecurity.org/)
- [CIS Controls Documentation](https://www.cisecurity.org/controls/)
- [Microsoft Security Baselines](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-compliance-toolkit-10)

### Best Practices
- Regular security assessments
- Continuous monitoring and logging
- Regular updates and patch management
- Employee security training
- Incident response planning

## Disclaimer

These scripts modify critical system security settings. While designed to enhance security, they may impact system functionality or application compatibility. Always test thoroughly in non-production environments before deploying to production systems. Users assume full responsibility for any system changes or impacts resulting from script execution.

---

**Created by:** [Gulab Prasad](https://gulabprasad.com)  
**Website:** https://gulabprasad.com  
**Version:** 1.0  
**Last Updated:** 2024
