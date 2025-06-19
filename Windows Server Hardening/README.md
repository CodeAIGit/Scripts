# CIS Security Hardening Scripts

PowerShell scripts for implementing CIS (Center for Internet Security) benchmarks on Windows systems to enhance security posture and compliance.

## Overview

The Center for Internet Security (CIS) Controls are a prioritized set of actions that collectively form a defense-in-depth set of best practices that mitigate the most common attack vectors. These scripts automate the implementation of CIS benchmarks for Windows environments.

## Scripts Included

### CIS Level 1 Hardening Script
- **Purpose**: Implements essential security configurations with minimal impact on functionality
- **Target**: Basic security hardening suitable for most environments
- **Compatibility**: Designed for general enterprise use with broad compatibility

![CIS Level 1 Hardening Screenshot](screenshots/cis-level1-hardening.png)
*CIS Level 1 Hardening Script execution with real-time progress tracking*
![image](https://github.com/user-attachments/assets/09409781-a8aa-4619-a335-f5af1aa8e1fa)

### CIS Level 2 Hardening Script  
- **Purpose**: Applies advanced security configurations for high-security environments
- **Target**: Enhanced security for sensitive or high-risk environments
- **Compatibility**: May impact some applications - thorough testing recommended

![CIS Level 2 Hardening Screenshot](screenshots/cis-level2-hardening.png)
*CIS Level 2 Hardening Script with advanced security configurations*
![image](https://github.com/user-attachments/assets/c5c1212c-f2dc-4b4e-9b85-3287ef730cde)

### CIS Assessment Tool
- **Purpose**: Evaluates current system configuration against CIS benchmarks
- **Function**: Generates compliance reports and identifies security gaps
- **Usage**: Run before hardening to establish baseline, or after to verify implementation
- **Output**: Detailed HTML/CSV reports with recommendations and current status

![CIS Assessment Tool Screenshot](screenshots/cis-assessment-tool.png)
*CIS Assessment Tool in action - compliance dashboard and report generation*
![image](https://github.com/user-attachments/assets/7d9e724e-d640-4115-a979-0c301828c155)

## System Requirements

- **Operating System**: Windows Server 2019/2022/2025
- **PowerShell**: Version 5.1 or higher
- **Privileges**: Administrator rights required
- **Memory**: Minimum 4GB RAM recommended
- **Disk Space**: At least 1GB free space for logs and restore points

## Installation & Usage

### Directory Structure
```
CIS-Hardening-Scripts/
├── CIS-Level1-Hardening.ps1
├── CIS-Level2-Hardening.ps1
├── CIS-Assessment-Tool.ps1
├── README.md
└── screenshots/
    ├── cis-assessment-tool.png
    ├── cis-level1-hardening.png
    ├── cis-level2-hardening.png
    └── cis-assessment-report.png
```

### Pre-Execution Checklist
1. **Run initial CIS assessment** to establish current compliance baseline
2. Create full system backup
3. Test in non-production environment first
4. Review organizational policies and requirements
5. **Analyze assessment report** and plan implementation strategy
6. Schedule maintenance window for implementation

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
   # For CIS compliance assessment (recommended first step)
   .\CIS Security Assessment Tool for Windows Server.ps1
   
   # For Level 1 hardening
   .\CIS-Level1-MultiVersion-Hardening.ps1
   
   # For Level 2 hardening (run after Level 1)
   .\CIS-Level2-MultiVersion-Hardening.ps1
   
   # Re-run assessment to verify implementation
   .\CIS Security Assessment Tool for Windows Server.ps1 -PostHardening
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
- ✅ **Pre-implementation compliance assessment**
- ✅ **Post-implementation verification and reporting**
- ✅ System restore point creation before changes
- ✅ Detailed logging and progress tracking
- ✅ Comprehensive error handling
- ✅ Real-time status reporting
- ✅ Rollback capabilities via restore points
- ✅ **HTML and CSV compliance reports**
- ✅ **Gap analysis and recommendation engine**

### Logging & Monitoring
- Detailed execution logs stored in `C:\Windows\Temp\`
- Progress tracking with colored output
- Error reporting and troubleshooting information
- Summary reports of applied configurations

## Assessment Tool Features

### CIS Compliance Assessment
The assessment tool provides comprehensive evaluation of your system's current security posture against CIS benchmarks.

### Key Assessment Capabilities
- **Baseline Analysis**: Evaluates current system configuration
- **Gap Identification**: Highlights non-compliant settings
- **Risk Assessment**: Prioritizes security issues by severity
- **Compliance Scoring**: Provides percentage compliance ratings
- **Detailed Reporting**: Generates professional HTML and CSV reports
- **Recommendation Engine**: Suggests specific remediation steps
- **Historical Tracking**: Maintains assessment history for trend analysis

### Assessment Categories
- Password and account policies
- User rights and privileges
- Audit and logging configurations
- Security options and settings
- Service configurations
- Registry security settings
- Network security protocols
- System hardening status

### Report Outputs
- **Executive Summary**: High-level compliance overview
- **Detailed Findings**: Item-by-item compliance status
- **Risk Matrix**: Categorized security gaps
- **Remediation Guide**: Step-by-step fix instructions
- **Compliance Trends**: Historical comparison data

### Recommended Workflow
1. **Initial Assessment**: Run assessment tool to establish baseline
2. **Plan Implementation**: Review findings and plan hardening approach
3. **Apply Hardening**: Execute Level 1 and/or Level 2 scripts
4. **Verify Results**: Re-run assessment to confirm successful implementation
5. **Regular Monitoring**: Schedule periodic assessments for ongoing compliance

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
- Windows Server 2019/2022/2025 standard configurations
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
- **Run assessment tool to identify specific configuration issues**
- Review detailed logs for specific failure points
- **Compare pre and post-hardening assessment reports**
- Consult CIS documentation for manual configuration steps
- Contact system administrator for enterprise environments

## Support & Documentation

### Additional Resources
- [CIS Official Website](https://www.cisecurity.org/)
- [CIS Controls Documentation](https://www.cisecurity.org/controls/)
- [Microsoft Security Baselines](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-compliance-toolkit-10)

### Best Practices
- **Regular compliance assessments** using the assessment tool
- Regular security assessments
- Continuous monitoring and logging
- Regular updates and patch management
- **Trend analysis** using historical assessment data
- Employee security training
- Incident response planning

## Disclaimer

These scripts modify critical system security settings. While designed to enhance security, they may impact system functionality or application compatibility. Always test thoroughly in non-production environments before deploying to production systems. Users assume full responsibility for any system changes or impacts resulting from script execution.

---

**Created by:** [Gulab Prasad](https://gulabprasad.com)  
**Website:** https://gulabprasad.com  
**Version:** 1.0  
**Last Updated:** 2025
