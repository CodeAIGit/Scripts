# Azure Temporary Access Pass (TAP) Script - Usage Guide

## 👨‍💻 Created By
**Gulab Prasad**  
🌐 [https://gulabprasad.com](https://gulabprasad.com)  
🔗 [LinkedIn](https://www.linkedin.com/in/gulab/)

---

## 📝 License
This script is licensed under the MIT License.  

## Script Overview
This script enables Temporary Access Pass (TAP) authentication method in your Azure AD tenant and optionally creates TAP codes for multiple users from a CSV file.

## Usage Options

### 1. **Basic Usage (Default Settings)**
```powershell
.\EnableTAP.ps1 -CsvFilePath "users.csv"
```
- **Lifetime**: 60 minutes
- **Reusability**: One-time use
- **Log**: Auto-generated with timestamp

### 2. **Custom Lifetime Only**
```powershell
.\EnableTAP.ps1 -CsvFilePath "users.csv" -LifetimeInMinutes 120
```
- Sets all TAPs to 120 minutes
- Still one-time use (default)

### 3. **Custom Reusability Only**
```powershell
.\EnableTAP.ps1 -CsvFilePath "users.csv" -IsOneTimeUse $false
```
- 60 minutes (default) but reusable TAPs

### 4. **Custom Lifetime + Reusability**
```powershell
.\EnableTAP.ps1 -CsvFilePath "users.csv" -LifetimeInMinutes 180 -IsOneTimeUse $false
```
- 180-minute reusable TAPs

### 5. **Custom Log File Location**
```powershell
.\EnableTAP.ps1 -CsvFilePath "users.csv" -LogFilePath "C:\Logs\MyTAP.log"
```
- Specify custom log file path

### 6. **All Parameters Custom**
```powershell
.\EnableTAP.ps1 -CsvFilePath "users.csv" -LifetimeInMinutes 240 -IsOneTimeUse $false -LogFilePath "C:\Logs\TAP_Custom.log"
```
- Full parameter customization

### 7. **Per-User Settings via CSV**
Use CSV with individual settings, then run:
```powershell
.\EnableTAP.ps1 -CsvFilePath "users.csv"
```
- CSV values override script parameters for each user

**Enhanced CSV Format (with per-user settings):**
```csv
UserPrincipalName,LifetimeInMinutes,IsOneTimeUse
burris.walker@company.com,120,true
gulab.prasad@company.com,180,false
himangshu.malik@company.com,60,true
```

### 8. **Mixed: Script Defaults + CSV Overrides**
```powershell
.\EnableTAP.ps1 -CsvFilePath "users.csv" -LifetimeInMinutes 90 -IsOneTimeUse $false
```
- Script provides defaults (90 min, reusable)
- CSV columns override defaults per user
- Users without CSV values use script defaults

### 9. **Enable TAP Method Only** (No User Creation)
```powershell
.\EnableTAP.ps1
```
**What it does:**
- Enables TAP authentication method globally in your tenant
- Uses script parameter defaults for global policy
- Allows admins to manually create TAP codes for users later

**Basic CSV Format:**
```csv
UserPrincipalName
burris.walker@company.com
gulab.prasad@company.com
himangshu.malik@company.com
```

---

### 10. **Using Relative Paths**
```powershell
# CSV in same folder as script
.\EnableTAP.ps1 -CsvFilePath "users.csv"

# CSV in subfolder
.\EnableTAP.ps1 -CsvFilePath "data\users.csv"

# CSV in parent folder
.\EnableTAP.ps1 -CsvFilePath "..\users.csv"
```

---

### 11. **Run from Different Locations**

**From Script Directory:**
```powershell
cd C:\Scripts\Azure\TAP
.\EnableTAP.ps1 -CsvFilePath "users.csv" -LifetimeInMinutes 120
```

**From Any Directory (Full Path):**
```powershell
C:\Scripts\Azure\TAP\EnableTAP.ps1 -CsvFilePath "C:\Data\users.csv" -IsOneTimeUse $false
```

**Using PowerShell ISE:**
```powershell
# Open PowerShell ISE, load script, then run with F5
# Or use Invoke-Expression
Invoke-Expression "C:\Scripts\Azure\TAP\EnableTAP.ps1 -CsvFilePath 'C:\Data\users.csv' -LifetimeInMinutes 180"
```

---

### 12. **Advanced Execution Methods**

**Run as Administrator (Recommended):**
```powershell
# Right-click PowerShell → "Run as Administrator"
Set-Location C:\Scripts\Azure\TAP
.\EnableTAP.ps1 -CsvFilePath "users.csv" -LifetimeInMinutes 240
```

**Run with Execution Policy Bypass:**
```powershell
PowerShell.exe -ExecutionPolicy Bypass -File "C:\Scripts\Azure\TAP\EnableTAP.ps1" -CsvFilePath "users.csv" -IsOneTimeUse $false
```

**Run Minimized/Hidden:**
```powershell
PowerShell.exe -WindowStyle Hidden -File "C:\Scripts\Azure\TAP\EnableTAP.ps1" -CsvFilePath "users.csv"
```

---

### 13. **Batch/Scheduled Execution**

**Create a Batch File:**
```batch
@echo off
cd /d C:\Scripts\Azure\TAP
PowerShell.exe -ExecutionPolicy Bypass -File "EnableTAP.ps1" -CsvFilePath "users.csv" -LifetimeInMinutes 120 -IsOneTimeUse $false
pause
```

**Schedule with Task Scheduler:**
```
Program: PowerShell.exe
Arguments: -ExecutionPolicy Bypass -File "C:\Scripts\Azure\TAP\EnableTAP.ps1" -CsvFilePath "C:\Data\users.csv" -LifetimeInMinutes 180
Start In: C:\Scripts\Azure\TAP
```

---

### 14. **Network/UNC Path Usage**
```powershell
# Script on network share
\\server\share\Scripts\EnableTAP.ps1 -CsvFilePath "\\server\data\users.csv" -LogFilePath "\\server\logs\TAP.log"

# Map network drive first
net use Z: \\server\share
Z:\Scripts\EnableTAP.ps1 -CsvFilePath "Z:\data\users.csv" -LifetimeInMinutes 300
```

---

### 15. **Testing and Validation**

**Test Script Syntax First:**
```powershell
# Check for syntax errors without running
PowerShell.exe -NoExecute -File "EnableTAP.ps1"
```

**Dry Run (Check CSV Format):**
```powershell
# Just validate CSV without creating TAPs
Import-Csv "users.csv" | Select-Object UserPrincipalName, LifetimeInMinutes, IsOneTimeUse
```

**Test with Single User:**
```csv
UserPrincipalName,LifetimeInMinutes,IsOneTimeUse
test.user@company.com,30,true
```

**Parameter Validation Test:**
```powershell
# Test custom parameters
.\EnableTAP.ps1 -LifetimeInMinutes 480 -IsOneTimeUse $false -LogFilePath "test.log"
```

---

## Enhanced CSV Formats

### **Basic CSV (Script defaults apply):**
```csv
UserPrincipalName
burris.walker@company.com
gulab.prasad@company.com
himangshu.malik@company.com
```

### **Full CSV (Per-user customization):**
```csv
UserPrincipalName,LifetimeInMinutes,IsOneTimeUse
burris.walker@company.com,60,true
gulab.prasad@company.com,120,false
himangshu.malik@company.com,180,true
admin@company.com,30,true
```

### **Mixed CSV (Some users customized):**
```csv
UserPrincipalName,LifetimeInMinutes,IsOneTimeUse
burris.walker@company.com,240,false
gulab.prasad@company.com,,
himangshu.malik@company.com,60,true
```
*Note: Empty values use script defaults*

---

## Output Files Generated

### When CSV is provided:
- **`TAP_Results_[timestamp].csv`** - Contains TAP codes and detailed status for each user
- **`TAP_[timestamp].log`** - Detailed execution log with timestamps
- **Console Output** - Real-time progress and TAP codes

### Enhanced TAP_Results.csv:
```csv
UserPrincipalName,DisplayName,TemporaryAccessPass,LifetimeInMinutes,IsOneTimeUse,StartDateTime,Status,Error
burris.walker@company.com,John Doe,A1B2C3D4,120,True,2024-01-15T10:30:00Z,SUCCESS,
gulab.prasad@company.com,Jane Smith,X5Y6Z7W8,180,False,2024-01-15T10:31:00Z,SUCCESS,
himangshu.malik@company.com,Bob Wilson,,60,True,,FAILED,User not found in Azure AD
```

### Sample Log Output:
```
[10:30:01] [SUCCESS] === Azure TAP Script Starting ===
[10:30:01] [INFO] Script Parameters:
[10:30:01] [INFO]   CSV File: users.csv
[10:30:01] [INFO]   Default Lifetime: 120 minutes
[10:30:01] [INFO]   Default Reusability: One-time use
[10:30:02] [SUCCESS] Connected to tenant: 12345678-1234-1234-1234-123456789012
[10:30:03] [SUCCESS] TAP authentication method enabled successfully
[10:30:04] [INFO] Detected per-user settings in CSV:
[10:30:04] [INFO]   - Individual LifetimeInMinutes values
[10:30:05] [SUCCESS] SUCCESS: burris.walker@company.com = A1B2C3D4
[10:30:06] [SUCCESS] === TAP Creation Summary ===
[10:30:06] [INFO] Total Users: 3
[10:30:06] [SUCCESS] Successful: 2
[10:30:06] [ERROR] Failed: 1
```

---

## Common Usage Scenarios

### **Scenario 1: New Employee Onboarding**
```powershell
# Short-term TAPs for initial setup
.\EnableTAP.ps1 -CsvFilePath "new_employees.csv" -LifetimeInMinutes 30 -IsOneTimeUse $true
```

### **Scenario 2: Password Reset Campaign**
```powershell
# Longer TAPs for password reset process
.\EnableTAP.ps1 -CsvFilePath "password_reset_users.csv" -LifetimeInMinutes 180 -IsOneTimeUse $false
```

### **Scenario 3: MFA Enrollment Drive**
```powershell
# Extended reusable TAPs for MFA setup
.\EnableTAP.ps1 -CsvFilePath "mfa_enrollment_users.csv" -LifetimeInMinutes 240 -IsOneTimeUse $false
```

### **Scenario 4: Emergency Access**
```powershell
# Quick emergency TAPs
.\EnableTAP.ps1 -CsvFilePath "emergency_users.csv" -LifetimeInMinutes 60
```

### **Scenario 5: Mixed User Requirements**
Create CSV with per-user settings:
```csv
UserPrincipalName,LifetimeInMinutes,IsOneTimeUse
new.employee@company.com,30,true
contractor@company.com,480,false
temp.worker@company.com,120,true
```
Then run: `.\EnableTAP.ps1 -CsvFilePath "mixed_users.csv"`

---

## Troubleshooting

### **Permission Issues:**
```powershell
# Run as Administrator
# Or install modules in CurrentUser scope (script handles this)
```

### **Module Installation Issues:**
```powershell
# Manual module installation
Install-Module Microsoft.Graph.Authentication -Force -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.SignIns -Force -Scope CurrentUser
Install-Module Microsoft.Graph.Users -Force -Scope CurrentUser
```

### **CSV Format Issues:**
- Ensure column is named exactly `UserPrincipalName`
- Use full email addresses (user@domain.com)
- Save CSV in UTF-8 encoding
- No empty rows

### **Authentication Issues:**
- Ensure you have Global Administrator or Authentication Policy Administrator role
- Modern authentication must be enabled
- Account must have appropriate Graph API permissions

---

## Best Practices

1. **Always test with a small CSV first** (1-2 users)
2. **Run as Administrator** for module installation
3. **Keep CSV files secure** (contain user information)
4. **Review TAP_Results.csv** for failed users
5. **Distribute TAP codes securely** (encrypted email, secure portal)
6. **Monitor TAP usage** in Azure AD sign-in logs
7. **Clean up old CSV/result files** regularly

---

## Quick Reference Commands

```powershell
# Enable TAP method only (no users)
.\EnableTAP.ps1

# Basic usage - default settings (60 min, one-time)
.\EnableTAP.ps1 -CsvFilePath "users.csv"

# Custom lifetime only
.\EnableTAP.ps1 -CsvFilePath "users.csv" -LifetimeInMinutes 120

# Reusable TAPs
.\EnableTAP.ps1 -CsvFilePath "users.csv" -IsOneTimeUse $false

# Full customization
.\EnableTAP.ps1 -CsvFilePath "users.csv" -LifetimeInMinutes 240 -IsOneTimeUse $false -LogFilePath "C:\Logs\TAP.log"

# Full path execution
C:\Scripts\Azure\TAP\EnableTAP.ps1 -CsvFilePath "C:\Data\users.csv" -LifetimeInMinutes 180

# Check basic CSV format
Import-Csv "users.csv" | Format-Table UserPrincipalName

# Check enhanced CSV format
Import-Csv "users.csv" | Format-Table UserPrincipalName, LifetimeInMinutes, IsOneTimeUse

# View results
Import-Csv "TAP_Results_20240115_103001.csv" | Format-Table UserPrincipalName, TemporaryAccessPass, Status

# View successful TAPs only
Import-Csv "TAP_Results_20240115_103001.csv" | Where-Object Status -eq "SUCCESS" | Format-Table

# View failed TAPs only
Import-Csv "TAP_Results_20240115_103001.csv" | Where-Object Status -eq "FAILED" | Format-Table UserPrincipalName, Error
```

## Parameter Reference

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-CsvFilePath` | String | None | Path to CSV file with users |
| `-LifetimeInMinutes` | Int | 60 | TAP lifetime (10-43200 minutes) |
| `-IsOneTimeUse` | Bool | $true | Single use (true) or reusable (false) |
| `-LogFilePath` | String | Auto | Custom log file path |

## CSV Column Reference

| Column | Required | Type | Description |
|--------|----------|------|-------------|
| `UserPrincipalName` | ✅ | String | User email/UPN |
| `LifetimeInMinutes` | ❌ | Int | Per-user lifetime override |
| `IsOneTimeUse` | ❌ | Bool | Per-user reusability override |

---
