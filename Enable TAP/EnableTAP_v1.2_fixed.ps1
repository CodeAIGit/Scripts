# Connect Mg-Graph
Connect-MgGraph -Scopes "UserAuthenticationMethod.ReadWrite.All", "Directory.AccessAsUser.All", "Policy.Read.All" -NoWelcome

# Check if TAP is enabled
$tapPolicy = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "TemporaryAccessPass"

if ($tapPolicy.state -ne "enabled") {
    Write-Host "❌ Please enable TAP in Microsoft Entra Authentication Methods before running this script." -ForegroundColor Red
    exit
}

Write-Host "✅ TAP is enabled. Continuing script execution..." -ForegroundColor Green


# Import user list from CSV
$users = Import-Csv -Path ".\users.csv"

# Initialize an array to store TAP details
$tapList = @()

foreach ($user in $users) {
    # Generate TAP for each user
    $tap = @{
        isUsable = $true
        lifetimeInMinutes = 480  # TAP valid for 8 hours, Change this if you want a shorter timespan.
    }

    $result = New-MgUserAuthenticationTemporaryAccessPassMethod -UserId $user.UserPrincipalName -BodyParameter $tap

    # Store TAP details in an array
    $tapDetails = [PSCustomObject]@{
        Email        = $user.UserPrincipalName
        TAP_Password = $result.TemporaryAccessPass  # Retrieve TAP password
    }

    $tapList += $tapDetails
    Write-Host "Created TAP for: $($user.UserPrincipalName) - Password: $($result.TemporaryAccessPass)" -ForegroundColor Cyan
}

# Export TAPs to CSV
$tapList | Export-Csv -Path ".\TAP_Users.csv" -NoTypeInformation -Force

Write-Host "TAP creation complete. Check TAP_Users.csv for details." -ForegroundColor Green