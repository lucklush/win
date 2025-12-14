Import-Module .\api.ps1

if(!((GetSettings).ADInstalled)) {
    Write-Output "This is an active directory specific module"
    exit
}

function getGuestUser() {
    $users = Get-ADUser -Filter * -Properties *
    foreach($user in $users) {
        if($user.Description.Contains("Built-in account for guest access to the computer/domain")) {
            return $user
        }
    }
}

Write-Output "Fixing SAM ACLs in case they are broken"

$rootACL = Get-Acl "HKLM:\SAM\SAM"

if(-not $rootACL) {
    Write-Output "Holy shit something really fucked up happend here"
    Write-Output "If you see this you gonna have to somehow do this manually (windows PE maybe???)"
    exit
}

$rootACL.SetOwner((New-Object System.Security.Principal.NTAccount("Builtin", "Administrators"))) # Set Owner to Administrators group
$rootACL.SetSecurityDescriptorSddlForm("O:BAG:SYD:P(A;CI;KA;;;SY)(A;CI;RCWD;;;BA)") # Sets SSDL to default one
$rootACL.SetAccessRuleProtection($true, $false) # Disables any inheritance

Set-Acl "HKLM:\SAM\SAM" -AclObject $rootACL

.\tools\regjump.exe -accepteula HKEY_LOCAL_MACHINE\SAM\SAM

Write-Output "Right Click highlighted key > Permissions > Advanced > Check 'Replace all child object permissions...' > OK > Yes"

pause

Get-ChildItem -Path "HKLM:\SAM\SAM" -Recurse | ForEach-Object { # Reset the owner to the Administrators group since the above action does not do that
    $acl = Get-Acl $_.PsPath
    $acl.SetOwner((New-Object System.Security.Principal.NTAccount("Builtin", "Administrators")))
    Set-Acl -Path $_.PSPath -AclObject $acl
}

clear

$password = "k97(0HaZ8~9^QMcxsg15rX-z"

$currentUser = (GetSettings).CurrentUser

while(!(Test-Path .\UserData.txt)) {
    clear
    Write-Output "User data file not found, make a file called UserData.txt in the main directory"
    Write-Output "Use the format in the README to see format"
    pause
}

clear

# Read file
$lines = Get-Content .\UserData.txt

# Variables for data from file
$defaultUsers = "Administrator","DefaultAccount","Guest","WDAGUtilityAccount","SYSTEM","LOCAL SERVICE","NETWORK SERVICE","DWM-1","UMFD-0","UMFD-1","sshd","ssh-agent","LxssManagerUser","IUSR","IWAM","DefaultAppPool","vmms","vmcompute","MSSQLSERVER","SQLSERVERAGENT", "Spooler","TrustedInstaller"
$mode = ""
$admins = @()
$users = @()

foreach ($line in $lines) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }

    switch -Regex ($line) {
        '^Authorized Administrators:' { $mode = "admins"; continue }
        '^Authorized Users:' { $mode = "users"; continue }

        default {
            if ($mode -eq "admins") { $admins += $line.Trim() }
            elseif ($mode -eq "users") { $users += $line.Trim() }
        }
    }
}

Write-Host "Admins from file: $($admins -join ', ')"
Write-Host "Users from file: $($users -join ', ')"

# ------------------------------
# START ACCOUNT ENFORCEMENT LOGIC
# ------------------------------

$localAdminsGroup = "Administrators"
$localUsersGroup  = "Domain Users"

# Default password for new accounts
$defaultPassword = ConvertTo-SecureString "CyberPatriot1#" -AsPlainText -Force

Write-Output "Unlocking all accounts"

$users = Get-ADUser -Filter * -Properties *

foreach($user in $users) { Set-AdObject "$($user.ObjectGUID)" -ProtectedFromAccidentalDeletion $false -Confirm:$false }

Write-Output "Deleting unauthorized users"

$builtInAccounts = [System.Collections.ArrayList]::new()

$users = Get-ADUser -Filter * -Properties *

foreach ($user in $users) {
    if ($userData.Contains($user.SamAccountName)) { continue }

    # Skip built-in accounts
    if ($user.SamAccountName -in @("Administrator","Guest","krbtgt")) {
        $builtInAccounts.Add($user) | Out-Null
        continue
    }

    Write-Output "Deleting User: $($user.SamAccountName)"
    Remove-ADUser -Identity $user -Confirm:$false
    Write-Output ""
}

Remove-Item .\err.txt

Write-Output "Disabling built in accounts"

Disable-ADAccount -Identity "Administrator"
Disable-ADAccount -Identity "Guest"

Write-Output "Creating any missing users"

foreach ($user in $userData.Keys) {
    $adUser = Get-ADUser -Filter "SamAccountName -eq '$user'" -ErrorAction SilentlyContinue
    if (-not $adUser) {
        Write-Output "Creating new AD user: $user"
        New-ADUser -SamAccountName $user -Name $user -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -Enabled $true
    }
}


$ErrorActionPreference = "Continue"

Write-Output "Enabling all non-builtin accounts"

$users = Get-ADUser -Filter * -Properties *

foreach($user in $users) {
    if($builtInAccounts.Contains($user.Name)) { continue }
    Enable-ADAccount "$user"
}

Write-Output "Setting all users primary group to 'Domain Users'"

$users = Get-ADUser -Filter *
$domainUsersGroup = Get-ADGroup "Domain Users" -Properties @("primaryGroupToken")

foreach($user in $users) { Set-ADUser "$user" -replace @{primaryGroupID=$domainUsersGroup.primaryGroupToken} }

Write-Output "Removing the users in all the groups (besides Domain Users) to reset them"

$groups = Get-ADGroup -Filter *

foreach($group in $groups) {
    if($group.Name -eq "Domain Users") { continue }
    $members = Get-ADGroupMember "$group"
    foreach($member in $members) {
        if("$member".Length -ne 0) {
            Write-Output "Removing $($member.Name) from $($group.Name)"
            Remove-ADGroupMember "$group" "$member" -Confirm:$false
        }
    }
}

Write-Output "Adding users to their groups defined in user data file"

$ErrorActionPreference = "SilentlyContinue"

foreach($user in $userData.Keys) {
    $groups = $userData[$user]
    foreach($group in $groups) {
        $adGroup = Get-ADGroup "$group"
        if(!$adGroup) {
            Write-Output "Creating new group: $group"
            New-ADGroup "$group" -GroupScope Global | Out-Null
        }
        Add-ADGroupMember "$group" "$user"
        $adGroup = $null
    }
}

$guestUser = getGuestUser

Add-ADGroupMember "Domain Guests" $guestUser

$ErrorActionPreference = "Continue"

$renameAccounts = (Read-Host "Rename builtin accounts? (Might break some checks) (y/n)") -eq "y"

if($renameAccounts) {
    foreach($user in $builtInAccounts) {
        $newName = -join ((48..57) + (97..122) | Get-Random -Count 20 | % {[char]$_})
        Rename-LocalUser "$($user.Name)" "$newName"
        Rename-ADObject "$($user.ObjectGUID)" $newName
    }
}

Write-Output "Setting user passwords and properties"

$users = Get-ADUser -Filter *

foreach($user in $users) {
    if($user.Name -ne $currentUser) {
        Set-ADAccountPassword -Identity $user.SamAccountName -NewPassword (ConvertTo-SecureString $password -AsPlainText -Force) -Reset
        Set-ADUser "$user" -TrustedForDelegation $False -AllowReversiblePasswordEncryption $False -CannotChangePassword $False -ChangePasswordAtLogon $True -CompoundIdentitySupported $True -KerberosEncryptionType AES256 -PasswordNeverExpires $False -PasswordNotRequired $False -Clear scriptPath -SmartcardLogonRequired $False -AccountNotDelegated $True
        Set-ADAccountControl "$user" -DoesNotRequirePreAuth $False -AllowReversiblePasswordEncryption $False -TrustedForDelegation $False -TrustedToAuthForDelegation $False -UseDESKeyOnly $False -AccountNotDelegated $True
    }
}

Write-Output "Mitigating RID Hijacking and deleting ResetData keys" # ResetData keys are security questions, which as of writing this, are stored IN PLAIN TEXT (wtf microsoft)

$items = Get-ChildItem -Path "HKLM:\SAM\SAM\Domains\Account\Users"

foreach($item in $items) {
    $rawName = $item.Name.ToString().Split("\")
    $name = $rawName[$rawName.Count - 1]
    $props = (Get-ItemProperty -Path "HKLM:\SAM\SAM\Domains\Account\Users\$name")
    if(!$props.F) { continue }
    $f = $props.F
    $f[48] = [convert]::ToInt32($name.SubString($name.Length - 2), 16)
    $f[49] = [convert]::ToInt32($name.SubString($name.Length - 4, 2), 16)
    Set-ItemProperty -Path "HKLM:\SAM\SAM\Domains\Account\Users\$name" -Name F -Value $f
    if(((Get-ItemProperty -Path "HKLM:\SAM\SAM\Domains\Account\Users\$name").ResetData)) {
        reg delete "HKLM\SAM\SAM\Domains\Account\Users\$name" /v ResetData /f | Out-Null
    }
}

Write-Output "Deleting SID Histories from users and groups"

# Remove SIDHistory from users who have it
$users = Get-ADUser -Filter {SIDHistory -like "*"} -Properties SIDHistory, servicePrincipalName
Set-ADUser -Identity $user -Clear SIDHistory

foreach ($user in $users) {
    if ($user.SIDHistory) {
        Write-Output "Clearing SIDHistory from user: $($user.SamAccountName)"
        Set-ADUser -Identity $user -Clear SIDHistory
    }
    if ($user.servicePrincipalName) {
        Write-Output "Clearing servicePrincipalName from user: $($user.SamAccountName)"
        Set-ADUser -Identity $user -Clear servicePrincipalName
    }
}

# Remove SIDHistory from groups who have it
$groups = Get-ADGroup -Filter {SIDHistory -like "*"} -Properties SIDHistory
foreach ($group in $groups) {
    if ($group.SIDHistory) {
        Write-Output "Clearing SIDHistory from group: $($group.SamAccountName)"
        Set-ADGroup -Identity $group -Clear SIDHistory
    }
}

# Ask for the username to skip
$skipUser = Read-Host "Enter your username (case-sensitive)"

function Show-Tree {
    param(
        [string]$Path = ".",
        [int]$Indent = 0
    )

    Get-ChildItem -LiteralPath $Path | ForEach-Object {
        # Skip hidden folders
        if ($_.PSIsContainer -and ($_.Attributes -band [System.IO.FileAttributes]::Hidden)) {
            return
        }

        # Skip the specified user folder if in C:\Users
        if ($Path -eq "C:\Users" -and $_.PSIsContainer -and $_.Name -eq $skipUser) {
            return
        }

        # Print the current item
        Write-Output (" " * $Indent + "|-- " + $_.Name)

        # Recurse into directories
        if ($_.PSIsContainer) {
            Show-Tree -Path $_.FullName -Indent ($Indent + 2)
        }
    }
}

# Start at C:\Users
Show-Tree -Path "C:\Users"
Write-Host "Look for any prohibited files/malware above. Still do a manual search though"
pause
