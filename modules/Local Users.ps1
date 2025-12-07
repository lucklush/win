function getGuestUser() {
    $users = Get-LocalUser
    foreach($user in $users) {
        if($user.Description -and $user.Description.Contains("Built-in account for guest access to the computer/domain")) {
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
$defaultUsers = "Administrator", "DefaultAccount", "Guest", "WDAGUtilityAccount"
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
$localUsersGroup  = "Users"

# Default password for new accounts
$defaultPassword = ConvertTo-SecureString "CyberPatriot1#" -AsPlainText -Force

# Get local accounts
$localAccounts = Get-LocalUser | Select-Object -ExpandProperty Name

# 1. DELETE accounts that aren't in either list
foreach ($acct in $localAccounts) {
    if ($acct -notin $admins -and $acct -notin $users -and $acct -notin $defaultUsers) {
        Write-Host "Deleting account not in list: $acct"
        Remove-LocalUser -Name $acct
    }
}

# Refresh local accounts again
$localAccounts = Get-LocalUser | Select-Object -ExpandProperty Name

# 4. CREATE missing user accounts
foreach ($u in $users) {
    if ($u -notin $localAccounts) {
        Write-Host "Creating NEW USER account: $u"
        New-LocalUser -Name $u -Password $defaultPassword -Description "Authorized User"
        Add-LocalGroupMember -Group $localUsersGroup -Member $u
    }
}

# 5. CREATE missing admin accounts
foreach ($a in $admins) {
    if ($a -notin $localAccounts) {
        Write-Host "Creating NEW ADMIN account: $a"
        New-LocalUser -Name $a -Password $defaultPassword -Description "Authorized Administrator"
        Add-LocalGroupMember -Group $localAdminsGroup -Member $a
    }
}

net user administrator /active:no
net user guest /active:no

Write-Host ""
Write-Host "=== DONE ==="
Write-Host "Current Admins:"
(Get-LocalGroupMember Administrators).Name | ForEach-Object { Write-Host "  $_" }

Write-Host ""
Write-Host "Current Users:"
(Get-LocalGroupMember Users).Name | ForEach-Object { Write-Host "  $_" }

# Combine user and admin arrays
$allAccounts = $admins + $users

# Loop through each account and set the password
foreach ($acct in $allAccounts) {
    # Make sure the account exists before attempting to set password
    if (Get-LocalUser -Name $acct -ErrorAction SilentlyContinue) {
        Write-Host "Setting password for $acct"
        Set-LocalUser -Name $acct -Password $defaultPassword
    } else {
        Write-Host "Account $acct does not exist, skipping password change"
    }
    net user $acct /passwordreq:yes | Out-Null
    net user $acct /passwordchg:yes | Out-Null
    net user $acct /expires:"never" | Out-Null
    Set-LocalUser -Name $acct -PasswordNeverExpires $false | Out-Null
    net user $acct /logonpasswordchg:yes | Out-Null
    net user $acct /active:yes | Out-Null
}

$guestUser = getGuestUser

Add-LocalGroupMember "Guests" $guestUser

Write-Output "Removing any logon scripts that users may have"

$users = Get-LocalUser

$Computer = [adsi]"WinNT://$env:COMPUTERNAME"

foreach($user in $users) {
    $name = $user.Name
    $u = $Computer.psbase.Children.Find("$name")
    $u.LoginScript = ""
    $u.setInfo()
}

Write-Host "Looking for users in suspicious groups"

# Get all local groups
$groups = Get-LocalGroup | Where-Object { $_.Name -ne "Users" -and $_.Name -ne "Administrators" }

foreach ($group in $groups) {
    # Get members of the group
    $members = Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue

    # Only print if there are members
    if ($members.Count -gt 0) {
        Write-Output "Group: $($group.Name)"
        foreach ($member in $members) {
            Write-Output "  $($member.Name)"
        }
        Write-Output ""  # blank line for readability
    }
}

Write-Host "Look through the above for anything suspicious and then press Enter to continue..."
Read-Host

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
function Show-Tree {
    param(
        [string]$Path = ".",
        [int]$Indent = 0
    )

    Get-ChildItem $Path -Force:$false |
        Where-Object {
            -not ($_.Attributes -match "Hidden|System") -and
            -not ($_.Name.StartsWith('.'))
        } |
        ForEach-Object {
            Write-Output (" " * $Indent + "|-- " + $_.Name)

            # Only recurse into directories that do NOT start with '.'
            if ($_.PSIsContainer -and -not ($_.Name.StartsWith('.'))) {
                Show-Tree -Path $_.FullName -Indent ($Indent + 2)
            }
        }
}

Show-Tree -Path "C:\Users"
pause
