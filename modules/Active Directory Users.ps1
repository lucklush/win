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
$defaultUsers = "Administrator","DefaultAccount","Guest","WDAGUtilityAccount","SYSTEM","LOCAL SERVICE","NETWORK SERVICE","DWM-1","UMFD-0","UMFD-1","sshd","ssh-agent","LxssManagerUser","IUSR","IWAM","DefaultAppPool","vmms","vmcompute","MSSQLSERVER","SQLSERVERAGENT", "Spooler","TrustedInstaller","krbtgt"
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

# Define your AD groups
$adAdminsGroup = "Domain Admins"         # AD group for admins
$adUsersGroup = "Domain Users"           # AD group for regular users

# Default password for new accounts
$defaultPassword = ConvertTo-SecureString "CyberPatriot1#" -AsPlainText -Force

Write-Output "Unlocking all accounts"

$users = Get-ADUser -Filter * -Properties *

foreach($user in $users) { Set-AdObject "$($user.ObjectGUID)" -ProtectedFromAccidentalDeletion $false -Confirm:$false }

$adAccounts = Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName | ForEach-Object {
    if ($_ -like "*\*") {
        ($_ -split "\\")[-1]  # take the part after the last backslash
    } else {
        $_
    }
}

# 1. Delete bad users
foreach ($acct in $adAccounts) {
    if ($acct -notin $admins -and $acct -notin $users -and $acct -notin $defaultUsers) {
        Write-Host "Deleting account not in list: $acct"
        Remove-ADUser -Identity $acct -Confirm:$false
    }
}

$adAccounts = Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName | ForEach-Object {
    if ($_ -like "*\*") {
        ($_ -split "\\")[-1]  # take the part after the last backslash
    } else {
        $_
    }
}

# 2. Convert users → admins if they appear in admin list
foreach ($acct in $adAccounts) {
    if ($acct -in $admins -and $acct -notin $defaultUsers) {
        try {
            Add-ADGroupMember -Identity $adAdminsGroup -Members $acct -ErrorAction SilentlyContinue
            Write-Host "Added $acct to $adAdminsGroup"
        } catch {
            Write-Warning "Could not add $acct to $adAdminsGroup: $_"
        }
    }
}

# 3. Convert admins → users if they appear in user list
foreach ($acct in $adAccounts) {
    if ($acct -in $users -and $acct -notin $admins -and $acct -notin $defaultUsers) {
        
            # Add to regular users group
            Add-ADGroupMember -Identity $adUsersGroup -Members $acct -ErrorAction SilentlyContinue

            # Remove from admin group
            Remove-ADGroupMember -Identity $adAdminsGroup -Members $acct -Confirm:$false -ErrorAction SilentlyContinue
            Remove-ADGroupMember -Identity "Administrators" -Members $acct -Confirm:$false -ErrorAction SilentlyContinue
            Remove-ADGroupMember -Identity "Enterprise Admins" -Members $acct -Confirm:$false -ErrorAction SilentlyContinue

            Write-Host "Moved $acct to $adUsersGroup and removed from $adAdminsGroup"
        
    }
}

$adAccounts = Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName | ForEach-Object {
    if ($_ -like "*\*") {
        ($_ -split "\\")[-1]  # take the part after the last backslash
    } else {
        $_
    }
}

# 4. CREATE missing user accounts
foreach ($u in $users) {
    if ($u -notin $adAccounts) {
        Write-Host "Creating NEW USER account: $u"
        New-ADUser -Name $u `
                   -SamAccountName $u `
                   -AccountPassword $defaultPassword `
                   -Enabled $true `
                   -Description "Authorized User" `
                   -PasswordNeverExpires $false `
                   -ChangePasswordAtLogon $true

        # Add to Domain Users group (usually automatic, but safe to ensure)
        Add-ADGroupMember -Identity $adUsersGroup -Members $u
    }
}

# 5. CREATE missing admin accounts
foreach ($a in $admins) {
    if ($a -notin $adAccounts) {
        Write-Host "Creating NEW ADMIN account: $a"
        New-ADUser -Name $a `
                   -SamAccountName $a `
                   -AccountPassword $defaultPassword `
                   -Enabled $true `
                   -Description "Authorized Administrator" `
                   -PasswordNeverExpires $false `
                   -ChangePasswordAtLogon $true

        # Add to groups
        Add-ADGroupMember -Identity $adUsersGroup -Members $a
        Add-ADGroupMember -Identity $adAdminsGroup -Members $a
    }
}

Write-Output "Disabling built in accounts"

Disable-ADAccount -Identity "Administrator"
Disable-ADAccount -Identity "Guest"

$ErrorActionPreference = "Continue"

Write-Output "Enabling all non-builtin accounts"

$allUsers = $users + $admins

foreach($user in $allUsers) {
    Enable-ADAccount "$user"
}

$guestUser = getGuestUser

Add-ADGroupMember "Domain Guests" $guestUser

$ErrorActionPreference = "Continue"

Write-Output "Setting user passwords and properties"

foreach ($user in $allUsers) {

    $sam = $user.SamAccountName

    # Reset password
    Set-ADAccountPassword `
        -Identity $sam `
        -NewPassword $defaultPassword `
        -Reset

    # Harden account settings
    Set-ADUser `
        -Identity $sam `
        -ChangePasswordAtLogon $true `
        -PasswordNeverExpires $false `
        -PasswordNotRequired $false `
        -CannotChangePassword $false `
        -AllowReversiblePasswordEncryption $false `
        -TrustedForDelegation $false `
        -TrustedToAuthForDelegation $false `
        -AccountNotDelegated $true `
        -UseDESKeyOnly $false `
        -DoesNotRequirePreAuth $false `
        -KerberosEncryptionType @("AES128","AES256") `
        -ScriptPath $null `
        -SmartcardLogonRequired $false
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
Write-Output "Deleting SIDHistory from users and groups"

# USERS
$users = Get-ADUser -Filter { SIDHistory -like "*" } `
    -Properties SIDHistory, servicePrincipalName, SamAccountName

foreach ($user in $users) {

    if ($user.SIDHistory) {
        Write-Output "Clearing SIDHistory from user: $($user.SamAccountName)"
        Set-ADUser -Identity $user.SamAccountName -Clear SIDHistory
    }

    if ($user.servicePrincipalName) {
        Write-Output "Clearing servicePrincipalName from user: $($user.SamAccountName)"
        Set-ADUser -Identity $user.SamAccountName -Clear servicePrincipalName
    }
}

# GROUPS
$groups = Get-ADGroup -Filter { SIDHistory -like "*" } `
    -Properties SIDHistory, Name

foreach ($group in $groups) {

    if ($group.SIDHistory) {
        Write-Output "Clearing SIDHistory from group: $($group.Name)"
        Set-ADGroup -Identity $group.Name -Clear SIDHistory
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
# Get all user Startup folders
$startupFolders = Get-ChildItem "C:\Users\" -Directory | ForEach-Object {
    Join-Path $_.FullName "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
}

# Check each folder
foreach ($folder in $startupFolders) {
    if (Test-Path $folder) {
        $items = Get-ChildItem $folder -Force -ErrorAction SilentlyContinue
        if ($items.Count -gt 0) {
            Write-Host "Files found in $folder:"
            $items | ForEach-Object { Write-Host "  $_" }
        }
    }
}

$folder = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"

if (Test-Path $folder) {
    $items = Get-ChildItem $folder -Force -ErrorAction SilentlyContinue
    if ($items.Count -gt 0) {
        $items | ForEach-Object { Write-Host $_.FullName }
    }
}
Write-Host "Look for any prohibited files/malware above. Still do a manual search though"
pause
$root = "C:\Windows\SYSVOL"

function Show-TreeSysvol {
    param (
        [string]$Path,
        [string]$Prefix = ""
    )

    $items = Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue

    for ($i = 0; $i -lt $items.Count; $i++) {
        $item = $items[$i]
        $isLast = ($i -eq $items.Count - 1)

        $connector = if ($isLast) { "└── " } else { "├── " }
        Write-Output "$Prefix$connector$($item.Name)"

        if ($item.PSIsContainer) {
            $newPrefix = if ($isLast) {
                "$Prefix    "
            } else {
                "$Prefix│   "
            }

            Show-Tree -Path $item.FullName -Prefix $newPrefix
        }
    }
}

Write-Output $root
Show-TreeSysvol -Path $root
Write-Host "Look for any suspicious startup scripts especially .bat and .ps1 files"
pause
