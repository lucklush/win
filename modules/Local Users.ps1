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

$password = "k97(0HaZ8~9^QMcxsg15rX-z"

$currentUser = (GetSettings).CurrentUser

while(!(Test-Path .\UserData.txt)) {
    clear
    Write-Output "User data file not found, make a file called UserData.txt in the main directory"
    Write-Output "Use the format in the README to see format"
    pause
}

clear

# Read user data
$userData = @{}
$lines = Get-Content .\UserData.txt

foreach ($line in $lines) {
    if (-not [string]::IsNullOrWhiteSpace($line)) {
        $parts = $line -split '\|'
        $user = $parts[0].Trim()
        $groups = $parts[1] -split ',' | ForEach-Object { $_.Trim() }
        $userData[$user] = $groups
    }
}

$users = Get-LocalUser

foreach($user in $users) {
    net.exe user "$user" /active:yes
}

Write-Output "Deleting unauthorized users"

$builtInAccounts = [System.Collections.ArrayList]::new()

$users = Get-LocalUser

foreach($user in $users) {
    if($userData.Contains($user.Name)) { continue }
    Write-Output "Deleting User: $user"
    ((net.exe user /delete "$user") 2>&1) > err.txt
    $err = (Get-Content .\err.txt)
    if($err.Count -gt 5) { # Pretty much only reason why this would error would be if the requested deleted user is a built in account
        $builtInAccounts.Add($user) | Out-Null
    }
    Write-Output ""
}

Remove-Item .\err.txt

Write-Output "Disabling built in accounts"
Disable-LocalUser -Name "Administrator"
Disable-LocalUser -Name "Guest"

foreach ($user in $userData.Keys) {
    # Check if user exists
    if (-not (Get-LocalUser -Name $user -ErrorAction SilentlyContinue)) {
        # Create the user with a default password
        $defaultPassword = ConvertTo-SecureString "P@ssw0rd123" -AsPlainText -Force
        try {
            New-LocalUser -Name $user -Password $defaultPassword -FullName $user -Description "Created by script"
            Write-Host "Created user $user"
        } catch {
            Write-Warning "Failed to create user ${user}: $($_.Exception.Message)"
        }
    }
}

# Prompt for your username
$currentUser = Read-Host "Enter your username to exclude from Administrators"

Write-Output "Removing users from local groups (safe mode)..."

# Get all local groups except 'Users'
$groups = Get-LocalGroup | Where-Object { $_.Name -ne 'Users' }

foreach ($group in $groups) {
    # Get all members of the group
    $members = Get-LocalGroupMember -Group $group.Name

    foreach ($member in $members) {
        # Skip the current user if it's the Administrators group
        if ($group.Name -eq 'Administrators' -and $member.Name -eq $currentUser) {
            Write-Host "Skipping $currentUser in Administrators"
            continue
        }

        # Remove the member
        Remove-LocalGroupMember -Group $group.Name -Member $member.Name -Confirm:$false
        Write-Host "Removed $($member.Name) from $($group.Name)"
    }
}

Write-Host "Add users to groups" 

foreach ($user in $userData.Keys) {
    $groups = $userData[$user]

    if (-not $groups -or $groups.Count -eq 0) {
        continue
    }

    foreach ($group in $groups) {
        # Create the group if it doesn't exist
        if (-not (Get-LocalGroup -Name $group -ErrorAction SilentlyContinue)) {
            New-LocalGroup -Name $group
            Write-Host "Created group $group"
        }

        # Add user to the group
        try {
            Add-LocalGroupMember -Group $group -Member $user -ErrorAction Stop
            Write-Host "Added $user to $group"
        } catch {
            Write-Warning "Failed to add ${user} to ${group}: $($_.Exception.Message)"
        }
    }
}


$guestUser = getGuestUser

Add-LocalGroupMember "Guests" $guestUser

$renameAccounts = (Read-Host "Rename builtin accounts? (Might break some checks) (y/n)") -eq "y"

if($renameAccounts) {
    foreach($user in $builtInAccounts) {
        $newName = -join ((48..57) + (97..122) | Get-Random -Count 20 | % {[char]$_})
        Rename-LocalUser "$user" "$newName"
    }
}

Write-Output "Setting user passwords and properties"

$passwordR = ConvertTo-SecureString "CyBeRpAtRiOt1#" -AsPlainText -Force
$users = Get-LocalUser

foreach ($user in $users) {
    $name = $user.Name
    net user "$name" "CyBeRpAtRiOt1#" /logonpasswordchg:yes /passwordreq:yes /passwordchg:yes /expires:2/20 /comment:"" /usecomment:""
}


Write-Output "Removing any logon scripts that users may have"

$users = Get-LocalUser

$Computer = [adsi]"WinNT://$env:COMPUTERNAME"

foreach($user in $users) {
    $name = $user.Name
    $u = $Computer.psbase.Children.Find("$name")
    $u.LoginScript = ""
    $u.setInfo()
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
# Starting search in users' home directories
Write-Host "--------------------All-home-dirs----------------------"
# Get all directories inside C:\Users
$usersDirs = Get-ChildItem -Path C:\Users -Directory

# Loop through each directory and generate a tree for it
foreach ($dir in $usersDirs) {
    Write-Host "Tree for $($dir.FullName)"
    Write-Host "-------------------------------------------------------------"
    tree $dir.FullName /F /A
    Write-Host "-------------------------------------------------------------"
    Write-Host ""
}

