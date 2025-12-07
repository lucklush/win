$folders = Get-ChildItem -Path "C:\Users" -Directory

foreach($folder in $folders) {

    # Skip Public
    if ($folder.Name -eq "Public") {
        continue
    }

    $name = $folder.Name
    ((net.exe user "$name") 2>&1) > err.txt
    $err = Get-Content .\err.txt

    # Correct error message
    if ($err -contains "The user name could not be found.") {
        Write-Output "Deleting Directory: C:\Users\$name"
        Remove-Item -Path "C:\Users\$name" -Recurse -Force
    }
}

Remove-Item .\err.txt
