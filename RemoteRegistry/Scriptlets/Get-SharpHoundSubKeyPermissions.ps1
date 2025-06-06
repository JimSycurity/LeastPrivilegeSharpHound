
#$FlaggedRights = 'GA|GR|KA|KR'
#$FlaggedTrustees = 'RU|AN|AU|BU|DU|WD|UD|LU|NU'
$SDDLRegex = '\(([A|D|OA|OD|AU|AL|OU|OL]+);([A-Z]*);(GA|GR|KA|KR);([a-zA-Z-0-9-]*);([a-zA-Z0-9-]*);(RU|AN|AU|BU|DU|WD|UD|LU|NU)\)'
$AllPaths = @{}
$WriteOutput = $False
$AllACEs = $False

$InitialPaths = @(
    # SharpHound
    'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc',
    'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL',
    'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa',
    'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0',
    'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
)

foreach ($path in $InitialPaths) {
    $AllPaths[$path] = $null
    foreach ($subpath in (Get-ChildItem -Path "Registry::$($path)" -Recurse).Name) {
        $AllPaths[$subpath] = $null
    }
}

$values = @($AllPaths.Keys)

foreach ($value in $values) {
    $RegSD = $null
    $RegSDDL = $null
    $state = $null
    $MatchedACEs = $null
    $ParsedACEs = $null

    #Write-Host "`r`n-----------------------------------"

    try {
        $RegSD = Get-Acl -Path "Registry::$($value)"
        $RegSDDL = $RegSD.Sddl
    }
    catch {
        $state = 'ReadControl Error'
    }
    $MatchedACEs = Select-String -InputObject $RegSDDL -Pattern $SDDLRegex -AllMatches
    if ($MatchedACEs) {
        $ParsedACEs = $MatchedACEs.Matches.Value -join ''
        $AllPaths[$value] = $ParsedACEs
        if ($WriteOutput) {
            Write-Host "Path: $value - Standard User SubKey ACEs: $ParsedACEs"
        }
        if ($AllACEs) {
            Write-Host "Full SDDL: $RegSDDL"
        }
    }
    elseif ($state) {
        if ($WriteOutput) {
            Write-Host "Path: $value - $state" -ForegroundColor Red
        }
    }
    else {
        $AllPaths[$value] = 'No Unprivileged Access'
        if ($WriteOutput) {
            Write-Host "Path: $value - Standard Users have no access" -ForegroundColor DarkYellow
        }
    }
    #Write-Host "-----------------------------------"
}

$SortedData = $AllPaths.GetEnumerator() | Sort-Object -Property Value -Descending

$SortedData | Format-Table -AutoSize