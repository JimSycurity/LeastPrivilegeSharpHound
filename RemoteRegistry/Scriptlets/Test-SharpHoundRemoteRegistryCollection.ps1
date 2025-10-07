[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [Alias('Name','CN','Computer','DNSHostName','PSComputerName')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [ValidateRange(1, 300)]
    [int]$PipeTimeoutSeconds = 5
)

begin {
    $script:HKLMHiveId = [uint32]2147483650

    $script:RegistryTargets = @(
        [ordered]@{ Name = 'StrongCertificateBindingEnforcement'; Path = 'SYSTEM\CurrentControlSet\Services\Kdc'; Category = 'DC' }
        [ordered]@{ Name = 'CertificateMappingMethods'; Path = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'; Category = 'DC' }
        [ordered]@{ Name = 'VulnerableChannelAllowList'; Path = 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Category = 'DC' }
        [ordered]@{ Name = 'ProductSuite'; Path = 'SYSTEM\CurrentControlSet\Control\ProductOptions'; Category = 'Control' }
        [ordered]@{ Name = 'DefaultSpoolDirectory'; Path = 'SYSTEM\CurrentControlSet\Control\Print\Printers'; Category = 'Control' }
        [ordered]@{ Name = 'ClientAllowedNTLMServers'; Path = 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Category = 'NTLM' }
        [ordered]@{ Name = 'NtlmMinClientSec'; Path = 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Category = 'NTLM' }
        [ordered]@{ Name = 'NtlmMinServerSec'; Path = 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Category = 'NTLM' }
        [ordered]@{ Name = 'RestrictReceivingNTLMTraffic'; Path = 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Category = 'NTLM' }
        [ordered]@{ Name = 'RestrictSendingNTLMTraffic'; Path = 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Category = 'NTLM' }
        [ordered]@{ Name = 'LMCompatibilityLevel'; Path = 'SYSTEM\CurrentControlSet\Control\Lsa'; Category = 'NTLM' }
        [ordered]@{ Name = 'UseMachineId'; Path = 'SYSTEM\CurrentControlSet\Control\Lsa'; Category = 'NTLM' }
        [ordered]@{ Name = 'EnableSecuritySignature'; Path = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Category = 'NTLM' }
        [ordered]@{ Name = 'RequireSecuritySignature'; Path = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Category = 'NTLM' }
    )

    $script:StdRegProvTypeMap = @{
        1  = 'REG_SZ'
        2  = 'REG_EXPAND_SZ'
        3  = 'REG_BINARY'
        4  = 'REG_DWORD'
        7  = 'REG_MULTI_SZ'
        11 = 'REG_QWORD'
    }

    $script:StdRegProvMethodMap = @{
        'REG_SZ'        = @{ Method = 'GetStringValue'; Property = 'sValue' }
        'REG_EXPAND_SZ' = @{ Method = 'GetExpandedStringValue'; Property = 'sValue' }
        'REG_BINARY'    = @{ Method = 'GetBinaryValue'; Property = 'uValue' }
        'REG_DWORD'     = @{ Method = 'GetDWORDValue'; Property = 'uValue' }
        'REG_MULTI_SZ'  = @{ Method = 'GetMultiStringValue'; Property = 'sValue' }
        'REG_QWORD'     = @{ Method = 'GetQWORDValue'; Property = 'uValue' }
    }

    $script:AceRegex = [regex]'\(([A|D|OA|OD|AU|AL|OU|OL]+);([A-Z]*);(GA|GR|KA|KR);([a-zA-Z0-9-]*);([a-zA-Z0-9-]*);(RU|AN|AU|BU|DU|WD|UD|LU|NU)\)'

    $script:AllowedPathTargets = @(
        @{ Label = 'AllowedPaths'; SubKey = 'SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths' }
        @{ Label = 'AllowedExactPaths'; SubKey = 'SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths' }
    )

    function Convert-RegistryValue {
        param(
            $Value,
            [string]$Kind
        )

        if ($null -eq $Value) {
            return $null
        }

        switch ($Kind) {
            'REG_BINARY' { return [System.Convert]::ToBase64String([byte[]]$Value) }
            'Binary' { return [System.Convert]::ToBase64String([byte[]]$Value) }
            'REG_MULTI_SZ' { return [string[]]$Value }
            'MultiString' { return [string[]]$Value }
            'REG_DWORD' { return [int]([uint32]$Value) }
            'DWord' { return [int]([uint32]$Value) }
            'REG_QWORD' { return [long]([uint64]$Value) }
            'QWord' { return [long]([uint64]$Value) }
            default {
                if ($Value -is [byte[]]) {
                    return [System.Convert]::ToBase64String($Value)
                }

                if ($Value -is [System.Array]) {
                    return $Value
                }

                return $Value
            }
        }
    }

    function Test-WinRegPipe {
        param(
            [Parameter(Mandatory = $true)][string]$Computer,
            [Parameter(Mandatory = $true)][int]$TimeoutSeconds
        )

        $timeoutMs = [Math]::Max(1, $TimeoutSeconds) * 1000
        $result = [ordered]@{
            Accessible = $false
            Error = $null
        }

        $pipe = $null
        try {
            $pipe = New-Object System.IO.Pipes.NamedPipeClientStream($Computer, 'winreg', [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::None, [System.Security.Principal.TokenImpersonationLevel]::Impersonation)
            $pipe.Connect($timeoutMs)
            $result.Accessible = $true
        }
        catch {
            $result.Error = $_.Exception.Message
        }
        finally {
            if ($pipe) {
                try { $pipe.Dispose() } catch { }
            }
        }

        return [PSCustomObject]$result
    }

    function Open-RemoteHive {
        param([string]$Computer)

        $outcome = [ordered]@{
            Hive = $null
            Error = $null
        }

        try {
            $outcome.Hive = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $Computer)
        }
        catch {
            $outcome.Error = $_.Exception.Message
        }

        return $outcome
    }

    function Get-StdRegProv {
        param([string]$Computer)

        $outcome = [ordered]@{
            Provider = $null
            Error = $null
        }

        try {
            $outcome.Provider = Get-WmiObject -List -Namespace root\default -ComputerName $Computer -ErrorAction Stop | Where-Object { $_.Name -eq 'StdRegProv' }
        }
        catch {
            $outcome.Error = $_.Exception.Message
        }

        return $outcome
    }

    function Get-RegistryValueWinReg {
        param(
            [Microsoft.Win32.RegistryKey]$Hive,
            [string]$SubKey,
            [string]$ValueName
        )

        $result = [ordered]@{
            Success = $false
            Value = $null
            ValueKind = $null
            Error = $null
        }

        if (-not $Hive) {
            $result.Error = 'Remote registry hive unavailable'
            return [PSCustomObject]$result
        }

        $key = $null
        try {
            $key = $Hive.OpenSubKey($SubKey, [System.Security.AccessControl.RegistryRights]::ReadKey)
            if (-not $key) {
                $result.Error = 'Unable to open registry key'
                return [PSCustomObject]$result
            }

            $kind = $null
            try {
                $kind = $key.GetValueKind($ValueName)
                if ($kind) {
                    $result.ValueKind = $kind.ToString()
                }
            }
            catch {
                # Value kind unavailable (value might not exist or access denied)
            }

            $value = $key.GetValue($ValueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if ($null -eq $value -and -not $result.ValueKind) {
                $result.Error = 'Value not found'
                return [PSCustomObject]$result
            }

            if (-not $result.ValueKind) {
                if ($value -is [byte[]]) {
                    $result.ValueKind = 'Binary'
                }
                elseif ($value -is [System.Array]) {
                    $result.ValueKind = 'MultiString'
                }
            }

            $result.Value = Convert-RegistryValue -Value $value -Kind $result.ValueKind
            $result.Success = $true
        }
        catch {
            $result.Error = $_.Exception.Message
        }
        finally {
            if ($key) {
                try { $key.Close() } catch { }
            }
        }

        return [PSCustomObject]$result
    }

    function Get-RegistryValueWmi {
        param(
            $Provider,
            [uint32]$HiveId,
            [string]$SubKey,
            [string]$ValueName
        )

        $result = [ordered]@{
            Success = $false
            Value = $null
            ValueKind = $null
            Error = $null
        }

        if (-not $Provider) {
            $result.Error = 'StdRegProv unavailable'
            return [PSCustomObject]$result
        }

        $candidateKinds = @()

        try {
            $enumResult = $Provider.EnumValues($HiveId, $SubKey)
            if ($enumResult.ReturnValue -eq 0 -and $enumResult.sNames) {
                $index = [Array]::IndexOf($enumResult.sNames, $ValueName)
                if ($index -ge 0 -and $enumResult.Types) {
                    $typeId = $enumResult.Types[$index]
                    if ($script:StdRegProvTypeMap.ContainsKey($typeId)) {
                        $candidateKinds += $script:StdRegProvTypeMap[$typeId]
                    }
                }
            }
        }
        catch {
            # EnumValues might fail due to permissions; fall back to brute force
        }

        if (-not $candidateKinds) {
            $candidateKinds = $script:StdRegProvMethodMap.Keys
        }

        foreach ($kind in $candidateKinds) {
            $methodInfo = $script:StdRegProvMethodMap[$kind]
            if (-not $methodInfo) { continue }

            try {
                $methodResult = $Provider.InvokeMethod($methodInfo.Method, @($HiveId, $SubKey, $ValueName))
                if ($null -eq $methodResult) {
                    continue
                }

                $returnCode = $methodResult.ReturnValue
                if ($null -eq $returnCode -and $methodResult.PSBase.Properties['ReturnValue']) {
                    $returnCode = $methodResult.PSBase.Properties['ReturnValue'].Value
                }

                if ($returnCode -ne 0) {
                    continue
                }

                $rawValue = $methodResult."$($methodInfo.Property)"
                $result.ValueKind = $kind
                $result.Value = Convert-RegistryValue -Value $rawValue -Kind $kind
                $result.Success = $true
                $result.Error = $null
                break
            }
            catch {
                $result.Error = $_.Exception.Message
            }
        }

        if (-not $result.Success -and -not $result.Error) {
            $result.Error = 'StdRegProv returned non-zero status'
        }

        return [PSCustomObject]$result
    }

    function Get-KeySecurityInfo {
        param(
            [Microsoft.Win32.RegistryKey]$Hive,
            [string]$SubKey
        )

        $result = [ordered]@{
            Success = $false
            Sddl = $null
            FlaggedAces = @()
            Error = $null
        }

        if (-not $Hive) {
            $result.Error = 'Remote registry hive unavailable'
            return [PSCustomObject]$result
        }

        $key = $null
        try {
            $key = $Hive.OpenSubKey($SubKey, [System.Security.AccessControl.RegistryRights]::ReadPermissions)
            if (-not $key) {
                $result.Error = 'Unable to open registry key for security'
                return [PSCustomObject]$result
            }

            $sd = $key.GetAccessControl()
            $sddl = $sd.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All)
            $result.Sddl = $sddl
            $result.Success = $true

            $matches = $script:AceRegex.Matches($sddl)
            if ($matches.Count -gt 0) {
                $result.FlaggedAces = $matches.Value
            }
        }
        catch {
            $result.Error = $_.Exception.Message
        }
        finally {
            if ($key) {
                try { $key.Close() } catch { }
            }
        }

        return [PSCustomObject]$result
    }

    function Get-AllowedPathInfo {
        param(
            [Microsoft.Win32.RegistryKey]$Hive,
            [string]$PathLabel,
            [string]$SubKey
        )

        $result = [ordered]@{
            PathType = $PathLabel
            Success = $false
            Values = @()
            Error = $null
        }

        if (-not $Hive) {
            $result.Error = 'Remote registry hive unavailable'
            return [PSCustomObject]$result
        }

        $key = $null
        try {
            $key = $Hive.OpenSubKey($SubKey, [System.Security.AccessControl.RegistryRights]::ReadKey)
            if (-not $key) {
                $result.Error = 'Unable to open registry key'
                return [PSCustomObject]$result
            }

            $machineValue = $key.GetValue('Machine', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if ($null -eq $machineValue) {
                $result.Values = @()
            }
            elseif ($machineValue -is [System.Array]) {
                $result.Values = $machineValue
            }
            else {
                $result.Values = ,$machineValue
            }

            $result.Success = $true
        }
        catch {
            $result.Error = $_.Exception.Message
        }
        finally {
            if ($key) {
                try { $key.Close() } catch { }
            }
        }

        return [PSCustomObject]$result
    }

    function Select-FinalValue {
        param(
            [PSCustomObject]$WinRegResult,
            [PSCustomObject]$WmiResult,
            [ValidateSet('PreferWinReg','PreferWmi')][string]$Preference
        )

        $final = [ordered]@{
            Source = $null
            Value = $null
            ValueKind = $null
        }

        $order = if ($Preference -eq 'PreferWmi') { @('Wmi', 'WinReg') } else { @('WinReg', 'Wmi') }

        foreach ($candidate in $order) {
            switch ($candidate) {
                'WinReg' {
                    if ($WinRegResult -and $WinRegResult.Success) {
                        $final.Source = 'WinReg'
                        $final.Value = $WinRegResult.Value
                        $final.ValueKind = $WinRegResult.ValueKind
                        return [PSCustomObject]$final
                    }
                }
                'Wmi' {
                    if ($WmiResult -and $WmiResult.Success) {
                        $final.Source = 'Wmi'
                        $final.Value = $WmiResult.Value
                        $final.ValueKind = $WmiResult.ValueKind
                        return [PSCustomObject]$final
                    }
                }
            }
        }

        return [PSCustomObject]$final
    }

    function Get-CertSvcPerCA {
        param(
            [Microsoft.Win32.RegistryKey]$Hive,
            $Provider,
            [string]$CaName
        )

        $baseKey = "SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CaName"
        $policyKey = "$baseKey\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy"

        $valuesToFetch = @(
            @{ Name = 'Security'; Path = $baseKey; Preference = 'PreferWinReg'; Purpose = 'Binary security descriptor' }
            @{ Name = 'EnrollmentAgentRights'; Path = $baseKey; Preference = 'PreferWinReg'; Purpose = 'Enrollment agent rights' }
            @{ Name = 'RoleSeparationEnabled'; Path = $baseKey; Preference = 'PreferWinReg'; Purpose = 'Role separation flag' }
            @{ Name = 'EditFlags'; Path = $policyKey; Preference = 'PreferWinReg'; Purpose = 'Policy module edit flags' }
        )

        $entry = [ordered]@{
            CAName = $CaName
            Values = @()
        }

        foreach ($target in $valuesToFetch) {
            $winRegResult = Get-RegistryValueWinReg -Hive $Hive -SubKey $target.Path -ValueName $target.Name
            $wmiResult = $null

            if (-not $winRegResult.Success) {
                $wmiResult = Get-RegistryValueWmi -Provider $Provider -HiveId $script:HKLMHiveId -SubKey $target.Path -ValueName $target.Name
            }
            elseif ($target.Preference -eq 'PreferWmi') {
                $wmiResult = Get-RegistryValueWmi -Provider $Provider -HiveId $script:HKLMHiveId -SubKey $target.Path -ValueName $target.Name
            }

            $final = Select-FinalValue -WinRegResult $winRegResult -WmiResult $wmiResult -Preference $target.Preference

            $record = [ordered]@{
                Name = $target.Name
                Path = $target.Path
                Purpose = $target.Purpose
                WinReg = $winRegResult
                Wmi = $wmiResult
                Final = $final
            }

            if ($target.Name -eq 'RoleSeparationEnabled' -and $final.Source) {
                try {
                    $record.RoleSeparationEnabled = [bool]([int64]$final.Value)
                }
                catch { }
            }

            if ($target.Name -eq 'EditFlags' -and $final.Source) {
                try {
                    $flags = [int64]$final.Value
                    $record.UserSpecifiedSanEnabled = (($flags -band 0x00040000) -eq 0x00040000)
                }
                catch { }
            }

            $entry.Values += [PSCustomObject]$record
        }

        return [PSCustomObject]$entry
    }

    function Get-CertSvcDetails {
        param(
            [Microsoft.Win32.RegistryKey]$Hive,
            $Provider
        )

        $basePath = 'SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'

        $result = [ordered]@{
            RemoteAccessible = $false
            RemoteError = $null
            CANames = @()
            Entries = @()
        }

        $configKey = $null
        try {
            if ($Hive) {
                $configKey = $Hive.OpenSubKey($basePath, [System.Security.AccessControl.RegistryRights]::ReadKey)
                if ($configKey) {
                    $result.RemoteAccessible = $true
                    $result.CANames = $configKey.GetSubKeyNames()
                }
                else {
                    $result.RemoteError = 'Unable to open configuration key via RemoteRegistry'
                }
            }
            else {
                $result.RemoteError = 'Remote registry hive unavailable'
            }
        }
        catch {
            $result.RemoteError = $_.Exception.Message
        }
        finally {
            if ($configKey) {
                try { $configKey.Close() } catch { }
            }
        }

        if (-not $result.RemoteAccessible -and $Provider) {
            try {
                $enumKey = $Provider.EnumKey($script:HKLMHiveId, $basePath)
                if ($enumKey.ReturnValue -eq 0 -and $enumKey.sNames) {
                    $result.CANames = $enumKey.sNames
                }
            }
            catch {
                if (-not $result.RemoteError) {
                    $result.RemoteError = $_.Exception.Message
                }
            }
        }

        foreach ($caName in $result.CANames) {
            $entry = Get-CertSvcPerCA -Hive $Hive -Provider $Provider -CaName $caName
            $result.Entries += $entry
        }

        return [PSCustomObject]$result
    }
}

process {
    foreach ($computer in $ComputerName) {
        Write-Verbose "Processing $computer"

        $pipeStatus = Test-WinRegPipe -Computer $computer -TimeoutSeconds $PipeTimeoutSeconds
        $remote = Open-RemoteHive -Computer $computer
        $stdProv = Get-StdRegProv -Computer $computer

        $result = [ordered]@{
            ComputerName = $computer
            Timestamp = Get-Date
            PipeStatus = $pipeStatus
            RemoteRegistry = [PSCustomObject]@{
                Connected = [bool]$remote.Hive
                Error = $remote.Error
            }
            WmiStatus = [PSCustomObject]@{
                Connected = [bool]$stdProv.Provider
                Error = $stdProv.Error
            }
            SecurePipeServer = Get-KeySecurityInfo -Hive $remote.Hive -SubKey 'SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg'
            AllowedPaths = @()
            RegistryValues = [ordered]@{
                DC = @()
                Control = @()
                NTLM = @()
                Other = @()
            }
            CertSvc = Get-CertSvcDetails -Hive $remote.Hive -Provider $stdProv.Provider
        }

        foreach ($target in $script:AllowedPathTargets) {
            $result.AllowedPaths += Get-AllowedPathInfo -Hive $remote.Hive -PathLabel $target.Label -SubKey $target.SubKey
        }

        foreach ($target in $script:RegistryTargets) {
            $winRegResult = Get-RegistryValueWinReg -Hive $remote.Hive -SubKey $target.Path -ValueName $target.Name
            $wmiResult = $null
            $preference = 'PreferWinReg'

            if ($target.Category -eq 'NTLM') {
                $wmiResult = Get-RegistryValueWmi -Provider $stdProv.Provider -HiveId $script:HKLMHiveId -SubKey $target.Path -ValueName $target.Name
                $preference = 'PreferWmi'
            }
            elseif (-not $winRegResult.Success) {
                $wmiResult = Get-RegistryValueWmi -Provider $stdProv.Provider -HiveId $script:HKLMHiveId -SubKey $target.Path -ValueName $target.Name
            }

            $final = Select-FinalValue -WinRegResult $winRegResult -WmiResult $wmiResult -Preference $preference

            $record = [ordered]@{
                Name = $target.Name
                Path = $target.Path
                Category = $target.Category
                WinReg = $winRegResult
                Wmi = $wmiResult
                Final = $final
            }

            switch ($target.Category) {
                'DC' { $result.RegistryValues.DC += [PSCustomObject]$record }
                'Control' { $result.RegistryValues.Control += [PSCustomObject]$record }
                'NTLM' { $result.RegistryValues.NTLM += [PSCustomObject]$record }
                default { $result.RegistryValues.Other += [PSCustomObject]$record }
            }
        }

        Write-Output ([PSCustomObject]$result)

        if ($remote.Hive) {
            try { $remote.Hive.Close() } catch { }
        }
    }
}
