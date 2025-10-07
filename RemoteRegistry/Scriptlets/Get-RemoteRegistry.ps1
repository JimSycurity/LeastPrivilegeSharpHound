<#
.SYNOPSIS
    Gets remote registry keys with security descriptors and values.

.DESCRIPTION
    Connects to a remote computer's registry and recursively enumerates specified registry paths,
    displaying SDDL security descriptors with SID resolution, values, and subkeys in a tree format
    with color coding. Automatically resolves SIDs to domain principals using .NET methods and
    caches results for performance. Supports multiple output formats including collapsible HTML sections.

.PARAMETER ComputerName
    The name of the remote computer to connect to.

.PARAMETER RegistryPath
    One or more registry paths to enumerate. Can be a single string or an array of strings.
    Format: HIVE\Path (e.g., "HKLM\SOFTWARE\Microsoft")

.PARAMETER OutputMode
    Output format: Console, HTML, ANSI, or Both

.PARAMETER OutputFile
    Path for output file. Default: RemoteRegistry_ComputerName_YYYYMMDD_HHMMSS.html

.PARAMETER ResolveSids
    Switch to enable/disable SID resolution to domain principals. Default: $true
    When enabled, SIDs in SDDL strings are resolved to DOMAIN\Principal format using .NET.
    Resolution results are cached for performance.

.EXAMPLE
    # Single registry path with SID resolution
    .\Get-RemoteRegistry.ps1 -ComputerName "Server01" -RegistryPath "HKLM\SYSTEM\CurrentControlSet\Services\CertSvc"

.EXAMPLE
    # Multiple paths without SID resolution (faster)
    .\Get-RemoteRegistry.ps1 -ComputerName "Server01" -RegistryPath @(
        "HKLM\SYSTEM\CurrentControlSet\Services\CertSvc",
        "HKLM\SOFTWARE\Microsoft\Cryptography"
    ) -OutputMode Both -ResolveSids:$false

.EXAMPLE
    # Security audit with SID resolution and HTML report
    $paths = @(
        "HKLM\SYSTEM\CurrentControlSet\Services\Kdc",
        'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL',
        'HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration',
        "HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
        "HKLM\SOFTWARE\Policies\Microsoft\Windows"
    )
    .\Get-RemoteRegistry.ps1 -ComputerName "corp1-dc01" -RegistryPath $paths -OutputMode HTML -ResolveSids

.NOTES
    Version: 1.1.0
    Author: Jim Sykora
    Last Modified: 2025-09-022

    Requirements:
    - PowerShell 2.0 minimum (Console or HTML output modes)
    - PowerShell 7.0+ Full feature support
    - .NET Framework 2.0+ (for System.Web assembly)
    - Remote Registry Service enabled on target
    - Network connectivity and appropraite firewall rules

    Security Considerations:
    - Gathers remote registry path ACL and data in the authentication context of the account running the script.

#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ComputerName,

    [Parameter(Mandatory = $true)]
    [string[]]$RegistryPath,

    [Parameter()]
    [int]$IndentSize = 2,

    [Parameter()]
    [ValidateSet('Console', 'HTML', 'ANSI', 'Both')]
    [string]$OutputMode = 'Console',

    [Parameter()]
    [string]$OutputFile = "",

    [Parameter()]
    [switch]$ResolveSids = $true
)

# Set default output file if not specified
if (-not $OutputFile) {
    $OutputFile = "RemoteRegistry_{0}_{1}.html" -f $ComputerName, (Get-Date -Format "yyyyMMdd_HHmmss")
}

# Load required assembly for HTML encoding
Add-Type -AssemblyName System.Web

# HTML output builder
$script:HtmlContent = @()
$script:AnsiContent = @()
$script:PathSections = @()
$script:CurrentPathContent = @()
$script:CurrentPathId = ""

# SID resolution cache
$script:SidCache = @{}

# ANSI color codes
$AnsiColors = @{
    'Cyan'     = "`e[36m"
    'Yellow'   = "`e[33m"
    'Green'    = "`e[32m"
    'Red'      = "`e[31m"
    'DarkRed'  = "`e[91m"
    'DarkGray' = "`e[90m"
    'White'    = "`e[37m"
    'Gray'     = "`e[37m"
    'Reset'    = "`e[0m"
}

# HTML color mappings
$HtmlColors = @{
    'Cyan'     = '#00FFFF'
    'Yellow'   = '#FFFF00'
    'Green'    = '#00FF00'
    'Red'      = '#FF0000'
    'DarkRed'  = '#8B0000'
    'DarkGray' = '#696969'
    'White'    = '#FFFFFF'
    'Gray'     = '#808080'
}

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = 'Gray',
        [switch]$NoNewline
    )

    # Console output
    if ($OutputMode -eq 'Console' -or $OutputMode -eq 'Both') {
        $params = @{
            Object = $Message
        }
        if ($Color -and $Color -ne 'Gray') {
            $params['ForegroundColor'] = $Color
        }
        if ($NoNewline) {
            $params['NoNewline'] = $true
        }
        Write-Host @params
    }

    # HTML output - add to current path section
    if ($OutputMode -eq 'HTML' -or $OutputMode -eq 'Both') {
        $htmlColor = $HtmlColors[$Color]
        $escapedMessage = [System.Web.HttpUtility]::HtmlEncode($Message)
        $escapedMessage = $escapedMessage.Replace(' ', '&nbsp;').Replace("`t", '&nbsp;&nbsp;&nbsp;&nbsp;')
        $htmlLine = "<span style='color: $htmlColor'>$escapedMessage</span>"
        if (-not $NoNewline) {
            $htmlLine += "<br/>"
        }

        if ($script:CurrentPathId) {
            $script:CurrentPathContent += $htmlLine
        }
        else {
            $script:HtmlContent += $htmlLine
        }
    }

    # ANSI output
    if ($OutputMode -eq 'ANSI') {
        $ansiColor = $AnsiColors[$Color]
        $ansiReset = $AnsiColors['Reset']
        $script:AnsiContent += "${ansiColor}${Message}${ansiReset}"
        if (-not $NoNewline) {
            $script:AnsiContent += "`n"
        }
    }
}

function Initialize-HtmlOutput {
    if ($OutputMode -eq 'HTML' -or $OutputMode -eq 'Both') {
        $script:HtmlContent = @()
        $script:PathSections = @()
        $pathList = $RegistryPath -join ', '
        $script:HtmlContent += @"
<!DOCTYPE html>
<html>
<head>
    <title>Remote Registry Report - $ComputerName - $(Get-Date)</title>
    <meta charset="UTF-8">
    <style>
        body {
            background-color: #1e1e1e;
            color: #d4d4d4;
            font-family: 'Cascadia Code', 'Courier New', monospace;
            font-size: 14px;
            padding: 20px;
        }
        .header {
            background-color: #0c0c0c;
            border: 1px solid #464647;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
            color: #569cd6;
        }
        .header h1 {
            margin: 0;
            color: #4fc1ff;
        }
        .header-info {
            margin-top: 10px;
            color: #9cdcfe;
        }
        .collapsible {
            background-color: #2d2d30;
            color: #fff;
            cursor: pointer;
            padding: 10px 15px;
            width: 100%;
            border: 1px solid #464647;
            text-align: left;
            outline: none;
            font-size: 15px;
            transition: 0.2s;
            border-radius: 5px;
            margin-bottom: 5px;
            font-family: 'Cascadia Code', 'Courier New', monospace;
        }
        .collapsible:hover {
            background-color: #3e3e42;
        }
        .collapsible:after {
            content: '\002B';
            color: #aaa;
            font-weight: bold;
            float: right;
            margin-left: 5px;
        }
        .active:after {
            content: "\2212";
        }
        .content {
            padding: 0;
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.2s ease-out;
            background-color: #0c0c0c;
            border: 1px solid #464647;
            border-radius: 5px;
            margin-bottom: 10px;
        }
        .content-inner {
            padding: 15px;
            white-space: pre;
            overflow-x: auto;
        }
        .path-success {
            color: #4ec9b0;
        }
        .path-error {
            color: #f48771;
        }
        .summary {
            background-color: #0c0c0c;
            border: 1px solid #464647;
            border-radius: 5px;
            padding: 15px;
            margin-top: 20px;
            color: #4ec9b0;
        }
        .controls {
            margin-bottom: 15px;
            padding: 10px;
            background-color: #2d2d30;
            border-radius: 5px;
        }
        .control-button {
            background-color: #0e639c;
            border: none;
            color: white;
            padding: 8px 16px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 14px;
            margin: 4px 2px;
            cursor: pointer;
            border-radius: 3px;
            font-family: 'Cascadia Code', 'Courier New', monospace;
        }
        .control-button:hover {
            background-color: #1177bb;
        }
    </style>
    <script>
        function toggleAll(expand) {
            var collapsibles = document.getElementsByClassName("collapsible");
            for (var i = 0; i < collapsibles.length; i++) {
                var content = collapsibles[i].nextElementSibling;
                if (expand) {
                    collapsibles[i].classList.add("active");
                    content.style.maxHeight = content.scrollHeight + "px";
                } else {
                    collapsibles[i].classList.remove("active");
                    content.style.maxHeight = "0";
                }
            }
        }

        document.addEventListener('DOMContentLoaded', function() {
            var coll = document.getElementsByClassName("collapsible");
            for (var i = 0; i < coll.length; i++) {
                coll[i].addEventListener("click", function() {
                    this.classList.toggle("active");
                    var content = this.nextElementSibling;
                    if (content.style.maxHeight && content.style.maxHeight !== "0px"){
                        content.style.maxHeight = "0";
                    } else {
                        content.style.maxHeight = content.scrollHeight + "px";
                    }
                });
            }
        });
    </script>
</head>
<body>
    <div class="header">
        <h1>Remote Registry Enumeration Report</h1>
        <div class="header-info">
            <strong>Computer:</strong> $ComputerName<br/>
            <strong>Generated:</strong> $(Get-Date)<br/>
            <strong>Total Paths:</strong> $($RegistryPath.Count)<br/>
        </div>
    </div>
    <div class="controls">
        <button class="control-button" onclick="toggleAll(true)">Expand All</button>
        <button class="control-button" onclick="toggleAll(false)">Collapse All</button>
    </div>
"@
    }
}

function Start-PathSection {
    param(
        [string]$Path,
        [int]$Index,
        [int]$Total
    )

    if ($OutputMode -eq 'HTML' -or $OutputMode -eq 'Both') {
        $script:CurrentPathId = "path_$Index"
        $script:CurrentPathContent = @()
    }
}

function End-PathSection {
    param(
        [string]$Path,
        [bool]$Success = $true,
        [string]$ErrorMessage = ""
    )

    if ($OutputMode -eq 'HTML' -or $OutputMode -eq 'Both') {
        $statusClass = if ($Success) { "path-success" } else { "path-error" }
        $statusText = if ($Success) { "Y" } else { "N" }
        $errorSuffix = if (-not $Success -and $ErrorMessage) { " - $ErrorMessage" } else { "" }

        $sectionHtml = @"
<button class="collapsible"><span class="$statusClass">[$statusText]</span> $Path$errorSuffix</button>
<div class="content">
    <div class="content-inner">
$($script:CurrentPathContent -join '')
    </div>
</div>
"@
        $script:PathSections += $sectionHtml
        $script:CurrentPathId = ""
        $script:CurrentPathContent = @()
    }
}

function Finalize-HtmlOutput {
    if ($OutputMode -eq 'HTML' -or $OutputMode -eq 'Both') {
        # Add all path sections
        foreach ($section in $script:PathSections) {
            $script:HtmlContent += $section
        }

        # Build summary statistics
        $summaryStats = "Total paths processed: $($RegistryPath.Count)"
        if ($script:SidCache.Count -gt 0) {
            $resolvedCount = ($script:SidCache.GetEnumerator() | Where-Object { $_.Value -ne $_.Key }).Count
            $summaryStats += "<br/>SIDs encountered: $($script:SidCache.Count) (Resolved: $resolvedCount)"
        }

        # Add summary
        $script:HtmlContent += @"
    <div class="summary">
        <strong>Enumeration Complete</strong><br/>
        $summaryStats
    </div>
</body>
</html>
"@
        $finalHtml = $script:HtmlContent -join ''
        $finalHtml | Out-File -FilePath $OutputFile -Encoding UTF8
        Write-Host "`nHTML output saved to: $OutputFile" -ForegroundColor Green
    }

    if ($OutputMode -eq 'ANSI') {
        $ansiFile = $OutputFile -replace '\.html', '.ans'

        function Resolve-SidToName {
            param([string]$Sid)

            # Check cache first
            if ($script:SidCache.ContainsKey($Sid)) {
                return $script:SidCache[$Sid]
            }

            try {
                # Use .NET to resolve the SID
                $sidObj = New-Object System.Security.Principal.SecurityIdentifier($Sid)

                # Try to translate to NTAccount
                try {
                    $ntAccount = $sidObj.Translate([System.Security.Principal.NTAccount])
                    $resolvedName = $ntAccount.Value

                    # Cache the result
                    $script:SidCache[$Sid] = $resolvedName
                    return $resolvedName
                }
                catch {
                    # Translation failed - check if it's a well-known SID
                    # Some well-known SIDs that might not translate in certain contexts
                    $wellKnown = @{
                        'S-1-0-0'      = 'NULL SID'
                        'S-1-1-0'      = 'EVERYONE'
                        'S-1-2-0'      = 'LOCAL'
                        'S-1-2-1'      = 'CONSOLE LOGON'
                        'S-1-3-0'      = 'CREATOR OWNER'
                        'S-1-3-1'      = 'CREATOR GROUP'
                        'S-1-3-2'      = 'CREATOR OWNER SERVER'
                        'S-1-3-3'      = 'CREATOR GROUP SERVER'
                        'S-1-3-4'      = 'OWNER RIGHTS'
                        'S-1-5-1'      = 'DIALUP'
                        'S-1-5-2'      = 'NETWORK'
                        'S-1-5-3'      = 'BATCH'
                        'S-1-5-4'      = 'INTERACTIVE'
                        'S-1-5-6'      = 'SERVICE'
                        'S-1-5-7'      = 'ANONYMOUS'
                        'S-1-5-8'      = 'PROXY'
                        'S-1-5-9'      = 'ENTERPRISE DOMAIN CONTROLLERS'
                        'S-1-5-10'     = 'PRINCIPAL SELF'
                        'S-1-5-11'     = 'AUTHENTICATED USERS'
                        'S-1-5-12'     = 'RESTRICTED CODE'
                        'S-1-5-13'     = 'TERMINAL SERVER USER'
                        'S-1-5-14'     = 'REMOTE INTERACTIVE LOGON'
                        'S-1-5-15'     = 'THIS ORGANIZATION'
                        'S-1-5-17'     = 'IUSR'
                        'S-1-5-18'     = 'LOCAL SYSTEM'
                        'S-1-5-19'     = 'LOCAL SERVICE'
                        'S-1-5-20'     = 'NETWORK SERVICE'
                        'S-1-5-32-544' = 'BUILTIN\Administrators'
                        'S-1-5-32-545' = 'BUILTIN\Users'
                        'S-1-5-32-546' = 'BUILTIN\Guests'
                        'S-1-5-32-547' = 'BUILTIN\Power Users'
                        'S-1-5-32-548' = 'BUILTIN\Account Operators'
                        'S-1-5-32-549' = 'BUILTIN\Server Operators'
                        'S-1-5-32-550' = 'BUILTIN\Print Operators'
                        'S-1-5-32-551' = 'BUILTIN\Backup Operators'
                        'S-1-5-32-552' = 'BUILTIN\Replicator'
                        'S-1-5-32-554' = 'BUILTIN\Pre-Windows 2000 Compatible Access'
                        'S-1-5-32-555' = 'BUILTIN\Remote Desktop Users'
                        'S-1-5-32-556' = 'BUILTIN\Network Configuration Operators'
                        'S-1-5-32-557' = 'BUILTIN\Incoming Forest Trust Builders'
                        'S-1-5-32-558' = 'BUILTIN\Performance Monitor Users'
                        'S-1-5-32-559' = 'BUILTIN\Performance Log Users'
                        'S-1-5-32-560' = 'BUILTIN\Windows Authorization Access Group'
                        'S-1-5-32-561' = 'BUILTIN\Terminal Server License Servers'
                        'S-1-5-32-562' = 'BUILTIN\Distributed COM Users'
                        'S-1-5-32-568' = 'BUILTIN\IIS_IUSRS'
                        'S-1-5-32-569' = 'BUILTIN\Cryptographic Operators'
                        'S-1-5-32-573' = 'BUILTIN\Event Log Readers'
                        'S-1-5-32-574' = 'BUILTIN\Certificate Service DCOM Access'
                        'S-1-5-32-575' = 'BUILTIN\RDS Remote Access Servers'
                        'S-1-5-32-576' = 'BUILTIN\RDS Endpoint Servers'
                        'S-1-5-32-577' = 'BUILTIN\RDS Management Servers'
                        'S-1-5-32-578' = 'BUILTIN\Hyper-V Administrators'
                        'S-1-5-32-579' = 'BUILTIN\Access Control Assistance Operators'
                        'S-1-5-32-580' = 'BUILTIN\Remote Management Users'
                        'S-1-5-32-582' = 'BUILTIN\Storage Replica Administrators'
                    }

                    if ($wellKnown.ContainsKey($Sid)) {
                        $resolvedName = $wellKnown[$Sid]
                        $script:SidCache[$Sid] = $resolvedName
                        return $resolvedName
                    }

                    # If it's not a well-known SID and translation failed, cache the SID itself
                    $script:SidCache[$Sid] = $Sid
                    return $Sid
                }
            }
            catch {
                # If SID object creation failed, cache the SID itself
                $script:SidCache[$Sid] = $Sid
                return $Sid
            }
        }

        function Format-SddlWithNames {
            param([string]$Sddl)

            # If SID resolution is disabled, just return the SDDL
            if (-not $ResolveSids) {
                return @{
                    Sddl   = $Sddl
                    Legend = $null
                }
            }

            # Pattern to match SIDs in SDDL
            $sidPattern = 'S-1-[\d-]+'

            # Find all SIDs in the SDDL string
            $sids = [regex]::Matches($Sddl, $sidPattern) | ForEach-Object { $_.Value } | Sort-Object -Unique

            # Build a mapping of SIDs to names for this SDDL
            $sidMap = @{}
            foreach ($sid in $sids) {
                $resolvedName = Resolve-SidToName -Sid $sid
                if ($resolvedName -ne $sid) {
                    $sidMap[$sid] = $resolvedName
                }
            }

            # If we resolved any SIDs, return both SDDL and a legend
            if ($sidMap.Count -gt 0) {
                $legend = ($sidMap.GetEnumerator() | ForEach-Object {
                        "$($_.Key)=$($_.Value)"
                    }) -join '; '
                return @{
                    Sddl   = $Sddl
                    Legend = "SID Resolution: $legend"
                }
            }

            return @{
                Sddl   = $Sddl
                Legend = $null
            }
        }

        function Get-RegistryHiveFromPath {
            param([string]$Path)

            $parts = $Path -split '\\'
            $hiveName = $parts[0].ToUpper()

            $hiveMapping = @{
                'HKLM'                = [Microsoft.Win32.RegistryHive]::LocalMachine
                'HKEY_LOCAL_MACHINE'  = [Microsoft.Win32.RegistryHive]::LocalMachine
                'HKU'                 = [Microsoft.Win32.RegistryHive]::Users
                'HKEY_USERS'          = [Microsoft.Win32.RegistryHive]::Users
                'HKCR'                = [Microsoft.Win32.RegistryHive]::ClassesRoot
                'HKEY_CLASSES_ROOT'   = [Microsoft.Win32.RegistryHive]::ClassesRoot
                'HKCC'                = [Microsoft.Win32.RegistryHive]::CurrentConfig
                'HKEY_CURRENT_CONFIG' = [Microsoft.Win32.RegistryHive]::CurrentConfig
                'HKCU'                = [Microsoft.Win32.RegistryHive]::CurrentUser
                'HKEY_CURRENT_USER'   = [Microsoft.Win32.RegistryHive]::CurrentUser
            }

            if ($hiveMapping.ContainsKey($hiveName)) {
                $hive = $hiveMapping[$hiveName]
                $subKeyPath = ($parts | Select-Object -Skip 1) -join '\'
                return @{
                    Hive       = $hive
                    SubKeyPath = $subKeyPath
                }
            }
            else {
                throw "Unknown registry hive: $hiveName"
            }
        }

        function Format-RegistryValue {
            param(
                [Microsoft.Win32.RegistryKey]$Key,
                [string]$ValueName
            )

            try {
                $valueKind = $Key.GetValueKind($ValueName)
                $value = $Key.GetValue($ValueName)

                $formattedValue = switch ($valueKind) {
                    'Binary' {
                        if ($value) {
                            $hexString = ($value | ForEach-Object { $_.ToString("X2") }) -join ' '
                            "[$valueKind] $hexString"
                        }
                        else {
                            "[$valueKind] (null)"
                        }
                    }
                    'DWord' {
                        "[$valueKind] 0x{0:X8} ({0})" -f $value
                    }
                    'QWord' {
                        "[$valueKind] 0x{0:X16} ({0})" -f $value
                    }
                    'MultiString' {
                        if ($value) {
                            "[$valueKind] {0}" -f ($value -join '; ')
                        }
                        else {
                            "[$valueKind] (null)"
                        }
                    }
                    'ExpandString' {
                        "[$valueKind] $value"
                    }
                    'String' {
                        "[$valueKind] $value"
                    }
                    default {
                        "[$valueKind] $value"
                    }
                }

                return $formattedValue
            }
            catch {
                return "[Error reading value: $_]"
            }
        }

        function Process-RegistryKey {
            param(
                [Microsoft.Win32.RegistryKey]$Key,
                [string]$KeyPath,
                [int]$Depth = 0
            )

            $indent = ' ' * ($Depth * $IndentSize)
            $keyName = Split-Path -Leaf $KeyPath

            # Display key name
            if ($Depth -eq 0) {
                Write-ColorOutput "${indent}[$KeyPath]" -Color 'Cyan'
            }
            else {
                Write-ColorOutput "${indent}|- [$keyName]" -Color 'Cyan'
            }

            # Get and display SDDL with SID resolution
            try {
                $acl = $Key.GetAccessControl()
                $sddl = $acl.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All)

                # Format SDDL with SID names
                $sddlInfo = Format-SddlWithNames -Sddl $sddl

                Write-ColorOutput "${indent}|  SDDL: $($sddlInfo.Sddl)" -Color 'Yellow'

                if ($sddlInfo.Legend) {
                    Write-ColorOutput "${indent}|       $($sddlInfo.Legend)" -Color 'DarkGray'
                }
            }
            catch {
                Write-ColorOutput "${indent}|  SDDL: [Access Denied or Error: $_]" -Color 'Red'
            }

            # Get and display values
            try {
                $valueNames = $Key.GetValueNames()
                if ($valueNames.Count -gt 0) {
                    Write-ColorOutput "${indent}|  Values:" -Color 'Green'
                    foreach ($valueName in $valueNames) {
                        $displayName = if ([string]::IsNullOrEmpty($valueName)) { "(Default)" } else { $valueName }
                        $formattedValue = Format-RegistryValue -Key $Key -ValueName $valueName
                        Write-ColorOutput "${indent}|    * $displayName = $formattedValue"
                    }
                }
            }
            catch {
                Write-ColorOutput "${indent}|  Values: [Error reading values: $_]" -Color 'Red'
            }

            # Process subkeys recursively
            try {
                $subKeyNames = $Key.GetSubKeyNames()
                if ($subKeyNames.Count -gt 0) {
                    Write-ColorOutput "${indent}|" -Color 'DarkGray'
                    foreach ($subKeyName in $subKeyNames) {
                        try {
                            $subKey = $Key.OpenSubKey($subKeyName, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree)
                            if ($subKey) {
                                $subKeyPath = if ($KeyPath) { "$KeyPath\$subKeyName" } else { $subKeyName }
                                Process-RegistryKey -Key $subKey -KeyPath $subKeyPath -Depth ($Depth + 1)
                                $subKey.Close()
                            }
                            else {
                                # Key exists but couldn't be opened (likely null return)
                                Write-ColorOutput "${indent}|- [$subKeyName]" -Color 'DarkRed'
                                Write-ColorOutput "${indent}|  [Unable to open subkey]" -Color 'Red'
                            }
                        }
                        catch {
                            # Handle access denied or other errors - continue with next key
                            Write-ColorOutput "${indent}|- [$subKeyName]" -Color 'DarkRed'
                            Write-ColorOutput "${indent}|  [Error: $($_.Exception.Message)]" -Color 'Red'
                            # Continue to next subkey - non-terminating error
                            continue
                        }
                    }
                }
            }
            catch {
                Write-ColorOutput "${indent}|  [Error enumerating subkeys: $_]" -Color 'Red'
            }
        }

        # Main script execution
        try {
            # Initialize output
            Initialize-HtmlOutput

            Write-ColorOutput "Connecting to registry on computer: $ComputerName" -Color 'White'
            Write-ColorOutput "Registry paths to enumerate: $($RegistryPath.Count)" -Color 'White'
            Write-ColorOutput ("-" * 60) -Color 'DarkGray'

            $pathIndex = 0
            foreach ($path in $RegistryPath) {
                $pathIndex++

                try {
                    Write-ColorOutput "`n" -Color 'White'
                    Write-ColorOutput ("=" * 60) -Color 'Cyan'
                    Write-ColorOutput "Processing path [$pathIndex/$($RegistryPath.Count)]: $path" -Color 'Yellow'
                    Write-ColorOutput ("=" * 60) -Color 'Cyan'

                    # Start HTML section for this path
                    Start-PathSection -Path $path -Index $pathIndex -Total $RegistryPath.Count

                    # Parse the registry path
                    $pathInfo = Get-RegistryHiveFromPath -Path $path

                    # Open remote base key
                    Write-ColorOutput "Opening remote registry hive: $($pathInfo.Hive)" -Color 'Gray'
                    $remoteHive = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($pathInfo.Hive, $ComputerName)

                    if (-not $remoteHive) {
                        $errorMsg = "Failed to connect to remote registry hive: $($pathInfo.Hive)"
                        Write-ColorOutput $errorMsg -Color 'Red'
                        End-PathSection -Path $path -Success $false -ErrorMessage $errorMsg
                        continue
                    }

                    # Open the specified subkey
                    $targetKey = $null
                    if ($pathInfo.SubKeyPath) {
                        Write-ColorOutput "Opening subkey: $($pathInfo.SubKeyPath)" -Color 'Gray'
                        try {
                            $targetKey = $remoteHive.OpenSubKey($pathInfo.SubKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree)

                            if (-not $targetKey) {
                                $errorMsg = "Unable to open registry key: $($pathInfo.SubKeyPath)"
                                Write-ColorOutput "[Error: $errorMsg]" -Color 'Red'
                                Write-ColorOutput "Skipping this path..." -Color 'Yellow'
                                End-PathSection -Path $path -Success $false -ErrorMessage $errorMsg
                                $remoteHive.Close()
                                continue
                            }
                        }
                        catch {
                            $errorMsg = $_.Exception.Message
                            Write-ColorOutput "[Error: $errorMsg]" -Color 'Red'
                            Write-ColorOutput "Skipping this path..." -Color 'Yellow'
                            End-PathSection -Path $path -Success $false -ErrorMessage $errorMsg
                            $remoteHive.Close()
                            continue
                        }
                    }
                    else {
                        $targetKey = $remoteHive
                    }

                    Write-ColorOutput ("-" * 60) -Color 'DarkGray'

                    # Process the key and all subkeys recursively
                    Process-RegistryKey -Key $targetKey -KeyPath $pathInfo.SubKeyPath -Depth 0

                    # Clean up
                    if ($targetKey -and $targetKey -ne $remoteHive) {
                        $targetKey.Close()
                    }
                    $remoteHive.Close()

                    Write-ColorOutput ("-" * 60) -Color 'DarkGray'
                    Write-ColorOutput "Completed enumeration for: $path" -Color 'Green'

                    # End HTML section for this path
                    End-PathSection -Path $path -Success $true
                }
                catch {
                    $errorMsg = $_.Exception.Message
                    Write-ColorOutput "Error processing path '$path': $errorMsg" -Color 'Red'
                    End-PathSection -Path $path -Success $false -ErrorMessage $errorMsg
                    # Continue with next path
                    continue
                }
                finally {
                    # Ensure cleanup for this iteration
                    if ($targetKey -and $targetKey -ne $remoteHive) {
                        try { $targetKey.Close() } catch {}
                    }
                    if ($remoteHive) {
                        try { $remoteHive.Close() } catch {}
                    }
                }
            }

            Write-ColorOutput "`n" -Color 'White'
            Write-ColorOutput ("=" * 60) -Color 'Green'
            Write-ColorOutput "Registry enumeration completed for all paths." -Color 'Green'
            Write-ColorOutput "Total paths processed: $($RegistryPath.Count)" -Color 'Green'

            # Display SID resolution statistics
            if ($ResolveSids -and $script:SidCache.Count -gt 0) {
                $resolvedCount = ($script:SidCache.GetEnumerator() | Where-Object { $_.Value -ne $_.Key }).Count
                Write-ColorOutput "SIDs encountered: $($script:SidCache.Count) (Resolved: $resolvedCount)" -Color 'Green'
            }

            Write-ColorOutput ("=" * 60) -Color 'Green'

            # Finalize output
            Finalize-HtmlOutput
        }
        catch {
            Write-ColorOutput "Critical Error: $_" -Color 'Red'
            Write-ColorOutput $_.Exception.StackTrace -Color 'DarkRed'
            Finalize-HtmlOutput
        }
        $finalAnsi = $script:AnsiContent -join ''
        $finalAnsi | Out-File -FilePath $ansiFile -Encoding UTF8
        Write-Host "`nANSI output saved to: $ansiFile" -ForegroundColor Green
        Write-Host "View with: Get-Content '$ansiFile' -Raw" -ForegroundColor Yellow
    }
}

function Resolve-SidToName {
    param([string]$Sid)

    # Check cache first
    if ($script:SidCache.ContainsKey($Sid)) {
        return $script:SidCache[$Sid]
    }

    try {
        # Use .NET to resolve the SID
        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($Sid)
        $ntAccount = $sidObj.Translate([System.Security.Principal.NTAccount])
        $resolvedName = $ntAccount.Value

        # Cache the result
        $script:SidCache[$Sid] = $resolvedName
        return $resolvedName
    }
    catch {
        # If resolution fails, cache the SID itself to avoid repeated lookup attempts
        $script:SidCache[$Sid] = $Sid
        return $Sid
    }
}

function Format-SddlWithNames {
    param([string]$Sddl)

    # Pattern to match SIDs in SDDL
    $sidPattern = 'S-1-[\d-]+'

    # Find all SIDs in the SDDL string
    $sids = [regex]::Matches($Sddl, $sidPattern) | ForEach-Object { $_.Value } | Sort-Object -Unique

    # Build a mapping of SIDs to names for this SDDL
    $sidMap = @{}
    foreach ($sid in $sids) {
        $resolvedName = Resolve-SidToName -Sid $sid
        if ($resolvedName -ne $sid) {
            $sidMap[$sid] = $resolvedName
        }
    }

    # If we resolved any SIDs, return both SDDL and a legend
    if ($sidMap.Count -gt 0) {
        $legend = ($sidMap.GetEnumerator() | ForEach-Object {
                "$($_.Key)=$($_.Value)"
            }) -join '; '
        return @{
            Sddl   = $Sddl
            Legend = "SID Resolution: $legend"
        }
    }

    return @{
        Sddl   = $Sddl
        Legend = $null
    }
}

function Get-RegistryHiveFromPath {
    param([string]$Path)

    $parts = $Path -split '\\'
    $hiveName = $parts[0].ToUpper()

    $hiveMapping = @{
        'HKLM'                = [Microsoft.Win32.RegistryHive]::LocalMachine
        'HKEY_LOCAL_MACHINE'  = [Microsoft.Win32.RegistryHive]::LocalMachine
        'HKU'                 = [Microsoft.Win32.RegistryHive]::Users
        'HKEY_USERS'          = [Microsoft.Win32.RegistryHive]::Users
        'HKCR'                = [Microsoft.Win32.RegistryHive]::ClassesRoot
        'HKEY_CLASSES_ROOT'   = [Microsoft.Win32.RegistryHive]::ClassesRoot
        'HKCC'                = [Microsoft.Win32.RegistryHive]::CurrentConfig
        'HKEY_CURRENT_CONFIG' = [Microsoft.Win32.RegistryHive]::CurrentConfig
        'HKCU'                = [Microsoft.Win32.RegistryHive]::CurrentUser
        'HKEY_CURRENT_USER'   = [Microsoft.Win32.RegistryHive]::CurrentUser
    }

    if ($hiveMapping.ContainsKey($hiveName)) {
        $hive = $hiveMapping[$hiveName]
        $subKeyPath = ($parts | Select-Object -Skip 1) -join '\'
        return @{
            Hive       = $hive
            SubKeyPath = $subKeyPath
        }
    }
    else {
        throw "Unknown registry hive: $hiveName"
    }
}

function Format-RegistryValue {
    param(
        [Microsoft.Win32.RegistryKey]$Key,
        [string]$ValueName
    )

    try {
        $valueKind = $Key.GetValueKind($ValueName)
        $value = $Key.GetValue($ValueName)

        $formattedValue = switch ($valueKind) {
            'Binary' {
                if ($value) {
                    $hexString = ($value | ForEach-Object { $_.ToString("X2") }) -join ' '
                    "[$valueKind] $hexString"
                }
                else {
                    "[$valueKind] (null)"
                }
            }
            'DWord' {
                "[$valueKind] 0x{0:X8} ({0})" -f $value
            }
            'QWord' {
                "[$valueKind] 0x{0:X16} ({0})" -f $value
            }
            'MultiString' {
                if ($value) {
                    "[$valueKind] {0}" -f ($value -join '; ')
                }
                else {
                    "[$valueKind] (null)"
                }
            }
            'ExpandString' {
                "[$valueKind] $value"
            }
            'String' {
                "[$valueKind] $value"
            }
            default {
                "[$valueKind] $value"
            }
        }

        return $formattedValue
    }
    catch {
        return "[Error reading value: $_]"
    }
}

function Process-RegistryKey {
    param(
        [Microsoft.Win32.RegistryKey]$Key,
        [string]$KeyPath,
        [int]$Depth = 0
    )

    $indent = ' ' * ($Depth * $IndentSize)
    $keyName = Split-Path -Leaf $KeyPath

    # Display key name
    if ($Depth -eq 0) {
        Write-ColorOutput "${indent}[$KeyPath]" -Color 'Cyan'
    }
    else {
        Write-ColorOutput "${indent}|- [$keyName]" -Color 'Cyan'
    }

    # Get and display SDDL with SID resolution
    try {
        $acl = $Key.GetAccessControl()
        $sddl = $acl.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All)

        # Format SDDL with SID names
        $sddlInfo = Format-SddlWithNames -Sddl $sddl

        Write-ColorOutput "${indent}|  SDDL: $($sddlInfo.Sddl)" -Color 'Yellow'

        if ($sddlInfo.Legend) {
            Write-ColorOutput "${indent}|       $($sddlInfo.Legend)" -Color 'DarkGray'
        }
    }
    catch {
        Write-ColorOutput "${indent}|  SDDL: [Access Denied or Error: $_]" -Color 'Red'
    }

    # Get and display values
    try {
        $valueNames = $Key.GetValueNames()
        if ($valueNames.Count -gt 0) {
            Write-ColorOutput "${indent}|  Values:" -Color 'Green'
            foreach ($valueName in $valueNames) {
                $displayName = if ([string]::IsNullOrEmpty($valueName)) { "(Default)" } else { $valueName }
                $formattedValue = Format-RegistryValue -Key $Key -ValueName $valueName
                Write-ColorOutput "${indent}|    * $displayName = $formattedValue"
            }
        }
    }
    catch {
        Write-ColorOutput "${indent}|  Values: [Error reading values: $_]" -Color 'Red'
    }

    # Process subkeys recursively
    try {
        $subKeyNames = $Key.GetSubKeyNames()
        if ($subKeyNames.Count -gt 0) {
            Write-ColorOutput "${indent}|" -Color 'DarkGray'
            foreach ($subKeyName in $subKeyNames) {
                try {
                    $subKey = $Key.OpenSubKey($subKeyName, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree)
                    if ($subKey) {
                        $subKeyPath = if ($KeyPath) { "$KeyPath\$subKeyName" } else { $subKeyName }
                        Process-RegistryKey -Key $subKey -KeyPath $subKeyPath -Depth ($Depth + 1)
                        $subKey.Close()
                    }
                    else {
                        # Key exists but couldn't be opened (likely null return)
                        Write-ColorOutput "${indent}|- [$subKeyName]" -Color 'DarkRed'
                        Write-ColorOutput "${indent}|  [Unable to open subkey]" -Color 'Red'
                    }
                }
                catch {
                    # Handle access denied or other errors - continue with next key
                    Write-ColorOutput "${indent}|- [$subKeyName]" -Color 'DarkRed'
                    Write-ColorOutput "${indent}|  [Error: $($_.Exception.Message)]" -Color 'Red'
                    # Continue to next subkey - non-terminating error
                    continue
                }
            }
        }
    }
    catch {
        Write-ColorOutput "${indent}|  [Error enumerating subkeys: $_]" -Color 'Red'
    }
}

# Main script execution
try {
    # Initialize output
    Initialize-HtmlOutput

    Write-ColorOutput "Connecting to registry on computer: $ComputerName" -Color 'White'
    Write-ColorOutput "Registry paths to enumerate: $($RegistryPath.Count)" -Color 'White'
    Write-ColorOutput ("-" * 60) -Color 'DarkGray'

    $pathIndex = 0
    foreach ($path in $RegistryPath) {
        $pathIndex++

        try {
            Write-ColorOutput "`n" -Color 'White'
            Write-ColorOutput ("=" * 60) -Color 'Cyan'
            Write-ColorOutput "Processing path [$pathIndex/$($RegistryPath.Count)]: $path" -Color 'Yellow'
            Write-ColorOutput ("=" * 60) -Color 'Cyan'

            # Start HTML section for this path
            Start-PathSection -Path $path -Index $pathIndex -Total $RegistryPath.Count

            # Parse the registry path
            $pathInfo = Get-RegistryHiveFromPath -Path $path

            # Open remote base key
            Write-ColorOutput "Opening remote registry hive: $($pathInfo.Hive)" -Color 'Gray'
            $remoteHive = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($pathInfo.Hive, $ComputerName)

            if (-not $remoteHive) {
                $errorMsg = "Failed to connect to remote registry hive: $($pathInfo.Hive)"
                Write-ColorOutput $errorMsg -Color 'Red'
                End-PathSection -Path $path -Success $false -ErrorMessage $errorMsg
                continue
            }

            # Open the specified subkey
            $targetKey = $null
            if ($pathInfo.SubKeyPath) {
                Write-ColorOutput "Opening subkey: $($pathInfo.SubKeyPath)" -Color 'Gray'
                try {
                    $targetKey = $remoteHive.OpenSubKey($pathInfo.SubKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree)

                    if (-not $targetKey) {
                        $errorMsg = "Unable to open registry key: $($pathInfo.SubKeyPath)"
                        Write-ColorOutput "[Error: $errorMsg]" -Color 'Red'
                        Write-ColorOutput "Skipping this path..." -Color 'Yellow'
                        End-PathSection -Path $path -Success $false -ErrorMessage $errorMsg
                        $remoteHive.Close()
                        continue
                    }
                }
                catch {
                    $errorMsg = $_.Exception.Message
                    Write-ColorOutput "[Error: $errorMsg]" -Color 'Red'
                    Write-ColorOutput "Skipping this path..." -Color 'Yellow'
                    End-PathSection -Path $path -Success $false -ErrorMessage $errorMsg
                    $remoteHive.Close()
                    continue
                }
            }
            else {
                $targetKey = $remoteHive
            }

            Write-ColorOutput ("-" * 60) -Color 'DarkGray'

            # Process the key and all subkeys recursively
            Process-RegistryKey -Key $targetKey -KeyPath $pathInfo.SubKeyPath -Depth 0

            # Clean up
            if ($targetKey -and $targetKey -ne $remoteHive) {
                $targetKey.Close()
            }
            $remoteHive.Close()

            Write-ColorOutput ("-" * 60) -Color 'DarkGray'
            Write-ColorOutput "Completed enumeration for: $path" -Color 'Green'

            # End HTML section for this path
            End-PathSection -Path $path -Success $true
        }
        catch {
            $errorMsg = $_.Exception.Message
            Write-ColorOutput "Error processing path '$path': $errorMsg" -Color 'Red'
            End-PathSection -Path $path -Success $false -ErrorMessage $errorMsg
            # Continue with next path
            continue
        }
        finally {
            # Ensure cleanup for this iteration
            if ($targetKey -and $targetKey -ne $remoteHive) {
                try { $targetKey.Close() } catch {}
            }
            if ($remoteHive) {
                try { $remoteHive.Close() } catch {}
            }
        }
    }

    Write-ColorOutput "`n" -Color 'White'
    Write-ColorOutput ("=" * 60) -Color 'Green'
    Write-ColorOutput "Registry enumeration completed for all paths." -Color 'Green'
    Write-ColorOutput "Total paths processed: $($RegistryPath.Count)" -Color 'Green'

    # Display SID resolution statistics
    if ($script:SidCache.Count -gt 0) {
        $resolvedCount = ($script:SidCache.GetEnumerator() | Where-Object { $_.Value -ne $_.Key }).Count
        Write-ColorOutput "SIDs encountered: $($script:SidCache.Count) (Resolved: $resolvedCount)" -Color 'Green'
    }

    Write-ColorOutput ("=" * 60) -Color 'Green'

    # Finalize output
    Finalize-HtmlOutput
}
catch {
    Write-ColorOutput "Critical Error: $_" -Color 'Red'
    Write-ColorOutput $_.Exception.StackTrace -Color 'DarkRed'
    Finalize-HtmlOutput
}

