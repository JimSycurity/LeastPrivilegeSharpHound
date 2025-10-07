[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [Alias('Name','Host','DNSHostName')]
    [ValidateNotNullOrEmpty()]
    [string[]]$ComputerName,

    [Parameter(Position = 1)]
    [ValidateRange(1000, 60000)]
    [int]$TimeoutMilliseconds = 5000
)

begin {
    function Load-SharpHoundDependency {
        param([string]$Path)
        if (-not (Test-Path -LiteralPath $Path)) {
            throw "Dependency not found: $Path"
        }

        $loaded = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.Location -eq $Path }
        if (-not $loaded) {
            [void][System.Reflection.Assembly]::LoadFrom($Path)
        }
    }

    $assemblyRoot = Join-Path -Path $PSScriptRoot -ChildPath 'Dependencies'
    if (-not (Test-Path -LiteralPath $assemblyRoot)) {
        throw "Expected dependency folder '$assemblyRoot' was not found."
    }

    Load-SharpHoundDependency -Path (Join-Path $assemblyRoot 'Microsoft.Extensions.Logging.Abstractions.dll')
    Load-SharpHoundDependency -Path (Join-Path $assemblyRoot 'SharpHoundRPC.dll')
    Load-SharpHoundDependency -Path (Join-Path $assemblyRoot 'SharpHoundCommonLib.dll')

    $ntlmUnsupportedCode = '80090302'
    $badBindingsCode = '80090346'

    function New-ResultObject {
        param(
            [string]$Computer,
            [string]$ErrorMessage = $null
        )

        [PSCustomObject][ordered]@{
            ComputerName             = $Computer
            HasLdap                  = $null
            HasLdaps                 = $null
            SigningRequired          = $null
            SigningCollected         = $false
            SigningFailureReason     = $null
            ChannelBindingDisabled   = $null
            ChannelBindingCollected  = $false
            ChannelBindingFailure    = $null
            EPAEnforced              = $null
            NtlmDisabled             = $null
            ChannelBindingEnforced   = $null
            Error                    = $ErrorMessage
        }
    }
}

process {
    foreach ($target in $ComputerName) {
        if ([string]::IsNullOrWhiteSpace($target)) {
            continue
        }

        $result = New-ResultObject -Computer $target

        try {
            $processor = [SharpHoundCommonLib.Processors.DCLdapProcessor]::new($TimeoutMilliseconds, $target)
            $scan = $processor.Scan($target)
            $service = $scan.GetAwaiter().GetResult()

            $result.HasLdap = $service.HasLdap
            $result.HasLdaps = $service.HasLdaps

            $signing = $service.IsSigningRequired
            if ($null -ne $signing) {
                $result.SigningCollected = $signing.Collected
                $result.SigningFailureReason = $signing.FailureReason
                if ($signing.Collected) {
                    $result.SigningRequired = $signing.Result
                } elseif ($signing.FailureReason -and $signing.FailureReason -match $ntlmUnsupportedCode) {
                    $result.NtlmDisabled = $true
                }
            }

            $channel = $service.IsChannelBindingDisabled
            if ($null -ne $channel) {
                $result.ChannelBindingCollected = $channel.Collected
                $result.ChannelBindingFailure = $channel.FailureReason
                if ($channel.Collected) {
                    $result.ChannelBindingDisabled = $channel.Result
                    if ($service.HasLdaps) {
                        $result.EPAEnforced = -not $channel.Result
                        $result.ChannelBindingEnforced = -not $channel.Result
                    }
                } elseif ($channel.FailureReason -and $channel.FailureReason -match $badBindingsCode) {
                    $result.ChannelBindingEnforced = $true
                    $result.EPAEnforced = $true
                }
            }
        }
        catch {
            $result.Error = $_.Exception.Message
        }

        $result
    }
}
