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

        $resolvedPath = (Resolve-Path -LiteralPath $Path).ProviderPath

        if ($script:SharpHoundDependencyMap) {
            try {
                $assemblyIdentity = [System.Reflection.AssemblyName]::GetAssemblyName($resolvedPath).Name
                $script:SharpHoundDependencyMap[$assemblyIdentity] = $resolvedPath
            }
            catch {
                # Swallow metadata resolution failures and continue loading from disk.
            }
        }

        $loaded = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.Location -eq $resolvedPath }
        if (-not $loaded) {
            [void][System.Reflection.Assembly]::LoadFrom($resolvedPath)
        }
    }

    function Register-SharpHoundAssemblyResolver {
        param([string]$DependencyRoot)

        if (-not $script:SharpHoundDependencyMap) {
            $script:SharpHoundDependencyMap = @{}
        }
        else {
            $script:SharpHoundDependencyMap.Clear()
        }

        $dependencyDlls = Get-ChildItem -Path $DependencyRoot -Filter '*.dll' -File -ErrorAction SilentlyContinue
        foreach ($dll in $dependencyDlls) {
            try {
                $assemblyIdentity = [System.Reflection.AssemblyName]::GetAssemblyName($dll.FullName).Name
                $script:SharpHoundDependencyMap[$assemblyIdentity] = (Resolve-Path -LiteralPath $dll.FullName).ProviderPath
            }
            catch {
                continue
            }
        }

        if (-not $script:SharpHoundAssemblyResolverRegistered) {
            $handler = [System.ResolveEventHandler]{
                param($sender, $args)

                if (-not $args.Name) {
                    return $null
                }

                $requestedName = (New-Object System.Reflection.AssemblyName($args.Name)).Name
                if ($script:SharpHoundDependencyMap.ContainsKey($requestedName)) {
                    $candidatePath = $script:SharpHoundDependencyMap[$requestedName]
                    if ($candidatePath -and (Test-Path -LiteralPath $candidatePath)) {
                        return [System.Reflection.Assembly]::LoadFrom($candidatePath)
                    }
                }

                return $null
            }

            [System.AppDomain]::CurrentDomain.add_AssemblyResolve($handler)
            $script:SharpHoundAssemblyResolverRegistered = $true
            $script:SharpHoundAssemblyResolveHandler = $handler
        }
    }

    $assemblyRoot = Join-Path -Path $PSScriptRoot -ChildPath 'Dependencies'
    if (-not (Test-Path -LiteralPath $assemblyRoot)) {
        throw "Expected dependency folder '$assemblyRoot' was not found."
    }

    Register-SharpHoundAssemblyResolver -DependencyRoot $assemblyRoot

    Load-SharpHoundDependency -Path (Join-Path $assemblyRoot 'Microsoft.Extensions.Logging.Abstractions.dll')
    Load-SharpHoundDependency -Path (Join-Path $assemblyRoot 'SharpHoundRPC.dll')
    Load-SharpHoundDependency -Path (Join-Path $assemblyRoot 'SharpHoundCommonLib.dll')
    Load-SharpHoundDependency -Path (Join-Path $assemblyRoot 'System.Memory.dll')
    Load-SharpHoundDependency -Path (Join-Path $assemblyRoot 'System.Buffers.dll')
    Load-SharpHoundDependency -Path (Join-Path $assemblyRoot 'System.Runtime.CompilerServices.Unsafe.dll')
    Load-SharpHoundDependency -Path (Join-Path $assemblyRoot 'System.Numerics.Vectors.dll')

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
