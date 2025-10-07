<#
.SYNOPSIS
    Test AD CS enrollment endpoints for HTTP/HTTPS availability and EPA status.
.DESCRIPTION
    Probes a remote certification authority enrollment server for the legacy Web Enrollment
    application and optional Certificate Enrollment Service endpoints. The test mirrors the
    logic from SharpHoundCommon's CAEnrollmentProcessor by issuing an NTLM negotiate message
    to the target URLs and evaluating the responses for NTLM support and HTTPS channel
    binding (Extended Protection for Authentication).
.PARAMETER ComputerName
    DNS name or IP address of the enrollment server to probe.
.PARAMETER CACommonName
    Optional common name of the certification authority. Required to test the CES endpoint
    (<CAName>_CES_Kerberos/service.svc).
.PARAMETER TimeoutSeconds
    Maximum time in seconds to wait for each HTTP request. Defaults to 10 seconds.
.PARAMETER SkipWebEnrollment
    Skip probing the legacy certsrv Web Enrollment application endpoint.
.PARAMETER SkipEnrollmentWebService
    Skip probing the Certificate Enrollment Service endpoint.
.PARAMETER IncludeRawChallenges
    Include raw NTLM challenge data (Type 2 message) in the output for troubleshooting.
.EXAMPLE
    .\Get-CertEnrollmentTest.ps1 -ComputerName 'corp-ca1'
.EXAMPLE
    .\Get-CertEnrollmentTest.ps1 -ComputerName 'corp-ca1' -CACommonName 'CORP-CA' -Verbose
.NOTES
    Inspired by SharpHoundCommon's CAEnrollmentProcessor.cs implementation.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ComputerName,

    [string]$CACommonName,

    [ValidateRange(1, 120)]
    [int]$TimeoutSeconds = 10,

    [switch]$SkipWebEnrollment,

    [switch]$SkipEnrollmentWebService,

    [switch]$IncludeRawChallenges
)

# Normalise the computer name to avoid accidental whitespace issues.
$ComputerName = $ComputerName.Trim()

# Align TLS behavior with the SharpHound implementation by enabling older protocol fallbacks.
$desiredProtocols = @(
    [System.Net.SecurityProtocolType]::Tls12,
    [System.Net.SecurityProtocolType]::Tls11,
    [System.Net.SecurityProtocolType]::Tls
)

if ([System.Enum]::IsDefined([System.Net.SecurityProtocolType], 'Ssl3')) {
    $desiredProtocols += [System.Net.SecurityProtocolType]::Ssl3
}

foreach ($protocol in $desiredProtocols) {
    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor $protocol
    } catch {
        Write-Verbose "Security protocol $protocol not supported on this platform: $($_.Exception.Message)"
    }
}

# Pre-built NTLM Type 1 negotiate message requesting target info (channel binding hints).
$Script:NtlmType1Message = 'TlRMTVNTUAABAAAAt4KI4AAAAAAAAAAAAAAAAAAAAAA='

function Get-NtlmChannelBindingInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Type2MessageBase64
    )

    $result = [ordered]@{
        TargetInfoPresent        = $false
        ChannelBindingAvPresent  = $false
        ParseError               = $null
    }

    try {
        $bytes = [Convert]::FromBase64String($Type2MessageBase64)
    } catch {
        $result.ParseError = "Invalid base64 NTLM challenge: $($_.Exception.Message)"
        return [PSCustomObject]$result
    }

    if ($bytes.Length -lt 32) {
        $result.ParseError = "Type 2 message too short ($($bytes.Length) bytes)"
        return [PSCustomObject]$result
    }

    if ([System.Text.Encoding]::ASCII.GetString($bytes, 0, 7) -ne 'NTLMSSP') {
        $result.ParseError = 'Missing NTLMSSP signature in Type 2 message'
        return [PSCustomObject]$result
    }

    $messageType = [BitConverter]::ToUInt32($bytes, 8)
    if ($messageType -ne 2) {
        $result.ParseError = "Unexpected NTLM message type $messageType (expected 2)"
        return [PSCustomObject]$result
    }

    if ($bytes.Length -lt 48) {
        $result.ParseError = 'Type 2 message missing target info descriptor'
        return [PSCustomObject]$result
    }

    $flags = [BitConverter]::ToUInt32($bytes, 20)
    $result.TargetInfoPresent = (($flags -band 0x00800000) -ne 0)

    if (-not $result.TargetInfoPresent) {
        return [PSCustomObject]$result
    }

    $targetInfoLength = [BitConverter]::ToUInt16($bytes, 40)
    $targetInfoOffset = [BitConverter]::ToUInt32($bytes, 44)

    if ($targetInfoLength -eq 0) {
        return [PSCustomObject]$result
    }

    if (($targetInfoOffset + $targetInfoLength) -gt $bytes.Length) {
        $result.ParseError = 'Target info buffer extends beyond Type 2 message length'
        return [PSCustomObject]$result
    }

    $targetInfo = New-Object byte[] $targetInfoLength
    [System.Array]::Copy($bytes, $targetInfoOffset, $targetInfo, 0, $targetInfoLength)

    $index = 0
    while ($index -le $targetInfo.Length - 4) {
        $avId = [BitConverter]::ToUInt16($targetInfo, $index)
        $avLen = [BitConverter]::ToUInt16($targetInfo, $index + 2)
        $index += 4

        if ($avId -eq 0) {
            break
        }

        if (($index + $avLen) -gt $targetInfo.Length) {
            $result.ParseError = 'AV pair declared length exceeds target info buffer'
            break
        }

        if ($avId -eq 10) {
            $result.ChannelBindingAvPresent = ($avLen -gt 0)
            break
        }

        $index += $avLen
    }

    return [PSCustomObject]$result
}

function Invoke-NtlmProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [uri]$Uri,

        [Parameter(Mandatory = $true)]
        [string]$Type1MessageBase64,

        [ValidateRange(1, 120)]
        [int]$TimeoutSeconds = 10
    )

    $result = [ordered]@{
        Uri                 = $Uri
        Protocol            = $Uri.Scheme
        Responded           = $false
        StatusCode          = $null
        ReasonPhrase        = $null
        NtlmSupported       = $false
        Type2Base64         = $null
        ChannelBindingInfo  = $null
        Error               = $null
        ExceptionType       = $null
        FailureCategory     = $null
    }

    $handler = [System.Net.Http.HttpClientHandler]::new()
    try {
        $handler.AllowAutoRedirect = $false
        $handler.UseCookies = $false
        $handler.PreAuthenticate = $false

        if ($Uri.Scheme -eq 'https') {
            $handler.ServerCertificateCustomValidationCallback = { $true }
        }

        $client = [System.Net.Http.HttpClient]::new($handler)
        try {
            $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
            $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $Uri)
            try {
                $request.Headers.Add('Authorization', "NTLM $Type1MessageBase64")
                $request.Headers.ConnectionClose = $true

                $response = $client.SendAsync($request).GetAwaiter().GetResult()
                try {
                    $result.Responded = $true
                    $result.StatusCode = [int]$response.StatusCode
                    $result.ReasonPhrase = $response.ReasonPhrase

                    if ($response.Headers.WwwAuthenticate) {
                        foreach ($authHeader in $response.Headers.WwwAuthenticate) {
                            if ($authHeader.Scheme -eq 'NTLM') {
                                $result.NtlmSupported = $true
                                if ($authHeader.Parameter -and $authHeader.Parameter.Trim().Length -gt 0) {
                                    $result.Type2Base64 = $authHeader.Parameter.Trim()
                                    $result.ChannelBindingInfo = Get-NtlmChannelBindingInfo -Type2MessageBase64 $result.Type2Base64
                                }
                            }
                        }
                    }
                } finally {
                    $response.Dispose()
                }
            } finally {
                $request.Dispose()
            }
        } finally {
            $client.Dispose()
        }
    } catch [System.Threading.Tasks.TaskCanceledException] {
        $result.Error = "Request timed out after $TimeoutSeconds second(s)"
        $result.ExceptionType = $_.Exception.GetType().FullName
        $result.FailureCategory = 'Timeout'
    } catch [System.Net.Http.HttpRequestException] {
        $message = $_.Exception.Message
        $result.ExceptionType = $_.Exception.GetType().FullName
        if ($_.Exception.InnerException) {
            $inner = $_.Exception.InnerException
            $message = "$message ($($inner.Message))"
            $result.ExceptionType = $inner.GetType().FullName

            if ($inner -is [System.Net.Sockets.SocketException]) {
                switch ($inner.SocketErrorCode) {
                    'ConnectionRefused' { $result.FailureCategory = 'PortInaccessible' }
                    'HostNotFound' { $result.FailureCategory = 'NameResolutionFailure' }
                    'NoData' { $result.FailureCategory = 'NameResolutionFailure' }
                    'TryAgain' { $result.FailureCategory = 'NameResolutionFailure' }
                    'TimedOut' { $result.FailureCategory = 'Timeout' }
                    default { $result.FailureCategory = 'SocketError' }
                }
            }
        }

        if (-not $result.FailureCategory) {
            $result.FailureCategory = 'HttpRequestException'
        }

        $result.Error = $message
    } catch {
        $result.Error = $_.Exception.Message
        $result.ExceptionType = $_.Exception.GetType().FullName
        $result.FailureCategory = 'UnhandledException'
    } finally {
        $handler.Dispose()
    }

    return [PSCustomObject]$result
}

function Get-HttpEndpointStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ProbeResult
    )

    $status = 'Failure_Unknown'
    $tagHttp = $false

    if (-not $ProbeResult.Responded) {
        switch ($ProbeResult.FailureCategory) {
            'PortInaccessible' { $status = 'NotVulnerable_PortInaccessible' }
            'Timeout' { $status = 'Failure_Timeout' }
            'NameResolutionFailure' { $status = 'Failure_NameResolutionFailure' }
            default { $status = 'Failure_RequestException' }
        }
    } else {
        switch ($ProbeResult.StatusCode) {
            200 { $status = 'Vulnerable_NtlmHttpEndpoint'; $tagHttp = $true }
            401 {
                if ($ProbeResult.NtlmSupported -and $ProbeResult.Type2Base64) {
                    $status = 'Vulnerable_NtlmHttpEndpoint'
                    $tagHttp = $true
                } elseif ($ProbeResult.NtlmSupported) {
                    $status = 'Failure_MissingChallenge'
                } else {
                    $status = 'NotVulnerable_NoNtlmChallenge'
                }
            }
            302 {
                if ($ProbeResult.NtlmSupported -and $ProbeResult.Type2Base64) {
                    $status = 'Vulnerable_NtlmHttpEndpoint'
                    $tagHttp = $true
                } elseif ($ProbeResult.NtlmSupported) {
                    $status = 'Failure_MissingChallenge'
                } else {
                    $status = 'Failure_UnexpectedStatus'
                }
            }
            403 { $status = 'NotVulnerable_PathForbidden' }
            404 { $status = 'NotVulnerable_PathNotFound' }
            500 {
                if ($ProbeResult.NtlmSupported -and $ProbeResult.Type2Base64) {
                    $status = 'Vulnerable_NtlmHttpEndpoint'
                    $tagHttp = $true
                } else {
                    $status = 'Failure_ServerError'
                }
            }
            default {
                if ($ProbeResult.NtlmSupported -and $ProbeResult.Type2Base64) {
                    $status = 'Vulnerable_NtlmHttpEndpoint'
                    $tagHttp = $true
                } elseif ($ProbeResult.NtlmSupported) {
                    $status = 'Failure_MissingChallenge'
                } else {
                    $status = 'Failure_UnexpectedStatus'
                }
            }
        }
    }

    return [PSCustomObject]@{
        Status     = $status
        TagHttp    = $tagHttp
        TagHttps   = $false
        TagEpa     = $false
        Collected  = $ProbeResult.Responded
    }
}

function Get-HttpsEndpointStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ProbeResult
    )

    $status = 'Failure_Unknown'
    $tagHttps = $false
    $tagEpa = $false

    if (-not $ProbeResult.Responded) {
        switch ($ProbeResult.FailureCategory) {
            'PortInaccessible' { $status = 'NotVulnerable_PortInaccessible' }
            'Timeout' { $status = 'Failure_Timeout' }
            'NameResolutionFailure' { $status = 'Failure_NameResolutionFailure' }
            default { $status = 'Failure_RequestException' }
        }
    } else {
        switch ($ProbeResult.StatusCode) {
            401 {
                if ($ProbeResult.NtlmSupported -and $ProbeResult.Type2Base64) {
                    $channelInfo = $ProbeResult.ChannelBindingInfo
                    if ($channelInfo -and $channelInfo.ParseError) {
                        $status = 'Failure_Type2ParseError'
                    } elseif ($channelInfo -and $channelInfo.ChannelBindingAvPresent) {
                        $status = 'NotVulnerable_NtlmChannelBindingRequired'
                        $tagHttps = $true
                        $tagEpa = $true
                    } else {
                        $status = 'Vulnerable_NtlmHttpsNoChannelBinding'
                        $tagHttps = $true
                    }
                } elseif ($ProbeResult.NtlmSupported) {
                    $status = 'Failure_MissingChallenge'
                } else {
                    $status = 'NotVulnerable_NoNtlmChallenge'
                }
            }
            200 {
                $status = 'Vulnerable_NtlmHttpsNoChannelBinding'
                $tagHttps = $true
            }
            302 {
                if ($ProbeResult.NtlmSupported -and $ProbeResult.Type2Base64) {
                    $channelInfo = $ProbeResult.ChannelBindingInfo
                    if ($channelInfo -and $channelInfo.ParseError) {
                        $status = 'Failure_Type2ParseError'
                    } elseif ($channelInfo -and $channelInfo.ChannelBindingAvPresent) {
                        $status = 'NotVulnerable_NtlmChannelBindingRequired'
                        $tagHttps = $true
                        $tagEpa = $true
                    } else {
                        $status = 'Vulnerable_NtlmHttpsNoChannelBinding'
                        $tagHttps = $true
                    }
                } else {
                    $status = 'Failure_UnexpectedStatus'
                }
            }
            403 { $status = 'NotVulnerable_PathForbidden' }
            404 { $status = 'NotVulnerable_PathNotFound' }
            500 { $status = 'Failure_ServerError' }
            default {
                if ($ProbeResult.NtlmSupported -and $ProbeResult.Type2Base64) {
                    $channelInfo = $ProbeResult.ChannelBindingInfo
                    if ($channelInfo -and $channelInfo.ParseError) {
                        $status = 'Failure_Type2ParseError'
                    } elseif ($channelInfo -and $channelInfo.ChannelBindingAvPresent) {
                        $status = 'NotVulnerable_NtlmChannelBindingRequired'
                        $tagHttps = $true
                        $tagEpa = $true
                    } else {
                        $status = 'Vulnerable_NtlmHttpsNoChannelBinding'
                        $tagHttps = $true
                    }
                } elseif ($ProbeResult.NtlmSupported) {
                    $status = 'Failure_MissingChallenge'
                } else {
                    $status = 'Failure_UnexpectedStatus'
                }
            }
        }
    }

    return [PSCustomObject]@{
        Status     = $status
        TagHttp    = $false
        TagHttps   = $tagHttps
        TagEpa     = $tagEpa
        Collected  = $ProbeResult.Responded
    }
}

function Test-CaEnrollmentEndpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [string]$EndpointType,

        [Parameter(Mandatory = $true)]
        [string]$RelativePath,

        [Parameter(Mandatory = $true)]
        [string]$Type1MessageBase64,

        [ValidateRange(1, 120)]
        [int]$TimeoutSeconds = 10,

        [switch]$IncludeRawChallenges
    )

    $relativePath = $RelativePath.TrimStart('/')
    $httpUri = [uri]::new("http://$ComputerName/$relativePath")
    $httpsUri = [uri]::new("https://$ComputerName/$relativePath")

    Write-Verbose "Probing $EndpointType endpoint paths '$($httpUri.AbsoluteUri)' and '$($httpsUri.AbsoluteUri)'"

    $httpProbe = Invoke-NtlmProbe -Uri $httpUri -Type1MessageBase64 $Type1MessageBase64 -TimeoutSeconds $TimeoutSeconds
    $httpsProbe = Invoke-NtlmProbe -Uri $httpsUri -Type1MessageBase64 $Type1MessageBase64 -TimeoutSeconds $TimeoutSeconds

    $httpStatus = Get-HttpEndpointStatus -ProbeResult $httpProbe
    $httpsStatus = Get-HttpsEndpointStatus -ProbeResult $httpsProbe

    $output = [ordered]@{
        ComputerName              = $ComputerName
        EndpointType              = $EndpointType
        RelativePath              = $relativePath
        HttpUrl                   = $httpUri.AbsoluteUri
        HttpStatus                = $httpStatus.Status
        HttpStatusCode            = $httpProbe.StatusCode
        HttpResponded             = $httpProbe.Responded
        HttpNtlmSupported         = $httpProbe.NtlmSupported
        HttpFailureCategory       = $httpProbe.FailureCategory
        HttpError                 = $httpProbe.Error
        HttpsUrl                  = $httpsUri.AbsoluteUri
        HttpsStatus               = $httpsStatus.Status
        HttpsStatusCode           = $httpsProbe.StatusCode
        HttpsResponded            = $httpsProbe.Responded
        HttpsNtlmSupported        = $httpsProbe.NtlmSupported
        HttpsChannelBindingPresent= if ($httpsProbe.ChannelBindingInfo) { [bool]$httpsProbe.ChannelBindingInfo.ChannelBindingAvPresent } else { $null }
        HttpsTargetInfoPresent    = if ($httpsProbe.ChannelBindingInfo) { [bool]$httpsProbe.ChannelBindingInfo.TargetInfoPresent } else { $null }
        HttpsChannelBindingError  = if ($httpsProbe.ChannelBindingInfo) { $httpsProbe.ChannelBindingInfo.ParseError } else { $null }
        HttpsFailureCategory      = $httpsProbe.FailureCategory
        HttpsError                = $httpsProbe.Error
        ADCSWebEnrollmentHTTP     = $httpStatus.TagHttp
        ADCSWebEnrollmentHTTPS    = $httpsStatus.TagHttps
        ADCSWebEnrollmentEPA      = $httpsStatus.TagEpa
    }

    if ($IncludeRawChallenges) {
        $output.HttpType2 = $httpProbe.Type2Base64
        $output.HttpsType2 = $httpsProbe.Type2Base64
    }

    return [PSCustomObject]$output
}
$results = @()

if (-not $SkipWebEnrollment) {
    $results += Test-CaEnrollmentEndpoint -ComputerName $ComputerName -EndpointType 'WebEnrollmentApplication' -RelativePath 'certsrv/' -Type1MessageBase64 $Script:NtlmType1Message -TimeoutSeconds $TimeoutSeconds -IncludeRawChallenges:$IncludeRawChallenges
}

if (-not $SkipEnrollmentWebService) {
    if ([string]::IsNullOrWhiteSpace($CACommonName)) {
        Write-Verbose 'CACommonName not supplied; skipping Enrollment Web Service probe.'
    } else {
        $cesPath = "{0}_CES_Kerberos/service.svc" -f $CACommonName
        $results += Test-CaEnrollmentEndpoint -ComputerName $ComputerName -EndpointType 'EnrollmentWebService' -RelativePath $cesPath -Type1MessageBase64 $Script:NtlmType1Message -TimeoutSeconds $TimeoutSeconds -IncludeRawChallenges:$IncludeRawChallenges
    }
}

$results


