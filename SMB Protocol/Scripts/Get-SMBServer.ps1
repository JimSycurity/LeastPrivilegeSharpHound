# Get SMB server data similar to sharphound https://github.com/SpecterOps/SharpHoundCommon/blob/1ec7cbaee444f4a2cf6e257042c8591e4ae831e2/src/CommonLib/Processors/SmbProcessor.cs
# Also check for webclient https://github.com/SpecterOps/SharpHoundCommon/blob/1ec7cbaee444f4a2cf6e257042c8591e4ae831e2/src/CommonLib/Processors/WebClientServiceProcessor.cs#L78
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [Alias('Name','DNSHostName','Host')]
    [ValidateNotNullOrEmpty()]
    [string[]]$ComputerName
)

begin {
    $script:Smb1Dialects = @(
        'PC NETWORK PROGRAM 1.0',
        'LANMAN1.0',
        'Windows for Workgroups 3.1a',
        'LM1.2X002',
        'LANMAN2.1',
        'NT LM 0.12',
        'SMB 2.002',
        'SMB 2.???'
    )

    function New-Smb1NegotiateRequestBytes {
        $dialectStream = New-Object System.IO.MemoryStream
        $dialectWriter = New-Object System.IO.BinaryWriter($dialectStream, [System.Text.Encoding]::ASCII, $true)
        try {
            foreach ($dialect in $script:Smb1Dialects) {
                $dialectWriter.Write([byte]0x02)
                $dialectWriter.Write([System.Text.Encoding]::ASCII.GetBytes($dialect))
                $dialectWriter.Write([byte]0x00)
            }
            $dialectWriter.Flush()
            $dialectBytes = $dialectStream.ToArray()
        }
        finally {
            $dialectWriter.Dispose()
            $dialectStream.Dispose()
        }

        $ms = New-Object System.IO.MemoryStream
        $writer = New-Object System.IO.BinaryWriter($ms, [System.Text.Encoding]::ASCII, $true)
        try {
            $writer.Write([byte[]](0,0,0,0))
            $writer.Write([byte[]](0xFF,0x53,0x4D,0x42))
            $writer.Write([byte]0x72)
            $writer.Write([uint32]0)
            $writer.Write([byte]0x18)
            $writer.Write([System.UInt16]0xC853)
            $writer.Write([System.UInt16]0)
            $writer.Write((New-Object byte[] 8))
            $writer.Write([System.UInt16]0)
            $writer.Write([System.UInt16]0xFFFF)
            $writer.Write([System.UInt16]0xFEFF)
            $writer.Write([System.UInt16]0)
            $writer.Write([System.UInt16]0)
            $writer.Write([byte]0)
            $writer.Write([System.UInt16]$dialectBytes.Length)
            $writer.Write($dialectBytes)
            $writer.Flush()
            $packet = $ms.ToArray()
        }
        finally {
            $writer.Dispose()
            $ms.Dispose()
        }

        $length = $packet.Length - 4
        $packet[0] = 0x00
        $packet[1] = [byte](($length -shr 16) -band 0xFF)
        $packet[2] = [byte](($length -shr 8) -band 0xFF)
        $packet[3] = [byte]($length -band 0xFF)
        return $packet
    }

    function New-Smb2NegotiateRequestBytes {
        $dialects = [System.UInt16[]](0x0202,0x0210,0x0300,0x0302)
        $clientGuid = [Guid]::NewGuid().ToByteArray()

        $ms = New-Object System.IO.MemoryStream
        $writer = New-Object System.IO.BinaryWriter($ms, [System.Text.Encoding]::ASCII, $true)
        try {
            $writer.Write([byte[]](0,0,0,0))
            $writer.Write([uint32]0x424D53FE)
            $writer.Write([System.UInt16]0x0040)
            $writer.Write([System.UInt16]0)
            $writer.Write([uint32]0)
            $writer.Write([System.UInt16]0)
            $writer.Write([System.UInt16]1)
            $writer.Write([uint32]0)
            $writer.Write([uint32]0)
            $writer.Write([uint64]0)
            $writer.Write([uint32]0)
            $writer.Write([uint32]0)
            $writer.Write([uint64]0)
            $writer.Write((New-Object byte[] 16))

            $writer.Write([System.UInt16]0x0024)
            $writer.Write([System.UInt16]$dialects.Length)
            $writer.Write([System.UInt16]0x0001)
            $writer.Write([System.UInt16]0)
            $writer.Write([uint32]0)
            $writer.Write($clientGuid)
            $writer.Write([uint32]0)
            $writer.Write([System.UInt16]0)
            $writer.Write([System.UInt16]0)

            foreach ($dialect in $dialects) {
                $writer.Write([System.UInt16]$dialect)
            }

            $writer.Flush()
            $packet = $ms.ToArray()
        }
        finally {
            $writer.Dispose()
            $ms.Dispose()
        }

        $length = $packet.Length - 4
        $packet[0] = 0x00
        $packet[1] = [byte](($length -shr 16) -band 0xFF)
        $packet[2] = [byte](($length -shr 8) -band 0xFF)
        $packet[3] = [byte]($length -band 0xFF)
        return $packet
    }

    function Invoke-SmbRequest {
        param(
            [Parameter(Mandatory = $true)][string]$Target,
            [Parameter(Mandatory = $true)][byte[]]$RequestBytes,
            [int]$Port = 445,
            [int]$TimeoutMs = 5000
        )

        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $connectTask = $client.ConnectAsync($Target, $Port)
            if (-not $connectTask.Wait($TimeoutMs)) {
                throw "Timeout connecting to ${Target}:$Port"
            }
            if ($connectTask.IsFaulted) {
                throw $connectTask.Exception.InnerException
            }
            if ($connectTask.IsCanceled) {
                throw "Connection attempt to ${Target}:$Port was cancelled"
            }

            $client.ReceiveTimeout = $TimeoutMs
            $client.SendTimeout = $TimeoutMs
            $stream = $client.GetStream()
            try {
                $stream.Write($RequestBytes, 0, $RequestBytes.Length)
                $stream.Flush()

                $netbiosHeader = New-Object byte[] 4
                $readOffset = 0
                while ($readOffset -lt 4) {
                    $bytesRead = $stream.Read($netbiosHeader, $readOffset, 4 - $readOffset)
                    if ($bytesRead -le 0) {
                        throw "Connection closed before NetBIOS header received"
                    }
                    $readOffset += $bytesRead
                }

                if ($netbiosHeader[0] -ne 0x00) {
                    throw ("Unexpected NetBIOS message type 0x{0:X2}" -f $netbiosHeader[0])
                }

                [int]$payloadLength = ($netbiosHeader[1] -shl 16) -bor ($netbiosHeader[2] -shl 8) -bor $netbiosHeader[3]
                if ($payloadLength -lt 0 -or $payloadLength -gt 1048576) {
                    throw "Suspicious SMB payload length: $payloadLength"
                }

                $payload = New-Object byte[] $payloadLength
                $received = 0
                while ($received -lt $payloadLength) {
                    $bytesRead = $stream.Read($payload, $received, $payloadLength - $received)
                    if ($bytesRead -le 0) {
                        throw "Connection closed before SMB message completed"
                    }
                    $received += $bytesRead
                }

                $response = New-Object byte[] (4 + $payloadLength)
                [Array]::Copy($netbiosHeader, 0, $response, 0, 4)
                if ($payloadLength -gt 0) {
                    [Array]::Copy($payload, 0, $response, 4, $payloadLength)
                }

                return ,$response
            }
            finally {
                $stream.Dispose()
            }
        }
        finally {
            $client.Dispose()
        }
    }

    function Get-Smb2DialectName {
        param([System.UInt16]$DialectRevision)
        switch ($DialectRevision) {
            0x0202 { 'SMB 2.0.2' ; break }
            0x0210 { 'SMB 2.1' ; break }
            0x0300 { 'SMB 3.0' ; break }
            0x0302 { 'SMB 3.0.2' ; break }
            0x0311 { 'SMB 3.1.1' ; break }
            default { 'Unknown (0x{0:X4})' -f $DialectRevision ; break }
        }
    }

    function Parse-Smb2NegotiateResponse {
        param([byte[]]$Response)
        Write-Verbose ("SMB2 response length: {0}" -f $Response.Length)
        if ($Response.Length -lt 100) {
            Write-Verbose ("SMB2 response (Base64): {0}" -f [Convert]::ToBase64String($Response))
            throw 'SMB2 response too small'
        }
        if ($Response[0] -ne 0x00) {
            throw 'Unexpected NetBIOS message type'
        }
        if ([BitConverter]::ToUInt32($Response, 4) -ne 0x424D53FE) {
            throw 'Response is not SMB2'
        }

        $ms = New-Object -TypeName System.IO.MemoryStream -ArgumentList $Response, 4, ($Response.Length - 4), $false
        $reader = New-Object System.IO.BinaryReader($ms)
        try {
            $protocol = $reader.ReadUInt32()
            $structureSize = $reader.ReadUInt16()
            $reader.ReadUInt16() | Out-Null
            $status = $reader.ReadUInt32()
            $command = $reader.ReadUInt16()
            $reader.ReadUInt16() | Out-Null
            $reader.ReadUInt32() | Out-Null
            $reader.ReadUInt32() | Out-Null
            $reader.ReadUInt64() | Out-Null
            $reader.ReadUInt32() | Out-Null
            $reader.ReadUInt32() | Out-Null
            $reader.ReadUInt64() | Out-Null
            $signature = $reader.ReadBytes(16)

            $negSize = $reader.ReadUInt16()
            if ($negSize -ne 65) {
                throw "Unexpected SMB2 negotiate structure size: $negSize"
            }
            $securityMode = $reader.ReadUInt16()
            $dialectRevision = $reader.ReadUInt16()
            $contextCount = $reader.ReadUInt16()
            $reader.ReadBytes(16) | Out-Null
            $capabilities = $reader.ReadUInt32()
            $maxTrans = $reader.ReadUInt32()
            $maxRead = $reader.ReadUInt32()
            $maxWrite = $reader.ReadUInt32()
            $reader.ReadUInt64() | Out-Null
            $reader.ReadUInt64() | Out-Null
            $securityBufferOffset = $reader.ReadUInt16()
            $securityBufferLength = $reader.ReadUInt16()
            $negotiateContextOffset = $reader.ReadUInt32()
        }
        finally {
            $reader.Dispose()
            $ms.Dispose()
        }

        $signingEnabled = [bool]($securityMode -band 0x0001)
        $signingRequired = [bool]($securityMode -band 0x0002)

        [PSCustomObject]@{
            Protocol = 'SMB2'
            Status = $status
            Command = $command
            SigningEnabled = $signingEnabled
            SigningRequired = $signingRequired
            DialectRevision = $dialectRevision
            NegotiatedVersion = Get-Smb2DialectName -DialectRevision $dialectRevision
            NegotiateContextCount = $contextCount
            Capabilities = $capabilities
            MaxTransactionSize = $maxTrans
            MaxReadSize = $maxRead
            MaxWriteSize = $maxWrite
            SecurityBufferOffset = $securityBufferOffset
            SecurityBufferLength = $securityBufferLength
            NegotiateContextOffset = $negotiateContextOffset
        }
    }

    function Parse-Smb1NegotiateResponse {
        param(
            [byte[]]$Response,
            [string[]]$Dialects
        )
        if ($Response.Length -lt 80) {
            throw 'SMB1 response too small'
        }
        if ($Response[0] -ne 0x00) {
            throw 'Unexpected NetBIOS message type'
        }
        if ([BitConverter]::ToUInt32($Response, 4) -ne 0x424D53FF) {
            throw 'Response is not SMB1'
        }

        $ms = New-Object System.IO.MemoryStream($Response, 4, $Response.Length - 4, $false)
        $reader = New-Object System.IO.BinaryReader($ms)
        try {
            $protocol = $reader.ReadUInt32()
            $command = $reader.ReadByte()
            if ($command -ne 0x72) {
                throw ('Unexpected SMB1 command: 0x{0:X2}' -f $command)
            }
            $reader.ReadUInt32() | Out-Null
            $reader.ReadByte() | Out-Null
            $reader.ReadUInt16() | Out-Null
            $reader.ReadUInt16() | Out-Null
            $reader.ReadBytes(8) | Out-Null
            $reader.ReadUInt16() | Out-Null
            $reader.ReadUInt16() | Out-Null
            $reader.ReadUInt16() | Out-Null
            $reader.ReadUInt16() | Out-Null
            $reader.ReadUInt16() | Out-Null

            $wordCount = $reader.ReadByte()
            if ($wordCount -lt 1) {
                throw "Unexpected SMB1 WordCount: $wordCount"
            }

            $dialectIndex = $reader.ReadUInt16()
            $securityMode = $reader.ReadByte()
        }
        finally {
            $reader.Dispose()
            $ms.Dispose()
        }

        if ($dialectIndex -eq 0xFFFF) {
            throw 'Server did not accept supplied SMB1 dialects'
        }

        $dialectName = if ($dialectIndex -lt $Dialects.Length) { $Dialects[$dialectIndex] } else { "Unknown index $dialectIndex" }
        $signingEnabled = [bool]($securityMode -band 0x04)
        $signingRequired = [bool]($securityMode -band 0x08)

        [PSCustomObject]@{
            Protocol = 'SMB1'
            SigningEnabled = $signingEnabled
            SigningRequired = $signingRequired
            NegotiatedVersion = $dialectName
            DialectIndex = $dialectIndex
        }
    }

    function Initialize-WebClientNative {
        if (-not $script:WebClientNativeLoaded) {
            $typeDefinition = @"
using System;
using System.Runtime.InteropServices;

public static class WebClientNative {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@
            Add-Type -TypeDefinition $typeDefinition -Language CSharp
            $script:WebClientNativeLoaded = $true
        }
    }

    function Test-WebClientPipe {
        param([string]$Target)

        Initialize-WebClientNative

        $pipePath = "\\$Target\pipe\DAV RPC SERVICE"
        $desiredAccess = 0x02000000
        $shareMode = 0x00000001 -bor 0x00000002 -bor 0x00000004

        $handle = [WebClientNative]::CreateFile(
            $pipePath,
            $desiredAccess,
            $shareMode,
            [IntPtr]::Zero,
            3,
            0,
            [IntPtr]::Zero
        )

        try {
            if ($handle -eq [IntPtr]::Zero -or $handle.ToInt64() -eq -1) {
                $error = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                switch ($error) {
                    5 { return $true }
                    2 { return $false }
                    53 { return $false }
                    64 { return $false }
                    65 { return $false }
                    default {
                        throw (New-Object System.ComponentModel.Win32Exception($error))
                    }
                }
            }

            return $true
        }
        finally {
            if ($handle -ne [IntPtr]::Zero -and $handle.ToInt64() -ne -1) {
                [void][WebClientNative]::CloseHandle($handle)
            }
        }
    }

    function Test-SmbServer {
        param([string]$Target)

        $result = [ordered]@{
            ComputerName = $Target
            Status = 'Failed'
            ProtocolFamily = $null
            SMBVersion = $null
            SigningEnabled = $null
            SigningRequired = $null
            RelayCapable = $null
            WebClientRunning = $null
            Error = $null
        }

        $errors = @()

        try {
            $smb2Response = Invoke-SmbRequest -Target $Target -RequestBytes (New-Smb2NegotiateRequestBytes)
            $parsed2 = Parse-Smb2NegotiateResponse -Response $smb2Response
            $result.Status = 'Success'
            $result.ProtocolFamily = $parsed2.Protocol
            $result.SMBVersion = $parsed2.NegotiatedVersion
            $result.SigningEnabled = $parsed2.SigningEnabled
            $result.SigningRequired = $parsed2.SigningRequired
            $result.RelayCapable = if ($parsed2.SigningRequired -eq $false) { $true } elseif ($parsed2.SigningRequired -eq $true) { $false } else { $null }
        }
        catch {
            $errors += $_.Exception.Message
            try {
                $smb1Response = Invoke-SmbRequest -Target $Target -RequestBytes (New-Smb1NegotiateRequestBytes)
                $parsed1 = Parse-Smb1NegotiateResponse -Response $smb1Response -Dialects $script:Smb1Dialects
                $result.Status = 'Success'
                $result.ProtocolFamily = $parsed1.Protocol
                $result.SMBVersion = $parsed1.NegotiatedVersion
                $result.SigningEnabled = $parsed1.SigningEnabled
                $result.SigningRequired = $parsed1.SigningRequired
                $result.RelayCapable = if ($parsed1.SigningRequired -eq $false) { $true } elseif ($parsed1.SigningRequired -eq $true) { $false } else { $null }
            }
            catch {
                $errors += $_.Exception.Message
            }
        }

        if ($result.Status -eq 'Success') {
            try {
                $result.WebClientRunning = Test-WebClientPipe -Target $Target
            }
            catch {
                $errors += $_.Exception.Message
                $result.WebClientRunning = $null
            }
        }

        if ($errors.Count -gt 0) {
            $result.Error = ($errors -join '; ')
        }

        [PSCustomObject]$result
    }
}

process {
    foreach ($name in $ComputerName) {
        if ([string]::IsNullOrWhiteSpace($name)) {
            continue
        }

        try {
            Test-SmbServer -Target $name
        }
        catch {
            [PSCustomObject][ordered]@{
                ComputerName = $name
                Status = 'Failed'
                ProtocolFamily = $null
                SMBVersion = $null
                SigningEnabled = $null
                SigningRequired = $null
                RelayCapable = $null
                WebClientRunning = $null
                Error = $_.Exception.Message
            }
        }
    }
}

