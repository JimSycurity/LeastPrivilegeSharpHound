function Get-WinRegAllowedPaths {
    <#
    .SYNOPSIS
        Enumerates Windows Registry remote access allowed paths from target computers.

    .DESCRIPTION
        Utilizes a Remote Registry connection to enumerate the values of:
            - HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths\Machine
            - HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths\Machine

        These registry locations control which registry paths can be accessed remotely via the
        Remote Registry service. This is a security configuration that determines what registry
        keys remote users can access even when they don't have explicit permissions.

    .PARAMETER ComputerName
        The name of the computer(s) to query. Accepts pipeline input.
        If not specified, queries the local computer.

    .PARAMETER OutputPath
        Optional path to export results to CSV file. If not specified, results are only returned as objects.

    .EXAMPLE
        Get-WinRegAllowedPaths -ComputerName "Server01"

        Retrieves the allowed registry paths from Server01.

    .EXAMPLE
        "Server01","Server02","Server03" | Get-WinRegAllowedPaths -OutputPath "C:\Reports\AllowedPaths.csv"

        Retrieves allowed paths from multiple servers and exports to CSV.

    .EXAMPLE
        Get-ADComputer -Filter {OperatingSystem -like "*Server*"} | Select-Object -ExpandProperty Name | Get-WinRegAllowedPaths

        Retrieves allowed paths from all servers in Active Directory.

    .NOTES
        Author: Updated by Assistant
        Requires: Remote Registry service must be running on target computers
        Authentication: Uses current user's security context (Windows authentication)
                       Alternative credentials cannot be passed to OpenRemoteBaseKey method

        To use alternative credentials, consider:
        - Running PowerShell as different user (RunAs)
        - Using Invoke-Command with -Credential parameter (requires different approach)
        - Establishing a net use connection with credentials before running

    .OUTPUTS
        PSCustomObject with properties:
        - ComputerName: Name of the computer
        - PathType: Either "AllowedPaths" or "AllowedExactPaths"
        - AllowedPath: Individual allowed registry path
        - Status: Success or error message
        - Timestamp: When the data was collected
    #>

    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Name', 'PSComputerName', 'DNSHostName')]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [ValidateScript({
            if ($_ -and !(Test-Path (Split-Path $_ -Parent))) {
                throw "Output directory does not exist: $(Split-Path $_ -Parent)"
            }
            $true
        })]
        [string]$OutputPath
    )

    begin {
        Write-Verbose "Starting Get-WinRegAllowedPaths enumeration"

        # Define the registry paths to check
        $registryPaths = @{
            'AllowedPaths' = 'SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths'
            'AllowedExactPaths' = 'SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths'
        }

        # Initialize results collection
        $allResults = [System.Collections.ArrayList]::new()
    }

    process {
        foreach ($Computer in $ComputerName) {
            Write-Verbose "Processing computer: $Computer"

            try {
                # Open remote registry connection
                Write-Verbose "Opening registry connection to $Computer"
                $regHive = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
                    [Microsoft.Win32.RegistryHive]::LocalMachine,
                    $Computer
                )

                # Enumerate each registry path type
                foreach ($pathType in $registryPaths.Keys) {
                    $path = $registryPaths[$pathType]
                    $fullPath = "HKLM:\$path"

                    Write-Verbose "Checking path: $fullPath"

                    try {
                        # Open the registry subkey
                        $regKey = $regHive.OpenSubKey($path)

                        if ($null -eq $regKey) {
                            Write-Verbose "Registry key not found: $fullPath"

                            $result = [PSCustomObject]@{
                                ComputerName = $Computer
                                PathType = $pathType
                                AllowedPath = 'N/A'
                                Status = 'Registry key not found'
                                Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                            }

                            [void]$allResults.Add($result)
                            continue
                        }

                        # Get the Machine value (REG_MULTI_SZ - array of strings)
                        $machineValue = $regKey.GetValue('Machine')

                        if ($null -eq $machineValue) {
                            Write-Verbose "Machine value not found in: $fullPath"

                            $result = [PSCustomObject]@{
                                ComputerName = $Computer
                                PathType = $pathType
                                AllowedPath = 'N/A'
                                Status = 'Machine value not found'
                                Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                            }

                            [void]$allResults.Add($result)
                        }
                        elseif ($machineValue.Count -eq 0) {
                            Write-Verbose "Machine value is empty in: $fullPath"

                            $result = [PSCustomObject]@{
                                ComputerName = $Computer
                                PathType = $pathType
                                AllowedPath = '(empty)'
                                Status = 'Success'
                                Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                            }

                            [void]$allResults.Add($result)
                        }
                        else {
                            # Process each allowed path
                            foreach ($allowedPath in $machineValue) {
                                Write-Verbose "Found allowed path: $allowedPath"

                                $result = [PSCustomObject]@{
                                    ComputerName = $Computer
                                    PathType = $pathType
                                    AllowedPath = $allowedPath
                                    Status = 'Success'
                                    Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                                }

                                [void]$allResults.Add($result)

                                # Output object to pipeline
                                Write-Output $result
                            }
                        }
                    }
                    catch {
                        Write-Warning "Error accessing $pathType on $Computer : $_"

                        $result = [PSCustomObject]@{
                            ComputerName = $Computer
                            PathType = $pathType
                            AllowedPath = 'N/A'
                            Status = "Error: $_"
                            Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                        }

                        [void]$allResults.Add($result)
                    }
                    finally {
                        # Clean up registry key
                        if ($null -ne $regKey) {
                            $regKey.Close()
                            $regKey.Dispose()
                        }
                    }
                }
            }
            catch {
                Write-Error "Failed to connect to registry on $Computer : $_"

                $result = [PSCustomObject]@{
                    ComputerName = $Computer
                    PathType = 'N/A'
                    AllowedPath = 'N/A'
                    Status = "Connection Error: $_"
                    Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                }

                [void]$allResults.Add($result)
            }
            finally {
                # Clean up registry hive connection
                if ($null -ne $regHive) {
                    $regHive.Close()
                    $regHive.Dispose()
                }
            }
        }
    }

    end {
        Write-Verbose "Completed enumeration of $($allResults.Count) entries"

        # Export to file if specified
        if ($OutputPath) {
            try {
                Write-Verbose "Exporting results to: $OutputPath"
                $allResults | Export-Csv -Path $OutputPath -NoTypeInformation -Force
                Write-Host "Results exported to: $OutputPath" -ForegroundColor Green

                # Display summary
                $summary = $allResults | Group-Object ComputerName, PathType | ForEach-Object {
                    [PSCustomObject]@{
                        Computer = $_.Group[0].ComputerName
                        PathType = $_.Group[0].PathType
                        Count = $_.Count
                        Status = $_.Group[0].Status
                    }
                }

                Write-Host "`nSummary:" -ForegroundColor Cyan
                $summary | Format-Table -AutoSize
            }
            catch {
                Write-Error "Failed to export results to file: $_"
            }
        }

        Write-Verbose "Get-WinRegAllowedPaths completed"
    }
}

# Example usage (commented out):
# Get-WinRegAllowedPaths -ComputerName "localhost" -Verbose
# Get-WinRegAllowedPaths -ComputerName "Server01","Server02" -OutputPath "C:\Reports\WinRegPaths.csv"