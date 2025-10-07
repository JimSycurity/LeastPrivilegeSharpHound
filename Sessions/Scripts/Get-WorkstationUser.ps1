<#
.SYNOPSIS
    Wrapper for NetWkstaUserEnum to enumerate logged on users.

.DESCRIPTION
    Enumerates users logged on to a local or remote computer using NetWkstaUserEnum.
    Returns objects that can be captured in PowerShell jobs.

.PARAMETER ComputerName
    The name of the computer to query. If not specified, queries the local computer.

.EXAMPLE
    Get-WorkstationUser -ComputerName corp1-dc01

.EXAMPLE
    'corp1-dc01','corp1-dc02' | Get-WorkstationUser

.EXAMPLE
    $computers = 'corp1-dc01','corp1-dc02','corp1-ws01'
    $jobs = $computers | ForEach-Object {
        Start-Job -ScriptBlock {
            param($Computer)
            Import-Module PSReflect-Functions
            Get-WorkstationUser -ComputerName $Computer
        } -ArgumentList $_
    }
    $results = $jobs | Wait-Job | Receive-Job
    $jobs | Remove-Job
#>

[CmdletBinding()]
param(
    [Parameter(
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        Position = 0
    )]
    [Alias('CN', 'Computer', 'Name')]
    [string]$ComputerName
)


    # Verify NetWkstaUserEnum is available
    if (-not (Get-Command -Name NetWkstaUserEnum -ErrorAction SilentlyContinue)) {
        throw "NetWkstaUserEnum command not found. Please ensure PSReflect-Functions module is imported."
    }


    try {
        if ($ComputerName) {
            Write-Verbose "Querying users on $ComputerName"
            $users = NetWkstaUserEnum -ComputerName $ComputerName
        }
        else {
            Write-Verbose "Querying users on local computer"
            $users = NetWkstaUserEnum
        }

        # Return the objects directly for job capture
        # Add ComputerName property for tracking in multi-computer scenarios
        if ($users) {
            foreach ($user in $users) {
                $user | Add-Member -NotePropertyName 'QueriedComputer' -NotePropertyValue $(
                    if ($ComputerName) { $ComputerName } else { $env:COMPUTERNAME }
                ) -Force -PassThru
            }
            return $users
        } else {
            return 'No data'
        }

    }
    catch {
        Write-Error "Failed to enumerate users on $($ComputerName): $_"
    }
