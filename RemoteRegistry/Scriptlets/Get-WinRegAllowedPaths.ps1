function Get-WinRegAllowedPaths {
    <#
    .SYNOPSIS
        Utilizes a Remote Registry connection to enumerate the values of:
            Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths\Machine
            Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths\Machine

    .DESCRIPTION

    #>
    param (
        [CmdletBinding()]
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Computer
    )

    # TODO: Actually write this
    begin {

    }

    process {

    }

    end {

    }
}