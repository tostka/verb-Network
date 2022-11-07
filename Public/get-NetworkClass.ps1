#*------v Function get-NetworkClass v------
function get-NetworkClass {
    <#
    .SYNOPSIS
    get-NetworkClass.ps1 - Use to determine the network class of a given IP address.
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2021-08-16
    FileName    : get-NetworkClass.ps1
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,Network,IP,Subnet
    AddedCredit : Mark Wragg
    AddedWebsite: https://github.com/markwragg
    AddedTwitter: 
    REVISIONS
    * 2:49 PM 11/2/2021 refactor/fixed CBH
    * 1:29 PM 8/12/2021 tweaked CBH, minor param inline help etc.
    * 9/10/2019 Mark Wragg posted rev (corresponds to PSG v1.1.14)
    .DESCRIPTION
    get-NetworkClass.ps1 - Use to determine the network class of a given IP address.
    .PARAMETER IP
    The IP address to test[-IP 192.168.0.1]
    .EXAMPLE
    '10.1.1.1' | Get-NetworkClass
    Result
    ------
    A
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://github.com/markwragg/PowerShell-Subnet/blob/master/Subnet/Public/Test-PrivateIP.ps1
    #>

    ###Requires -Modules DnsClient
    [CmdletBinding()]
    PARAM (
        [parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="The IP address to test[-IP 192.168.0.1]")]
        [string]$IP
    )
    BEGIN {
        ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
        $Verbose = ($VerbosePreference -eq 'Continue') ; 
    } ;  # BEG-E
    PROCESS {
        switch ($IP.Split('.')[0]) {
            { $_ -in 0..127 } { 'A' }
            { $_ -in 128..191 } { 'B' }
            { $_ -in 192..223 } { 'C' }
            { $_ -in 224..239 } { 'D' }
            { $_ -in 240..255 } { 'E' }
        } ;
    } ;  # PROC-E
    END {}
} ; 
#*------^ END Function get-NetworkClass ^------
