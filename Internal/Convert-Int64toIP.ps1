#*------v Function convert-Int64toIP v------
function convert-Int64toIP {
    <#
    .SYNOPSIS
    Convert-Int64toIP.ps1 - Converts 64bit Integer representation back to IPv4 Address
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2021-08-16
    FileName    : Convert-Int64toIP.ps1
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,Network,IP,Subnet
    AddedCredit : Mark Wragg
    AddedWebsite: https://github.com/markwragg
    AddedTwitter: 
    REVISIONS
        * 1:29 PM 8/12/2021 added CBH, minor param inline help etc.
    * 4/14/2019 Mark Wragg posted rev (corresponds to PSG v1.1.14)
    .DESCRIPTION
    Convert-Int64toIP.ps1 - Converts 64bit Integer representation back to IPv4 Address
    .PARAMETER IP
    The IP address to convert[-IP 192.168.0.1]
    .OUTPUT
    System.String
    .EXAMPLE
    convert-Int64toIP -int 3232235521
    Result
    ------
    192.168.0.1
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://github.com/markwragg/PowerShell-Subnet/blob/master/Subnet/Private/Convert-Int64toIP.ps1
    #>
    ###Requires -Modules DnsClient
    [CmdletBinding()]
    PARAM (
        [parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="64-bit integer IP address  representation, to be converted back to IP[-int 3232235521]")]
        [int64]$int
    )
    BEGIN {
        ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
        $Verbose = ($VerbosePreference -eq 'Continue') ; 
    } ;  # BEG-E
    PROCESS {
        (([math]::truncate($int / 16777216)).tostring() + "." + ([math]::truncate(($int % 16777216) / 65536)).tostring() + "." + ([math]::truncate(($int % 65536) / 256)).tostring() + "." + ([math]::truncate($int % 256)).tostring() )
    } ;  # PROC-E
    END {} ;
} ; 
#*------^ END Function Convert-Int64toIP ^------