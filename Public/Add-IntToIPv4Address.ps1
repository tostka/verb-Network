#*------v Function Add-IntToIPv4Address v------
function Add-IntToIPv4Address {
<#
    .SYNOPSIS
    Add-IntToIPv4Address.ps1 - Add an integer to an IP Address and get the new IP Address.
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2021-08-16
    FileName    : Add-IntToIPv4Address.ps1
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,Network,IP,Subnet
    AddedCredit :  Brian Farnsworth
    AddedWebsite: https://codeandkeep.com/
    AddedTwitter: 
    REVISIONS
    * 1:29 PM 8/12/2021 tweaked CBH, minor param inline help etc.
    * 9/10/2019 Mark Wragg posted rev (corresponds to PSG v1.1.14)
    .DESCRIPTION
    Add an integer to an IP Address and get the new IP Address.
    .PARAMETER IP
    The IP Address to add an integer to [-IP 192.168.0.1]
    .PARAMETER Integer
    An integer to add to the IP Address. Can be a positive or negative number[-integer 1].
    .EXAMPLE
    .EXAMPLE
    Add-IntToIPv4Address -IPv4Address 10.10.0.252 -Integer 10
    10.10.1.6
    Description
    -----------
    This command will add 10 to the IP Address 10.10.0.1 and return the new IP Address.
    .EXAMPLE
    Add-IntToIPv4Address -IPv4Address 192.168.1.28 -Integer -100
    192.168.0.184
    Description
    -----------
    This command will subtract 100 from the IP Address 192.168.1.28 and return the new IP Address.
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://codeandkeep.com/PowerShell-Get-Subnet-NetworkID/
    #>
    ##Requires -Modules DnsClient
    [CmdletBinding()]
    Param(
      [parameter(HelpMessage="The IP address to test[-IP 192.168.0.1]")]
      [String]$IP,
      [parameter(HelpMessage="An integer to add to the IP Address. Can be a positive or negative number[-integer 1]")]
      [int64]$Integer
    )
    BEGIN {
        ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
        $Verbose = ($VerbosePreference -eq 'Continue') ; 
    } ;  # BEG-E
    PROCESS {
        Try{
            #$ipInt=ConvertIPv4ToInt -IP $IP  -ErrorAction Stop ; 
            $ipInt=Convert-IPtoInt64 -IP $IP  -ErrorAction Stop ; 
            $ipInt+=$Integer ; 
            #ConvertIntToIPv4 -Integer $ipInt ; 
            convert-Int64toIP -int $ipInt  |write-output ; 
        }Catch{
              Write-Error -Exception $_.Exception -Category $_.CategoryInfo.Category ; 
        } ; 
    } ;  # PROC-E
    END {}
} ; 
#*------^ END Function Add-IntToIPv4Address ^------
