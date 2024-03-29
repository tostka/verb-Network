# Test-NetAddressIpv6TDO.ps1

#*------v Function Test-NetAddressIpv6TDO v------
function Test-NetAddressIpv6TDO {
    <#
    .SYNOPSIS
    Test-NetAddressIpv6TDO.ps1 - Test if a given string is an IPv6 Network Address
    .NOTES
    Version     : 0.0.1
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2024-03-22
    FileName    : Test-NetAddressIpv6TDO.ps1
    License     : MIT License
    Copyright   : (c) 2024 Todd Kadrie
    Github      : https://github.com/tostka/verb-XXX
    Tags        : Powershell,Network,Address
    AddedCredit : REFERENCE
    AddedWebsite: URL
    AddedTwitter: URL
    REVISIONS
    * 2:49 PM 3/22/2024 init, wrapped simple [IPAddress] type accelerator test
    .DESCRIPTION
    Test-NetAddressIpv6TDO.ps1 - Test if a given string is an IPv6 Network Address
    .PARAMETER  Address
    String array to be tested for IPv6 format.
    .INPUTS
    String Accepts piped input
    .OUTPUTS
    System.Boolean
    .EXAMPLE
    PS> Test-NetAddressIpv6TDO -Address '2603:10b6:610:9f::16'
    
        True

    Test speciried string as an IPv6 Address
    .LINK
    https://github.com/tostka/verb-Network
    #>
    [CmdletBinding()]
    [Alias('Test-NetAddressIpv6')]
    [OutputType([bool])]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0,HelpMessage="Address to be validated")]
        [string[]]$Address
    ) ;
    PROCESS{
        foreach($item in $Address){
            [IPAddress]$item = $item -as [IPAddress] ; 
            [boolean]($item.AddressFamily -eq 'InterNetworkV6') | write-output ;
        } ; 
    } ; 
} ;
#*------^ END Function Test-NetAddressIpv6TDO ^------