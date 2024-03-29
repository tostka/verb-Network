# Test-NetAddressIpv4TDO.ps1

#*------v Function Test-NetAddressIpv4TDO v------
function Test-NetAddressIpv4TDO {
    <#
    .SYNOPSIS
    Test-NetAddressIpv4TDO.ps1 - Test if a given string is an IPv4 Network Address
    .NOTES
    Version     : 0.0.1
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2024-03-22
    FileName    : Test-NetAddressIpv4TDO.ps1
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
    Test-NetAddressIpv4TDO.ps1 - Test if a given string is an IPv4 Network Address
    .PARAMETER  Address
    String array to be tested for IPv4 format.
    .INPUTS
    String Accepts piped input
    .OUTPUTS
    System.Boolean
    .EXAMPLE
    PS> Test-NetAddressIpv4TDO -Address '2603:10b6:610:9f::16'
    
        True

    Test speciried string as an IPv4 Address
    .LINK
    https://github.com/tostka/verb-Network
    #>
    [CmdletBinding()]
    [Alias('Test-NetAddressIpv4')]
    [OutputType([bool])]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0,HelpMessage="Address to be validated")]
        [string[]]$Address
    ) ;
    PROCESS{
        foreach($item in $Address){
            [IPAddress]$item = $item -as [IPAddress] ; 
            [boolean]($item.AddressFamily -eq 'InterNetwork') | write-output ;
        } ;
    } ;
} ;
#*------^ END Function Test-NetAddressIpv4TDO ^------