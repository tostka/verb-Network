# Test-IPAddressInRangeIp6.ps1

#*------v Function Test-IPAddressInRangeIp6 v------
function Test-IPAddressInRangeIp6 {
    <#
    .SYNOPSIS
    Test-IPAddressInRangeIp6  Tests if an IPv6 address is within a specified CIDR range.
    .NOTES
    Version     : 0.0.1
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2024-12-11
    FileName    : Test-IPAddressInRangeIp6.ps1
    License     : (non asserted)
    Copyright   : (non asserted)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,Network,Ipv6,Subnet,Validate
    AddedCredit : Google AI snippet (returned on Google search)
    AddedWebsite: https://www.google.com/search?q=powershell+test+ipv6+address+is+in+cidr+range
    AddedTwitter: URL
    REVISIONS
    * 4:13 PM 12/11/2024 init rev
    .DESCRIPTION
    This function checks if a given IPv6 address falls within a specified CIDR-notation subnet. It splits the CIDR into the network address and prefix length, converts the IP address and network address to byte arrays, calculates the mask, and then checks if the IP address is in the range.

    Expanded from Google AI offered snippet from search.
    .PARAMETER IPAddress
    IPv6 IP Address to be tested (e.g., "2001:0db8:85a3:0000:0000:8a2e:0370:7334").
    .PARAMETER CIDR
    IPv6 CIDR-notation Subnet to be tested against (e.g., "2001:0db8:85a3::/48").
    .INPUTS
    None. The function does not accept pipeline input.
    .OUTPUTS
    System.Boolean. Returns $true if the IP address is within the CIDR range, otherwise $false.
    .EXAMPLE
    PS> Test-IPAddressInRangeIp6 -IPAddress "2001:0db8:85a3:0000:0000:8a2e:0370:7334" -CIDR "2001:0db8:85a3::/48"
    .LINK
    https://github.com/tostka/verb-Network
    #>
    [CmdletBinding()]
    [Alias('Test-IPv6InCIDR','Alias2')]
    PARAM(
        [Parameter(Mandatory=$True,HelpMessage="IPv6 IP Address to be tested [-Ticket ;'2001:0db8:85a3:0000:0000:8a2e:0370:7334']")]
            [string]$IPAddress,
        [Parameter(Mandatory=$True,HelpMessage="IPv6 CIDR-notation Subnet to be tested against[-Ipv6 CIDR  '2001:0db8:85a3::/48']")]
            [string]$CIDR
    )
    # Split the CIDR into the network address and prefix length
    $network, $prefixLength = $CIDR.Split('/')
    # Convert the IP address and network address to byte arrays
    $ipBytes = [System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes()
    $networkBytes = [System.Net.IPAddress]::Parse($network).GetAddressBytes()
    # Calculate the mask
    $maskBytes = New-Object byte[] 16
    for ($i = 0; $i -lt 16; $i++) {
        #if ($i * 8 < $prefixLength) {
        if ($i * 8 -lt $prefixLength) {
            $maskBytes[$i] = 255 ; 
        #} elseif ($i * 8 < $prefixLength + 8) {
        } elseif ($i * 8 -lt $prefixLength + 8) {
            $maskBytes[$i] = [byte](256 - [Math]::Pow(2, 8 - ($prefixLength % 8))) ; 
        } ; 
    } ; 
    # Check if the IP address is in the range
    for ($i = 0; $i -lt 16; $i++) {
        if (($ipBytes[$i] -band $maskBytes[$i]) -ne ($networkBytes[$i] -band $maskBytes[$i])) {
            return $false ; 
        } ; 
    } ; 
    return $true ; 
} ; 
#*------^ END Function Test-IPAddressInRangeIp6 ^------
