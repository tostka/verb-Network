# convert-IPAddressToReverseTDO.ps1

#*------v Function convert-IPAddressToReverseTDO v------
#if(-not (get-command convert-IPAddressToReverseTDO -ea 0)){
    function convert-IPAddressToReverseTDO {
        <#
        .SYNOPSIS
        Reverse IP Address. 
        .NOTES
        Version     : 0.0.1
        Author      : Todd Kadrie
        Website     : http://www.toddomation.com
        Twitter     : @tostka / http://twitter.com/tostka
        CreatedDate : 2025-01-02
        FileName    : convert-IPAddressToReverseTDO.ps1
        License     : (none asserted)
        Copyright   : (none asserted)
        Github      : https://github.com/tostka/verb-Network
        Tags        : Powershell,TCP,IPAddress
        AddedCredit : REFERENCE
        AddedWebsite: URL
        AddedTwitter: URL
        * 4:02 PM 1/2/2025 coded in solid ipv6 support (IP reverse process is diff ipv4 & ipv6)
            ren Reverse-IP -> convert-IPAddressToReverseTDO, alias Reverse-IP
        * 8:58 AM 1/2/2025 generated source via Copilot
        .DESCRIPTION
        Reverse IPAddress Address (ipv4 or ipv6). 

        Was originally cheating my way to the IPv6 reverse by resolving a PTR, and cutting the returned PTR record name at .ipv6', and taking the left half. 
        But [Shortest Script Challenge - Convert IPv6 to nibble format : r/PowerShell](https://www.reddit.com/r/PowerShell/comments/6wcpfv/shortest_script_challenge_convert_ipv6_to_nibble/)
        outlined a series of algos to get to the same thing, wo the PTR resolution step.

        .PARAMETER IPAddress
        The IPAddress address to be used in macro expansion.
        .INPUTS
        None. The script does not accept pipeline input.
        .OUTPUTS
        System.String The Reversed IP Address
        .EXAMPLE
        PS> $IPRev = convert-IPAddressToReverseTDO -ipaddress 192.168.1.1 ; 
        Reverse an IPv4 addres
        .EXAMPLE
        PS> $IPAddress = (resolve-dnsname -name ipv6.google.com | ?{$_.Type -eq 'AAAA'} |select -expand ipaddress) ; 
        PS> $IPRev = convert-IPAddressToReverseTDO  -ipaddress $ipaddress.IPAddressToString ; 
            
            Ipv6 address specified:2607:f8b0:4009:817::200e

        PS> $IPRev ; 
            
            E.0.0.2.0.0.0.0.0.0.0.0.0.0.0.0.7.1.8.0.9.0.0.4.0.B.8.F.7.0.6.2

        Reverse an IPv6 address
        .LINK
        https://github.com/tostka/verb-Network
        #>    
        [CmdletBinding()]
        [Alias('Reverse-IP')]
        PARAM(
            [Parameter(Mandatory=$TRUE,HelpMessage="IPAddress (supports ipv4 & ipv6)[-IPAddress 192.168.1.1]")]
            [system.net.ipaddress]$IPAddress
        ) ; 
        switch($IPAddress.AddressFamily){
            'InterNetwork' { 
                write-verbose "Ipv4 address specified:$($IPAddress)" ; 
                return ($IP -split '\.')[-1..0] -join '.' ; 
            }
            'InterNetworkV6' { 
                write-verbose "Ipv6 address specified:$($IPAddress.IPAddressToString)" ; 
                <# doing it by pulling a PTR, and cutting the trailing .ip6.. from the returned record Name (select unique)
                if($resolvedPTR = resolve-dnsname -name $IPAddress.IPAddressToString -type PTR -server 1.1.1.1){
                    return (($resolvedPTR | select -unique name).name  -replace '.ip6.arpa')
                } else {
                    $smsg = "Unable to:resolve-dnsname -name $($IPAddress.IPAddressToString) -type PTR -server 1.1.1.1!" ; 
                    write-warning $smsg ; 
                    throw $smsg ;
                    return $false ;
                }; 
                #>
                # or doing it using the [Shortest Script Challenge - Convert IPv6 to nibble format : r/PowerShell](https://www.reddit.com/r/PowerShell/comments/6wcpfv/shortest_script_challenge_convert_ipv6_to_nibble/)
                # param($i)
                #((([ipaddress]$i)|% GetA*|%{('{0:x2}'-f$_)[0,1]})[31..0]-join'.')+".ip6.arpa"
                # we don't need the ip6.arpa trailing bit, just the algo to flip the elements.
                #return ((([ipaddress]$IPAddress.IPAddressToString)|% GetA*|%{('{0:x2}'-f$_)[0,1]})[31..0]-join'.') ; 
                # expanded a bit, less compressed logic:
                $i=[bitconverter]::ToString( [IPAddress]::Parse($IPAddress.IPAddressToString).GetAddressBytes()).Replace('-','').ToCharArray() ; 
                [array]::Reverse($i);
                return ($i -join ".") # +'.ip6.arpa' 
                # dropped trailing string from the above linked example: the ip6.arpa is the PTR record name, we just want the reversed ipv6 IP, to use in the %{ir} macro replacements
            }
        } ; 
    } ; 
#} ; 
#*------^ END Function convert-IPAddressToReverseTDO ^------