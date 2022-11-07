#*------v Function test-IpAddressCidrRange v------
function test-IpAddressCidrRange{
    <#
    .SYNOPSIS
    test-IpAddressCidrRange.ps1 - evaluate an IP Address specification as either IPAddress|CidrRange|IPAddressRange
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2020-
    FileName    : 
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,Network,IPAddress
    AddedCredit : cyruslab (from public forum post, cited as 'https://powershell.org/forums/topic/detecting-if-ip-address-entered/', now gone)
    AddedWebsite: https://cyruslab.net/2018/04/26/powershellcheck-valid-ip-address-subnet-or-ip-address-range/
    AddedTwitter: 
    REVISIONS
    * 10:51 AM 8/13/2021 added to verb-network ; updated base code to work with ip6 CIDR notation ; fixed 
    bug in if/then comparisions: need to coerce subnet mask to integer, for 
    comparison (esp under ip6) ; converted to function updated format to OTB, added 
    CBH, minor param inline help etc. 
    * 4/26/2016 cyruslab posted ps code from earlier unattributed powershell.org forums post (non-function)
    .DESCRIPTION
    test-IpAddressCidrRange.ps1 - evaluate an IP Address specification as either IPAddress|CidrRange|IPAddressRange
    .PARAMETER Address
    IPAddress, CIDR notation, or IP range specification to be tested[-Address 192.168.0.1]
    .INPUTS
    Does not accept piped input
    .OUTPUTS
    System.SystemObject with Type (IPAddress|CIDRRange|IPAddressRange) and boolean Valid properties
    .EXAMPLE
    PS> $ret= test-IpAddressCidrRange -Address 192.168.1.1 ;
    if(($ret.type -eq 'IPAddress' -AND $ret.valid){'Valid IP'} ; 
    Test IP Address
    .EXAMPLE
    PS> $ret= test-IpAddressCidrRange -Address 91.198.224.29/32
    if(( $ret.type -eq 'CIDRRange' -AND $ret.valid){'Valid CIDR'} ; 
    Test CIDR notation block
    .EXAMPLE
    PS> $ret= test-IpAddressCidrRange -Address '192.168.0.1-192.168.0.200' ;
    if($ret.type -eq 'IPAddressRange' -AND $ret.valid){'Valid CIDR'} ; 
    Test IP Address range
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://cyruslab.net/2018/04/26/powershellcheck-valid-ip-address-subnet-or-ip-address-range/
    #>            
    [CmdletBinding()]
    PARAM(
        [Parameter(HelpMessage="IPAddress, CIDR notation, or IP range specification to be tested[-Address 192.168.0.1]")]
        $Address
    ) ;
    $isIPAddr = ($Address -as [IPaddress]) -as [Bool] ;
    $report=[ordered]@{
        Type = $null ;
        Valid = $false ;
    } ;
    write-verbose "specified Address:$($Address)" ;
    if($isIPAddr){
        write-verbose "Valid ip address" ;
        $report.type = 'IPAddress' ;
        $report.Valid = $true ; 
    } elseif($Address -like "*/*" -or $Address -like "*-*"){
        $cidr = $Address.split("/") ;
        if($cidr){ 
            $report.type = 'CIDRRange'
        } ;
        # ip4 CIDR range: 0 to 32
        # ip6 CIDR range: 0 to 128 - need to update to accomodate cidr ip6
        if($Address -like "*:*" -AND [int]$cidr[1] -ge 0 -AND [int]$cidr[1] -le 128){
            # CIDR ip6
            write-verbose "valid ipv6 CIDR subnet syntax" ;
            $report.Valid = $true ; 
        } elseif([int]$cidr[1] -ge 0 -and [int]$cidr[1] -le 32){
            write-verbose "valid ipv4 CIDR subnet syntax" ;
            $report.Valid = $true ; 
        }elseif($Address -like "*-*"){
            $report.type = 'IPAddressRange' ; 
            $ip = $Address.split("-") ; 
            $ip1 = $ip[0] -as [IPaddress] -as [Bool] ; 
            $ip2 = $ip[1] -as [IPaddress] -as [Bool] ; 
            if($ip -and $ip){
                write-verbose "valid ip address range" ;
                $report.Valid = $true ;
            } else{
                write-verbose "invalid range" ;
                $report.Valid = $false ;
            } ;
        } else {
            $report.type = 'INVALID' ;
            $report.Valid = $false ;
            write-warning "invalid subnet" ;
        } ; 
    }else{
        $report.type = 'INVALID' ;
        $report.Valid = $false ;
        write-warning "not valid address" ;
    } ;
    New-Object PSObject -Property $report | write-output ;   
} ; 

#*------^ END Function test-IpAddressCidrRange ^------
