#*------v Function get-Subnet v------
function get-Subnet {
    <#
    .SYNOPSIS
    get-Subnet.ps1 - Returns subnet details for the local IP address, or a given network address and mask.
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
    Tags        : Powershell,Network,IP,Subnet
    AddedCredit : Mark Wragg
    AddedWebsite: https://github.com/markwragg
    AddedTwitter: 
    REVISIONS
    * 12:33 PM 8/16/2021 renamed/added -Enumerate for prior -force, turned off autoexpansion (unless -enumerate), shifted to maxhosts calc to gen count, vs full expansion & count
    * 1:29 PM 8/12/2021 tweaked CBH, minor param inline help etc.
    * 1:29 PM 5/12/2021 Mark Wragg posted rev (corresponds to PSG v1.1.14)
    .DESCRIPTION
    get-Subnet.ps1 - Returns subnet details for the local IP address, or a given network address and mask.
    Use to get subnet details  for a given network address and mask, including network address, broadcast address, network class, address range, host addresses and host address count.
    .PARAMETER IP
    The network IP address or IP address with subnet mask via slash notation.
    .PARAMETER MaskBits
    The numerical representation of the subnet mask.
    .PARAMETER Enumerate
    Use to calc & return all host IP addresses regardless of the subnet size (skipped by default)).[-Eunumerate]
    .EXAMPLE
    Get-Subnet 10.1.2.3/24
    Description
    -----------
    Returns the subnet details for the specified network and mask, specified as a single string to the -IP parameter.
    .EXAMPLE
    Get-Subnet 192.168.0.1 -MaskBits 23
    Description
    -----------
    Returns the subnet details for the specified network and mask.
    .EXAMPLE
    Get-Subnet
    Description
    -----------
    Returns the subnet details for the current local IP.
    .EXAMPLE
    '10.1.2.3/24','10.1.2.4/24' | Get-Subnet
    Description
    -----------
    Returns the subnet details for two specified networks.    
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://github.com/markwragg/PowerShell-Subnet/tree/master/Subnet/Public
    #>
    ##Requires -Modules DnsClient
    [CmdletBinding()]
    PARAM (
        [parameter(ValueFromPipeline,HelpMessage="The network IP address or IP address with subnet mask via slash notation.[-IP 192.168.0.1]")]
        [string]$IP,
        [parameter(HelpMessage="The numerical representation of the subnet mask.[-MaskBits 23]")]
        [ValidateRange(0, 32)]
        [Alias('CIDR')]
        [int]$MaskBits,
        #[parameter(HelpMessage="Use to force the return of all host IP addresses regardless of the subnet size (skipped by default for subnets larger than /16).[-Force]")]
        #[switch]$Force
        [parameter(HelpMessage="Use to calc & return all host IP addresses regardless of the subnet size (skipped by default)).[-Eunumerate]")]
        [switch]$Enumerate
    )
    BEGIN {
        ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
        $Verbose = ($VerbosePreference -eq 'Continue') ; 
    } ;  # BEG-E
    PROCESS {

        if ($PSBoundParameters.ContainsKey('MaskBits')) { 
            $Mask = $MaskBits  ; 
        } ; 

        if (-not $IP) { 
            $LocalIP = (Get-NetIPAddress | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.PrefixOrigin -ne 'WellKnown' }) ; 
            $IP = $LocalIP.IPAddress ; 
            If ($Mask -notin 0..32) { $Mask = $LocalIP.PrefixLength } ; 
        } ; 

        if ($IP -match '/\d') { 
            $IPandMask = $IP -Split '/'  ; 
            $IP = $IPandMask[0] ; 
            $Mask = $IPandMask[1] ; 
        } ; 
        
        $Class = Get-NetworkClass -IP $IP ; 

        <# detecting ipv6 - core was written for ipv4...
        # ip4 CIDR range: 0 to 32
        # ip6 CIDR range: 0 to 128 - need to update to accomodate cidr ip6
        if($Address -like "*:*" -AND [int]$cidr[1] -ge 0 -AND [int]$cidr[1] -le 128){
            # CIDR ip6
            write-verbose "valid ipv6 CIDR subnet syntax" ;
            $report.Valid = $true ; 
        } elseif([int]$cidr[1] -ge 0 -and [int]$cidr[1] -le 32){}
        #>

        if($IP -like "*:*" -AND [int]$Mask -ge 0 -AND [int]$Mask -le 128){
                write-warning "ipv6 CIDR detected: unsupported to expand subnet specs with this function" ; 
                $false | write-output ; 
        }else{
        
            if ($Mask -notin 0..32) {
                $Mask = switch ($Class) {
                    'A' { 8 }
                    'B' { 16 }
                    'C' { 24 }
                    #'Single' { 32 } # just marking 32 indicates a single IP, not used in code below
                    default { 
                        throw "Subnet mask size was not specified and could not be inferred because the address is Class $Class." 
                    }
                } ; 
                Write-Warning "Subnet mask size was not specified. Using default subnet size for a Class $Class network of /$Mask." ; 
            } ; 

            $IPAddr = [ipaddress]::Parse($IP) ; 
            $MaskAddr = [ipaddress]::Parse((Convert-Int64toIP -int ([convert]::ToInt64(("1" * $Mask + "0" * (32 - $Mask)), 2)))) ; 

            # fast way to get a count, wo full expansion
            $maxHosts=[math]::Pow(2,(32-$Mask)) - 2 ; 

            $NetworkAddr = [ipaddress]($MaskAddr.address -band $IPAddr.address) ; 
            #$BroadcastAddr = [ipaddress](([ipaddress]::parse("255.255.255.255").address -bxor $MaskAddr.address -bor $NetworkAddr.address)) ; 
            # inacc, returning 255.255.255.255 for 170.92.0.0/16
            # Add-IntToIPv4Address -IPv4Address 10.10.0.252 -Integer 10
            $BroadcastAddr = [ipaddress](Add-IntToIPv4Address -IP $NetworkAddr.IPAddressToString  -Integer ($maxHosts+1)) ; 
            $Range = "$NetworkAddr ~ $BroadcastAddr" ; 
        
            $HostStartAddr = (Convert-IPtoInt64 -ip $NetworkAddr.ipaddresstostring) + 1 ; 
            $HostEndAddr = (Convert-IPtoInt64 -ip $broadcastaddr.ipaddresstostring) - 1 ; 
        

            #if ($Mask -ge 16 -or $Force) {
            if ($Enumerate) {
                Write-Progress "Calcualting host addresses for $NetworkAddr/$Mask.." ; 
                if ($Mask -ge 31) {
                    $HostAddresses = ,$NetworkAddr ; 
                    if ($Mask -eq 31) {
                        $HostAddresses += $BroadcastAddr ; 
                    } ; 

                    $HostAddressCount = $HostAddresses.Length ; 
                    $NetworkAddr = $null ; 
                    $BroadcastAddr = $null ; 
                } else {
                    $HostAddresses = for ($i = $HostStartAddr; $i -le $HostEndAddr; $i++) {
                        Convert-Int64toIP -int $i ; 
                    }
                    $HostAddressCount = ($HostEndAddr - $HostStartAddr) + 1 ; 
                }                     
            } ; 
            # more interested in the count than specific ips
            <#else {
                Write-Warning "Host address enumeration was not performed because it would take some time for a /$Mask subnet. `nUse -Force if you want it to occur." ; 
            } ; 
            #>

            $report = [ordered]@{
                IPAddress        = $IPAddr
                MaskBits         = $Mask
                NetworkAddress   = $NetworkAddr
                BroadcastAddress = $broadcastaddr
                SubnetMask       = $MaskAddr
                NetworkClass     = $Class
                Range            = $Range
            } ; 
            if($Enumerate){
                $report.add('HostAddresses',$HostAddresses) ;
                $report.add('HostAddressCount',$HostAddressCount );
            } else {
                $report.add('HostAddressCount',$maxHosts);
            } ; ;

            <#[pscustomobject]@{
                IPAddress        = $IPAddr
                MaskBits         = $Mask
                NetworkAddress   = $NetworkAddr
                BroadcastAddress = $broadcastaddr
                SubnetMask       = $MaskAddr
                NetworkClass     = $Class
                Range            = $Range
                HostAddresses    = $HostAddresses
                HostAddressCount = $HostAddressCount
            } ; 
            #>

            New-Object PSObject -Property $report | write-output ;    
        } ;

    } ; # PROC-E
    END {}
} ; 
#*------^ END Function get-Subnet ^------