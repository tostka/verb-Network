#*------v Function get-NetworkSubnet v------
        function get-NetworkSubnet {
            <#
            .SYNOPSIS
            get-NetworkSubnet.ps1 - Returns subnet details for the local IP address, or a given network address and mask.
            .NOTES
            Version     : 1.0.0
            Author      : Todd Kadrie
            Website     :	http://www.toddomation.com
            Twitter     :	@tostka / http://twitter.com/tostka
            CreatedDate : 2020-
            FileName    : 
            License     : (none asserted)
            Copyright   : (none asserted)
            Github      : https://github.com/tostka/verb-XXX
            Tags        : Powershell
            AddedCredit : Mark Wragg (markwragg)
            AddedWebsite: https://github.com/markwragg
            AddedTwitter:	URL
            AddedCredit : Michael Samuel
            AddedWebsite: https://stackoverflow.com/users/12068738/michael-samuel
            AddedTwitter:	URL
            REVISIONS
            * 10:16 AM 1/9/2023 ren: get-NetworkSubnet -> get-NetworkSubnet (alias'd  orig name); 
            Tried overide of HostAddressCount .tostring to emit a formatted output (#,###): was blanking the member value, so flipped to a formatted variant property (and still using tostring() on receiving end, needed to do math on the result).
            * 4:08 PM 1/6/2023 adapt get-NetworkSubnet for ipv6 (seeing a ton of ranges in spf includes), used... 
            [Parsing IPv6 CIDR into first address and last address in Powershell - Stack Overflow - stackoverflow.com/](https://stackoverflow.com/questions/42118198/parsing-ipv6-cidr-into-first-address-and-last-address-in-powershell)
            ...Michael Samuel's Sep 15, 2019 at 2:03 sample ipv6 CIDR range calculator code (from comment on q above), and Ron Maupin's comment about diff between Ipv4 maxhosts cacl & ipv6:
            It really comes down to subtract the mask from 128, instead of ipv4's from 32. Math is the same otherwise.
            * 2:53 PM 11/2/2021 refactor/fix CBH
            * 12:33 PM 8/16/2021 renamed/added -Enumerate for prior -force, turned off autoexpansion (unless -enumerate), shifted to maxhosts calc to gen count, vs full expansion & count
            * 1:29 PM 8/12/2021 tweaked CBH, minor param inline help etc.
            * 1:29 PM 5/12/2021 Mark Wragg posted rev (corresponds to PSG v1.1.14)
            .DESCRIPTION
            get-NetworkSubnet.ps1 - Returns subnet details for the local IP address, or a given network address and mask.
            Use to get subnet details  for a given network address and mask, including network address, broadcast address, network class, address range, host addresses and host address count.
            .PARAMETER IP
            The network IP address or IP address with subnet mask via slash notation.
            .PARAMETER MaskBits
            The numerical representation of the subnet mask.
            .PARAMETER Enumerate
            Use to calc & return all host IP addresses regardless of the subnet size (skipped by default)).[-Eunumerate]
            .EXAMPLE
            get-NetworkSubnet 10.1.2.3/24
            Returns the subnet details for the specified network and mask, specified as a single string to the -IP parameter.
            .EXAMPLE
            get-NetworkSubnet 192.168.0.1 -MaskBits 23
            Returns the subnet details for the specified network and mask.
            .EXAMPLE
            get-NetworkSubnet
            Returns the subnet details for the current local IP.
            .EXAMPLE
            '10.1.2.3/24','10.1.2.4/24' | get-NetworkSubnet
            Returns the subnet details for two specified networks.    
            .LINK
            https://github.com/tostka/verb-Network
            .LINK
            https://github.com/markwragg/PowerShell-Subnet/blob/master/Subnet/Public/get-NetworkSubnet.ps1
            #>
            ##Requires -Modules DnsClient
            [CmdletBinding()]
            [Alias('get-Subnet')]
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
                    $LocalIP = (Get-NetIPAddress -Verbose:$($PSBoundParameters['Verbose'] -eq $true) | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.PrefixOrigin -ne 'WellKnown' }) ; 
                    $IP = $LocalIP.IPAddress ; 
                    If ($Mask -notin 0..32) { $Mask = $LocalIP.PrefixLength } ; 
                } ; 

                if ($IP -match '/\d') { 
                    #$IPandMask = $IP -Split '/'  ; 
                    $IP,$Mask = $IP -Split '/'  ; 
                } ; 
        
                $Class = Get-NetworkClass -IP $IP -Verbose:$($PSBoundParameters['Verbose'] -eq $true) ; 

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
                    
                    # IPv6 has no classes, and reportedly IPv4 classes A, B and C have been deprecated since the publication of RFC 1519 in 1993. So fogetabout it
                    $Class = '(Classless)' ; 

                    $IPAddr = [ipaddress]::Parse($IP) ; 

                    # -------
                    #convert IPv6 CIDR to IPv6 range
                    
                    $AllAddresses = '::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
                    #$ipv6cidr = $_
                    $ipv6cidr = $IP,$MASK -join '/' ;  
                    $sw = [Diagnostics.Stopwatch]::StartNew();
                    if ($ipv6cidr -match "[0-9a-f:]+[:]" -and $_ -ne $AllAddresses) {
                        $EndBinaryArray = $StartBinaryArray = $null
                        $NetBits = $($ipv6cidr.Split("/").Replace('::', ''))[1]
                        #Convert To Binary
                        $BinaryEquivalent = $(($ipv6cidr.Split("/").Replace('::', ''))[0].Split(':').ForEach(
                                {
                                    $Decimal = '0x' + $_
                                    [Convert]::ToString($([Uint32]($Decimal)), 2).PadLeft(16, '0')
                                }
                            )
                        ) ; 
                        $BitLength = $BinaryEquivalent.length * 16 ; 
                        $HostId = $BinaryEquivalent -join "" ; 
                        #Adjust for NetMask
                        if ($Netbits -lt $BitLength) {
                            $Difference = $BitLength - $NetBits ; 
                            $HostnetworkId = $HostId -Replace ".{$Difference}$" ; 
                        } ; 
                        if ($Netbits -gt $BitLength) {
                            $Difference = $Netbits - $BitLength ; 
                            $HostnetworkId = [String]::Format("$HostId{0}", $("0" * $Difference)) ; 
                        } ; 
                        if ($Netbits -eq $BitLength) {
                            $HostnetworkId = $HostId ; 
                        } ; 
                        $BinaryStart = $HostnetworkId.PadRight(128, '0') ; 
                        $BinaryEnd = $HostnetworkId.PadRight(128, '1') ; 
                        #Convert Back to Decimal then to Hex
                        While ($BinaryStart) {
                            $Bytes, $BinaryStart = ([char[]]$BinaryStart).where( { $_ }, 'Split', 16) ; 
                            [Array]$StartBinaryArray += $Bytes -join '' ; 
                        } ; 
                        $finalstartip = $HexStartArray = ($StartBinaryArray.ForEach( { '{0:X4}' -f $([Convert]::ToInt32("$_", 2)) })) -join ":" ; 
                        While ($BinaryEnd) {
                            $Bytes, $BinaryEnd = ([char[]]$BinaryEnd).where( { $_ }, 'Split', 16) ; 
                            [Array]$EndBinaryArray += $Bytes -join '' ; 
                        } ; 
                        $finalendip = $HexEndArray = ($EndBinaryArray.ForEach( { '{0:X4}' -f $([Convert]::ToInt32("$_", 2)) })) -join ":" ; 
                        "[{0}] Start: {1} End: {2}" -f $ipv6cidr, $HexStartArray, $HexEndArray ; 
                        $ipv6range+=$finalstartip+'-'+$finalendip ; 
                    } ; 
                    if ($ipv6cidr -eq $AllAddresses) {
                        "[{0}] Start: {1} End: {2}" -f $ipv6cidr, '000:000:000:0000:0000:0000:0000', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff' ; 
                        $ipv6range+='000:000:000:0000:0000:0000:0000'+'-'+'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff' ; 
                    } ; 
                    $sw.Stop() ;
                    write-verbose ("Elapsed Time: {0:dd}d {0:hh}h {0:mm}m {0:ss}s {0:fff}ms" -f $sw.Elapsed) ; 

                    <#[ip - ipv6 number of Host Address - Network Engineering Stack Exchange - networkengineering.stackexchange.com/](https://networkengineering.stackexchange.com/questions/49094/ipv6-number-of-host-address)
                        
                        Just like with IPv4, you subtract the mask length from the size of the address 
                        (32 for IPv4, and 128 for IPv6) to get the number of host bits. Take two to the 
                        power of the number of host bits, and that is how many host addresses you have. 
                        With IPv4, you must subtract two from that number (except for /31 and /32 
                        networks) because you cannot use the network or broadcast addresses. With IPv6, 
                        you can actually use any address in the hosts addresses

                        The standard IPv6 network size is /64, so you will have 128 - 64 = 64 
                        host bits, and that is 2^64 = 18,446,744,073,709,551,616 host addresses in a 
                        standard 64-bit IPv6 network

                        cidr ipv6 subnet: 
                        $cidr = '2a01:4180:4051:0400::/64' ;
                        $ip,$mask = $cidr.split('/') ; 
                        [bigint]$maxhosts = [math]::Pow(2,(128-$Mask)) - 2 ;
                        # also subtracts the bcast & network addrs from the net pool, they're aren't assignable
                        write-verbose "echo with commas for legibility)
                        $maxhosts.tostring("#,###")
                        18,446,744,073,709,551,616 
                    #>
                    # fast way to get a count, wo full expansion
                    #IPV4: $maxHosts=[math]::Pow(2,(32-$Mask)) - 2 ; 
                    #IPV6:
                    $maxHosts=[math]::Pow(2,(128-$Mask)) - 2 ;

                    $NetworkAddr = [ipaddress]$finalstartip ; 
                    $BroadcastAddr = [ipaddress]$finalendip; 
                    $Range = "$NetworkAddr ~ $BroadcastAddr" ; 
                    $MaskAddr = "/$($MASK)" ; # just send back the CIDR mask, simpler
                    #$HostStartAddr = (Convert-IPtoInt64 -ip $NetworkAddr.ipaddresstostring) + 1 ; 
                    #$HostEndAddr = (Convert-IPtoInt64 -ip $broadcastaddr.ipaddresstostring) - 1 ; 

                    if ($Enumerate) {
                        write-warning "This function does not support fully eunmerating ipv6 subnets!" ; 

                    } ; 

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

                    $NetworkAddr = [ipaddress]($MaskAddr.address -band $IPAddr.address); 
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
   
                } ;

                $report = [ordered]@{
                    IPAddress        = $IPAddr
                    MaskBits         = $Mask
                    NetworkAddress   = $NetworkAddr.IPAddressToString 
                    BroadcastAddress = $broadcastaddr.IPAddressToString
                    SubnetMask       = $MaskAddr
                    NetworkClass     = $Class
                    Range            = $Range
                } ; 
                if($Enumerate){
                    $report.add('HostAddresses',$HostAddresses) ;
                    $report.add('HostAddressCount',$HostAddressCount );
                    # back to add a formatted variant
                    $report.add('HostAddressCountString',$HostAddressCount.tostring("#,###") );
                } else {
                    $report.add('HostAddressCount',$maxHosts);
                    $report.add('HostAddressCountString',$maxHosts.tostring("#,###") );
                } ; ;
                <# for some reason overriding outstring completely blanks the hostaddresscount, if it's not an array, include it in the output, right of the |
                # have to capture and post-add-member the override, can't be done on the source hashtable
                $out = New-Object PSObject -Property $report ;
                # overload the HostAddressCount tostring with a formatted output, can't use tostring('#,###'), so use the -f with the .net formatting string for commas (0:N for 2decimal pts; 0:N0 for no decimals)
                #$out.HostAddressCount | Add-Member -MemberType ScriptMethod -Name ToString -Value {
                $out.HostAddressCount = $out.HostAddressCount | Add-Member -MemberType ScriptMethod -Name ToString -Value {
                    '{0:N0}' -f $_.HostAddressCount 
                } -Force -PassThru
                $out | write-output ;  
                #>
                New-Object PSObject -Property $report | write-output ; 
            } ; # PROC-E
            END {}
        } ; 
        #*------^ END Function get-NetworkSubnet ^------