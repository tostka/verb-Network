# Test-IPAddressInRange.ps1

#*------v Function Test-IPAddressInRange v------
        function Test-IPAddressInRange {
            <#
            .SYNOPSIS
            Test-IPAddressInRange - Test an array of IP Addreses for presence in specified CIDR-notated subnet range. 
            .NOTES
            Version     : 0.0.5
            Author      : Todd Kadrie
            Website     : http://www.toddomation.com
            Twitter     : @tostka / http://twitter.com/tostka
            CreatedDate : 2022-11-03
            FileName    : Test-IPAddressInRange
            License     : (none asserted)
            Copyright   : (none asserted)
            Github      : https://github.com/tostka/verb-network
            Tags        : Powershell,Network,Ipv6,Ipv4,Subnet,Validate
            AddedCredit : Nick James (omniomi)
            AddedWebsite: https://github.com/omniomi/PSMailTools/blob/v0.2.0/src/Private/spf/IPInRange.ps1
            AddedTwitter: 
            REVISIONS
            * 4:08 PM 12/11/2024 updated to support Ipv6 addresses & CIDR subnets; also supports auto-flipping inbound -Range as non-cidr notated single IP, into proper ipv4 /32 or ipv6 /128 single-ip CIDR subnet notation,
            to support pipeing resolved/expanded SPF record for valiating spf support for sending server IPs.
            * 11:57 AM 1/5/2023 TSK flipped $IPAddress type from [string] to [ipaddress]; Added CBH, and example; converted to Adv Func syntax; 
            added pipeline support on the IPAddress input ; simplfied compound stmts ; added to verb-Network.
            * Apr 17, 2018 Nick James (omniomi) posted github version from: https://github.com/omniomi/PSMailTools/blob/v0.2.0/src/Private/spf/IPInRange.ps1
            .DESCRIPTION
            Test-IPAddressInRange - Test an array of IP Addreses for presence in specified CIDR-notated subnet range. 

            If an ip address - ipv4 or ipv6 - is specified as the -Range (wo CIDR subnet), as is the case for testing against SPF ip-records, the Range specification is auto-updated to the equiv single-IP CIDR subnet (/32 for ipv4, /128 for ipv6).

            .SYNOPSIS
            Test-IPAddressInRange - Test an array of IP Addreses for presence in specified CIDR-notated subnet range.
            .PARAMETER IPAddress
            Array of ipv4 or ipv6 IP Addresses to be compared to specified Range[-IPAddress 192.168.1.1]
            .PARAMETER Range
            CIDR-notated subnet specification (non-CIDR single ip addresses are auto-patched into equiv /32 or /128 ipv4/ipv6 CIDR single-ip notation)[-Range 10.10.10.10/24

            .INPUTS
            System.String.Array Accepts piped input 
            .OUTPUTS
            System.Boolean
            .EXAMPLE
            PS> Test-IPAddressInRange 10.10.10.230 10.10.10.10/24 ; 
                True
            Feed it an IP and a CIDR address and it returns true or false.
            .EXAMPLE
            PS>  if((Test-IPAddressInRange -IPAddress 10.10.10.230,10.10.11.230 -Range 10.10.10.10/24 -verbose) -contains $false){
            PS>      write-warning 'FAIL!';
            PS>  } else { write-host "TRUE!"} ;
                WARNING: FAIL!
            Test an array of ips against the specified CIDR subnet, and warn if any fails (outside of the subnet).
            .EXAMPLE
            PS> @('10.10.10.230','10.10.11.230') | Test-IPAddressInRange -Range 10.10.10.10/24 -verbose ;
            Pipeline demo, fed with array of ip's, loops each through a test on the specified cidr range.
            .EXAMPLE
            PS> if(Test-IPAddressInRange -IPAddress "2001:0db8:85a3:0000:0000:8a2e:0370:7334" -Range "2001:0db8:85a3::/48" -verbose){
            PS>     write-host -foregroundcolor green  "is in range!" 
            PS> } else { write-host -foregroundcolor yellow "Is NOT in range"} ;
            Test ipv6 IP Address & CIDR subnet
            .EXAMPLE
            PS> write-verbose "Resolve expanded SPF record specificaitons for domain" ; 
            PS> $spfs = Resolve-SPFRecord -Name DOMAIN.COM  ; 
            PS> $ipaddress = '170.92.7.105','fe80::5859:395f:7987:9bc8' ; 
            PS> $verbose= $false ; 
            PS> write-verbose "Test `$ipaddress list entries, against each of the SPF specifications returned" ; 
            PS> foreach($ip in $ipaddress){
            PS>   write-host -foregroundcolor yellow "==Test-IPAddressInRange IP:$($ip)" ; 
            PS>   #$spfs.ipaddress |%{ 
            PS>   foreach($spf in $spfs.ipaddress){
            PS>       $range = $spf ;
            PS>       write-host "==Test in Range:$($range):" ;
            PS>       if(Test-IPAddressInRange -IPAddress $ip -Range $range -Verbose:$($verbose)){
            PS>         write-host -foregroundcolor green "$($ip) is in range:$($range)";
            PS>         break ; 
            PS>       } else{write-host "-"} ;
            PS>   } ;
            PS> } ; 
            Demo resolving out expanded SPF ip specifications, and then testing a series of IP Addresses against those returned spf specifications 
            (non-CIDR single addresses from SPF record are auto-patched by this script into equiv /32 or /128 ipv4/ipv6 CIDR single-ip notation inputs).
            .LINK
            https://github.com/tostka/verb-network
            .LINK
            https://github.com/omniomi/PSMailTools/blob/v0.2.0/src/Private/spf/IPInRange.ps1
            #>
            # VALIDATORS: [ValidateNotNull()][ValidateNotNullOrEmpty()][ValidateLength(24,25)][ValidateLength(5)][ValidatePattern("some\sregex\sexpr")][ValidateSet("US","GB","AU")][ValidateScript({Test-Path $_ -PathType 'Container'})][ValidateScript({Test-Path $_})][ValidateRange(21,65)]#positiveInt:[ValidateRange(0,[int]::MaxValue)]#negativeInt:[ValidateRange([int]::MinValue,0)][ValidateCount(1,3)]
            [outputtype([System.Boolean])]
            [Alias('test-IPInRange')]
            [CmdletBinding()]
            PARAM(
                [parameter(Mandatory=$true, Position=0,ValueFromPipeline = $True,HelpMessage="Array of ipv4 or ipv6 IP Addresses to be compared to specified Range[-IPAddress 192.168.1.1]")]
                    #[validatescript({([System.Net.IPAddress]$_).AddressFamily -eq 'InterNetwork'})] # covers solely ipv4
                    # cover both ipv4 & ipv6
                    [validatescript({([System.Net.IPAddress]$_).AddressFamily -match '^(InterNetwork|InterNetworkV6)$'})]
                    [ipaddress[]]$IPAddress,
                [parameter(Mandatory,Position=1,HelpMessage="CIDR-notated subnet specification (non-CIDR single ip addresses are auto-patched into equiv /32 or /128 ipv4/ipv6 CIDR single-ip notation)[-Range 10.10.10.10/24")]
                    [alias('CIDR')]
                    [string]$Range
            ) ;
            BEGIN{
                #region CONSTANTS-AND-ENVIRO #*======v CONSTANTS-AND-ENVIRO v======
                # function self-name (equiv to script's: $MyInvocation.MyCommand.Path) ;
                ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
                #region BANNER ; #*------v BANNER v------
                $sBnr="#*======v $(${CmdletName}): v======" ;
                $smsg = $sBnr ;
                write-verbose "$($smsg)"  ;
                #endregion BANNER ; #*------^ END BANNER ^------
                $verbose = ($VerbosePreference -eq "Continue") ;
                $PSParameters = New-Object -TypeName PSObject -Property $PSBoundParameters ;
                write-verbose -message "`$PSBoundParameters:`n$(($PSBoundParameters|out-string).trim())" ;
                #endregion CONSTANTS-AND-ENVIRO ; #*------^ END CONSTANTS-AND-ENVIRO ^------       

                #*======v FUNCTIONS v======

                #*------v Function Test-IPAddressInRangeIp6 v------
                if(-not (get-command Test-IPAddressInRangeIp6 -ea 0)){
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
                        * 3:16 PM 12/11/2024 init rev
                        .DESCRIPTION
                        This function checks if a given IPv6 address falls within a specified CIDR-notation subnet. .

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
                } ; 
                #*------^ END Function Test-IPAddressInRangeIp6 ^------

                #*======^ END FUNCTIONS ^======

                # $CIDR, feeding these in from SPF records, some are raw single IP, so detect them and tack a single-IP CIDR /32 on them
                <# In most modern routers (post 1998) have classless routing, (CIDR) in classless routing is a single IP address 1.2.3.4 equivalent to 1.2.3.4/32
                for IPV6 single IP it's a /128 e.g. fe80::1/128 or ::/128 or 2001:db8:3973:08ef:08ef:c7ba:96a6:49c8/128/128
                #>
                # 9:47 AM 12/11/2024 moved validation here: validation reapplies on any update of the vary, and fails flipping from IP to /32 CIDR subnet.
                #if($Range -notcontains '/'){
                if($Range.Contains('/')){
                    write-verbose "-range:$($Range) confirmed has an Address and Bitmask w / delimiter" ; 
                }else{
                    TRY{
                        if($Range -like "*.*" -AND  ([System.Net.IPAddress]($Range)).AddressFamily -eq 'InterNetwork'){
                            write-host "Range is single ip4 IP: Coercing -Range:$($Range) to single IP ip4 '/32' CIDR range input:`n$($Range)/32" ; 
                            $Range = "$($Range)/32"
                        #}elseif((($Range -like "*:*" -AND [System.Net.IPAddress]($IP)).AddressFamily -eq 'InterNetworkV6'){
                        }elseif($Range -like "*:*" -AND ([System.Net.IPAddress]($Range)).AddressFamily -eq 'InterNetworkV6'){
                            write-host "Range is single ip6 IP: Coercing -Range:$($Range) to single IP ip6 '/128' CIDR range input:`n$($Range)/128" ; 
                            $Range = "$($Range)/128"
                        }  ; 
                    }CATCH{write-warning "-range:$($Range) has no Bitmask / delimiter, and doesn't convert cleanly to [ipaddress]" } ; 
                } ;
                # moving active validation down here.
                <#$IP,$Bits  = $Range -split '/' 
                    if(([System.Net.IPAddress]($IP)).AddressFamily -match 'InterNetwork|InterNetworkV6'){}else{
                        $smsg = "resolved -Range $($range) IP - $($IP), does not resolve to ipv4 (AddressFamily:InterNetwork) or ipv6 (AddressFamily:InterNetworkV6)!" ; 
                        throw $smsg ; 
                        break ; 
                    } ;
                if (-not($Bits)) {
                    throw 'Missing CIDR notiation.' 
                #} elseif (-not(0..32 -contains [int]$Bits)) { # ipv4 cidr rang
                } elseif (-not(0..128 -contains [int]$Bits)) {
                    #throw 'Invalid CIDR notation. The valid bit range is 0 to 32.' ; 
                    throw 'Invalid CIDR notation. The valid bit range is 0 to 128.' ; 
                } ; 
                #>
                <#
                if($Range -notcontains '/'){
                    if(([System.Net.IPAddress]($Range)).AddressFamily -eq 'InterNetwork'){
                        $Range = "$($Range)/32"
                        write-host "Range is single ip4 IP: Coercing -Range:$($Range) to single IP ip4 '/32' CIDR range input:`n$($Range)" ; 
                    }elseif( ($Range -like "*:*") -AND ([System.Net.IPAddress]($IP)).AddressFamily -eq 'InterNetworkV6'){
                        $Range = "$($Range)/128"
                        write-host "Range is single ip6 IP: Coercing -Range:$($Range) to single IP ip6 '/128' CIDR range input:`n$($Range)" ; 
                        
                    }  ; 
                }
                #>

                write-verbose "Split Range into the address and the CIDRBits notation" ; 
                [String]$CIDRAddress,[int]$CIDRBits = $Range.Split('/') ; 
                if(([System.Net.IPAddress]($CIDRAddress)).AddressFamily -match 'InterNetwork|InterNetworkV6'){}else{
                    $smsg = "resolved -Range $($range) IP - $($CIDRAddress), does not resolve to ipv4 (AddressFamily:InterNetwork) or ipv6 (AddressFamily:InterNetworkV6)!" ; 
                    throw $smsg ; 
                    break ; 
                } ;
                if (-not($CIDRBits)) {
                    throw 'Missing CIDR notiation.' 
                #} elseif (-not(0..32 -contains [int]$CIDRBits)) { # ipv4 cidr rang
                } elseif (-not(0..128 -contains [int]$CIDRBits)) {
                    #throw 'Invalid CIDR notation. The valid bit range is 0 to 32.' ; 
                    throw 'Invalid CIDR notation. The valid bit range is 0 to 32 (ipv4) 0 to 128 (ipv6).' ; 
                } ; 

                # ip4 CIDR range: 0 to 32
                # ip6 CIDR range: 0 to 128 - need to update to accomodate cidr ip6
                $CIDRisIp6 = $CIDRisIp4 = $false ;
                if($CIDRAddress -like "*:*" -AND [int]$CIDRBits -ge 0 -AND [int]$CIDRBits -le 128){
                    # CIDR ip6
                    write-verbose "valid ipv6 CIDR subnet syntax" ;
                    #$report.Valid = $true ; 
                    $CIDRisIp6 = $true ; 
                } elseif([int]$CIDRBits -ge 0 -and [int]$CIDRBits -le 32){
                    write-verbose "valid ipv4 CIDR subnet syntax" ;
                    #$report.Valid = $true ; 
                    $CIDRisIp4 = $true ; 
                }

                if ($PSCmdlet.MyInvocation.ExpectingInput) {
                    write-verbose -message "Data received from pipeline input: '$($InputObject)'" ; 
                } else {
                    #write-verbose "Data received from parameter input: '$($InputObject)'" ; 
                    write-verbose -message "(non-pipeline - param - input)" ; 
                } ; 
            } ; 
            PROCESS{
                foreach($item in $IPAddress){
                    $sBnrS="`n#*------v PROCESSING : $($item.IPAddressToString) against CIDR range: $($Range) v------" ; 
                    write-verbose -message "$($sBnrS)" ;
                    if($CIDRisIp4){
                        write-verbose "Address from range and the search address are converted to Int32 and the full mask is calculated from the CIDR notation."
                        [int]$BaseAddress    = [System.BitConverter]::ToInt32((([System.Net.IPAddress]::Parse($CIDRAddress)).GetAddressBytes()), 0) ; 
                        [int]$Address        = [System.BitConverter]::ToInt32(([System.Net.IPAddress]::Parse($item).GetAddressBytes()), 0) ; 
                        [int]$Mask           = [System.Net.IPAddress]::HostToNetworkOrder(-1 -shl ( 32 - $CIDRBits)) ; 

                        write-verbose "Determine whether the address is in the range. (-band == bitwise-AND)"
                        if (($BaseAddress -band $Mask) -eq ($Address -band $Mask)) {
                            $true | write-output ; 
                        } else {
                            #$false | write-output  ; # 1:12 PM 12/11/2024 no return unless true
                        } ;  
                    }elseif($CIDRisIp6){
                        <# having trouble getting ported to work, passes everything, defer to the canned function
                        # Convert to byte arrays
                        $ipBytes = [System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes() ; 
                        $networkBytes = [System.Net.IPAddress]::Parse($CIDRAddress).GetAddressBytes() ; 
                        # Calculate the mask
                        $maskBytes = New-Object byte[] 16 ; 
                        for ($i = 0; $i -lt 16; $i++) {
                            #if ($i * 8 < $prefixLength) {
                            if ($i * 8 -lt $prefixLength) {
                                $maskBytes[$i] = 255 ; 
                            #} elseif ($i * 8 < $CIDRBits+ 8) {
                            } elseif ($i * 8 -lt $CIDRBits+ 8) {
                                $maskBytes[$i] = [byte](256 - [Math]::Pow(2, 8 - ($CIDRBits% 8))) ; 
                            } ; 
                        } ; 
                        # Check IP address in range
                        for ($i = 0; $i -lt 16; $i++) {
                            if (($ipBytes[$i] -band $maskBytes[$i]) -ne ($networkBytes[$i] -band $maskBytes[$i])) {
                                return $false ; 
                            } ; 
                        } ; 
                        return $true ; 
                        #>

                        if(Test-IPAddressInRangeIp6 -IPAddress $item.IPAddressToString -CIDR $Range -Verbose:($PSBoundParameters['Verbose'] -eq $true)){
                            $true | write-output 
                        } 
                    } ;
                    write-verbose -message "$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;

                } ;  # loop-E
            }  # PROC-E
            END{
                write-verbose -message "$($sBnr.replace('=v','=^').replace('v=','^='))" ;
            } ;
        } ; 
        #*------^ END Function Test-IPAddressInRange ^------