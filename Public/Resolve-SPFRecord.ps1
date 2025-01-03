#*------v Function Resolve-SPFRecord v------
function Resolve-SPFRecord {
    <#
    .SYNOPSIS
    resolve-SPFRecord.ps1 - This expands the specified domainName's SPF record: 1. Expands any discovered SPF macros, 2. Accumulates all ip[46]: IP specifications; 3. Recursively expands nested include:'s; and 4. Adds expanded IP range specification for 'exists':, 'mx:' & 'a:' mechanisms. Then returns the resulting assembled IP range specifications to the pipeline. 
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
    Tags        : Powershell
    AddedCredit : Fabian Bader
    AddedWebsite: https://cloudbrothers.info/en/
    AddedTwitter: 
    REVISION
    * 4:28 PM 1/3/2025 finally rounded out, to return full stack of Pass Subnet IP specifications, for post-review and test-IPAddressInRange() checking
    * 2:21 PM 1/2/2025 $DomainName/Name update $Name/Domainname regex to make the CN portion optional (fails toro.com, but has to accomodate recursive include:calls to resolve _spf.salesforce.com)
    * 12:36 PM 12/12/2024 add: alias:Resolve-DNSNameSPF, param alias: $name: 'DomainName', 'Domain'
    * 4:11 PM 12/10/2024 added explicit write-output's, a few w-v's, some comments to make the logic more clear. 
    * 3:46 PM 11/2/2021 flipped some echos to wv ;  CBH minor cleanup
    * 2:28 PM 8/16/2021 spliced in simple summarize of ipv4 CIDR subnets (range, # usable ips in range etc), leveraging combo of Mark Wragg get-subnet() and a few bits from Brian Farnsworth's Get-IPv4Subnet() (which pulls summaries wo fully enumeratinfg every ip - much faster)
    * 12:25 PM 8/13/2021Add ip4/6 syntax testing/simple validation (via 
    test-IpAddressCidrRange, sourced in verb-network, local deferral copy) ; 
    extended verbose echos ; add case for version spec & [~+-?]all (suppress spurious 
    warnings) ; expanded macro/explanation mechanism warnings (non-invalid: just script 
    doesn't support their expansion/validation). Added examples for grouping referrer and 
    dumping summaries per referrer. 
    * 1:29 PM 8/12/2021 updated format to OTB, added CBH, minor param inline help etc.
    * 1:29 PM 4/12/2021 Fabian Bader posted rev
    .DESCRIPTION
    resolve-SPFRecord.ps1 - This expands the specified domainName's SPF record: 1. Expands any discovered SPF macros, 2. Accumulates all ip[46]: IP specifications; 3. Recursively expands nested include:'s; and 4. Adds expanded IP range specification for 'exists':, 'mx:' & 'a:' mechanisms. Then returns the resulting assembled IP range specifications to the pipeline. 
    
    Started from posted, somewhat incomplete code at below (lacked Macro, and range of less common mechanisms, support)

        #-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        From [PowerShell Tip: Resolve SPF Records - Cloudbrothers - cloudbrothers.info/](https://cloudbrothers.info/en/powershell-tip-resolve-spf/):
        ## Supported SPF directives and functions: 
            - include
            - mx
            - a
            - ip4 und ip6
            - redirect
            - Warning for too many include entries
        ## Not supported: 
            - exp
            - Macros
            - Usage
     
        Optionally, the Server (DNS) parameter can be used. Defaults to cloudflare resolver: 1.1.1.1 (secondary is 1.0.0.1)
        documented here: [Introducing DNS Resolver, 1.1.1.1 (not a joke) - blog.cloudflare.com/](https://blog.cloudflare.com/dns-resolver-1-1-1-1/)
    
        Specify explicit DNS server to be queried. Useful, if you want to test the DNS changes directly on your own root name server shortly after the update, or if there are restrictions on which DNS server your client is allowed to query.
        #-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

    - Added Macro-expansion support (via verb-network\resolve-SpfMacrosTDO()). 
    - added exists:, and sketched in ptr: support pulled core RFC docs that firmly indicate deprecated option 
        
    .PARAMETER Name
    Domain Name[-Name some.tld]
    .PARAMETER Server
    DNS Server to use (defaults to Cloudflare public resolver 1.1.1.1)[-Server 1.0.0.1]
    .PARAMETER Referrer
    If called nested provide a referrer to build valid objects[-Referrer referrer]
    .PARAMETER IPAddress
    OptionalSending server IP Address to be tested against the domain SPF record (required to attempt to expand macros)[-IPAddress 192.168.1.1]
    .PARAMETER SenderAddress
    Optional SenderAddress to use for '%{d}','%{s}','%{s}','%{o}' SenderAddress based macros (required to attempt to expand macros)[-SenderAddress email@domain.tld]
    .PARAMETER RawOutput
    Switch to return the raw resolved strings to the pipeline (vs summary [pscustomobject])
    .INPUTS
    Accepts piped input
    .OUTPUTS
    None. Returns no objects or output (.NET types)
    System.Boolean
    [| get-member the output to see what .NET obj TypeName is returned, to use here]
    .EXAMPLE
    PS> Resolve-SPFRecord -Name domainname.tld
    For the query of the corresponding TXT records in the DNS only the paramater name is needed
    .EXAMPLE
    PS> Resolve-SPFRecord -Name domainname.tld | ft
    It is recommended to output the result with 'Format-Table' for better readability.
    .EXAMPLE
    PS> $spfs = Resolve-SPFRecord -name domain.com ; 
    PS> $spfs| ft -a

        SPFSourceDomain               IPAddress               Referrer     Qualifier Include
        ---------------               ---------               --------     --------- -------
        domain.com                    148.163.146.158                      softfail    False
        domain.com                    148.163.142.153                      softfail    False
        domain.com                    170.92.0.0/16                        softfail    False
        spf.protection.outlook.com    40.92.0.0/15            domain.com   fail         True
        spf.protection.outlook.com    40.107.0.0/16           domain.com   fail         True
        spf.protection.outlook.com    52.100.0.0/15           domain.com   fail         True
        spf.protection.outlook.com    52.102.0.0/16           domain.com   fail         True
        spf.protection.outlook.com    52.103.0.0/17           domain.com   fail         True
        spf.protection.outlook.com    104.47.0.0/17           domain.com   fail         True
        spf.protection.outlook.com    2a01:111:f400::/48      domain.com   fail         True
        spf.protection.outlook.com    2a01:111:f403::/49      domain.com   fail         True
        spf.protection.outlook.com    2a01:111:f403:8000::/51 domain.com   fail         True
        spf.protection.outlook.com    2a01:111:f403:c000::/51 domain.com   fail         True
        spf.protection.outlook.com    2a01:111:f403:f000::/52 domain.com   fail         True
        111368.spf10.hubspotemail.net 3.93.157.0/24           domain.com   fail         True
        ...
        111368.spf10.hubspotemail.net 216.139.64.0/19         domain.com   fail         True

    .EXAMPLE
    PS> $spfs = Resolve-SPFRecord -name domain.com ; 
    PS> write-verbose "group referrers" ; 
    PS> $spfs | group referrer | ft -auto count,name ;
     
        Count Name                      
        ----- ----                      
            3                           
            10 domain.com                  
            9 spf.protection.outlook.com

    PS> write-verbose "output ip summary for a specific referrer"
    PS> $spfs|?{$_.Referrer  -eq 'spf.protection.outlook.com'} | ft -auto ipaddress,referrer ; 

        IPAddress                Referrer                  
        ---------                --------                  
        51.4.72.0/24             spf.protection.outlook.com

    Broader example, group/profile returned referrers, dump summaries on referrers
    .EXAMPLE
    PS> write-verbose "Define inputs, and Macro-expansion-dependant specifications" ; 
    PS> $pltDomSpecs = [ordered]@{
    PS>     DomainName = 'bossplow.com' ;
    PS>     IPAddress = '170.92.7.36' ;
    PS>     SenderAddress = 'todd.kadrie@bossplow.com' ;
    PS>     SenderHeloName = 'mymailoutlyn0.toro.com' ;
    PS>     verbose = $true ;
    PS> } ;
    PS> write-verbose "Resolve populated specifications above, and process through Resolve-SPFRecord" ; 
    PS> $mts = $pltDomSpecs.GetEnumerator() | ?{ -NOT ($_.Value -AND $_.value.length)}
    PS> $mts | ForEach-Object { $pltDomSpecs.remove($_.Key) } ;
    PS> write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):Resolve-SPFRecord w`n$(($pltDomSpecs|out-string).trim())" ;
    PS> $results = Resolve-SPFRecord @pltDomSpecs ;
    PS> write-verbose "Process returned results, checking for specified IPAddress above within returned 'pass' subnets : => Approved SPF deliveries for host" ; 
    PS> $PassSubnets = $results.ipaddress ;
    PS> $smsg = "==$($pltDomSpecs.DomainName) expanded SPF returned $($PassSubnets|  measure | select -expand count) 'Pass' subnets" ;
    PS> $smsg += "`n$(($PassSubnets |out-string).trim())" ;
    PS> write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)"  ;
    PS> write-host "Processing the list in order, for IPAddress:$($pltDomSpecs.IPAddress) within each..." ;
    PS> $foundPass = $false ;
    PS> $pltTIpInSub=[ordered]@{
    PS>     IPAddress = $pltDomSpecs.IPAddress ;
    PS>     Range = $null ;
    PS>     Verbose = ($PSBoundParameters['Verbose'] -eq $true)
    PS> } ;
    PS> foreach($subn in $PassSubnets){
    PS>     $smsg = $sBnrS="`n#*------v TESTING $($pltDomSpecs.IPAddress) against:$($subn) v------" ;
    PS>     write-verbose $smsg ; 
    PS>     $pltTIpInSub.Range = $subn ;
    PS>     $smsg = "Test-IPAddressInRange  w`n$(($pltTIpInSub|out-string).trim())" ;
    PS>     if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE }
    PS>     else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
    PS>     if(Test-IPAddressInRange @pltTIpInSub){
    PS>         $foundPass = $true ;
    PS>         $smsg = "==> Matched $($pltDomSpecs.IPAddress) against:$($subn) !" ;
    PS>         write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" ;
    PS>         break ; 
    PS>         write-verbose "rem/remove the break above, to process and report entire list (vs abort at first pass)" ; 
    PS>     }else{
    PS>         $smsg = "(didn't match $($pltDomSpecs.IPAddress) against:$($subn))" ;
    PS>         if($verbose){write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" }  ;
    PS>     }
    PS>     $smsg = "$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;
    PS>     write-verbose $smsg ; 
    PS> } ;     
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://cloudbrothers.info/en/powershell-tip-resolve-spf/
    #>
    #Requires -Modules DnsClient
    [CmdletBinding()]
    [Alias('Resolve-DNSNameSPF')]
    PARAM (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 1,HelpMessage="Domain Name[-Name some.tld]")]
            [ValidateNotNullOrEmpty()]
            #[ValidatePattern("^([-0-9a-zA-Z]+[.])+[a-zA-Z]{2,63}$")] # email domain name restrictions
            #[ValidatePattern("^([-0-9a-zA-Z_]+[.])+([-0-9a-zA-Z]+[.])+[a-zA-Z]{2,63}$")] # DNS -type TXT permits underscores, but not in the DomainName portion on the right 
            # make the CN machinename optional: 
            [ValidatePattern("^((([-0-9a-zA-Z_]+[.])+)*)([-0-9a-zA-Z]+[.])+[a-zA-Z]{2,63}$")] # DNS -type TXT permits underscores, but not in the DomainName portion on the right 
            # Note: -type SRV also permit leading _ on records
            [Alias('DomainName', 'Domain')]
            [string]$Name,
        [Parameter(Mandatory = $false,Position = 2,HelpMessage="DNS Server to use (defaults to Cloudflare public resolver 1.1.1.1)[-Server 1.0.0.1]")]
            [string]$Server = "1.1.1.1",
        [Parameter(Mandatory = $false,HelpMessage="If called nested provide a referrer to build valid objects[-Referrer referrer]")]
            [string]$Referrer,
        [Parameter(Position=0,Mandatory=$false,ValueFromPipeline=$true,
            HelpMessage="OptionalSending server IP Address to be tested against the domain SPF record (required to attempt to expand macros)[-IPAddress 192.168.1.1]")]
            #[ValidateNotNullOrEmpty()]
            [ValidateScript({
                TRY{[system.net.ipaddress]$_}CATCH{throw "non-IP Address!"}
            })]
            [Alias('SenderIPAddress','SenderIP')]
            #[string[]]
            [string]$IPAddress, # =  @($Tormeta.OP_ExEgressIPs + $CMWMeta.OP_ExEgressIPs) ,
        [Parameter(Mandatory=$False,HelpMessage="SenderAddress to use for '%{d}','%{s}','%{l}','%{o}' SenderAddress based macros[-SenderAddress EMAIL@DOMAIN.TLD]")]
            #[ValidateNotNullOrEmpty()]
            [ValidatePattern("^([0-9a-zA-Z]+[-._+&'])*[0-9a-zA-Z]+@([-0-9a-zA-Z]+[.])+[a-zA-Z]{2,63}$")]
            #[Alias('ALIAS1', 'ALIAS2')]
            [string]$SenderAddress,
        [Parameter(Mandatory=$false,HelpMessage="Optional Sending server HELO/EHLO name, to use for '%{h}' macro substitution (should be an FQDN or where Dyn-ip & no PTR, a squarebracketed ip4 ip, or prefixed ip6 ip: [192.0.2.1] or [IPv6:fe80::1]) [-SenderHeloName SERVER.DOMAIN.TLD]")]
            #[ValidateNotNullOrEmpty()] # rgx below matches all three: server.sub.domain.com|[192.0.2.1]|[IPv6:fe80::1]
            [ValidatePattern("^((?=.{1,254}$)(^(?:(?!\d+\.|-)[a-zA-Z0-9_\-]{1,63}(?<!-)\.?)+(?:[a-zA-Z]{2,}))|\[(IPv6:((([0-9A-Fa-f]{1,4}:){1,6}:)|(([0-9A-Fa-f]{1,4}:){7}))([0-9A-Fa-f]{1,4})|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})])$")]
            #[Alias('ALIAS1', 'ALIAS2')]
            [string]$SenderHeloName,
        [Parameter(HelpMessage="Switch to return the raw resolved strings to the pipeline (vs summary [pscustomobject])[-RawOutput")]
            [switch]$RawOutput
    ) ; 
    BEGIN {
        #*======v CLASSES v======
        class SPFRecord {
            [string] $SPFSourceDomain
            [string] $IPAddress
            [string] $Referrer
            [string] $Qualifier
            [bool] $Include
            # Constructor: Creates a new SPFRecord object, with a specified IPAddress
            SPFRecord ([string] $IPAddress) {
                $this.IPAddress = $IPAddress
            }
            # Constructor: Creates a new SPFRecord object, with a specified IPAddress and DNSName
            SPFRecord ([string] $IPAddress, [String] $DNSName) {
                $this.IPAddress = $IPAddress
                $this.SPFSourceDomain = $DNSName
            }
            # Constructor: Creates a new SPFRecord object, with a specified IPAddress and DNSName and
            SPFRecord ([string] $IPAddress, [String] $DNSName, [String] $Qualifier) {
                $this.IPAddress = $IPAddress
                $this.SPFSourceDomain = $DNSName
                $this.Qualifier = $Qualifier
            }
        } ; 
        #*======^ END CLASSES ^======

        #region CONSTANTS_AND_ENVIRO #*======v CONSTANTS_AND_ENVIRO v======
        #region ENVIRO_DISCOVER ; #*------v ENVIRO_DISCOVER v------
        $Verbose = ($VerbosePreference -eq 'Continue') ; 
        # Debugger:proxy automatic variables that aren't directly accessible when debugging (must be assigned and read back from another vari) ; 
        $rPSCmdlet = $PSCmdlet ; 
        $rPSScriptRoot = $PSScriptRoot ; 
        $rPSCommandPath = $PSCommandPath ; 
        $rMyInvocation = $MyInvocation ; 
        $rPSBoundParameters = $PSBoundParameters ; 
        [array]$score = @() ; 
        if($rPSCmdlet.MyInvocation.InvocationName){
            if($rPSCmdlet.MyInvocation.InvocationName -match '\.ps1$'){
                $score+= 'ExternalScript' 
            }elseif($rPSCmdlet.MyInvocation.InvocationName  -match '^\.'){
                write-warning "dot-sourced invocation detected!:$($rPSCmdlet.MyInvocation.InvocationName)`n(will be unable to leverage script path etc from MyInvocation objects)" ; 
                # dot sourcing is implicit scripot exec
                $score+= 'ExternalScript' ; 
            } else {$score+= 'Function' };
        } ; 
        if($rPSCmdlet.CommandRuntime){
            if($rPSCmdlet.CommandRuntime.tostring() -match '\.ps1$'){$score+= 'ExternalScript' } else {$score+= 'Function' }
        } ; 
        $score+= $rMyInvocation.MyCommand.commandtype.tostring() ; 
        $grpSrc = $score | group-object -NoElement | sort count ;
        if( ($grpSrc |  measure | select -expand count) -gt 1){
            write-warning  "$score mixed results:$(($grpSrc| ft -a count,name | out-string).trim())" ;
            if($grpSrc[-1].count -eq $grpSrc[-2].count){
                write-warning "Deadlocked non-majority results!" ;
            } else {
                $runSource = $grpSrc | select -last 1 | select -expand name ;
            } ;
        } else {
            write-verbose "consistent results" ;
            $runSource = $grpSrc | select -last 1 | select -expand name ;
        };
        write-verbose  "Calculated `$runSource:$($runSource)" ;
        'score','grpSrc' | get-variable | remove-variable ; # cleanup temp varis
        ${CmdletName} = $rPSCmdlet.MyInvocation.MyCommand.Name ; # function self-name (equiv to script's: $MyInvocation.MyCommand.Path) ;
        #region PsParams ; #*------v PsParams v------
        $PSParameters = New-Object -TypeName PSObject -Property $rPSBoundParameters ;
        write-verbose "`$rPSBoundParameters:`n$(($rPSBoundParameters|out-string).trim())" ;
        # pre psv2, no $rPSBoundParameters autovari to check, so back them out:
        if($rPSCmdlet.MyInvocation.InvocationName){
            if($rPSCmdlet.MyInvocation.InvocationName  -match '^\.'){
                $smsg = "detected dot-sourced invocation: Skipping `$PSCmdlet.MyInvocation.InvocationName-tied cmds..." ; 
                if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
            } else { 
                write-verbose 'Collect all non-default Params (works back to psv2 w CmdletBinding)'
                $ParamsNonDefault = (Get-Command $rPSCmdlet.MyInvocation.InvocationName).parameters | Select-Object -expand keys | Where-Object{$_ -notmatch '(Verbose|Debug|ErrorAction|WarningAction|ErrorVariable|WarningVariable|OutVariable|OutBuffer)'} ;
            } ; 
        } else { 
            $smsg = "(blank `$rPSCmdlet.MyInvocation.InvocationName, skipping Parameters collection)" ; 
            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
        } ; 
        #endregion PsParams ; #*------^ END PsParams ^------
        #endregion ENVIRO_DISCOVER ; #*------^ END ENVIRO_DISCOVER ^------
        # rgx for filtering $rPSBoundParameters for params to pass on in recursive calls (excludes keys matching below)
        $rgxBoundParamsExcl = '^(Name|RawOutput|Server|Referrer)$' ; 

        #region FUNCTIONS ; #*======v FUNCTIONS v======
        
         #*------v Function convert-IPAddressToReverseTDO v------
        if(-not (get-command convert-IPAddressToReverseTDO -ea 0)){
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
                * 4:44 PM 1/2/2025 replace borked Copilot ipv4 demo (didn't work, as expected, clearly [-1..1] isn't reverse array, it's pull last & first element); 
                    coded in solid ipv6 support (IP reverse process is diff ipv4 & ipv6)
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
                        #return ($IPAddress -split '\.')[-1..0] -join '.' ; 
                        # Copilot's algo above didn't work properly :'P [-1..1] doesn't reverse the array, it pulls [last..first]. 
                        $IpParts = $IPAddress -split '\.' ; 
                        [array]::Reverse($IpParts);
                        return ($IpParts -join ".")
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
        } ; 
        #*------^ END Function convert-IPAddressToReverseTDO ^------

        #*------v Function test-IpAddressCidrRange v------
        if(!(get-command  test-IpAddressCidrRange)){
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
        } ;
        #*------^ END Function test-IpAddressCidrRange ^------

        #endregion FUNCTIONS ; #*======^ END FUNCTIONS ^======
               
        $SPFRawAggreg  = @() ; 

        #Aggregate all ip46
        #$aggrIp46Specs = @() ; 
        <# 3:19 PM 1/3/2025 add test support
            Run each as they occur
            '^a:
            '^exists:
            '^mx:
            '^ptr:

            Aggregate results by type, testing against SenderIP/IPAddress/Domain/SenderAddress etc
        #>
        <#
        $aggrATests = @() ; 
        $aggrExistsTests = @() ; 
        $aggrMxTests = @() ; 
        $aggrPtrTests = @() ; 
        #>
    } ; 
    PROCESS {
        # Keep track of number of DNS queries
        # DNS Lookup Limit = 10
        # https://tools.ietf.org/html/rfc7208#section-4.6.4
        # Query DNS Record
        write-verbose "(pulling TXT DNS records for $($Name) from server:$($Server))" ;
        $DNSRecords = Resolve-DnsName -Server $Server -Name $Name -Type TXT ; 
        # Check SPF record
        $SPFRecord = $DNSRecords | Where-Object { $_.Strings -match "^v=spf1" } ; 
        # Validate SPF record
        $SPFCount = ($SPFRecord | Measure-Object).Count ; 
        write-verbose "(returned $($SPFCount) spf records)" ; 
        if ( $SPFCount -eq 0) {
            # If there is no error show an error
            Write-Error "No SPF record found for `"$Name`""
        } elseif ( $SPFCount -ge 2 ) {
            # Multiple DNS Records are not allowed
            # https://tools.ietf.org/html/rfc7208#section-3.2
            Write-Error "There is more than one SPF for domain `"$Name`"" ; 
        } else {
            # Multiple Strings in a Single DNS Record
            # https://tools.ietf.org/html/rfc7208#section-3.3
            $SPFString = $SPFRecord.Strings -join '' ; 
            # Split the directives at the whitespace
            $SPFDirectives = $SPFString -split " " ; 

            # Check for a redirect
            <# [The SPF redirect explained - Mailhardener blog](https://www.mailhardener.com/blog/spf-redirect-explained)
                A redirect is a pointer to another domain name that hosts an SPF policy, it 
                allows for multiple domains to share the same SPF policy. It is useful when 
                working with a large amount of domains that share the same email 
                infrastructure

                1: The redirect is not an SPF _mechanism_ it is known as a _modifier_

                    - Modifiers differ in syntax from mechanisms: 
                        O must always contain a value, as opposed to mechanisms where values are 
                    often optional

                        O have a different key/value separator: modifiers use the equal sign 
                    (=), whereas mechanisms use a colon (:)

                        O do not use a prefix (+, -, ~ or ?)

                        example: the v=spf, at the beginning of the record, is actually 
                            Modifier (based on it's = key/value delimiter) 
                    - The mechanisms in an SPF record are evaluated from left to right. Since 
                    redirect is not a mechanism, it is always evaluated after the mechanisms, 
                    regardless of where you place it

                        It is therefore recommended, but not required to place the redirect at 
                        the very end of the SPF record, to clarify that it is only used if the 
                        preceding mechanisms didn't match

                2: mechanisms overrule a redirect: The redirect modifier is _only used if no other mechanism matches_

                    - important: the 'all' mechanism *always matches* : So if there is an all 
                    mechanism anywhere in the record, the redirect is *completely ignored*. An SPF 
                    record with a redirect should not contain the all mechanism

                3: redirect changes the domain name: 
                    - For mechanisms a, mx and ptr the value is optional == If no value is set it 
                    defaults to the current domain

                    - But when a redirect is used, the a, mx or ptr mechanism will point _to 
                    the redirected domain_ 
                4: redirect affects the all mechanism: 
                    - the redirect modifier will cause the all mechanism of the redirected domain 
                    to be used (because when working with the redirect modifier, the origin domain 
                    is not supposed to have the all modifier set.) 
                5: redirect retains error state: 
                    - Normally, if a domain has no SPF record, the SPF evaluation will return a 
                    none error, meaning that the receiver will take a neutral stance in examining 
                    the email

                    - If you redirect to a domain that does not have an SPF policy, or the 
                    SPF policy contains a syntax error, the SPF validation will fail with a 
                    permerror error. This usually results in the email failing SPF validation

                    - With the include mechanism if the included policy does not exist or 
                    contains a syntax error, the evaluation continues. A softerror may be reported 
                    with DMARC, but a sender can still pass SPF validation if it matches any other 
                    mechanism

                6: redirect counts as a DNS query: (counts toward the 10 additional DNS 
                queries limit) 

            #>
            # WITH A REDIRECT, NO OTHER ITEMS ARE EVALUATED, PROCESSING STOPS HERE, AND THE RECORD IS DROPPED INTO PIPELINE
            if ( $SPFDirectives -match "redirect" ) {
                $RedirectRecord = $SPFDirectives -match "redirect" -replace "redirect=" ; 
                Write-Verbose "[REDIRECT]`t$RedirectRecord" ; 
                # Follow the REDIRECT "include" and resolve the include
                #Resolve-SPFRecord -Name "$RedirectRecord" -Server $Server -Referrer $Name | write-output ; 
                # Resolve-SPFRecord | write-output : leverage $rPSBoundParameters post-filtered instead
                if($rPSBoundParameters){
                        $pltRvSPFRec = [ordered]@{} ;
                        # add the specific Name for this call, and Server spec (which defaults, is generally not 
                        $pltRvSPFRec.add('Name',"$RedirectRecord" ) ;
                        $pltRvSPFRec.add('Referrer',$Name) ; 
                        $pltRvSPFRec.add('Server',$Server ) ;
                        $rPSBoundParameters.GetEnumerator() | ?{ $_.key -notmatch $rgxBoundParamsExcl} | foreach-object { $pltRvSPFRec.add($_.key,$_.value)  } ;
                        write-host "Resolve-SPFRecord w`n$(($pltRvSPFRec|out-string).trim())" ;
                        Resolve-SPFRecord @pltRvSPFRec  | write-output ;
                } else {
                    $smsg = "unpopulated `$rPSBoundParameters!" ;
                    write-warning $smsg ;
                    throw $smsg ;
                }; 
            } else {
                # Extract the qualifier
                $Qualifier = switch ( $SPFDirectives -match "^[+-?~]all$" -replace "all" ) {
                    "+" { "pass" }
                    "-" { "fail" }
                    "~" { "softfail" }
                    "?" { "neutral" }
                } ; 
                write-verbose "detected Qualifier:$($Qualifier)" ; 

                # precheck for IP-tied DNS pre-expansions on $IPAddress
                # use $spfRec for resolve-spfMacrosTDO()
                # use $SPFString for resolve-SPfRecord()
                if(($SPFString -match '%\{[ivp]}') -OR ($SPFString -match 'ptr:')){
                    write-verbose "$($SPFString):IP-dependant Tests found:Doing IP-test DNS transforms" ;

                    #region Resolve_Information ; #*------v Resolve_Information v------
                    $isIPv4 = $isIPv6 = $isFQDN = $isNBName = $false ; 
                    $SendNameHost = $ComputerARec =  $SendIP =  $SendPTR =  $SendIPRev =  $SendAddressfamily = $null ; 
                    # string
                    $Computer = $IPAddress ; 
                    #ipaddr
                    #$Computer = $IPAddress.IPAddressToString
                    TRY{
                        # for [string] IP spec
                        $SendAddressfamily = ([ipaddress]$IPAddress).addressfamily ; # InterNetwork|InterNetworkV6
                        # for [ipaddress] IP spec
                        #$SendAddressfamily = $IPAddress.addressfamily ; # InterNetwork|InterNetworkV6
                        switch($SendAddressfamily){
                            'InterNetwork' { $isIpv4 = $true  }
                            'InterNetworkV6' { $isIPv6 = $true  }
                        }
                    } CATCH {
                        $ErrTrapd=$Error[0] ;
                        $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;
                        write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" ;
                    } ;

                    if( -not ($isIPv4 -OR $isIPv6) -AND (6 -le $Computer.length -le 253) -AND ($Computer -match '^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$') ){
                        $isFQDN = $true ; 
                    }  ;
                    <#[ValidateLength(1, 15)]
                    [ValidateScript({$PSItem -replace '\\|/|:|\*|\?|"||\||\.' -eq $PSItem})]
                    #>
                    if( -not ($isIPv4 -OR $isIPv6) -AND  (1 -le $Computer.length -le 15) -AND ($Computer -replace '\\|/|:|\*|\?|"||\||\.' -eq $Computer) ){
                        $isNBName = $true ; 
                    }  ;
                    #$Computer = 'NAME.SUB.DOMAIN.com' ; 
                    #$SenderAddress = 'SENDER@DOMAIN.com' ; 
                    TRY{
                        $cachedName = $null ; 
                        $cachedName = $Computer ; 
                        if($isIPv4 -OR $isIPv6){
                            write-verbose "Resolve IP to FQDN (PTR): `nresolve-dnsname -name $($Computer) -type PTR -ea STOP -server $($Server) | select -expand namehost" ; 
                            $SendNameHost = $Computer = resolve-dnsname -name $Computer -type PTR -ea STOP -server $Server | select -expand namehost; 
                        } ; 
                        if($isNBName){
                            write-verbose "Resolve NBName to FQDN (A): `nresolve-dnsname -name $($Computer) -type A -ea STOP -server $($Server)| select -expand Name" ; 
                            $SendNameHost = $Computer = resolve-dnsname -name $Computer -type A -ea STOP -server $Server | select -expand Name
                        } ; 
            
                        write-verbose "Resolve IP A Record: resolve-dnsname -name $($Computer) -type A: `nresolve-dnsname -name $($Computer) -type A  -server $($Server) -ea STOP | select -first 1 " ; 
                        TRY{
                            #$ComputerARec = resolve-dnsname -name $Computer -type A  -ea STOP -server $Server | select -first 1  ; 
                            $ComputerARec = resolve-dnsname -name $SendNameHost  -type A  -ea STOP -server $Server | select -first 1  ; 
                            write-host -foregroundcolor green "Resolved $($SendNameHost ) A Record:`n$(($ComputerARec|out-string).trim())" ; 
                            $SendIP = $ComputerARec.IPAddress ; 
                            write-verbose "`$SendIP: $($SendIP)" ; 
                        }CATCH{
                            $smsg = "Failed to:resolve-dnsname -name $($Computer) -type A " ; 
                            $smsg += "`nFalling back to original cached identifier: $($cachedName)" ; 
                            $smsg += "`n and reattempting resolution of that value" ; 
                            write-warning $smsg ; 
                            $ComputerARec = $null ; 
                            $Computer = $cachedName  ; 
                            if($isIPv4 -OR $isIPv6){$SendIP = $cachedName} ; 
                            # if non IPv4 or IPv6 and computer length is 6-253 chars, and is an fqdn, resolve fqdn to IPaddress
                            if( -not ($isIPv4 -OR $isIPv6) -AND (6 -le $Computer.length -le 253) -AND ($Computer -match '^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$') ){
                                write-verbose "resolve-dnsname -name $($Computer) -server $($Server) | select -first 1 | select -expand IPAddress" ; 
                                # no -type returns any type matched, regardless of type; mult, the first should be primary
                                $SendIP = resolve-dnsname -name $Computer -ea stop -server $Server | select -first 1 | select -expand IPAddress
                            }  ;
                            # if non IPv4 or IPv6 and computer length is 1-15 chars, and is an nbname matching the input $IPAddress (computer), resolve the name to IPAddress
                            if( -not ($isIPv4 -OR $isIPv6) -AND  (1 -le $Computer.length -le 15) -AND ($Computer -replace '\\|/|:|\*|\?|"||\||\.' -eq $Computer) ){
                                write-verbose "resolve-dnsname -name $($Computer) -ea stop | select -first 1 | select -expand IPAddress" ; 
                                $SendIP = resolve-dnsname -name $Computer -ea stop -server $Server | select -first 1 | select -expand IPAddress
                            }  ;
                            write-verbose "`$SendIP: $($SendIP)" ; 
                        } ; 
                        $SendAddressfamily = ([ipaddress]$sendip).addressfamily ; # InterNetwork|InterNetworkV6
                        # move PTR etc up here, this isn't a 10-limited SenderID check, it's a manual all-encompassing test; may as well always do the queries and populate the values
                        if($SendPTR = resolve-dnsname -name $SendIP -type PTR -server $Server){ # pull the -ea STOP , dyns etc won't properly PTR
                            #$SendIPRev = (($SendPTR | select -expand name) -split '.in-addr.')[0] ; 
                        }else {
                            $smsg = "UNABLE TO PTR!:resolve-dnsname -name $($SendIP) -type PTR -server $($Server)`n(-> `$SendPTR blank as well)" ; 
                            write-WARNING $smsg ;  
                        } ; 
                        $SendIPRev = (convert-IPAddressToReverseTDO -IPAddress $SendIP) 
                        $smsg = "Resolved:"
                        $smsg += "`n`$SendPTR`n$(($SendPTR|out-string).trim())" ; 
                        $smsg += "`n`$SendIPRev: $($SendIPRev)" ; 
                        write-verbose $smsg ;

                        #endregion Resolve_Information ; #*------^ END Resolve_Information ^------
                    } CATCH {
                        $ErrTrapd=$Error[0] ;
                        $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;
                        write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" ;
                    } ; 
                } ; 

                write-host -foregroundcolor green "Processing SPFDirectives:`n$(($SPFDirectives|out-string).trim())" ; 
                $hasMacros = $false ; 
                $ReturnValues = foreach ($SPFDirective in $SPFDirectives) {
                    write-verbose "process:$($SPFDirective)" ; 
                    if($SPFDirective -eq 'include:_spf.salesforce.com'){
                        write-verbose "gotcha!" ; 
                    } ;
                    switch -Regex ($SPFDirective) {
                        # 9:59 AM 8/13/2021 add case for version spec, otherwise it throws:WARNING: [v=spf1]	 Unknown directive
                        "v=spf\d" {
                            write-verbose "Spf Version modifier: $($SPFDirective)" ;
                        } 
                        # 9:59 AM 8/13/2021 add a case for all mechanism, or throws: WARNING: [~all]	 Unknown directive
                        "[~+-?]all" {
                            switch ($Qualifier){
                                "pass" {write-verbose "all PASS mechanism: $($SPFDirective)"}
                                "fail" {write-verbose "all FAIL mechanism: $($SPFDirective)"}
                                "softfail" {write-verbose "all SOFTFAIL mechanism: $($SPFDirective)"}
                                "neutral" {write-verbose "all NEUTRAL mechanism: $($SPFDirective)"}
                            } ;
                        } 
                        "%[{%-_]" {
                            <#
                                macro syntax %{a} etc
                                rplace each %{x} with approp resolved submitter info (ip, rev IP, SenderAddress, SenderDomainName, HeloHostname)
                                before running any directive
                                this is being examined 3rd, after v=spf & all
                            #>
                            if( get-command -name resolve-SPFMacrosTDO -ea 0){
                                $hasMacros = $true ; 
                                # deps check
                                # $IPAddress
                                if($SPFDirective -match '%\{[ivp]}'){
                                    if(-not $IPAddress){
                                        $smsg = "SPF Directive specified:"
                                        $smsg += "`n$(($SPFDirective|out-string).trim())" ;
                                        $smsg += "Includes IPAddress-dependant Macros '%{i}','%{ir}','%{v}','%{p}'" ;
                                        $smsg += "`n but *no* `$IPAddress has been specified!" ;
                                        #$smsg += "`nPlease retry with a suitable `$IPAddress specification"
                                        $smsg += "`nPrompting for an address" ;
                                        $smsg = "" ;
                                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Prompt }
                                        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                        #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                                        #throw $smsg ;
                                        #BREAK ;
                                        $IPAddress = Read-Host "Specify a suitable IPAddress for '%{i}','%{iv}','%{p}' expansion" ;
                                    } else{
                                        write-verbose  "SPF Directive specified:Includes IPAddress-dependant Macros '%{i}','%{ir}','%{v}','%{p}', and an `$IPAddress has been specified ($($IPAddress.IPAddressToString))" ;
                                        #$smsg = "`n`n==Processing:`$IPAddress:`n$(($IPAddress.IPAddressToString|out-string).trim())" ;
                                        # ip in this func is a string, not [ipaddress]
                                        $smsg = "`n`n==Processing:`$IPAddress:`n$($IPAddress)" ;
                                        $smsg += "`nagainst DomainName: $($DomainName)`n`n" ;
                                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
                                        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                    } ;
                                };
                                # $SenderAddress
                                if($SPFDirective -match '%\{[dslo]}'){
                                    if(-not $SenderAddress){
                                        $smsg = "SPF Directive specified:"
                                        $smsg += "`n$(($SPFDirective|out-string).trim())" ;
                                        $smsg += "Includes SenderAddress-dependant Macros '%{d}','%{s}','%{l}','%{o}'" ;
                                        $smsg += "`n but *no* `$SenderAddress has been specified!" ;
                                        #$smsg += "`nPlease retry with a suitable `$SenderAddress specification"
                                        $smsg += "`nPrompting for an address" ;
                                        #throw $smsg ;
                                        #BREAK ;
                                        $SenderAddress = Read-Host "Specify a suitable SenderAddress for '%{d}','%{s}','%{l}','%{o}' expansion" ;
                                    } else{
                                        write-verbose  "SPF Directive specified:Includes SenderAddress-dependant Macros '%{d}','%{s}','%{l}','%{o}', and a `$SenderAddress has been specified ($($SenderAddress))" ;
                                    } ;
                                };
                                # $SenderHeloName
                                if($SPFDirective -match '%\{[h]}'){
                                    if(-not $SenderHeloName){
                                        $smsg = "SPF Directive specified:"
                                        $smsg += "`n$(($SPFDirective|out-string).trim())" ;
                                        $smsg += "Includes Sender Server HELO name dependant Macro '%{h}'" ;
                                        $smsg += "`n but *no* `$SenderHeloName has been specified!" ;
                                        #$smsg += "`nPlease retry with a suitable `$SenderHeloName specification"
                                        $smsg += "`nPrompting for an address" ;
                                        #throw $smsg ;
                                        #BREAK ;
                                        $SenderHeloName = Read-Host "Specify a suitable SenderHeloName for '%{h}' expansion" ;
                                    } else{
                                        write-verbose  "SPF Directive specified:Includes Sender Server HELO name dependant Macro '%{h}', and a `$SenderHeloName has been specified ($($SenderHeloName))" ;
                                    } ;
                                }; 
                                <#$pltDomSpecs = [ordered]@{
                                    SpfRecord = $SPFDirective ; 
                                    DomainName = $Name ;
                                    IPAddress = $IPAddress ;
                                    SenderAddress = $SenderAddress ;
                                    SenderHeloName = $SenderHeloName ;
                                    Verbose = $($PSBoundParameters['Verbose'] -eq $true) ; 
                                    #Verbose = $($PSBoundParameters.Verbose -eq $true) ;
                                } ;
                                $mts = $pltDomSpecs.GetEnumerator() | ?{ -NOT ($_.Value -AND $_.value.length)} 
                                $mts | ForEach-Object { $pltDomSpecs.remove($_.Key) } ; 
                                write-host -foregroundcolor green "resolve-SPFMacros w`n$(($pltDomSpecs|out-string).trim())" ; 
                                #>
                                # resolve-SPFMacros call: build splat on filtered $rPSBoundParameters
                                if($rPSBoundParameters){
                                      $pltRvSPFMacr = [ordered]@{} ; 
                                      # add the specific domainname for this call
                                      $pltRvSPFMacr.add('DomainName',$Name) ;
                                      $pltRvSPFMacr.add('SpfRecord',$SPFDirective) ;
                                      $rPSBoundParameters.GetEnumerator() | ?{ $_.key -notmatch $rgxBoundParamsExcl} | foreach-object { $pltRvSPFMacr.add($_.key,$_.value)  } ;
                                      write-host -foregroundcolor green "resolve-SPFMacros w`n$(($pltRvSPFMacr|out-string).trim())" ; 
                                      $SPFDirective = resolve-SPFMacros @pltRvSPFMacr  ;
                                } else {
                                    $smsg = "unpopulated `$rPSBoundParameters!" ; 
                                    write-warning $smsg ; 
                                    throw $smsg ; 
                                }; 
                            }else {
                                Write-Warning "[$_]`tMacro sytax detected:Macros validation/expansion is not supported by this function. For more information, see https://tools.ietf.org/html/rfc7208#section-7" ;  
                                Continue ; 
                            } ; 
                        }
                        
                        
                        "^exp:.*$" {
                            Write-Warning "[$_]`texp: Explanation syntax detected:Explanation validation/expansion is not supported by this function. For more information, see https://tools.ietf.org/html/rfc7208#section-6.2" ; 
                            Continue ; 
                        }
                        '^include:.*$' {
                            # Follow the include and resolve the include
                            Write-Verbose "[include]`tSPF entry: $SPFDirective (recursing)" ; 
                            #Resolve-SPFRecord -Name ( $SPFDirective -replace "^include:" ) -Server $Server -Referrer $Name | write-output ; 
                            # Resolve-SPFRecord | write-output : leverage $rPSBoundParameters post-filtered instead
                            if($rPSBoundParameters){
                                    $pltRvSPFRec = [ordered]@{} ;
                                    # add the specific Name for this call, and Server spec (which defaults, is generally not 
                                    $pltRvSPFRec.add('Name',( $SPFDirective -replace "^include:" ) ) ;
                                    $pltRvSPFRec.add('Referrer',$Name) ; 
                                    $pltRvSPFRec.add('Server',$Server ) ;
                                    $rPSBoundParameters.GetEnumerator() | ?{ $_.key -notmatch $rgxBoundParamsExcl} | foreach-object { $pltRvSPFRec.add($_.key,$_.value)  } ;
                                    write-host "Resolve-SPFRecord w`n$(($pltRvSPFRec|out-string).trim())" ;
                                    Resolve-SPFRecord @pltRvSPFRec  | write-output ;
                            } else {
                                $smsg = "unpopulated `$rPSBoundParameters!" ;
                                write-warning $smsg ;
                                throw $smsg ;
                            }; 
                        }
                        '^ip[46]:.*$' {
                            Write-Verbose "[IP]`tSPF entry: $SPFDirective" ; 
                            $SPFObject = [SPFRecord]::New( ($SPFDirective -replace "^ip[46]:"), $Name, $Qualifier) ; 
                            #if ( $PSBoundParameters.ContainsKey('Referrer') ) {
                            if ( $PSParameters.psobject.Properties.name -contains 'Referrer' ) {
                                $SPFObject.Referrer = $Referrer ; 
                                $SPFObject.Include = $true ; 
                            } ; 
                            <# just do subnets & other raw IP aggregates into the stack, no active local tests)
                            $subSpec = [ordered]@{
                                Subnet = ($SPFDirective -replace "^ip[46]:")
                                Name = $Name ; 
                                Qualifier = $Qualifier ; 
                                SenderPassed = $null ; 
                            } ; 
                            if ( $PSParameters.psobject.Properties.name -contains 'Referrer' ) {
                                $subSpec.add('Referrer',$Referrer) ; 
                                $subSpec.add('Include',$true) ; 
                            } ; 
                            #$aggrIp46Specs += [pscustomobject]$subSpec ; 
                            #>

                            # validate ip spec (IPAddress|CIDRRange|IPAddressRange) and boolean Valid properties
                            
                            $ret= test-IpAddressCidrRange -Address $SPFDirective.replace('ip4:','').replace('ip6:','') ;
                            #$type = [regex]::match($ret.type ,'(IPAddress|CIDRRange)').captures[0].groups[0].value
                            if($ret.valid){
                                if($ret.type -match '(IPAddress|CIDRRange)'){
                                    write-verbose "(Validated ip4: entry format is:$($matches[0]))" 
                                    if($ret.type -eq 'CIDRRange'){
                                        $subnet = Get-Subnet -ip $SPFDirective.replace('ip4:','').replace('ip6:','') -verbose:$($verbose);
                                        if($subnet){
                                            if($subnet.MaskBits -eq 32){
                                                $smsg = "$($subnet.ipaddress)/$($subnet.MaskBits) is a single IP address (/32)" ;
                                            } elseif($subnet.HostAddressCount -eq 0){
                                                $smsg = "$($subnet.ipaddress)/$($subnet.MaskBits) is Class$($subnet.NetworkClass) spanning $($subnet.HostAddressCount+1) usable addresses on range:$($subnet.Range)" ;
                                            }  else { 
                                                $smsg = "$($subnet.ipaddress)/$($subnet.MaskBits) is Class$($subnet.NetworkClass) spanning $($subnet.HostAddressCount) usable addresses on range:$($subnet.Range)" ;
                                            } ; 
                                        } elseif($SPFDirective -like 'ip6:*') { 
                                            $smsg = "($($SPFDirective) is an ipv6 CIDR Range: This script does not support summarizing ipv6 Ranges)" ; 
                                        } else {
                                            $smsg = "WARNING: unrecognized CIDRRange specification" ; 
                                        } ; 
                                        write-host -foregroundcolor green "`n$($smsg)" ; 
                                    } ; 
                                } else {
                                    write-warning "invalid IP specification:$($ret.type) is unsupported format" ;
                                } ;       
                            } else { 
                                write-warning "invalid IP specification:$($SPFDirective.replace('ip4:',''))" ;
                            } ; 

                            # do a test Test-IPAddressInRange agains the $SenderIP, now NOPE
                            <#
                            PS> if(Test-IPAddressInRange -IPAddress "2001:0db8:85a3:0000:0000:8a2e:0370:7334" -Range "2001:0db8:85a3::/48" -verbose){
                            PS>     write-host -foregroundcolor green  "is in range!" 
                            PS> } else { write-host -foregroundcolor yellow "Is NOT in range"} ;
                            #>
                            <# skip, we're appending the discovered A's into the stack for later SenderIP compaire
                            if(Test-IPAddressInRange -IPAddress $IPAddress -Range $subSpec.Subnet -Verbose:($PSBoundParameters['Verbose'] -eq $true)){
                                $subSpec.SenderPassed = $true ; 
                            }else{
                                $subSpec.SenderPassed = $false ; 
                            }
                            $aggrIp46Specs += [pscustomobject]$subSpec ; 
                            #>

                            $SPFObject | write-output  ; 
                        } 
                        '^a:.*$' {
                            <#
                                The "a" mechanism 
                                a
                                a/<prefix-length>
                                a:<domain>
                                a:<domain>/<prefix-length>
                                All the A records for domain are tested. If the client IP is found among them, 
                                this mechanism matches. If the connection is made over IPv6, then an AAAA 
                                lookup is performed instead. 
                                If domain is not specified, the current-domain is used. 
                                The A records have to match the client IP 
                                exactly, unless a prefix-length is provided, in which case each IP address 
                                returned by the A lookup will be expanded to its corresponding CIDR prefix, and 
                                the client IP will be sought within that subnet.                                 
                            #>
                            Write-Verbose "[A]`tSPF entry: $SPFDirective"
                            $DNSRecords = Resolve-DnsName -Server $Server -Name $Name -Type A ; 
                            # Check SPF record
                            foreach ($IPAddress in ($DNSRecords.IPAddress) ) {
                                $SPFObject = [SPFRecord]::New( $IPAddress, ($SPFDirective -replace "^a:"), $Qualifier) ; 
                                #if ( $PSBoundParameters.ContainsKey('Referrer') ) {
                                if ( $PSParameters.psobject.Properties.name -contains 'Referrer' ) {
                                    $SPFObject.Referrer = $Referrer ; 
                                    $SPFObject.Include = $true ; 
                                }
                                
                                $SPFObject | write-output  ; 
                            } ;  # loop-E
                        }
                        '^exists:.*$' {
                             <#
                                The "exists" mechanism (edit)
                                exists:<domain>
                                Perform an A query on the provided domain. If a result is found, this constitutes a match. It doesn't matter what the lookup result is – it could be 127.0.0.2.
                                When you use macros with this mechanism, you can perform RBL-style reversed-IP lookups, or set up per-user exceptions.
                            #>
                            # as macro replace occurs first, before mechanisms, any macros should already be swapped by the time it gets to here
                            Write-Verbose "[A]`tSPF entry: $SPFDirective"
                            # this is a simple: $DNSRecords = Resolve-DnsName -Name ( $SPFDirective -replace "^exists:" ) -Server $Server $Name -Type A ; 
                            # *not* a run back through Resolve-SpfRecord() (which only does Type TXT SPF explicit processing)
                            <#
                            #$DNSRecords = Resolve-DnsName -Server $Server -Name $Name -Type A ; 
                            #$DNSRecords = Resolve-SPFRecord -Name ( $SPFDirective -replace "^exists:" ) -Server $Server -Referrer $Name | write-output ; 
                            #$DNSRecords = Resolve-SPFRecord -Name ( $SPFDirective -replace "^exists:" ) -Server $Server -Referrer $Referrer | write-output ; 
                            #$DNSRecords = Resolve-SPFRecord -Name ( $SPFDirective -replace "^exists:" ) -Type A -Server $Server -Referrer $Referrer 
                            # $DNSRecords = Resolve-SPFRecord : leverage $rPSBoundParameters post-filtered instead
                            if($rPSBoundParameters){
                                    $pltRvSPFRec = [ordered]@{} ;
                                    # add the specific Name for this call, and Server spec (which defaults, is generally not
                                    $pltRvSPFRec.add('Name',( $SPFDirective -replace "^exists:" ) ) ;
                                     $pltRvSPFRec.add('Type','A') ; 
                                    $pltRvSPFRec.add('Referrer',$Name) ;
                                    $pltRvSPFRec.add('Server',$Server ) ;
                                    $rPSBoundParameters.GetEnumerator() | ?{ $_.key -notmatch $rgxBoundParamsExcl} | foreach-object { $pltRvSPFRec.add($_.key,$_.value)  } ;
                                    write-host "Resolve-SPFRecord w`n$(($pltRvSPFRec|out-string).trim())" ;
                                    $DNSRecords = Resolve-SPFRecord @pltRvSPFRec ;
                                    # Resolve-SPFRecord isn't written to do -Type (A); have to do directly
                            } else {
                                $smsg = "unpopulated `$rPSBoundParameters!" ;
                                write-warning $smsg ;
                                throw $smsg ;
                            };
                            #>

                            $pltRvDNSName=[ordered]@{
                                Name = ( $SPFDirective -replace "^exists:" ) ;
                                Server = $Server ;
                                Type = 'A' ;                                
                                erroraction = 'silentlycontinue' ; # flip to silentlycontinue - let it drop, they'll frequently not be present
                            } ;
                            $smsg = "Resolve-DnsName w`n$(($pltRvDNSName|out-string).trim())" ; 
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            #$DNSRecords = Resolve-DnsName -Name ( $SPFDirective -replace "^exists:" ) -Server $Server $Name -Type A ; 
                            $DNSRecords = Resolve-DnsName @pltRvDNSName ; 

                            <## Check SPF record
                            foreach ($IPAddress in ($DNSRecords.IPAddress) ) {
                                $SPFObject = [SPFRecord]::New( $IPAddress, ($SPFDirective -replace "^a:"), $Qualifier) ; 
                                #if ( $PSBoundParameters.ContainsKey('Referrer') ) {
                                if ( $PSParameters.psobject.Properties.name -contains 'Referrer' ) {
                                    $SPFObject.Referrer = $Referrer ; 
                                    $SPFObject.Include = $true ; 
                                }
                                
                                $SPFObject | write-output  ; 
                            } ;  # loop-E
                            #>
                            if($DNSRecords){
                                # hit on the exists: pass - add the IPAddress, Directive & Qualifier into the returned SPfObject (will be avail to match with the SenderIP later)
                                $SPFObject = [SPFRecord]::New( $IPAddress, ($SPFDirective -replace "^exists:"), $Qualifier) ; 
                                #if ( $PSBoundParameters.ContainsKey('Referrer') ) {
                                if ( $PSParameters.psobject.Properties.name -contains 'Referrer' ) {
                                    $SPFObject.Referrer = $Referrer ; 
                                    $SPFObject.Include = $true ; 
                                }
                                
                                $SPFObject | write-output  ;
                            } else {
                                # fail on the A: fail
                            } ; 
                        }
                        '^mx:.*$' {
                            <#
                                The "mx" mechanism (edit)
                                mx
                                mx/<prefix-length>
                                mx:<domain>
                                mx:<domain>/<prefix-length>
                                All the A records for all the MX records for domain are tested in order of MX priority. If the client IP is found among them, this mechanism matches.
                                If domain is not specified, the current-domain is used.
                                The A records have to match the client IP exactly, unless a prefix-length is provided, in which case each IP address returned by the A lookup will be expanded to its corresponding CIDR prefix, and the client IP will be sought within that subnet.
                            #>
                            Write-Verbose "[MX]`tSPF entry: $SPFDirective" ; 
                            $DNSRecords = Resolve-DnsName -Server $Server -Name $Name -Type MX ; 
                            # same as the A: & exists: discoveries: append the discovered IPAddress, Directive, and Qualifier into the SenderIP eval stack
                            foreach ($MXRecords in ($DNSRecords.NameExchange) ) {
                                # Check SPF record
                                $DNSRecords = Resolve-DnsName -Server $Server -Name $MXRecords -Type A ; 
                                foreach ($IPAddress in ($DNSRecords.IPAddress) ) {
                                    $SPFObject = [SPFRecord]::New( $IPAddress, ($SPFDirective -replace "^mx:"), $Qualifier) ; 
                                    #if ( $PSBoundParameters.ContainsKey('Referrer') ) {
                                    if ( $PSParameters.psobject.Properties.name -contains 'Referrer' ) {
                                        $SPFObject.Referrer = $Referrer ; 
                                        $SPFObject.Include = $true ; 
                                    } ; 
                                    
                                   $SPFObject | write-output  ; 
                                } ; 
                            } ; 
                        }
                        '^ptr:.*$' {
                            <#
                                The "ptr" mechanism
                                ptr
                                ptr:<domain>
                                The hostname or hostnames for the client IP are looked up using PTR queries. 
                                The hostnames are then validated: at least one of the A records for a PTR 
                                hostname must match the original client IP. Invalid hostnames are discarded. If 
                                a valid hostname ends in domain, this mechanism matches. 
                                If domain is not specified, the current-domain is used.
                                If at all possible, you should avoid using this mechanism in your SPF record, because it will result in a larger number of expensive DNS lookups.
                                [PTR mechanisms in SPF records - dmarcian](https://dmarcian.com/ptr-mechanisms-in-spf-records/)
                                When an email receiver gets a piece of email and the PTR mechanism is in the 
                                sender's SPF record, the receiver will look at the incoming IP address and do a 
                                "PTR" lookup

                                For example, if the sender is sending email from IP address 1.2.3.4, the 
                                receiver will perform a PTR lookup of 1.2.3.4 to attempt to retrieve a hostname.
                                 Lastly, if a hostname is discovered for IP address 1.2.3.4, then 
                                that hostname's domain is compared to the domain that was originally used to 
                                lookup the SPF record. 

                                The PTR mechanism has been deprecated.  See the relevant RFC for more info

                                The SPF Surveyor cannot resolve PTR mechanisms because a real 
                                connection from a real sender is necessary to complete the lookup

                                MOST IMPORTANTLY: Some large receivers will skip the mechanism – or 
                                worse they'll skip the entire SPF record – because such mechanisms cannot be 
                                easily cached.  Imagine a large receiver doing a PTR lookup for millions of 
                                different connections… the size of the local cache explodes. 

                            #>
                            Write-Warning "[$_]`tptr: PTR syntax detected:PTR validation/expansion is not supported by this function (and is DEPRECATED UNDER RFC). For more information, see https://tools.ietf.org/html/rfc7208#section-6.2" ; 
                            Continue ;
                        }
                        Default {
                            Write-Warning "[$_]`t Unknown directive" ; 
                        }
                    } ; 
                } ; 
                # 3:40 PM 12/30/2024 actually, macro's get replcd in mechanisms/directives *before* running the test, so I updated the SpfDirective above, and assigned it back to itself 
                # below should be unnecc
                <#
                if($hasMacros){
                    write-host -foregroundcolor yellow "SPF Macros detected, running test-SPFMacroSpecificationTDO() expansion attempt" ; 
                    # #test-SPFMacroSpecificationTDO -SpfRecord -DomainName -SenderAddress -IPAddress
                    $pltRvSPFMacros=[ordered]@{
                        SpfRecord = $ReturnValues  # need to reformat these to the raw entries
                        DomainName = $Name ; 
                        #Verbose = ($PSBoundParameters['Verbose'] -eq $true)
                        Verbose = $($PSParameters.verbose -eq $true)
                        erroraction = 'STOP' ;
                        whatif = $($whatif) ;
                    } ;
                    if($SenderAddress){
                        $pltRvSPFMacros.add('SenderAddress',$SenderAddress) ; 
                    } ; 
                    if($IPAddress){
                        $pltRvSPFMacros.add('IPAddress',$IPAddress) ; 
                    } ; 
                    $smsg = "test-SPFMacroSpecificationTDO w`n$(($pltRvSPFMacros|out-string).trim())" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    $ReturnValues += @(
                        test-SPFMacroSpecificationTDO @pltRvSPFMacros ; 
                    ); 
                } ; 
                #>
                $DNSQuerySum = $ReturnValues | Select-Object -Unique SPFSourceDomain | Measure-Object | Select-Object -ExpandProperty Count ; 
                if ( $DNSQuerySum -le 6) {
                    write-host -foregroundcolor yellow "($DNSQuerySum) DNS queries made  (Must not exceed 10 DNS queries)." ; 
                }elseif ( $DNSQuerySum -gt 6) {
                    Write-Warning "Watch your includes!`nThe maximum number of DNS queries is 10 and you have already $DNSQuerySum.`nCheck https://tools.ietf.org/html/rfc7208#section-4.6.4" ; 
                } ; 
                if ( $DNSQuerySum -gt 10) {
                    Write-Error "Too many DNS queries made ($DNSQuerySum).`nMust not exceed 10 DNS queries.`nCheck https://tools.ietf.org/html/rfc7208#section-4.6.4" ; 
                } ; 

                if($RawOutput){
                    foreach ($dir in $returnvalues){
                        if($dir.IPAddress){
                            if($dir.IPAddress.contains('.')){
                                $SPFRawAggreg += "ip4:$($dir.IPAddress)" ;
                            }elseif($dir.IPAddress.contains(':')){
                               $SPFRawAggreg += "ip6:$($dir.IPAddress)" ;
                            } ; 
                        } ;
                    } ; 
                    $SPFRawAggreg += switch ($Qualifier){
                        "pass" { '+all'}
                        "fail" { '-all'}
                        "softfail" { '~all'}
                        "neutral" { '?all'}
                    } ; 
                    #$SPFRawAggreg -join " " | write-output  ; 
                    # either output unwrapped ^ or as is as an array:
                    $SPFRawAggreg | write-output  ; 
                } else { 
                    $ReturnValues | write-output ; 
                } ; 
            } ; 
        } ; 
    } ; 

    END {}
} ; 
#*------^ END Function Resolve-SPFRecord ^------
