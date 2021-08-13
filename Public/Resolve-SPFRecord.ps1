#*------v Function Resolve-SPFRecord v------
function Resolve-SPFRecord {
    <#
    .SYNOPSIS
    resolve-SPFRecord.ps1 - query & parse/validate the current SPF DNS records, including all included services
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
    REVISIONS
    * 12:25 PM 8/13/2021Add ip4/6 syntax testing/simple validation (via 
    test-IpAddressCidrRange, sourced in verb-network, local deferral copy) ; 
    extended verbose echos ; add case for version spec & [~+-?]all (suppress spurious 
    warnings) ; expanded macro/explanation mechanism warnings (non-invalid: just script 
    doesn't support their expansion/validation). Added examples for grouping referrer and 
    dumping summaries per referrer. 
    * 1:29 PM 8/12/2021 updated format to OTB, added CBH, minor param inline help etc.
    * 1:29 PM 4/12/2021 Fabian Bader posted rev
    .DESCRIPTION
    resolve-SPFRecord.ps1 - query & parse/validate the current SPF DNS records, including all included services. 
    
    from [PowerShell Tip: Resolve SPF Records - Cloudbrothers - cloudbrothers.info/](https://cloudbrothers.info/en/powershell-tip-resolve-spf/):
    Supported SPF directives and functions
     - include
     - mx
     - a
     - ip4 und ip6
     - redirect
     - Warning for too many include entries
    Not supported
     - exp
     - Makros
     - Usage
     
    For the query of the corresponding TXT records in the DNS only the paramater name is needed. The domain to be queried must be specified here, and the script does the rest.
    Resolve-SPFRecord -Name domainname.tld
    It is recommended to output the result with 'Format-Table' for better readability.
    Resolve-SPFRecord -Name domainname.tld | ft
    Alternative DNS server
    Optionally, the Server parameter can be used. Defaults to defaults to cloudflare resolver 1.1.1.1 (secondary is 1.0.0.1):
    [Introducing DNS Resolver, 1.1.1.1 (not a joke) - blog.cloudflare.com/](https://blog.cloudflare.com/dns-resolver-1-1-1-1/)
    With this you change the DNS server to be queried. This can be helpful, for example, if you want to test the DNS changes directly on your own root name server shortly after the update, or if there are restrictions on which DNS server your client is allowed to query.
    .PARAMETER Name
    Domain Name[-Name some.tld]
    .PARAMETER Server
    DNS Server to use (defaults to Cloudflare public resolver 1.1.1.1)[-Server 1.0.0.1]
    .PARAMETER Referrer
    if called nested provide a referrer to build valid objects[-Referrer referrer]
    .INPUTS
    Accepts piped input
    .OUTPUTS
    None. Returns no objects or output (.NET types)
    System.Boolean
    [| get-member the output to see what .NET obj TypeName is returned, to use here]
    .EXAMPLE
    PS> Resolve-SPFRecord -Name domainname.tld
    .EXAMPLE
    PS> Resolve-SPFRecord -Name domainname.tld | ft
    It is recommended to output the result with 'Format-Table' for better readability.
    .EXAMPLE
    PS> $spfs = Resolve-SPFRecord -name domain.com ; 
    # group referrers
    $spfs | group referrer | ft -auto count,name ;
    output: 
    Count Name                      
    ----- ----                      
        3                           
        10 domain.com                  
        9 spf.protection.outlook.com
    # output ip summary for a specific referrer
    $spfs|?{$_.Referrer  -eq 'spf.protection.outlook.com'} | ft -auto ipaddress,referrer ; 
    output: 
    IPAddress                Referrer                  
    ---------                --------                  
    51.4.72.0/24             spf.protection.outlook.com
    ...
    Broader example, group/profile returned referrers, dump summaries on referrers
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://cloudbrothers.info/en/powershell-tip-resolve-spf/
    #>
    #Requires -Modules DnsClient
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 1,HelpMessage="Domain Name[-Name some.tld]")]
        [string]$Name,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true,Position = 2,HelpMessage="DNS Server to use (defaults to Cloudflare public resolver 1.1.1.1)[-Server 1.0.0.1]")]
        [string]$Server = "1.1.1.1",
        [Parameter(Mandatory = $false,HelpMessage="If called nested provide a referrer to build valid objects[-Referrer referrer]")]
        [string]$Referrer
    ) ; 
    BEGIN {
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

        ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
        $Verbose = ($VerbosePreference -eq 'Continue') ; 
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
            if ( $SPFDirectives -match "redirect" ) {
                $RedirectRecord = $SPFDirectives -match "redirect" -replace "redirect=" ; 
                Write-Verbose "[REDIRECT]`t$RedirectRecord" ; 
                # Follow the include and resolve the include
                Resolve-SPFRecord -Name "$RedirectRecord" -Server $Server -Referrer $Name ; 
            } else {
                # Extract the qualifier
                $Qualifier = switch ( $SPFDirectives -match "^[+-?~]all$" -replace "all" ) {
                    "+" { "pass" }
                    "-" { "fail" }
                    "~" { "softfail" }
                    "?" { "neutral" }
                } ; 
                write-verbose "detected Qualifier:$($Qualifier)" ; 
                $ReturnValues = foreach ($SPFDirective in $SPFDirectives) {
                    switch -Regex ($SPFDirective) {
                        # 9:59 AM 8/13/2021 add case for version spec, otherwise it throws:WARNING: [v=spf1]	 Unknown directive
                        "v=spf\d" {
                            write-verbose "Spf Version: $($SPFDirective)" ;
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
                            Write-Warning "[$_]`tMacro sytax detected:Macros validation/expansion is not supported by this function. For more information, see https://tools.ietf.org/html/rfc7208#section-7" ;  
                            Continue ; 
                        }
                        "^exp:.*$" {
                            Write-Warning "[$_]`texp: Explanation syntax detected:Explanation validation/expansion is not supported by this function. For more information, see https://tools.ietf.org/html/rfc7208#section-6.2" ; 
                            Continue ; 
                        }
                        '^include:.*$' {
                            # Follow the include and resolve the include
                            Write-Verbose "[include]`tSPF entry: $SPFDirective (recursing)" ; 
                            Resolve-SPFRecord -Name ( $SPFDirective -replace "^include:" ) -Server $Server -Referrer $Name ; 
                        }
                        '^ip[46]:.*$' {
                            Write-Verbose "[IP]`tSPF entry: $SPFDirective" ; 
                            $SPFObject = [SPFRecord]::New( ($SPFDirective -replace "^ip[46]:"), $Name, $Qualifier) ; 
                            if ( $PSBoundParameters.ContainsKey('Referrer') ) {
                                $SPFObject.Referrer = $Referrer ; 
                                $SPFObject.Include = $true ; 
                            } ; 

                            # validate ip spec (IPAddress|CIDRRange|IPAddressRange) and boolean Valid properties
                            
                            $ret= test-IpAddressCidrRange -Address $SPFDirective.replace('ip4:','').replace('ip6:','') ;
                            #$type = [regex]::match($ret.type ,'(IPAddress|CIDRRange)').captures[0].groups[0].value
                            if($ret.valid){
                                if($ret.type -match '(IPAddress|CIDRRange)'){
                                    write-host -ForegroundColor gray "(Validated ip4: entry format is:$($matches[0]))" 
                                } else {
                                    write-warning "invalid IP specification:$($ret.type) is unsupported format" ;
                                } ;       
                            } else { 
                                write-warning "invalid IP specification:$($SPFDirective.replace('ip4:',''))" ;
                            } ; 
                            
                            $SPFObject ; 
                        } 
                        '^a:.*$' {
                            Write-Verbose "[A]`tSPF entry: $SPFDirective"
                            $DNSRecords = Resolve-DnsName -Server $Server -Name $Name -Type A ; 
                            # Check SPF record
                            foreach ($IPAddress in ($DNSRecords.IPAddress) ) {
                                $SPFObject = [SPFRecord]::New( $IPAddress, ($SPFDirective -replace "^a:"), $Qualifier) ; 
                                if ( $PSBoundParameters.ContainsKey('Referrer') ) {
                                    $SPFObject.Referrer = $Referrer ; 
                                    $SPFObject.Include = $true ; 
                                }
                                $SPFObject ; 
                            }
                        }
                        '^mx:.*$' {
                            Write-Verbose "[MX]`tSPF entry: $SPFDirective" ; 
                            $DNSRecords = Resolve-DnsName -Server $Server -Name $Name -Type MX ; 
                            foreach ($MXRecords in ($DNSRecords.NameExchange) ) {
                                # Check SPF record
                                $DNSRecords = Resolve-DnsName -Server $Server -Name $MXRecords -Type A ; 
                                foreach ($IPAddress in ($DNSRecords.IPAddress) ) {
                                    $SPFObject = [SPFRecord]::New( $IPAddress, ($SPFDirective -replace "^mx:"), $Qualifier) ; 
                                    if ( $PSBoundParameters.ContainsKey('Referrer') ) {
                                        $SPFObject.Referrer = $Referrer ; 
                                        $SPFObject.Include = $true ; 
                                    } ; 
                                    $SPFObject ; 
                                } ; 
                            } ; 
                        }
                        Default {
                            Write-Warning "[$_]`t Unknown directive" ; 
                        }
                    } ; 
                } ; 

                $DNSQuerySum = $ReturnValues | Select-Object -Unique SPFSourceDomain | Measure-Object | Select-Object -ExpandProperty Count ; 
                if ( $DNSQuerySum -gt 6) {
                    Write-Warning "Watch your includes!`nThe maximum number of DNS queries is 10 and you have already $DNSQuerySum.`nCheck https://tools.ietf.org/html/rfc7208#section-4.6.4" ; 
                } ; 
                if ( $DNSQuerySum -gt 10) {
                    Write-Error "Too many DNS queries made ($DNSQuerySum).`nMust not exceed 10 DNS queries.`nCheck https://tools.ietf.org/html/rfc7208#section-4.6.4" ; 
                } ; 

                $ReturnValues ; 
            } ; 
        } ; 
    } ; 

    END {}
} ; 
#*------^ END Function Resolve-SPFRecord ^------