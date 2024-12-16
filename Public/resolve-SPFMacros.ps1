#*------v resolve-SPFMacros.ps1 v------
function resolve-SPFMacros {
    <#
    .SYNOPSIS
    resolve-SPFMacros - Expand macros in provided SPF specification string
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2024-
    FileName    : resolve-SPFMacros
    License     : MIT License
    Copyright   : (c) 2024 Todd Kadrie
    Github      : https://github.com/tostka/verb-XXX
    Tags        : Powershell,SenderID,SPF,DNS,SenderPolicyFramework
    AddedCredit : REFERENCE
    AddedWebsite: URL
    AddedTwitter: URL
    REVISIONS
    * 4:10 PM 12/16/2024 questions about header sources for various tests: went back to RFC source, and dug out the detailed mechaism engring specs. Then worked through pphosted & salesforce macro expansion, 
    added them to expls. 
    * 9:31 AM 12/13/2024 adapted from resolve-SPFMacros, stip it down to just a Macro replace/expansion func, on passed strings (as Macros are expanded to final form, before eval of the subject record against sending Host occurs)
    * 11:05 AM 12/12/2024 ren: test-SPFMacroEgressIPs -> resolve-SPFMacros; 
        revised to permit a fully pre-resolved SPF record input, to skip the inital resolution step
    * 3:06 PM 12/10/2024 port to a verb-network function, REN test-SPFMacroEgressIPs -> test-SPFMacroIPs
    *4:47 PM 6/6/2024 init vers; works for validating the ppthosted record
    .DESCRIPTION
    resolve-SPFMacros - Expand macros in provided SPF specification string

    Ref:
    [dns spf "Modifier" "mechanism" when are macro replaced - Google Search](https://www.google.com/search?q=dns+spf+%22Modifier%22+%22mechanism%22+when+are+macro+replaced)

        #-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        AI Overview
        Learn more
        In a DNS SPF record, macros are replaced immediately before the SPF record is evaluated, meaning that when the receiving mail server looks up the SPF record, the macro variables like "%{i}" (representing the sender's IP address) are substituted with their actual values before any checks against the specified mechanisms are performed. 
        Key points about macro replacement in SPF:

            Dynamic substitution:
            Macros allow for dynamic insertion of contextual information like the sender's IP address or domain name directly into the SPF record.

        Mechanism evaluation:
        Once the macros are replaced, the SPF record is then evaluated based on the specified mechanisms (like "ip4", "mx", "exists") using the substituted values. 
        No separate lookup:
        The macro expansion happens during the initial DNS lookup of the SPF record, so there's no additional DNS query needed to retrieve the macro values.

        Example:
        Code

        v=spf1 include:subdomain.example.com ~all

            Without macros:
            This would simply check if the sending IP address is listed within the "subdomain.example.com" domain's SPF record.
            With macros:
                v=spf1 exists:%{i}.%{v}.arpa._spf.example.com ~all
                Here, "%{i}" would be replaced with the sender's IP address, allowing for a reverse DNS lookup on that specific IP to check if it's allowed to send mail on behalf of "example.com". 
        #-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

        Ref: 
        When a DNS record is stated as:
        IN TXT "v=spf1 include:example.com include:example.org -all"
        "IN" indicates the Internet, eg. the ip address is an internet ip address
        "The CLASS of a record is set to IN (for Internet) for common DNS records involving Internet hostnames, servers, or IP addresses.)"

        [Automating SPF macro management with scripting and APIs: a step-by-step guide - AutoSPF - Automatic SPF flattening](https://autospf.com/blog/automating-spf-macro-management-with-scripting-apis-step-by-step-guide/)
        #-=-=-=-=-=-=-=-=
        Here are the commonly integrated SPF macros–
            %{i}: Represents the IP address of the sender
            %{s}: Represents the sender's email address (the "MAIL FROM" address).
            %{h}: Represents the HELO/EHLO domain of the SMTP server.
            %{d}: Represents the domain of the sender's email address.
            %{p}: Represents the validated domain name of the sender's IP address.
            %{v}: Represents the literal string "in-addr" or "ip6", depending on whether the sender's IP address is IPv4 or IPv6.
            %{l}: Represents the local part of the sender's email address (the part before the "@" symbol).
            %{o}: Represents the domain part of the "MAIL FROM" address (the part after the "@" symbol).
            %{r}: Represents the domain of the recipient.
            %{t}: Represents the current timestamp in Unix time.

        #-=-=-=-=-=-=-=-=

        [RFC 4408 Sender Policy Framework (SPF) for Authorizing Use of Domains in Email, Version 1](https://www.rfc-editor.org/rfc/rfc7208)

        - <Sender> is checked against 1) The HELO Identity (full fqdn from HELO/EHLO greeting sent by client, if enabled on server), 
            or 2) the Mail From:/Envelope-From:/Return-Path:/5321.MailFrom:

        - 3.3.  Multiple Strings in a Single DNS Record
            As defined in [RFC1035], Sections 3.3 and 3.3.14, a single text DNS record can 
            be composed of more than one string.  If a published record contains multiple 
            character-strings, then the record MUST be treated as if those strings are 
            concatenated together without adding spaces.  For example: 

              IN TXT "v=spf1 .... first" "second string..."

            is equivalent to:
              IN TXT "v=spf1 .... firstsecond string..."

            TXT records containing multiple strings are useful in constructing records that would exceed the 255-octet maximum length of a character-string within a single TXT record.            

        - 3.4.  Record Size

            The published SPF record for a given domain name SHOULD remain small enough 
            that the results of a query for it will fit within 512 octets. Otherwise, there 
            is a possibility of exceeding a DNS protocol limit. This UDP limit is defined 
            in [RFC1035], Section 2.3.4, although it was raised by [RFC2671].  Staying 
            below 512 octets ought to prevent older DNS implementations from failing over 
            to TCP and will work with UDP in the absence of EDNS0 [RFC6891] support.  Since 
            the answer size is dependent on many things outside the scope of this document, 
            it is only possible to give this guideline: If the size of the DNS message, the 
            combined length of the DNS name and the text of all the records of a given type 
            is under 450 octets, then DNS answers ought to fit in UDP packets.  Records 
            that are too long to fit in a single UDP packet could be silently ignored by 
            SPF verifiers due to firewall and other issues that interfere with the 
            operation of DNS over TCP or using ENDS0.  

            Note that when computing the sizes for replies to queries of the TXT format, 
            one has to take into account any other TXT records published at the domain name.
             Similarly, the sizes for replies to all queries related to SPF have to 
            be evaluated to fit in a single 512-octet UDP packet (i.e., DNS message size 
            limited to 450 octets). 

        - 4.6.1.  Term Evaluation
            
            o two types of terms: mechanisms (defined in Section 5) and modifiers (defined in Section 6)
            o directive = [ qualifier ] mechanism
            o qualifier = "+" / "-" / "?" / "~"
            o mechanism  = ( all / include / a / mx / ptr / ip4 / ip6 / exists )
                Most mechanisms allow a ":" or "/" character after the name.
                Each mechanism is considered in turn from left to right.  If there are no more mechanisms, the result is the default result as described in Section 4.7.
                When a mechanism is evaluated, one of three things can happen: it can match, not match, or return an exception. 
                If it matches, processing ends and the qualifier value is returned as the 
                result of that record.  If it does not match, processing continues with the 
                next mechanism.  If it returns an exception, mechanism processing ends and the 
                exception value is returned. The possible qualifiers, and the results they 
                cause check_host() to return, are as follows: "+" pass|  "-" fail|  "~" 
                softfail|  "?" neutral|
 
                The qualifier is optional and defaults to "+"

                When a mechanism matches and the qualifier is "-", then a "fail" result 
                is returned and the explanation string is computed as described in Section 6.2. 

            o modifier = redirect / explanation / unknown-modifier
                Modifiers always contain an equals ('=') character immediately after the name, 
                and before any ":" or "/" characters that might be part of the macro-string.  
                Modifiers are not mechanisms.  They do not return match or not-match. Instead, 
                they provide additional information.  Although modifiers do not directly affect 
                the evaluation of the record, the "redirect" modifier has an effect after all 
                the mechanisms have been evaluated.  
            o unknown-modifier = name "=" macro-string
                      ; where name is not any known modifier
            o name = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )

        - 4.6.4.  DNS Lookup Limits
            - The following terms cause DNS queries: the "include", "a", "mx", "ptr", and 
            "exists" mechanisms, and the "redirect" modifier

            - SPF implementations MUST limit the total number of those terms to 10
            during SPF evaluation, to avoid unreasonable load on the DNS

            - the "all", "ip4", and "ip6" mechanisms, and the "exp" modifier -- do 
            not cause DNS queries at the time of SPF evaluation (the "exp" modifier 
            only causes a lookup at a later time), and their use is not subject to 
            this limit. 

            - When evaluating the "mx" mechanism, the number of "MX" resource records queried 
            is included in the overall limit of 10 mechanisms/ modifiers that cause DNS 
            lookups as described above.  In addition to that limit, the evaluation of each 
            "MX" record MUST NOT result in querying more than 10 address records -- either 
            "A" or "AAAA" resource records. If this limit is exceeded, the "mx" mechanism MUST 
            produce a "permerror" result.

            - When evaluating the "ptr" mechanism or the %{p} macro, the number of "PTR" 
            resource records queried is included in the overall limit of 10 
            mechanisms/modifiers that cause DNS lookups as described above.  In addition to 
            that limit, the evaluation of each "PTR" record MUST NOT result in querying 
            more than 10 address records -- either "A" or "AAAA" resource records.  If this 
            limit is exceeded, all records other than the first 10 MUST be ignored. 

            The reason for the disparity is that the set of and contents of the
            MX record are under control of the publishing ADMD, while the set of
            and contents of PTR records are under control of the owner of the IP
            address actually making the connection.

            These limits are per mechanism or macro in the record, and are in
            addition to the lookup limits specified above.

            - MTAs or other processors SHOULD impose a limit on the maximum amount
            of elapsed time to evaluate check_host().  Such a limit SHOULD allow
            at least 20 seconds.  If such a limit is exceeded, the result of
            authorization SHOULD be "temperror".
            
        - 4.8 Domain Specification
            - The <domain-spec> string is subject to macro expansion
            - The resulting string is the common presentation form of 
                a fully qualified DNS name: a series of labels separated by periods.
                This domain is called the <target-name> in the rest of this document.

            - For several mechanisms, the <domain-spec> is optional.  If it is not
            provided, the <domain> from the check_host() arguments (see Section 4.1) 
            is used as the <target-name>.  "domain" and <domain-spec> are syntactically 
            identical after macro expansion.
            "domain" is an input value for check_host(), while <domain-spec> is
            computed by check_host()
        
        - 5.  Mechanism Definitions
            -When any mechanism fetches host addresses to compare with <ip>, 
                o when <ip> is an IPv4, "A" records are fetched;
                o when <ip> is an IPv6 address, "AAAA" records are fetched.  

            - "a" An address lookup is done on the <target-name>/domain-spec/domain using the type of
                lookup (A or AAAA) appropriate for the connection type (IPv4 or
                IPv6).  The <ip> is compared to the returned address(es).  If any
                address matches, the mechanism matches.
            - "mx" performs an MX lookup on the <target-name>/domain-spec/domain 
                Then performs an address lookup on each MX name returned.
                The <ip> is compared to each returned IP address.
                e.g.: resolve domain MX's, then resolve the NameHost of each records 'A' on the Namehost, to the underlying IP Addresses: compare the sending server IP against those IPs
                resolve-dnsname -type 'A' -name (resolve-dnsname -type mx -name toro.com -server 1.1.1.1).NameExchange -server 1.1.1.1 | select -expand ipaddress
                    52.101.194.17
                    52.101.8.44
                    52.101.41.58
                    52.101.42.10
           - "ptr" (do not use)
                The <ip>'s name is looked up using this procedure:
                o  Perform a DNS reverse-mapping for <ip>: 
                        Look up the corresponding PTR record in "in-addr.arpa." if the address is an IPv4 address and in "ip6.arpa." if it is an IPv6 address.
                o  For each record returned, validate the domain name by looking up its IP addresses.  
                o  If <ip> is among the returned IP addresses, then that domain name is validated.
                e.g: Resolve the sender server IP to the PTR, then resolve the A record for the prior's Namehost, back to it's IP address, and compare senderserver IP to the IP from trhe expansions
                resolve-dnsname -name (resolve-dnsname -type ptr -name 170.92.7.36 -server 1.1.1.1).namehost -type A -server 1.1.1.1 | select -expand ipaddress
                    170.92.7.36
            - "ip4" and "ip6" 
                The <ip> is compared to the given network.  If CIDR prefix length high-order bits match, the mechanism matches.
                If ip4-cidr-length is omitted - only an IP is listed - it is taken to be "/32".  If ip6-cidr-length is omitted - only an ip6 IP is listed - it is taken to be "/128".  
                    e.g. go ahead and append /32 & /128 to single IPs in ip4 & ip6 entries
            - "exists" This mechanism is used to construct an arbitrary domain name that is 
                used for a DNS A record query.  It allows for complicated schemes involving 
                arbitrary parts of the mail envelope to determine what is permitted. 
                The <domain-spec> is expanded as per above (including macros etc).  
                The resulting domain name is used for a DNS A RR lookup - == resolve the A record to the IP - (even when the connection type is IPv6).  
                If any A record is returned, this mechanism matches.
                Domains can use this mechanism to specify arbitrarily complex queries.  For example, suppose example.com publishes the record:
                    v=spf1 exists:%{ir}.%{l1r+-}._spf.%{d} -all

                The <target-name> might expand to
                    "1.2.0.192.someuser._spf.example.com".  
                This makes fine-grained decisions possible at the level of the user and client IP address.


    This is specifically tuned to resolve & lookup dynamic per-host DNS records, over validating standard include or other records
    .PARAMETER SpfRecord
    Optional Pre-resolved SpfRecord specification string to be evaluated (skips initial resolution pass; used to recycle from Resolve-SPFRecord() call[-SpfRecord `$spfRec]
    .PARAMETER IPAddress
    Sending server IP Address to be tested against the domain SPF record[-IPAddress 192.168.1.1]
    .PARAMETER DomainName
    DomainName for which SPF records should be retrieved and tested against[-DomainName domain.com]
    .PARAMETER SenderAddress
    Optional SenderAddress to use for '%{d}','%{s}','%{s}','%{o}' SenderAddress based macros[-SenderAddress email@domain.tld]
    .PARAMETER SenderHeloName
    Optional Sending server HELO name, to use for '%{h}' macro substitution [-SenderHeloName SERVER.DOMAIN.TLD]
    .INPUTS
    None. Does not accepted piped input.(.NET types, can add description)
    .OUTPUTS
    None. Returns no objects or output (.NET types)
    System.Boolean
    [| get-member the output to see what .NET obj TypeName is returned, to use here]
    .EXAMPLE
    PS> $spfspec = Resolve-DnsName -name _spf.salesforce.com -server 1.1.1.1 -type TXT | ? strings -match '^v=spf1' | select -expand strings ; 
    PS> $spfspec ; 

        v=spf1 exists:%{i}._spf.mta.salesforce.com -all

    PS> $resolvedSPFString = resolve-SPFMacros -SpfRecord $spfspec -IPAddress 52.88.39.26 -DomainName salesforce.com -SenderAddress PartsClaims@toro.com

        VERBOSE: 15:50:48:===> Specified $SpfRecord:
        v=spf1 exists:%{i}._spf.mta.salesforce.com -all
        has been resolved to:
        v=spf1 exists:52.88.39.26._spf.mta.salesforce.com -all
        (sending to pipeline)

    PS> $resolvedSPFString  ; 

        v=spf1 exists:52.88.39.26._spf.mta.salesforce.com -all

    PS> write-verbose "Resolve the include:36.7.92.170.in-addr.toro.com.spf.has.pphosted.com name to A record" ; 
    PS> resolve-dnsname -name ($resolvedSPFString.split(' ') | ?{$_ -match 'exists:'}).replace('exists:','') -type A -server 1.1.1.1 ; 

        Name                                           Type   TTL   Section    IPAddress                                
        ----                                           ----   ---   -------    ---------                                
        52.88.39.26._spf.mta.salesforce.com            A      3600  Answer     52.88.39.26            

    PS> write-verbose "A matching A record was returned for the macro expanded name => the SPF lookup passes.
    Demo retrieving an SPF record, expanding macros present, and then re-resolving the updated include: hostname to an existing A record (which therefore passes the SPF test).
    .EXAMPLE
    PS> $spfspec = resolve-dnsname -name toro.com -type TXT -server 1.1.1.1 | ? strings -match 'spf' | select -expand strings
    PS> $spfspec ; 

        v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com ~all

    PS> $resolvedSPFString = resolve-SPFMacros -SpfRecord $spfspec -IPAddress 170.92.7.36 -DomainName toro.com -SenderAddress PartsClaims@toro.com -SenderHeloName mymailoutlyn0.toro.com -verbose ;

        VERBOSE: 15:50:48:===> Specified $SpfRecord:
        v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com ~all
        has been resolved to:
        v=spf1 include:36.7.92.170.in-addr.toro.com.spf.has.pphosted.com ~all
        (sending to pipeline)

    PS> $resolvedSPFString  ; 

        v=spf1 include:36.7.92.170.in-addr.toro.com.spf.has.pphosted.com ~all

    PS> write-verbose "Resolve the include:36.7.92.170.in-addr.toro.com.spf.has.pphosted.com name to A record" ; 
    PS> resolve-dnsname -name ($xpanded.split(' ') | ?{$_ -match 'include:'}).replace('include:','') -type A -server 1.1.1.1

        Name                                           Type   TTL   Section    IPAddress                                
        ----                                           ----   ---   -------    ---------                                
        36.7.92.170.in-addr.toro.com.spf.has.pphosted. A      3600  Answer     127.0.0.2                                
        com        

    PS> write-verbose "A matching A record was returned for the macro expanded name => the SPF lookup passes.
    Demo retrieving an SPF record (in this case utilizes the include: mechanism), expanding macros present, and then re-resolving the updated include: hostname to an existing A record (which therefore passes the SPF test).
    
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://bitbucket.org/tostka/powershell/
    .LINK
    [ name related topic(one keyword per topic), or http://|https:// to help, or add the name of 'paired' funcs in the same niche (enable/disable-xxx)]
    #>
    <#List of Eggress IP addresses to resolve against SPF macro settings
    IPAddress
    DomainName to be tested for SPF validity
    DomainName
    #>
    #[Alias('ConvertTo-CanonicalName')]
    PARAM(
        [Parameter(Mandatory=$True,HelpMessage="Optional Pre-resolved SpfRecord specification string to be evaluated (skips initial resolution pass; used to recycle from Resolve-SPFRecord() call[-SpfRecord `$spfRec]")]
            <# 8:58 AM 12/13/2024 prob don't have to eval the v=spf for full spf compliance - not this func''s role, and it may be handling substrings of a full spf, so just sub through the sent text and send updated back
            [ValidateScript({
                ($_ -is [string])
                if($_ -match '^v=spf'){$true}else{
                    throw "specified SPF Record does not have a leading '^v=spf' string`nensure you are passing the expanded SPF specification, and not the entire retrieved DNS record" ; 
                } ; 
            })]
            #>
            #[string]
            [string[]]$SpfRecord, # make it an array to accomodate stacked strings, and crlf-split herestrings
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="Sending server IP Address(es) to be tested for '%{i}','%{ir}','%{v}','%{p}' IP-based macros in the DomainName SPF record[-IPAddress '192.168.1.1','192.168.1.2']")]
            #[ValidateNotNullOrEmpty()]
            #[Alias('ALIAS1', 'ALIAS2')]
            #[string[]]
            #if doing a single submitting server eval, this should be a single ip string, better, [system.net.ipaddress]
            [system.net.ipaddress]$IPAddress, # =  @($Tormeta.OP_ExEgressIPs + $CMWMeta.OP_ExEgressIPs) ,
        [Parameter(Mandatory=$True,HelpMessage="DomainName for which SPF records should be retrieved and tested against[-DomainName DOMAIN.COM]")]
            [ValidateNotNullOrEmpty()]
            [Alias('Domain','Name')]
            [string]$DomainName,
        [Parameter(Mandatory=$True,HelpMessage="Required SenderAddress to use for '%{d}','%{s}','%{l}','%{o}' SenderAddress based macros[-SenderAddress EMAIL@DOMAIN.TLD]")]
            [ValidateNotNullOrEmpty()]
            #[Alias('ALIAS1', 'ALIAS2')]
            [string]$SenderAddress,
        [Parameter(Mandatory=$false,HelpMessage="Optional Sending server HELO name, to use for '%{h}' macro substitution [-SenderHeloName SERVER.DOMAIN.TLD]")]
            [ValidateNotNullOrEmpty()]
            #[Alias('ALIAS1', 'ALIAS2')]
            [string]$SenderHeloName
    ) ; 
    BEGIN { 
        #region CONSTANTS_AND_ENVIRO #*======v CONSTANTS_AND_ENVIRO v======
        #region ENVIRO_DISCOVER ; #*------v ENVIRO_DISCOVER v------
        $Verbose = ($VerbosePreference -eq 'Continue') ; 
        # Debugger:proxy automatic variables that aren't directly accessible when debugging (must be assigned and read back from another vari) ; 
        $rPSCmdlet = $PSCmdlet ; 
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
        #region COMMON_CONSTANTS ; #*------v COMMON_CONSTANTS v------
    
        if(-not $DoRetries){$DoRetries = 4 } ;    # # times to repeat retry attempts
        if(-not $RetrySleep){$RetrySleep = 10 } ; # wait time between retries
        if(-not $RetrySleep){$DawdleWait = 30 } ; # wait time (secs) between dawdle checks
        if(-not $DirSyncInterval){$DirSyncInterval = 30 } ; # AADConnect dirsync interval
        if(-not $ThrottleMs){$ThrottleMs = 50 ;}
        if(-not $rgxDriveBanChars){$rgxDriveBanChars = '[;~/\\\.:]' ; } ; # ;~/\.:,
        if(-not $rgxCertThumbprint){$rgxCertThumbprint = '[0-9a-fA-F]{40}' } ; # if it's a 40char hex string -> cert thumbprint  
        if(-not $rgxSmtpAddr){$rgxSmtpAddr = "^([0-9a-zA-Z]+[-._+&'])*[0-9a-zA-Z]+@([-0-9a-zA-Z]+[.])+[a-zA-Z]{2,63}$" ; } ; # email addr/UPN
        if(-not $rgxDomainLogon){$rgxDomainLogon = '^[a-zA-Z][a-zA-Z0-9\-\.]{0,61}[a-zA-Z]\\\w[\w\.\- ]+$' } ; # DOMAIN\samaccountname 
        if(-not $exoMbxGraceDays){$exoMbxGraceDays = 30} ; 
        if(-not $XOConnectionUri ){$XOConnectionUri = 'https://outlook.office365.com'} ; 
        if(-not $SCConnectionUri){$SCConnectionUri = 'https://ps.compliance.protection.outlook.com'} ; 

        #region LOCAL_CONSTANTS ; #*------v LOCAL_CONSTANTS v------

        #endregion LOCAL_CONSTANTS ; #*------^ END LOCAL_CONSTANTS ^------  
        #endregion CONSTANTS_AND_ENVIRO ; #*------^ END CONSTANTS_AND_ENVIRO ^------

        #endregion CONSTANTS_AND_ENVIRO ; #*------^ END CONSTANTS_AND_ENVIRO ^------

        #region FUNCTIONS ; #*======v FUNCTIONS v======

        #endregion FUNCTIONS ; #*======^ END FUNCTIONS ^======

        #region BANNER ; #*------v BANNER v------
        $sBnr="#*======v $(${CmdletName}): v======" ;
        $smsg = $sBnr ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H1 } #Error|Warn|Debug
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        #endregion BANNER ; #*------^ END BANNER ^------

        # check if using Pipeline input or explicit params:
        if ($rPSCmdlet.MyInvocation.ExpectingInput) {
            $smsg = "Data received from pipeline input: '$($InputObject)'" ;
            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
        } else {
            # doesn't actually return an obj in the echo
            #$smsg = "Data received from parameter input: '$($InputObject)'" ;
            #if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
            #else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
        } ;

        if(-not $IPAddress){
            throw "Empty `!: (should contain `$Tormeta.OP_ExEgressIPs,`$CMWMeta.OP_ExEgressIPs)" ; 
            break ; 
        } else {
            #$IPAddress = $IPAddress | select -unique ; 
    
            $smsg = "`n`n==Processing:`$IPAddress:`n$(($IPAddress.IPAddressToString|out-string).trim())" ; 
            $smsg += "`nagainst DomainName: $($DomainName)`n`n" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

        } ;  ;
        if($SpfRecord){
            $smsg = "-SpfRecord specified: Using passed spf specification string" ; 
            $smsg = "`n$(($SpfRecord|out-string).trim())" ; 
            write-host -foregroundcolor yellow $smsg ; 
            $SpfRec = $SpfRecord ; 
        }else {
            #write-verbose "Resolve DNS SPF record: resolve-dnsname -name $($DomainName) -type TXT -server 1.1.1.1" ; 
            #$SpfRec = resolve-dnsname -name $DomainName -type TXT -server 1.1.1.1  -ea STOP| ? strings  -match '^v=spf' | select -expand strings ; 
            $smsg = "Missing REQUIRED -SpfRecord spec!" ; 
            throw $smsg ;
        } ; 

        #write-host -foregroundcolor green "Resolved $($DomainName) SPF strings:`n$(($SpfRec|out-string).trim())" ; 

        # check for macros syntax in spf record
        if($SpfRec -notmatch '%\{[slodipvh]}' ){
            #$smsg = "DomainName:$($DomainName) retrieved SPF record" ; 
            $smsg = "Provided SPF record (or substring)" ; 
            $smsg +="`nDOES NOT USE ANY SPF MACROS that act against dynamic per-host records" ; 
            $smsg +="`nThis script does not apply to this domain. ABORTING" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
            Break; 
        } ; 
        # $IPAddress
        if($SpfRec -match '%\{[ivp]}'){
            if(-not $IPAddress){
                $smsg = "SPF Record specified:" 
                $smsg += "`n$(($SpfRecord|out-string).trim())" ; 
                $smsg += "Includes IPAddress-dependant Macros '%{i}','%{ir}','%{v}','%{p}'" ; 
                $smsg += "`n but *no* `$IPAddress has been specified!" ; 
                $smsg += "`nPlease retry with a suitable `$IPAddress specification"
                throw $smsg ; 
                BREAK ; 
            } else{
                write-verbose  "SPF Record specified:Includes IPAddress-dependant Macros '%{i}','%{ir}','%{v}','%{p}', and an `$IPAddress has been specified ($($IPAddress.IPAddressToString))" ; 
            } ; 
        }; 
        # $SenderAddress
        if($SpfRec -match '%\{[dslo]}'){
            if(-not $SenderAddress){
                $smsg = "SPF Record specified:" 
                $smsg += "`n$(($SenderAddress|out-string).trim())" ; 
                $smsg += "Includes SenderAddress-dependant Macros '%{d}','%{s}','%{l}','%{o}'" ; 
                $smsg += "`n but *no* `$SenderAddress has been specified!" ; 
                $smsg += "`nPlease retry with a suitable `$SenderAddress specification"
                throw $smsg ; 
                BREAK ; 
            } else{
                write-verbose  "SPF Record specified:Includes SenderAddress-dependant Macros '%{d}','%{s}','%{l}','%{o}', and an `$SenderAddress has been specified ($($SenderAddress))" ; 
            } ; 
        }; 
        # $SenderHeloName
        if($SpfRec -match '%\{[h]}'){
            if(-not $IPAddress){
                $smsg = "SPF Record specified:" 
                $smsg += "`n$(($SenderAddress|out-string).trim())" ; 
                $smsg += "Includes Sender Server HELO name dependant Macro '%{h}'" ; 
                $smsg += "`n but *no* `$SenderHeloName has been specified!" ; 
                $smsg += "`nPlease retry with a suitable `$SenderHeloName specification"
                throw $smsg ; 
                BREAK ; 
            } else{
                write-verbose  "SPF Record specified:Includes Sender Server HELO name dependant Macro '%{h}', and a `$SenderHeloName has been specified ($($SenderHeloName))" ;
            } ; 
        }; 
    } ;  # BEGIN-E
    PROCESS {
        #Foreach($Computer in $IPAddress[-1] ){
        Foreach($Computer in $IPAddress.IPAddressToString ){
            $sBnrS="`n#*------v PROCESSING $($Computer): v------" ; 
            write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($sBnrS)" ;
            #region Resolve_Information ; #*------v Resolve_Information v------
            $isIPv4 = $isIPv6 = $isFQDN = $isNBName = $false ; 
            TRY{if(([ipaddress]$Computer).AddressFamily -eq 'InterNetwork'){ $isIpv4 = $true  } ; } CATCH {} ; 
            TRY{if(([ipaddress]$Computer).AddressFamily -eq 'InterNetworkV6'){ $isIPv6 = $true  } ; } CATCH {} ; 
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
                    write-verbose "Resolve IP to FQDN (PTR): `nresolve-dnsname -name $($Computer) -type PTR -ea STOP -server 1.1.1.1 | select -expand namehost" ; 
                    $Computer = resolve-dnsname -name $Computer -type PTR -ea STOP -server 1.1.1.1 | select -expand namehost; 
                } ; 
                if($isNBName){
                    write-verbose "Resolve NBName to FQDN (A): `nresolve-dnsname -name $($Computer) -type A -ea STOP -server 1.1.1.1 | select -expand Name" ; 
                    $Computer = resolve-dnsname -name $Computer -type A -ea STOP -server 1.1.1.1 | select -expand Name
                } ; 
            
                write-verbose "Resolve IP A Record: resolve-dnsname -name $($Computer) -type A: `nresolve-dnsname -name $($Computer) -type A  -ea STOP | select -first 1 " ; 
                TRY{
                    $ComputerARec = resolve-dnsname -name $Computer -type A  -ea STOP -server 1.1.1.1 | select -first 1  ; 
                    write-host -foregroundcolor green "Resolved $($Computer) A Record:`n$(($ComputerARec|out-string).trim())" ; 
                    $SendIP = $ComputerARec.IPAddress ; 
                    write-verbose "`$SendIP: $($SendIP)" ; 
                }CATCH{
                    $smsg = "Failed to:resolve-dnsname -name $($Computer) -type A " ; 
                    $smsg += "`nFalling back to original cached identifier: $($cachedName)" ; 
                    $smsg += "`n and reattempting resolution of that value" ; 
                    write-warning $smsg ; 
                    $Computer = $cachedName  ; 
                    if($isIPv4 -OR $isIPv6){$SendIP = $cachedName} ; 
                    # if non IPv4 or IPv6 and computer length is 6-253 chars, and is an fqdn, resolve fqdn to IPaddress
                    if( -not ($isIPv4 -OR $isIPv6) -AND (6 -le $Computer.length -le 253) -AND ($Computer -match '^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$') ){
                        write-verbose "resolve-dnsname -name $($Computer) -server 1.1.1.1 | select -first 1 | select -expand IPAddress" ; 
                        $SendIP = resolve-dnsname -name $Computer -ea stop -server 1.1.1.1 | select -first 1 | select -expand IPAddress
                    }  ;
                    # if non IPv4 or IPv6 and computer length is 1-15 chars, and is an nbname matching the input $IPAddress (computer), resolve the name to IPAddress
                    if( -not ($isIPv4 -OR $isIPv6) -AND  (1 -le $Computer.length -le 15) -AND ($Computer -replace '\\|/|:|\*|\?|"||\||\.' -eq $Computer) ){
                        write-verbose "resolve-dnsname -name $($Computer) -ea stop | select -first 1 | select -expand IPAddress" ; 
                        $SendIP = resolve-dnsname -name $Computer -ea stop -server 1.1.1.1 | select -first 1 | select -expand IPAddress
                    }  ;
                    write-verbose "`$SendIP: $($SendIP)" ; 
                } ; 
        
                #endregion Resolve_Information ; #*------^ END Resolve_Information ^------
                #region Macro_Expansion  ; #*------v Macro_Expansion v------
                $StepNo = 0 ; 

                #if($SpfRec -match '%\{[dslo]}'){
                if($SpfRec -match '%\{[i]}'){
                    write-verbose "$($StepNo++; $StepNo). Replace %{i} with with sender IP" ; 
                    #$SpfRec = $SpfRec
                    $SpfRec = $SpfRec.replace('%{i}',$SendIP) ; 
                } 
                if($SpfRec -match '%\{ir}'){
                    write-verbose "$($StepNo++; $StepNo). reverse the SendBox IP" ; 
                    $SendPTR = resolve-dnsname -name $SendIP -type PTR  -ea STOP -server 1.1.1.1 ; 
                    $SendIPRev = (($SendPTR | select -expand name) -split '.in-addr.')[0] ; 
                    write-verbose "$($StepNo++; $StepNo). Replace %{ir} with with reversed sender IP" ; 
                    #$SpfRecResolved = $SpfRec.replace('%{ir}',$SendIPRev) ; 
                    $SpfRec = $SpfRec.replace('%{ir}',$SendIPRev) ; 
                } ; 

                if($SpfRec -match '%\{v}'){
                    write-verbose "$($StepNo++; $StepNo). Replace %{v} with with sender IP version" ; 
                    switch(([ipaddress]$sendip).addressfamily){
                      'InterNetwork' { 
                          write-verbose "$($StepNo++; $StepNo). Replace %{v} with with in-addr for ipv4 IP" ; 
                          $SpfRec = $SpfRec.replace('%{v}','in-addr') 
                      }
                      'InterNetworkV6' {
                          write-verbose "$($StepNo++; $StepNo). Replace %{v} with with ip6 for ipv6 IP" ; 
                          $SpfRec = $SpfRec.replace('%{v}','ip6')
                      }
                    };
                } ; 

                #SenderAddress: '%{d}','%{s}','%{s}','%{o}'
                #'%\{d}','%\{s}','%\{s}','%\{o}' :::  '%\{[dslo]}'

                if($SpfRec -match '%\{d}' ){
                    write-host -foregroundcolor gray "Note: SPF Record conains SenderAddress-related Macros:`n$($SpfRec)" ; 
                    write-verbose "$($StepNo++; $StepNo). Replace %{d} with SPF sender domain" ; 
                    if(-not $SenderAddress -AND $DomainName){
                        write-verbose "$($StepNo++; $StepNo). Replace %{d} with SPF sender DomainName" ; 
                        $SpfRec = $SpfRec.replace('%{d}',$DomainName) ; 
                    } elseif($SenderAddress){
                        write-verbose "$($StepNo++; $StepNo). Replace %{d} with SPF split SenderAddress Domain" ; 
                        $SpfRec = $SpfRec.replace('%{d}',($SenderAddress.split('@')[1])) ; 
                    } ; 
                } ; 

                #if($SpfRec -match '%\{[dslo]}' ){
                if($SpfRec -match '%\{[slo]}' ){
                    write-warning "SPF Record conains SenderAddress-related Macros:`n$($SpfRec)" ; 
                    if(-not $SenderAddress){
                        $smsg = "$($StepNo++; $StepNo). WARN! No -SenderAddress specified from which to calculate SenderAddres macros!" ; 
                        write-warning $smsg ; 
                        throw $smsg ; 
                        break ; 
                    } else {
                        write-verbose "$($StepNo++; $StepNo). Replace %{s} with with sender address" ; 
                        $SpfRec = $SpfRec.replace('%{s}',$SenderAddress) ; 
                        write-verbose "$($StepNo++; $StepNo). Replace %{l} with with SenderAddress local part" ; 
                        $SpfRec = $SpfRec.replace('%{l}',$SenderAddress.split('@')[0]) ; 
                        write-verbose "$($StepNo++; $StepNo). Replace %{o} with with sender domain" ; 
                        $SpfRec = $SpfRec.replace('%{o}',$SenderAddress.split('@')[1]) ; 
                    } ; 
                } ; 

                if($SpfRec -match '%\{p}'){
                    <# 	%{p}: The validated reverse-DNS domain of the source IP, 
                        e.g. if example.com IN A is 203.0.113.1 and 1.113.0.203.in-addr.arpa IN PTR is example.com, 
                        the validated domain will be example.com.
                        if 170.92.7.36, sending server IP, resolves as -PTR -> 36.7.92.170.in-addr.arpa

                        [Automating SPF macro management with scripting and APIs: a step-by-step guide - AutoSPF - Automatic SPF flattening](https://autospf.com/blog/automating-spf-macro-management-with-scripting-apis-step-by-step-guide/)
                        %{p}: Represents the validated domain name of the sender’s IP address.

                    #>
                    #throw "$($StepNo++; $StepNo). $(SpfRec) contains the %{p} macro (replace HELO name from last conn)`ncannot emulate that state in a vacuum" ; 
                    #break ; 
                    # $SenderHeloName             
                    <#$smsg = "SPF Record specified:" 
                    $smsg += "`n$(($SenderAddress|out-string).trim())" ; 
                    $smsg += "Includes Sender Server HELO name dependant Macro '%{p}'" ; 
                    $smsg += "`n but *no* `$SenderHeloName has been specified!" ; 
                    $smsg += "`nPlease retry with a suitable `$SenderHeloName specification"       
                    #>
                    write-warning "SPF Record conains Sender Server HELO name dependant Macro '%{p}':`n$($SpfRec)" ; 
                    write-verbose "$($StepNo++; $StepNo). Replace %{p} with SPF sender domain" ; 
                    $SpfRec = $SpfRec.replace('%{p}',(($sendptr.namehost.split('.') | select -skip 1 ) -join '.')) ; 
                    if(-not $SenderHeloName){
                        $smsg = "$($StepNo++; $StepNo). WARN! No -SenderHeloName specified from which to replace %{p} macros!" ; 
                        write-warning $smsg ; 
                        throw $smsg ; 
                        break ; 
                    } ; 
                } ; 
                
                if($SpfRec -match '%\{h}'){
                    #throw "$($StepNo++; $StepNo). $(SpfRec) contains the %{h} macro (replace HELO name from last conn)`ncannot emulate that state in a vacuum" ; 
                    #break ; 
                    # $SenderHeloName             
                    <#$smsg = "SPF Record specified:" 
                    $smsg += "`n$(($SenderAddress|out-string).trim())" ; 
                    $smsg += "Includes Sender Server HELO name dependant Macro '%{h}'" ; 
                    $smsg += "`n but *no* `$SenderHeloName has been specified!" ; 
                    $smsg += "`nPlease retry with a suitable `$SenderHeloName specification"       
                    #>
                    write-warning "SPF Record conains Sender Server HELO name dependant Macro '%{h}':`n$($SpfRec)" ; 
                    write-verbose "$($StepNo++; $StepNo). Replace %{h} with SPF sender domain" ; 
                    $SpfRec = $SpfRec.replace('%{h}',$SenderHeloName) ; 
                    if(-not $SenderHeloName){
                        $smsg = "$($StepNo++; $StepNo). WARN! No -SenderHeloName specified from which to replace %{h} macros!" ; 
                        write-warning $smsg ; 
                        throw $smsg ; 
                        break ; 
                    } ; 
                } ; 

                $smsg = "===> Specified `$SpfRecord:" ; 
                $smsg += "`n$(($SpfRecord|out-string).trim())" ; 
                $smsg += "`nhas been resolved to:"
                $smsg += "`n$(($SpfRec|out-string).trim())" ; 
                $smsg += "`n(sending to pipeline)" ; 
                if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 

                $SpfRec | write-output ;

            } CATCH {
                $ErrTrapd=$Error[0] ;
                $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;
                write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" ;
            } ; 
            write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($sBnrS.replace('-v','-^').replace('v-','^-'))`n" ;
        } ;  # loop-E
    }  # PROC-E
    END{
        $smsg = "$($sBnr.replace('=v','=^').replace('v=','^='))" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H1 } #Error|Warn|Debug
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        $stopResults = try {Stop-transcript -ErrorAction stop} catch {} ;
        if($stopResults){
            $smsg = "Stop-transcript:$($stopResults)" ; 
            # Opt:verbose
            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
            # # Opt:pswlt
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
        } ; 
    } ;
} ; 
#*------^ resolve-SPFMacros.ps1 ^------
