# Test-DnsDkimCnameToTxtKeyTDO.ps1
#*------v Function Test-DnsDkimCnameToTxtKeyTDO v------
function Test-DnsDkimCnameToTxtKeyTDO {
    <#
    .SYNOPSIS
    Test-DnsDkimCnameToTxtKeyTDO - Trace a local CNAME DKIM DNS record, to it's endpoint TXT DKIM key-holding record (and validate it's actually a DKIM key). 
    .NOTES
    Version     : 0.0.5
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2022-11-03
    FileName    : Test-DnsDkimCnameToTxtKeyTDO
    License     : MIT License
    Copyright   : (c) 2022 Todd Kadrie
    Github      : https://github.com/tostka/verb-network
    Tags        : Powershell
    REVISIONS
    * 5:41 PM 12/30/2022 expanded rgx public-key test, added dkim key tag 
        requirements doc, test is down to essential p=xxx public key only ;  updated 
        CBH demos w fancy EXO DKIM per-domain looped validation; ported to func, 
        working; init;  
    .DESCRIPTION
    Test-DnsDkimCnameToTxtKeyTDO - Trace a local CNAME DKIM DNS record, to it's endpoint TXT DKIM key-holding record (and validate it's actually a DKIM key). 

       Along the way, I did a *a fair amount* of coding logic...

        1. running looped CNAME resolve-dnsname's, 
        2. detecting a returned SOA type (when the next record was a TXT), 
        3. then switching resolution to a final TXT resolve-dnsname pass.
    
    ... to quickly deliver local domain CNAME to remote SAAS vendor DKIM key TXT validation
     (when, 'It NO WORKY!' tickets came through against 3rd-party operated services). 

    Had that version *working*, and *then* while testing, I noticed a 'feature' of resolve-dnsname:

    Feed a cname fqdn through resolve-dnsname, WITHOUT A TYPE spec, and it AUTO RECURSES!
        - If it's a CNAME -> CNAME -> TXT chain, you'll get back 3 records: CNAME, CNAME, SOA (fail indicator). 
        - Postfilter out the SOA, and you've got the series of initial hops to the TXT.
        - Then Run a final -type TXT on the last CNAME's NameHost, and you get the TXT back (with the DKIM key)
   
    > Note: have to strongly type output assignment as Array to get proper Op.addition support for the trailing TXT record.

    $results = @(resolve-dnsname CNAME.domain.tld  -server 1.1.1.1 |? type -ne 'SOA') ; 
    $results += @($results | select -last 1  | %{resolve-dnsname -type TXT -server 1.1.1.1 -name $_.namehost}) ; 

    => 99% of my prior non-reporting & content validating code, could be reduced down to the above 2 LINES! [facepalm]

    I've retained the rem'd out original code (in case they write the 'autorecurse' feature out, down the road), but boiled this down to that essential logic above.

    Uses my verb-IO module convertTo-MarkdownTable() to box-format the output, diverts to format-table -a when it's not available. 

    .PARAMETER DkimDNSName
    Local AcceptedDomain CNAME DKIM DNS record, to be trace-resolved to key-holding TXT record. [-DkimDNSName 'host.domain.com']
    .PARAMETER PublicDNSServerIP
    Public DNS server (defaults to Cloudflare's 1.1.1.1, could use Google's 8.8.8.8)[-PublicDNSServerIP '8.8.8.8']
    .PARAMETER outputObject
    Switch that triggers output of results to pipeline [-outputObject] 
    .INPUTS
    None. Does not accepted piped input.(.NET types, can add description)
    .OUTPUTS
    None. Returns no objects or output (.NET types)
    .EXAMPLE
    PS> Test-DnsDkimCnameToTxtKeyTDO -DkimDNSName HOST.DOMAIN.COM -verbose ;
    Demo resursive CNAME to TXT DKIM key resolve of DKIM CNAME DNS record name
    .EXAMPLE
    PS> Test-DnsDkimCnameToTxtKeyTDO -DkimDNSName 'selector1._domainkey.DOMAIN.TLD','HOST.DOMAIN.com' ; 
        11:25:09:#*======v Test-DnsDkimCnameToTxtKeyTDO v======
        11:25:09:
        #*------v PROCESSING : selector1._domainkey.DOMAIN.TLD v------
        11:25:09:

        ==HOP: 1: CNAME: selector1._domainkey.DOMAIN.TLD ==> selector1-domain-tld._domainkey.TENANT.onmicrosoft.com:
        | Type  | Name                            | NameHost                                               |
        | ----- | ------------------------------- | ------------------------------------------------------ |
        | CNAME | selector1._domainkey.DOMAIN.TLD | selector1-domain-tld._domainkey.TENANT.onmicrosoft.com |
        
        11:25:09:

        ==HOP: 2: TXT:Value record::

        | Type | Name                                                   |
        | ---- | ------------------------------------------------------ |
        | TXT  | selector1-domain-tld._domainkey.TENANT.onmicrosoft.com |

        | Strings         |
        | --------------- |
        | v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3D[TRIMMED]NcHJRPWbPisCiRFPfUGtCNQIDAQAB; |
        
        ===:TXT: selector1-domain-tld._domainkey.TENANT.onmicrosoft.com.strings *IS VALIDATED* to contain a DKIM key:
        
        11:25:09:
        #*------^ PROCESSING : selector1._domainkey.DOMAIN.TLD ^------
        11:25:09:
        #*------v PROCESSING : HOST.DOMAIN.com v------
        11:25:09:

        ==HOP: 1: CNAME: HOST.DOMAIN.com ==> HOST.vnnnnnnnn.nnnnnnnnnn.e.VENDOR.services:
        | Type  | Name            | NameHost                                    |
        | ----- | --------------- | ------------------------------------------- |
        | CNAME | HOST.DOMAIN.com | HOST.vnnnnnnnn.nnnnnnnnnn.e.VENDOR.services |
        
        11:25:09:

        ==HOP: 2: CNAME: HOST.vnnnnnnnn.nnnnnnnnnn.e.VENDOR.services ==> unnnnnnnn.wlnnn.sendgrid.net:
        | Type  | Name                                        | NameHost                     |
        | ----- | ------------------------------------------- | ---------------------------- |
        | CNAME | HOST.vnnnnnnnn.nnnnnnnnnn.e.VENDOR.services | unnnnnnnn.wlnnn.sendgrid.net |
        
        WARNING: 11:25:09:

        ==HOP: 3: TXT:Value record::

        | Type | Name                         |
        | ---- | ---------------------------- |
        | TXT  | unnnnnnnn.wlnnn.sendgrid.net |

        | Strings         |
        | --------------- |
        | v=spf1 ip4:167.11.11.96 ip4:167.11.11.1 ip4:167.11.11.100 ip4:167.11.11.102 -all |
        
        ===:TXT: unnnnnnnn.wlnnn.sendgrid.net.strings *DOES NOT VALIDATE* to contain a DKIM key!
        (strings should start with 'v=DKIM1')

        11:25:09:
        #*------^ PROCESSING : HOST.DOMAIN.com ^------
        11:25:09:#*======^ Test-DnsDkimCnameToTxtKeyTDO ^======

    Demo looping array of names, with one with a failure to validate ('cuz the vendor stuffed an SPF where a DKIM TXT record belonged!)
    .EXAMPLE
    PS>  $domains = Get-xoDkimSigningConfig |Where-Object {$_.Enabled -like "True" -AND $_.name -notlike '*.onmicrosoft.com'} ;
    PS>  foreach($domain in $domains){
    PS>      $dNow = Get-date ; 
    PS>      $lCNAMES1 = "$($domain.Selector1CNAME.split('-')[0])._domainkey.$($domain.Name)" ; 
    PS>      $lCNAMES2 = "$($domain.Selector2CNAME.split('-')[0])._domainkey.$($domain.Name)" ; 
    PS>      $PreRollSelector = $domain.SelectorBeforeRotateOnDate ; 
    PS>      $PostRollSelector = $domain.SelectorAfterRotateOnDate ; 
    PS>      If($($domain.RotateOnDate.ToUniversalTime()) -gt $($dNow.ToUniversalTime()) ){
    PS>          $whichSelector = "$($PreRollSelector)Cname" ; 
    PS>      } else{
    PS>          $whichSelector = "$($PostRollSelector)Cname" ; 
    PS>      } ; 
    PS>      $ActiveSelector = $domain."$whichSelector" ;
    PS>      $ActivelCNAME = @($lCNAMES1,$lCNAMES2) | ?{$_ -like "$($domain."$whichSelector".split('-')[0])*"} ; 
    PS>      $INActivelCNAME = @($lCNAMES1,$lCNAMES2) | ?{$_ -notlike "$($domain."$whichSelector".split('-')[0])*"} ; 
    PS>      $ActivelCNAME | Test-DnsDkimCnameToTxtKeyTDO ; 
    PS>      write-host "Validate *INACTIVE* local CNAME (exists in local External DNS, but won't be resolvable at vendor)" ; 
    PS>      $INActivelCNAME | Resolve-DnsName -Type CNAME -server 1.1.1.1 | ft -a 'Type','Name','NameHost' ;
    PS>  } ; 

        16:01:09:#*======v Test-DnsDkimCnameToTxtKeyTDO v======
        16:01:09:
        #*------v PROCESSING : selector2._domainkey.DOMAIN.TLD v------
        16:01:10:

        ==HOP: 1: CNAME: selector2._domainkey.DOMAIN.TLD ==> selector2-domain-tld._domainkey.TENANT.onmicrosoft.com:
        | Type  | Name                          | NameHost                                             |
        | ----- | ----------------------------- | ---------------------------------------------------- |
        | CNAME | selector2._domainkey.DOMAIN.TLD | selector2-domain-tld._domainkey.TENANT.onmicrosoft.com |


        16:01:10:

        ==HOP: 2: TXT:Value record::

        | Type | Name                                                 |
        | ---- | ---------------------------------------------------- |
        | TXT  | selector2-domain-tld._domainkey.TENANT.onmicrosoft.com |

        | Strings         |
        | --------------- |
        | v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUA[TRIMMED]4/EVxy78tKSfzdMoBV20IDO9GvGnDF1WLdOO48IUi+1Oa4bMoLqizt5Duv4WbgY/lXePnSA9iQIDAQAB; |

        --->TXT: selector2-domain-tld._domainkey.TENANT.onmicrosoft.com.strings *IS VALIDATED* to contain a DKIM key.

        16:01:10:
        #*------^ PROCESSING : selector2._domainkey.DOMAIN.TLD ^------
        16:01:10:#*======^ Test-DnsDkimCnameToTxtKeyTDO ^======
        Validate *INACTIVE* local CNAME (exists in local External DNS, but won't be resolvable at vendor)

         Type Name                          NameHost
         ---- ----                          --------
        CNAME selector1._domainkey.DOMAIN.TLD selector1-domain-tld._domainkey.TENANT.onmicrosoft.com
    
        # (above continues for each configured enabled domain)

    Fancier demo of walking the enabled EXO DkimSigningConfig domains (non-onmicrosoft, which have no local DNS validation), foreach:
        - resolve the pair of local CNAME hostnames (MS uses 2, rolled on key rollovers sequentially, only one active at a time).
        - calculate the active MS Selector, and the matching local CNAME
        - Then validating the chain from the active local CNAME through to the MS-hosted TXT record and validating it has a DKIM key.
    .LINK
    https://bitbucket.com/tostka/powershell
    #>
    # VALIDATORS: [ValidateNotNull()][ValidateNotNullOrEmpty()][ValidateLength(24,25)][ValidateLength(5)][ValidatePattern("some\sregex\sexpr")][ValidateSet("US","GB","AU")][ValidateScript({Test-Path $_ -PathType 'Container'})][ValidateScript({Test-Path $_})][ValidateRange(21,65)]#positiveInt:[ValidateRange(0,[int]::MaxValue)]#negativeInt:[ValidateRange([int]::MinValue,0)][ValidateCount(1,3)]
    ## [OutputType('bool')] # optional specified output type
    [CmdletBinding()]
    PARAM(
        [Parameter(Mandatory=$true,Position = 0,ValueFromPipeline = $True,HelpMessage="Array of local AcceptedDomain CNAME DKIM DNS record, to be trace-resolved to key-holding TXT record. [-DkimDNSName 'host.domain.com']")]
        [Alias('Name')]
        [string[]] $DkimDNSName,
        [Parameter(HelpMessage="Public DNS server (defaults to Cloudflare's 1.1.1.1, could use Google's 8.8.8.8)[-PublicDNSServerIP '8.8.8.8']")]
        [Alias('Server')]
        [ipaddress]$PublicDNSServerIP = '1.1.1.1',
        [Parameter(HelpMessage="Switch that triggers output of results to pipeline [-outputObject]")]
        [switch]$outputObject
    ) ;
    BEGIN{
        #region CONSTANTS-AND-ENVIRO #*======v CONSTANTS-AND-ENVIRO v======
        # function self-name (equiv to script's: $MyInvocation.MyCommand.Path) ;
        ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
        $verbose = ($VerbosePreference -eq "Continue") ;
        $PSParameters = New-Object -TypeName PSObject -Property $PSBoundParameters ;
        write-verbose "`$PSBoundParameters:`n$(($PSBoundParameters|out-string).trim())" ;

                                                                                                                                                                                                                                                                                                                                                                                                                                                                            
<# PRIOR CODE THAT HAS BEEN SUBSTANTIALLY REPLACED WITH THE DEMO IN THE CBH:

$pltRDNS=[ordered]@{
    Name= $null ;
    Type='CNAME' ;
    Server=$PublicDNSServerIP ;
    erroraction = 'SilentlyContinue' ;
} ;
$smsg = "Recursive CNAME -> TXT lookup..." ; 
if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level PROMPT } 
else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
#Levels:Error|Warn|Info|H1|H2|H3|Debug|Verbose|Prompt
$pltRDNS.Name= $DkimDNSName;
$pltRDNS.type = 'CNAME' ; 
$pltRDNS.erroraction = 'SilentlyContinue' ;
$depth = 0 ; 
$CNAMEEnd = $false ; 
$prpCNAME = 'Type','Name','NameHost' ; 
$prpTXT = 'Type','Name','Strings' ; 
$prpSOA = 'Type','Name','PrimaryServer' ; 
$TypeOrder = 'CNAME','TXT' ; 
$TypeCurr = 0 ; 
$ResolvedStack = @() ; 
$works = $null ; 
$rNo=1 ; 
Do {
    if($works -eq $null){
        $pltRDNS.Name = $DkimDNSName; 
    } else { 
        if(-not $works.namehost){
            $pltRDNS.name = $priorName
        } else {
            $pltRDNS.Name = $works.namehost
        } ; 
    } ; 
    $pltRDNS.type = $TypeOrder[$TypeCurr] ; 
    $depth ++ ; 
    $smsg = "==Hop:$($rNo):"
    $smsg += "Resolve-DnsName w`n$(($pltRDNS|out-string).trim())" ; 
    if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
    $works = $null ; 
    $works = Resolve-DnsName @pltRDNS ; 
    If($works){
        switch($works.type){
            $TypeOrder[$TypeCurr]{
                $smsg = "record.Type:$($works.Type) returned (expected for this query type)" ; 
                $smsg += "`n$(($works|out-string).trim())" ; 
                if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                $priorName = $works.NameHost ; 
                $ResolvedStack += $works ;
                if($works.Type -eq 'TXT'){
                    $CNAMEEnd = $true ;
                    Break ; 
                } ; 
                $rNo++ 
            } 
            default {
                $smsg = "($($TypeOrder[$TypeCurr]):attempted lookup fail: type:$($works.type) returned. Retrying as $($TypeOrder[$TypeCurr + 1]))" ; 
                if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                $TypeCurr++ ; 
            } 
        }  ; 
    } else {
        $smsg = "Resolution attempt FAILED to return populated data!" ; 
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } 
        else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
    } ;     
} Until ($CNAMEEnd -eq $true) ; 
$smsg = "(Lookup chain completed, $($rNo) Hops traced)" ; 
if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level PROMPT } 
else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
#Levels:Error|Warn|Info|H1|H2|H3|Debug|Verbose|Prompt
$rNo=0 ; 
foreach($rec in $ResolvedStack){
    $rNo++ ; 
    $smsg = "`n`n==HOP: $($rNo): " ;
    switch ($rec.type){
        'CNAME' {
            $smsg += "$($rec.Type): $($rec.Name) ==> $($rec.NameHost):" ; 
            #$smsg += "`n`n$(($rec | ft -a $prpCNAME |out-string).trim())`n" ; 
            $smsg += "`n" ; 
            $smsg += $rec | select $prpCNAME | Convertto-Markdowntable -Border ; 
            $smsg += "`n" ; 
        } 
        'TXT' { 
            $smsg += "$($rec.Type):Value record::`n" ; 
            #$smsg += "`n$(($rec | ft -a $prpTXT[0..1] |out-string).trim())" ; 
            #$smsg += "`nStrings(e.g KEY FIELD):`n$(($rec | ft -a $prpTXT[2] | out-string).trim())" ; 
            $smsg += "`n" ; 
            #$smsg += $rec | select $prpTXT | Convertto-Markdowntable -Border ; 
            $smsg += $rec | select $prpTXT[0..1] | Convertto-Markdowntable -Border ; 
            $smsg += "`n" ;
            $smsg += $rec | select $prpTXT[2] | Convertto-Markdowntable -Border ; 
            $smsg += "`n" ; 
            if($rec.Strings -match 'v=DKIM1;\sk=rsa;\sp='){
                $domainSummary.TXTActiveValid = $true ; 
                $smsg += "`n--->TXT: $($rec.Name).strings *IS VALIDATED* to contain a DKIM key.`n" ; 
            }else {
                $smsg += "`n`n--->TXT: $($rec.Name).strings *DOES NOT VALIDATE* to contain a DKIM key`n`n" ; 
                throw $smsg ; 
            }
       } 
       'SOA' {
            $smsg += "`nSOA/Lookup-FAIL record detected!" ; 
            $smsg += "`n$(($rec | ft -a $prpSOA | out-string).trim())" ; 
            throw $smsg ;
       }
       default {throw "Unrecognized record TYPE!" } 
    } ; 
    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
};
write-host " " ; 
    #>

        $prpCNAME = 'Type','Name','NameHost' ; 
        $prpTXT = 'Type','Name','Strings' ; 
        $prpSOA = 'Type','Name','PrimaryServer' ; 
        $sBnr="#*======v $($CmdletName) v======" ; 
        $whBnr = @{BackgroundColor = 'Magenta' ; ForegroundColor = 'Black' } ;
        write-host @whBnr -obj "$((get-date).ToString('HH:mm:ss')):$($sBnr)" ;
    } ; 
    PROCESS{
        foreach($item in $DkimDNSName){

            $sBnrS="`n#*------v PROCESSING : $($item) v------" ; 
            $whBnrS =@{BackgroundColor = 'Blue' ; ForegroundColor = 'Cyan' } ;
            write-host @whBnrS -obj "$((get-date).ToString('HH:mm:ss')):$($sBnrS)" ;
            [array]$results = @() ; 
            $results = @(resolve-dnsname $item -server $PublicDNSServerIP) ; 

            write-verbose "postfilter out the SOA result  (leaving CNAMES)" ; 
            $results = $results |? type -ne 'SOA' ; 

            write-verbose " then re-search and add the Namehost on the final CNAME as a TXT" ; 
            $results += @($results | select -last 1  | %{resolve-dnsname -type TXT -server $PublicDNSServerIP -name $_.namehost}) ; 

            write-verbose "Report the formatted/validated output" ;
            $rNo=0 ; 
            foreach($rec in $results){
                $rNo++ ; 
                $RecFail = $false ; 
                $smsg = "`n`n==HOP: $($rNo): " ;
                switch ($rec.type){
                    'CNAME' {
                        $smsg += "$($rec.Type): $($rec.Name) ==> $($rec.NameHost):" ; 
                        $smsg += "`n" ; 
                        if(get-command Convertto-Markdowntable -ea 0){
                            $smsg += $rec | select $prpCNAME | Convertto-Markdowntable -Border ; 
                        } else { 
                            $smsg += $rec | ft -a $prpCNAME  ; 
                        } ; 
                        $smsg += "`n" ; 
                    } 
                    'TXT' { 
                        $smsg += "$($rec.Type):Value record::`n" ; 
                        $smsg += "`n" ; 
                        if(get-command Convertto-Markdowntable -ea 0){
                            $smsg += $rec | select $prpTXT[0..1] | Convertto-Markdowntable -Border ; 
                            $smsg += "`n" ;
                            $smsg += $rec | select $prpTXT[2] | Convertto-Markdowntable -Border ; 
                        } else { 
                            $smsg += $rec | ft -a  $prpTXT[0..1] ; 
                            $smsg += "`n" ;
                            $smsg += $rec | ft -a $prpTXT[2] ; 
                        } ; 
                        $smsg += "`n" ; 
<# 
    # DKIM TAG REQUIREMENTS

    [DKIM DNS record overview – Validity Help Center - help.returnpath.com/](https://help.returnpath.com/hc/en-us/articles/222481088-DKIM-DNS-record-overview)

    ### Required tag

    -   p= is the public key used by a mailbox provider to match to the DKIM 
        signature generated using the private key. The value is a string of characters 
        representing the public key. It is generated along with its corresponding 
        private key during the DKIM set-up process

    ### Recommended optional tags 
    -   v= is the version of the DKIM record. The value must be DKIM1 and be 
        the first tag in the DNS record

    -   t= indicates the domain is testing DKIM or is enforcing a domain 
        match in the signature header between the "i=" and "d=" tags

    -   t=y indicates the domain is testing DKIM.​ Senders use this tag 
        when first setting up DKIM to ensure the DKIM signature is verifying correctly. 
        Some mailbox providers ignore a DKIM signature in test mode, so this tag should 
        be removed prior to full deployment or changed to t=s if using the "i=" tag in 
        the DKIM signature header

    -   t=s indicates that any DKIM signature header using the "i=" tag 
        must have the same domain value on the right-hand side of the @ sign in the 
        "i=" tag and the "d=" tag (i= local-part@domain.com). The "i=" tag  domain must 
        not be a subdomain of the "d=" tag. Do not include this tag if the use of a 
        subdomain is required

    ### Optional tags 
    -   g= is the granularity of the public key. The value must match the 
        local-part of the i= flag in the DKIM signature field (i= 
        local-part@domain.com) or contain a wildcard asterisk (\*). The use of this 
        flag is intended to constrain which signing address can use the selector 
        record

    -   h= indicates which hash algorithms are acceptable. The default 
        value is to allow for all algorithms but you can specify sha1 and sha256. 
        Signers and verifiers must support sha256. Verifiers must also support sha1

    -   k= indicates the key type. The default value is rsa which must be 
        supported by both signers and verifiers

    -   n= is a note field intended for administrators, not end users. 
        The default value is empty and may contain a note that an administrator may 
        want to read

    -   s= indicates the service type to which this record applies. The 
        default value is a wildcard asterisk (\*) which matches all service types. The 
        other acceptable value allowed is the word "email" which indicates that the 
        message is an electronic mail message. This tag is not the same as a selector record.
        It is intended to constrain the use of keys if DKIM is used for other 
        purposes other than email in the future. If used, it is included in the DKIM 
        DNS TXT record and not the DKIM signature. Should other service types be 
        defined in the future, verifiers will ignore the DKIM record if it does not 
        match the type of message sent

 

#>
                        #if($rec.Strings -match 'v=DKIM1;\sk=rsa;\sp='){
                        if($rec.Strings -match 'v=DKIM1;\sk=rsa;\sp='){
                            $smsg += "`n`n--->TXT: $($rec.Name).strings *IS VALIDATED* to contain a DKIM key.`n`n" ; 
                        }elseif($rec.Strings -match 'p=\w+'){
                            # per above, this matches only the bare minimum!
                            $smsg += "`n`n--->TXT: $($rec.Name).strings *IS VALIDATED* to contain a DKIM key.`n`n" ; 
                        }else {
                            $smsg += "`n`n--->TXT: $($rec.Name).strings *DOES NOT VALIDATE* to contain a DKIM key!`n(strings should start with 'v=DKIM1', or at minimum include a p=xxx public key)`n`n" ; 
                            #if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } 
                            #else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                            #write-host @whBnr -obj "$((get-date).ToString('HH:mm:ss')):$($sBnr.replace('=v','=^').replace('v=','^='))" ;
                            #throw $smsg ; 
                            #Break ; 
                            $RecFail = $true ; 
                        }
                   } 
                   'SOA' {
                        $smsg += "`nSOA/Lookup-FAIL record detected!" ; 
                        $smsg += "`n$(($rec | ft -a $prpSOA | out-string).trim())" ; 
                        #throw $smsg ;
                        $RecFail = $true ; 
                   }
                   default {throw "Unrecognized record TYPE!" ; $RecFail = $true ; } 
                } ; 

                if($RecFail -eq $true){
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } 
                    else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                } else { 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                } ; 

            };  # loop-E

            if($outputObject){
                $smsg = "(output results to pipeline)" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #Levels:Error|Warn|Info|H1|H2|H3|Debug|Verbose|Prompt
                $results | write-output ; 
            } ; 
            write-host @whBnrS -obj "$((get-date).ToString('HH:mm:ss')):$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;

        } ;  # loop-E
    }  # PROC-E
    END{
        write-host @whBnr -obj "$((get-date).ToString('HH:mm:ss')):$($sBnr.replace('=v','=^').replace('v=','^='))" ;
    } ;
} ; 
#*------^ END Function Test-DnsDkimCnameToTxtKeyTDO ^------