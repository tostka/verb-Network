#*------v Function Resolve-DnsSenderIDRecords v------
function Resolve-DnsSenderIDRecords {
    <#
    .SYNOPSIS
    Resolve-DnsSenderIDRecords.ps1 - Function to resolve a given domain's SPF & DMARC records, and attempt to detect existing DKIM records (searching common selector host names)
    .NOTES
    Version     : 0.0.
    Author      :  (T13nn3s )
    Website     : https://binsec.nl
    Twitter     : @T13nn3s / https://twitter.com/T13nn3s
    CreatedDate : 2022-04-06
    FileName    : Resolve-DnsSenderIDRecords.ps1
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/powershell
    Tags        : Powershell,DNS,Email,SPF
    AddedCredit : Todd Kadrie
    AddedWebsite: toddomation.com
    AddedTwitter: @tostka/https://twitter.com/tostka
    REVISIONS
    * 9:24 AM 3/20/2024 rework output - dumping mix of record types into the pipeline - with mult dkim selectors is a confusing mismatch return: flip to a constructed object with SPF, DKIM & DMARC as sub-objects that can be examined in isolation.
    * 3:01 PM 3/19/2024 adapt to full range of SenderID resolution from get-DNSDkimRecord.ps1
    * 11/02/2022 T13nn3s posted rev v1.5.2 (DKIM expansion example)
    .DESCRIPTION
    Resolve-DnsSenderIDRecords.ps1 - Function to resolve a given domain's SPF & DMARC records, and attempt to detect existing DKIM records (searching common selector host names)

    Reasonable listing of common selectors here
    [Email Provider Commonly Used DKIM Selectors : Sendmarc - help.sendmarc.com/](https://help.sendmarc.com/support/solutions/articles/44001891845-email-provider-commonly-used-dkim-selectors)


    .PARAMETER Name
    Specifies the domain for resolving the DKIM-record.[-Name Domain.tld]
    .PARAMETER DkimSelector
    Specify a custom DKIM selector.[-DkimSelector myselector
    .PARAMETER Server
    DNS Server to use.[-Server 8.8.8.8]
    .INPUTS
    Accepts piped input.
    .OUTPUTS
    System.object
    .EXAMPLE
    PS> $results = Resolve-DnsSenderIDRecords -name SOMEDOMAIN.com ;
    PS> write-verbose 'Display returned object properties'
    PS> $results | get-member ; 

            TypeName: System.Management.Automation.PSCustomObject

        Name        MemberType   Definition                                                                                                                             
        ----        ----------   ----------                                                                                                                             
        Equals      Method       bool Equals(System.Object obj)                                                                                                         
        GetHashCode Method       int GetHashCode()                                                                                                                      
        GetType     Method       type GetType()                                                                                                                         
        ToString    Method       string ToString()                                                                                                                      
        DKIM        NoteProperty System.Collections.Generic.List`1[[System.Object, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]] DKIM=  
        DMARC       NoteProperty System.Collections.Generic.List`1[[System.Object, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]] DMARC= 
        SPF         NoteProperty System.Collections.Generic.List`1[[System.Object, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]] SPF=   

    PS> write-verbose 'Includes SPF, DKIM, and DMARC information for specified domain' ; 
    PS> write-verbose "examine properties of SPF returned" ; 

        $return.spf

        Name                SPFRecord                                  ReturnedType
        ----                ---------                                  ------------
        mtidistributing.com Microsoft.DnsClient.Commands.DnsRecord_TXT          TXT
        $return.spf.spfrecord

    PS> write-verbose "Examine SPF record returned" ; 
    PS> $return.spf.spfrecord ; 

        Name                                     Type   TTL   Section    Strings                                  
        ----                                     ----   ---   -------    -------                                  
        mtidistributing.com                      TXT    3600  Answer     {v=spf1 ip4:64.16.11.232/32              
                                                                         ip4:64.16.11.233/32                      
                                                                         include:spf.termsync.com                 
                                                                         include:spf.protection.outlook.com       
                                                                         include:sendgrid.net -all}           
    PS> write-verbose "Examine DKIM summaries returned" ; 
    PS> $return.dkim

        Name         : mtidistributing.com
        DkimRecord   : Microsoft.DnsClient.Commands.DnsRecord_PTR
        DkimSelector : selector1
        ReturnedType : CNAME
        DKIMAdvisory : Located CNAME pointer

        Name         : mtidistributing.com
        DkimRecord   : v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCstQzRq+OSOJM8isy+RYnrVMmZrfXLujLs3e1z5eILA0Ya8MQFYGOQgJbj06nyNtC3Qb2vHWcvX6oU/hBJ5fLeaH3lIcgbG91p3cE/4gxh9rncprv/ICkfj0SqIalwoie2uEcWfPmkCMaAwNKIB77SGDEPnetgqt
                       SVC5XMFFTtJwIDAQAB;
        DkimSelector : selector1
        ReturnedType : TXT
        DKIMAdvisory : DKIM-record found.

        Name         : mtidistributing.com
        DkimRecord   : Microsoft.DnsClient.Commands.DnsRecord_PTR
        DkimSelector : selector2
        ReturnedType : CNAME
        DKIMAdvisory : Located CNAME pointer

    PS> write-verbose "Examine DKIM records returned" ; 
    PS> $return.dkim | %{write-host "`n`n$(($_.dkimrecord|out-string).trim())" ; }

        Name                           Type   TTL   Section    NameHost                                                                                                                                                                        
        ----                           ----   ---   -------    --------                                                                                                                                                                        
        selector1._domainkey.mtidistri CNAME  3600  Answer     selector1-mtidistributing-com._domainkey.mtidistributing.onmicrosoft.com                                                                                                        
        buting.com


        v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCstQzRq+OSOJM8isy+RYnrVMmZrfXLujLs3e1z5eILA0Ya8MQFYGOQgJbj06nyNtC3Qb2vHWcvX6oU/hBJ5fLeaH3lIcgbG91p3cE/4gxh9rncprv/ICkfj0SqIalwoie2uEcWfPmkCMaAwNKIB77SGDEPnetgqtSVC5XMFFTtJwIDAQ
        AB;


        Name                           Type   TTL   Section    NameHost                                                                                                                                                                        
        ----                           ----   ---   -------    --------                                                                                                                                                                        
        selector2._domainkey.mtidistri CNAME  3600  Answer     selector2-mtidistributing-com._domainkey.mtidistributing.onmicrosoft.com                                                                                                        
        buting.com

    PS> write-verbose "In this case two selector CNAMES were discovered, and a single functional DKIM TXT key record (not unusual: MS for example only makes one selector of the pair functional at a time, for key rotation process)"
    PS> write-verbose "Examine DMARC summaries returned" ; 
    PS> $return.dmarc


        Name               : mtidistributing.com
        DmarcRecord        : Microsoft.DnsClient.Commands.DnsRecord_TXT
        PolicyTag          : p=quarantine
        SubDomainPolicyTag : 
        PolicyInheritance  : SUBDOMAINS:Policy p=xxx with no sp=xxx subdomain pol: Subdomains inherit the p=xxx Policy
        ReturnedType       : TXT

    PS> write-verbose "Examine DMARC records returned" ; 
    PS> $return.dmarc.dmarcrecord

        Name                                     Type   TTL   Section    Strings                                  
        ----                                     ----   ---   -------    -------                                  
        _dmarc.mtidistributing.com               TXT    3600  Answer     {v=DMARC1; p=quarantine; pct=100}       

    Resolve SPF, DKIM, DMARC for on targeted domain, assign results to variable, then expand the returned object subproperties for each type of record.

    .EXAMPLE
    PS>  $result = Resolve-DnsSenderIDRecords -name DOMAIN.com -verbose -Selector hs1-20997172._domainkey ; 
    PS>  if($result.DKIM.DkimRecord){
    PS>      $smsg = "DKIM TXT/Key record returned on query:`n"  ; 
    PS>      $smsg += "`n$(($return.dkim | ?{$_.Returnedtype -eq 'TXT'} | select -expand DkimRecord) | format-list |out-string).trim())" ;
    PS>      write-host $smsg ; 
    PS>      if($pkey = ($return.dkim | ?{$_.ReturnedType -eq 'TXT'} | select -expand DkimRecord).split(';') | ?{$_ -match 'p=[a-zA-z0-9]+'}){
    PS>          $smsg = "`nMatched Public Key tag:`n$(($pkey | format-list |out-string).trim())" ;
    PS>          write-host $smsg ; 
    PS>      } else { 
    PS>          $smsg += "`nNO PUBLIC KEY MATCHED IN RETURNED RECORD!`n$(($pkey | format-list |out-string).trim())" ;
    PS>          write-warning $smsg ;
    PS>      } ; 
    PS>  } else { 
    PS>      $smsg = "`nNO DKIM RECORD RETURNED ON QUERY:`N"  ; 
    PS>      $smsg += "`n$(($result.DkimRecord | format-list |out-string).trim())" ;
    PS>      write-warning $smsg ; 
    PS>  } ; 

        DKIM TXT/Key record returned on query:

        v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCstQzRq+OSOJM8isy+xxxxxxxxxxxxxjLs3e1z5eILA0Ya8MQFYGOQgJbj06nyNtC3Qb2vHWcvX6oU/hBJ5fLeaH3lIcgbG91p3cE/4gxh9rncprv/ICkfj0SqIalwoie2uEcWfPmkCMaAwNKIB77SGDEPnetgqtSVC5XMFFTtJwIDAQ
        AB;
        .trim())

        Matched Public Key tag:
        p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCstQzRq+OSOJM8isy+RYnrVMmZrfXLuxxxxxxxxxxxxxxa8MQFYGOQgJbj06nyNtC3Qb2vHWcvX6oU/hBJ5fLeaH3lIcgbG91p3cE/4gxh9rncprv/ICkfj0SqIalwoie2uEcWfPmkCMaAwNKIB77SGDEPnetgqtSVC5XMFFTtJwIDAQAB

    Example processing the returned TXT DKIM record and outputing the public key tag.
    DESCRIPTION    
.LINK
    https://github.com/T13nn3s/Invoke-SpfDkimDmarc/blob/main/public/Get-DMARCRecord.ps1
    https://www.powershellgallery.com/packages/DomainHealthChecker/1.5.2/Content/public%5CResolve-DnsSenderIDRecords.ps1
    https://binsec.nl/powershell-script-for-spf-dmarc-and-dkim-validation/
    https://github.com/T13nn3s
    .LINK
    https://github.COM/tostka/verb-Network/
    #>
    [CmdletBinding()]
    # Set-Alias gdkim -Value Resolve-DnsSenderIDRecords   # move trailing alias here
    [Alias('gdkim')]
    PARAM(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, 
            HelpMessage = "Specifies the domain for resolving the DKIM-record.[-Name Domain.tld]")]
        [string]$Name,
        [Parameter(Mandatory = $False,
            HelpMessage = "An array of custom DKIM selector strings.[-DkimSelector myselector")]
        [Alias('Selector')]
        [string[]]$DkimSelector,
        [Parameter(Mandatory = $false,
            HelpMessage = "DNS Server to use.[-Server 8.8.8.8]")]
        [string]$Server='1.1.1.1'
    ) ; 
    BEGIN {
        $verbose = ($VerbosePreference -eq "Continue") ; 
        #if ($PSBoundParameters.ContainsKey('Server')) {
        # above doesn't work if $Server is defaulted value
        if ($PSBoundParameters.ContainsKey('Server') -OR $Server) {
            $SplatParameters = @{
                'Server'      = $Server ; 
                'ErrorAction' = 'SilentlyContinue' ; 
            } ; 
        } Else {
            $SplatParameters = @{
                'ErrorAction' = 'SilentlyContinue' ; 
            } ; 
        } ; 
        
        $prpSPFDMARC = 'Name','Type';
        $prpDKIM = 'Type','Name','NameHost';
        
        #$whReportSub = @{BackgroundColor = 'Gray' ; ForegroundColor = 'DarkMagenta' } ;
        $whElement = @{BackgroundColor = 'Yellow' ; ForegroundColor = 'Black' } ;
        #$whQualifier = @{BackgroundColor = 'Blue' ; ForegroundColor = 'White' } ;

        $prpCNAME = 'Type','Name','NameHost' ; 
        $prpTXT = 'Type','Name','Strings' ; 
        $prpSOA = 'Type','Name','PrimaryServer' ; 

        # Custom list of DKIM-selectors
        # https://help.sendmarc.com/email-provider-commonly-used-dkim-selectors
        # https://www.reddit.com/r/DMARC/comments/1bffol7/list_of_most_common_dkim_selectors/
        # https://github.com/ryancdotorg/dkimscan/blob/master/dkimscan.pl#L313-L451
        $DKSelArray = 'selector1','selector2','s1','s2','k1','k2','sig1','smtp','default','mail','a1','a2','key1','key2',
            'kl','kl2','K1','K2','Default','smtpapi','dkim','domk','dk','smtpout','authsmtp','dkrnt','dkimrnt','private',
            'selector','publickey','proddkim','mail-in','key','ed-dkim','smtpauth','smtp','sl','primary','mdaemon',
            'mailrelay','mail-dkim','mailo','global','dksel','dkimmail','allselector','email' ;
        <#$DKSelArray = @(
            'selector1' # Microsoft
            'selector2' # Microsoft
            'google', # Google
            'everlytickey1', # Everlytic
            'everlytickey2', # Everlytic
            'eversrv', # Everlytic OLD selector
            'k1', # Mailchimp / Mandrill
            'mxvault' # Global Micro
            'dkim' # Hetzner
            's1' # generic
            's2' # generic
        ) ; 
        #>

        if ($PSCmdlet.MyInvocation.ExpectingInput) {
            write-verbose "Data received from pipeline input: '$($InputObject)'" ; 
        } else {
            #write-verbose "Data received from parameter input: '$($InputObject)'" ; 
            write-verbose "(non-pipeline - param - input)" ; 
        } ; 

        $SPFObject = New-Object System.Collections.Generic.List[System.Object] ; 
        $DKimObject = New-Object System.Collections.Generic.List[System.Object] ; 
        $DMARCObject = New-Object System.Collections.Generic.List[System.Object] ; 
        
        $objReturn = [ordered]@{
            SPF = $null ; 
            DKIM = $null ; 
            DMARC = $null ; 
        } ; 

        if(-not $DkimSelector){
            $DkimSelector = $DKSelArray ; 
            $noSelectorSpecified = $true ; 
            #$smsg = "Running specified `Name:$($Name) through common selector names:" ; 
            $smsg = "Running with common selector names:" ; 
            $smsg += "`n($($DKSelArray -join '|'))..." ; 
            #write-host -Object $smsg @whElement ; 
        } else {
            $noSelectorSpecified = $false ; 
            #$smsg = "Running specified `Name:$($Name) through specified -DkimSelector selector names:" ; 
            $smsg = "Running specified -DkimSelector selector names:" ; 
            $smsg += "`n($($DkimSelector -join '|'))..." ; 
            #write-host -Object $smsg @whElement ;
        }; 
        write-host -Object $smsg @whElement ; 
    } ; 
    PROCESS { 
        $Error.Clear() ; 

        foreach($item in $Name) {

            $sBnr="#*======v Name: $($item) v======" ; 
            $whBnr = @{BackgroundColor = 'Magenta' ; ForegroundColor = 'Black' } ;
            write-host @whBnr -obj "$((get-date).ToString('HH:mm:ss')):$($sBnr)" ;

            $pltRvDN=[ordered]@{
                Type = $null ;
                Name = $item  ;
                server = $server
                erroraction = 'SilentlyContinue' ;
            } ;
            
            $pltRvDN.Type= 'TXT' ;
            $smsg = "`n1. Resolve-DNSName SPF TXT type Matching 'spf1' w`n$(($pltRvDN|out-string).trim())" ;
            write-host -foregroundcolor yellow $smsg  ;

            TRY{
                $SPF  = Resolve-DNSName @pltRvDN ;
            }CATCH{} ;
            $SpfReturnValues = New-Object psobject ;
            $SpfReturnValues | Add-Member NoteProperty "Name" $item ;
             

            if($SPF = $SPF | ? Strings -Match "spf1"){
                $rType = $SPF.Type ;
                $smsg = "`n=>Matched to SPF:`n$(($SPF|ft -a $prpSPFDMARC | out-string).trim())" ;
                $smsg += "`nStrings:`n$(($SPF|select -expand Strings | out-string).trim())`n"
                write-host -foregroundcolor green $smsg ; 
                $SpfReturnValues | Add-Member NoteProperty "SPFRecord" $spf ;
            
            } else {
                $smsg = "`n=>NO SPF RECORD FOUND FOR DOMAIN:$($item )`n" ;
                write-warning $smsg ;

                write-verbose "asserting SPFRecord:`$null" ;
                $SpfReturnValues | Add-Member NoteProperty "SPFRecord" $null ;
                <#if($noSelectorSpecified){
                    $SpfAdvisory = $SpfAdvisory.replace('domain.',"domain, against a common Selectors list:`n($($DKSelArray -join '|')).") ; 
                };
                #> 
                $rType = $SPF.Type ;

            } ;
            $SpfReturnValues | Add-Member NoteProperty "ReturnedType" $rType ;
            #$SpfReturnValues | Add-Member NoteProperty "DKIMAdvisory" $SpfAdvisory ;
            $SpfObject.Add($SpfReturnValues) ;
            #$SpfReturnValues | write-output ;
            
            write-host -fore yellow "`n2. Attempt to resolve DKIMs (by checking common DKIM Selector host names)..." ;
            $pltRvDN.Type= 'CNAME' ;
            $foundSelector = $false ; 

            foreach ($DSel in $DkimSelector) {
                $pltRvDN.Name = "$($DSel)._domainkey.$($item )" ;
                $smsg = "Resolve-DNSName SPF TXT type Matching 'spf1' w`n$(($pltRvDN|out-string).trim())" ;
                write-verbose $smsg ; 
                $DKIM  = $null ;
                TRY{
                    $DKIM  = Resolve-DNSName @pltRvDN ;
                }CATCH{write-host -nonewline '.'} ;
                if($DKIM){

                } else { 
                    # above doesn't accomodate custom SAAS vendor DKIMs and CNAMe pointers, so retry on selector.name
                    $smsg = "Fail on prior TXT qry" ; 
                    $smsg += "`nRetrying TXT qry:-Name $($DSel).$($item)"
                    $smsg += "`nResolve-DnsName -Type TXT -Name $($DSel).$($item)"  ;
                    write-verbose $smsg ; 
                    $DKIM = Resolve-DnsName -Type TXT -Name "$($DSel).$($item)" @SplatParameters ; 
                } ;  
                
                if(($DKIM |  measure).count -gt 1){
                    write-verbose "Multiple Records returned on qry: Likely resolution chain CNAME->(CNAME->)TXT`nuse the TXT record in the chain" ;   

                    # dump the chain
                    # ---
                    $rNo=0 ; 
                    foreach($rec in $DKIM){
                        $rNo++ ; 
                        $RecFail = $false ; 
                        $smsg = "`n`n==HOP: $($rNo): " ;
                        switch ($rec.type){
                            'CNAME' {
                                $smsg += "$($rec.Type): $($rec.Name) ==> $($rec.NameHost):" ; 
                                if($verbose){
                                    $smsg += "`n" ; 
                                } ; 
                                if($verbose -AND (get-command Convertto-Markdowntable -ea 0)){
                                    $smsg += $rec | select $prpCNAME | Convertto-Markdowntable -Border ; 
                                } else { 
                                    $smsg += "`n$(($rec | ft -a $prpCNAME |out-string).trim())" ; 
                                } ; 
                                if($verbose){
                                    $smsg += "`n" ; 
                                } ; 
                            } 
                            'TXT' { 
                                $smsg += "$($rec.Type):Value record::`n" ; 
                                if($verbose){
                                    $smsg += "`n" ; 
                                } ; 
                                if($verbose -AND (get-command Convertto-Markdowntable -ea 0)){
                                    $smsg += $rec | select $prpTXT[0..1] | Convertto-Markdowntable -Border ; 
                                    $smsg += "`n" ;
                                    $smsg += $rec | select $prpTXT[2] | Convertto-Markdowntable -Border ; 
                                } else { 
                                    $smsg += "`n$(($rec | ft -a  $prpTXT[0..1] |out-string).trim())" ; 
                                    $smsg += "`n" ;
                                    $smsg += "`n$(($rec | ft -a $prpTXT[2]|out-string).trim())" ; 
                                } ; 
                                if($verbose){
                                    $smsg += "`n" ; 
                                } ; 
                                if($rec.Strings -match 'v=DKIM1;\sk=rsa;\sp='){
                                    $smsg += "`n`n--->TXT: $($rec.Name).strings *IS FULLY VALIDATED* to contain a DKIM key.`n`n" ; 
                                }elseif($rec.Strings -match 'v=DKIM1;\s.*;\sp='){
                                    # per above, this matches only the bare minimum!
                                    $smsg += "`n`n--->TXT: $($rec.Name).strings *IS VALIDATED* to start with v=DKIM1 and contains a key (lacks k=rsa; tag, partial standard compliant).`n`n" ; 
                                }elseif($rec.Strings -match 'p=\w+'){
                                    # per above, this matches only the bare minimum!
                                    $smsg += "`n`n--->TXT: $($rec.Name).strings *IS VALIDATED* to contain a DKIM key only (min standard compliant).`n`n" ; 
                                }else {
                                    $smsg += "`n`n--->TXT: $($rec.Name).strings *DOES NOT VALIDATE* to contain a DKIM key!" ;
                                    $smsg += "`n(strings should start with 'v=DKIM1', or at minimum include a p=xxx public key)`n`n" ; 
                                    $RecFail = $true ; 
                                } ; 
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
                    #---

                    #if($DKIM |?{$_.type -eq 'TXT'}){
                    if($DKIM.type -contains 'TXT'){
                        $DKIM  = $DKIM |?{$_.type -eq 'TXT'} ; 
                        $rtype = $DKIM.type ; 
                        $DKIM  = $DKIM | Select-Object -ExpandProperty Strings -ErrorAction SilentlyContinue ;
                        if ($DKIM -eq $null) {
                            $DkimAdvisory = "No DKIM-record found for selector $($DSel)._domainkey." ;
                        } elseif ($DKIM -match "v=DKIM1" -or $DKIM -match "k=") {
                            $DkimAdvisory = "DKIM-record found." ;
                            if($noSelectorSpecified -AND ($DSel -match "^selector1|everlytickey1|s1$") ){
                                $smsg = "$($DkimSelector) is one of a pair of records, contining, to run the second partner record" ; 
                                write-host $smsg ; 
                            }elseif($noSelectorSpecified -eq $false){
                                write-verbose "always run all explicit -DkimSelector values" ; 
                            } else { 
                                #break ; 
                                $foundSelector = $true ; 
                            } ; 
                        # TK: test variant p= public key as fall back
                        } elseif ($DKIM -match 'p=\w+' ) {
                                # test above is too restrictive, min tag for functional dkim is a 'p=XXX' public key, not DKIM & k= tags)
                                $DkimAdvisory = "*Minimum requirement* (p=XXX) Public Key found: Likely DKIM-record present." ;
                                if($noSelectorSpecified -AND ($DSel -match "^selector1|everlytickey1|s1$") ){
                                    $smsg = "$($DkimSelector) is one of a pair of records, contining, to run the second partner record" ; 
                                    write-host $smsg ; 
                                }elseif($noSelectorSpecified -eq $false){
                                    write-verbose "always run all explicit -DkimSelector values" ; 
                                } else { 
                                    #break ; 
                                    $foundSelector = $true ; ; 
                                } ; 
                        } else {;
                                $DkimAdvisory = "We couldn't find a DKIM record associated with your domain." ;
                                $DkimAdvisory += "`n$($rType) record returned, unrecognized:" ; 
                                $DkimAdvisory += "`n$(($DKIM | format-list |out-string).trim())" ;
                        } ; 
                    } ;
                } elseif ($DKIM.Type -eq "CNAME") {
                    # record cnames ahead of txt resolution

                    $DkimReturnValues = New-Object psobject ;
                    $DkimReturnValues | Add-Member NoteProperty "Name" $item ;
                    $DkimReturnValues | Add-Member NoteProperty "DkimRecord" $DKIM ;
                    $DkimReturnValues | Add-Member NoteProperty "DkimSelector" $DSel ;
                    $DkimReturnValues | Add-Member NoteProperty "ReturnedType" $DKIM.Type ;
                    $DkimReturnValues | Add-Member NoteProperty "DKIMAdvisory" "Located CNAME pointer" ;
                    $DkimObject.Add($DkimReturnValues) ;
                    #$DkimReturnValues | write-output ;
                    <#$objReturn = [ordered]@{
                        SPF = $null ; 
                        DKIM = $null ; 
                        DMARC =  = $null ; 
                    } ; 
                    #>
                    
                    while ($DKIM.Type -eq "CNAME") {
                        $DKIMCname = $DKIM.NameHost ; 
                        $DKIM = Resolve-DnsName -Type TXT -name "$DKIMCname" @SplatParameters ;
                        # 5:00 PM 3/19/2024 need to support non-functional selectors (MS only has one mounted hot at a time):
                        if(-not $DKIM){
                            <# 
                            $DkimReturnValues = New-Object psobject ;
                            $DkimReturnValues | Add-Member NoteProperty "Name" $item ;
                            $DkimReturnValues | Add-Member NoteProperty "DkimRecord" $DKIMCname ;
                            $DkimReturnValues | Add-Member NoteProperty "DkimSelector" $DSel ;
                            $DkimReturnValues | Add-Member NoteProperty "ReturnedType" $DKIM.Type;
                            $DkimReturnValues | Add-Member NoteProperty "DKIMAdvisory" "Resolved TXT fail: non-functional selector target" ;
                            $DkimObject.Add($DkimReturnValues) ;
                            $DkimReturnValues | write-output ;
                            #>
                            break ; 

                        } elseif($DKIM.Type -eq "CNAME"){
                            $DkimReturnValues = New-Object psobject ;
                            $DkimReturnValues | Add-Member NoteProperty "Name" $item ;
                            $DkimReturnValues | Add-Member NoteProperty "DkimRecord" $DKIM ;
                            $DkimReturnValues | Add-Member NoteProperty "DkimSelector" $DSel ;
                            $DkimReturnValues | Add-Member NoteProperty "ReturnedType" $DKIM.Type ;
                            $DkimReturnValues | Add-Member NoteProperty "DKIMAdvisory" "Located CNAME pointer" ;
                            $DkimObject.Add($DkimReturnValues) ;
                        }; 
                    } ; # loop-E
                    $rType = $DKIM.Type ; 
                    #$DkimAdvisory = _test-DkimString -DKIM $DKIM -selector $DSel
                    $DKIM = $DKIM | Select-Object -ExpandProperty Strings -ErrorAction SilentlyContinue ;
                    if ($DKIM -eq $null) {
                        $DkimAdvisory = "No DKIM-record found for selector $($DSel)._domainkey." ;
                    } elseif ($DKIM -match "v=DKIM1" -or $DKIM -match "k=") {
                        $DkimAdvisory = "DKIM-record found." ;
                    # TK: test variant p= public key as fall back
                    } elseif ($DKIM -match 'p=\w+' ) {
                            # test above is too restrictive, min tag for functional dkim is a 'p=XXX' public key, not DKIM & k= tags)
                            $DkimAdvisory = "*Minimum requirement* (p=XXX) Public Key found: Likely DKIM-record present." ;
                            #break ; # can't break here, it leaps the emit end of the loop
                    } else {;
                            $DkimAdvisory = "We couldn't find a DKIM record associated with your domain." ;
                            $DkimAdvisory += "`n$($rType) record returned, unrecognized:" ; 
                            $DkimAdvisory += "`n$(($DKIM | format-list |out-string).trim())" ;
                    } ; 

                } else {
                    $rType = $DKIM.Type ; 
                    $DKIM = $DKIM | Select-Object -ExpandProperty Strings -ErrorAction SilentlyContinue ;
                    if ($DKIM -eq $null) {
                        $DkimAdvisory = "No DKIM-record found for selector $($DSel)._domainkey." ;
                    } elseif ($DKIM -match "v=DKIM1" -or $DKIM -match "k=") {
                        $DkimAdvisory = "DKIM-record found." ;
                    } ;
                } ;

                $DkimReturnValues = New-Object psobject ;
                $DkimReturnValues | Add-Member NoteProperty "Name" $item ;
                $DkimReturnValues | Add-Member NoteProperty "DkimRecord" $DKIM ;
                if($rType -eq 'SOA'){
                    write-verbose "asserting DkimSelector:`$null" ;
                    $DkimReturnValues | Add-Member NoteProperty "DkimSelector" $null ;
                    if($noSelectorSpecified){
                        $DkimAdvisory = $DkimAdvisory.replace('domain.',"domain, against a common Selectors list:`n($($DKSelArray -join '|')).") ; 
                    }; 
                } else { 
                    $DkimReturnValues | Add-Member NoteProperty "DkimSelector" $DSel ;
                } ; 
                $DkimReturnValues | Add-Member NoteProperty "ReturnedType" $rType ;
                $DkimReturnValues | Add-Member NoteProperty "DKIMAdvisory" $DkimAdvisory ;
                
                if($rType -match "CNAME|TXT"){
                    $DkimObject.Add($DkimReturnValues) ;
                    #$DkimReturnValues | write-output ;
                } else { 

                } ; 
                if($foundSelector){
                    Break ; 
                } ; 
            } # loop-E DkimSelectors

            write-host "`n" ;
            $pltRvDN.Type= 'TXT' ;
            $pltRvDN.Name = "_dmarc.$($item )" ;
            $smsg = "`n3. Resolve-DNSName DMARC TXT type Matching '^v=DMARC1' w`n$(($pltRvDN|out-string).trim())" ;
            write-host -foregroundcolor GRAY $smsg  ;
            $pltRvDN.erroraction = 'SilentlyContinue' ;
            $hit = Resolve-DNSName @pltRvDN ;
            if($DMARC = $hit | ?{$_.Strings -Match '^v=DMARC1'}){
                $smsg = "`n=>Matched to DMARC domain record:`n$(($DMARC|ft -a $prpSPFDMARC | out-string).trim())" ;
                $smsg += "`nStrings:`n$(($hit|select -expand Strings | out-string).trim())`n"
                write-host -foregroundcolor green $smsg ;
                $PolTag = $hit.strings.split(';').trim() |?{$_ -match 'p='} ;
                $SubdomPol = $hit.strings.split(';').trim() |?{$_ -match 'sp='} ;
                $rType = $DMARC.Type ;

                $DmarcReturnValues = New-Object psobject ;
                $DmarcReturnValues | Add-Member NoteProperty "Name" $item ;
                $DmarcReturnValues | Add-Member NoteProperty "DmarcRecord" $Dmarc ;
                $DmarcReturnValues | Add-Member NoteProperty "PolicyTag" $PolTag ;
                $DmarcReturnValues | Add-Member NoteProperty "SubDomainPolicyTag" $SubdomPol ;

                $smsg = "Policy tag:$($PolTag)" ;
                $smsg += "`n$($poltag.split('=')[1]) all traffic that doesn't pass either:"
                $smsg += "`n  -- SPF (egressed from an SPF IP)" ;
                $smsg += "`n  -- OR DKIM signing (stamped in message header with DKIM key)" ;
                if($PolTag -AND -not $SubdomPol){
                    $smsg += "`n`nSUBDOMAINS:Policy p=xxx with no sp=xxx subdomain pol: Subdomains inherit the p=xxx Policy" ;
                    $DmarcReturnValues | Add-Member NoteProperty "PolicyInheritance" "SUBDOMAINS:Policy p=xxx with no sp=xxx subdomain pol: Subdomains inherit the p=xxx Policy"  ;
                } elseif($PolTag -AND $SubdomPol){
                    $smsg += "`n`nSUBDOMAINS:Policy p=xxx AND sp=xxx subdomain pol: Subdomains inherit the p=xxx Policy" ;
                    $smsg += "`n(unless subdomain has it's own DMARC record)" ;
                    $DmarcReturnValues | Add-Member NoteProperty "PolicyInheritance" "SUBDOMAINS:Policy p=xxx AND sp=xxx subdomain pol: Subdomains inherit the p=xxx Policy (unless subdomain has it's own DMARC record)" ;
                } ;
                write-host -fore yellow $smsg ;

                
                <#if($rType -eq 'SOA'){
                    #write-verbose "asserting DkimSelector:`$null" ;
                    $DmarcReturnValues | Add-Member NoteProperty "DkimSelector" $null ;
                    if($noSelectorSpecified){
                        $DmarcAdvisory = $DmarcAdvisory.replace('domain.',"domain, against a common Selectors list:`n($($DKSelArray -join '|')).") ; 
                    };
                    
                } else { 
                    $DmarcReturnValues | Add-Member NoteProperty "DkimSelector" $DSel ;
                } ; 
                #>
                $DmarcReturnValues | Add-Member NoteProperty "ReturnedType" $rType ;
                #$DmarcReturnValues | Add-Member NoteProperty "DKIMAdvisory" $DmarcAdvisory ;

            } else {
                $smsg = "`n=>NO DMARC RECORD FOUND FOR DOMAIN:$($item )`n" ;
                write-warning $smsg ;

                $DmarcReturnValues = New-Object psobject ;
                $DmarcReturnValues | Add-Member NoteProperty "Name" $item ;
                $DmarcReturnValues | Add-Member NoteProperty "DmarcRecord" $null ;
            } ;
            $DmarcObject.Add($DmarcReturnValues) ;
            #$DmarcReturnValues | write-output ;

            # since we're comingling 3 types of record, doesn't pay to dump them into the pipeline: org them into a return object with a property per obj type
            <#$objReturn = [ordered]@{
                SPF = $null ; 
                DKIM = $null ; 
                DMARC =  = $null ; 
            } ; 
            #>
            $objReturn.SPF = $SpfObject ; 
            $objReturn.DKIM = $DKIMObject ; 
            $objReturn.DMARC = $DMARCObject ; 
            write-host -foregroundcolor green "(returning summary object to pipeline)" ; 
            New-Object -TypeName PsObject -Property $objReturn | write-output ; 

            write-host @whBnr -obj "$((get-date).ToString('HH:mm:ss')):$($sBnr.replace('=v','=^').replace('v=','^='))" ;

        } # loop-E Name
    } END {
        
    } ;
} ; 
 #*------^ END Function Resolve-DnsSenderIDRecords ^------