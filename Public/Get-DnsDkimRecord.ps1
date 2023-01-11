#*------v Function Get-DnsDkimRecord v------
function Get-DnsDkimRecord {
    <#
    .SYNOPSIS
    Get-DnsDkimRecord.ps1 - Function to resolve a DKIM record of a domain, under common or specified selectors for a domain.
    .NOTES
    Version     : 0.0.
    Author      :  (T13nn3s )
    Website     : https://binsec.nl
    Twitter     : @T13nn3s / https://twitter.com/T13nn3s
    CreatedDate : 2022-04-06
    FileName    : Get-DnsDkimRecord.ps1
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/powershell
    Tags        : Powershell,DNS,Email,SPF
    AddedCredit : Todd Kadrie
    AddedWebsite: toddomation.com
    AddedTwitter: @tostka/https://twitter.com/tostka
    REVISIONS
    * 6:09 PM 1/10/2023 TK revised: ren'd Get-DnsDkimRecord-> Get-DnsDkimRecord; 
    Added/updated CBH, and citations to variety of related link websites ; 
    Defaulted -Server to 1.1.1.1 (public default resolution) ; 
    added a bunch of verbose echoes for tshooting ; 
    added elseif test for not just v=dkim1 & k=, but accept p= public key (functional min requirement the other 2 tags are common but not required for function);
    [DKIM DNS record overview – Validity Help Center - help.returnpath.com/](https://help.returnpath.com/hc/en-us/articles/222481088-DKIM-DNS-record-overview)
    added trailing RturnedType to outputk, and tested for SOA and suppressed spurious last kdimselector as output. 
    Also updates DKIMAdvisory output to reflect failed generic selectors search (e.g. user should spec known-selector as next step).
    fundemental logic rewrite: when a selector is specified, it defaults to the 'accepteddomain' fqdn *only*:
    $($DkimSelector)._domainkey.$($Name)"
    issue: that doesn't accomodate custom SAAS vendor DKIM's or their CNAME pointers (which could be any arbitrary hostname on the domain). 
    retry the failure on an explicit selector.name(.com) pass.; 
    Finally just simplified into a single loop regardless of source or if looping static array; 
    spliced in block to dump out full chain on multi dns records returned (more detail on -verbose)
    * 11/02/2022 T13nn3s posted rev v1.5.2
    .DESCRIPTION
    Get-DnsDkimRecord.ps1 - Checks DKIM records under common or specified selectors for a domain.

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
    PS>  $results = get-dnsdkimrecord -name SOMEDOMAIN.com 
    PS>  $results ; 

        Name         : DOMAIN.com
        DkimRecord   : v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQE[TRIMMED]qizt5Duv4WbgY/lXePnSA9iQIDAQAB;
        DkimSelector : selector2
        ReturnedType : TXT
        DKIMAdvisory : DKIM-record found.

    Simple expansion on targeted domain, assign results to variable .
    .EXAMPLE
    PS>  $result = get-dnsdkimrecord -name DOMAIN.com -verbose -Selector hs1-20997172._domainkey ; 
    PS>  if($result.DkimRecord){
    PS>      $smsg = "DKIM record returned on query:`n" 
    PS>      $smsg += "`n$(($result.DkimRecord | format-list |out-string).trim())" ;
    PS>      write-host $smsg ; 
    PS>      if($pkey = $result.DkimRecord.split(';') | ?{$_ -match 'p=[a-zA-z0-9]+'}){
    PS>          $smsg = "`nMatched Public Key tag:`n$(($pkey | format-list |out-string).trim())" ;
    PS>          write-host $smsg ; 
    PS>      } else { 
    PS>          $smsg += "`nNO PUBLIC KEY MATCHED IN RETURNED RECORD!`n$(($pkey | format-list |out-string).trim())" ;
    PS>          write-warning $smsg ;
    PS>      } ; 
    PS>  } else { 
    PS>      $smsg = "`nNO DKIM RECORD RETURNED ON QUERY:`N" 
    PS>      $smsg += "`n$(($result.DkimRecord | format-list |out-string).trim())" ;
    PS>      write-warning $smsg ; 
    PS>  } ; 

        DKIM record returned on query:

        k=rsa;t=s;p=MIIBIjANBgkqhk[TRIMMED]klCj9qU9oocSLd3PlChiBQHgz7e9wGbtIgV2xVwIDAQAB

        Matched Public Key:
        p=MIIBIjANBgkqhk[TRIMMED]klCj9qU9oocSLd3PlChiBQHgz7e9wGbtIgV2xVwIDAQAB

    Example processing the returned TXT DKIM record and outputing the public key tag.
    DESCRIPTION    
.LINK
    https://github.com/T13nn3s/Invoke-SpfDkimDmarc/blob/main/public/Get-DMARCRecord.ps1
    https://www.powershellgallery.com/packages/DomainHealthChecker/1.5.2/Content/public%5CGet-DnsDkimRecord.ps1
    https://binsec.nl/powershell-script-for-spf-dmarc-and-dkim-validation/
    https://github.com/T13nn3s
    .LINK
    https://github.COM/tostka/verb-Network/
    #>
    [CmdletBinding()]
    # Set-Alias gdkim -Value Get-DnsDkimRecord   # move trailing alias here
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
        
        #$whReportSub = @{BackgroundColor = 'Gray' ; ForegroundColor = 'DarkMagenta' } ;
        $whElement = @{BackgroundColor = 'Yellow' ; ForegroundColor = 'Black' } ;
        #$whQualifier = @{BackgroundColor = 'Blue' ; ForegroundColor = 'White' } ;

        $prpCNAME = 'Type','Name','NameHost' ; 
        $prpTXT = 'Type','Name','Strings' ; 
        $prpSOA = 'Type','Name','PrimaryServer' ; 

        # Custom list of DKIM-selectors
        # https://help.sendmarc.com/support/solutions/articles/44001891845-email-provider-commonly-used-dkim-selectors
        $DKSelArray = @(
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

        if ($PSCmdlet.MyInvocation.ExpectingInput) {
            write-verbose "Data received from pipeline input: '$($InputObject)'" ; 
        } else {
            #write-verbose "Data received from parameter input: '$($InputObject)'" ; 
            write-verbose "(non-pipeline - param - input)" ; 
        } ; 

        $DKimObject = New-Object System.Collections.Generic.List[System.Object] ; 
        
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

            $foundSelector = $false ; 

            foreach ($DSel in $DkimSelector) {

                $smsg = "DkimSelector:$($DSel) specified for domain Name:$($item)" ; 
                $smsg += "`nResolve-DnsName -Type TXT -Name $($DSel)._domainkey.$($item)" ; 
                write-verbose $smsg ; 
                if($DKIM = Resolve-DnsName -Type TXT -Name "$($DSel)._domainkey.$($item)" @SplatParameters){

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
                                    $smsg += "`n`n--->TXT: $($rec.Name).strings *IS VALIDATED* to contain a DKIM key.`n`n" ; 
                                }elseif($rec.Strings -match 'p=\w+'){
                                    # per above, this matches only the bare minimum!
                                    $smsg += "`n`n--->TXT: $($rec.Name).strings *IS VALIDATED* to contain a DKIM key.`n`n" ; 
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
                    while ($DKIM.Type -eq "CNAME") {
                        $DKIMCname = $DKIM.NameHost ; 
                        $DKIM = Resolve-DnsName -Type TXT -name "$DKIMCname" @SplatParameters ;
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
                $DkimObject.Add($DkimReturnValues) ;
                $DkimReturnValues | write-output ;

                if($foundSelector){
                    Break ; 
                } ; 
            } # loop-E DkimSelectors

            

            write-host @whBnr -obj "$((get-date).ToString('HH:mm:ss')):$($sBnr.replace('=v','=^').replace('v=','^='))" ;

        } # loop-E Name
    } END {
        
    } ;
} ; 
 #*------^ END Function Get-DnsDkimRecord ^------