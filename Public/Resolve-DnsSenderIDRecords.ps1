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
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,DNS,Email,SPF
    AddedCredit : Todd Kadrie
    AddedWebsite: toddomation.com
    AddedTwitter: @tostka/https://twitter.com/tostka
    REVISIONS
    * 12:44 PM 6/28/2024 rejiggered dkim series post testing (wasn't really reporting on the hits, and fibbed were no hits). Worked fine for checking toro.com against a ticket.
    * 9:09 AM 6/27/2024 WIP, got the WHPASSFail block updated with winterm test
    * 5:34 PM 6/19/2024 spliced over code to do SPF egress testing, and ensure all spf clauses match into the core ip4, ip6 etc of a specified 
    * 9:57 AM 5/2/2024 updated to accomodate Sec's decision to start parking dmarcs on domains as cnames pointed at a common dmarc txt (recogs cname, resolves to txt, and returns both in output)
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
    .PARAMETER SpfModelDomain
    DomainName from which to obtain model SPF string for comparison[-SpfModelDomain somdeomain.tld]
    .PARAMETER TestSPFEgress
    Switch to perform element by element SPF compairsons against specified SpfModelDomain's SPF record ip4|ip6 and all designator[-SpfModelDomain somdeomain.tld]
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
    .EXAMPLE
    PS> $results = Resolve-DnsSenderIDRecords -name somedomain.tld -TestSPFEgress -verbose ;
    PS> foreach($result in $results){
    PS>     $sBnrS="`n#*------v DOMAIN: $($result.mx.name) v------" ; 
    PS>     $whBnrS =@{BackgroundColor = 'Blue' ; ForegroundColor = 'Cyan' } ;
    PS>     write-host @whBnrS -obj "$((get-date).ToString('HH:mm:ss')):$($sBnrS)" ;
    PS>     $hsReport = @"
  
    ==DomainName: 
$(($result.mx.name|out-string).trim()) 
    
    ==MX Record: 
$(($result.mx.MXRecord | ft -AutoSize|out-string).trim())
    
    ==SPF Record: 
$(($result.spf.SPFRecord | ft -AutoSize|out-string).trim())
    
    ==DKIM Record: 
$(
      
      $smsg = "`n`n" ; 
      foreach($rec in $result.dkim){
      
          $smsg += "`n`n$(($rec.dkimrecord | ft -AutoSize|out-string).trim())" ; 
          $smsg += "`n`n$(($rec.DKIMAdvisory |out-string).trim())" ; 
          
      } ; 
      $smsg |out-string
) 
    
    ==DMARC Record: 
$(
    ($result.dmarc.dmarcrecord | ft -AutoSize|out-string).trim()
 )   
        --PolicyTag:
$(   ($result.dmarc.policytag|out-string).trim()
)
      
        --SubDomainPolicyTag:
$(
  ($result.dmarc.SubDomainPolicyTag|out-string).trim()
)
     
        --PolicyInheritance:
$(   
  ($result.dmarc.PolicyInheritance|out-string).trim()
) 
     
"@ ; 
    PS>     write-host $hsReport ; 
    PS>     write-host @whBnrS -obj "$((get-date).ToString('HH:mm:ss')):$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;
    PS> } ; 
    Demos a pass with trailing looped reporting
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
            [string]$Server='1.1.1.1',
        [Parameter(Mandatory=$false,HelpMessage="DomainName from which to obtain model SPF string for comparison[-SpfModelDomain somdeomain.tld]")]
            [string]$SpfModelDomain = 'myturf.com',
        [Parameter(HelpMessage="Switch to perform element by element SPF compairsons against specified SpfModelDomain's SPF record ip4|ip6 and all designator[-SpfModelDomain somdeomain.tld]")]
            [switch]$TestSPFEgress
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

        #region WHPASSFAIL ; #*------v WHPASSFAIL v------
        $whPASS = @{
        Object = "$([Char]8730) PASS" ;
        ForegroundColor = 'Green' ;
        NoNewLine = $true ;
        } ;
        $whFAIL = @{
            # light diagonal cross: ╳ U+2573 DOESN'T RENDER IN PS, use it if WinTerm
            'Object'= if ($env:WT_SESSION) { "$([Char]8730) FAIL"} else {' X FAIL'};
            ForegroundColor = 'RED' ;
            NoNewLine = $true ;
        } ;
        <#
        # inline pass/fail color-coded w char
        $smsg = "Testing:THING" ; 
        $Passed = $true ; 
        Write-Host "$($smsg)... " -NoNewline ; 
        if($Passed){Write-Host @whPASS} else {write-host @whFAIL} ; 
        Write-Host " (Done)" ;
        # out: Test:Thing... √ PASS (Done) | Test:Thing...  X FAIL (Done)
        #>
        #endregion WHPASSFAIL ; #*------^ END WHPASSFAIL ^------

        if ($PSCmdlet.MyInvocation.ExpectingInput) {
            write-verbose "Data received from pipeline input: '$($InputObject)'" ; 
        } else {
            #write-verbose "Data received from parameter input: '$($InputObject)'" ; 
            write-verbose "(non-pipeline - param - input)" ; 
        } ; 

        if($TestSPFEgress){
            write-verbose "resolve `$modelspf from `$SpfModelDomain ($($SpfModelDomain))" ; 
            TRY{
                $modelspf  =  resolve-dnsname -server $Server -type txt -name $SpfModelDomain ;
            }CATCH{} ;
            if($modelspf = $modelspf | ? Strings -Match "spf1"){
                write-verbose "split model spf into elements, on spaces" ; 
                $modelSPFElements = $modelspf.strings -split ' ' ; 
            }else{
                write-warning "-TestSPFEgress specified: Unable to resolve functional SPF record for specified -SpfModelDomain $($SpfModelDomain)`n(ABORT)" ; 
                break ; 
            } ; 
        } ; 

        $SPFObject = New-Object System.Collections.Generic.List[System.Object] ; 
        $DKimObject = New-Object System.Collections.Generic.List[System.Object] ; 
        $DMARCObject = New-Object System.Collections.Generic.List[System.Object] ; 
        $MXObject = New-Object System.Collections.Generic.List[System.Object] ; 
        
        $objReturn = [ordered]@{
            SPF = $null ; 
            DKIM = $null ; 
            DMARC = $null ; 
            MX = $null ; 
        } ; 

        if(-not $DkimSelector){
            $DkimSelector = $DKSelArray ; 
            $noSelectorSpecified = $true ; 
            #$smsg = "Running specified `Name:$($Name) through common selector names:" ; 
            $smsg = "Running with common selector names:" ; 
            $smsg += "`n($($DKSelArray -join '|'))..." ; 
            $smsg += "`n$(($DkimSelector |  measure | select -expand count |out-string).trim()) selector variants being checked" ; 
            #write-host -Object $smsg @whElement ; 
        } else {
            $noSelectorSpecified = $false ; 
            #$smsg = "Running specified `Name:$($Name) through specified -DkimSelector selector names:" ; 
            $smsg = "Running specified -DkimSelector selector names:" ; 
            $smsg += "`n($($DkimSelector -join '|'))..." ; 
            $smsg += "`n$(($DkimSelector |  measure | select -expand count |out-string).trim()) selector variants being checked" ; 
            #write-host -Object $smsg @whElement ;
        }; 
        write-host -Object $smsg @whElement ; 

    } ; 

    PROCESS { 
        $Error.Clear() ; 

        foreach($DomainName in $Name) {

            $steps = 0 ; 

            $sBnr="#*======v Name: $($DomainName) v======" ; 
            $whBnr = @{BackgroundColor = 'Magenta' ; ForegroundColor = 'Black' } ;
            write-host @whBnr -obj "$((get-date).ToString('HH:mm:ss')):$($sBnr)" ;

            $steps++ ; 

            $pltRvDN=[ordered]@{
                Type = $null ;
                Name = $DomainName  ;
                server = $server
                erroraction = 'SilentlyContinue' ;
            } ;
            
            $pltRvDN.Type= 'MX' ;
            $smsg = "`n$($steps). Resolve-DNSName MX type w`n$(($pltRvDN|out-string).trim())" ;
            write-host -foregroundcolor yellow $smsg  ;

            TRY{
                $MX  = Resolve-DNSName @pltRvDN ;
            }CATCH{} ;
            $MXReturnValues = New-Object psobject ;
            $MXReturnValues | Add-Member NoteProperty "Name" $DomainName ;

            #-=-=-=-=-=-=-=-=
            $prpMX = 'Name','Typ','TTL','Section','NameExchange','Preference' ; 
            if($MX){
                $rType = $MX.Type ;
                write-host @whPASS ; 
                $smsg = "`n=>Matched to MX:`n$(($MX|ft -a $prpMX | out-string).trim())" ;
                #$smsg += "`nStrings:`n$(($MX|select -expand Strings | out-string).trim())`n"
                write-host -foregroundcolor green $smsg ;
                $MXReturnValues | Add-Member NoteProperty "MXRecord" $MX ;
            } else {
                write-host @whFAIL ; 
                $smsg = "`n=>NO MX RECORD FOUND FOR DOMAIN:$($DomainName )`n" ;
                write-warning $smsg ;
                write-verbose "asserting MXRecord:`$null" ;
                $MXReturnValues | Add-Member NoteProperty "MXRecord" $null ;
                <#if($noSelectorSpecified){
                    $SpfAdvisory = $SpfAdvisory.replace('domain.',"domain, against a common Selectors list:`n($($DKSelArray -join '|')).") ;
                };
                #>
                $rType = $MX.Type ;
            } ;
            $MXReturnValues | Add-Member NoteProperty "ReturnedType" $rType ;
            #$MXReturnValues | Add-Member NoteProperty "DKIMAdvisory" $MXAdvisory ;
            $MXObject.Add($MXReturnValues) ;
            #$MXReturnValues | write-output ;

            $steps++ ;

            $pltRvDN.Type= 'TXT' ;
            $smsg = "`n$($steps). Resolve-DNSName $($pltRvDN.Type) type w`n$(($pltRvDN|out-string).trim())" ;
            write-host -foregroundcolor yellow $smsg  ;

            TRY{
                $SPF  = Resolve-DNSName @pltRvDN ;
            }CATCH{} ;
            $SpfReturnValues = New-Object psobject ;
            $SpfReturnValues | Add-Member NoteProperty "Name" $DomainName ;
             

            if($SPF = $SPF | ? Strings -Match "spf1"){
                $rType = $SPF.Type ;
                $smsg = "`n=>Matched to SPF:`n$(($SPF|ft -a $prpSPFDMARC | out-string).trim())" ;
                $smsg += "`nStrings:`n$(($SPF|select -expand Strings | out-string).trim())`n"
                write-host -foregroundcolor green $smsg ; 
                $SpfReturnValues | Add-Member NoteProperty "SPFRecord" $spf ;
                
                if($TestSPFEgress){
                    #$SpfModelDomain = 'myturf.com' ; 
                    #$DomainName = 'bossplow.com' ; 
                    write-host "==Separately validating key elements in $($SpfModelDomain) model spf are present (avoids ordering issues in full string tests):" ; 
                
                    $thisSPFElements = $spf.strings -split ' ' ; 
                    $FailCount = 0 ; 
                    $cacheFails = @() ; 
                    foreach($item in $modelSPFElements){
                        $smsg = "Test:$($item)..." ; 
                        write-host -foregroundcolor yellow $smsg  -NoNewline ; 
                        if($thisSPFElements | ?{$_ -match ([regex]::escape($item))} ){
                            #write-host -foregroundcolor green "SPF $($item) present" ; 
                            #Write-Host "$($smsg)... " -NoNewline ; 
                            #Write-Host " (Done)" ;
                            #if($Passed){Write-Host @whPASS} else {write-host @whFAIL} ; 
                            Write-Host @whPASS ; 
                        }else{
                            #write-warning "$item missing"
                            Write-Host @whFAIL ; 
                            $FailCount++ ; 
                            $cacheFails += @($item) ; 
                        }  ; 
                        write-host "" ; # assert a line wrap to finish the -nonewlines above
                    } ; 
                    write-verbose "Item tests completed" ;     
                } ; 
            } else {
                $smsg = "`n=>NO SPF RECORD FOUND FOR DOMAIN:$($DomainName )`n" ;
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
            if($FailCount -gt 0){
                $SpfObject.Add($FailCount) ; 
            }  
            if($cacheFails.count -gt 0){
                $SpfObject.Add($cacheFails) ; 
            }  
            #$SpfReturnValues | write-output ;
            
            $steps++ ;
            write-host -fore yellow "`n$($steps). Attempt to resolve DKIMs (by checking common DKIM Selector host names)..." ;
            $pltRvDN.Type= 'CNAME' ;
            $foundSelector = $false ; 

            foreach ($DSel in $DkimSelector) {
                $pltRvDN.Name = "$($DSel)._domainkey.$($DomainName )" ;
                $smsg = "Resolve-DNSName DKIM $($pltRvDN.Type) type w`n$(($pltRvDN|out-string).trim())" ;
                write-host -foregroundcolor yellow $smsg ; 
                $DKIM  = $null ;
                $smsg = "Testing:DKIM" ; 
                TRY{
                    $DKIM  = Resolve-DNSName @pltRvDN ;
                }CATCH{write-host -nonewline '.'} ;
                if($DKIM){
                    Write-Host @whPASS ; 
                    switch($dkim.type){
                        'CNAME' {
                            write-host " : $($DKIM.type): $($DKIM.Name) => $($DKIM.NameHost)" 
                        }
                        'TXT' {
                            write-host " : $($DKIM.type): $($DKIM.Name) => $($DKIM.Strings)" 
                        }
                        'SOA'{
                            write-warning " : (invalid lookup)" ; 
                        }
                        default{
                            write-warning " : (invalid return)" ; 
                        }
                    }
                } else {
                    write-host @whFAIL ; Write-Host " " ;
                    # above doesn't accomodate custom SAAS vendor DKIMs and CNAMe pointers, so retry on selector.name
                    $smsg = "Fail on prior TXT qry" ; 
                    $smsg += "`nRetrying TXT qry:-Name $($DSel).$($DomainName)"
                    $smsg += "`nResolve-DnsName -Type TXT -Name $($DSel).$($DomainName)"  ;
                    write-verbose $smsg ; 
                    $DKIM = Resolve-DnsName -Type TXT -Name "$($DSel).$($DomainName)" @SplatParameters ; 
                } ;  
                write-host "`n" ; 
                
                if(($DKIM |  measure).count -gt 1){
                    write-host -foregroundcolor yellow "Multiple Records returned on qry: Likely resolution chain CNAME->(CNAME->)TXT`nuse the TXT record in the chain" ;   

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
                                    write-host @whPASS ; 
                                    $smsg += "`n`n--->TXT: $($rec.Name).strings *IS FULLY VALIDATED* to contain a DKIM key.`n`n" ; 
                                }elseif($rec.Strings -match 'v=DKIM1;\s.*;\sp='){
                                    # per above, this matches only the bare minimum!
                                    write-host @whPASS ; 
                                    $smsg += "`n`n--->TXT: $($rec.Name).strings *IS VALIDATED* to start with v=DKIM1 and contains a key (lacks k=rsa; tag, partial standard compliant).`n`n" ; 
                                }elseif($rec.Strings -match 'p=\w+'){
                                    write-host @whPASS ; 
                                    # per above, this matches only the bare minimum!
                                    $smsg += "`n`n--->TXT: $($rec.Name).strings *IS VALIDATED* to contain a DKIM key only (min standard compliant).`n`n" ; 
                                }else {
                                    write-host @whFAIL ; 
                                    $smsg += "`n`n--->TXT: $($rec.Name).strings *DOES NOT VALIDATE* to contain a DKIM key!" ;
                                    $smsg += "`n(strings should start with 'v=DKIM1', or at minimum include a p=xxx public key)`n`n" ; 
                                    $RecFail = $true ; 
                                } ; 
                            } 
                            'SOA' {
                                write-host @whFAIL ; 
                                $smsg += "`nSOA/Lookup-FAIL record detected!" ; 
                                $smsg += "`n$(($rec | ft -a $prpSOA | out-string).trim())" ; 
                                #throw $smsg ;
                                $RecFail = $true ; 
                            }
                            default {throw "Unrecognized record TYPE!" ; $RecFail = $true ; } 
                        } ; 

                        if($RecFail -eq $true){
                            write-host @whFAIL ; 
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } 
                            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                        } else { 
                            write-host @whPASS ; 
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
                            write-host @whFAIL ; 
                            $DkimAdvisory = "No DKIM-record found for selector $($DSel)._domainkey." ;
                        } elseif ($DKIM -match "v=DKIM1" -or $DKIM -match "k=") {
                            write-host @whPASS ; 
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
                                    write-host @whPASS ; 
                                    $foundSelector = $true ; ; 
                                } ; 
                        } else {;
                            write-host @whFAIL ; 
                            $DkimAdvisory = "We couldn't find a DKIM record associated with your domain." ;
                            $DkimAdvisory += "`n$($rType) record returned, unrecognized:" ; 
                            $DkimAdvisory += "`n$(($DKIM | format-list |out-string).trim())" ;
                        } ; 
                    } ;

                    $DkimReturnValues = New-Object psobject ;
                    $DkimReturnValues | Add-Member NoteProperty "Name" $DomainName ;
                    $DkimReturnValues | Add-Member NoteProperty "DkimRecord" $DKIM ;
                    $DkimReturnValues | Add-Member NoteProperty "DkimSelector" $DSel ;
                    $DkimReturnValues | Add-Member NoteProperty "ReturnedType" $DKIM.Type ;
                    $DkimReturnValues | Add-Member NoteProperty "DKIMAdvisory" "Located CNAME pointer" ;
                    $DkimObject.Add($DkimReturnValues) ;

                } elseif ($DKIM.Type -eq "CNAME") {
                    # record cnames ahead of txt resolution

                    $DkimReturnValues = New-Object psobject ;
                    $DkimReturnValues | Add-Member NoteProperty "Name" $DomainName ;
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
                            $DkimReturnValues | Add-Member NoteProperty "Name" $DomainName ;
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
                            $DkimReturnValues | Add-Member NoteProperty "Name" $DomainName ;
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
                        $DkimAdvisory = "No leaf DKIM-record TXT found for selector $($DSel)._domainkey NameHost: " ;
                        $DkimAdvisory += "-> $($DKIMCname)" ; 
                        
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
                $DkimReturnValues | Add-Member NoteProperty "Name" $DomainName ;
                $DkimReturnValues | Add-Member NoteProperty "DkimRecord" $DKIM ;
                if($rType -eq 'SOA'){
                    write-verbose "asserting DkimSelector:`$null" ;
                    $DkimReturnValues | Add-Member NoteProperty "DkimSelector" $null ;
                    if($noSelectorSpecified){
                        $DkimAdvisory = $DkimAdvisory.replace('domain.',"domain, against a common Selectors list:`n($($DkimSelector -join '|')).") ; 
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
                    # no return hit here                    
                } ; 
                if($foundSelector){
                    Break ; 
                } ; 
            } # loop-E DkimSelectors

            #if($DkimReturnValues.DKIMAdvisory -eq 'No DKIM-record found for selector email._domainkey.'){
            if($DKimObject){
                $prpDKIMSels = 'name','dkimselector','returnedtype','dkimadvisory' ; 

                foreach($ditem in $dkimobject){ 
                    $smsg = "`n====`n$(($ditem | ft -a $prpDKIMSels|out-string).trim())" ; 
                    switch($ditem.DkimRecord.type){
                        'CNAME' {
                            $smsg += "`n$($ditem.dkimrecord.type): $($ditem.dkimrecord.Name) => $($ditem.dkimrecord.NameHost)" 
                            write-host $smsg ; 
                        }
                        'TXT' {
                            $smsg += "`n$($ditem.dkimrecord.type): $($ditem.dkimrecord.Name) => $($ditem.dkimrecord.Strings)" 
                            write-host $smsg ; 
                        }
                        'SOA'{
                            $smsg += "`n(invalid lookup)" ; 
                            write-warning $smsg ; 
                        }
                        default{
                            # DKIM TXT'S ARE STORED AS THE STRING, NOT TYPE
                            if($ditem.DkimRecord -match 'v=DKIM1;'){
                                $smsg += "`n$($ditem.dkimselector) : dkim key string:`n`n$($ditem.DkimRecord)`n`n" 
                                write-host $smsg ; 
                            } ELSE { 
                                $smsg += "`n(invalid return)" ; 
                                write-warning $smsg ; 
                            } ; 
                        }
                    } ; 
                } ; 

                <#$smsg = "`n`n DKIM:`nThe following matched selector CNAME or TXT records were discovered (in $($DkimSelector|  measure | select -expand count ) names series run)" ; 
                $smsg = "`n$(($DKimObject | ft -a prpDKIMSels |out-string).trim())" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level PROMPT } 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)`n`n" } ;
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                #>
            } else {
                $smsg = "`n(No matching DKIM Selector found in series checked:" ; 
                if($DkimSelector){
                    $smsg += "`n$(($DkimSelector -join ', '|out-string).trim()))" ; 
                } else { 
                    $smsg += "`n$(($dkselarray -join ', '|out-string).trim()))" ; 
                } ; 
                write-host -foregroundcolor gray $smsg ; 
            } ; 

            $steps++ ;
            write-host "`n" ;
            $pltRvDN.Type= 'TXT' ;
            $pltRvDN.Name = "_dmarc.$($DomainName )" ;
            $smsg ="`n$($steps). Resolve-DNSName DMARC TXT type Matching '^v=DMARC1' w`n$(($pltRvDN|out-string).trim())" ;
            write-host -foregroundcolor GRAY $smsg  ;
            $pltRvDN.erroraction = 'SilentlyContinue' ;
            # 9:39 AM 5/2/2024 seeing sec park doms under cname pointed at _dmarc.parked.thetoroco.com, try through it
            $hit = Resolve-DNSName @pltRvDN ;
            if($hit -is [system.array]){
                if($hit[0].type -eq 'CNAME'){
                    $dmarcCname = $hit[0] ; 
                    #$smsg = "Existing DMARC -type CNAME pointer found:" ; 
                    #$smsg += "`n$(($dmarcCname|out-string).trim())" ; 
                    #write-warning $smsg ; 
                    $hit = $hit | select -last 1 
                } ; 
            }
            if($DMARC = $hit | ?{$_.Strings -Match '^v=DMARC1'}){
                if($dmarcCname){
                    $smsg = "`n=>Matched to DMARC CNAME pointer:"
                    $smsg += "`n$(($dmarcCname|out-string).trim())" ; 
                    $smsg += "`n=>Which resolves to DMARC domain record:`n$(($DMARC|ft -a $prpSPFDMARC | out-string).trim())" ;
                } else { 
                    $smsg = "`n=>Matched to DMARC domain record:`n$(($DMARC|ft -a $prpSPFDMARC | out-string).trim())" ;
                } ; 
                $smsg += "`nStrings:`n$(($hit|select -expand Strings | out-string).trim())`n"
                write-host -foregroundcolor green $smsg ;
                $PolTag = $hit.strings.split(';').trim() |?{$_ -match 'p='} ;
                $SubdomPol = $hit.strings.split(';').trim() |?{$_ -match 'sp='} ;
                $rType = $DMARC.Type ;

                $DmarcReturnValues = New-Object psobject ;
                $DmarcReturnValues | Add-Member NoteProperty "Name" $DomainName ;
                if($dmarcCname){
                    $DmarcReturnValues | Add-Member NoteProperty "DmarcRecord" @($dmarcCname,$Dmarc) ;
                } else {
                    $DmarcReturnValues | Add-Member NoteProperty "DmarcRecord" $Dmarc ;
                } ; 
                $DmarcReturnValues | Add-Member NoteProperty "PolicyTag" $PolTag ;
                $DmarcReturnValues | Add-Member NoteProperty "SubDomainPolicyTag" $SubdomPol ;

                $smsg = "Policy tag:$($PolTag)" ;
                $smsg += "`np=$($poltag.split('=')[1]): all traffic that doesn't pass either:"
                $smsg += "`n  -- SPF (egressed from an SPF IP)" ;
                $smsg += "`n  -- OR DKIM signing (stamped in message header with DKIM key)" ;
                switch($poltag.split('=')[1]){ 
                    'none'{
                        $smsg +="`np=none: => No action is taken/messages remain unexamined." ; 
                    } 
                    'quarantine'{
                        $smsg +="`np=quarantine: => Further examination (Quarantine/Junk folder)." ;  
                    }
                    'reject'{
                        $smsg +="`np=reject: => Reject those messages that fail DMARC authentication"
                    }
                    default {
                        $smsg +="`nUNCRECOGNIZED $($poltag.split('=')[1])! MISCONFIGURED DMARC?" ; 
                    }                
                }
                if($PolTag -AND -not $SubdomPol){
                    $smsg += "`n`nSUBDOMAINS:Policy p=xxx with NO sp=xxx subdomain pol: Subdomains inherit the p=xxx Policy" ;
                    $DmarcReturnValues | Add-Member NoteProperty "PolicyInheritance" "SUBDOMAINS:Policy p=xxx with no sp=xxx subdomain pol: Subdomains inherit the p=xxx Policy"  ;
                } elseif($PolTag -AND $SubdomPol){
                    if($SubdomPol -like '*=reject'){
                        $smsg += "`n`nSUBDOMAINS:Policy p=xxx AND sp=reject subdomain pol: Subdomains inherit the sp=reject Policy" ;
                        $smsg += "`n(unless subdomain has it's _own_ DMARC record with it's own p=xxx effective local policy)" ;
                        $DmarcReturnValues | Add-Member NoteProperty "PolicyInheritance" "SUBDOMAINS:Policy p=xxx AND sp=xxx subdomain pol: Subdomains inherit the sp=xxx Policy (unless subdomain has it's own DMARC record w a p= pol)" ;
                    } else { 
                        $smsg += "`n`nSUBDOMAINS:Policy p=xxx AND sp=xxx subdomain pol: Subdomains inherit the sp=xxx Policy" ;
                        $smsg += "`n(unless subdomain has it's _own_ DMARC record with it's own p=xxx effective local policy)" ;
                        $DmarcReturnValues | Add-Member NoteProperty "PolicyInheritance" "SUBDOMAINS:Policy p=xxx AND sp=xxx subdomain pol: Subdomains inherit the p=xxx Policy (unless subdomain has it's own DMARC record)" ;
                    } ; 
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
                $smsg = "`n=>NO DMARC RECORD FOUND FOR DOMAIN:$($DomainName )`n" ;
                write-warning $smsg ;

                $DmarcReturnValues = New-Object psobject ;
                $DmarcReturnValues | Add-Member NoteProperty "Name" $DomainName ;
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
            $objReturn.MX = $MXObject ; 
            write-host -foregroundcolor green "(returning summary object to pipeline)" ; 
            New-Object -TypeName PsObject -Property $objReturn | write-output ; 

            write-host @whBnr -obj "$((get-date).ToString('HH:mm:ss')):$($sBnr.replace('=v','=^').replace('v=','^='))" ;

        } # loop-E Name
    } END {
        
    } ;
} ; 
 #*------^ END Function Resolve-DnsSenderIDRecords ^------