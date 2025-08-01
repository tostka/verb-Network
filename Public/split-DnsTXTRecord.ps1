# split-DnsTXTRecord.ps1

function split-DnsTXTRecord{
    <#
    .SYNOPSIS
    split-DnsTXTRecord - Splits long TXT DNS record strings into quote-space delimited substrings (to permit the record to exceed the DNS Bind '255-character per single string' limit)
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2024-
    FileName    : split-DnsTXTRecord.ps1
    License     : MIT License
    Copyright   : (c) 2024 Todd Kadrie
    Github      : https://github.com/tostka/verb-XXX
    Tags        : Powershell
    AddedCredit : REFERENCE
    AddedWebsite: URL
    AddedTwitter: URL
    REVISIONS
    * 2:18 PM 8/1/2025 updated WHPASSFAIL defs to curr
    * 4:52 PM 7/17/2024 init
    .DESCRIPTION
    split-DnsTXTRecord - Splits long TXT DNS record strings into quote-space delimited substrings (to permit the record to exceed the DNS Bind '255-character per single string' limit)


    ### Creating TXT records

    Key points to remember:

    -   A TXT record contains one or more strings that are enclosed in double quotation marks (").
    -   You can enter a value of up to 255 characters in one string in a TXT record.
    -   You can add multiple strings of 255 characters in a single TXT record.
    -   The maximum length of a value in a TXT record is 4,000 characters.
    -   TXT record values are case-sensitive.

    For values that exceed 255 characters, break the value into strings of 255 characters or less. Enclose each string in double quotation marks (") using the following syntax: 
    **Domain name TXT "String 1" "String 2" "String 3"….."String N"**.

    [easyDmarc Raw Record Pre-publishing validator]([SPF Validator and Raw Checker | EasyDMARC](https://easydmarc.com/tools/spf-record-raw-check-validate)
     
     Note: The above will test the _raw_ un quote-spaced version of the record. It will _not_ properly handle long, 255char+, records that have been split up into "string" "string2" "string3"' strings to exceed the 255-char substring limit (which this function outputs)
     For that matter, it won't even complain about records that are longer than the 255char single string limit.

    .PARAMETER TextRecord
    Raw full length desired TXT record[-TextRecord `$spfFullRecord]
    .INPUTS
    None. Does not accepted piped input.(.NET types, can add description)
    .OUTPUTS
    System.String space quote-wrapped returned to pipeline
    .EXAMPLE
    PS> $dkimString = $instring = "v=DKIM1;k=rsa;p=MIIBIjANBgkqhkiG1w1BAQEFAAOCAQ1AMIIBCgKCAQEAh111KTmtf+f1GCrdVKydz1x1NDs1Cx/g/AYIlx1QcyOpXzd1DNC1saykKjfwYEIGq11UdnLQdJztINPu1QsphwSnpQiGqV11EltNp1poNNeUwSno1vrUTQI11vkD1OosCh+yLVD1AWCqxOr1l1C1kp1UuXvEc1zANPQrbOuVABmGf1nLFvcR1iswFC1JpLOdZr111BelASlU1WApIeDK/a1Qo111WzpFCeFtamIxZFkeHdCSmrS1zrtDrxxvXzYhXIFharkWeY1cXKzZ1vUGR11Zie1gzNzoz1NoibngkBH1dw1C11lU1ynVwx+/U+TCEKOZu1X1K/ZC1/1NrsW11QIDAQAB" ;
    PS> $outformated = split-DnsTXTRecord -TextRecord  $instring -verbose ;
    PS> write-host "`n`$outformated:`n$(($outformated|out-string).trim())`n" ; 
    PS> if($instring.contains(' ')){
    PS>   $reconstitute = ($outformated -split '\s' | %{$_ -replace '["]',''} ) -join ' ' ; 
    PS> } else { 
    PS>   $reconstitute = ($outformated -split '\s' | %{$_ -replace '["]',''} ) -join '' ; 
    PS> } ; 
    PS> if($reconstitute -eq $instring ){$isPass = $true } else { $isPass = $false } ; 
    PS> if($isPass){
    PS>     $smsg = "$([Char]8730) Confirmed reconstited matches original!" ;
    PS> } else { $smsg = "`n`$reconstitute <> `$outformated" } 
    PS> $smsg += "`n`$reconstitute:`n$($reconstitute)" ; 
    PS> $smsg += "`n`n`$instring:`n$($instring)" ; 
    PS> if($isPass){ write-host -foregroundcolor green $smsg } else { write-warning $smsg } ; 

        $outformated:
        "v=DKIM1;k=rsa" ";p=MIIBIjANBgkqhkiG1w1BAQEFAAOCAQ1AMIIBCgKCAQEAh111KTmtf+f1GCrdVKydz1x1NDs1Cx/g/AYIlx1QcyOpXzd1DNC1saykKjfwYEIGq11UdnLQdJztINPu1QsphwSnpQiGqV11EltNp1poNNeUwSno1vrUTQI11vkD1OosCh+yLVD1AWCqxOr1l1C1kp1UuXvEc1zAN
        PQrbOuVABmGf1nLFvcR1iswFC1JpLOdZr111BelASlU1W" "ApIeDK/a1Qo111WzpFCeFtamIxZFkeHdCSmrS1zrtDrxxvXzYhXIFharkWeY1cXKzZ1vUGR11Zie1gzNzoz1NoibngkBH1dw1C11lU1ynVwx+/U+TCEKOZu1X1K/ZC1/1NrsW11QIDAQAB"

        √ Confirmed reconstited matches original!
        $reconstitute:
        v=DKIM1;k=rsa;p=MIIBIjANBgkqhkiG1w1BAQEFAAOCAQ1AMIIBCgKCAQEAh111KTmtf+f1GCrdVKydz1x1NDs1Cx/g/AYIlx1QcyOpXzd1DNC1saykKjfwYEIGq11UdnLQdJztINPu1QsphwSnpQiGqV11EltNp1poNNeUwSno1vrUTQI11vkD1OosCh+yLVD1AWCqxOr1l1C1kp1UuXvEc1zANPQrb
        OuVABmGf1nLFvcR1iswFC1JpLOdZr111BelASlU1WApIeDK/a1Qo111WzpFCeFtamIxZFkeHdCSmrS1zrtDrxxvXzYhXIFharkWeY1cXKzZ1vUGR11Zie1gzNzoz1NoibngkBH1dw1C11lU1ynVwx+/U+TCEKOZu1X1K/ZC1/1NrsW11QIDAQAB

        $instring:
        v=DKIM1;k=rsa;p=MIIBIjANBgkqhkiG1w1BAQEFAAOCAQ1AMIIBCgKCAQEAh111KTmtf+f1GCrdVKydz1x1NDs1Cx/g/AYIlx1QcyOpXzd1DNC1saykKjfwYEIGq11UdnLQdJztINPu1QsphwSnpQiGqV11EltNp1poNNeUwSno1vrUTQI11vkD1OosCh+yLVD1AWCqxOr1l1C1kp1UuXvEc1zANPQrb
        OuVABmGf1nLFvcR1iswFC1JpLOdZr111BelASlU1WApIeDK/a1Qo111WzpFCeFtamIxZFkeHdCSmrS1zrtDrxxvXzYhXIFharkWeY1cXKzZ1vUGR11Zie1gzNzoz1NoibngkBH1dw1C11lU1ynVwx+/U+TCEKOZu1X1K/ZC1/1NrsW11QIDAQAB

    Demo reformatting of a public key-holding DKIM TXT record string
    .EXAMPLE
    PS> $spfString = $instring = "v=spf1 ip4:111.111.111.111 ip4:111.111.111.111 ip4:111.11.1.111 ip4:111.11.1.111 ip4:111.11.11.11 ip4:111.11.11.11 ip4:111.11.1.11 ip4:111.11.1.11 ip4:111.111.111.11 include:spf.protection.outlook.com include:_spf.vendor.com include:111111.spf11.vendor.net ~all" ;
    PS> $outformated = split-DnsTXTRecord -TextRecord  $instring -verbose ;
    PS> write-host "`n`$outformated:`n$(($outformated|out-string).trim())`n" ; 
    PS> if($instring.contains(' ')){
    PS>   $reconstitute = ($outformated -split '\s' | %{$_ -replace '["]',''} ) -join ' ' ; 
    PS> } else { 
    PS>   $reconstitute = ($outformated -split '\s' | %{$_ -replace '["]',''} ) -join '' ; 
    PS> } ; 
    PS> if($reconstitute -eq $instring ){$isPass = $true } else { $isPass = $false } ; 
    PS> if($isPass){
    PS>     $smsg = "$([Char]8730) Confirmed reconstited matches original!" ;
    PS> } else { $smsg = "`n`$reconstitute <> `$outformated" } 
    PS> $smsg += "`n`$reconstitute:`n$($reconstitute)" ; 
    PS> $smsg += "`n`n`$instring:`n$($instring)" ; 
    PS> if($isPass){ write-host -foregroundcolor green $smsg } else { write-warning $smsg } ;  

        $outformated:
        "v=spf1 ip4:111.111.111.111 ip4:111.111.111.111 ip4:111.11.1.111 ip4:111.11.1.111 ip4:111.11.11.11 ip4:111.11.11.11 ip4:111.11.1.11 ip4:111.11.1.11 ip4:111.111.111.11 include:spf.protection.outlook.com include:_spf.vendor
        .com" "include:111111.spf11.somedomain.net ~all"

        √ Confirmed reconstited matches original!
        $reconstitute:
        v=spf1 ip4:111.111.111.111 ip4:111.111.111.111 ip4:111.11.1.111 ip4:111.11.1.111 ip4:111.11.11.11 ip4:111.11.11.11 ip4:111.11.1.11 ip4:111.11.1.11 ip4:111.111.111.11 include:spf.protection.outlook.com include:_spf.vendor.
        com include:111111.spf11.somedomain.net ~all

        $instring:
        v=spf1 ip4:111.111.111.111 ip4:111.111.111.111 ip4:111.11.1.111 ip4:111.11.1.111 ip4:111.11.11.11 ip4:111.11.11.11 ip4:111.11.1.11 ip4:111.11.1.11 ip4:111.111.111.11 include:spf.protection.outlook.com include:_spf.vendor.
        com include:111111.spf11.somedomain.net ~all

    Demo reformatting of a an SPF TXT record string
    .LINK
    https://bitbucket.org/tostka/powershell/
    .LINK
    https://kb.isc.org/docs/aa-00356
    .LINK
    https://datatracker.ietf.org/doc/html/rfc1035
    .LINK
    https://easydmarc.com/tools/spf-record-raw-check-validate
    #>
    [CmdletBinding()]
    ## PSV3+ whatif support:[CmdletBinding(SupportsShouldProcess)]
    ###[Alias('Alias','Alias2')]
    PARAM(
        [Parameter(Mandatory=$True,HelpMessage="Raw full length desired TXT record[-TextRecord `$spfFullRecord]")]
            [ValidateNotNullOrEmpty()]
            #[Alias('ALIAS1', 'ALIAS2')]
            [string]$TextRecord
    ) ; 
    $substringMaxChars = 255 ; 
    $TXTRecordMaxChars = 4000 ; 
    
    #region WHPASSFAIL ; #*======v WHPASSFAIL v======
    $whTPad = 72  ; $whTChar = '.' ; # scale $whTPad to longest Testing:xxx line you use in the test array
    if(-not $whPASS){$whPASS = @{ Object = "$([Char]8730) PASS`n" ; ForegroundColor = 'Green' ; NoNewLine = $true  } }
    if(-not $whFAIL){$whFAIL = @{'Object'= if ($env:WT_SESSION) { "$([Char]8730) FAIL`n"} else {" !X! FAIL`n"}; ForegroundColor = 'RED' ; NoNewLine = $true } } ;
    # light diagonal cross: ╳ U+2573 DOESN'T RENDER IN PS, use it if WinTerm
    if(-not $psPASS){$psPASS = "$([Char]8730) PASS`n" } # $smsg = $pspass + " :Tested Drives" ; write-host $smsg ;
    if(-not $psFAIL){$psFAIL = if ($env:WT_SESSION) { "$([Char]8730) FAIL`n"} else {" !X! FAIL`n"} } ; # $smsg = $psfail + " :Tested Drives" ; write-warning $smsg ;    
    <# WHPASSFAIL:SAMPLE TESTS:
    #region WHPASSFAILSimpleTest ; #*------v WHPASSFAILSimpleTest v------
    $tFormat = 'NTFS' ; 
    $smsg = "Testing: Volume.FileSystem against: $($tFormat)" ; #Write-Host "$($smsg)... " -NoNewline ;
    $smsg += " $($whTChar * ($whTPad - $smsg.length))" ; Write-Host "$($smsg) " -NoNewline ;
    if ($VOL.FileSystem -eq $tFormat) {Write-Host @whPASS} else {write-host @whFAIL };
    #endregion WHPASSFAILSimpleTest ; #*------^ END WHPASSFAILSimpleTest ^------    
    #region WHPASSFAILCapacityTest ; #*------v WHPASSFAILCapacityTest v------
    # Test: Capacity match, threshold vs %:
    $tSpaceThresh = 10 * 1GB ; # .9 (for %)
    if($tSpaceThresh -gt 1000){ $smsg = "Testing: Volume.SizeRemainingStatus against: $(RndTo3($tSpaceThresh/1GB))GB" }
    elseif($tSpaceThresh -lt 1){$smsg = "Testing: Volume.SizeRemainingStatus against: $(RndTo3($tSpaceThresh * 100))%" }
    else {$smsg = "Testing: Volume.SizeRemainingStatus against: $($tSpaceThresh)" } ;
    $smsg += " $($whTChar * ($whTPad - $smsg.length))" ; Write-Host "$($smsg) " -NoNewline ;
    if($VerbosePreference -eq 'Continue'){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE }else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
    if($tSpaceThresh -lt 1){
        $smsg = "Detected $($tSpaceThresh) is a percentage free test" ;
        if($VerbosePreference -eq 'Continue'){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE }else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
        if ($tv.SizeRemaining / $tv.Size -lt $tSpaceThresh) {
            $rptDrive.SizeRemainingStatus = $false ;
            write-host @whFAIL ;
            $smsg = "Insufficient free space on DB drive: $($tv.DriveLetter): $(RndTo2($tv.SizeRemaining/1GB)) GB, needs at least $($tv.Size/1GB * $tSpaceThresh) GB" ;
            $rptDrive.DriveIssues += @($smsg)
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent}else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        } else {
            $rptDrive.SizeRemainingStatus = $true ;
            Write-Host @whPASS ;   ;
            $smsg = "DB drive: $($tv.DriveLetter): $(RndTo2($tv.SizeRemaining/1GB)) GB free, sufficient for install" ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        } ;
    }else{
        $smsg = "Detected $($tSpaceThresh) is a free space floor test" ;
        if($VerbosePreference -eq 'Continue'){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE }else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
        if ($tv.SizeRemaining -lt $tSpaceThresh){
            $rptDrive.SizeRemainingStatus = $false ;
            write-host @whFAIL ;
            $smsg = "Insufficient free space on $($rptDrive.DriveRole -join ',') drive: $(RndTo2($tv.SizeRemaining/1GB)) GB, needs at least $(RndTo2($tSpaceThresh/1GB)) GB" ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent}else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        } else {
            $rptDrive.SizeRemainingStatus = $true ;
            Write-Host @whPASS ;   ;
            $smsg = "$($rptDrive.DriveRole -join ','): $(RndTo2($tv.SizeRemaining/1GB)) GB free, sufficient for install" ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        } ;
    } ; 
    #endregion WHPASSFAILCapacityTest ; #*------^ END WHPASSFAILCapacityTest ^------
    #>
    #endregion WHPASSFAIL ; #*======^ END WHPASSFAIL ^======

    # precheck for existing compliance
    $smsg = "Testing:-TextRecord.length -lt $($TXTRecordMaxChars) : " ;
    Write-Host "$($smsg)... " -NoNewline ; 
    if($TextRecord.length -gt $TXTRecordMaxChars){
        write-host @whFail ; 
        $smsg = " : Record length - $($TextRecord.length) - is ABOVE the $($TXTRecordMaxChars) max!" ; 
        $smsg += "`nMUST BE REFACTORED TO FEWER CHARACTERS (CIDR SUBNETS, 2NDARY INCLUDES TC)" ; 
        write-host $smsg ; 
    } else {
        Write-Host @whPASS ; 
        write-host " : Record length - $($TextRecord.length) - is below the $($TXTRecordMaxChars) max" ; 
    }; 
    
    if($TextRecord.Contains('"')){
        $smsg = "-TextRecord contains existing quotation marks (`"): Appears to be a pre-reformated record" 
        $smsg += "`n$(($TextRecord|out-string).trim())`n" ; 
        write-host -foregroundcolor yellow $smsg ;

        $smsg = "Testing:quoted substrings are -lt $($substringMaxChars) :" ;
        Write-Host "$($smsg)... " -NoNewline ; 
        #if($Passed){Write-Host @whPASS} else {write-host @whFAIL} ; 
        #Write-Host " (Done)" ;
        if($badsubstrings = ($outformated -split '\"\s\"')|%{$_.replace('"','') | ?{$_.length -gt $substringMaxChars}}){
            write-host @whFail ; 
            write-host " : substrings are within the record, that are -gt than the $($substringMaxChars) DNS BIND substring limit!" ; 
        } else { 
            Write-Host @whPASS
            write-host " : All substrings within the record are -lt than the $($substringMaxChars) DNS BIND substring limit" ; 
        } ; 

        # reconstitute quoted to original raw text string:
        write-host "Reconstituting quoted substrings to flattened unquoted record for reporcessing" ; 
        if($TextRecord.contains(' ')){
            $reconstitute = ($TextRecord -split '\s' | %{$_ -replace '["]',''} ) -join ' ' ; 
        } else { 
            $reconstitute = ($TextRecord -split '\s' | %{$_ -replace '["]',''} ) -join '' ; 
        } ; 
        $TextRecord = $reconstitute ; 
    }else{
        # test for non-quote-split pre-compliant -lt 255char
        $smsg = "Testing already compliant:-TextRecord.length -le $($substringMaxChars) : " ;
        Write-Host "$($smsg)... " -NoNewline ; 
        if($TextRecord.length -gt $substringMaxChars){
            write-host @whFail ; 
            $smsg = " : Record length - $($TextRecord.length) - is ABOVE the $($substringMaxChars) max!" ; 
            $smsg += "`nMUST BE REFACTORED TO FEWER CHARACTERS (CIDR SUBNETS, 2NDARY INCLUDES TC)" ; 
            write-host $smsg ; 
        } else {
            Write-Host @whPASS ; 
            $smsg = " : Record length - $($TextRecord.length) - is already below the $($substringMaxChars) max" ; 
            $smsg += "`nNo further revisions of the record are necessary to a provide a compliant TXT record" ; 
            $smsg += "`n(EXITING)" ; 
            #$TextRecord | write-output ;
            return $TextRecord ; 
            break ; 
        }; 
    }
    
    [string[]]$FinishedStrs = $WorkingStrings = @() ; 
    [string]$WorkingStrings = $TextRecord ; 
    $cutchar = ' ' ; 
    [string[]]$strArray = @() ;  
    if($WorkingStrings.Contains($cutchar)){
        write-verbose "WorkingStrings includes '$($cutchar)' characters: Splitting into substrings at those characters"
        if($substrs = $WorkingStrings -split $cutchar ){
            $sPad = $sTextO = "";
            foreach ($substr in $substrs) {
                $prospect = (@($sPad,$substr)|?{$_}) -join $cutchar ; 
                write-verbose "`$prospect:`n$($prospect)" ; 
                if ($prospect.length -gt $substringMaxChars) {
                    #$sTextO = '"' + $((@($sTextO,$sPad)|?{$_}) -join $cutchar) + '"'  ; 
                    # put off quot wrap until done
                    $strArray += @($((@($sTextO,$sPad)|?{$_}) -join $cutchar))
                    $sPad = $substr ;
                }else {
                    $sPad = $prospect; 
                } ;
            }  ;
            if ($sPad.length -ne 0) {
                if($cutchar -ne ' '){
                    # final delim will be spaces, we don't need extras
                    $strArray += @("$($cutchar)$($sPad)") ; 
                } else {
                    $strArray += @($sPad) ; 
                }; 
            };
            [string[]]$WorkingStrings = $strArray|?{$_.length -gt $substringMaxChars} ; 
            [string[]]$FinishedStrs += $strArray|?{$_.length -le $substringMaxChars} ; 
        } ; 
    }; 

    #} else {
    if($WorkingStrings){
        #write-verbose "No spaces in string, performing cuts at arbitrary locations" ; 
        $cutchar = ';' 
        [string[]]$strArray = @() ;  
        if($WorkingStrings.Contains($cutchar)){
            write-verbose "WorkingStrings includes '$($cutchar)' characters: Splitting into substrings at those characters"
            if($substrs = $WorkingStrings -split $cutchar ){
                $sPad = $sTextO = "";
                foreach ($substr in $substrs) {
                    $prospect = (@($sPad,$substr)|?{$_}) -join $cutchar ; 
                    write-verbose "`$prospect:`n$($prospect)" ; 
                    if ($prospect.length -gt $substringMaxChars) {
                        $strArray += @($((@($sTextO,$sPad)|?{$_}) -join $cutchar))
                        $sPad = $substr ;
                    }else {
                        $sPad = $prospect; 
                    } ;
                }  ;
                if ($sPad.length -ne 0) {
                    if($cutchar -ne ' '){
                        # final delim will be spaces, we don't need extras
                        $strArray += @("$($cutchar)$($sPad)") ; 
                    } else {
                        $strArray += @($sPad) ; 
                    }; 
                };
            } ; 
        }; 

        #[string[]]$WorkingStrings = $strArray|?{$_.length -gt $substringMaxChars} ; 
        #[string[]]$PreHandled = $strArray|?{$_.length -le $substringMaxChars} ; 

        [string[]]$WorkingStrings = $strArray|?{$_.length -gt $substringMaxChars} ; 
        [string[]]$FinishedStrs += $strArray|?{$_.length -le $substringMaxChars} ;

        if($WorkingStrings){
            # been through \s & ; splits; -> split long substrings at arbitrary points to get -lt $($substringMaxChars)
            $cutchar = '' ;
            #if($Chars = $WorkingStrings.ToCharArray()){
            #if($Chars = $WorkingStrings -split $cutchar){
            if($Chars = $WorkingStrings -split $cutchar |?{$_}){
                $sPad = $sTextO = "";
                foreach ($char in $chars) {
                    #if (($sPad + $char).length -gt ($substringMaxChars-2)) {
                    $prospect = (@($sPad,$char)|?{$_}) -join $cutchar ;
                    write-verbose "`$prospect:`n$($prospect)" ; 
                    if ($prospect.length -gt $substringMaxChars - 2) {
                        $FinishedStrs += $((@($sTextO,$sPad)|?{$_}) -join $cutchar)
                        $sPad = $char ;
                    }else {
                        $sPad = $prospect; 
                    } ;
                                        <#    $sTextO = '"' + $sTextO + $sPad + '"'  ; 
                    $sPad = $char ;
                }else {
                    $sPad = ($sPad + $char).trim() ; 
                } ;
                #>
                }  ;
                if ($sPad.length -ne 0) {
                    #$sTextO = $sTextO + (' "' + $sPad + '"') ;
                    #$PreHandled += $sPad ; 
                    $FinishedStrs += $sPad ; 
                };
            } else { 
                throw "Unable to split specified string into characters" ; 
            } ; 
        } ;
    } ; 
    #if($FinishedStrs -AND $sTextO){
    if($FinishedStrs ){
        $FinishedStrs = $FinishedStrs | select -unique ; 
        [string]$strReturn = $( ($FinishedStrs | %{ '"' + $_ + '"'} ) -join ' ') ; 
    } ; 
    if($strReturn.length -lt $TXTRecordMaxChars){
        $strReturn  | write-output ; 
        #return $strReturn  ; 
    } else {
        throw "Aggregate length is -gt than $($TXTRecordMaxChars)char max TXT record size limit!" ; 
    } ;
} ;  