# New-SelfSignedCertificateTDO.ps1

#*----------v Function New-SelfSignedCertificateTDO() v----------
function New-SelfSignedCertificateTDO {
    <#
    .SYNOPSIS
    New-SelfSignedCertificateTDO.ps1 - Create SelfSigned certificate (PKI) in specified -CertStoreLocation location, export same to pfx (named for DnsName with dateranges), and return a raw object version of the cert, along with the PFXPath and certificate properties to the pipeline. Objects created are suitable for Certificate-Based-Authentication of EntraID/AzureAD Application objects. 
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2022-
    FileName    : New-SelfSignedCertificateTDO.ps1
    License     : MIT License
    Copyright   : (c) 2022 Todd Kadrie
    Github      : https://github.com/tostka/powershell
    Tags        : Powershell,AzureAD,Authentication,Certificate,CertificateAuthentication
    AddedCredit : REFERENCE
    AddedWebsite: URL
    AddedTwitter: URL
    REVISIONS
    * 12:49 PM 6/22/2026 updated CBH demo to include sample AppFqDN value; added Output object definition/properties 
    * 4:23 PM 3/17/2026 new verb-network renamed copy prior New-AADAppAuthCertificate (AzureAD is completeley shutdown by M$)
    * 3:45 PM 6/23/2023 pulled req: verb-AAD 
    * 2:54 PM 6/13/2022 debugged, functional
    .DESCRIPTION
    New-SelfSignedCertificateTDO.ps1 - Create SelfSigned certificate (PKI) in specified -CertStoreLocation location, export same to pfx (named for DnsName with dateranges), and return a raw object version of the cert, along with the PFXPath and certificate properties to the pipeline. Objects created are suitable for Certificate-Based-Authentication of EntraID/AzureAD Application objects. 
    
    => renamed copy of prior New-AADAppAuthCertificate
    
    .PARAMETER DnsName
    Certificate DNSName (AppFQDN)[-DnsName server.domain.com]
    .PARAMETER CertStoreLocation
    Certificate store for storage of new certificate[-CertStoreLocation 'Cert:\CurrentUser\My']
    .PARAMETER StartDate
    New certificate StartDate
    .PARAMETER EndDate
    New certificate EndDate
    .PARAMETER Whatif
    Parameter to run a Test no-change pass [-Whatif switch]
    .INPUTS
    None. Does not accepted piped input.(.NET types, can add description)
    .OUTPUTS
    PSCustomObject containing following properties about new certificate:
        Certificate = System.Security.Cryptography.X509Certificates.X509Certificate2 - An X509Certificate2 object for the certificate that has been created.; 
        CertRaw = Base64String representation of the RawCertData
        PFXPath = Path to exported pfx file for the certificate ; 
        Valid = set $true if Valid Certificate, CertRaw property, and PFXPath property;     
    .EXAMPLE
    PS> $AppFqDN = 'DESCRIPTIVETAG-AppReg.TENANT.onmicrosoft.com'
    PS> $certStore = 'Cert:\CurrentUser\My' ; 
    PS> $pltNSSC=[ordered]@{
    PS>     DnsName=$AppFqDN ;
    PS>     CertStoreLocation = $certStore ;
    PS>     EndDate=(get-date ).addyears(3) ;
    PS>     StartDate = (get-date ) ; 
    PS>     verbose = $($verbose) ; 
    PS>     whatif = $($whatif) ;
    PS> } ;
    PS> $smsg = "New-SelfSignedCertificateTDO w`n$(($pltNSSC|out-string).trim())" ;
    PS> if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
    PS> else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    PS> $bRet = New-SelfSignedCertificateTDO @pltNSSC ; 
    PS> if($bREt.Valid){
    PS>     $smsg = "`n`n==>Valid return:" ; 
    PS>     $smsg += "`n$(($bREt|out-string).trim())" ; 
    PS>     $smsg += "`n--CERTIFICATE:$(($bREt.Certificate|out-string).trim())" ; 
    PS>     $smsg += "`n--CERTIFICATE-RAW:$(($bREt.CertRaw|out-string).trim())`n`n" ; 
    PS>     write-host -foregroundcolor green $smsg ; 
    PS> } else { 
    PS>     $smsg ="New-SelfSignedCertificateTDO returned INVALID outputs`n$(($bRet|out-string).trim())" ;
    PS>     if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } 
    PS>     else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
    PS>     throw $smsg ; 
    PS>     break ; 
    PS> } ;     
    Splatted demo with whatif & verbose, gens cert, exports pfx, provides raw content of cert (for mounting on appreg), and runs cmd to add cert to existing AAD Registered App.
    .LINK
    https://github.com/tostka/verb-XXX
    .LINK
    https://bitbucket.org/tostka/powershell/
    .LINK
    [ name related topic(one keyword per topic), or http://|https:// to help, or add the name of 'paired' funcs in the same niche (enable/disable-xxx)]
    #>
    #Requires -Modules PKI, verb-IO, verb-logging
    # VALIDATORS: [ValidateNotNull()][ValidateNotNullOrEmpty()][ValidateLength(24,25)][ValidateLength(5)][ValidatePattern("some\sregex\sexpr")][ValidateSet("US","GB","AU")][ValidateScript({Test-Path $_ -PathType 'Container'})][ValidateScript({Test-Path $_})][ValidateRange(21,65)]#positiveInt:[ValidateRange(0,[int]::MaxValue)]#negativeInt:[ValidateRange([int]::MinValue,0)][ValidateCount(1,3)]
    ## [OutputType('bool')] # optional specified output type
    [CmdletBinding()]
    ###[Alias('Alias','Alias2')]
    PARAM(
        [Parameter(Mandatory=$True,HelpMessage="Certificate DNSName (AppFQDN)[-DnsName server.domain.com]")]
            [ValidateNotNullOrEmpty()]
            #[Alias('ALIAS1', 'ALIAS2')]
            [string]$DnsName,
        [Parameter(Mandatory=$True,HelpMessage="Certificate store for storage of new certificate[-CertStoreLocation 'Cert:\CurrentUser\My']")]
            [ValidateNotNullOrEmpty()]
            #[Alias('ALIAS1', 'ALIAS2')]
            [string]$CertStoreLocation,
        [Parameter(Mandatory=$True,HelpMessage="New certificate StartDate[-StartDate '6/9/2022']")]
            [ValidateNotNullOrEmpty()]
            #[Alias('ALIAS1', 'ALIAS2')]
            [datetime]$startDate, 
        [Parameter(Mandatory=$True,HelpMessage="New certificate EndDate[-EndDate '6/9/2024']")]
            [ValidateNotNullOrEmpty()]
            #[Alias('ALIAS1', 'ALIAS2')]
            [datetime]$endDate,
        [Parameter(HelpMessage="Whatif Flag  [-whatIf]")]
            [switch] $whatIf=$true
    ) ;
    #region CONSTANTS-AND-ENVIRO #*======v CONSTANTS-AND-ENVIRO v======
    # function self-name (equiv to script's: $MyInvocation.MyCommand.Path) ;
    ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
    $PSParameters = New-Object -TypeName PSObject -Property $PSBoundParameters ;
    write-verbose -verbose:$verbose "`$PSBoundParameters:`n$(($PSBoundParameters|out-string).trim())" ;
    $Verbose = ($VerbosePreference -eq 'Continue') ; 
    
    $objReturn = @{
        Certificate = $null ; 
        CertRaw = $null ; 
        PFXPath = $null ; 
        Valid = $false ; 
    } ; 
    
    $smsg = "---1)ENTER CERTIFICATE PFX Password: (use 'dummy' for UserName)" ;
    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    $pfxcred=(Get-Credential -credential dummy) ;

    $pltNSSCert=[ordered]@{
        DnsName=$DnsName ;
        CertStoreLocation = $CertStoreLocation ;
        KeyExportPolicy='Exportable' ;
        Provider="Microsoft Enhanced RSA and AES Cryptographic Provider" ;
        NotAfter=$endDate ;
        KeySpec='KeyExchange' ;
        erroraction='STOP';
        whatif = $($whatif) ;
    } ;
    $smsg = "---2)New-SelfSignedCertificate w`n$(($pltNSSCert|out-string).trim())" ;
    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

    # precheck for conflicting existing on same dnsname
    if($conflicts = gci $pltNSSCert.CertStoreLocation |?{$_.subject -eq "CN=$($pltNSSCert.DnsName)"} ){
        $smsg = "PREXISTING CERT IN $($CertStoreLocation) W MATCHING DNSNAME!`n$(($conflicts | ft -a thumbprint,subject,when*|out-string).trim())" ; 
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug 
        else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        $bRet=Read-Host "Enter YYY to continue. Anything else will exit" 
        if ($bRet.ToUpper() -eq "YYY") {
            $smsg = "Moving on" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        } else {
            $smsg = "Invalid response. Exiting"
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug 
            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            Break ;# exit <asserted exit error #>
            #exit 1
        } # if-block end
    } ; 
    
    $newcert = (New-SelfSignedCertificate @pltNSSCert); 
    $objReturn.Certificate = $newcert ; 
    
    if(-not $whatif -AND $newcert){
        $smsg = "(new cert:$($newcert.thumbprint) created)" ; 
        if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 

        #$newcert.thumbprint | set-Content -Path "$(split-path $transcript)\cert-$($DnsName)-thumb-$(get-date -format 'yyyyMMdd-HHmmtt').txt" ; 

        $pltExPfx=[ordered]@{
            Cert= "$($CertStoreLocation)\$($newcert.thumbprint)"
            FilePath="$(split-path $profile)\keys\$($DnsName)-NOTAFTER-$(get-date $pltNSSCert.notafter -format 'yyyyMMdd-HHmmtt').pfx" ;
            Password=$pfxcred.password ;
            erroraction='STOP';
        } ;
        $smsg = "---3)Export-PfxCertificate  w`n$(($pltExPfx|out-string).trim())" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        $newpfx = Export-PfxCertificate @pltExPfx ;
        $objReturn.PFXPath = $pltExPfx.FilePath ; 

        $smsg = "`n$(($newpfx|out-string).trim())" ; 
        if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
    
        $smsg = "(create cert object)" ; 
        if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate($pltExPfx.FilePath, $pfxcred.password) ;
        $smsg = "`ncert obj created:w`n$(($cert | ft -a handle,issuer,subject |out-string).trim())" ; 
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
        else{ write-host -foregroundcolor green $($smsg) } ;

        $certRaw = [System.Convert]::ToBase64String($cert.GetRawCertData()) ;
        $objReturn.CertRaw = $certRaw ; 
        
        if($objReturn.Certificate -AND $objReturn.CertRaw -AND $objReturn.PFXPath){ 
            $smsg = "Valid Certificate, CertRaw, and PFX values: Setting Valid:`$true" ; 
            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
            $objReturn.Valid = $true ; 
        } else { 
            $smsg = "INVALID CERTIFICATE, CERTRAW, or PFX: Setting Valid:`$FALSE" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } 
            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
            $objReturn.Valid = $false 
        } ; 
        
        New-Object -TypeName PSObject -Property $objReturn | write-output ; 
        
    } else { 
        $smsg = "`n(-whatif, skipping post-creation cert-handling code)" ; 
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    } ; 
} ;  
#*------^ END Function New-SelfSignedCertificateTDO ^------
