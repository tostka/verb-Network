# set-RDPFileSignatureTDO.ps1

#region SET_RDPFILESIGNATURETDO ; #*------v set-RDPFileSignatureTDO v------
function set-RDPFileSignatureTDO {
    <#
    .SYNOPSIS
    set-RDPFileSignatureTDO - Digitally sign .rdp TermServ connection files with specified local certificate (wrapper for rdpsign.exe)
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2026-04-29
    FileName    : set-RDPFileSignatureTDO.ps1
    License     : MIT License
    Copyright   : (c) 2026 Todd Kadrie
    Github      : https://github.com/tostka/verb-XXX
    Tags        : Powershell
    AddedCredit : REFERENCE
    AddedWebsite: URL
    AddedTwitter: URL
    REVISIONS
    * 10:07 AM 4/29/2026 fixed bvorked help parsing: removed leading periods from all RDP file ext refs (confused parser on dotted help keywords) ; 
         moved vio -> vnet ; add -RegisterCertificate & vnet\Test-CertificateTDO() chain of trust validation
    * 12:59 PM 4/28/2026 init
    .DESCRIPTION
        
    set-RDPFileSignatureTDO - Digitally sign rdp TermServ connection files with specified local certificate (wrapper for rdpsign.exe)

    [Signing rdp files with Signotaurbr / (and surviving the April - www.finalbuilder.com/](https://www.finalbuilder.com/resources/blogs/signing-rdp-files-with-signotaur-and-surviving-the-april-windows-update)

    ## What Microsoft changed

    The April cumulative addresses [CVE-2026-26151](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26151). Two user-visible things came with it:

    1. The Remote Desktop Connection warning dialog was redesigned. It now 
        lists every resource the connection can redirect (drives, printers, clipboard, 
        USB, etc.) with individual checkboxes, and **every box is off by default**. 
        Users have to opt in to each one on every connection, every time. 
    2. The trust criteria for signed `rdp` files tightened. Pre-April, a file 
        signed by an untrusted cert got a yellow "Verify the publisher" banner. 
        Post-April, the same file gets an orange "Caution: Unknown remote connection" 
        banner — visually indistinguishable from an unsigned file

 
    Here's what the new per-launch dialog looks like. For an unsigned file:

    [The RDP security warning dialog for an unsigned file: an orange 'Caution: Unknown remote connection' banner, 'Unknown publisher', and per-redirection checkboxes all off by default.]

    And for a file signed by a publisher Windows can verify:

    [The RDP security warning dialog for a signed file: a yellow 'Verify the publisher of this remote connection' banner with the publisher name, and the same per-redirection checkboxes.]

    Separately, the first time any user opens an `rdp` file after installing the update, Windows shows a one-time educational dialog explaining what `rdp` files are and why they can be dangerous:

    [The first-launch educational dialog shown once per user account after installing KB5083769, explaining what RDP files are and the associated phishing risks.]

    Once dismissed, it doesn't reappear for that account.


    Here's what recipient machines need for a signed `rdp` file to open with no warning dialog at all:
    
    [Note: HKCU material below is implmented by the -RegisterCertificate parameter]

    1.  The signing certificate's chain must terminate in a root the client machine trusts.
        Commercial code-signing certs (DigiCert, Sectigo, etc.) chain to roots Windows already trusts. 
        For an internal CA or self-signed cert, the root has to be imported into `Cert:\*\Root` on each client. 
    2.  A Remote Desktop trust policy must be in place that whitelists your 
        signing certificate's SHA-1 thumbprint. This lives at either 
        `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services` (machine-wide, requires admin) 
        or `HKCU\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services` (per-user, no admin required), and needs two values: 
        -   `AllowSignedFiles` — REG\_DWORD, set to `1`
        -   `TrustedCertThumbprints` — REG\_SZ, the SHA-1 thumbprint of your signing cert, uppercase, no spaces (semicolon-separated if you have more than one)

    A word of warning about one trap we hit: `TrustedCertThumbprints` is a 
    whitelist on top of normal chain validation, not a replacement for it. Dropping 
    a self-signed cert's thumbprint into the list without also importing the cert 
    into a trusted root store does nothing. If you've tried this and wondered why 
    it didn't work, that's why. 

    .PARAMETER Path
    rdp File paths[-path c:\pathto\file.rdp]
    .PARAMETER Thumbprint
    Signing certificate thumbprint (locally installed)[-Thumbprint 9A9A999A999A9A9999999A9A9AAA99AAA99AA9A9]
    .PARAMETER DiscoverCertificate
    Discover a local signing Certificate (-thumbprint) in local HKCU as Trusted for signed RDP files.[-RegisterCertificate]
    .PARAMETER RegisterCertificate
    Register specified Certificate (-thumbprint) in local HKCU as Trusted for signed RDP files.
    .INPUTS
    Accepts piped input Path.
    .OUTPUTS
    Returns a path to signed object on a successful signing
    .EXAMPLE
    PS> $results = set-RDPFileSignatureTDO -path 'C:\Users\aaaaaAAA\Desktop\rdp-faves\AAAAAAAAAAA-AAA-Ex16-Mbx1-1024x768-SID.RDP: confirmed' -Thumbprint 9A9A999A999A9A9999999A9A9AAA99AAA99AA9A9 ;
    PS> $results ; 

    Report on results of signing file   
    .EXAMPLE
    PS> gci "$($env:USERPROFILE)\Desktop\rdp-faves*.rdp" | select -first 1  | set-RDPFileSignatureTDO -verbose ;
    Demo signing all .rdp files in the specified dir, with pipeline input.
    .EXAMPLE
    PS> $Thumbprint = "9A9A999A999A9A9999999A9A9AAA99AAA99AA9A9"
    PS> $RegPath = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    PS> write-verbose "Create the key path if it does not exist" ; 
    PS> if (-not (Test-Path $RegPath)) {New-Item -Path $RegPath -Force | Out-Null} ; 
    PS> New-ItemProperty  -Path $RegPath  -Name 'AllowSignedFiles'  -PropertyType DWord  -Value 1  -Force | Out-Null ; 
    PS> New-ItemProperty -Path $RegPath -Name 'TrustedCertThumbprints' -PropertyType String -Value '$($Thumbprint)' -Force | Out-Null ; 
    Code to configure HKCU required keys and values to register the signing certificate used, to be trusted to load signed .rdp files without prompts (e.g. as implemented via -RegisterCertificate param)
    .EXAMPLE
    PS> $results = set-RDPFileSignatureTDO -RegisterCertificate -Thumbprint $TORMeta.SignCertThumb ;
    PS> $results ;
    Demo use of -RegisterCErtificate to populate HKCU required keys and values to register the signing certificate specified, to be trusted to load signed .rdp files without prompts
    .EXAMPLE
    PS> write-verbose "Create Self-Signed certificate in LocalMachine\My store" ; 
    PS> $pltNSSC=@{
    PS>     Type = 'CodeSigningCert' ;
    PS>     Subject = "CN=RDP PUBLISHER, O=YOUR ORGANISATION, C=US" ;
    PS>     KeyUsage = 'DigitalSignature' ;
    PS>     FriendlyName = "RDP Signing Certificate" ;
    PS>     CertStoreLocation = "Cert:\LocalMachine\My" ;
    PS>     NotAfter = (Get-Date).AddYears(3); # NOTE: 3 YEAR LIFE
    PS> } ; 
    PS> $cert = New-SelfSignedCertificate @pltNSSC ; 
    PS> $exportBaseFileName = "C:\Certs\rdp-signing" # EXPORTS BUILT ON VARIANTS OF THIS PATH AND FILENAME
    PS> $PFXPassword = ConvertTo-SecureString -String "YOURSTRONGPASSWORD!" -Force -AsPlainText ; 
    PS> if($cert = New-SelfSignedCertificate @pltNSSC){
    PS>     write-verbose "Export cert to .cer file (no key)" ; 
    PS>     Export-Certificate  -Cert $cert  -FilePath "$($exportBaseFileName)-public.cer" ; 
    PS>     write-verbose "Export cert to .pfx file (w private key)" ;         
    PS>     Export-PfxCertificate  -Cert $cert  -FilePath "$($exportBaseFileName).pfx"  -Password $PFXPassword ; 
    PS>     write-verbose "=>import the cert on a client, to critical-path required trust locations" ; 
    PS>     write-verbose "-->Import to Trusted Root CA" ; 
    PS>     Import-Certificate  -FilePath "$($exportBaseFileName)-public.cer"  -CertStoreLocation "Cert:\LocalMachine\Root" ; 
    PS>     write-verbose "-->Import to Trusted Publishers" ; 
    PS>     Import-Certificate  -FilePath "$($exportBaseFileName)-public.cer"  -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher"
    PS> } ; 
    Demo use of a self-signed cert: 1)Generate a certificate; 2)export to .cer (no key), and pfx (w private key); 3)and on client(s) import to critical-path trust locations.
    .LINK
    https://github.com/tostka/verb-io
#>
    [CmdletBinding(DefaultParameterSetName='Sign')]
    [Alias('sign-RdpFile','sign-RdpFileTDO')]
    PARAM(
        [Parameter(ParameterSetName="Sign",Mandatory = $False,Position = 0,ValueFromPipeline = $True, HelpMessage = '.Rdp File paths[-path c:\pathto\file.rdp]')]
            [Alias('PsPath')]
            [ValidateScript({Test-Path $_.fullname})]
            [ValidateScript({ if([IO.Path]::GetExtension($_) -ne ".rdp") { throw "Path must point to an .rdp file" } $true })]
            [system.io.fileinfo[]]$Path,
        [Parameter(ParameterSetName="Sign",Mandatory = $false,HelpMessage = 'Signing certificate thumbprint (locally installed)[-Thumbprint 9A9A999A999A9A9999999A9A9AAA99AAA99AA9A9]')]
        [Parameter(ParameterSetName="Register",Mandatory = $false,HelpMessage = 'Signing certificate thumbprint (locally installed)[-Thumbprint 9A9A999A999A9A9999999A9A9AAA99AAA99AA9A9]')]
            [ValidateNotNullOrEmpty()]
            [ValidatePattern("[0-9a-fA-F]{40}")]           
            [string]$Thumbprint = $TORMeta['SignCertThumb'],
        [Parameter(ParameterSetName="Discover",Mandatory = $false,HelpMessage = 'Discover a local signing Certificate (-thumbprint) in local HKCU as Trusted for signed RDP files.[-RegisterCertificate]')]
            [switch]$DiscoverCertificate,
        [Parameter(ParameterSetName="Register",Mandatory = $false,HelpMessage = 'Register specified Certificate (-thumbprint) in local HKCU as Trusted for signed RDP files.[-RegisterCertificate]')]
            [switch]$RegisterCertificate
    ) ; 
    BEGIN {
        #region LOCAL_CONSTANTS ; #*------v LOCAL_CONSTANTS v------
        $prpCert = 'Thumbprint','Subject','NotAfter','NotBefore' ; 
        $RegPath = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
        #endregion LOCAL_CONSTANTS ; #*------^ END LOCAL_CONSTANTS ^------
        #region FUNCTIONS_INTERNAL ; #*======v  FUNCTIONS_INTERNAL v======
        
        if(-not(get-command Test-CertificateTDO)){
            #*------v Function test-CertificateTDO v------
            function test-CertificateTDO {
                <#
                .SYNOPSIS
                test-CertificateTDO -  Tests specified certificate for certificate chain and revocation
                .NOTES
                Version     : 0.63
                Author      : Vadims Podans
                Website     : http://www.sysadmins.lv/
                Twitter     : 
                CreatedDate : 2024-08-22
                FileName    : test-CertificateTDO.ps1
                License     : (none asserted)
                Copyright   : Vadims Podans (c) 2009
                Github      : https://github.com/tostka/verb-network
                Tags        : Powershell,Certificate,Validation,Authentication,Network
                AddedCredit : Todd Kadrie
                AddedWebsite: http://www.toddomation.com
                AddedTwitter: @tostka / http://twitter.com/tostka
                REVISIONS
                * 9:18 AM 4/29/2026 Removed rem'd param lines, minor capitalization tweaks 
                * 9:55 AM 7/9/2025 updated CBH, corrected link vio -> vnet mod; updated CBH to explicitly note it supports testing _installed_ certs as well (VP's original didn't and relied on filesystem .ext for logic handling pfx pw etc). Shifted copies of the pki\test-certificate examples down into actual CBH expl entries, for broad reference
                * 8:20 AM 8/30/2024 pulled errant alias (rol, restart-outlook)
                * 2:29 PM 8/22/2024 fixed process looping (lacked foreach); added to verb-Network; retoololed to return a testable summary report object (summarizes Subject,Issuer,Not* dates,thumbprint,Usage (FriendlyName),isSelfSigned,Status,isValid,and the full TrustChain); 
                    added param valid on [ValidateSet, CRLMode, CRLFlag, VerificationFlags ; updated CBH; added support for .p12 files (OpenSSL pfx variant ext), rewrite to return a status object
                * 9:34 AM 8/22/2024 Vadims Podans posted poshcode.org copy from web.archive.org, grabbed 11/2016 (orig dates from 2009, undated beyond copyright line)
                .DESCRIPTION
                test-CertificateTDO -  Tests specified certificate for certificate chain and revocation status for each certificate in chain
                    exluding Root certificates
    
                    Based on Vadim Podan's 2009-era Test-Certificate function, expanded/reworked to return a testable summary report object (summarizes Subject,Issuer,NotBefore|After dates,thumbprint,Usage(FriendlyName),isSelfSigned,Status,isValid. 
        
                    Also revised to support testing _installed_ certs (original only did filesystem, used .extension to determine pw etc handling)

                    ## Note:Powershell v4+ PKI mod includes a native Test-Certificate cmdlet that returns a boolean, and supports -DNSName to test a given fqdn against the CN/SANs list on the certificate. 
                    Limitations of that alternate, for non-public certs, include that it lacks the ability to suppress CRL-testing to evaluate *private/internal-CA-issued certs, which lack a publcly resolvable CRL url. 
                    Those certs, will always fail the bundled Certificate Revocation List checks. 

                    This code does not have that issue: test-CertificateTDO used with -CRLMode NoCheck & -CRLFlag EntireChain validates a given internal Cert is...
                    - in daterange, 
                    - and has a locally trusted chain, 
                    ...where psv4+ test-certificate will always fail a non-CRL-accessible cert.

                    ### Examples of use of that cmdlet:
    
                    Demo 1:

                    PS C:\>Get-ChildItem -Path Cert:\localMachine\My | Test-Certificate -Policy SSL -DNSName "dns=contoso.com"

                    This example verifies each certificate in the MY store of the local machine and verifies that it is valid for SSL
                    with the DNS name specified.

                    Demo 2:

                    PS C:\>Test-Certificate –Cert cert:\currentuser\my\191c46f680f08a9e6ef3f6783140f60a979c7d3b -AllowUntrustedRoot
                    -EKU "1.3.6.1.5.5.7.3.1" –User

                    This example verifies that the provided EKU is valid for the specified certificate and its chain. Revocation
                    checking is not performed.
        
                .PARAMETER Certificate
                Specifies the certificate to test certificate chain. This parameter may accept X509Certificate, X509Certificate2 objects or physical file path. this paramter accept pipeline input
                .PARAMETER Password
                Specifies PFX file password. Password must be passed as SecureString.
                .PARAMETER CRLMode
                Sets revocation check mode. May contain on of the following values:
       
                    - Online - perform revocation check downloading CRL from CDP extension ignoring cached CRLs. Default value
                    - Offline - perform revocation check using cached CRLs if they are already downloaded
                    - NoCheck - specified certificate will not checked for revocation status (not recommended)
                .PARAMETER CRLFlag
                Sets revocation flags for chain elements. May contain one of the following values:
       
                    - ExcludeRoot - perform revocation check for each certificate in chain exluding root. Default value
                    - EntireChain - perform revocation check for each certificate in chain including root. (not recommended)
                    - EndCertificateOnly - perform revocation check for specified certificate only.
                .PARAMETER VerificationFlags
                Sets verification checks that will bypassed performed during certificate chaining engine
                check. You may specify one of the following values:
       
                - NoFlag - No flags pertaining to verification are included (default).
                - IgnoreNotTimeValid - Ignore certificates in the chain that are not valid either because they have expired or they are not yet in effect when determining certificate validity.
                - IgnoreCtlNotTimeValid - Ignore that the certificate trust list (CTL) is not valid, for reasons such as the CTL has expired, when determining certificate verification.
                - IgnoreNotTimeNested - Ignore that the CA (certificate authority) certificate and the issued certificate have validity periods that are not nested when verifying the certificate. For example, the CA cert can be valid from January 1 to December 1 and the issued certificate from January 2 to December 2, which would mean the validity periods are not nested.
                - IgnoreInvalidBasicConstraints - Ignore that the basic constraints are not valid when determining certificate verification.
                - AllowUnknownCertificateAuthority - Ignore that the chain cannot be verified due to an unknown certificate authority (CA).
                - IgnoreWrongUsage - Ignore that the certificate was not issued for the current use when determining certificate verification.
                - IgnoreInvalidName - Ignore that the certificate has an invalid name when determining certificate verification.
                - IgnoreInvalidPolicy - Ignore that the certificate has invalid policy when determining certificate verification.
                - IgnoreEndRevocationUnknown - Ignore that the end certificate (the user certificate) revocation is unknown when determining     certificate verification.
                - IgnoreCtlSignerRevocationUnknown - Ignore that the certificate trust list (CTL) signer revocation is unknown when determining certificate verification.
                - IgnoreCertificateAuthorityRevocationUnknown - Ignore that the certificate authority revocation is unknown when determining certificate verification.
                - IgnoreRootRevocationUnknown - Ignore that the root revocation is unknown when determining certificate verification.
                - AllFlags - All flags pertaining to verification are included.   
                .INPUTS
                Accepts piped input Certificate
                .OUTPUTS
                This script return general info about certificate chain status 
                .EXAMPLE
                PS> Get-ChilItem cert:\CurrentUser\My | test-CertificateTDO -CRLMode "NoCheck"
                Will check certificate chain for each certificate in current user Personal container.
                Specifies certificates will not be checked for revocation status.
                .EXAMPLE
                PS> $output = test-CertificateTDO C:\Certs\certificate.cer -CRLFlag "EndCertificateOnly"
                Will check certificate chain for certificate that is located in C:\Certs and named
                as Certificate.cer and revocation checking will be performed for specified certificate oject
                .EXAMPLE
                PS> $output = gci Cert:\CurrentUser\My -CodeSigningCert | Test-CertificateTDO -CRLMode NoCheck -CRLFlag EntireChain -verbose ;
                Demo Self-signed codesigning tests from CU\My, skips CRL revocation checks (which self-signed wouldn't have); validates that the entire chain is trusted.
                .EXAMPLE
                PS> if( gci Cert:\CurrentUser\My -CodeSigningCert | Test-CertificateTDO -CRLMode NoCheck -CRLFlag EntireChain |  ?{$_.valid -AND $_.Usage -contains 'Code Signing'} ){
                PS>         write-host "A-OK for code signing!"
                PS> } else { write-warning 'Bad Cert for code signing!'} ; 
                Demo conditional branching on basis of output valid value.
                .EXAMPLE
                PS C:\>Get-ChildItem -Path Cert:\localMachine\My | Test-Certificate -Policy SSL -DNSName "dns=contoso.com"
                Native PKI\test-certificate() demo: verifies each certificate in the MY store of the local machine and verifies that it is valid for SSL
                with the DNS name specified.
                .EXAMPLE
                PS C:\>Test-Certificate –Cert cert:\currentuser\my\191c46f680f08a9e6ef3f6783140f60a979c7d3b -AllowUntrustedRoot
                -EKU "1.3.6.1.5.5.7.3.1" –User
                Native PKI\test-certificate() demo: Verifies that the provided EKU is valid for the specified certificate and its chain. Revocation
                checking is not performed.    
                .LINK
                https://web.archive.org/web/20160715110022/poshcode.org/1633
                .LINK
                https://github.com/tostka/verb-network
                #>
                #requires -Version 2.0
                [CmdletBinding()]
                #[Alias('','')]
                PARAM(        
                    [Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$true,HelpMessage="Specifies the certificate to test certificate chain. This parameter may accept X509Certificate, X509Certificate2 objects or physical file path. this paramter accepts pipeline input")]
                        $Certificate,
                    [Parameter(HelpMessage="Specifies PFX|P12 file password. Password must be passed as SecureString.")]
                        [System.Security.SecureString]$Password,
                    [Parameter(HelpMessage="Sets revocation check mode (Online|Offline|NoCheck)")]
                        [ValidateSet('Online','Offline','NoCheck')]
                        [System.Security.Cryptography.X509Certificates.X509RevocationMode]$CRLMode = "Online",
                    [Parameter(HelpMessage="Sets revocation flags for chain elements ('ExcludeRoot|EntireChain|EndCertificateOnly')")]
                        [ValidateSet('ExcludeRoot','EntireChain','EndCertificateOnly')]
                        [System.Security.Cryptography.X509Certificates.X509RevocationFlag]$CRLFlag = "ExcludeRoot",
                    [Parameter(HelpMessage="Sets verification checks that will bypassed performed during certificate chaining engine check (NoFlag|IgnoreNotTimeValid|IgnoreCtlNotTimeValid|IgnoreNotTimeNested|IgnoreInvalidBasicConstraints|AllowUnknownCertificateAuthority|IgnoreWrongUsage|IgnoreInvalidName|IgnoreInvalidPolicy|IgnoreEndRevocationUnknown|IgnoreCtlSignerRevocationUnknown|IgnoreCertificateAuthorityRevocationUnknown|IgnoreRootRevocationUnknown|AllFlags)")]
                        [validateset('NoFlag','IgnoreNotTimeValid','IgnoreCtlNotTimeValid','IgnoreNotTimeNested','IgnoreInvalidBasicConstraints','AllowUnknownCertificateAuthority','IgnoreWrongUsage','IgnoreInvalidName','IgnoreInvalidPolicy','IgnoreEndRevocationUnknown','IgnoreCtlSignerRevocationUnknown','IgnoreCertificateAuthorityRevocationUnknown','IgnoreRootRevocationUnknown','AllFlags')]
                        [System.Security.Cryptography.X509Certificates.X509VerificationFlags]$VerificationFlags = "NoFlag"
                ) ;
                BEGIN { 
                    $Verbose = ($VerbosePreference -eq 'Continue') 
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 ; 
                    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain ; 
                    $chain.ChainPolicy.RevocationFlag = $CRLFlag ; 
                    $chain.ChainPolicy.RevocationMode = $CRLMode ; 
                    $chain.ChainPolicy.VerificationFlags = $VerificationFlags ; 
                    #*------v Function _getstatus_ v------
                    function _getstatus_ ($status, $chain, $cert){
                        # add a returnable output object
                        if($host.version.major -ge 3){$oReport=[ordered]@{Dummy = $null ;} }
                        else {$oReport=@{Dummy = $null ;}} ;
                        If($oReport.Contains("Dummy")){$oReport.remove("Dummy")} ;
                        $oReport.add('Subject',$cert.Subject); 
                        $oReport.add('Issuer',$cert.Issuer); 
                        $oReport.add('NotBefore',$cert.NotBefore); 
                        $oReport.add('NotAfter',$cert.NotAfter);
                        $oReport.add('Thumbprint',$cert.Thumbprint); 
                        $oReport.add('Usage',$cert.EnhancedKeyUsageList.FriendlyName) ; 
                        $oReport.add('isSelfSigned',$false) ; 
                        $oReport.add('Status',$status); 
                        $oReport.add('Valid',$false); 
                        if($cert.Issuer -eq $cert.Subject){
                            $oReport.SelfSigned = $true ;
                            write-host -foregroundcolor yellow "NOTE⚠️:Current certificate $($cert.SerialNumber) APPEARS TO BE *SELF-SIGNED* (SUBJECT==ISSUER)" ; 
                        } ; 
                        # Return the list of certificates in the chain (the root will be the last one)
                        $oReport.add('TrustChain',($chain.ChainElements | ForEach-Object {$_.Certificate})) ; 
                        write-verbose "Certificate Trust Chain`n$(($chain.ChainElements | ForEach-Object {$_.Certificate}|out-string).trim())" ; 
                        if ($status) {
                            $smsg = "Current certificate $($cert.SerialNumber) chain and revocation status is valid" ; 
                            if($CRLMode -eq 'NoCheck'){
                                $smsg += "`n(NOTE:-CRLMode:'NoCheck', no Certificate Revocation Check performed)" ; 
                            } ; 
                            write-host -foregroundcolor green $smsg;
                            $oReport.valid = $true ; 
                        } else {
                            Write-Warning "Current certificate $($cert.SerialNumber) chain is invalid due of the following errors:" ; 
                            $chain.ChainStatus | foreach-object{Write-Host $_.StatusInformation.trim() -ForegroundColor Red} ; 
                            $oReport.valid = $false ; 
                        } ; 
                        New-Object PSObject -Property $oReport | write-output ;
                    } ; 
                    #*------^ END Function _getstatus_ ^------
                } ;
                PROCESS {
                    foreach($item in $Certificate){
                        if ($item -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
                            $status = $chain.Build($item)   ; 
                            $report = _getstatus_ $status $chain $item   ; 
                            write-verbose "return report to pipeline" ; 
                            RETURN $report ;
                        } else {
                            if (!(Test-Path $item)) {
                                Write-Warning "Specified path is invalid" #return
                                $valid = $false ; 
                                RETURN $false ; 
                            } else {
                                if ((Resolve-Path $item).Provider.Name -ne "FileSystem") {
                                    Write-Warning "Spicifed path is not recognized as filesystem path. Try again" ; #return   ; 
                                    RETURN $false ; 
                                } else {
                                    $item = get-item $(Resolve-Path $item)   ; 
                                    switch -regex ($item.Extension) {
                                        "\.CER|\.DER|\.CRT" {$cert.Import($item.FullName)}  
                                        "\.PFX|\.P12" {
                                                if (!$Password) {$Password = Read-Host "Enter password for PFX file $($item)" -AsSecureString}
                                                        $cert.Import($item.FullName, $password, "UserKeySet")  ;  
                                        }  
                                        "\.P7B|\.SST" {
                                                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection ; 
                                                $cert.Import([System.IO.File]::ReadAllBytes($item.FullName))   ; 
                                        }  
                                        default {
                                            Write-Warning "Looks like your specified file is not a certificate file" #return
                                            RETURN $false ; 
                                        }  
                                    }  
                                    $cert | foreach-object{
                                            $status = $chain.Build($_)  
                                            $report = _getstatus_ $status $chain $_   ; 
                                            RETURN $report ;
                                    }  
                                    $cert.Reset()  
                                    $chain.Reset()  
                                } ; 
                            } ; 
                        }   ; 
                    } ;  # loop-E $Certificate
                } ;  # PROC-E
                END {} ; 
            } ; 
            #*------^ END Function test-CertificateTDO ^------
        }
        #endregion FUNCTIONS_INTERNAL ; #*======^ END FUNCTIONS_INTERNAL ^======

        TRY{            
            ($RDPSignExec = get-command rdpsign.exe -ea STOP).source ; 
            if($DiscoverCertificate){
                write-host "-DiscoverCertificate: Discovering 1st signing certificate in CU\My, LM\My order" ; 
                if($Cert = @(get-childitem cert:\currentuser\my -codesigning -ea 0 )[0]){
                    write-verbose "found matching -codesigning CU\My cert:`n$(($cert|out-string).trim())" ; 
                } elseif($Cert = @(get-childitem cert:\LocalMachine\my -codesigning -ea 0 )[0]){
                    write-verbose "found -codesigning  matching LM\My cert:`n$(($cert|out-string).trim())" ; 
                } else { 
                    throw "Unable to locate a Signing Cert in either`ncert:\currentuser\my -codesigning`nor cert:\LocalMachine\my -codesigning. ABORTING!" ; 
                } 
            }else{
                $Thumbprint = $Thumbprint -replace '\s','' ; 
                if($Cert = Get-ChildItem "Cert:\*\My\$($Thumbprint)" -ea STOP | 
                    Where-Object { $_.EnhancedKeyUsageList -match "Code Signing" } | 
                        sort pspath | select -last 1
                ){

                } ; 
            }
            if($Cert){
                $smsg = "Matched Certificate:" ; 
                $smsg += "`n`n$(($Cert | ft -a $prpCert|out-string).trim())" ; 
                write-verbose $smsg ; 
                $pltTCT=[ordered]@{
                    Certificate = $cert ;
                    CRLMode = 'NoCheck' ;
                    CRLFlag = 'EntireChain' ;
                } ;
                $smsg = "test-CertificateTDO w`n$(($pltTCT|out-string).trim())" ; 
                write-verbose $smsg ; 
                if($bRet = test-CertificateTDO @pltTCT |  ?{$_.valid -AND $_.Usage -contains 'Code Signing'} ){
                    write-verbose "Certificate...`n`n$(($bret.TrustChain | %{$_| ft -a subject,notbefore,notafter,issuer}|out-string).trim())`n`n... is valid for CodeSigning" ; 
                } else { 
                    $smsg = "Unable to locate a usable -codesigning certificate in either CU\My or LM\My! ABORTING!" ; 
                    write-warning $smsg ; 
                    throw $smsg ;
                    break ; 
                } ; 
            }else{
                $smsg = "UNABLE TO LOCATE CERT IN LOCAL OR CURRENTUSER\MY\$($THUMBPRINT)!" ; 
                write-warning $smsg ; 
                throw $smsg ; 
            }

            if($RegisterCertificate -AND $Thumbprint ){
                $smsg = "-RegisterCertificate & -Thumbprint :$($Thumbprint) : Configure HKCU required keys and values to register the signing certificate specified`nto be trusted to load signed .rdp files without prompts" ; 
                write-host -foregroundcolor yellow $smsg ;                 
                write-verbose "Create the key path $($RegPath)`nif it does not exist" ; 
                if (-not (Test-Path $RegPath)) {New-Item -Path $RegPath -Force -verbose } ; # | Out-Null
                New-ItemProperty  -Path $RegPath  -Name 'AllowSignedFiles'  -PropertyType DWord  -Value 1  -Force -verbose  ; # | Out-Null
                New-ItemProperty -Path $RegPath -Name 'TrustedCertThumbprints' -PropertyType String -Value '$($Thumbprint)' -Force  -verbose  ; # | Out-Null                
                $smsg += "Certificate`n`n$(($Cert | ft -a $prpCert|out-string).trim())" ;
                $smsg += "`nRegistered/Trusted at`n$($RegPath)`nwith:AllowSignedFiles:1`nand:TrustedCertThumbprints: $($Thumbprint) " ; 
                write-host -foregroundcolor green $smsg ; 
                return $smsg ; 
            } ; 
        } CATCH {
            $ErrTrapd=$Error[0] ;
            write-host -foregroundcolor gray "TargetCatch:} CATCH [$($ErrTrapd.Exception.GetType().FullName)] {"  ;
            $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;
            write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" ;
            return $false ; 
        } ;

        ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;

        if ($PSCmdlet.MyInvocation.ExpectingInput) {
            write-verbose "Data received from pipeline input: '$($InputObject)'" ; 
        } else {
            #write-verbose "Data received from parameter input: '$($InputObject)'" ; 
            write-verbose "(non-pipeline - param - input)" ; 
        } ; 
    } ;  # BEGIN-E
    PROCESS {
        $Error.Clear() ; 
        foreach ($item in $Path){
            TRY{
                Write-Verbose "Signing RDP file: $($item.fullname)" ; 
                #& rdpsign.exe /sha256 $Thumbprint $RdpFilePath ; 
                $ret = & $RDPSignExec /sha256 $Thumbprint $item.fullname; 
                if(gc $item.fullname | Where-Object { $_ -match "^signature" -or $_ -match "^signscope" }){
                    $smsg = $ret ; 
                    $smsg += "`n$($item.fullname): confirmed '^(signature|signscope) applied" ; 
                    write-verbose $smsg ; 
                    $item.fullname | write-output 
                }else{
                    $smsg = "$($item.fullname): MISSING '^(signature|signscope)!" ; 
                    write-warning $smsg ; 
                }
            } CATCH {$ErrTrapd=$Error[0] ;
                write-host -foregroundcolor gray "TargetCatch:} CATCH [$($ErrTrapd.Exception.GetType().FullName)] {"  ;
                $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;
                write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" ;
            } ;
        } ;  # loop-E
    }  # if-E PROC
    END{} ; 
} ; 
#endregion SET_RDPFILESIGNATURETDO ; #*------^ END set-RDPFileSignatureTDO ^------