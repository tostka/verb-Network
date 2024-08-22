# test-CertificateTDO

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
    Github      : https://github.com/tostka/verb-IO
    Tags        : Powershell,FileSystem,File,Lock
    AddedCredit : Todd Kadrie
    AddedWebsite: http://www.toddomation.com
    AddedTwitter: @tostka / http://twitter.com/tostka
    REVISIONS
    * 2:29 PM 8/22/2024 fixed process looping (lacked foreach); added to verb-Network; retoololed to return a testable summary report object (summarizes Subject,Issuer,Not* dates,thumbprint,Usage (FriendlyName),isSelfSigned,Status,isValid,and the full TrustChain); 
        added param valid on [ValidateSet, CRLMode, CRLFlag, VerificationFlags ; updated CBH; added support for .p12 files (OpenSSL pfx variant ext), rewrite to return a status object
    * 9:34 AM 8/22/2024 Vadims Podans posted poshcode.org copy from web.archive.org, grabbed 11/2016 (orig dates from 2009, undated beyond copyright line)
    .DESCRIPTION
    test-CertificateTDO -  Tests specified certificate for certificate chain and revocation status for each certificate in chain
        exluding Root certificates
    
        Based on Vadim Podan's 2009-era Test-Certificate function, expanded/reworked to return a testable summary report object (summarizes Subject,Issuer,NotBefore|After dates,thumbprint,Usage(FriendlyName),isSelfSigned,Status,isValid


        ## Note:Powershell v4+ includes a native Test-Certificate cmdlet that returns a boolean, and supports -DNSName to test a given fqdn against the CN/SANs list on the certificate. 
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
    None. Does not accepted piped input.
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
    .LINK
    https://web.archive.org/web/20160715110022/poshcode.org/1633
    .LINK
    https://github.com/tostka/verb-io
    #>
    #requires -Version 2.0
    [CmdletBinding()]
    [Alias('rol','restart-Outlook')]
    PARAM(
        #[Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,HelpMessage="Path to file[-path 'c:\pathto\file.txt']")]
        #[Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0,HelpMessage="Specifies the certificate to test certificate chain. This parameter may accept X509Certificate, X509Certificate2 objects or physical file path. this paramter accept pipeline input)"]
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
                return $report ;
            } else {
                if (!(Test-Path $item)) {
                    Write-Warning "Specified path is invalid" #return
                    $valid = $false ; 
                    return $false ; 
                } else {
                    if ((Resolve-Path $item).Provider.Name -ne "FileSystem") {
                        Write-Warning "Spicifed path is not recognized as filesystem path. Try again" ; #return   ; 
                        return $false ; 
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
                                return $false ; 
                            }  
                        }  
                        $cert | foreach-object{
                                $status = $chain.Build($_)  
                                $report = _getstatus_ $status $chain $_   ; 
                                return $report ;
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
