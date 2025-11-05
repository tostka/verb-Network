# Import-CertificateTrustFileTDO

    #region IMPORT_CERTIFICATETRUSTFILETDO ; #*------v Import-CertificateTrustFileTDO v------
    Function Import-CertificateTrustFileTDO {
        <#
        .SYNOPSIS
        Import-CertificateTrustFileTDO - Imports Root or Intermediate/Sub-CA non-key CER/CRT type certs into the proper rgx hive. Dynamically determines cert type (CA/IA) and imports as appropriate)
        .NOTES
        Version     : 0.0.
        Author      : Todd Kadrie
        Website     : http://www.toddomation.com
        Twitter     : @tostka / http://twitter.com/tostka
        CreatedDate : 2025-
        FileName    : Import-CertificateTrustFileTDO.ps1
        License     : MIT License
        Copyright   : (c) 2025 Todd Kadrie
        Github      : https://github.com/tostka/verb-XXX
        Tags        : Powershell,Certificate,TrustChain,Import,Maintenance
        AddedCredit : REFERENCE
        AddedWebsite: URL
        AddedTwitter: URL
        REVISIONS
        * 4:28 PM 11/4/2025 debugging fixes, added coverage for psv2 lack of pki\import-certificate (via vnet\import-certCERLegacy())
        * 4:40 PM 8/11/2025 FIXED MISSING $certStringLenMax
        * 9:38 AM 7/24/2025 ren Import-CertificateTrustFile -> Import-CertificateTrustFileTDO, alias orig
        * 11:30 AM 7/11/2025 init
        .DESCRIPTION
        Import-CertificateTrustFileTDO - Imports Root or Intermediate/Sub-CA certs into the proper rgx hive
        
        Type discovery does the following:
        1) Checks for $basicConstraintsData.CertificateAuthority, which indicates a CA/IA cert
        2) Then compares Issuer & Subject on the cert: 
            - CA's are self-signed, and have matching Issuer & Subject values (and are installed into the Root hive)
            - IA's are signed by a CA, and have non-matching Issuer & Subject  (and are installed into the CA hive)
        
        .PARAMETER FilePath
        Path to target Chain of Trust file (or folder containing discoverable files)
        .PARAMETER .PARAMETER CertStoreLocation
        Destination Certificate Hive (CurrentUser|LocalMachine|Both)[-CertStoreLocation 'LocalMachine']
        .INPUTS
        None. Does not accepted piped input.
        .OUTPUTS
        System.Security.Cryptography.X509Certificates.X509Certificate
        .EXAMPLE
        PS> Import-CertificateTrustFileTDO -whatif -verbose
        EXSAMPLEOUTPUT
        Run with whatif & verbose
        .EXAMPLE
        PS> $pltLegCER=@{
        PS>     computername = $env:computername ;
        PS>     CertStoreLocation = 'LocalMachine' ;
        PS>     TargetCertStore = 'Root' ;
        PS>     Path = 'c:\path-to\cert.cer' ;
        PS>     whatIf = $($whatif)
        PS> } ;
        PS> $smsg += "`nusing Import-CertificateTrustFileTDO`n$(($pltLegCER|out-string).trim())" ;
        PS> write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" ;
        PS> $ret = Import-CertificateTrustFileTDO @pltLegCER ;
        Typical splatted call
        .EXAMPLE
        PS> $result = Import-CertificateTrustFileTDO -computername $env:computername -CertStoreLocation 'LocalMachine' -TargetCertStore Root -Path d:\cab\new_entrust_bundle 8-20241010-0931AM.crt -whatIf:$true ;
        PS> $result ; 

                SubjectName  : System.Security.Cryptography.X509Certificates.X500DistinguishedName
                NotAfter     : 12/31/2039 5:59:59 PM
                NotBefore    : 12/29/2014 11:07:33 AM
                Thumbprint   : 5x8x454x477x2x4539296x5x4xxx71xxx94xx5x5
                FriendlyName : xxxxxxxxxx-(12-31-2039)

        Typical call and fields returned
        .EXAMPLE
        PS> $result = Import-CertificateTrustFileTDO -FilePath "C:\Path\To\RootCA.cer"
        PS> $result ; 

                SubjectName  : System.Security.Cryptography.X509Certificates.X500DistinguishedName
                NotAfter     : 12/31/2039 5:59:59 PM
                NotBefore    : 12/29/2014 11:07:33 AM
                Thumbprint   : 5x8x454x477x2x4539296x5x4xxx71xxx94xx5x5
                FriendlyName : xxxxxxxxxx-(12-31-2039)

        Demo import of a Root CA cert 
        PS> $results = Import-CertificateTrustFileTDO -FilePath "C:\Path\To\IntermediateCA.crt"
        Demo import of an Intermediate/Sub-CA cert 
        .EXAMPLE
            PS> $results = Import-CertificateTrustFileTDO -FilepATH "C:\Scripts\certs" -VERBOSE 
            Call specifying a folder to be searched for known CA certs 
        .LINK
        https://github.com/tostka/verb-Network
        #>
        [CmdletBinding()]
        [Alias('Import-CertificateTrustFile')]
        Param (
            [Parameter(Mandatory = $false, HelpMessage = "Destination Certificate Hive (CurrentUser|LocalMachine|Both)[-CertStoreLocation 'LocalMachine']")]
                [ValidateNotNullOrEmpty()]
                [ValidateSet('CurrentUser', 'LocalMachine', 'Both')]
                [string]$CertStoreLocation = 'LocalMachine',
            [Parameter(Mandatory=$false,HelpMessage="Path to target Chain of Trust file (or folder containing discoverable files)")]
                [string]$FilePath
        ) ; 
        BEGIN{
            $certStringLenMax = 30 ; # MAX STRING TO DISPLAY IN ECHOS 4:40 PM 8/11/2025 MISSING
            if(-not (get-command -name import-Certificate)){
                TRY {Add-Type -AssemblyName System.Security }CATCH{} ; 
            } ; 
            if(test-path $FilePath -PathType Container -ea 0){
                # fed a folder it tries to discover for the domain in the folder
                # gci -include requires a wildcard on the path spec
                $FilePath = join-path -path $FilePath -childpath '*' ; 
                switch ($env:USERDOMAIN){
                    'TORO'{
                        #$TrustChainFile = (join-path -path $FilePath -childpath 'new_entrust_bundle 8-20241010-0931AM.crt')
                        #Default discoverable CA FileNames (array of files that discovery will attempt to locate, within specified FilePath)[-CAFileNames @('file1.crt','file2.cer')]")]
                        [string[]]$CAFileNames = @("DigiCert Global G2 TLS RSA SHA256 2020 CA1-IA-(*).crt","Entrust Certification Authority - L1K-IA-(*).crt","Entrust Root Certification Authority - G2-CA-(*).crt")      
                        #$TrustChainFile = (join-path -path $FilePath -childpath 'new_entrust_bundle 8-20241010-0931AM.crt')
                        $TrustChainFile = get-childitem -path $FilePath -include $CAFileNames ; 
                    }
                    'TORO-LAB'{
                        [string[]]$CAFileNames = @("DigiCert Global G2 TLS RSA SHA256 2020 CA1-IA-(*).crt","Entrust Certification Authority - L1K-IA-(*).crt","Entrust Root Certification Authority - G2-CA-(*).crt")      
                        #$TrustChainFile = (join-path -path $FilePath -childpath 'new_entrust_bundle 8-20241010-0931AM.crt')
                        $TrustChainFile = get-childitem -path $FilePath -include $CAFileNames ; 
                    }
                    DEFAULT{
                       $smsg = "UNCONFIGURED/UNRECOGNIZED `$ENV:USERDOMAIN: $($env:USERDOMAIN)`nSKIPPING CERT CHAIN OF TRUST IMPORT" ; 
                       if(gcm Write-MyError -ea 0){Write-MyError $smsg } else {
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Error}
                            else{ write-ERROR "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                        } ;
                    }
                }
                if(test-path $TrustChainFile -PathType Leaf){
                    $smsg = "Using $($env:USERDOMAIN) -discovered trust chain file(s):$($TrustChainFile)" ;
                    if(gcm Write-MyOutput -ea 0){Write-MyOutput $smsg } else {
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }
                        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                    } ;
                    $FilePath = $TrustChainFile ; 
                }
            } ; 
        }
        PROCESS{
            foreach($certFName in $FilePath){
                $certExt = [regex]::match($certFname,'(\.\w+)$').groups[0].value.tostring().tolower() ; 
                switch -Regex ($certExt) {
                    '\.(cer|crt|cert)' { # CA/IA certs
                        $smsg = "isolated `$COT CER|CRT: $($certFName )" ; 
                        if(gcm Write-MyVerbose -ea 0){Write-MyVerbose $smsg } else {
                            if($VerbosePreference -eq 'Continue'){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE }
                            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
                        } ;
                        $CotFilePath = $certFname         
                        $smsg = "resolved `$CotFilePath: $($CotFilePath )" ; 
                        if(gcm Write-MyVerbose -ea 0){Write-MyVerbose $smsg } else {
                            if($VerbosePreference -eq 'Continue'){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE }
                            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
                        } ;
                        if(test-path $CotFilePath -PathType Leaf){
                            $smsg = "confirmed $($CotFilePath) exists"
                            if(gcm Write-MyVerbose -ea 0){Write-MyVerbose $smsg } else {
                                if($VerbosePreference -eq 'Continue'){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE }
                                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
                            } ;
                            # root cert .cer install (un-encrypted)
                            $pltImpCert=@{
                                FilePath = $CotFilePath ;
                                CertStoreLocation= $null  ;
                                #whatif=$($whatif) ;
                            } ; 
                        } else{
                            $smsg = "Unable to locate local copy of $($CotFilePath) IN SPECIFIED -sourcepath $$($SourcePath)!" ; 
                            if(gcm Write-MyWarning -ea 0){Write-MyWarning $smsg } else {
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent}
                                else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            } ;
                            Break ; 
                        } ; 
                                        
                        $smsg = "Resolving 'cert' type to determine suitable TargetCertStore..." ; 
                        if(gcm Write-MyOutput -ea 0){Write-MyOutput $smsg } else {
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }
                            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                        #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                        } ;
                        $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($pltImpCert.FilePath) ;
                        $basicConstraints = $certificate.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Basic Constraints"} ; 
                        if($basicConstraints){
                            $basicConstraintsData = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]$basicConstraints ;
                            if ($basicConstraintsData.CertificateAuthority) {
                                $smsg = "$($pltImpCert.FilePath) certificate is a Certificate Authority (CA) (basicConstraintsData.CertificateAuthority populated)."
                                if(gcm Write-MyOutput -ea 0){Write-MyOutput $smsg } else {
                                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }
                                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                                } ;
                                # Root CA certs are self-signed: have matching Issuer & Subject
                                if ($certificate.Issuer -eq $certificate.Subject) {
                                    $smsg = "$($pltImpCert.FilePath) has matching Issuer & Subject: Self-signed: likely a Root CA" ; 
                                    if(gcm Write-MyOutput -ea 0){Write-MyOutput $smsg } else {
                                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }
                                        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                        #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                                    } ;
                                    $smsg = "ISSUER:`n$($certificate.Issuer.substring(0,[math]::min($certificate.Issuer.tostring().length,$certStringLenMax)))..." ;
                                    $smsg += "`n-EQ" ;
                                    $smsg += "`nSUBJECT:`n$($certificate.Subject.substring(0,[math]::min($certificate.Issuer.tostring().length,$certStringLenMax)))..."
                                    if(gcm Write-MyVerbose -ea 0){Write-MyVerbose $smsg } else {
                                        if($VerbosePreference -eq 'Continue'){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE }
                                        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
                                    } ;
                                    $pltImpCert.CertStoreLocation = "Cert:\$($CertStoreLocation)\Root\" 
                                } else {
                                    $smsg = "$($pltImpCert.FilePath) has NON-MATCHING Issuer & Subject: *NON*-Self-signed: likely an Intermediate or 'sub' CA" ;
                                    if(gcm Write-MyOutput -ea 0){Write-MyOutput $smsg } else {
                                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }
                                        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                        #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                                    } ;
                                    $smsg = "ISSUER:`n$($certificate.Issuer.substring(0,[math]::min($certificate.Issuer.tostring().length,$certStringLenMax)))..." ;
                                    $smsg += "`n-NE" ;
                                    $smsg += "`nSUBJECT:`n$($certificate.Subject.substring(0,[math]::min($certificate.Issuer.tostring().length,$certStringLenMax)))..."
                                    if(gcm Write-MyVerbose -ea 0){Write-MyVerbose $smsg } else {
                                        if($VerbosePreference -eq 'Continue'){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE }
                                        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
                                    } ;
                                    $pltImpCert.CertStoreLocation = "Cert:\$($CertStoreLocation)\CA\" 
                                } ;                          
                            } else {
                                $smsg = "$($pltImpCert.FilePath) is *not* a Certificate Authority certificate (has *no* basicConstraintsData.CertificateAuthority populated)."
                                if(gcm Write-MyVerbose -ea 0){Write-MyVerbose $smsg } else {
                                    if($VerbosePreference -eq 'Continue'){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE }
                                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
                                } ;
                            }
                        } else {
                            $smsg = "$($pltImpCert.FilePath) has *no* basicConstraintsData populated: Non-CA, Standard certificate (un-encrypted, in cert format)."
                            if(gcm Write-MyVerbose -ea 0){Write-MyVerbose $smsg } else {
                                if($VerbosePreference -eq 'Continue'){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE }
                                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
                            } ;
                            $pltImpCert.CertStoreLocation = "Cert:\$($CertStoreLocation)\My\" 
                        } ; 
                        
                        if((get-command -name import-Certificate -ea 0)){
                            $smsg = "Import-Certificate w`n$(($pltImpCert|out-string).trim())" ; 
                            if(gcm Write-MyOutput -ea 0){Write-MyOutput $smsg } else {
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                            } ;
                            #Import-Certificate @pltImpCert; 
                            # Outputs  X509Certificate2[]  The output is an array of X509Certificate2[] objects.
                            <#
                                -FilePath: Specifies the path to a certificate file to be imported. Acceptable formats 
                                include .sst, .p7b, and .cert files. If the file contains multiple 
                                certificates, then each certificate will be imported to the destination store. 
                                The file must be in .sst format to import multiple certificates; otherwise, 
                                only the first certificate in the file will be imported. 
                            #>             
                            $results = Import-Certificate @pltImpCert -Verbose:($PSBoundParameters['Verbose'] -eq $true)              
                            if(-not $whatif){
                                #$results | select SubjectName,not*,thumb*,friend* | write-output ;
                                $smsg = "Results`n$(($results | select SubjectName,not*,thumb*,friend*|out-string).trim())" ; 
                                if(gcm Write-MyOutput -ea 0){Write-MyOutput $smsg } else {
                                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }
                                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                                } ;
                                # return the x509cert objects, not the summary fields, we need it for followup verific
                                $results | write-output ; 
                            } elseif(-not $whatif){
                                $false | write-output ; 
                            }else {
                                $smsg = "-whatif:$($whatif): skipped import/confirmation" ; 
                                if(gcm Write-MyOutput -ea 0){Write-MyOutput $smsg } else {
                                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }
                                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                                } ;
                            } ;
                        }else{
                            <#$pltImpCert=@{
                                FilePath = $CotFilePath ;
                                CertStoreLocation= $null  ;
                                #whatif=$($whatif) ;
                            } ; 
                            #>
                            # $CertStoreLocation: LocalMachine
                            # $pltImpCert.CertStoreLocation = "Cert:\$($CertStoreLocation)\CA\" 
                            $pltLegCER=@{
                                computername = $env:computername ;
                                CertStoreLocation = $CertStoreLocation ;
                                TargetCertStore = ($pltImpCert.CertStoreLocation.split('\') | ?{$_})[-1] ;
                                Path = $pltImpCert.FilePath ;
                                #whatIf = $($whatif)
                            } ;
                            $smsg += "`nusing import-CertCERLegacy`n$(($pltLegCER|out-string).trim())`n(PS$($host.version.major): missing import-certificate cmdlet)" ;
                            if(gcm Write-MyOutput -ea 0){Write-MyOutput $smsg } else {
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H1 } else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                            } ;
                            $results = import-CertCERLegacy @pltLegCER ;                            
                            if(-not $whatif){
                                #$results | select SubjectName,not*,thumb*,friend* | write-output ;
                                if($results.Thumbprint -AND $results.subject -eq $null){
                                    # re-lookup on the thumbprint
                                    $results = get-childitem -path "cert:\$($CertStoreLocation)\$($TargetCertStore)\$($results.Thumbprint)"
                                } ; 
                                $prpResults = 'Issuer','Subject','NotBefore','NotAfter','HasPrivateKey','Thumbprint','psPath' ; 
                                #$smsg = "Results`n$(($results | select SubjectName,not*,thumb*,friend*|out-string).trim())" ; 
                                $smsg = "Results`n$(($results | fl $prpResults |out-string).trim())" ; 
                                if(gcm Write-MyOutput -ea 0){Write-MyOutput $smsg } else {
                                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }
                                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                                } ;
                                # return the x509cert objects, not the summary fields, we need it for followup verific
                                $results | write-output ; 
                            } elseif(-not $whatif){
                                $false | write-output ; 
                            }else {
                                $smsg = "-whatif:$($whatif): skipped import/confirmation" ; 
                                if(gcm Write-MyOutput -ea 0){Write-MyOutput $smsg } else {
                                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info }
                                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                                } ;
                            } ;
                        } ; 
                    }
                    default {
                        $smsg = "$($certFName) is not a crt|cer file (and pfx should be imported via import-ExchangeCertificate" ; 
                        if(gcm Write-MyWarning -ea 0){Write-MyWarning $smsg } else {
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent}
                            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                        } ;
                    }
                }  # swtch-E
             } ; # loop-E
         } ;  # PROC-E
    }
    #endregion IMPORT_CERTIFICATETRUSTFILETDO ; #*------^ END Import-CertificateTrustFileTDO ^------