# import-CertCERLegacy
    
    #region IMPORT_CERTCERLEGACY ; #*------v import-CertCERLegacy v------
    if (-not (get-command import-CertCERLegacy -ea 0)) {
        function import-CertCERLegacy {
            <#
            .SYNOPSIS
            import-CertCERLegacy.ps1 - Imports Cert/CER (non-key CA) files into specified Store & location (fall back use for when PKI\Import-Certificate() is not available - Psv2 etc)
            .NOTES
            Version     : 0.0.
            Author      : Todd Kadrie
            Website     : http://www.toddomation.com
            Twitter     : @tostka / http://twitter.com/tostka
            CreatedDate : 2025-
            FileName    : import-CertCERLegacy.ps1
            License     : MIT License
            Copyright   : (c) 2025 Todd Kadrie
            Github      : https://github.com/tostka/verb-XXX
            Tags        : Powershell,Certificate,TrustChain,Import,Maintenance
            AddedCredit : REFERENCE
            AddedWebsite: URL
            AddedTwitter: URL
            REVISIONS
            * 4:18 PM 11/4/2025 debugged to function - wasn't working in lab, had to recode the import to function, revised return
            * 11:30 AM 7/11/2025 init
            .DESCRIPTION
            import-CertCERLegacy.ps1 - Imports Cert/CER (non-key CA) files into specified Store & location (fall back use for when PKI\Import-Certificate() is not available - Psv2 etc)
            .PARAMETER Computername
            Target Computer name[-Computername 'servername']
            .PARAMETER CertStoreLocation
            Destination Certificate Hive (CurrentUser|LocalMachine|Both)[-CertStoreLocation 'LocalMachine']
            .PARAMETER TargetCertStore
            Destination Certificate Store name ('My':Certificates|'CA':IA's|'Root':Root CAs|'REQUEST':Pending CSRs)[-TargetCertStore 'CA']
            .PARAMETER Path
            Path to a target Certificate .cer/.crt file [-Path \\machine\share\]
            .PARAMETER whatIf
            Whatif Flag  [-whatIf]")]
            .INPUTS
            None. Does not accepted piped input.
            .OUTPUTS
            System.Security.Cryptography.X509Certificates.X509Certificate
            .EXAMPLE
            PS> $pltLegCER=@{
            PS>     computername = $env:computername ;
            PS>     CertStoreLocation = 'LocalMachine' ;
            PS>     TargetCertStore = 'Root' ;
            PS>     Path = 'c:\path-to\cert.cer' ;
            PS>     whatIf = $($whatif)
            PS> } ;
            PS> $smsg += "`nusing import-CertCERLegacy`n$(($pltLegCER|out-string).trim())" ;
            PS> write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" ;
            PS> $ret = import-CertCERLegacy @pltLegCER ;
            Typical splatted call to import a Root CA cert (vs IA, which would go to the CA TargetCertStore
            .EXAMPLE
            PS> $result = import-CertCERLegacy -computername $env:computername -CertStoreLocation 'LocalMachine' -TargetCertStore Root -Path d:\cab\new_entrust_bundle 8-20241010-0931AM.crt -whatIf:$true ;
            Parameter call            
            .LINK
            https://github.com/tostka/verb-Network
            #>
            [CmdletBinding()]
            PARAM(
                [Parameter(Mandatory = $true, HelpMessage = "Target Computer name[-Computername 'servername']")]
                    [ValidateNotNullOrEmpty()]
                    [string]$Computername,
                [Parameter(Mandatory = $true, HelpMessage = "Destination Certificate Hive (CurrentUser|LocalMachine|Both)[-CertStoreLocation 'LocalMachine']")]
                    [ValidateSet('CurrentUser', 'LocalMachine', 'Both')]
                    [string]$CertStoreLocation,
                [Parameter(Mandatory = $true, HelpMessage = "Destination Certificate Store name ('My':Certificates|'CA':IA's|'Root':Root CAs|'REQUEST':Pending CSRs)[-TargetCertStore 'CA']")]
                    [ValidateSet('My', 'CA', 'Root', 'REQUEST')]
                    [string]$TargetCertStore = 'CA',
                [Parameter(Mandatory = $true, HelpMessage = "Path to a target Certificate .cer/.crt file [-Path \\machine\share\]")]
                    [ValidateScript({ Test-Path $_ })]
                    #[system.io.fileinfo[]] # psv2 doesn't like use of fileinfo (blank fullname prop), better to use string, and gci result
                    [string]$Path,
                [Parameter(HelpMessage = "Whatif Flag  [-whatIf]")]
                    [switch] $whatIf
            ) ;
            $prpCert = 'Issuer','Subject','NotBefore','NotAfter','HasPrivateKey','Thumbprint',@{Name='PsPath';Expression={$_.pspath.replace('Microsoft.PowerShell.Security\Certificate::','') }} 
            # no return the entire 509 cert object, match the return of an import-certificate command
            TRY{
                Add-Type -AssemblyName System.Security ;
                #$CertStore = New-Object System.Security.Cryptography.X509Certificates.X509Store -ArgumentList  "\\$($Computername)\$($TargetCertStore)", $CertStoreLocation ;                
                $CertStore = New-Object System.Security.Cryptography.X509Certificates.X509Store($TargetCertStore, $CertStoreLocation)
                $CertStore.Open('ReadWrite');
                #$smsg = "Once it's open ReadWrite, you can dump certs with: $certstore.certificates" ;
                #if(gcm Write-MyVerbose -ea 0){Write-MyVerbose $smsg } else {
                #    if($VerbosePreference -eq 'Continue'){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE }
                #    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
                #} ;
                # tried to use [fileinfo], but fullname is blank, so do remedial gci to get there.
                if($rvPath = get-childitem -path $Path -ea STOP){
                    #$cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate($Path.FullName) ;
                    $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate($rvPath.FullName) ;
                } ; 
                if (-not $whatif) {
                    $CertStore.Add($cert) ;
                } ;
                $CertStore.Close() ;
                $smsg = "Checking for installed Cert:" ;
                if(gcm Write-MyVerbose -ea 0){Write-MyVerbose $smsg } else {
                    if($VerbosePreference -eq 'Continue'){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE }
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
                } ;
                # get-childitem -path "cert:\$($CertStoreLocation)\$($TargetCertStore)\$($results.Thumbprint)"
                $result = get-childitem -path "cert:\$($CertStoreLocation)\$($TargetCertStore)\" | ?{ $_.subject -eq $cert.subject }
                #if (-not $whatif -AND (Get-ChildItem -Path cert: -Recurse | ? { $_.subject -eq $cert.subject })) {
                #if (-not $whatif -AND ($hitCert = Get-ChildItem -Path cert: -Recurse | ? { $_.subject -eq $cert.subject })) {
                    #$hitCert | select $prpCert | write-output ;
                if($result){
                    $result | write-output ; 
                } elseif (-not $whatif) {
                    $smsg = "UNABLE TO LOCATE ADDD CERT!"
                    if(gcm Write-MyWarning -ea 0){Write-MyWarning $smsg } else {
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN} else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    } ;
                    $false | write-output ;
                } else {
                    $smsg = "-whatif:$($whatif): skipped import/confirmation" ;                    
                    if(gcm Write-MyOutput -ea 0){Write-MyOutput $smsg } else {
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H1 } else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                        #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                    } ;
                } ;                
            } CATCH {
                $ErrTrapd=$Error[0] ;
                $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;
                if(gcm Write-MyWarning -ea 0){Write-MyWarning $smsg } else {
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN} else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                } ;
            } ; 
        } ;
    }
    #endregion IMPORT_CERTCERLEGACY ; #*------^ END import-CertCERLegacy ^------