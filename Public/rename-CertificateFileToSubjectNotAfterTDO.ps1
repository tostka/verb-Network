# rename-CertificateFileToSubjectNotAfterTDO.ps1

#region RENAME_CERTIFICATEFILETOSUBJECTNOTAFTERTDO ; #*------v rename-CertificateFileToSubjectNotAfterTDO v------
function rename-CertificateFileToSubjectNotAfterTDO {
    <#
    .SYNOPSIS
    rename-CertificateFileToSubjectNotAfterTDO - Rename specified Certificate file for the contained certificates SubjectName, and NotAfter date (e.g. '[subject]-[CA|IA]-([notafter]).ext')
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2026-
    FileName    : rename-CertificateFileToSubjectNotAfterTDO.ps1
    License     : MIT License
    Copyright   : (c) 2026 Todd Kadrie
    Github      : https://github.com/tostka/verb-XXX
    Tags        : Powershell
    AddedCredit : REFERENCE
    AddedWebsite: URL
    AddedTwitter: URL
    REVISIONS
    * 3:42 PM 10/14/2026 init
    .DESCRIPTION
    rename-CertificateFileToSubjectNotAfterTDO - Rename specified Certificate file for the contained certificates SubjectName, and NotAfter date (e.g. '[subject]-[CA|IA]-([notafter]).ext')

    ## Ref: 
    Cert file types:
    A .key file is an RSA public/private key file (PEM formatted). Protect these! 
    A ".pfx" file is a PKCS#12 archive: a bag which can contain a lot of objects with optional password protection; but, usually, a PKCS#12 archive contains a certificate (possibly with its assorted set of CA certificates) and the corresponding private key.
    A ".cert" (or ".cer" or ".crt") file usually contains a single certificate, alone and without any wrapping (no private key, no password protection, just the certificate).
    A .p7b file is just the certificate in PKCS7 package. The private  .key file is needed to use it.
    A .p12 file is PKCS12 Package containing CRT and Private key.
    A .pem file is a PEM Certificate with private key.
    A .csr file is a certificate signing request.

    A .pem, is "generally" an un-encrypted object (I think), seems to be used on *nix for unencrypted certs, even csrs (xxx.csr.pem). 

    Certificates are public data; everybody has them. But client authentication is about having the client do something that only that client can do; so the client must know something which is not public, and that's the private key. Thus, the client must have a private key along with its certificate; if the key was generated out of the client browser, then the expected setup is to import it into the client along with the certificate. Therefore, a .pfx file

    No you do not distribute the .pfx file because that is the file containing the private key. You can extract and distribute the certificate (.cer .crt, which is public) from the .pfx file
    You should never disclose your private key. These keys are contained in .pfx and .pvk files.
    Generally, you only exchange your certificate (.cer) and the certificates of any intermediate issuers (i.e., the certificates of all of your CAs, except the root CA) with other parties.

    Protect these files: .key , .p12, .pfx & .pvk


    .PARAMETER Path
    Path to Certificate files to be renamed[-Path c:\pathto\file.xml]
    .PARAMETER Credential
    Use specific Credentials (defaults to Tenant-defined SvcAccount)[-Credentials [credential object]]
    .PARAMETER whatIf
    Whatif switch  [-whatIf]
    .INPUTS
    system.io.fileinfo[] Accepts piped input.
    .OUTPUTS
    System.String emits revised file name to pipelineeName is returned, to use here]
    .EXAMPLE
    PS> rename-CertificateFileToSubjectNotAfterTDO -path 'c:\pathto\file.crt' -whatif -verbose
    Run with whatif & verbose
    .EXAMPLE
    PS> rename-CertificateFileToSubjectNotAfterTDO -path @('C:\usr\work\exch\cert\torolab_com_1631061291-20261013-0118PM\torolab_com_1631061291\DigiCertCA.crt','C:\usr\work\exch\cert\torolab_com_1631061291-20261013-0118PM\torolab_com_1631061291\torolab_com.crt') -whatif -verbose ;
    .EXAMPLE
    PS> $rgxCertExts = "\.(crt|cer|ca-bundle|p7b|p7c|p7s|pem|key|keystore|jks|p12|pfx|pkcs12)$" ; 
    PS> $updatedfiles = gci C:\usr\work\exch\cert\torolab_com_1631061291-20261013-0118PM\torolab_com_1631061291\* | 
    PS>     ?{$_.extension -match $rgxCertExts} | select -expand fullname | 
    PS>     rename-CertificateFileToSubjectNotAfterTDO -whatif -verbose  ; 
    PS> $updatedfiles | gci ; 
    .LINK
    https://github.com/tostka/verb-XXX
    .LINK
    https://github.com/tostka/powershellbb/
    #>
    [CmdletBinding()]
    PARAM(
        #[Parameter(ParameterSetName='Certificate',Mandatory=$True,ValueFromPipeline=$true,HelpMessage="X509 Certificate object to be tested[-Certificate `$certObj]")]
        #    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(ParameterSetName='File',Mandatory = $true,Position = 0,ValueFromPipeline = $True,HelpMessage = 'Path to Certificate files to be renamed[-Path c:\pathto\file.xml]')]
            [AllowNull()]
            [AllowEmptyCollection()]
            [ValidateScript({Test-Path $_})]
            [system.io.fileinfo[]]$Path,
        [Parameter(Mandatory = $false, HelpMessage = "Optional Credential object, from which to obtain PFX password (only password is used; prompts interactively if required and not-specified)[-Credential [credential object]]")]
            [System.Management.Automation.PSCredential]$Credential,
        [Parameter(HelpMessage="Whatif switch [-whatIf]")]
            [switch]$whatIf
    )
    BEGIN{
        #$Path = @('C:\usr\work\exch\cert\torolab_com_1631061291-20261013-0118PM\torolab_com_1631061291\DigiCertCA.crt') ;
        #write-verbose "import crt/cer into x509 object" ;
        $RootCAMsg = "-> Root certificate: installs to`ncert:\CurrentUser|LocalMachine\CA (AKA 'Intermediate Certification Authorities')";
        $SubCAMsg = "-> SubCA/IA certificate: installs to `ncert:\CurrentUser|LocalMachine\Root (AKA 'Trusted Root Certification Authorities')";
        $LeafCertMsg = "-> EndEntity/Leaf certificate: installs to `ncert:\CurrentUser|LocalMachine\My (AKA 'Certificates')";
    } ;
    PROCESS{
        $prcd = 0 ; $ttl = $Path |  measure | select -expand count ; 
        foreach($thisCertFile in $Path){
            $prcd++ ; 
            $sBnrS="`n#*------v PROCESSING ($($prcd)/$($ttl) $([math]::round($prcd/$ttl * 100))%): $($thisCertFile.fullname) v------" ;
            write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($sBnrS)" ;
            TRY{
                switch -regex ($thisCertFile.extension){
                    '.(pfx|p12|pkcs12)'{
                        # Define your file path and password
                        #$pfxPath = "C:\path\to\your\certificate.pfx"
                        #$password = "YourPfxPassword"
                        write-host -foregroundcolor yellow "ENTER PFX PW: (use 'dummy' for User Name)" ;
                        if(-not $Credential){
                            $Credential=(Get-Credential -credential dummy) ;     ; # Password = $Credential.password;
                        } ; 
                        # Create an empty X509Certificate2 object
                        $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                        # Load the PFX file into the object
                        $Certificate.Import($thiscertfile.fullname, $Credential.password, "Exportable,PersistKeySet")
                        # View the Subject property
                        #$Certificate.Subject
                    }
                    '.(crt|cer|pem|der|p7b|p7c|cert)'{
                        $Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($thisCertFile.fullname) ;
                    }
                    default{
                        throw "Unrecognized extension: $($thisCertFile.extension)" ;
                    }
                }
                [array]$newName = @() ;
                [string]$hivename = $null ;
                $newName += @(($Certificate.subject -split ',\s' -replace 'CN=','')[0]) ;
                $rmsg = "`n($thisCertFile.FullName) ->`n$(($Certificate | fl Subject,Issuer,Thumbprint,notbefore,notafter|out-string).trim())" ;
                if($sanExt=$Certificate.Extensions | Where-Object {$_.Oid.FriendlyName -match "subject alternative name"}){
                    $sanObjs = new-object -ComObject X509Enrollment.CX509ExtensionAlternativeNames ;  $altNamesStr=[System.Convert]::ToBase64String($sanExt.RawData) ; 
                    $sanObjs.InitializeDecode(1, $altNamesStr) ; 
                    $rmsg += "`nSANS:`n$(($sanObjs.AlternativeNames | select -expand strValue | sort |out-string).trim())" ; 
                    #Foreach ($SAN in $sanObjs.AlternativeNames){$SAN.strValue} ;                
                } ; 
                $bc = $Certificate.Extensions | Where-Object {
                    $_ -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]
                } ;

                if ($bc -and $bc.CertificateAuthority) {
                    if ($Certificate.Subject -eq $Certificate.Issuer) {
                        #'RootCA' | write-output  ;
                        $smsg = $RootCAMsg + $rmsg ;
                        $newName += @('CA') ;
                        $hivename = 'Root' ;
                    }else {
                        #'IntermediateCA'  | write-output  ;
                        $smsg = $SubCAMsg + $rmsg ;
                        $newName += @('IA') ;
                        $hivename = 'CA' ;
                    }
                }else {
                    #'EndEntity' | write-output  ;
                    $smsg = $LeafCertMsg + $rmsg ;
                    # don't add delimited role to non-CA certs
                    $hivename = 'My' ;
                }
                write-host $smsg ;
                $newName += @("($(get-date $Certificate.notafter -format 'yyyyMMdd-HHmmtt'))") ;
                $newName = ($newName -join '-').Trim() ;
                #$newName = $newName -replace '[\r\n]+'
                # strip all non-alphanum or -/. from the name
                $newname = ($newname.toCharArray() | ?{$_ -match '[A-Za-z0-9\s\-\.\(\)]'}) -join '' ;
                #$newName += $thisCertFile.extension # '.crt' ;
                WRITE-VERBOSE "`$newname: '$($newname)'" ;
                $pltRNI = [ordered]@{
                    path = $thisCertFile.FullName ;
                    newname = "$($newName)$($thisCertFile.extension)" ;
                    ErrorAction = 'STOP';
                    Verbose = $($VerbosePreference -eq 'Continue') ;
                    whatif = $($whatif) ;
                }
                write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):rename-item w`n$(($pltRNI|out-string).trim())" ;
                #write-verbose "`$newName: `n$(($newName|out-string).trim())" ;
                #write-host -foregroundcolor yellow "Renaming COT .crt file:`n$($thisCertFile.FullName)`n->to: $($pltRNI.newname):" ;
                #gci $thisCertFile.FullName | rename-item -newname $newName -verbose -ErrorAction STOP -whatif:$($whatif) ;
                rename-item @pltRNI
                write-host -foregroundcolor yellow "(Emitting Updated filename to pipeline)" ; 
                $pltRNI.newname| write-output 
            } CATCH {$ErrTrapd=$Error[0] ;   write-host -foregroundcolor gray "TargetCatch:} CATCH [$($ErrTrapd.Exception.GetType().FullName)] {"  ;   $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;   write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" ; } ;
            write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;
        } ; # loop-E
    }
} ; 
#endregion RENAME_CERTIFICATEFILETOSUBJECTNOTAFTERTDO ; #*------^ END rename-CertificateFileToSubjectNotAfterTDO ^------