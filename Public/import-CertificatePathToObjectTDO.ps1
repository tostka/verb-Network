# import-CertificatePathToObjectTDO.ps1

#region IMPORT_CERTIFICATEPATHTOOBJECTTDO ; #*------v import-CertificatePathToObjectTDO v------
function import-CertificatePathToObjectTDO {
    <#
    .SYNOPSIS
    import-CertificatePathToObjectTDO - Imports a certificate  path (filesystem or cert: certificate-path) into an x509 object
    .NOTES
    Version     : 0.0.1
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2026-10-15
    FileName    : import-CertificatePathToObjectTDO.ps1
    License     : MIT License
    Copyright   : (c) 2026 Todd Kadrie
    Github      : https://github.com/tostka/verb-network
    Tags        : Powershell,certificate,management
    AddedCredit : REFERENCE
    AddedWebsite: URL
    AddedTwitter: URL
    REVISIONS
    * 10:35 AM 10/15/2026 ren import-CertificateFileToObjectTDO -> import-CertificatePathToObjectTDO, more descriptive; init
    .DESCRIPTION
    import-CertificatePathToObjectTDO - Imports a certificate  path (filesystem or cert: certificate-path) into an x509 object

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
    Path to Certificate files to be imported (filesystem or certificate-path)[-Path c:\pathto\file.crt]
    .PARAMETER Credential
    Use specific Credentials (defaults to Tenant-defined SvcAccount)[-Credentials [credential object]]
    .INPUTS
    system.io.fileinfo[] Accepts piped input.
    .OUTPUTS
    [System.Security.Cryptography.X509Certificates.X509Certificate2] emits imported Certificate object to pipelineeName
    .EXAMPLE
    PS> import-CertificatePathToObjectTDO -path 'c:\pathto\file.crt' -whatif -verbose
    Run with whatif & verbose
    .EXAMPLE
    PS> $certobj = import-CertificatePathToObjectTDO -path 'C:\usr\work\exch\cert\torolab_com_1631061291-20261013-0118PM\torolab_com_1631061291\DigiCert Global G2 TLS RSA SHA256 2020 CA1-IA-(20310329-1859PM).crt' ;
    .EXAMPLE    
    PS> $certobj = import-CertificatePathToObjectTDO -path cert:\currentUser\my\5F8F454A477F2C4539296F5E4EEE71FBB94CF5E5 ; 
    Demo importing certificate from hive into an object (same effect as running gci on the path)
    .LINK
    https://github.com/tostka/verb-XXX
    .LINK
    https://github.com/tostka/powershellbb/
    #>
    [CmdletBinding()]
    PARAM(
        #[Parameter(ParameterSetName='Certificate',Mandatory=$True,ValueFromPipeline=$true,HelpMessage="X509 Certificate object to be tested[-Certificate `$certObj]")]
        #    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(ParameterSetName='File',Mandatory = $true,Position = 0,ValueFromPipeline = $True,HelpMessage = 'Path to Certificate files to be imported (filesystem or cert:certificate-path)[-Path c:\pathto\file.crt]]')]
            [AllowNull()]
            [AllowEmptyCollection()]
            [ValidateScript({Test-Path $_})]
            #[system.io.fileinfo[]]
            [string[]]$Path,
        [Parameter(Mandatory = $false, HelpMessage = "Optional Credential object, from which to obtain PFX password (only password is used; prompts interactively if required and not-specified)[-Credential [credential object]]")]
            [System.Management.Automation.PSCredential]$Credential
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
            $sBnrS="`n#*------v PROCESSING ($($prcd)/$($ttl) $([math]::round($prcd/$ttl * 100))%): $($thisCertFile) v------" ;
            write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($sBnrS)" ;
            TRY{
                $rvPath = Get-Item -LiteralPath $Path -ErrorAction Stop
            } CATCH {$ErrTrapd=$Error[0] ;
                write-host -foregroundcolor gray "TargetCatch:} CATCH [$($ErrTrapd.Exception.GetType().FullName)] {"  ;
                $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;
                write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" ;
            } ;
            $provider = $rvPath.PSProvider.Name ; 
            switch -regex ($provider){
                'FileSystem'{
                    switch -regex ($rvPath.extension){
                        '.(pfx|p12|pkcs12)'{
                            <# Password is optional, not a hard requirement
                            Unfortunately, there's no reliable "password required?" flag exposed in a PKCS#12/PFX file that you can query beforehand.
                            A PFX can be:
                            Unencrypted (empty password)
                            Encrypted with a non-empty password
                            Protected using MAC integrity only
                            Created by different toolchains with slightly different interpretations of "no password" vs. "empty password"
                            The .NET APIs generally determine this only when they attempt to import/decode the PFX.
                            #>
                                
                            # Define your file path and password
                            #$pfxPath = "C:\path\to\your\certificate.pfx"
                            #$password = "YourPfxPassword"                                
                            # Create an empty X509Certificate2 object
                            $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                            # attempt null pw open, fail through to propmted/credential
                            if(-not $Credential){
                                TRY {
                                    [System.Security.Cryptography.X509Certificates.X509Certificate2\]::new($PfxPath,'')
                                }CATCH [System.Security.Cryptography.CryptographicException] {
                                    write-host -foregroundcolor yellow "ENTER $($rvPath.extension.ToUpper()) Password: (use 'dummy' for User Name)" ;
                                    if(-not $Credential){
                                        $Credential=(Get-Credential -credential dummy) ;     ; # Password = $Credential.password;
                                    } ; 
                                    # Load the PFX file into the object
                                    $Certificate.Import($thisCertFile, $Credential.password, "Exportable,PersistKeySet")
                                }
                            } else{
                                TRY{
                                    $Certificate.Import($thisCertFile, $Credential.password, "Exportable,PersistKeySet")
                                } CATCH {
                                    $ErrTrapd=$Error[0] ;
                                    write-host -foregroundcolor gray "TargetCatch:} CATCH [$($ErrTrapd.Exception.GetType().FullName)] {"  ;
                                    $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;
                                    write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" ;
                                } ;
                            };                                 
                        }
                        '.(crt|cer|pem|der|p7b|p7c|cert)'{
                            TRY{
                                $Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($thisCertFile) ;
                            } CATCH {$ErrTrapd=$Error[0] ;
                                write-host -foregroundcolor gray "TargetCatch:} CATCH [$($ErrTrapd.Exception.GetType().FullName)] {"  ;
                                $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;
                                write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" ;
                            } ;
                        }
                        default{
                            throw "Unrecognized extension: $($thisCertFile.extension)" ;
                            CONTINUE
                        }
                    }
                }
                'Certificate|certificate-path'{
                    TRY{
                        write-output "Object is already a certificate: Passthru" ; 
                        get-item $path -ErrorAction STOP | write-output ; 
                    } CATCH {$ErrTrapd=$Error[0] ;
                        write-host -foregroundcolor gray "TargetCatch:} CATCH [$($ErrTrapd.Exception.GetType().FullName)] {"  ;
                        $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;
                        write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" ;
                    } ;
                }
                default{
                    throw "Unrecognized -Path type!" ; 
                    return $false ; 
                }
            } ; 
            [string]$hivename = $null ;            
            $rmsg = "`n($thisCertFile) ->`n$(($Certificate | fl Subject,Issuer,Thumbprint,notbefore,notafter|out-string).trim())" ;
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
                    $hivename = 'Root' ;
                }else {
                    #'IntermediateCA'  | write-output  ;
                    $smsg = $SubCAMsg + $rmsg ;                    
                    $hivename = 'CA' ;
                }
            }else {
                #'EndEntity' | write-output  ;
                $smsg = $LeafCertMsg + $rmsg ;
                # don't add delimited role to non-CA certs
                $hivename = 'My' ;
            }
            write-host $smsg ;
            write-host -foregroundcolor green "(returning imported Certificate object to pipeline)J" ; 
            $Certificate | write-output ; 
            
            write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;
        } ; # loop-E
    }
} ; 
#endregion IMPORT_CERTIFICATEPATHTOOBJECTTDO ; #*------^ END import-CertificatePathToObjectTDO ^------