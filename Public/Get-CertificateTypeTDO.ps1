# Get-CertificateTypeTDO

#region GET_CERTIFICATETYPETDO ; #*------v  Get-CertificateTypeTDO v------
    function Get-CertificateTypeTDO {
        <#
        .SYNOPSIS
        Get-CertificateTypeTDO - Classifies a given x509 certificate object as CA/IA, or End Entity cert
        .NOTES
        Version     : 0.0.1
        Author      : Todd Kadrie
        Website     : http://www.toddomation.com
        Twitter     : @tostka / http://twitter.com/tostka
        CreatedDate : 2026-10-14
        FileName    : Get-CertificateTypeTDO.ps1
        License     : MIT License
        Copyright   : (c) 2025 Todd Kadrie
        Github      : https://github.com/tostka/verb-Network
        Tags        : Powershell,Certificate,Import,Maintenance
        AddedCredit : REFERENCE
        AddedWebsite: URL
        AddedTwitter: URL
        REVISIONS
        * 11:02 AM 10/14/2026 init, based on CPT sample
        .DESCRIPTION
        Get-CertificateTypeTDO - Classifies a given x509 certificate object as CA/IA, or End Entity cert
        
        .PARAMETER Certificate
        X509 Certificate object to be tested[-Certificate `$certObj]
        .INPUTS
        System.Security.Cryptography.X509Certificates.X509Certificate2 Accepts piped input.
        .OUTPUTS
        System.String of three type values: RootCA|IntermediateCA|EndEntity
        .EXAMPLE
        PS> switch ((gci Cert:\currentUser\My\9A9A999A999A9A9999999A9A9AAA99AAA99AA9A9) | Get-CertificateTypeTDO) {
        PS>     'RootCA'{
        PS>          write-host "RootCA type: Install to cert:\CurrentUser|LocalMachine\Root" ; 
        PS>     }
        PS>     'IntermediateCA'{
        PS>          write-host "Sub type: Install to cert:\CurrentUser|LocalMachine\CA" ; " ; 
        PS>     }
        PS>     'EndEntity'{
        PS>          write-host "Leaf Entity: Install to cert:\CurrentUser|LocalMachine\My\" ;  ; 
        PS>     }
        PS> }        
        Demo switch eval block
        .EXAMPLE
        PS> gci cert:\currentUser\root\DF3C24F9BFD666761B268073FE06D1CC8D4F82A4 | Get-CertificateTypeTDO
        
              RootCA
        
        Demo root cert check
        .EXAMPLE
        PS> gci cert:\currentUser\root\DF3C24F9BFD666761B268073FE06D1CC8D4F82A4 | Get-CertificateTypeTDO
        
              RootCA
              
        Demo root cert check
        .EXAMPLE
        PS>  gci cert:\currentUser\CA\ | select -first 1 | Get-CertificateTypeTDO
        
              IntermediateCA
              
        .LINK
        https://github.com/tostka/verb-Network
        #>
        [CmdletBinding()]
        [Alias('test-CertificateTypeTDO')]
        PARAM(            
            [Parameter(Mandatory=$True,ValueFromPipeline=$true,HelpMessage="X509 Certificate object to be tested[-Certificate `$certObj]")]
                [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
        )
        PROCESS{
            foreach($item in $certificate){
                TRY{
                    write-verbose "Processing: $($item.subject)" ; 
                    $bc = $Certificate.Extensions | Where-Object {
                        $_ -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]
                    } ; 
                    if ($bc -and $bc.CertificateAuthority) {
                        if ($Certificate.Subject -eq $Certificate.Issuer) {
                            'RootCA' | write-output  ; 
                        }else {
                            'IntermediateCA'  | write-output  ; 
                        }
                    }else {
                        'EndEntity' | write-output  ; 
                    }
                } CATCH {$ErrTrapd=$Error[0] ;
                    write-host -foregroundcolor gray "TargetCatch:} CATCH [$($ErrTrapd.Exception.GetType().FullName)] {"  ;
                    $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;
                    write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" ;
                } ;
            } ;  # loop-E
        } ; 
    } ; 
    #endregion GET_CERTIFICATETYPETDO ; #*------^ END Get-CertificateTypeTDO ^------