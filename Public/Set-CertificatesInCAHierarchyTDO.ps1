# Set-CertificatesInCAHierarchyTDO_func

#$cafiles = gci C:\OpenSSL-CAs\TKadrie256CA\*.crt -recur | select -expand fullname | sort ;

#region Set-CertificatesInCAHierarchyTDO ; #*------v Set-CertificatesInCAHierarchyTDO v------
function Set-CertificatesInCAHierarchyTDO {
    <#
    .SYNOPSIS
    Set-CertificatesInCAHierarchyTDO - Fed an array of Certificate Authority 'CA' cert names in cert (.cer|.cert|.crt) format, this will sort the Root CA certs first, followed by any Intermediate certificates (and any non-CA cert files will be appended last). Does not do more than two layers of sorting - CA & IA:  3rd level IAs will all be returned in initial order, along with 2nd-level IAs.
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 20250711-0423PM
    FileName    : Set-CertificatesInCAHierarchyTDO.ps1
    License     : MIT License
    Copyright   : (c) 2025 Todd Kadrie
    Github      : https://github.com/tostka/Network
    Tags        : Powershell
    AddedCredit : REFERENCE
    AddedWebsite: URL
    AddedTwitter: URL
    REVISIONS
    * 4:31 PM 7/11/2025 init; expanded into full function, adding to vnet
    .DESCRIPTION
    Set-CertificatesInCAHierarchyTDO - Fed an array of Certificate Authority 'CA' cert names in cert (.cer|.cert|.crt) format, this will sort the Root CA certs first, followed by any Intermediate certificates (and any non-CA cert files will be appended last). Does not do more than two layers of sorting - CA & IA:  3rd level IAs will all be returned in initial order, along with 2nd-level IAs.
    .PARAMETER  Path
    Array of cert-format CA file paths to be ordered[-Path @('c:\path-to\IA.cer','c:\path-to\Root.crt')]
    .INPUTS
    String[] Accepts piped input
    .OUTPUTS
    System.Array
    .EXAMPLE
    gci C:\OpenSSL-CAs\XXXCA\*.crt -recur | select -expand fullname | Set-CertificatesInCAHierarchyTDO;
    Pipeline example
    .EXAMPLE
    PS> Set-CertificatesInCAHierarchyTDO -path (gci C:\OpenSSL-CAs\XXXCA\*.crt -recur | select -expand fullname) -verbose
    Splatted example: Import specified pfx, using NotBefore and Change number, with -whatif & -verbose output
    .LINK
    https://github.org/tostka/powershellBB/
    #>
    [CmdletBinding()]
    [Alias('Set-CertificatesInCAHierarchy','sort-CertificatesInCAHierarchy')]
    PARAM(
        [Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$true,HelpMessage="Array of cert-format CA file paths to be ordered[-Path @('c:\path-to\IA.cer','c:\path-to\Root.crt')]")]
            [ValidateScript({Test-Path $_})]
            [string[]]$Path
    ) ;
    Begin{
    $RootCAs = @() ;
    $IAs = @() ;
    $NonCAs = @() ;
    }
    PROCESS{
        foreach ($file in $Path) {
            # load each cert
            $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($file) ;
            $basicConstraints = $certificate.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Basic Constraints"}
            if ($basicConstraints) {
                $basicConstraintsData = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]$basicConstraints ;
                if ($basicConstraintsData.CertificateAuthority) {
                    write-verbose "$($file) certificate is a Certificate Authority (CA) (basicConstraintsData.CertificateAuthority populated)."
                    # Root CA certs are self-signed: have matching Issuer & Subject
                    if ($certificate.Issuer -eq $certificate.Subject) {
                        write-verbose "$($file) have matching Issuer & Subject: Self-signed: likely a Root CA" ;
                        $RootCAs += @($file) ;
                    } else {
                        write-verbose "$($file) is likely an IA" ;
                        $IAs += @($file) ;
                    } ;
                }
            } else {
                write-verbose  "$($file) certificate in the array is NOT a Certificate Authority (CA) (CertificateAuthority UNPOPULATED)."
                $NonCAs += @($file) ;
            }
        } ;
    }
    END{
        # re-combine, Roots, then IAs
        write-verbose  "`RootCAs:`n$(($RootCAs|out-string).trim())" ;
        write-verbose  "`IAs:`n$(($IAs|out-string).trim())" ;
        write-verbose  "`NonCAs:`n$(($NonCAs|out-string).trim())" ;
        #[string[]]
        [array]$cafiles = $(@($RootCAs);@($IAs);@($NonCAs)) ;
        $cafiles | write-output ;
    }
}
#endregion Set-CertificatesInCAHierarchyTDO ; #*------^ END Set-CertificatesInCAHierarchyTDO ^------
