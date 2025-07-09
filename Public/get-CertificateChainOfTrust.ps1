# get-CertificateChainOfTrust
#*------v Function get-CertificateChainOfTrust v------
Function get-CertificateChainOfTrust {
    <#
    .SYNOPSIS
    get-CertificateChainOfTrust.ps1 - Function to get all certificate in in a certificate path (chain)
    .NOTES
    Version     : 2.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2023-10-26
    FileName    : get-CertificateChainOfTrust.ps1
    License     : (non asserted)
    Copyright   : (non asserted)
    Github      : https://github.com/tostka/verb-io
    Tags        : Powershell
    AddedCredit : Amir Sayes 
    AddedWebsite: https://amirsayes.co.uk/2019/01/02/get-and-enumerate-certificate-chains-remotely-using-powershell/
    AddedTwitter: URL
    REVISIONS
    * 10:03 AM 7/9/2025 updated CBH to reflect preference for use of vnet\test-certificateTDO for this niche. 
    * 10:31 AM 10/26/2023 add -CertificateStoreRoot param, to permit runs against CurrentUser or default LocalMachine; 
        ren CertificateName param -> CertificateID w alias for orig name ; 
        ren get-CertificatePath -> get-CertificateChainOfTrust (better reflects what it does) ; 
        removed default * Certificate spec, I don't want trust tests on all certs in the local\My, I want targeted reports ; 
        expanded CertificateName to support Thumbprint, full Subject DN or subset Subject 'shortname' (first element of Subject DN w 'CN=' prefix removed). 
        Use of Thumbprint spec is more usefual than Subject, during mid-rollover coexistance, want to pull only a specific cert of the set, rather than both new and retiring old.
        updated CBH, condensed some code.
    * 1/2/2019 AS posted version
    .DESCRIPTION
    get-CertificateChainOfTrust.ps1 - Function to get all certificate in in a certificate path (chain)

    ## Note: vnet\test-CertificateTDO() substantially reproduces this function -also dumps the COT, but has benefit of working for self-signed certs, where this one fails. 

    Function to get and display all the properties of the certificates in a certificate path (chain) until the Root CA.
    The Function would use Authority Key Identifier and the Subject Key Identifier to determine the certificate path
    [Get and Enumerate Certificate Chains Remotely Using PowerShell - Amir Sayes](https://amirsayes.co.uk/2019/01/02/get-and-enumerate-certificate-chains-remotely-using-powershell/)

    Credit to Splunk Base for Certificate Authority Situational Awareness
        https://splunkbase.splunk.com/app/3113/
        https://github.com/nsacyber/Certificate-Authority-Situational-Awareness
        Author: Amir Joseph Sayes
            www.Ninaronline.com
        Version: 1.0

    .PARAMETER CertificateID
    A certificate identifier: Thumbprint, Shortname (triest to match the 1st element of the SubjectName, cleaned of CN=), full Subject DN, or wildcard[-CertificateID nEFnnnnnnnEnnnDnFFBnnnDDnCnBCBnnBDnnnnnC
    .PARAMETER ParentAKI
    Not available for the user to use via the pipeline, this parameter is used internally to look for the certificates in the validation chain recursively
    .PARAMETER Recurse
    If this switch is ON, the function will recusivley call itself through the certificate chain until it gets to the Root CA.
    .PARAMETER CertificateStoreRoot
    Root below which to search certificates: LocalMachine (default) or CurrentUser[-CertificateRootStore CurrentUser]
    .PARAMETER CertificateStore
    Pass the certificateStore name to search for certificate only in certain Store. Default is "My" and you can pass "" to search in all stores.
    .INPUTS
    None. Does not accepted piped input.(.NET types, can add description)
    .OUTPUTS
    System.Object array summarizing matched certs in the chain, is returned to the pipeline
    .EXAMPLE 
    PS> $chain = get-CertificateChainOfTrust -CertificateID nEFnnnnnnnEnnnDnFFBnnnDDnCnBCBnnBDnnnnnC -Recurse -verbose 
    PS> $prpGCPSumm = 'FriendlyName','ssl_end_time','ssl_start_time','Thumbprint','ssl_subject','ssl_ext_Key_Usage','ssl_ext_Subject_Alternative_Name','CertShortName','IssuerShortName' ; 
    PS> $n =  ($chain | measure | select -expand count) ; 
    PS> write-host -fore yellow "Certificate Chain of Trust:" ; 
    PS> $chain | %{
    PS>     $n-- ;
    PS>     write-host "`n`n==($($n)):$($_.CertShortName):`n$(($_| fl $prpGCPSumm |out-string).trim())" ; 
    PS> } ;
    Recurse and dump a trust chain on a cert specified by Thumbprint
    .EXAMPLE
    $results = get-CertificateChainOfTrust -CertificateID * -recurse -verbose ; 
    Recurse *all* certificates (specifying explicit * wildcard for CertificateID) found in the default Cert:\LocalMachine\My store and store results into variable, with verbose output.
    .EXAMPLE
    PS> $Computername = "Computer1","Computer2","Computer3"
    PS> $CertificateID = "Mywebsite.MyDomain.com"
    PS> $res = @()
    PS> $getVert_Def = "Function get-CertificateChainOfTrust { ${function:get-CertificateChainOfTrust}} "
    PS> $Computername | foreeach-object {
    PS>     $res += icm -ComputerName $_ -ArgumentList $getVert_Def -ScriptBlock {
    PS>         Param($getVert_Def) ; 
    PS>         .([scriptblock]::Create($getVert_Def))  ; 
    PS>         get-CertificateChainOfTrust -CertificateID $using:CertificateID ; 
    PS>     } ; 
    PS> } ; 
    PS> $res ; 
    Runs the Function on remote computers using invoke-command (AS's original sole example)
    Starts by creating an array of computer names which you would like to remotely run the function against.
    Creates a parameter to pass the certificate you are looking for
    Create a definition to the function so we can pass it to each remote invoke-command
    Loop inside the array of computers and pass the function and run it against each one of them using invoke-command.
    .FUNCTIONALITY
    PowerShell Language
    .LINK
    https://bitbucket.org/tostka/powershell/
    .LINK
    https://amirsayes.co.uk/2019/01/02/get-and-enumerate-certificate-chains-remotely-using-powershell/
    https://splunkbase.splunk.com/app/3113/
    https://github.com/nsacyber/Certificate-Authority-Situational-Awareness
    #>
    [cmdletbinding()]
    [Alias('get-CertificatePath')]
    PARAM ( 
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True,
            HelpMessage='A certificate identifier: Thumbprint, Shortname (triest to match the 1st element of the SubjectName, cleaned of CN=), full Subject DN, or wildcard[-CertificateID nEFnnnnnnnEnnnDnFFBnnnDDnCnBCBnnBDnnnnnC')]
            [ValidateNotNullOrEmpty()]
            [Alias('CertificateName')]
            [string]$CertificateID,
        [parameter(ValueFromPipeline = $False,ValueFromPipeLineByPropertyName = $True,
            HelpMessage='Not available for the user to use via the pipeline, this parameter is used internally to look for the certificates in the validation chain recursively')]
            [string]$ParentAKI,
        [parameter(HelpMessage = "Switch that causes function to recusivley call itself through the certificate chain until it gets to the Root CA.")]
            [switch]$Recurse,
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True,
            HelpMessage='Root below which to search certificates: LocalMachine (default) or CurrentUser[-CertificateRootStore CurrentUser]')]
            [ValidateSet("CurrentUser","LocalMachine")]
            [string]$CertificateStoreRoot = "LocalMachine",
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True,
            HelpMessage='CertificateStore name to search for certificate only in certain Store. Default is "My" and you can pass "" to search in all stores.(TrustedPublisher|Remote Desktop|Root|TrustedDevices|CA|REQUEST|AuthRoot|TrustedPeople|addressbook|My|SmartCardRoot|Trust|Disallowed|SMS|"")')]
            [ValidateSet("TrustedPublisher","Remote Desktop","Root","TrustedDevices","CA","REQUEST","AuthRoot","TrustedPeople","addressbook","My","SmartCardRoot","Trust","Disallowed","SMS","")]
            [string]$CertificateStore = "My"
    ) ; 
    #Regex a certificate Thumbprint
    $rgxCertThumbprint = '[0-9a-fA-F]{40}'
    $rgxCertSubjDN = 'CN=.*,\sC=\w+$' ; 
    $prpCert = 'PSParentPath','FriendlyName',
        @{Name='EnhancedKeyUsageList';Expression={$_.EnhancedKeyUsageList}},
        @{Name='ssl_issuer';Expression={$_.IssuerName.name}},
        @{Name='ssl_end_time';Expression={$_.NotAfter}},
        @{Name='ssl_start_time';Expression={$_.NotBefore}},
        @{Name='ssl_serial';Expression={$_.SerialNumber}},
        @{Name='ssl_publickey_algorithm';Expression={$_.PublicKey.EncodedKeyValue.Oid.FriendlyName}},
        @{N='Public_Key_Size';E={$_.PublicKey.key.keysize}},
        @{Name='Encoded_Key_Parameters';Expression={foreach($value in $_.PublicKey.EncodedParameters.RawData){$value.ToString('X2')}}},
        @{N='Public_Key_Algorithm';E={$_.PublicKey.Oid.FriendlyName}},
        @{Name='ssl_signature_algorithm';Expression={$_.SignatureAlgorithm.FriendlyName}},
        'Thumbprint',
        @{Name='ssl_version';Expression={$_.Version}},
        @{Name='ssl_subject';Expression={$_.Subject}},
        @{Name='ssl_publickey';Expression={foreach($value in $_.PublicKey.EncodedKeyValue.RawData){$value.ToString('X2')}}},
        @{N='ssl_ext_Unique_Identifiers';E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq 'Unique Identifiers'}).Format(0)}},
        @{N='ssl_ext_Authority_Key_Identifier';E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq 'Authority Key Identifier'}).Format(0)}},
        @{N='ssl_ext_Subject_Key_Identifier';E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq 'Subject Key Identifier'}).Format(0)}},
        @{N='ssl_ext_Key_Usage';E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq 'Key Usage'}).Format(0)}},
        @{N='ssl_ext_Certificate_Policies';E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq 'Certificate Policies'}).Format(0)}},
        @{N='ssl_ext_Policy_Mappings';E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq 'Policy Mappings'}).Format(0)}},
        @{N='ssl_ext_Subject_Alternative_Name';E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq 'Subject Alternate Name'}).Format(0)}},
        @{N='ssl_ext_Issuer_Alternate_Name';E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq 'Issuer Alternate Name'}).Format(0)}},
        @{N='ssl_ext_Subject_Directory_Attributes';E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq 'Subject Directory Attributes'}).Format(0)}},
        @{N='ssl_ext_Basic_Constraints';E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq 'Basic Constraints'}).Format(0)}},
        @{N='ssl_ext_Name_Constraints';E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq 'Name Constraints'}).Format(0)}},
        @{N='ssl_ext_Policy_Constraints';E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq 'Policy Constraints'}).Format(0)}},
        @{N='ssl_ext_Extended_Key_Usage';E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq 'Extended Key Usage'}).Format(0)}},
        @{N='ssl_ext_CRL_Distribution_Points';E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq 'CRL Distribution Points'}).Format(0)}},
        @{N='ssl_ext_Inhibit_Policy';E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq 'Inhibit Policy'}).Format(0)}},
        @{N='ssl_ext_Freshest_CRL';E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq 'Freshest CRL'}).Format(0)}},
        @{N='ssl_pri_ext_Authority_Information_Access';E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq 'Authority Information Access'}).Format(0)}},
        @{N='ssl_pri_ext_Subject_Information_Access';E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq 'Subject Information Access'}).Format(0)}},
        @{N='CertShortName';E={($_.Subject.split(",")[0]).trimstart("CN=")}},
        @{N='IssuerShortName';E={($_.IssuerName.name.split(",")[0]).trimstart("CN=")}} ; 

    $result =@() 
    $Called_Cert = @() 
    $smsg = "Get-ChildItem -Path Cert:\$($CertificateStoreRoot)\$($CertificateStore) -Recurse"
    write-verbose $smsg ; 
    $Called_Cert = Get-ChildItem -Path Cert:\$CertificateStoreRoot\$CertificateStore -Recurse | Where {-not $_.PSIsContainer} | 
        Select $prpCert | sort Thumbprint -Unique 

        if (-not ($ParentAKI)) { 
            switch -regex ($CertificateID){
                $rgxCertThumbprint {
                    write-verbose "-CertificateID ($($CertificateID)) matches a Cert Thumbprint" ; 
                    $Called_Cert = $Called_Cert | where {$_.Thumbprint -eq "$CertificateID"} 
                } 
                $rgxCertSubjDN  {
                    write-verbose "-CertificateID ($($CertificateID)) matches a Cert Subject DN" ; 
                    $Called_Cert = $Called_Cert | where {$_.ssl_subject -eq "$CertificateID"} 
                } 
                default {
                    write-verbose "Attempting to compare -CertificateID ($($CertificateID)) to CertShortName..." ;
                    $Called_Cert = $Called_Cert | where {$_.CertShortName -like "$CertificateID"} 
                }
            } ; 
        } elseif ($ParentAKI) {
            $Called_Cert = $Called_Cert | where {$_.ssl_ext_Subject_Key_Identifier -eq $ParentAKI} | select -First 1 ; 
        } ; 

        If ($Recurse) {
            #Loop and recursively retrieve the certificates in the chain until Root CA 
            $Called_Cert | foreach-object { 
                if ($_.ssl_ext_Authority_Key_Identifier -ne $null) {
                    $CertParentAKI = ($_.ssl_ext_Authority_Key_Identifier.split("=")[1])
                    #Adding the Cert name as a member in the original object 
                    $_ | Add-Member -MemberType NoteProperty -Name 'CertParentAKI' -Value $CertParentAKI 
                } else {
                    $CertParentAKI = 0 
                    $_ | Add-Member -MemberType NoteProperty -Name 'CertParentAKI' -Value $CertParentAKI 
                } ; 
                #Output the results 
                $_ | write-output ; 
                #If recurse switch was On and we have not reached the Root CA then call the function and pass the AKI of the issure of the current certificate
                if ($_.CertParentAKI -ne $_.ssl_ext_Subject_Key_Identifier -and $_.CertParentAKI -ne 0) {
                    get-CertificateChainOfTrust -ParentAKI $_.CertParentAKI -Recurse -CertificateStore ""  ; 
                }  ; 

            } ;  # loop-E
        } else {
            # if no recurse was chosen then just show the results without looping
            $Called_Cert
        } ; 
} ; 
#*------^ END Function get-CertificateChainOfTrust ^------

