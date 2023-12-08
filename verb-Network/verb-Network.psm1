﻿# verb-network.psm1


<#
.SYNOPSIS
verb-Network - Generic network-related functions
.NOTES
Version     : 3.3.3.0
Author      : Todd Kadrie
Website     :	https://www.toddomation.com
Twitter     :	@tostka
CreatedDate : 4/8/2020
FileName    : verb-Network.psm1
License     : MIT
Copyright   : (c) 4/8/2020 Todd Kadrie
Github      : https://github.com/tostka
REVISIONS
* 4/8/2020 - 1.0.0.0
# 12:44 PM 4/8/2020 pub cleanup
# 8:20 AM 3/31/2020 shifted Send-EmailNotif fr verb-smtp.ps1
# 11:38 AM 12/30/2019 ran vsc alias-expan
# 11:41 AM 11/1/2017 initial version
.DESCRIPTION
verb-Network - Generic network-related functions
.LINK
https://github.com/tostka/verb-Network
#>


    $script:ModuleRoot = $PSScriptRoot ;
    $script:ModuleVersion = (Import-PowerShellDataFile -Path (get-childitem $script:moduleroot\*.psd1).fullname).moduleversion ;
    $runningInVsCode = $env:TERM_PROGRAM -eq 'vscode' ;

#*======v FUNCTIONS v======




#*------v Add-IntToIPv4Address.ps1 v------
function Add-IntToIPv4Address {
<#
    .SYNOPSIS
    Add-IntToIPv4Address.ps1 - Add an integer to an IP Address and get the new IP Address.
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2021-08-16
    FileName    : Add-IntToIPv4Address.ps1
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,Network,IP,Subnet
    AddedCredit :  Brian Farnsworth
    AddedWebsite: https://codeandkeep.com/
    AddedTwitter: 
    REVISIONS
    * 1:29 PM 8/12/2021 tweaked CBH, minor param inline help etc.
    * 9/10/2019 Mark Wragg posted rev (corresponds to PSG v1.1.14)
    .DESCRIPTION
    Add an integer to an IP Address and get the new IP Address.
    .PARAMETER IP
    The IP Address to add an integer to [-IP 192.168.0.1]
    .PARAMETER Integer
    An integer to add to the IP Address. Can be a positive or negative number[-integer 1].
    .EXAMPLE
    .EXAMPLE
    Add-IntToIPv4Address -IPv4Address 10.10.0.252 -Integer 10
    10.10.1.6
    Description
    -----------
    This command will add 10 to the IP Address 10.10.0.1 and return the new IP Address.
    .EXAMPLE
    Add-IntToIPv4Address -IPv4Address 192.168.1.28 -Integer -100
    192.168.0.184
    Description
    -----------
    This command will subtract 100 from the IP Address 192.168.1.28 and return the new IP Address.
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://codeandkeep.com/PowerShell-Get-Subnet-NetworkID/
    #>
    ##Requires -Modules DnsClient
    [CmdletBinding()]
    Param(
      [parameter(HelpMessage="The IP address to test[-IP 192.168.0.1]")]
      [String]$IP,
      [parameter(HelpMessage="An integer to add to the IP Address. Can be a positive or negative number[-integer 1]")]
      [int64]$Integer
    )
    BEGIN {
        ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
        $Verbose = ($VerbosePreference -eq 'Continue') ; 
    } ;  # BEG-E
    PROCESS {
        Try{
            #$ipInt=ConvertIPv4ToInt -IP $IP  -ErrorAction Stop ; 
            $ipInt=Convert-IPtoInt64 -IP $IP  -ErrorAction Stop ; 
            $ipInt+=$Integer ; 
            #ConvertIntToIPv4 -Integer $ipInt ; 
            convert-Int64toIP -int $ipInt  |write-output ; 
        }Catch{
              Write-Error -Exception $_.Exception -Category $_.CategoryInfo.Category ; 
        } ; 
    } ;  # PROC-E
    END {}
}

#*------^ Add-IntToIPv4Address.ps1 ^------


#*------v Connect-PSR.ps1 v------
Function Connect-PSR {
    <#
    .SYNOPSIS
    Connect-PSR - Setup Remote Powershell connection
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-06-09
    FileName    : Reconnect-PSR.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell,Remote
    REVISIONS
    * 8:56 AM 6/9/2020 added to verb-Network ; added verbose echo
    * 9:34 AM 12/21/2016 port to Powershell remote
    * 12:09 PM 12/9/2016 implented and debugged as part of verb-PSR set
    * 2:37 PM 12/6/2016 ported to local EMSRemote
    * 2/10/14 posted version 
    .DESCRIPTION
    Connect-PSR - Setup Remote Powershell connection
    $Credential can leverage a global: $Credential = $global:SIDcred
    .PARAMETER  Server
    Server to Remote to
    .PARAMETER CommandPrefix
    No console feedback 
    .PARAMETER Silent
    No console feedback 
    .PARAMETER  Credential
    Credential object
    .EXAMPLE
    # -----------
    try{    
        $reqMods="Connect-PSR;Reconnect-PSR;Disconnect-PSR;Disconnect-PssBroken;Cleanup".split(";") ; 
        $reqMods | % {if( !(test-path function:$_ ) ) {write-error "$((get-date).ToString("yyyyMMdd HH:mm:ss")):Missing $($_) function. EXITING." } } ; 
        Reconnect-PSR ; 
    } CATCH {
        Write-Warning "$(get-date -format 'HH:mm:ss'): Failed processing $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ;
        Exit #STOP(debug)|EXIT(close)|Continue(move on in loop cycle) ; 
    } ; 
    # -----------
    .LINK
    #>
    [CmdletBinding()]
    [Alias('cPSR')]
    Param( 
        [Parameter(Position=0,Mandatory=$True,HelpMessage="Server to Remote to")][Alias('__ServerName', 'Computer')]
        [string]$Server,
        [Parameter(HelpMessage="OptionalCommand Prefix for cmdlets from this session[PSR]")][string]$CommandPrefix,
        [Parameter(HelpMessage = 'Credential object')][System.Management.Automation.PSCredential]$Credential = $credTORSID,
        [Parameter(HelpMessage='Silent flag [-silent]')][switch]$silent
    )  ; 
    $verbose = ($VerbosePreference -eq "Continue") ; 
    if(!$silent){
        write-verbose -verbose:$true  "$((get-date).ToString("yyyyMMdd HH:mm:ss")):Adding Remote PS (connecting to $($Server))..." ; 
    } ; 
    
    $PSRsplat=@{ComputerName=$server ; Name="PSR"} ;
    # credential support
    if($Credential){ $PSRsplat.Add("Credential",$Credential) } ; 
    # -Authentication Basic only if specif needed: for Ex configured to connect via IP vs hostname)
    write-verbose "$((get-date).ToString('HH:mm:ss')):New-PSSession w`n$(($PSRsplat|out-string).trim())" ; 
    $error.clear() ;
    TRY {
      $Global:PSRSess = New-PSSession @PSRSplat -ea stop ;
    } CATCH {
      $ErrTrapd = $_ ; 
      write-warning "$(get-date -format 'HH:mm:ss'): Failed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: $($ErrTrapd)" ;
    } ;
}

#*------^ Connect-PSR.ps1 ^------


#*------v Disconnect-PSR.ps1 v------
Function Disconnect-PSR {
    <# 
    .SYNOPSIS
    Disconnect-PSR - Clear Remote Powershell connection
    .NOTES
    Author: Todd Kadrie
    Website:	http://tinstoys.blogspot.com
    Twitter:	http://twitter.com/tostka
    Inspired By: ExactMike Perficient, Global Knowl... (Partner)  
    Website:	https://social.technet.microsoft.com/Forums/msonline/en-US/f3292898-9b8c-482a-86f0-3caccc0bd3e5/exchange-powershell-monitoring-remote-sessions?forum=onlineservicesexchange
    REVISIONS   :
    * 2:56 PM 12/21/2016 add a pretest suppress not found error
    * 9:34 AM 12/21/2016 port to Powershell remote
    * 12:54 PM 12/9/2016 cleaned up, add pshelp
    * 12:09 PM 12/9/2016 implented and debugged as part of verb-PSR set
    * 2:37 PM 12/6/2016 ported to local EMSRemote
    * 2/10/14 posted version 
    .DESCRIPTION
    Disconnect-PSR - Clear Remote Powershell connection
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output.
    .EXAMPLE
    Disconnect-PSR ; 
    .LINK
    #>
        <#
    .SYNOPSIS
    Disconnect-PSR - Clear Remote Powershell connection
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-06-09
    FileName    : Disconnect-PSR .ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell,Remote
    REVISIONS
    * 2:56 PM 12/21/2016 add a pretest suppress not found error ; port to Powershell remote
    * 12:54 PM 12/9/2016 cleaned up, add pshelp ;implented and debugged as part of verb-PSR set
    * 2:37 PM 12/6/2016 ported to local EMSRemote
    .DESCRIPTION
    Disconnect-PSR - Clear Remote Powershell connection
    .EXAMPLE
    .\Disconnect-PSR .ps1
    .EXAMPLE
    .\Disconnect-PSR .ps1
    .LINK
    #>
    [CmdletBinding()]
    [Alias('dPSR')]
    Param() ;
    $verbose = ($VerbosePreference -eq "Continue") ; 
    if($Global:PSRSess){$Global:PSRSess | Remove-PSSession ; } ; 
    # kill any other sessions using my distinctive name; add verbose, to ensure they're echo'd that they were missed
    Get-PSSession |? {$_.name -eq 'PSR'} | Remove-PSSession -verbose ;
}

#*------^ Disconnect-PSR.ps1 ^------


#*------v get-CertificateChainOfTrust.ps1 v------
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
}

#*------^ get-CertificateChainOfTrust.ps1 ^------


#*------v Get-DnsDkimRecord.ps1 v------
function Get-DnsDkimRecord {
    <#
    .SYNOPSIS
    Get-DnsDkimRecord.ps1 - Function to resolve a DKIM record of a domain, under common or specified selectors for a domain.
    .NOTES
    Version     : 0.0.
    Author      :  (T13nn3s )
    Website     : https://binsec.nl
    Twitter     : @T13nn3s / https://twitter.com/T13nn3s
    CreatedDate : 2022-04-06
    FileName    : Get-DnsDkimRecord.ps1
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/powershell
    Tags        : Powershell,DNS,Email,SPF
    AddedCredit : Todd Kadrie
    AddedWebsite: toddomation.com
    AddedTwitter: @tostka/https://twitter.com/tostka
    REVISIONS
    * 6:09 PM 1/10/2023 TK revised: ren'd Get-DnsDkimRecord-> Get-DnsDkimRecord; 
    Added/updated CBH, and citations to variety of related link websites ; 
    Defaulted -Server to 1.1.1.1 (public default resolution) ; 
    added a bunch of verbose echoes for tshooting ; 
    added elseif test for not just v=dkim1 & k=, but accept p= public key (functional min requirement the other 2 tags are common but not required for function);
    [DKIM DNS record overview – Validity Help Center - help.returnpath.com/](https://help.returnpath.com/hc/en-us/articles/222481088-DKIM-DNS-record-overview)
    added trailing RturnedType to outputk, and tested for SOA and suppressed spurious last kdimselector as output. 
    Also updates DKIMAdvisory output to reflect failed generic selectors search (e.g. user should spec known-selector as next step).
    fundemental logic rewrite: when a selector is specified, it defaults to the 'accepteddomain' fqdn *only*:
    $($DkimSelector)._domainkey.$($Name)"
    issue: that doesn't accomodate custom SAAS vendor DKIM's or their CNAME pointers (which could be any arbitrary hostname on the domain). 
    retry the failure on an explicit selector.name(.com) pass.; 
    Finally just simplified into a single loop regardless of source or if looping static array; 
    spliced in block to dump out full chain on multi dns records returned (more detail on -verbose)
    * 11/02/2022 T13nn3s posted rev v1.5.2
    .DESCRIPTION
    Get-DnsDkimRecord.ps1 - Checks DKIM records under common or specified selectors for a domain.

    Reasonable listing of common selectors here
    [Email Provider Commonly Used DKIM Selectors : Sendmarc - help.sendmarc.com/](https://help.sendmarc.com/support/solutions/articles/44001891845-email-provider-commonly-used-dkim-selectors)


    .PARAMETER Name
    Specifies the domain for resolving the DKIM-record.[-Name Domain.tld]
    .PARAMETER DkimSelector
    Specify a custom DKIM selector.[-DkimSelector myselector
    .PARAMETER Server
    DNS Server to use.[-Server 8.8.8.8]
    .INPUTS
    Accepts piped input.
    .OUTPUTS
    System.object
    .EXAMPLE
    PS>  $results = get-dnsdkimrecord -name SOMEDOMAIN.com 
    PS>  $results ; 

        Name         : DOMAIN.com
        DkimRecord   : v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQE[TRIMMED]qizt5Duv4WbgY/lXePnSA9iQIDAQAB;
        DkimSelector : selector2
        ReturnedType : TXT
        DKIMAdvisory : DKIM-record found.

    Simple expansion on targeted domain, assign results to variable .
    .EXAMPLE
    PS>  $result = get-dnsdkimrecord -name DOMAIN.com -verbose -Selector hs1-20997172._domainkey ; 
    PS>  if($result.DkimRecord){
    PS>      $smsg = "DKIM record returned on query:`n" 
    PS>      $smsg += "`n$(($result.DkimRecord | format-list |out-string).trim())" ;
    PS>      write-host $smsg ; 
    PS>      if($pkey = $result.DkimRecord.split(';') | ?{$_ -match 'p=[a-zA-z0-9]+'}){
    PS>          $smsg = "`nMatched Public Key tag:`n$(($pkey | format-list |out-string).trim())" ;
    PS>          write-host $smsg ; 
    PS>      } else { 
    PS>          $smsg += "`nNO PUBLIC KEY MATCHED IN RETURNED RECORD!`n$(($pkey | format-list |out-string).trim())" ;
    PS>          write-warning $smsg ;
    PS>      } ; 
    PS>  } else { 
    PS>      $smsg = "`nNO DKIM RECORD RETURNED ON QUERY:`N" 
    PS>      $smsg += "`n$(($result.DkimRecord | format-list |out-string).trim())" ;
    PS>      write-warning $smsg ; 
    PS>  } ; 

        DKIM record returned on query:

        k=rsa;t=s;p=MIIBIjANBgkqhk[TRIMMED]klCj9qU9oocSLd3PlChiBQHgz7e9wGbtIgV2xVwIDAQAB

        Matched Public Key:
        p=MIIBIjANBgkqhk[TRIMMED]klCj9qU9oocSLd3PlChiBQHgz7e9wGbtIgV2xVwIDAQAB

    Example processing the returned TXT DKIM record and outputing the public key tag.
    DESCRIPTION    
.LINK
    https://github.com/T13nn3s/Invoke-SpfDkimDmarc/blob/main/public/Get-DMARCRecord.ps1
    https://www.powershellgallery.com/packages/DomainHealthChecker/1.5.2/Content/public%5CGet-DnsDkimRecord.ps1
    https://binsec.nl/powershell-script-for-spf-dmarc-and-dkim-validation/
    https://github.com/T13nn3s
    .LINK
    https://github.COM/tostka/verb-Network/
    #>
    [CmdletBinding()]
    # Set-Alias gdkim -Value Get-DnsDkimRecord   # move trailing alias here
    [Alias('gdkim')]
    PARAM(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, 
            HelpMessage = "Specifies the domain for resolving the DKIM-record.[-Name Domain.tld]")]
        [string]$Name,
        [Parameter(Mandatory = $False,
            HelpMessage = "An array of custom DKIM selector strings.[-DkimSelector myselector")]
        [Alias('Selector')]
        [string[]]$DkimSelector,
        [Parameter(Mandatory = $false,
            HelpMessage = "DNS Server to use.[-Server 8.8.8.8]")]
        [string]$Server='1.1.1.1'
    ) ; 
    BEGIN {
        $verbose = ($VerbosePreference -eq "Continue") ; 
        #if ($PSBoundParameters.ContainsKey('Server')) {
        # above doesn't work if $Server is defaulted value
        if ($PSBoundParameters.ContainsKey('Server') -OR $Server) {
            $SplatParameters = @{
                'Server'      = $Server ; 
                'ErrorAction' = 'SilentlyContinue' ; 
            } ; 
        } Else {
            $SplatParameters = @{
                'ErrorAction' = 'SilentlyContinue' ; 
            } ; 
        } ; 
        
        #$whReportSub = @{BackgroundColor = 'Gray' ; ForegroundColor = 'DarkMagenta' } ;
        $whElement = @{BackgroundColor = 'Yellow' ; ForegroundColor = 'Black' } ;
        #$whQualifier = @{BackgroundColor = 'Blue' ; ForegroundColor = 'White' } ;

        $prpCNAME = 'Type','Name','NameHost' ; 
        $prpTXT = 'Type','Name','Strings' ; 
        $prpSOA = 'Type','Name','PrimaryServer' ; 

        # Custom list of DKIM-selectors
        # https://help.sendmarc.com/support/solutions/articles/44001891845-email-provider-commonly-used-dkim-selectors
        $DKSelArray = @(
            'selector1' # Microsoft
            'selector2' # Microsoft
            'google', # Google
            'everlytickey1', # Everlytic
            'everlytickey2', # Everlytic
            'eversrv', # Everlytic OLD selector
            'k1', # Mailchimp / Mandrill
            'mxvault' # Global Micro
            'dkim' # Hetzner
            's1' # generic
            's2' # generic
        ) ; 

        if ($PSCmdlet.MyInvocation.ExpectingInput) {
            write-verbose "Data received from pipeline input: '$($InputObject)'" ; 
        } else {
            #write-verbose "Data received from parameter input: '$($InputObject)'" ; 
            write-verbose "(non-pipeline - param - input)" ; 
        } ; 

        $DKimObject = New-Object System.Collections.Generic.List[System.Object] ; 
        
        if(-not $DkimSelector){
            $DkimSelector = $DKSelArray ; 
            $noSelectorSpecified = $true ; 
            #$smsg = "Running specified `Name:$($Name) through common selector names:" ; 
            $smsg = "Running with common selector names:" ; 
            $smsg += "`n($($DKSelArray -join '|'))..." ; 
            #write-host -Object $smsg @whElement ; 
        } else {
            $noSelectorSpecified = $false ; 
            #$smsg = "Running specified `Name:$($Name) through specified -DkimSelector selector names:" ; 
            $smsg = "Running specified -DkimSelector selector names:" ; 
            $smsg += "`n($($DkimSelector -join '|'))..." ; 
            #write-host -Object $smsg @whElement ;
        }; 
        write-host -Object $smsg @whElement ; 
    } ; 
    PROCESS { 
        $Error.Clear() ; 

        

        foreach($item in $Name) {

            $sBnr="#*======v Name: $($item) v======" ; 
            $whBnr = @{BackgroundColor = 'Magenta' ; ForegroundColor = 'Black' } ;
            write-host @whBnr -obj "$((get-date).ToString('HH:mm:ss')):$($sBnr)" ;

            $foundSelector = $false ; 

            foreach ($DSel in $DkimSelector) {

                $smsg = "DkimSelector:$($DSel) specified for domain Name:$($item)" ; 
                $smsg += "`nResolve-DnsName -Type TXT -Name $($DSel)._domainkey.$($item)" ; 
                write-verbose $smsg ; 
                if($DKIM = Resolve-DnsName -Type TXT -Name "$($DSel)._domainkey.$($item)" @SplatParameters){

                } else { 
                    # above doesn't accomodate custom SAAS vendor DKIMs and CNAMe pointers, so retry on selector.name
                    $smsg = "Fail on prior TXT qry" ; 
                    $smsg += "`nRetrying TXT qry:-Name $($DSel).$($item)"
                    $smsg += "`nResolve-DnsName -Type TXT -Name $($DSel).$($item)"  ;
                    write-verbose $smsg ; 
                    $DKIM = Resolve-DnsName -Type TXT -Name "$($DSel).$($item)" @SplatParameters ; 
                } ;  

                if(($DKIM |  measure).count -gt 1){
                    write-verbose "Multiple Records returned on qry: Likely resolution chain CNAME->(CNAME->)TXT`nuse the TXT record in the chain" ;   

                    # dump the chain
                    # ---
                    $rNo=0 ; 
                    foreach($rec in $DKIM){
                        $rNo++ ; 
                        $RecFail = $false ; 
                        $smsg = "`n`n==HOP: $($rNo): " ;
                        switch ($rec.type){
                            'CNAME' {
                                $smsg += "$($rec.Type): $($rec.Name) ==> $($rec.NameHost):" ; 
                                if($verbose){
                                    $smsg += "`n" ; 
                                } ; 
                                if($verbose -AND (get-command Convertto-Markdowntable -ea 0)){
                                    $smsg += $rec | select $prpCNAME | Convertto-Markdowntable -Border ; 
                                } else { 
                                    $smsg += "`n$(($rec | ft -a $prpCNAME |out-string).trim())" ; 
                                } ; 
                                if($verbose){
                                    $smsg += "`n" ; 
                                } ; 
                            } 
                            'TXT' { 
                                $smsg += "$($rec.Type):Value record::`n" ; 
                                if($verbose){
                                    $smsg += "`n" ; 
                                } ; 
                                if($verbose -AND (get-command Convertto-Markdowntable -ea 0)){
                                    $smsg += $rec | select $prpTXT[0..1] | Convertto-Markdowntable -Border ; 
                                    $smsg += "`n" ;
                                    $smsg += $rec | select $prpTXT[2] | Convertto-Markdowntable -Border ; 
                                } else { 
                                    $smsg += "`n$(($rec | ft -a  $prpTXT[0..1] |out-string).trim())" ; 
                                    $smsg += "`n" ;
                                    $smsg += "`n$(($rec | ft -a $prpTXT[2]|out-string).trim())" ; 
                                } ; 
                                if($verbose){
                                    $smsg += "`n" ; 
                                } ; 
                                if($rec.Strings -match 'v=DKIM1;\sk=rsa;\sp='){
                                    $smsg += "`n`n--->TXT: $($rec.Name).strings *IS VALIDATED* to contain a DKIM key.`n`n" ; 
                                }elseif($rec.Strings -match 'p=\w+'){
                                    # per above, this matches only the bare minimum!
                                    $smsg += "`n`n--->TXT: $($rec.Name).strings *IS VALIDATED* to contain a DKIM key.`n`n" ; 
                                }else {
                                    $smsg += "`n`n--->TXT: $($rec.Name).strings *DOES NOT VALIDATE* to contain a DKIM key!" ;
                                    $smsg += "`n(strings should start with 'v=DKIM1', or at minimum include a p=xxx public key)`n`n" ; 
                                    $RecFail = $true ; 
                                } ; 
                            } 
                            'SOA' {
                                $smsg += "`nSOA/Lookup-FAIL record detected!" ; 
                                $smsg += "`n$(($rec | ft -a $prpSOA | out-string).trim())" ; 
                                #throw $smsg ;
                                $RecFail = $true ; 
                            }
                            default {throw "Unrecognized record TYPE!" ; $RecFail = $true ; } 
                        } ; 

                        if($RecFail -eq $true){
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } 
                            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                        } else { 
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                        } ; 

                    };  # loop-E
                    #---

                    #if($DKIM |?{$_.type -eq 'TXT'}){
                    if($DKIM.type -contains 'TXT'){
                        $DKIM  = $DKIM |?{$_.type -eq 'TXT'} ; 
                        $rtype = $DKIM.type ; 
                        $DKIM  = $DKIM | Select-Object -ExpandProperty Strings -ErrorAction SilentlyContinue ;
                        if ($DKIM -eq $null) {
                            $DkimAdvisory = "No DKIM-record found for selector $($DSel)._domainkey." ;
                        } elseif ($DKIM -match "v=DKIM1" -or $DKIM -match "k=") {
                            $DkimAdvisory = "DKIM-record found." ;
                            if($noSelectorSpecified -AND ($DSel -match "^selector1|everlytickey1|s1$") ){
                                $smsg = "$($DkimSelector) is one of a pair of records, contining, to run the second partner record" ; 
                                write-host $smsg ; 
                            }elseif($noSelectorSpecified -eq $false){
                                write-verbose "always run all explicit -DkimSelector values" ; 
                            } else { 
                                #break ; 
                                $foundSelector = $true ; 
                            } ; 
                        # TK: test variant p= public key as fall back
                        } elseif ($DKIM -match 'p=\w+' ) {
                                # test above is too restrictive, min tag for functional dkim is a 'p=XXX' public key, not DKIM & k= tags)
                                $DkimAdvisory = "*Minimum requirement* (p=XXX) Public Key found: Likely DKIM-record present." ;
                                if($noSelectorSpecified -AND ($DSel -match "^selector1|everlytickey1|s1$") ){
                                    $smsg = "$($DkimSelector) is one of a pair of records, contining, to run the second partner record" ; 
                                    write-host $smsg ; 
                                }elseif($noSelectorSpecified -eq $false){
                                    write-verbose "always run all explicit -DkimSelector values" ; 
                                } else { 
                                    #break ; 
                                    $foundSelector = $true ; ; 
                                } ; 
                        } else {;
                                $DkimAdvisory = "We couldn't find a DKIM record associated with your domain." ;
                                $DkimAdvisory += "`n$($rType) record returned, unrecognized:" ; 
                                $DkimAdvisory += "`n$(($DKIM | format-list |out-string).trim())" ;
                        } ; 
                    } ;
                } elseif ($DKIM.Type -eq "CNAME") {
                    while ($DKIM.Type -eq "CNAME") {
                        $DKIMCname = $DKIM.NameHost ; 
                        $DKIM = Resolve-DnsName -Type TXT -name "$DKIMCname" @SplatParameters ;
                    } ; # loop-E
                    $rType = $DKIM.Type ; 
                    #$DkimAdvisory = _test-DkimString -DKIM $DKIM -selector $DSel
                    $DKIM = $DKIM | Select-Object -ExpandProperty Strings -ErrorAction SilentlyContinue ;
                    if ($DKIM -eq $null) {
                        $DkimAdvisory = "No DKIM-record found for selector $($DSel)._domainkey." ;
                    } elseif ($DKIM -match "v=DKIM1" -or $DKIM -match "k=") {
                        $DkimAdvisory = "DKIM-record found." ;
                    # TK: test variant p= public key as fall back
                    } elseif ($DKIM -match 'p=\w+' ) {
                            # test above is too restrictive, min tag for functional dkim is a 'p=XXX' public key, not DKIM & k= tags)
                            $DkimAdvisory = "*Minimum requirement* (p=XXX) Public Key found: Likely DKIM-record present." ;
                            #break ; # can't break here, it leaps the emit end of the loop
                    } else {;
                            $DkimAdvisory = "We couldn't find a DKIM record associated with your domain." ;
                            $DkimAdvisory += "`n$($rType) record returned, unrecognized:" ; 
                            $DkimAdvisory += "`n$(($DKIM | format-list |out-string).trim())" ;
                    } ; 

                } else {
                    $DKIM = $DKIM | Select-Object -ExpandProperty Strings -ErrorAction SilentlyContinue ;
                    if ($DKIM -eq $null) {
                        $DkimAdvisory = "No DKIM-record found for selector $($DSel)._domainkey." ;
                    } elseif ($DKIM -match "v=DKIM1" -or $DKIM -match "k=") {
                        $DkimAdvisory = "DKIM-record found." ;
                    } ;
                } ;

                $DkimReturnValues = New-Object psobject ;
                $DkimReturnValues | Add-Member NoteProperty "Name" $item ;
                $DkimReturnValues | Add-Member NoteProperty "DkimRecord" $DKIM ;
                if($rType -eq 'SOA'){
                    write-verbose "asserting DkimSelector:`$null" ;
                    $DkimReturnValues | Add-Member NoteProperty "DkimSelector" $null ;
                    if($noSelectorSpecified){
                        $DkimAdvisory = $DkimAdvisory.replace('domain.',"domain, against a common Selectors list:`n($($DKSelArray -join '|')).") ; 
                    }; 
                } else { 
                    $DkimReturnValues | Add-Member NoteProperty "DkimSelector" $DSel ;
                } ; 
                $DkimReturnValues | Add-Member NoteProperty "ReturnedType" $rType ;
                $DkimReturnValues | Add-Member NoteProperty "DKIMAdvisory" $DkimAdvisory ;
                $DkimObject.Add($DkimReturnValues) ;
                $DkimReturnValues | write-output ;

                if($foundSelector){
                    Break ; 
                } ; 
            } # loop-E DkimSelectors

            

            write-host @whBnr -obj "$((get-date).ToString('HH:mm:ss')):$($sBnr.replace('=v','=^').replace('v=','^='))" ;

        } # loop-E Name
    } END {
        
    } ;
}

#*------^ Get-DnsDkimRecord.ps1 ^------


#*------v get-DNSServers.ps1 v------
function get-DNSServers{
    <#
    .SYNOPSIS
    get-DNSServers.ps1 - Get the DNS servers list of each IP enabled network connection
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2021-01-14
    FileName    : get-DNSServers.ps1
    License     : (non specified)
    Copyright   : (non specified)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,Network,DNS
    AddedCredit : Sitaram Pamarthi
    AddedWebsite:	http://techibee.com
    REVISIONS
    * 2:42 PM 11/2/2021 scratch refactor borked CBH, fixed
    * 3:00 PM 1/14/2021 updated CBH, minor revisions & tweaking
    .DESCRIPTION
    get-DNSServers.ps1 - Get the DNS servers list of each IP enabled network connection
    .Parameter ComputerName
    Computer Name(s) from which you want to query the DNS server details. If this
    parameter is not used, the the script gets the DNS servers from local computer network adapaters.
    .EXAMPLE
    Get-DNSServers -ComputerName MYTESTPC21 ;
    Get the DNS servers information from a remote computer MYTESTPC21.
    .LINK
    https://github.com/tostka/verb-Network
    #>
    [cmdletbinding()]
    param (
      [parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
      [string[]] $ComputerName = $env:computername
    )
    begin {}
    process {
      foreach($Computer in $ComputerName) {
        Write-Verbose "Working on $Computer"
        if(Test-Connection -ComputerName $Computer -Count 1 -ea 0) {
          try {
            $Networks = Get-WmiObject -Class Win32_NetworkAdapterConfiguration  -Filter IPEnabled=TRUE  -ComputerName $Computer  -ErrorAction Stop ; 
          } catch {
            Write-Verbose "Failed to Query $Computer. Error details: $_"
            continue
          }
          foreach($Network in $Networks) {
            $DNSServers = $Network.DNSServerSearchOrder
            $NetworkName = $Network.Description
            If(!$DNSServers) {
              $PrimaryDNSServer = "Notset"
              $SecondaryDNSServer = "Notset"
            } elseif($DNSServers.count -eq 1) {
              $PrimaryDNSServer = $DNSServers[0]
              $SecondaryDNSServer = "Notset"
            } else {
              $PrimaryDNSServer = $DNSServers[0]
              $SecondaryDNSServer = $DNSServers[1]
            }
            If($network.DHCPEnabled) {
              $IsDHCPEnabled = $true
            }
            $OutputObj  = New-Object -Type PSObject
            $OutputObj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $Computer.ToUpper()
            $OutputObj | Add-Member -MemberType NoteProperty -Name PrimaryDNSServers -Value $PrimaryDNSServer
            $OutputObj | Add-Member -MemberType NoteProperty -Name SecondaryDNSServers -Value $SecondaryDNSServer
            $OutputObj | Add-Member -MemberType NoteProperty -Name IsDHCPEnabled -Value $IsDHCPEnabled
            $OutputObj | Add-Member -MemberType NoteProperty -Name NetworkName -Value $NetworkName
            $OutputObj
          }
        } else {
          Write-Verbose "$Computer not reachable"
        }
      }
    }
    end {} ; 
}

#*------^ get-DNSServers.ps1 ^------


#*------v get-IPSettings.ps1 v------
function get-IPSettings {
    <#
    .SYNOPSIS
    get-IPSettings.ps1 - retrieve DNSHostName, ServiceName(nic), DNSServerSearchOrder, IPAddress & DefaultIPGateway for localhost
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2020-04-17
    FileName    : get-IPSettings.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell,Internet,Download,File
    REVISIONS
    11:31 AM 4/17/2020 added CBH
    .DESCRIPTION
    get-IPSettings.ps1 - retrieve DNSHostName, ServiceName(nic), DNSServerSearchOrder, IPAddress & DefaultIPGateway for localhost
    by iteself it returns the set as the object $OPSpecs
    .PARAMETER  url
    Url to be downloaded
    .PARAMETER  DestinationName
    Full path to destiontion file for download
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    Selected.System.Management.ManagementObject
    .EXAMPLE
    get-IPSettings
    Return the complete set of values
    .EXAMPLE
    (get-ipsettings).IPAddress
    Return solely the IPAddress value
    .LINK
    #>
        [CmdletBinding()]
        PARAM ()
$IPSpecs = Get-WMIObject Win32_NetworkAdapterConfiguration -Computername localhost | where { $_.IPEnabled -match "True" } | Select -property DNSHostName, ServiceName, @{N = "DNSServerSearchOrder"; E = { "$($_.DNSServerSearchOrder)" } }, @{N = 'IPAddress'; E = { $_.IPAddress } }, @{N = 'DefaultIPGateway'; E = { $_.DefaultIPGateway } } ;
    return $IPSpecs;
}

#*------^ get-IPSettings.ps1 ^------


#*------v Get-NetIPConfigurationLegacy.ps1 v------
function Get-NetIPConfigurationLegacy {
    <#
    .SYNOPSIS
    Get-NetIPConfigurationLegacy.ps1 - Wrapper for ipconfig, as Legacy/alt version of PSv3+'s 'get-NetIPConfiguration' cmdlet (to my knowledge) by get-NetIPConfiguration.
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 20210114-1055AM
    FileName    : 
    License     : MIT License
    Copyright   : (c) 2021 Todd Kadrie
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,Network,Ipconfig,Legacy
    AddedCredit : REFERENCE
    AddedWebsite:	URL
    AddedTwitter:	URL
    REVISIONS
    * 2:29 PM 11/2/2021 # flip $nic[dot]description to alt syntax: I think it's breaking CBH get-help parsing. ; refactored cbh from scra6tch, trying to get the get-help support to work properly, I'll bet you it's: $nic[period]Description = (
    * 11:02 AM 1/14/2021 initial vers. Still needs to accomodate Wins Servers (aren't config'd on my box):
    Connection-specific DNS Suffix  . :
       Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
       Physical Address. . . . . . . . . : 00-50-56-9D-93-7E
       DHCP Enabled. . . . . . . . . . . : No
       Autoconfiguration Enabled . . . . : Yes
       IPv4 Address. . . . . . . . . . . : 170.92.16.155(Preferred)
       Subnet Mask . . . . . . . . . . . : 255.255.255.0
       Default Gateway . . . . . . . . . : 170.92.16.254
       DNS Servers . . . . . . . . . . . : 170.92.16.157
                                           170.92.48.249
       Primary WINS Server . . . . . . . : 170.92.17.42
       Secondary WINS Server . . . . . . : 170.92.16.44
       NetBIOS over Tcpip. . . . . . . . : Enabled
    .DESCRIPTION
    Get-NetIPConfigurationLegacy.ps1 - Wrapper for ipconfig, as Legacy/alt version of PSv3+'s 'get-NetIPConfiguration' cmdlet (to my knowledge) by get-NetIPConfiguration.
    .INPUT
    Does not accept pipeline input
    .OUTPUT
    System.Object[]
    .EXAMPLE
    $nics = Get-NetIPConfigurationLegacy ; 
    Return an object summarizing the specs on all nics
    .EXAMPLE
    $DNSServer = (Get-NetIPConfigurationLegacy | ?{$_.DNSServers -AND $_.AdapterName -like 'PPP*'}).DNSServers[0] ; 
    Retrieve the first configured 'DNS Servers' entry on the Adapter named like 'PPP*'
    .LINK
    https://github.com/tostka/verb-Network
    #>
    [CmdletBinding()]
    Param () ; 
    $nicprops = [ordered]@{
        AdapterName = "" ;
        ConnectionspecificDNSSuffix  = "" ;
        MediaState = "" ;
        Description = "" ;
        MacAddress = "" ;
        DHCPEnabled = "" ;
        AutoconfigurationEnabled = "" ;
        IPv4Address = @("") ;
        SubnetMask = "" ;
        DefaultGateway = "" ;
        DNSServers = @("") ;
        NetBIOSoverTcpip = "" ;
        ConnectionspecificDNSSuffixSearchList = @("") ;
        BindingOrder = 0 ; 
    } ;
    $nics = @(); 
    $rgxIPv4='\b(?:\d{1,3}\.){3}\d{1,3}\b' ; 
    $error.clear() ;
    TRY {
        $output = ipconfig /all ;
        $bindingorder = 0 ; 
        for($i=0; $i -le ($output.Count -1); $i++) {
            if ($output[$i] -match 'Connection-specific\sDNS\sSuffix\s\s\.'){
                if ($output[$i-1] -match 'Media\sState\s\.\s\.\s\.\s\.\s\.\s\.\s\.\s\.\s\.\s\.\s\.'){
                    $nic = New-Object -TypeName psobject -Property $nics2 ;            
                    $nic.AdapterName =($output[$i - 3] -split -split ": ")[0].trim()  ;            
                    $nic.MediaState = ($output[$i-1] -split -split ": ")[1].trim()  ;
                    if($nic.MediaState -eq 'Media disconnected'){$nic.MediaState = 'disconnected' } else { $nic.MediaState = 'connected'} ;
                    $nic.ConnectionspecificDNSSuffix  = ($output[$i] -split -split ": ")[1].trim()  ;
                    # flip [dot]description to alt syntax: I think it's breaking CBH get-help parsing.
                    $nic["Description"] = ($output[$i+1] -split -split ": ")[1].trim() ;
                    $nic.MacAddress = ($output[$i+2] -split -split ": ")[1].trim() ;
                    $nic.DHCPEnabled = [boolean](($output[$i+3] -split -split ": ")[1].trim() -eq 'Yes') ; 
                    $nic.AutoconfigurationEnabled = [boolean](($output[$i+4] -split -split ": ")[1].trim() -eq 'Yes') ;  ;
                    $nic.BindingOrder = [int]$bindingorder ; 
                    $bindingorder++ ; 
                    $nics += $nic ;
                } elseif ($output[$i+1] -match 'Description\s\.\s\.\s\.\s\.\s\.\s\.\s\.\s\.\s\.\s\.\s\.') {
                    $nic = New-Object -TypeName psobject -Property $nicprops ;
                    $nic.AdapterName = ($output[$i-2] -split -split ": ")[0].trim()  ;
                    $nic.ConnectionspecificDNSSuffix  = ($output[$i] -split -split ": ")[1].trim()  ;
                    $nic["Description"] = ($output[$i+1] -split -split ": ")[1].trim() ;
                    $nic.MacAddress = ($output[$i+2] -split -split ": ")[1].trim() ;
                    $nic.DHCPEnabled = [boolean](($output[$i+3] -split -split ": ")[1].trim() -eq 'Yes') ;
                    $nic.AutoconfigurationEnabled = ($output[$i+4] -split -split ": ")[1].trim() ;
                    $nic.AutoconfigurationEnabled = [boolean]($nic.AutoconfigurationEnabled -eq 'Yes') ; 
                    $nic.IPv4Address = ($output[$i+5] -split ": ")[1].trim().replace('(Preferred)','(Pref)') ;
                    $nic.SubnetMask = ($output[$i+6] -split ": ")[1].trim() ;
                    $nic.DefaultGateway = ($output[$i+7] -split ": ")[1].trim() ;
                    $nic.DNSServers = @(($output[$i+8] -split ": ")[1].trim()) ;
                    for($j=$i+9;; $j++) {
                        # walk list until NetBios line
                        if($output[$j] -notmatch 'NetBIOS\sover\sTcpip\.\s\.\s\.\s\.\s\.\s\.\s\.\s\.'){
                            $nic.DNSServers+=$output[$j].trim() ; 
                        } else {break}; 
                    } ; 
                    $i = $j ; 
                    $nic.NetBIOSoverTcpip = [boolean](($output[$i] -split ": ")[1].trim() -eq 'Enabled') ; 
                    if($output[$i+1] -match 'Connection-specific\sDNS\sSuffix\sSearch\sList'){
                        #walk list until first line *not* containing an ipaddr
                        $nic.ConnectionspecificDNSSuffixSearchList = @($output[$i+2].trim()) ;
                        for($j=$i+3;; $j++) {
                            if($output[$j].trim -match $rgxIPv4){
                                $nic.ConnectionspecificDNSSuffixSearchList+=$output[$j].trim() ;
                            } else {break}; 
                        } ; 
                    } ; 
                    $nic.BindingOrder = [int]$bindingorder ; 
                    $bindingorder++ ; 
                    $nics += $nic ;
                };
            } else {
                continue 
            } ;
        } ;
        $nics | sort bindingorder | write-output ; 
    } CATCH {
        Write-Warning "$(get-date -format 'HH:mm:ss'): Failed processing $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ;
        $smsg = "FULL ERROR TRAPPED (EXPLICIT CATCH BLOCK WOULD LOOK LIKE): } catch[$($Error[0].Exception.GetType().FullName)]{" ; 
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level ERROR } #Error|Warn|Debug 
        else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        Exit #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
    } ; 
}

#*------^ Get-NetIPConfigurationLegacy.ps1 ^------


#*------v get-NetworkClass.ps1 v------
function get-NetworkClass {
            <#
            .SYNOPSIS
            get-NetworkClass.ps1 - Use to determine the network class of a given IP address.
            .NOTES
            Version     : 1.0.0
            Author      : Todd Kadrie
            Website     : http://www.toddomation.com
            Twitter     : @tostka / http://twitter.com/tostka
            CreatedDate : 2021-08-16
            FileName    : get-NetworkClass.ps1
            License     : (none asserted)
            Copyright   : (none asserted)
            Github      : https://github.com/tostka/verb-Network
            Tags        : Powershell,Network,IP,Subnet
            AddedCredit : Mark Wragg
            AddedWebsite: https://github.com/markwragg
            AddedTwitter: 
            REVISIONS
            * 3:53 PM 1/10/2023 modified to return a [psobject] rather than a string ; 
            * 2:49 PM 11/2/2021 refactor/fixed CBH
            * 1:29 PM 8/12/2021 tweaked CBH, minor param inline help etc.
            * 9/10/2019 Mark Wragg posted rev (corresponds to PSG v1.1.14)
            .DESCRIPTION
            get-NetworkClass.ps1 - Use to determine the network class of a given IP address.
            .INPUTS
            Accepts pipeline input.
            .OUTPUTS
            System.Object
            .PARAMETER IP
            The IP address to test[-IP 192.168.0.1]
            .EXAMPLE
            '10.1.1.1' | Get-NetworkClass
            Result
            ------
            A
            .LINK
            https://github.com/tostka/verb-Network
            .LINK
            https://github.com/markwragg/PowerShell-Subnet/blob/master/Subnet/Public/Test-PrivateIP.ps1
            #>

            ###Requires -Modules DnsClient
            [CmdletBinding()]
            PARAM (
                [parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="The IP address to test[-IP 192.168.0.1]")]
                [string]$IP
            )
            BEGIN {
                ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
                $Verbose = ($VerbosePreference -eq 'Continue') ; 
            } ;  # BEG-E
            PROCESS {
                $class = switch ($IP.Split('.')[0]) {
                    { $_ -in 0..127 } { 'A' }
                    { $_ -in 128..191 } { 'B' }
                    { $_ -in 192..223 } { 'C' }
                    { $_ -in 224..239 } { 'D' }
                    { $_ -in 240..255 } { 'E' }
                } ;
            
            } ;  # PROC-E
            END {
                [pscustomobject]$class | write-output ; 
            } ; 
        }

#*------^ get-NetworkClass.ps1 ^------


#*------v get-NetworkSubnet.ps1 v------
function get-NetworkSubnet {
            <#
            .SYNOPSIS
            get-NetworkSubnet.ps1 - Returns subnet details for the local IP address, or a given network address and mask.
            .NOTES
            Version     : 1.0.0
            Author      : Todd Kadrie
            Website     :	http://www.toddomation.com
            Twitter     :	@tostka / http://twitter.com/tostka
            CreatedDate : 2020-
            FileName    : 
            License     : (none asserted)
            Copyright   : (none asserted)
            Github      : https://github.com/tostka/verb-XXX
            Tags        : Powershell
            AddedCredit : Mark Wragg (markwragg)
            AddedWebsite: https://github.com/markwragg
            AddedTwitter:	URL
            AddedCredit : Michael Samuel
            AddedWebsite: https://stackoverflow.com/users/12068738/michael-samuel
            AddedTwitter:	URL
            REVISIONS
            * 10:16 AM 1/9/2023 ren: get-NetworkSubnet -> get-NetworkSubnet (alias'd  orig name); 
            Tried overide of HostAddressCount .tostring to emit a formatted output (#,###): was blanking the member value, so flipped to a formatted variant property (and still using tostring() on receiving end, needed to do math on the result).
            * 4:08 PM 1/6/2023 adapt get-NetworkSubnet for ipv6 (seeing a ton of ranges in spf includes), used... 
            [Parsing IPv6 CIDR into first address and last address in Powershell - Stack Overflow - stackoverflow.com/](https://stackoverflow.com/questions/42118198/parsing-ipv6-cidr-into-first-address-and-last-address-in-powershell)
            ...Michael Samuel's Sep 15, 2019 at 2:03 sample ipv6 CIDR range calculator code (from comment on q above), and Ron Maupin's comment about diff between Ipv4 maxhosts cacl & ipv6:
            It really comes down to subtract the mask from 128, instead of ipv4's from 32. Math is the same otherwise.
            * 2:53 PM 11/2/2021 refactor/fix CBH
            * 12:33 PM 8/16/2021 renamed/added -Enumerate for prior -force, turned off autoexpansion (unless -enumerate), shifted to maxhosts calc to gen count, vs full expansion & count
            * 1:29 PM 8/12/2021 tweaked CBH, minor param inline help etc.
            * 1:29 PM 5/12/2021 Mark Wragg posted rev (corresponds to PSG v1.1.14)
            .DESCRIPTION
            get-NetworkSubnet.ps1 - Returns subnet details for the local IP address, or a given network address and mask.
            Use to get subnet details  for a given network address and mask, including network address, broadcast address, network class, address range, host addresses and host address count.
            .PARAMETER IP
            The network IP address or IP address with subnet mask via slash notation.
            .PARAMETER MaskBits
            The numerical representation of the subnet mask.
            .PARAMETER Enumerate
            Use to calc & return all host IP addresses regardless of the subnet size (skipped by default)).[-Eunumerate]
            .EXAMPLE
            get-NetworkSubnet 10.1.2.3/24
            Returns the subnet details for the specified network and mask, specified as a single string to the -IP parameter.
            .EXAMPLE
            get-NetworkSubnet 192.168.0.1 -MaskBits 23
            Returns the subnet details for the specified network and mask.
            .EXAMPLE
            get-NetworkSubnet
            Returns the subnet details for the current local IP.
            .EXAMPLE
            '10.1.2.3/24','10.1.2.4/24' | get-NetworkSubnet
            Returns the subnet details for two specified networks.    
            .LINK
            https://github.com/tostka/verb-Network
            .LINK
            https://github.com/markwragg/PowerShell-Subnet/blob/master/Subnet/Public/get-NetworkSubnet.ps1
            #>
            ##Requires -Modules DnsClient
            [CmdletBinding()]
            [Alias('get-Subnet')]
            PARAM (
                [parameter(ValueFromPipeline,HelpMessage="The network IP address or IP address with subnet mask via slash notation.[-IP 192.168.0.1]")]
                [string]$IP,
                [parameter(HelpMessage="The numerical representation of the subnet mask.[-MaskBits 23]")]
                [ValidateRange(0, 32)]
                [Alias('CIDR')]
                [int]$MaskBits,
                #[parameter(HelpMessage="Use to force the return of all host IP addresses regardless of the subnet size (skipped by default for subnets larger than /16).[-Force]")]
                #[switch]$Force
                [parameter(HelpMessage="Use to calc & return all host IP addresses regardless of the subnet size (skipped by default)).[-Eunumerate]")]
                [switch]$Enumerate
            )
            BEGIN {
                ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
                $Verbose = ($VerbosePreference -eq 'Continue') ; 

            } ;  # BEG-E
            PROCESS {

                if ($PSBoundParameters.ContainsKey('MaskBits')) { 
                    $Mask = $MaskBits  ; 
                } ; 

                if (-not $IP) { 
                    $LocalIP = (Get-NetIPAddress -Verbose:$($PSBoundParameters['Verbose'] -eq $true) | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.PrefixOrigin -ne 'WellKnown' }) ; 
                    $IP = $LocalIP.IPAddress ; 
                    If ($Mask -notin 0..32) { $Mask = $LocalIP.PrefixLength } ; 
                } ; 

                if ($IP -match '/\d') { 
                    #$IPandMask = $IP -Split '/'  ; 
                    $IP,$Mask = $IP -Split '/'  ; 
                } ; 
        
                $Class = Get-NetworkClass -IP $IP -Verbose:$($PSBoundParameters['Verbose'] -eq $true) ; 

                <# detecting ipv6 - core was written for ipv4...
                # ip4 CIDR range: 0 to 32
                # ip6 CIDR range: 0 to 128 - need to update to accomodate cidr ip6
                if($Address -like "*:*" -AND [int]$cidr[1] -ge 0 -AND [int]$cidr[1] -le 128){
                    # CIDR ip6
                    write-verbose "valid ipv6 CIDR subnet syntax" ;
                    $report.Valid = $true ; 
                } elseif([int]$cidr[1] -ge 0 -and [int]$cidr[1] -le 32){}
                #>

                if($IP -like "*:*" -AND [int]$Mask -ge 0 -AND [int]$Mask -le 128){
                    
                    # IPv6 has no classes, and reportedly IPv4 classes A, B and C have been deprecated since the publication of RFC 1519 in 1993. So fogetabout it
                    $Class = '(Classless)' ; 

                    $IPAddr = [ipaddress]::Parse($IP) ; 

                    # -------
                    #convert IPv6 CIDR to IPv6 range
                    
                    $AllAddresses = '::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
                    #$ipv6cidr = $_
                    $ipv6cidr = $IP,$MASK -join '/' ;  
                    $sw = [Diagnostics.Stopwatch]::StartNew();
                    if ($ipv6cidr -match "[0-9a-f:]+[:]" -and $_ -ne $AllAddresses) {
                        $EndBinaryArray = $StartBinaryArray = $null
                        $NetBits = $($ipv6cidr.Split("/").Replace('::', ''))[1]
                        #Convert To Binary
                        $BinaryEquivalent = $(($ipv6cidr.Split("/").Replace('::', ''))[0].Split(':').ForEach(
                                {
                                    $Decimal = '0x' + $_
                                    [Convert]::ToString($([Uint32]($Decimal)), 2).PadLeft(16, '0')
                                }
                            )
                        ) ; 
                        $BitLength = $BinaryEquivalent.length * 16 ; 
                        $HostId = $BinaryEquivalent -join "" ; 
                        #Adjust for NetMask
                        if ($Netbits -lt $BitLength) {
                            $Difference = $BitLength - $NetBits ; 
                            $HostnetworkId = $HostId -Replace ".{$Difference}$" ; 
                        } ; 
                        if ($Netbits -gt $BitLength) {
                            $Difference = $Netbits - $BitLength ; 
                            $HostnetworkId = [String]::Format("$HostId{0}", $("0" * $Difference)) ; 
                        } ; 
                        if ($Netbits -eq $BitLength) {
                            $HostnetworkId = $HostId ; 
                        } ; 
                        $BinaryStart = $HostnetworkId.PadRight(128, '0') ; 
                        $BinaryEnd = $HostnetworkId.PadRight(128, '1') ; 
                        #Convert Back to Decimal then to Hex
                        While ($BinaryStart) {
                            $Bytes, $BinaryStart = ([char[]]$BinaryStart).where( { $_ }, 'Split', 16) ; 
                            [Array]$StartBinaryArray += $Bytes -join '' ; 
                        } ; 
                        $finalstartip = $HexStartArray = ($StartBinaryArray.ForEach( { '{0:X4}' -f $([Convert]::ToInt32("$_", 2)) })) -join ":" ; 
                        While ($BinaryEnd) {
                            $Bytes, $BinaryEnd = ([char[]]$BinaryEnd).where( { $_ }, 'Split', 16) ; 
                            [Array]$EndBinaryArray += $Bytes -join '' ; 
                        } ; 
                        $finalendip = $HexEndArray = ($EndBinaryArray.ForEach( { '{0:X4}' -f $([Convert]::ToInt32("$_", 2)) })) -join ":" ; 
                        "[{0}] Start: {1} End: {2}" -f $ipv6cidr, $HexStartArray, $HexEndArray ; 
                        $ipv6range+=$finalstartip+'-'+$finalendip ; 
                    } ; 
                    if ($ipv6cidr -eq $AllAddresses) {
                        "[{0}] Start: {1} End: {2}" -f $ipv6cidr, '000:000:000:0000:0000:0000:0000', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff' ; 
                        $ipv6range+='000:000:000:0000:0000:0000:0000'+'-'+'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff' ; 
                    } ; 
                    $sw.Stop() ;
                    write-verbose ("Elapsed Time: {0:dd}d {0:hh}h {0:mm}m {0:ss}s {0:fff}ms" -f $sw.Elapsed) ; 

                    <#[ip - ipv6 number of Host Address - Network Engineering Stack Exchange - networkengineering.stackexchange.com/](https://networkengineering.stackexchange.com/questions/49094/ipv6-number-of-host-address)
                        
                        Just like with IPv4, you subtract the mask length from the size of the address 
                        (32 for IPv4, and 128 for IPv6) to get the number of host bits. Take two to the 
                        power of the number of host bits, and that is how many host addresses you have. 
                        With IPv4, you must subtract two from that number (except for /31 and /32 
                        networks) because you cannot use the network or broadcast addresses. With IPv6, 
                        you can actually use any address in the hosts addresses

                        The standard IPv6 network size is /64, so you will have 128 - 64 = 64 
                        host bits, and that is 2^64 = 18,446,744,073,709,551,616 host addresses in a 
                        standard 64-bit IPv6 network

                        cidr ipv6 subnet: 
                        $cidr = '2a01:4180:4051:0400::/64' ;
                        $ip,$mask = $cidr.split('/') ; 
                        [bigint]$maxhosts = [math]::Pow(2,(128-$Mask)) - 2 ;
                        # also subtracts the bcast & network addrs from the net pool, they're aren't assignable
                        write-verbose "echo with commas for legibility)
                        $maxhosts.tostring("#,###")
                        18,446,744,073,709,551,616 
                    #>
                    # fast way to get a count, wo full expansion
                    #IPV4: $maxHosts=[math]::Pow(2,(32-$Mask)) - 2 ; 
                    #IPV6:
                    $maxHosts=[math]::Pow(2,(128-$Mask)) - 2 ;

                    $NetworkAddr = [ipaddress]$finalstartip ; 
                    $BroadcastAddr = [ipaddress]$finalendip; 
                    $Range = "$NetworkAddr ~ $BroadcastAddr" ; 
                    $MaskAddr = "/$($MASK)" ; # just send back the CIDR mask, simpler
                    #$HostStartAddr = (Convert-IPtoInt64 -ip $NetworkAddr.ipaddresstostring) + 1 ; 
                    #$HostEndAddr = (Convert-IPtoInt64 -ip $broadcastaddr.ipaddresstostring) - 1 ; 

                    if ($Enumerate) {
                        write-warning "This function does not support fully eunmerating ipv6 subnets!" ; 

                    } ; 

                }else{
        
                    if ($Mask -notin 0..32) {
                        $Mask = switch ($Class) {
                            'A' { 8 }
                            'B' { 16 }
                            'C' { 24 }
                            #'Single' { 32 } # just marking 32 indicates a single IP, not used in code below
                            default { 
                                throw "Subnet mask size was not specified and could not be inferred because the address is Class $Class." 
                            }
                        } ; 
                        Write-Warning "Subnet mask size was not specified. Using default subnet size for a Class $Class network of /$Mask." ; 
                    } ; 

                    $IPAddr = [ipaddress]::Parse($IP) ; 
                    $MaskAddr = [ipaddress]::Parse((Convert-Int64toIP -int ([convert]::ToInt64(("1" * $Mask + "0" * (32 - $Mask)), 2)))) ; 

                    # fast way to get a count, wo full expansion
                    $maxHosts=[math]::Pow(2,(32-$Mask)) - 2 ; 

                    $NetworkAddr = [ipaddress]($MaskAddr.address -band $IPAddr.address); 
                    $BroadcastAddr = [ipaddress](Add-IntToIPv4Address -IP $NetworkAddr.IPAddressToString  -Integer ($maxHosts+1)) ; 
                    $Range = "$NetworkAddr ~ $BroadcastAddr" ; 
        
                    $HostStartAddr = (Convert-IPtoInt64 -ip $NetworkAddr.ipaddresstostring) + 1 ; 
                    $HostEndAddr = (Convert-IPtoInt64 -ip $broadcastaddr.ipaddresstostring) - 1 ; 
        

                    #if ($Mask -ge 16 -or $Force) {
                    if ($Enumerate) {
                        Write-Progress "Calcualting host addresses for $NetworkAddr/$Mask.." ; 
                        if ($Mask -ge 31) {
                            $HostAddresses = ,$NetworkAddr ; 
                            if ($Mask -eq 31) {
                                $HostAddresses += $BroadcastAddr ; 
                            } ; 

                            $HostAddressCount = $HostAddresses.Length ; 
                            $NetworkAddr = $null ; 
                            $BroadcastAddr = $null ; 
                        } else {
                            $HostAddresses = for ($i = $HostStartAddr; $i -le $HostEndAddr; $i++) {
                                Convert-Int64toIP -int $i ; 
                            }
                            $HostAddressCount = ($HostEndAddr - $HostStartAddr) + 1 ; 
                        }                     
                    } ; 
                    # more interested in the count than specific ips
                    <#else {
                        Write-Warning "Host address enumeration was not performed because it would take some time for a /$Mask subnet. `nUse -Force if you want it to occur." ; 
                    } ; 
                    #>
   
                } ;

                $report = [ordered]@{
                    IPAddress        = $IPAddr
                    MaskBits         = $Mask
                    NetworkAddress   = $NetworkAddr.IPAddressToString 
                    BroadcastAddress = $broadcastaddr.IPAddressToString
                    SubnetMask       = $MaskAddr
                    NetworkClass     = $Class
                    Range            = $Range
                } ; 
                if($Enumerate){
                    $report.add('HostAddresses',$HostAddresses) ;
                    $report.add('HostAddressCount',$HostAddressCount );
                    # back to add a formatted variant
                    $report.add('HostAddressCountString',$HostAddressCount.tostring("#,###") );
                } else {
                    $report.add('HostAddressCount',$maxHosts);
                    $report.add('HostAddressCountString',$maxHosts.tostring("#,###") );
                } ; ;
                <# for some reason overriding outstring completely blanks the hostaddresscount, if it's not an array, include it in the output, right of the |
                # have to capture and post-add-member the override, can't be done on the source hashtable
                $out = New-Object PSObject -Property $report ;
                # overload the HostAddressCount tostring with a formatted output, can't use tostring('#,###'), so use the -f with the .net formatting string for commas (0:N for 2decimal pts; 0:N0 for no decimals)
                #$out.HostAddressCount | Add-Member -MemberType ScriptMethod -Name ToString -Value {
                $out.HostAddressCount = $out.HostAddressCount | Add-Member -MemberType ScriptMethod -Name ToString -Value {
                    '{0:N0}' -f $_.HostAddressCount 
                } -Force -PassThru
                $out | write-output ;  
                #>
                New-Object PSObject -Property $report | write-output ; 
            } ; # PROC-E
            END {}
        }

#*------^ get-NetworkSubnet.ps1 ^------


#*------v Get-RestartInfo.ps1 v------
function Get-RestartInfo {
    <#
    .SYNOPSIS
    Get-RestartInfo.ps1 - Returns reboot / restart event log info for specified computer
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2022-
    FileName    : 
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell
    AddedCredit : Mike Kanakos/compwiz32 
    AddedWebsite: https://www.commandline.ninja
    AddedTwitter:	
    REVISIONS
    * 2:14 PM 8/22/2022 expanded, have it dynamically locate a manual reboot in last $MaxDay days; runs setuplog evts & summary, and app log msinstaller evts summar; added minior formatting updates & CBH expansion
    * CREATED: 2016-09-27
    * LASTEDIT: 2019-12-17
    * CREDIT: Biswajit Biswas
    .DESCRIPTION
    Queries the system event log and returns all log entries related to reboot & shutdown events (event ID 1074)
    MISC: Function based on script found at:
    https://social.technet.microsoft.com/wiki/contents/articles/17889.powershell-script-for-shutdownreboot-events-tracker.aspx
    .PARAMETER ComputerName
    Specifies a computer to add the users to. Multiple computers can be specified with commas and single quotes
    (-Computer 'Server01','Server02')
    .PARAMETER Credential
    Specifies the user you would like to run this function as
    .PARAMETER MaxDays
    Maximum days ago, that a manual reboot should be checked for (drives logic between manual reboot detection, and finding last reboot of *any* type).
    .EXAMPLE
    Get-RestartInfo
    This command will return all the shutdown/restart eventlog info for the local computer.
    PS C:\Scripts\> Get-RestartInfo
    Computer : localhost
    Date     : 1/7/2019 5:16:50 PM
    Action   : shutdown
    Reason   : No title for this reason could be found
    User     : NWTRADERS.MSFT\Tom_Brady
    Process  : C:\WINDOWS\system32\shutdown.exe (CRDNAB-PC06LY52)
    Comment  :
    Computer : localhost
    Date     : 1/4/2019 5:36:58 PM
    Action   : shutdown
    Reason   : No title for this reason could be found
    User     : NWTRADERS.MSFT\Tom_Brady
    Process  : C:\WINDOWS\system32\shutdown.exe (CRDNAB-PC06LY52)
    Comment  :
    Computer : localhost
    Date     : 1/4/2019 9:10:11 AM
    Action   : restart
    Reason   : Operating System: Upgrade (Planned)
    User     : NT AUTHORITY\SYSTEM
    Process  : C:\WINDOWS\servicing\TrustedInstaller.exe (CRDNAB-PC06LY52)
    Comment  :
    .EXAMPLE
    PS> Get-RestartInfo SERVER01 | Format-Table -AutoSize
            Computer    Date                  Action  Reason                                  User
            --------    ----                  ------  ------                                  ----
            SERVER01    12/15/2018 6:21:45 AM restart No title for this reason could be found NT AUTHORITY\SYSTEM
            SERVER01    11/17/2018 6:57:53 AM restart No title for this reason could be found NT AUTHORITY\SYSTEM
            SERVER01    9/29/2018  6:47:50 AM restart No title for this reason could be found NT AUTHORITY\SYSTEM
            Example using the default original code 
    .EXAMPLE
    PS> get-restartinfo -ComputerName 'SERVER1','SERVER2' -Verbose ;
        14:09:10:
        #*======v Get-RestartInfo:SERVER1 v======
        VERBOSE: (pulling reboot events System 1074)
        VERBOSE: Constructed structured query:
        <QueryList><Query Id="0" Path="system"><Select Path="system">*[(System/EventID=1074)]</Select></Query></QueryList>.
        Manual Reboot detected!
        TimeCreated  : 8/21/2022 10:02:26 PM
        ProviderName : USER32
        Id           : 1074
        Message      : The process C:\Windows\system32\winlogon.exe (SERVER1) has initiated the restart of computer SERVER1 on behalf of user DOMAIN\ACCOUNT for the following reason: No title for this reason could be found
                        Reason Code: 0x500ff
                        Shutdown Type: restart
                        Comment:
        VERBOSE: (calculating Start & End as -/+ 20 mins of newest 1074)
        14:09:12:
        #*------v $SetupEvts : v------
        VERBOSE: Constructed structured query:
        <QueryList><Query Id="0" Path="setup"><Select Path="setup">*[(System/TimeCreated[@SystemTime&gt;='2022-08-22T02:42:26.000Z' and @SystemTime&lt;='2022-08-22T03:22:26.000Z'])]</Select></Query></QueryList>.

        Date                  EventID Process                          Reason
        ----                  ------- -------                          ------
        8/21/2022 9:58:32 PM        4 Update for Windows (KB2775511)
        8/21/2022 9:58:33 PM        2 "Update for Windows (KB2775511)"
        8/21/2022 10:03:43 PM       2 KB2775511                        Installed


        14:09:12:
        #*------^ $SetupEvts : ^------
        14:09:12:
        #*------v $patchevts : v------
        14:09:12:Get-WinEvent w
        Name                           Value
        ----                           -----
        EndTime                        8/21/2022 10:22:26 PM
        LogName                        Application
        ProviderName                   {MsiInstaller, Microsoft-Windows-RestartManager}
        StartTime                      8/21/2022 9:42:26 PM
        id                             {1033, 1035, 1036, 1040...}
        VERBOSE: Found matching provider: MsiInstaller
        VERBOSE: The MsiInstaller provider writes events to the Application log.
        VERBOSE: Found matching provider: Microsoft-Windows-RestartManager
        VERBOSE: The Microsoft-Windows-RestartManager provider writes events to the Application log.
        VERBOSE: The Microsoft-Windows-RestartManager provider writes events to the Microsoft-Windows-RestartManager/Operational log.
        VERBOSE: Constructed structured query:
        <QueryList><Query Id="0" Path="application"><Select Path="application">*[System/Provider[@Name='msiinstaller' or @Name='microsoft-windows-restartmanager'] and (System/TimeCreated[@SystemTime&gt;='2022-08-22T02:42:26.000Z' and
        @SystemTime&lt;='2022-08-22T03:22:26.000Z']) and ((System/EventID=1033) or (System/EventID=1035) or (System/EventID=1036) or (System/EventID=1040) or (System/EventID=1042) or (System/EventID=100000) or (System/EventID=100001))]</Select></Query></QueryList>.
        14:09:13:PatchEvts 1035|1036: w
        Date                  EventID Process                      Reason Message
        ----                  ------- -------                      ------ -------
        8/21/2022 10:03:40 PM    1035 Configuration Manager Client 1033   Windows Installer reconfigured the product. Product Name: Configuration Manager Client. Product Version: 4.00.6487.2000. Product Language: 1033. Manufacturer: Microsoft Corporation. Reconfigura...

        14:09:13:
        #*------^ $patchevts : ^------
        14:09:13:
        #*======^ Get-RestartInfo:SERVER1 ^======
    Example running an array of computers, verbose, demo'ing typical manual reboot System setup & Application patch-related events summary
    .LINK
    https://github.com/tostka/verb-IO
    https://github.com/compwiz32
    #>
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [alias("Name","MachineName","Computer")]
        [string[]]
        $ComputerName = 'localhost',
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,
        [int]$MaxDays = 7 
    )
    
    BEGIN {
        ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
        $prpSU = 'Date','EventID','Process','Reason' ; 
    }
    PROCESS {
        Foreach($Computer in $ComputerName){
            
            $sBnr="`n#*======v $($CmdletName):$($Computer) v======" ; 
            write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($sBnr)" ;

            $Connection = Test-Connection $Computer -Quiet -Count 2
            If(!$Connection) {
                Write-Warning "Computer: $Computer appears to be offline!"
            } Else {
                write-verbose "(pulling reboot events System 1074)" ; 
                if(($sevts = Get-WinEvent -computername $computer -FilterHashtable @{logname = 'System'; id = 1074} -MaxEvents 1) -AND ((new-timespan -start $sevts.TimeCreated -End (get-date)).TotalDays -lt $MaxDays)){ 
                    <# TimeCreated  : 8/22/2022 2:09:47 AM
                    ProviderName : USER32
                    ProviderId   :
                    Id           : 1074
                    Message      : The process C:\Windows\system32\winlogon.exe (LYNMS640) has initiated the restart of computer SERVER o
                                    n behalf of user DOMAIN\ADMIN for the following reason: No title for this reason could be found
                                    Reason Code: 0x500ff
                                    Shutdown Type: restart
                                    Comment:
                    #>

                    write-host -foregroundcolor green "Manual Reboot detected!`n$(($sevts[0] | fl $prpRbt|out-string).trim())" ; 
                    write-verbose "(calculating Start & End as -/+ 20 mins of newest 1074)" ; 
                    $start = (get-date $sevts[0].TimeCreated).addminutes(-20) ; 
                    $end = (get-date $sevts[0].TimeCreated).addminutes(20) ;
                    $sBnrS="`n#*------v `$SetupEvts : v------" ; 
                    write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($sBnrS)" ;

                    $sfltr = @{ LogName = "Setup"; StartTime = $start; EndTime = $end ; };
            
                    #Get-WinEvent -ComputerName $computer -FilterHashtable @{logname = 'System'; id = 1074,6005,6006,6008}  |
                    $SetupEvts = Get-WinEvent -ComputerName $computer -FilterHashtable $sfltr | 
                        ForEach-Object {
                            $EventData = New-Object PSObject | Select-Object Date, EventID, User, Action, Reason, ReasonCode, Comment, Computer, Message, Process
                            $EventData.Date = $_.TimeCreated
                            $EventData.User = $_.Properties[6].Value
                            $EventData.Process = $_.Properties[0].Value
                            $EventData.Action = $_.Properties[4].Value
                            $EventData.Reason = $_.Properties[2].Value
                            $EventData.ReasonCode = $_.Properties[3].Value
                            $EventData.Comment = $_.Properties[5].Value
                            $EventData.Computer = $Computer
                            $EventData.EventID = $_.id
                            $EventData.Message = $_.Message
                            $EventData | Select-Object Date, Computer, EventID, Process, Action, User, Reason, Message ; 
                        } ; 
                
                

                    $SetupEvts |  sort Date | ft -a $prpSU ; 
                    write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;

                    $sBnrS="`n#*------v `$patchevts : v------" ; 
                    write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($sBnrS)" ;
                    # AP patch installer evts
                    [int32[]]$ID = @(1033,1035,1036,1040,1042,100000,100001) ; 
                    [string[]]$provs = @('MsiInstaller','Microsoft-Windows-RestartManager') ; 
                    $cfltr = @{ LogName = "Application"; StartTime = $start; EndTime = $end ; ProviderName = $provs; id = $id};
                    write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):Get-WinEvent w`n$(($cfltr|out-string).trim())" ; 
                    $patchevts = Get-WinEvent -ComputerName $computer -FilterHashtable $cfltr  | 
                        ForEach-Object {
                            $EventData = New-Object PSObject | Select-Object Date, EventID, User, Action, Reason, ReasonCode, Comment, Computer, Message, Process
                            $EventData.Date = $_.TimeCreated
                            $EventData.User = $_.Properties[6].Value
                            $EventData.Process = $_.Properties[0].Value
                            $EventData.Action = $_.Properties[4].Value
                            $EventData.Reason = $_.Properties[2].Value
                            $EventData.ReasonCode = $_.Properties[3].Value
                            $EventData.Comment = $_.Properties[5].Value
                            $EventData.Computer = $Computer
                            $EventData.EventID = $_.id
                            $EventData.Message = $_.Message
                            $EventData | Select-Object Date, Computer, EventID, Process, Action, User, Reason, Message ; 
                        } ; 
                    #$patchevts |?{$_.id -match '(1035|1036)'} ; 
                    $prpsAp = 'Date','EventID','Process','Reason','Message' ; 

                    #write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):PatchEvts 1035|1036: w`n$(($patchevts |?{$_.Eventid -match '(1035|1036)'}  |  sort Date | ft -a $prpsAp  |out-string).trim())`n" ; 
                    write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):PatchEvts 1035|1036: w`n$(($patchevts | sort Date | ft -a $prpsAp  |out-string).trim())`n" ; 
                    write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;

                } else { 
                    $sBnrS="`n#*------v `$bootevts : v------" ; 
                    write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($sBnrS)" ;
                    $bootEvents = Get-WinEvent -ComputerName $computer -FilterHashtable @{logname = 'System'; id = 1074,6005,6006,6008}  |
                        ForEach-Object {
                            $EventData = New-Object PSObject | Select-Object Date, EventID, User, Action, Reason, ReasonCode, Comment, Computer, Message, Process
                            $EventData.Date = $_.TimeCreated
                            $EventData.User = $_.Properties[6].Value
                            $EventData.Process = $_.Properties[0].Value
                            $EventData.Action = $_.Properties[4].Value
                            $EventData.Reason = $_.Properties[2].Value
                            $EventData.ReasonCode = $_.Properties[3].Value
                            $EventData.Comment = $_.Properties[5].Value
                            $EventData.Computer = $Computer
                            $EventData.EventID = $_.id
                            $EventData.Message = $_.Message
                            $EventData | Select-Object Date, Computer, EventID, Process, Action, User, Reason, Message ; 
                        } ; 
                    #$bootEvents |?{$_.id -match '(1035|1036)'} ; 
                    write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):bootEvents`n$(($bootEvents | sort Date | ft -a $prpSU |out-string).trim())`n" ; 
                    write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;


                } ; 
                

            } # if-E
            write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($sBnr.replace('=v','=^').replace('v=','^='))`n" ;
        } #end Foreach Computer Loop
    } #end Process block
}

#*------^ Get-RestartInfo.ps1 ^------


#*------v get-tsusers.ps1 v------
function get-tsUsers {
    <# 
    .SYNOPSIS
    get-tsUsers.ps1 - Simple easy-to-remember wrapper for quser remote termserve query tool. Takes the output from the quser program and parses this to PowerShell objects
    .NOTES
    Version     : 1.0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2021-07-13
    FileName    : get-tsUsers.ps1
    License     : (non-asserted)
    Copyright   : (non-asserted)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell
    AddedCredit : REFERENCE
    AddedWebsite: URL
    AddedCredit : Jaap Brasser
    AddedWebsite: http://www.jaapbrasser.com	
    AddedTwitter: URL
    REVISIONS   :
    * 1:27 PM 9/27/2021 converted to verb-Network function, ren'd get-tsUser -> get-tsUsers
    * 7:42 AM 11/11/2016 corrected script name typo in help example
    * 9:55 AM 10/24/2016 updated 
    * 8:12 AM 10/24/2016 minor tweaking, reworked pshelp 1tb formation etc
    * 9/23/2015 v1.2.1 jaap's posted version
    .DESCRIPTION
    get-tsUsers.ps1 - simple easy-to-remember wrapper for quser remote termserve query tool. 
    Actually, I just decided to save time and rename Jaap's prefab to my preferred name get-tsUsers.ps1.
    Necessary because Win2012R2 permanetly removed 99% of the TSC mgmt tools that we've RELIED ON for the last decade. 
    Yea, the typical admin wants to build a full blown citrix-mgmt equivalent like a termserve farm, just to figure output
    Who the *REDACTED* is logged into and hogging that rdp console you need. Pftftft!
    All this does is put the quser into a ps-compliant verb-noun format. 
    Note: quser.exe requires open port 455, jumpbox 7330 is *blocked*, so use RemPS to run it on the remote box directly:
    Invoke-Command -ComputerName 'REMOTECOMPUTER' -ScriptBlock {quser} ;
    Invoke-Command -ComputerName 'REMOTECOMPUTER' -ScriptBlock { logoff 2 } ;
    .PARAMETER ComputerName
    The string or array of string for which a query will be executed
    .INPUTS
    Accepts piped input.
    .OUTPUTS
    Returns user logon summaries to the pipeline
    .EXAMPLE
    PS> 'server01','server02' | get-tsusers
    Display the session information on server01 and server02, default output
    .EXAMPLE
    PS> get-tsusers SERVERNAME | sort logontime | format-table -auto ;  
    More useful session display in condensed table layout, with logontime sorted on actual dates (non-alphabetic).
    .EXAMPLE
    PS> get-tsusers SERVERNAME | select -expand username |%{  if($_ -match "^(\w*)s$"){ $X=$matches[1] ;get-recipient -id $x | select windowsema*,dist*};};
    Version that converts SID logons, to UID equiv (truncates trailing s), and retrieves matching mbx 
    .EXAMPLE
    PS> $tus = SERVERNAME,SERVERNAME2 | get-tsusers | ?{$_.username -eq 'LOGON'};
        $tus | ft -auto ;
    returns: 
    UserName ComputerName SessionName Id State IdleTime LogonTime         Error
    -------- ------------ ----------- -- ----- -------- ---------         -----
    LOGON    SERVERNAME               2  Disc  2+15:00  9/7/2021 12:03 PM
        # then demo the logoffs:
        $tus |%{"logoff $($_.id) /server:$($_.computername)"}
        # then log off the sessions remotely:
        returns: 
        logoff 2 /server:SERVERNAME
        # then exec the logoffs
        $tus |%{"Exec:logoff $($_.id) /server:$($_.computername):" ; logoff $($_.id) /server:$($_.computername) ;}
        # confirm cleared
        SERVERNAME,SERVERNAME2 | get-tsusers | ft -auto ;
    Demo use of ft -a for cleaner report, post-filtered Username, looped use of the logoff cmd to do targeted logoffs
    .EXAMPLE
    PS> Invoke-Command -ComputerName 'REMOTECOMPUTER' -ScriptBlock {quser} ;
        Invoke-Command -ComputerName 'REMOTECOMPUTER' -ScriptBlock { logoff 2 } ; 
    If port 455 is blocked, use RemPS to bypass the restruction:
    .LINK
    https://gallery.technet.microsoft.com/scriptcenter/Get-LoggedOnUser-Gathers-7cbe93ea
    #>
    [CmdletBinding()] 
    PARAM(
        [Parameter(Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [string[]]$ComputerName = 'localhost'  
    ) ; 
    BEGIN {
        $ErrorActionPreference = 'Stop' ; 
    } ;  # BEG-E
    PROCESS {
        # underlying cmdline: quser.exe /server xxxx
        foreach ($Computer in $ComputerName) {
            TRY {
                quser /server:$Computer 2>&1 | Select-Object -Skip 1 | ForEach-Object {
                    $CurrentLine = $_.Trim() -Replace '\s+',' ' -Split '\s' ; 
                    $HashProps = @{
                        UserName = $CurrentLine[0] ; 
                        ComputerName = $Computer ; 
                    } ; 

                    # If session is disconnected different fields will be selected
                    if ($CurrentLine[2] -eq 'Disc') {
                            $HashProps.SessionName = $null ; 
                            $HashProps.Id = $CurrentLine[1] ; 
                            $HashProps.State = $CurrentLine[2] ; 
                            $HashProps.IdleTime = $CurrentLine[3] ; 
                            $HashProps.LogonTime = $CurrentLine[4..6] -join ' ' ; 
                            $HashProps.LogonTime = $CurrentLine[4..($CurrentLine.GetUpperBound(0))] -join ' ' ; 
                    } else {
                            $HashProps.SessionName = $CurrentLine[1] ; 
                            $HashProps.Id = $CurrentLine[2] ; 
                            $HashProps.State = $CurrentLine[3] ; 
                            $HashProps.IdleTime = $CurrentLine[4] ; 
                            $HashProps.LogonTime = $CurrentLine[5..($CurrentLine.GetUpperBound(0))] -join ' ' ; 
                    } ; 

                    New-Object -TypeName PSCustomObject -Property $HashProps |
                    Select-Object -Property UserName,ComputerName,SessionName,Id,State,IdleTime,LogonTime,Error | write-output ; 
                } ; 
            } CATCH {
                New-Object -TypeName PSCustomObject -Property @{
                    ComputerName = $Computer ; 
                    Error = $_.Exception.Message
                } | Select-Object -Property UserName,ComputerName,SessionName,Id,State,IdleTime,LogonTime,Error | write-output ; 
            } ; 
        } ; 
    } ; # PROC-E  
}

#*------^ get-tsusers.ps1 ^------


#*------v get-WebTableTDO.ps1 v------
function get-WebTableTDO {
	<#
	.SYNOPSIS
	get-WebTableTDO.ps1 - Extract Tables from Web pages (via PowerShellInvoke-WebRequest)
	.NOTES
	Version     : 1.0.0
	Author      : Todd Kadrie
	Website     :	http://www.toddomation.com
	Twitter     :	@tostka / http://twitter.com/tostka
	CreatedDate : 2023-
	FileName    : 
	License     : MIT License
	Copyright   : (c) 2023 Todd Kadrie
	Github      : https://github.com/tostka/verb-XXX
	Tags        : Powershell
	AddedCredit : REFERENCE
	AddedWebsite:	URL
	AddedTwitter:	URL
	REVISIONS
    * 3:25 PM 11/27/2023 added expanded CBH examples
	* 9:25 AM 11/8/2023 ported over from ImportExcel:get-HtmlTable, which is adapted version of Lee Holmes' Get-WebRequestTable.ps1 demo code. 
	add: -Summary param, which dumps a short index#|Summary (leading textcontent[0..56] string)
	add: param detailed out, helpmessage, CBH
	add: strongly typed params
	* 10/12/23 dfinke's adapted variant of LH's original code into ImportExcel:get-htmlTabl(): [PowerShell Gallery | ImportExcel 7.8.6](https://www.powershellgallery.com/packages/ImportExcel/7.8.6) (adds 
	* 1/5/2015 LH's posted code from https://www.leeholmes.com/extracting-tables-from-powershells-invoke-webrequest/
	.DESCRIPTION
	get-WebTableTDO.ps1 - Extract Tables from Web pages (via PowerShellInvoke-WebRequest)

	Original code: [Lee Holmes | Extracting Tables from PowerShell's Invoke-WebRequest](https://www.leeholmes.com/extracting-tables-from-powershells-invoke-webrequest/)
	By way of dFinke's ImportExcel:get-HtmlTable v7.8.6 [ImportExcel/Public/Get-HtmlTable.ps1 at master Â· dfinke/ImportExcel Â· GitHub](https://github.com/dfinke/ImportExcel/blob/master/Public/Get-HtmlTable.ps1)
	
	.PARAMETER Url
	Specifies the Uniform Resource Identifier (URI) of the Internet resource to which the web request is sent. Enter a URI. This parameter supports HTTP, HTTPS, FTP, and FILE values.[-Url https://somewebserver/page]
	.PARAMETER TableIndex
	Index number of the table from target URL, to be returned (defaults 0)[-TableIndex 2]
	.PARAMETER Header
	Table header properties to be substituted for the resulting table
	.PARAMETER FirstDataRow
	Index Row of table from which to begin returning data (defaults 0)[-FirstDataRow 2]
	.PARAMETER Summary
	Indicates that the cmdlet should return a summary of all tables currently on the subject URL page.[-summary]
	.PARAMETER UseDefaultCredentials
	Indicates that the cmdlet uses the credentials of the current user to send the web request.
	.EXAMPLE
	PS> get-WebTableTDO -URL "https://en.wikipedia.org/wiki/List_of_Star_Trek:_The_Original_Series_episodes" -UseDefaultCredentials:$false ;
	OPTSAMPLEOUTPUT
	Default output, non specified -TableIndex, which returns contents of first table:
	.EXAMPLE
	PS> get-WebTableTDO -URL "https://en.wikipedia.org/wiki/List_of_Star_Trek:_The_Original_Series_episodes" ; 
	
        Season      Episodes
        ------      --------
        First aired Last aired
        1           29
        2           26
        3           24
    
	Default output, without explicit -TableIndex, outputs the 0'th/first table found on the url.
	.EXAMPLE
	PS> get-WebTableTDO -URL "https://en.wikipedia.org/wiki/List_of_Star_Trek:_The_Original_Series_episodes" -summary
	

            Index#  :       textContent
            ------  :       -----------
            1       :       SeasonEpisodesOriginally airedFirst airedLast aired
            2       :       TitleDirected byWritten byOriginal air date [23][25
            3       :       No.overallNo. inseasonTitleDirected byWritten byOri
            4       :       No.overallNo. inseasonTitleDirected byWritten byOri
            5       :       No.overallNo. inseasonTitleDirected byWritten byOri
            6       :       Pilots 01"The Cage" 02a"Where No Man Has Gone Befor
            7       :       Season 1 02b"Where No Man Has Gone Before" 03"The C
            8       :       Season 2 30"Catspaw" 31"Metamorphosis" 32"Friday's
            9       :       Season 3 56"Spectre of the Gun" 57"Elaan of Troyius
            10      :       This section needs additional citations for verific
            11      :       vteStar Trek: The Original Series episodesSeasons 1
            12      :       vteStar Trek: The Original SeriesEpisodesSeason 1 2
            13      :       vteStar TrekOutline Timeline Canon ListsTelevision
            14      :       Live-actionThe Original Series episodesThe Next Gen
            15      :       The Original SeriesThe Motion Picture The Wrath of
            16      :       CharactersA–F G–M N–S T–ZCrossoversConceptsGames Ko

	Retrieve tables list and echo simple heading summary of each table (useful to determine which -tableIndex # to use for specific table retrieval).
	.EXAMPLE
    PS> get-WebTableTDO -URL "https://en.wikipedia.org/wiki/List_of_Star_Trek:_The_Original_Series_episodes" -index 2 | format-table -a ;

        No.          No.in         Title                             Directedby                    Writtenby
        overall      season
        ------------ ------------- -----                             ----------                    ---------
        1            1             "The Man Trap"                    Marc Daniels                  George Clayton Johnson
        2            2             "Charlie X"                       Lawrence Dobkin               Story by : Gene Roddenberry...
        3            3             "Where No Man Has Gone Before"    James Goldstone               Samuel A. Peeples
       ...TRIMMED...
        27           27            "The Alternative Factor"          Gerd Oswald                   Don Ingalls
        28           28            "The City on the Edge of Forever" Joseph Pevney                 Harlan Ellison
        29           29            "Operation -- Annihilate!"        Herschel Daugherty            Steven W. Carabatsos

    Retrieve the index 2 ("third") table on the specified page, and output format-table -auto, to align data into columns.
    .EXAMPLE
    PS> $data = get-WebTableTDO -Url $Url -TableIndex $Index -Header $Header -FirstDataRow $FirstDataRow -UseDefaultCredentials: $UseDefaultCredentials
    PS> $data | Export-Excel $xlFile -Show -AutoSize ; 
    Demo conversion, with export-excel exporting xlsx, and opening ase temp file in Excel
    .LINK
	https://github.com/tostka/verb-Network
	.LINK
	https://github.com/dfinke/ImportExcel/blob/master/Public/Get-HtmlTable.ps1
	.LINK
	https://www.leeholmes.com/extracting-tables-from-powershells-invoke-webrequest/
	#>
	[CmdletBinding()]
	[Alias('Get-WebRequestTable')]
    PARAM(
        [Parameter(Mandatory=$true,HelpMessage='Specifies the Uniform Resource Identifier (URI) of the Internet resource to which the web request is sent. Enter a URI. This parameter supports HTTP, HTTPS, FTP, and FILE values.[-Url https://somewebserver/page]')]
			[System.Uri]$Url,
        [Parameter(HelpMessage='Index number of the table from target URL, to be returned (defaults 0)[-TableIndex 2]')]
        [Alias('index')]
			[int]$TableIndex=0,
        [Parameter(HelpMessage='Table header properties to be substituted for the resulting table')]
			$Header,
        [Parameter(HelpMessage='Index Row of table from which to begin returning data (defaults 0)[-FirstDataRow 2]')]
			[int]$FirstDataRow=0,
		[Parameter(HelpMessage='Indicates that the cmdlet should return a summary of all tables currently on the subject URL page.[-summary]')]
			[Switch]$Summary,
        [Parameter(HelpMessage='Indicates that the cmdlet uses the credentials of the current user to send the web request.')]
			[Switch]$UseDefaultCredentials
    ) ; 
    if ($PSVersionTable.PSVersion.Major -gt 5 -and -not (Get-Command ConvertFrom-Html -ErrorAction SilentlyContinue)) {
         # Invoke-WebRequest on .NET core doesn't have ParsedHtml so we need HtmlAgilityPack or similiar Justin Grote's PowerHTML wraps that nicely
         throw "This version of PowerShell needs the PowerHTML module to process HTML Tables."
    }

    $r = Invoke-WebRequest $Url -UseDefaultCredentials: $UseDefaultCredentials
    $propertyNames = $Header

    if ($PSVersionTable.PSVersion.Major -le 5) {
		if(-not $Summary){
			$table = $r.ParsedHtml.getElementsByTagName("table")[$TableIndex]
        } else { 
			write-verbose "Returning target URL table summary"
			if($tbls = $r.ParsedHtml.getElementsByTagName("table")){
				"Index#`t:`ttextContent"  | write-output ; 
				"------`t:`t-----------"  | write-output ; 
				$idx = 0 ; $tbls | foreach-object{ 
					$idx++ ; 
					"$($idx)`t:`t$(($_.textcontent)[0..50] -join '')"  | write-output ; 
				} ; 
				break ; 
			} else { 
			
			} ;
        } ; 
        $totalRows=@($table.rows).count

        for ($idx = $FirstDataRow; $idx -lt $totalRows; $idx++) {

            $row = $table.rows[$idx]
            $cells = @($row.cells)

            if(!$propertyNames) {
                if($cells[0].tagName -eq 'th') {
                    $propertyNames = @($cells | ForEach-Object {$_.innertext -replace ' ',''})
                } else  {
                    $propertyNames =  @(1..($cells.Count + 2) | Foreach-Object { "P$_" })
                }
                continue
            }

            $result = [ordered]@{}

            for($counter = 0; $counter -lt $cells.Count; $counter++) {
                $propertyName = $propertyNames[$counter]

                if(!$propertyName) { $propertyName= '[missing]'}
                $result.$propertyName= $cells[$counter].InnerText
            }

            [PSCustomObject]$result | write-output ; 
        }
    }
    else {
        $h    = ConvertFrom-Html -Content $r.Content
        if ($TableIndex -is [valuetype]) { $TableIndex += 1}
        $rows =    $h.SelectNodes("//table[$TableIndex]//tr")
        if (-not $rows) {Write-Warning "Could not find rows for `"//table[$TableIndex]`" in $Url ."}
        if ( -not  $propertyNames) {
            if (   $tableHeaders  = $rows[$FirstDataRow].SelectNodes("th")) {
                   $propertyNames = $tableHeaders.foreach({[System.Web.HttpUtility]::HtmlDecode( $_.innerText ) -replace '\W+','_' -replace '(\w)_+$','$1' })
                   $FirstDataRow += 1
            }
            else {
                   $c = 0
                   $propertyNames = $rows[$FirstDataRow].SelectNodes("td") | Foreach-Object { "P$c" ; $c ++ }
            }
        }
        Write-Verbose ("Property names: " + ($propertyNames -join ","))
        foreach ($n in $FirstDataRow..($rows.Count-1)) {
            $r      = $rows[$n].SelectNodes("td|th")
            if ($r -and $r.innerText -ne "" -and $r.count -gt $rows[$n].SelectNodes("th").count  ) {
                $c      = 0
                $newObj = [ordered]@{}
                foreach ($p in $propertyNames) {
                    $n  = $null
                    #Join descentandts for cases where the text in the cell is split (e.g with a <BR> ). We also want to remove HTML codes, trim and convert unicode minus sign to "-"
                    $cellText = $r[$c].Descendants().where({$_.NodeType -eq "Text"}).foreach({[System.Web.HttpUtility]::HtmlDecode( $_.innerText ).Trim()}) -Join " " -replace "\u2212","-"
                    if ([double]::TryParse($cellText, [ref]$n)) {$newObj[$p] = $n     }
                    else                                        {$newObj[$p] = $cellText }
                    $c ++
                }
                [pscustomObject]$newObj
            }
        }
    }
}

#*------^ get-WebTableTDO.ps1 ^------


#*------v get-whoami.ps1 v------
function get-whoami {
        <#
        .SYNOPSIS
        get-whoami.ps1 - assemble & return DOMAIN\LOGON string from local eVaris
        .NOTES
        Version     : 1.0.0
        Author      : Todd Kadrie
        Website     : http://www.toddomation.com
        Twitter     : @tostka / http://twitter.com/tostka
        CreatedDate : 2020-04-17
        FileName    : get-whoami.ps1
        License     : MIT License
        Copyright   : (c) 2020 Todd Kadrie
        Github      : https://github.com/tostka
        Tags        : Powershell,Internet,Download,File
        REVISIONS
        11:31 AM 4/17/2020 added CBH
        .DESCRIPTION
        get-whoami.ps1 - assemble & return DOMAIN\LOGON string from local eVaris
        .INPUTS
        None. Does not accepted piped input.
        .OUTPUTS
        System.String 
        .EXAMPLE
        $logon = get-whoami
        .LINK
        #>
        [CmdletBinding()]
        PARAM ()
        return (get-content env:\userdomain).ToLower() + "\" + (get-content env:\username).ToLower() ;
    }

#*------^ get-whoami.ps1 ^------


#*------v Invoke-BypassPaywall.ps1 v------
function Invoke-BypassPaywall{
    <#
    .SYNOPSIS
    Invoke-BypassPaywall.ps1 - open a webpage locally, bypassing a paywall
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2022-07-18
    FileName    : 
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/verb-network
    Tags        : Powershell
    AddedCredit : cybercastor
    AddedWebsite:	https://www.reddit.com/user/cybercastor
    AddedTwitter:	
    REVISIONS
    * 2:25 PM 7/20/2022 added/expanded CBH, spliced in his later posted new-RandomFilename dependant function.
    * 7/18/22 cybercastor posted rev
    .DESCRIPTION
    Invoke-BypassPaywall.ps1 - open a webpage locally, bypassing a paywall

    [Invoke-BypassPaywall](https://www.reddit.com/r/PowerShell/comments/w1ypp2/invokebypasspaywall_open_a_webpage_locally/)
    Invoke-BypassPaywall : open a webpage locally, bypassing a paywall
    Script Sharing
    Invoke-BypassPaywall : open a webpage locally, bypassing a paywall
    EDIT
    Update: for those who asked about the cmdlet New-RandomFilename . It's indeed a function I made in one of my module. sorry about that.
    Core module Miscellaneous.ps1
    .EXAMPLE
    PS> Invoke-BypassPaywall 'https://www.washingtonpost.com/world/2022/07/15/eu-russia-sanctions-ukraine/'
    washingtonpost.com demo
    .EXAMPLE
    PS> .Invoke-BypassPaywall 'https://www.theatlantic.com/ideas/archive/2022/07/russian-invasion-ukraine-democracy-changes/661451'
    theatlantic.com demo
    .LINK
    https://github.com/tostka/verb-XXX
    https://www.reddit.com/r/PowerShell/comments/w1ypp2/invokebypasspaywall_open_a_webpage_locally/
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="url", Position=0)]
        [string]$Url
    )
    BEGIN{
        if(-not (get-command New-RandomFilename)){
            #*------v Function New-RandomFilename v------
            function New-RandomFilename{
                <#
                SYNOPSIS
                New-RandomFilename.ps1 - Create a RandomFilename
                .NOTES
                Version     : 1.0.0
                Author      : Todd Kadrie
                Website     :	http://www.toddomation.com
                Twitter     :	@tostka / http://twitter.com/tostka
                CreatedDate : 2022-07-18
                FileName    : 
                License     : (none asserted)
                Copyright   : (none asserted)
                Github      : https://github.com/tostka/verb-io
                Tags        : Powershell
                AddedCredit : cybercastor
                AddedWebsite:	https://www.reddit.com/user/cybercastor
                AddedTwitter:	
                REVISIONS
                * 2:25 PM 7/20/2022 added/expanded CBH, spliced in his later posted new-RandomFilename dependant function ; subst ValidateRange for $maxlen tests.
                * 7/18/22 cybercastor posted rev
                .DESCRIPTION
                New-RandomFilename.ps1 - Create a new random filename

                [Invoke-BypassPaywall](https://www.reddit.com/r/PowerShell/comments/w1ypp2/invokebypasspaywall_open_a_webpage_locally/)
    
                .PARAMETER Path
                Host directory for new file (defaults `$ENV:Temp)
                .PARAMETER Extension
                Extension for new file (defaults 'tmp')
                .PARAMETER MaxLen
                Length of new file name (defaults 6, 4-36 range)
                .PARAMETER CreateFile
                Switch to create new empty file matching the specification.
                .PARAMETER CreateDirectory
                Switch to create a new hosting directory below `$Path,  with a random (guid) name (which will be 36chars long).
                .EXAMPLE
                PS> $fn = New-RandomFilename -Extension 'html'
                Create a new randomfilename with html ext
                .EXAMPLE
                PS> .Invoke-BypassPaywall 'https://www.theatlantic.com/ideas/archive/2022/07/russian-invasion-ukraine-democracy-changes/661451'
                theatlantic.com demo
                .LINK
                https://github.com/tostka/verb-IO
                https://www.reddit.com/r/PowerShell/comments/w1ypp2/invokebypasspaywall_open_a_webpage_locally/               
                #>
                [CmdletBinding(SupportsShouldProcess)]
                param(
                    [Parameter(Mandatory=$false)]
                    [string]$Path = "$ENV:Temp",
                    [Parameter(Mandatory=$false)]
                    [string]$Extension = 'tmp',
                    [Parameter(Mandatory=$false)]
                    [ValidateRange(4,36)]
                    [int]$MaxLen = 6,
                    [Parameter(Mandatory=$false)]
                    [switch]$CreateFile,
                    [Parameter(Mandatory=$false)]
                    [switch]$CreateDirectory
                )    
                try{
                    #if($MaxLen -lt 4){throw "MaxLen must be between 4 and 36"}
                    #if($MaxLen -gt 36){throw "MaxLen must be between 4 and 36"}
                    [string]$filepath = $Null
                    [string]$rname = (New-Guid).Guid
                    Write-Verbose "Generated Guid $rname"
                    [int]$rval = Get-Random -Minimum 0 -Maximum 9
                    Write-Verbose "Generated rval $rval"
                    [string]$rname = $rname.replace('-',"$rval")
                    Write-Verbose "replace rval $rname"
                    [string]$rname = $rname.SubString(0,$MaxLen) + '.' + $Extension
                    Write-Verbose "Generated file name $rname"
                    if($CreateDirectory -eq $true){
                        [string]$rdirname = (New-Guid).Guid
                        $newdir = Join-Path "$Path" $rdirname
                        Write-Verbose "CreateDirectory option: creating dir: $newdir"
                        $Null = New-Item -Path $newdir -ItemType "Directory" -Force -ErrorAction Ignore
                        $filepath = Join-Path "$newdir" "$rname"
                    }
                    $filepath = Join-Path "$Path" $rname
                    Write-Verbose "Generated filename: $filepath"

                    if($CreateFile -eq $true){
                        Write-Verbose "CreateFile option: creating file: $filepath"
                        $Null = New-Item -Path $filepath -ItemType "File" -Force -ErrorAction Ignore 
                    }
                    return $filepath
                
                }catch{
                    Show-ExceptionDetails $_ -ShowStack
                }
            }
            #*------^ END Function New-RandomFilename ^------
        } ; 
    } ; 
    PROCESS{
        $fn = New-RandomFilename -Extension 'html'
      
        Write-Host -n -f DarkRed "[BypassPaywall] " ; Write-Host -f DarkYellow "Invoke-WebRequest -Uri `"$Url`""

        $Content = Invoke-WebRequest -Uri "$Url"
        $sc = $Content.StatusCode    
        if($sc -eq 200){
            $cnt = $Content.Content
            Write-Host -n -f DarkRed "[BypassPaywall] " ; Write-Host -f DarkGreen "StatusCode $sc OK"
            Set-Content -Path "$fn" -Value "$cnt"
            Write-Host -n -f DarkRed "[BypassPaywall] " ; Write-Host -f DarkGreen "start-process $fn"
            start-process "$fn"
        }else{
            Write-Host -n -f DarkRed "[BypassPaywall] " ; Write-Host -f DarkYellow "ERROR StatusCode $sc"
        }
    } ; 
}

#*------^ Invoke-BypassPaywall.ps1 ^------


#*------v Invoke-SecurityDialog.ps1 v------
function Invoke-SecurityDialog {
    <#
    .SYNOPSIS
    Invoke-SecurityDialog.ps1 - Open Windows System Security dialog via powershell (for Password changes etc) - handy for nested RDP/TermServ sessions where normal Ctrl+Alt+Del/Ctrl+Alt+End(remote) triggers don't work (hotkey, remote triggers only outtermost RDP sec dlg). 
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2021-11-23
    FileName    : 
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell
    AddedCredit : 
    AddedWebsite: 
    AddedTwitter: 
    REVISIONS
    * 9:16 AM 11/23/2021 init
    .DESCRIPTION
    Invoke-SecurityDialog.ps1 - Open system Security dialog via powershell - handy for nested RDP/TermServ sessions where normal Ctrl+Alt+Del/Ctrl+Alt+End (remote) triggers don't work. 
    .INPUTS
    Accepts piped input
    .OUTPUTS
    None. Returns no objects or output (.NET types)
    .EXAMPLE
    PS> Invoke-SecurityDialog
    For the query of the corresponding TXT records in the DNS only the paramater name is needed
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://cloudbrothers.info/en/powershell-tip-resolve-spf/
    #>
    #Requires -Modules DnsClient
    [CmdletBinding()]
    PARAM () ; 
    write-host "Triggering local Windows Security Dialog (requires RAA)...`n(cmd.exe RAA, alt:`nexplorer.exe shell:::{2559a1f2-21d7-11d4-bdaf-00c04f60b9f0}`n)" ; 
    (New-Object -COM Shell.Application).WindowsSecurity() ;
}

#*------^ Invoke-SecurityDialog.ps1 ^------


#*------v Reconnect-PSR.ps1 v------
Function Reconnect-PSR {
    <#
    .SYNOPSIS
    Reconnect-PSR - Reconnect Remote Powershell connection
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-06-09
    FileName    : Reconnect-PSR.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell,Remote
    REVISIONS
    * 8:56 AM 6/9/2020 added to verb-Network
    * 2:51 PM 12/21/2016 add support for Connect-PSR -silent ; port to Powershell remote
    * 1:26 PM 12/9/2016 split no-session and reopen code, to suppress notfound errors ; cleaned up, add pshelp; implented and debugged as part of verb-PSR set; ported to local EMSRemote
    .DESCRIPTION
    .EXAMPLE
    .\Reconnect-PSR.ps1
    .EXAMPLE
    .\Reconnect-PSR.ps1
    .LINK
    #>
    [CmdletBinding()]
    [Alias('rPSR')]
    Param() ;
    $verbose = ($VerbosePreference -eq "Continue") ; 
    if(!$PSRSess){Connect-PSR -silent }
    elseif($PSRSess.state -ne 'Opened' -OR $PSRSess.Availability -ne 'Available' ) { Disconnect-PSR ;Start-Sleep -S 3;Connect-PSR -silent ;} ;
}

#*------^ Reconnect-PSR.ps1 ^------


#*------v Resolve-DNSLegacy.ps1 v------
function Resolve-DNSLegacy.ps1{
    <#
    .SYNOPSIS
    Resolve-DNSLegacy.ps1 - 1LINEDESC
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2021-01-13
    FileName    : Resolve-DNSLegacy.ps1
    License     : (none specified)
    Copyright   : (none specified)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,DNS,Network
    AddedCredit :  i255d
    AddedWebsite:	https://community.idera.com/database-tools/powershell/ask_the_experts/f/powershell_for_windows-12/22127/powershell-wrapper-for-nslookup-with-error-handling-basically-nslookup-on-steroids
    REVISIONS
    * 3:02 PM 11/2/2021 refactor/fix cbh
    * 9:23 AM 1/13/2021 TSK:updated CBH, reformated & minor tweaks
    * 2015 orig posted copy
    .DESCRIPTION
    Get FQDN and IP for a single server, or a list of servers, specify the Ip of the DNS server otherwise it defaults to the 1st DNS Server on the PPP* nic, and then to the first non-PPP* nic.
    I tweaked this version to leverage my Get-NetIPConfigurationLegacy ipconfig /all wrapper fuct, to return the DNS servers on the PPP* (VPN in my case) nic, or the non-PPP* nic, by preference.
    Posted by i255d to Idera Forums (https://community.idera.com/database-tools/powershell/ask_the_experts/f/powershell_for_windows-12/22127/powershell-wrapper-for-nslookup-with-error-handling-basically-nslookup-on-steroids), tagged 'over 6 yrs ago' (in 2021 = ~2015) ; 
    Updated/tweaked by TSK 2021.
    .PARAMETER ComputerName
    Computername
    .PARAMETER DNSServerIP
    DNS Server IP Address
    .PARAMETER ErrorFile
    Path to output file for results
    .EXAMPLE
    PS> Get-Content C:\serverlist.txt | Resolve-DNSLegacy.ps1 | Export-CSV C:\ServerList.csv
    Process serverlist from pipelined txt file, and export to serverlist.
    .LINK
    https://github.com/tostka/verb-Network
    #>
    [CmdletBinding()]
    PARAM(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=0)]
        [alias("Computer")]
        [ValidateLength(3,35)]
        [string[]]$Computername,
        [Parameter(Position=1)]
        [string]$DNSServerIP,
        [Parameter(Position=2)]
        [string] $ErrorFile
    )
    BEGIN{
        # if not specified, move it to random temp file
        if(!$ErrorFile -OR (!(test-path $ErrorFile))){
            $ErrorFile = [System.IO.Path]::GetTempFileName().replace('.tmp','.txt') ;
        } ; 
        if(!$DNSServerIP){
            $nics = Get-NetIPConfigurationLegacy ; 
            if($DNSServerIP = ($nics | ?{$_.DNSServers -AND $_.AdapterName -like 'PPP*'}).DNSServers[0]){write-verbose "(Using PPP* Nic DNSServerIP:$($DNSServerIP)"}  ; 
        
            elseif($DNSServerIP = ($nics | ?{$_.DNSServers -AND $_.AdapterName -notlike 'PPP*'}).DNSServers[0]){
                write-verbose "(Using first non-PPP* Nic DNSServerIP:$($DNSServerIP)"
                if($DNSServerIP -is [system.array]){write-warning "Returned multiple DNS server IPs!"
            }} 
            else { throw "Get-NetIPConfigurationLegacy:No matchable DNS Server found"} ; 
        } ; 
        $server = ""
        $IP = ""
        $object = [pscustomobject]@{}
    }#end begin
    PROCESS{
        foreach($computer in $Computername){
            $Lookup = nslookup $computer $DNSServerIP 2> $ErrorFile
                $Lookup | Where{$_} | foreach{
                    if(($Error[1].Exception.Message -split ':')[1] -eq ' Non-existent domain'){
                        $object | Add-Member ComputeName $computer
                        $object | Add-Member IpAddress "None"
                        $object
                        $object = [pscustomobject]@{}
                        Write-Error "End" 2>> $ErrorFile
                    }elseif($_ -match "^Name:\s+(?<name>.+)"){
                            $server = $Matches.name
                    }elseif($_ -match "$DNSServerIP"){
                    }elseif($_ -match "^Address:\s+(?<ipaddress>.+)"){
                            $IP = $Matches.ipaddress
                    }#if
                }#foreach
            $Lookup = ''
            $object | Add-Member ComputeName $server
            $object | Add-Member IpAddress $ip
            if($object.ComputeName){$object| write-output }
            $server = ''
            $ip = ''
            $object = [pscustomobject]@{}
        } ; 
    } ; #end process
    END{} ; 
}

#*------^ Resolve-DNSLegacy.ps1 ^------


#*------v Resolve-SPFRecord.ps1 v------
function Resolve-SPFRecord {
    <#
    .SYNOPSIS
    resolve-SPFRecord.ps1 - query & parse/validate the current SPF DNS records, including all included services
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2020-
    FileName    : 
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell
    AddedCredit : Fabian Bader
    AddedWebsite: https://cloudbrothers.info/en/
    AddedTwitter: 
    REVISIONS
    * 3:46 PM 11/2/2021 flipped some echos to wv ;  CBH minor cleanup
    * 2:28 PM 8/16/2021 spliced in simple summarize of ipv4 CIDR subnets (range, # usable ips in range etc), leveraging combo of Mark Wragg get-subnet() and a few bits from Brian Farnsworth's Get-IPv4Subnet() (which pulls summaries wo fully enumeratinfg every ip - much faster)
    * 12:25 PM 8/13/2021Add ip4/6 syntax testing/simple validation (via 
    test-IpAddressCidrRange, sourced in verb-network, local deferral copy) ; 
    extended verbose echos ; add case for version spec & [~+-?]all (suppress spurious 
    warnings) ; expanded macro/explanation mechanism warnings (non-invalid: just script 
    doesn't support their expansion/validation). Added examples for grouping referrer and 
    dumping summaries per referrer. 
    * 1:29 PM 8/12/2021 updated format to OTB, added CBH, minor param inline help etc.
    * 1:29 PM 4/12/2021 Fabian Bader posted rev
    .DESCRIPTION
    resolve-SPFRecord.ps1 - query & parse/validate the current SPF DNS records, including all included services. 
    
    From [PowerShell Tip: Resolve SPF Records - Cloudbrothers - cloudbrothers.info/](https://cloudbrothers.info/en/powershell-tip-resolve-spf/):
    ## Supported SPF directives and functions: 
     - include
     - mx
     - a
     - ip4 und ip6
     - redirect
     - Warning for too many include entries
    ## Not supported: 
     - exp
     - Makros
     - Usage
     
    Optionally, the Server (DNS) parameter can be used. Defaults to cloudflare resolver: 1.1.1.1 (secondary is 1.0.0.1)
    documented here: [Introducing DNS Resolver, 1.1.1.1 (not a joke) - blog.cloudflare.com/](https://blog.cloudflare.com/dns-resolver-1-1-1-1/)
    
    Specify explicit DNS server to be queried. Useful, if you want to test the DNS changes directly on your own root name server shortly after the update, or if there are restrictions on which DNS server your client is allowed to query.
    .PARAMETER Name
    Domain Name[-Name some.tld]
    .PARAMETER Server
    DNS Server to use (defaults to Cloudflare public resolver 1.1.1.1)[-Server 1.0.0.1]
    .PARAMETER Referrer
    if called nested provide a referrer to build valid objects[-Referrer referrer]
    .INPUTS
    Accepts piped input
    .OUTPUTS
    None. Returns no objects or output (.NET types)
    System.Boolean
    [| get-member the output to see what .NET obj TypeName is returned, to use here]
    .EXAMPLE
    PS> Resolve-SPFRecord -Name domainname.tld
    For the query of the corresponding TXT records in the DNS only the paramater name is needed
    .EXAMPLE
    PS> Resolve-SPFRecord -Name domainname.tld | ft
    It is recommended to output the result with 'Format-Table' for better readability.
    .EXAMPLE
    PS> $spfs = Resolve-SPFRecord -name domain.com ; 
    # group referrers
    $spfs | group referrer | ft -auto count,name ;
    output: 
    Count Name                      
    ----- ----                      
        3                           
        10 domain.com                  
        9 spf.protection.outlook.com
    # output ip summary for a specific referrer
    $spfs|?{$_.Referrer  -eq 'spf.protection.outlook.com'} | ft -auto ipaddress,referrer ; 
    output: 
    IPAddress                Referrer                  
    ---------                --------                  
    51.4.72.0/24             spf.protection.outlook.com

    Broader example, group/profile returned referrers, dump summaries on referrers
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://cloudbrothers.info/en/powershell-tip-resolve-spf/
    #>
    #Requires -Modules DnsClient
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 1,HelpMessage="Domain Name[-Name some.tld]")]
        [string]$Name,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true,Position = 2,HelpMessage="DNS Server to use (defaults to Cloudflare public resolver 1.1.1.1)[-Server 1.0.0.1]")]
        [string]$Server = "1.1.1.1",
        [Parameter(Mandatory = $false,HelpMessage="If called nested provide a referrer to build valid objects[-Referrer referrer]")]
        [string]$Referrer
    ) ; 
    BEGIN {
        class SPFRecord {
            [string] $SPFSourceDomain
            [string] $IPAddress
            [string] $Referrer
            [string] $Qualifier
            [bool] $Include
            # Constructor: Creates a new SPFRecord object, with a specified IPAddress
            SPFRecord ([string] $IPAddress) {
                $this.IPAddress = $IPAddress
            }
            # Constructor: Creates a new SPFRecord object, with a specified IPAddress and DNSName
            SPFRecord ([string] $IPAddress, [String] $DNSName) {
                $this.IPAddress = $IPAddress
                $this.SPFSourceDomain = $DNSName
            }
            # Constructor: Creates a new SPFRecord object, with a specified IPAddress and DNSName and
            SPFRecord ([string] $IPAddress, [String] $DNSName, [String] $Qualifier) {
                $this.IPAddress = $IPAddress
                $this.SPFSourceDomain = $DNSName
                $this.Qualifier = $Qualifier
            }
        } ; 
        #*------v Function test-IpAddressCidrRange v------
        if(!(get-command  test-IpAddressCidrRange)){
            function test-IpAddressCidrRange{
                <#
                .SYNOPSIS
                test-IpAddressCidrRange.ps1 - evaluate an IP Address specification as either IPAddress|CidrRange|IPAddressRange
                .NOTES
                Version     : 1.0.0
                Author      : Todd Kadrie
                Website     : http://www.toddomation.com
                Twitter     : @tostka / http://twitter.com/tostka
                CreatedDate : 2020-
                FileName    : 
                License     : (none asserted)
                Copyright   : (none asserted)
                Github      : https://github.com/tostka/verb-Network
                Tags        : Powershell,Network,IPAddress
                AddedCredit : cyruslab (from public forum post, cited as 'https://powershell.org/forums/topic/detecting-if-ip-address-entered/', now gone)
                AddedWebsite: https://cyruslab.net/2018/04/26/powershellcheck-valid-ip-address-subnet-or-ip-address-range/
                AddedTwitter: 
                REVISIONS
                * 10:51 AM 8/13/2021 added to verb-network ; updated base code to work with ip6 CIDR notation ; fixed 
                bug in if/then comparisions: need to coerce subnet mask to integer, for 
                comparison (esp under ip6) ; converted to function updated format to OTB, added 
                CBH, minor param inline help etc. 
                * 4/26/2016 cyruslab posted ps code from earlier unattributed powershell.org forums post (non-function)
                .DESCRIPTION
                test-IpAddressCidrRange.ps1 - evaluate an IP Address specification as either IPAddress|CidrRange|IPAddressRange
                .PARAMETER Address
                IPAddress, CIDR notation, or IP range specification to be tested[-Address 192.168.0.1]
                .INPUTS
                Does not accept piped input
                .OUTPUTS
                System.SystemObject with Type (IPAddress|CIDRRange|IPAddressRange) and boolean Valid properties
                .EXAMPLE
                PS> $ret= test-IpAddressCidrRange -Address 192.168.1.1 ;
                if(($ret.type -eq 'IPAddress' -AND $ret.valid){'Valid IP'} ; 
                Test IP Address
                .EXAMPLE
                PS> $ret= test-IpAddressCidrRange -Address 91.198.224.29/32
                if(( $ret.type -eq 'CIDRRange' -AND $ret.valid){'Valid CIDR'} ; 
                Test CIDR notation block
                .EXAMPLE
                PS> $ret= test-IpAddressCidrRange -Address '192.168.0.1-192.168.0.200' ;
                if($ret.type -eq 'IPAddressRange' -AND $ret.valid){'Valid CIDR'} ; 
                Test IP Address range
                .LINK
                https://github.com/tostka/verb-Network
                .LINK
                https://cyruslab.net/2018/04/26/powershellcheck-valid-ip-address-subnet-or-ip-address-range/
                #>            
                [CmdletBinding()]
                PARAM(
                    [Parameter(HelpMessage="IPAddress, CIDR notation, or IP range specification to be tested[-Address 192.168.0.1]")]
                    $Address
                ) ;
                $isIPAddr = ($Address -as [IPaddress]) -as [Bool] ;
                $report=[ordered]@{
                    Type = $null ;
                    Valid = $false ;
                } ;
                write-verbose "specified Address:$($Address)" ;
                if($isIPAddr){
                    write-verbose "Valid ip address" ;
                    $report.type = 'IPAddress' ;
                    $report.Valid = $true ; 
                } elseif($Address -like "*/*" -or $Address -like "*-*"){
                    $cidr = $Address.split("/") ;
                    if($cidr){ 
                        $report.type = 'CIDRRange'
                    } ;
                    # ip4 CIDR range: 0 to 32
                    # ip6 CIDR range: 0 to 128 - need to update to accomodate cidr ip6
                    if($Address -like "*:*" -AND [int]$cidr[1] -ge 0 -AND [int]$cidr[1] -le 128){
                        # CIDR ip6
                        write-verbose "valid ipv6 CIDR subnet syntax" ;
                        $report.Valid = $true ; 
                    } elseif([int]$cidr[1] -ge 0 -and [int]$cidr[1] -le 32){
                        write-verbose "valid ipv4 CIDR subnet syntax" ;
                        $report.Valid = $true ; 
                    }elseif($Address -like "*-*"){
                        $report.type = 'IPAddressRange' ; 
                        $ip = $Address.split("-") ; 
                        $ip1 = $ip[0] -as [IPaddress] -as [Bool] ; 
                        $ip2 = $ip[1] -as [IPaddress] -as [Bool] ; 
                        if($ip -and $ip){
                            write-verbose "valid ip address range" ;
                            $report.Valid = $true ;
                        } else{
                            write-verbose "invalid range" ;
                            $report.Valid = $false ;
                        } ;
                    } else {
                        $report.type = 'INVALID' ;
                        $report.Valid = $false ;
                        write-warning "invalid subnet" ;
                    } ; 
                }else{
                    $report.type = 'INVALID' ;
                    $report.Valid = $false ;
                    write-warning "not valid address" ;
                } ;
                New-Object PSObject -Property $report | write-output ;   
            } ; 
        } ;
        #*------^ END Function test-IpAddressCidrRange ^------

        ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
        $Verbose = ($VerbosePreference -eq 'Continue') ; 
    } ; 
    PROCESS {
        # Keep track of number of DNS queries
        # DNS Lookup Limit = 10
        # https://tools.ietf.org/html/rfc7208#section-4.6.4
        # Query DNS Record
        write-verbose "(pulling TXT DNS records for $($Name) from server:$($Server))" ;
        $DNSRecords = Resolve-DnsName -Server $Server -Name $Name -Type TXT ; 
        # Check SPF record
        $SPFRecord = $DNSRecords | Where-Object { $_.Strings -match "^v=spf1" } ; 
        # Validate SPF record
        $SPFCount = ($SPFRecord | Measure-Object).Count ; 
        write-verbose "(returned $($SPFCount) spf records)" ; 
        if ( $SPFCount -eq 0) {
            # If there is no error show an error
            Write-Error "No SPF record found for `"$Name`""
        } elseif ( $SPFCount -ge 2 ) {
            # Multiple DNS Records are not allowed
            # https://tools.ietf.org/html/rfc7208#section-3.2
            Write-Error "There is more than one SPF for domain `"$Name`"" ; 
        } else {
            # Multiple Strings in a Single DNS Record
            # https://tools.ietf.org/html/rfc7208#section-3.3
            $SPFString = $SPFRecord.Strings -join '' ; 
            # Split the directives at the whitespace
            $SPFDirectives = $SPFString -split " " ; 

            # Check for a redirect
            if ( $SPFDirectives -match "redirect" ) {
                $RedirectRecord = $SPFDirectives -match "redirect" -replace "redirect=" ; 
                Write-Verbose "[REDIRECT]`t$RedirectRecord" ; 
                # Follow the include and resolve the include
                Resolve-SPFRecord -Name "$RedirectRecord" -Server $Server -Referrer $Name ; 
            } else {
                # Extract the qualifier
                $Qualifier = switch ( $SPFDirectives -match "^[+-?~]all$" -replace "all" ) {
                    "+" { "pass" }
                    "-" { "fail" }
                    "~" { "softfail" }
                    "?" { "neutral" }
                } ; 
                write-verbose "detected Qualifier:$($Qualifier)" ; 
                write-host -foregroundcolor green "Processing SPFDirectives:`n$(($SPFDirectives|out-string).trim())" ; 
                $ReturnValues = foreach ($SPFDirective in $SPFDirectives) {
                    switch -Regex ($SPFDirective) {
                        # 9:59 AM 8/13/2021 add case for version spec, otherwise it throws:WARNING: [v=spf1]	 Unknown directive
                        "v=spf\d" {
                            write-verbose "Spf Version: $($SPFDirective)" ;
                        } 
                        # 9:59 AM 8/13/2021 add a case for all mechanism, or throws: WARNING: [~all]	 Unknown directive
                        "[~+-?]all" {
                            switch ($Qualifier){
                                "pass" {write-verbose "all PASS mechanism: $($SPFDirective)"}
                                "fail" {write-verbose "all FAIL mechanism: $($SPFDirective)"}
                                "softfail" {write-verbose "all SOFTFAIL mechanism: $($SPFDirective)"}
                                "neutral" {write-verbose "all NEUTRAL mechanism: $($SPFDirective)"}
                            } ;
                        } 
                        "%[{%-_]" {
                            Write-Warning "[$_]`tMacro sytax detected:Macros validation/expansion is not supported by this function. For more information, see https://tools.ietf.org/html/rfc7208#section-7" ;  
                            Continue ; 
                        }
                        "^exp:.*$" {
                            Write-Warning "[$_]`texp: Explanation syntax detected:Explanation validation/expansion is not supported by this function. For more information, see https://tools.ietf.org/html/rfc7208#section-6.2" ; 
                            Continue ; 
                        }
                        '^include:.*$' {
                            # Follow the include and resolve the include
                            Write-Verbose "[include]`tSPF entry: $SPFDirective (recursing)" ; 
                            Resolve-SPFRecord -Name ( $SPFDirective -replace "^include:" ) -Server $Server -Referrer $Name ; 
                        }
                        '^ip[46]:.*$' {
                            Write-Verbose "[IP]`tSPF entry: $SPFDirective" ; 
                            $SPFObject = [SPFRecord]::New( ($SPFDirective -replace "^ip[46]:"), $Name, $Qualifier) ; 
                            if ( $PSBoundParameters.ContainsKey('Referrer') ) {
                                $SPFObject.Referrer = $Referrer ; 
                                $SPFObject.Include = $true ; 
                            } ; 

                            # validate ip spec (IPAddress|CIDRRange|IPAddressRange) and boolean Valid properties
                            
                            $ret= test-IpAddressCidrRange -Address $SPFDirective.replace('ip4:','').replace('ip6:','') ;
                            #$type = [regex]::match($ret.type ,'(IPAddress|CIDRRange)').captures[0].groups[0].value
                            if($ret.valid){
                                if($ret.type -match '(IPAddress|CIDRRange)'){
                                    write-verbose "(Validated ip4: entry format is:$($matches[0]))" 
                                    if($ret.type -eq 'CIDRRange'){
                                        $subnet = Get-Subnet -ip $SPFDirective.replace('ip4:','').replace('ip6:','') -verbose:$($verbose);
                                        if($subnet){
                                            if($subnet.MaskBits -eq 32){
                                                $smsg = "$($subnet.ipaddress)/$($subnet.MaskBits) is a single IP address (/32)" ;
                                            } elseif($subnet.HostAddressCount -eq 0){
                                                $smsg = "$($subnet.ipaddress)/$($subnet.MaskBits) is Class$($subnet.NetworkClass) spanning $($subnet.HostAddressCount+1) usable addresses on range:$($subnet.Range)" ;
                                            }  else { 
                                                $smsg = "$($subnet.ipaddress)/$($subnet.MaskBits) is Class$($subnet.NetworkClass) spanning $($subnet.HostAddressCount) usable addresses on range:$($subnet.Range)" ;
                                            } ; 
                                        } elseif($SPFDirective -like 'ip6:*') { 
                                            $smsg = "($($SPFDirective) is an ipv6 CIDR Range: This script does not support summarizing ipv6 Ranges)" ; 
                                        } else {
                                            $smsg = "WARNING: unrecognized CIDRRange specification" ; 
                                        } ; 
                                        write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):`n$($smsg)" ; 
                                    } ; 
                                } else {
                                    write-warning "invalid IP specification:$($ret.type) is unsupported format" ;
                                } ;       
                            } else { 
                                write-warning "invalid IP specification:$($SPFDirective.replace('ip4:',''))" ;
                            } ; 
                            
                            $SPFObject ; 
                        } 
                        '^a:.*$' {
                            Write-Verbose "[A]`tSPF entry: $SPFDirective"
                            $DNSRecords = Resolve-DnsName -Server $Server -Name $Name -Type A ; 
                            # Check SPF record
                            foreach ($IPAddress in ($DNSRecords.IPAddress) ) {
                                $SPFObject = [SPFRecord]::New( $IPAddress, ($SPFDirective -replace "^a:"), $Qualifier) ; 
                                if ( $PSBoundParameters.ContainsKey('Referrer') ) {
                                    $SPFObject.Referrer = $Referrer ; 
                                    $SPFObject.Include = $true ; 
                                }
                                $SPFObject ; 
                            }
                        }
                        '^mx:.*$' {
                            Write-Verbose "[MX]`tSPF entry: $SPFDirective" ; 
                            $DNSRecords = Resolve-DnsName -Server $Server -Name $Name -Type MX ; 
                            foreach ($MXRecords in ($DNSRecords.NameExchange) ) {
                                # Check SPF record
                                $DNSRecords = Resolve-DnsName -Server $Server -Name $MXRecords -Type A ; 
                                foreach ($IPAddress in ($DNSRecords.IPAddress) ) {
                                    $SPFObject = [SPFRecord]::New( $IPAddress, ($SPFDirective -replace "^mx:"), $Qualifier) ; 
                                    if ( $PSBoundParameters.ContainsKey('Referrer') ) {
                                        $SPFObject.Referrer = $Referrer ; 
                                        $SPFObject.Include = $true ; 
                                    } ; 
                                    $SPFObject ; 
                                } ; 
                            } ; 
                        }
                        Default {
                            Write-Warning "[$_]`t Unknown directive" ; 
                        }
                    } ; 
                } ; 

                $DNSQuerySum = $ReturnValues | Select-Object -Unique SPFSourceDomain | Measure-Object | Select-Object -ExpandProperty Count ; 
                if ( $DNSQuerySum -gt 6) {
                    Write-Warning "Watch your includes!`nThe maximum number of DNS queries is 10 and you have already $DNSQuerySum.`nCheck https://tools.ietf.org/html/rfc7208#section-4.6.4" ; 
                } ; 
                if ( $DNSQuerySum -gt 10) {
                    Write-Error "Too many DNS queries made ($DNSQuerySum).`nMust not exceed 10 DNS queries.`nCheck https://tools.ietf.org/html/rfc7208#section-4.6.4" ; 
                } ; 

                $ReturnValues ; 
            } ; 
        } ; 
    } ; 

    END {}
}

#*------^ Resolve-SPFRecord.ps1 ^------


#*------v save-WebDownload.ps1 v------
function save-WebDownload {
    <#
    .SYNOPSIS
    save-WebDownload - Download Uri file from Inet (via Invoke-WebRequest iwr), without need to know destination filename (parses filename out of headers of the download).
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2020-04-17
    FileName    : save-WebDownload.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell,Internet,Download,File
    AddedCredit : poshftw
    AddedWebsite: https://old.reddit.com/r/PowerShell/comments/moxy5v/downloading_a_file_with_powershell_without/
    AddedTwitter: URL
    AddedCredit : Jimmy McNatt
    AddedWebsite: https://jmcnatt.net/quick-tips/powershell-capturing-a-redirected-url-from-a-web-request/
    AddedTwitter: @jmcnatt / https://twitter.com/jmcnatt
    REVISIONS
    * 3:58 PM 3/7/2023 revalidated choco works with discovery;  rem'd out prior 
    path<file/dir code - it's not used with explicit params ; seems to work; fliped 
    the iwr's to use splats; the redir resolve also relies on -ea 0, not STOP or it 
    fails; ; rounded out, added missing code to detect successful first dl attempt. 
    * 2:56 PM 3.3.3023 finally generated throttling '(429) Too Many Requests.' from choco. 
    Reworked -path logic; replaced param with 2 params: -Destination (dir to target dl's into, w dynamic download file resolution) -DestinationFile (full path to download file -outputpath)
    Reworked a lot of the echos, added wlt support for all echos. 
    Only seems to occur pulling pkgs; when running installs, they run for minutes between dl's which seems to avoid issue.
    * 3:50 PM 2/24/2023 add: relative-path resolution on inbound $Path; code 
    [system.io.fileinfo] code to differntiate Leaf file from Container status of 
    Path ;  Logic to validate functional combo of existing/leaf/container -Path. Expanded wlt support throughout.
    * 11:46 AM 2/23/2023 retooled poshftw's original concept, expanding to fail back to obtain a redir for parsing. 
    .DESCRIPTION
    save-WebDownload - Download Uri file from Inet (via Invoke-WebRequest iwr), without need to know destination filename (parses filename out of headers of the download).

    Uses two levels of logic to try to obtain remote download filename (where it's a redirect or v-dir as a target uri):
    1) Leverages poshftw's Invoke-WebRequest -Method Head parse code, to pre-retrieve the Header and back out the target filename 
        (which is then used as final Invoke-WebRequest -Outfile). 
    2) And for sites that don't support -Header (chocolatey.org throws 501 not implemented), it falls back to to 
        trying to obtain and parse a redirect with the full file target present and detectable.
        (leveraging redirect-grabing specs pointed out by Jimmy McNatt in his post [PowerShell – Capturing a Redirected URL from a Web Request – JMCNATT.NET - jmcnatt.net/](https://jmcnatt.net/quick-tips/powershell-capturing-a-redirected-url-from-a-web-request/)
    
    Where the above fail though, you're just going to have to spec a generic -Outfile/DestinationFile, 
    if you really can't pre-determine what the version etc returned remotely is going to be.

    Note:-ThrottleDelay will pickup on and use any configured global $ThrottleMs value, for the PROCESS block loop pause.

    Originally implemented a generic -path param, which could be either a leaf file or a directory spec. 
    Issue: Can't tell the difference from the OS: c:\name could be either a non-extension dir name, or a non-ext file in the root. 
    Same issue with c:\name.ext, dirs can technically have periods/extensions like files.
    It's the property of the object - as set by the creating user that 
    determine which is which. 
    
    [system.io.fileinfo] complicates it further by sticking a 'd' directory attribute in the mod on *both* a *non-existant* 
    full file spec and a non-exist dir spec. 
    
    So I eventually *abandoned* use of generic -Path, and force user to spec either explicitly: 
        -DestinationFile  (leaf path spec)
        -Destation (dir spec)
    And, to simplify the equation, now requirre that the parent dir _pre-exist_ when -DestinationFile is used.


    .PARAMETER Uri
    Uri to be downloaded[-Uri https://community.chocolatey.org/api/v2/package/chocolatey]")] 
    .PARAMETER Destination
    Path to destination directory for dynamic filename download(defaults to pwd)[-Destination 'c:\path-to\']
    .PARAMETER DestinationFile
    Full path to destination file for download[-DestinationFile 'c:\path-to\']
    .PARAMETER ThrottleDelay
    Delay in milliseconds to be applied between a series of downloads(1000 = 1sec)[-ThrottleDelay 1000]
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output
    .EXAMPLE
    save-webdownload -Uri https://community.chocolatey.org/api/v2/package/chocolatey -Destination c:\tmp\ -verbose
    Demo download of a redirected generic url, to the derived filename into c:\tmp dir.
    .EXAMPLE
    save-webdownload -Uri https://fqdn/dir -Path c:\tmp\file.ext ;
    Demo standard Path-specified download
    .EXAMPLE
    $dlpkgs = 'https://community.chocolatey.org/api/v2/package/PowerShell/5.1.14409.20180811','https://community.chocolatey.org/api/v2/package/powershell-core/7.3.2','https://community.chocolatey.org/api/v2/package/vscode/1.75.1','https://community.chocolatey.org/api/v2/package/path-copy-copy/20.0','https://community.chocolatey.org/api/v2/package/choco-cleaner/0.0.8.4','https://community.chocolatey.org/api/v2/package/networkmonitor/3.4.0.20140224','https://community.chocolatey.org/api/v2/package/wireshark/4.0.3','https://community.chocolatey.org/api/v2/package/fiddler/5.0.20211.51073','https://community.chocolatey.org/api/v2/package/pal/2.7.6.0','https://community.chocolatey.org/api/v2/package/logparser/2.2.0.1','https://community.chocolatey.org/api/v2/package/logparserstudio/2.2','https://community.chocolatey.org/api/v2/package/bind-toolsonly/9.16.28','https://community.chocolatey.org/api/v2/package/WinPcap/4.1.3.20161116','https://community.chocolatey.org/api/v2/package/microsoft-message-analyzer/1.4.0.20160625' ; 
    $dlpkgs | save-webdownload -Destination C:\tmp\2023-02-23 -verbose  ;
    Demo pkgs array in variable, pipelined in, with destination folder (implies will attempt to obtain download file name from headers).
    .LINK
    #>
    ## [OutputType('bool')] # optional specified output type
    [CmdletBinding()]
    ###[Alias('Alias','Alias2')]
    PARAM (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0,
            HelpMessage="Uri to be downloaded[-Uri https://community.chocolatey.org/api/v2/package/chocolatey]")] 
            [uri[]]$Uri,
        [Parameter(Mandatory=$false,Position=1,
            HelpMessage = "Path to destination directory for dynamic filename download(defaults to pwd)[-Destination 'c:\path-to\']")]
            [string]$Destination,
        [Parameter(Mandatory=$false,Position=2,
            HelpMessage = "Full path to destination file for download[-DestinationFile 'c:\path-to\']")]
            [string]$DestinationFile,
        [Parameter(Mandatory=$false,Position=2,
            HelpMessage = "Delay in milliseconds to be applied between a series of downloads(1000 = 1sec)[-ThrottleDelay 1000]")]
            [int]$ThrottleDelay
    ) ; 
    BEGIN {
        $rgxHeaders = 'filename=(?:\")*(?<filename>.+?)(?:\")*$' ; 
        $rgxHtmlAnchor = '<a href="(.*)">' ; 

        if(-not $ThrottleDelay -AND ((get-variable -name ThrottleMs -ea 0).value)){
            $ThrottleDelay = $ThrottleMs ; 
            $smsg = "(no -ThrottleDelay specified, but found & using `$global:ThrottleMs:$($ThrottleMs)ms" ; 
            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
        } ; 

        $verbose = $($VerbosePreference -eq "Continue") ;


        if($Destination  -AND $DestinationFile){
            $smsg = "BOTH: -Destination & -DestinationFile specified!" ; 
            $smsg += "`nPlease choose one or the other, NOT BOTH!" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
            throw $smsg ; 
            BREAK ; 
        } ; 

        if(-not $Destination -AND -not $DestinationFile){
            $Destination = (Get-Location).Path
        } ; 

        # also if -DestinationFile, -URI cannot be an array (df forces explicit filename per uri).
        if($DestinationFile -AND ($uri.OriginalString -is [array])){
            $smsg = "-DestinationFile specified:`n($($DestinationFile))" ; 
            $smsg += "`nalong with an array of -uri:" ; 
            $smsg += "`n$(($uri.OriginalString|out-string).trim())" ; 
            $smsg += "-DestinationFile requires a *single* inbound -Uri to funciton properly" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
            throw $smsg ; 
            BREAK ; 
        } 

        TRY {
            $smsg = "Normalized out any relative paths to absolute:" ; 
            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
            if($Destination ){
                $Destination = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Destination) ;
            } ; 
            if($DestinationFile){
                $DestinationFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DestinationFile) ;
            } ; 
            <#
            # alt: hack of resolve-path (which norm can't resolve non-exist paths), grabbing resolved path out of the error of a fail, as TargetObject prop.
            # Src: joshuapoehls | https://stackoverflow.com/users/31308/joshuapoehls | Sep 26, 2012 at 15:56 | [Powershell: resolve path that might not exist? - Stack Overflow - stackoverflow.com/](https://stackoverflow.com/questions/3038337/powershell-resolve-path-that-might-not-exist)
            $Path = Resolve-Path $path -ErrorAction SilentlyContinue -ErrorVariable _frperror ; 
            if (-not($Destination)) {$Destination = $_frperror[0].TargetObject} ; 
            #>
            
            $smsg = "Cast `$Destination/`$DestinationFile to [system.io.fileinfo]" ; 
            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 

            if($Destination){
                [system.io.fileinfo]$Destination = $Destination ;
            } ; 
            if($DestinationFile){
                [system.io.fileinfo]$DestinationFile = $DestinationFile ;
            } ; 

            [boolean]$PathIsFile = [boolean]$PathExists = $false ; 


            if($Destination -and (test-path -path $Destination)){
                # we should *require* that dirs exist, if doing dyn paths
                $PathExists = $true
                # so if exists, check it's type:
                $tobj = get-item -path  $Destination -ea STOP; 
                $PathIsFile =  -not($tobj.PSIsContainer) ; 
                if($PathExists -AND $PathIsFile -eq $false){
                    $Path = $Destination
                } ; 
            } elseif($Destination -AND -not (test-path -path $Destination)){
                $PathExists = $false ;
                $PathIsFile = $false ; 

                $smsg = "NON-EXISTANT -Destination specified!" ; 
                $smsg += "`n$(($Destination.fullname|out-string).trim())" 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                # PLAN B: CREATE THE MISSING PROMPTED
                $smsg = "`n`nDO YOU WANT TO *CREATE* THE MISSING SPECIFIED -DESTINATION!?" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Prompt } 
                else{ write-host -foregroundcolor YELLOW "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                $bRet=Read-Host "Enter YYY to continue. Anything else will exit"  ; 
                if ($bRet.ToUpper() -eq "YYY") {
                    $smsg = "(Moving on)" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

                    $pltNI = @{
                        ItemType ="directory" ;
                        Path = $Destination.fullname ; 
                        erroraction = 'STOP' ;
                        whatif = $($whatif) ;
                    } ;
                    $smsg = "New-Item  w`n$(($pltNI|out-string).trim())" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

                    $Path = new-item @pltNI ; 
                    if(test-path $Path){
                        $PathExists = $true ;
                        $PathIsFile = $false ; 
                    } else { 
                        $PathExists = $false ;
                        $PathIsFile = $false ; 
                    } ; 

                } else {
                     $smsg = "Invalid response. Exiting" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } 
                    else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    break ; 
                }  ; 

            } elseif($DestinationFile -AND (test-path -path $DestinationFile)){
                # existing file spec, overwrite default
                $Path = $DestinationFile ; 
                $PathExists = $true ;
                $PathIsFile = $true ; 
            } elseif($DestinationFile -AND -not (test-path -path $DestinationFile)){
                $PathExists = $false ;
                $PathIsFile = $false ; 
                # non-existant file spec
                # does interrum dir exist?    
                $throwWarn = $false ; 
                if(-not $Destination){
                    $Destination = split-path $DestinationFile ; 
                    $smsg = "blank `$Destination w populated `$DestinationFile:`nderived $Destination from `$DestinationFile" ; 
                    if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                } ; 
                $smsg = "-DestinationFile as specified`n$($DestinationFile)`n...is *non-existant* file path:"
                if(test-path $Destination  ){
                    $smsg += "`nConfirmed presence of specified parent dir:`n$($Destination)" ; 

                    $path = $DestinationFile ; 
                    $PathExists = $false ;
                    $PathIsFile = $true ; 

                } else {
                    $smsg += "`n*COULD NOT* Confirm presence of specified parent dir:`n$($Destination.fullname)" ; 
                    $smsg += "`nA PRE-EXISTING parent is required for -DestinationFile downloads!" ; 
                    $throwWarn = $true ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                    else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                    throw $smsg ; 
                    break ; 
                } ; 
                if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 

            }
            
            if($Path){
                
                # with $Destination & $DestinationFile ,we *know* what the target is, don't need this eval code anymore
                $smsg = "Resolved `$Path:`n$($Path)" ;             
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success

            } else { 
                $smsg = "`$Path is unpopulated!`n$($Path)" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                throw $smsg ; 
                break ; 
            }

        } CATCH {
                # or just do idiotproof: Write-Warning -Message $_.Exception.Message ;
                $ErrTrapd=$Error[0] ;
                $smsg = "$('*'*5)`nFailed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: `n$(($ErrTrapd|out-string).trim())`n$('-'*5)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                else{ write-warning $smsg } ;
                $smsg = "FULL ERROR TRAPPED (EXPLICIT CATCH BLOCK WOULD LOOK LIKE): } catch[$($ErrTrapd.Exception.GetType().FullName)]{" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level ERROR } #Error|Warn|Debug
                else{ write-host $smsg } ;
                throw $ErrTrapd ; 
                Break #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
        } ; 
    } ;  # BEGIN-E
    PROCESS {
        $Error.Clear() ; 

        foreach($item in $Uri){
            TRY {
                [boolean]$isDone = $false ; 
                if($PathIsFile){
                    $smsg = "(-Path detected as Leaf object: Using as destination filename)" ; 
                    if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                    else{ write-verbose $smsg } ; } ; 

                    $pltIWR=[ordered]@{
                        Uri=$item ;
                        OutFile = $Path ; 
                        erroraction = 'STOP' ;
                    } ;
                    $smsg = "Invoke-WebRequest w`n$(($pltIWR|out-string).trim())" ; 
                    if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                    
                    $ret = Invoke-WebRequest @pltIWR ; 

                    $OutFilePath = $Path ; 
                    $isDone = $true ; 

                } elseif(-not $PathIsFile -AND -not $PathExists) { 
                    $smsg = "-Path detected as NON-EXISTANT Container object:" ; 
                    $smsg += "`n a pre-existing Container (or full path to file) must be specified for this function to work properly" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                    else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                    throw $smsg ; 
                    break ; 
                } else {
                    # not existing file, or missing file: Directory 
                    $PathIsFile = $false ; 
                    $smsg = "-Path detected as existing Container object: Attempting to derive the target filename from download Headers..." ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                    else{ write-host $smsg } ;
                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success

                    $pltIWR=[ordered]@{
                        Uri = $item ;
                        Method = 'Head' ;
                        #OutFile = $Path ; 
                        erroraction = 'STOP' ;
                    } ;
                    $smsg = "Invoke-WebRequest w`n$(($pltIWR|out-string).trim())" ; 
                    if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                    
                    $iwr = Invoke-WebRequest @pltIWR ; 



                    if ($iwr.Headers['Content-Disposition'] -match $rgxHeaders) {
                        $OutFilePath = Join-Path $Path $Matches['filename'] ; 
                        $smsg = "Derived filename/OutFilePath:`n" ; 
                        $smsg += "`n$($OutFilePath)" ; 
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                        else{ write-host $smsg } ;
                        #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                    }  else {
                        $smsg = ("Couldn't derive the filename from {0}" -f $item) ; 
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                        else{ write-WARNING $smsg } ; 
                        throw $smsg ; 
                    } ; 
                    $isDone = $false ; # trigger trailing final dl below
                } ; 
            }CATCH [System.Net.WebException]{
                $ErrTrapd=$Error[0] ;
                if($ErrTrapd.Exception -match '\(501\)'){
                    # choco returns 501 on both the -Method Head fail, and on lack of support for Start-BitsTransfer : HTTP status 501: The server does not support the functionality required to fulfill the request.
                    # on the 501 error - choco, which lacks header support - we can trap the redir for parsing:
                    $smsg = "Exception:'$($ErrTrapd.Exception)' returned" ; 
                    if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 

                    $smsg = "=>Remote server returned a 501 (not implemented error)" ; 
                    $smsg += "`n`n-->Re-Attempting:Obtain & parse redirection info for request..." ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                    else{ write-host $smsg } ;

                    TRY{
                        $pltIWR=[ordered]@{
                            Uri = $item ;
                            Method = 'Get' ; 
                            MaximumRedirection = 0 ; 
                            #Method = 'Head' ;
                            #OutFile = $Path ; 
                            erroraction = 'SilentlyContinue' ; # maxi redir resolve *relies* on silentlycontinue; use StOP and it fails.
                        } ;
                        $smsg = "Invoke-WebRequest w`n$(($pltIWR|out-string).trim())" ; 
                        if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 

                        if($Results = Invoke-WebRequest @pltIWR){
                            # checking for a redirect return, to parse:
                            <# Redirect error returned, sample:
                            StatusCode        : 302
                            StatusDescription : Found
                            Content           : <html><head><title>Object moved</title></head><body>
                                                <h2>Object moved to <a href="https://packages.chocolatey.org/chocolatey.1.3.0.nupkg">here</a>.</h2>
                                                </body></html>
                            RawContent        : HTTP/1.1 302 Found
                                                Transfer-Encoding: chunked
                                                Connection: keep-alive
                                                X-AspNetMvc-Version: 3.0
                                                X-Frame-Options: deny
                                                CF-Cache-Status: DYNAMIC
                                                Strict-Transport-Security: max-age=12960000
                                                X-Conten...
                            Forms             : {}
                            Headers           : {[Transfer-Encoding, chunked], [Connection, keep-alive], [X-AspNetMvc-Version, 3.0], [X-Frame-Options, deny]...}
                            Images            : {}
                            InputFields       : {}
                            Links             : {@{innerHTML=here; innerText=here; outerHTML=<A href="https://packages.chocolatey.org/chocolatey.1.3.0.nupkg">here</A>;
                                                outerText=here; tagName=A; href=https://packages.chocolatey.org/chocolatey.1.3.0.nupkg}}
                            ParsedHtml        : mshtml.HTMLDocumentClass
                            RawContentLength  : 171
                            #>
                            $lines = $results.Content.Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries) ; 
                            if($lines = $lines | ?{$_ -like '*href*'}){
                                if([uri]$RedirUrl = [regex]::match($lines,$rgxHtmlAnchor).groups[1].captures[0].value){
                                    if($OutFilePath = Join-Path $Path -childpath $RedirUrl.LocalPath.replace('/','')){
                                        $smsg = "Resolved redirect to a filename, for OutputPath:" ;
                                        $smsg += "`n$($OutFilePath)" ;  
                                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                                        else{ write-host $smsg } ;
                                        $isDone = $false ; # trigger trailing final dl below
                                    } else { 
                                        $smsg += "Unable to Construct a workable `$OutputFilePath from returned data:" ; 
                                        $smsg += "`nPlease specify a full leaf file -Path specification and retry (even a dummy filename will work)" ; 
                                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                                        else{ write-WARNING $smsg } ; 
                                        throw $smsg ; 
                                        break ; 
                                    } ; 
                                } ; 
                            } else { 
                                $smsg += "Unable to locate a `$returned.Content line containing an '*href*', for further parsing. Aborting" ; 
                                $smsg += "`nPlease specify a full leaf file -Path specification and retry" ; 
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                                else{ write-WARNING $smsg } ; 
                                throw $smsg ; 
                                break ; 
                            } ; 

                        } else {
                            #parse off and offer the leaf name of the uri 
                            TRY{
                                if($samplefilename = [System.IO.Path]::GetFileName($uri) ){
                                    # returns 'chocolatey' from expl url
                                    $smsg = "(removing illegal fs chars from resolved leaf name)" ; 
                                    if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                                    $samplefilename = [RegEx]::Replace($samplefilename, "[{0}]" -f ([RegEx]::Escape(-join [System.IO.Path]::GetInvalidFileNameChars())), '') ;
                                } else {
                                    $smsg = "(unable to parse a sample leaf name from the input -uri:`n$(($uri|out-string).trim())" ; 
                                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                                } ; 

                            }CATCH{
                                $smsg = "(unable to parse a sample leaf name from the input -uri:`n$(($uri|out-string).trim())" ; 
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                            } ; 
                            $smsg += "Unable to obtain useful Redirect info to parse. Aborting" ; 
                            $smsg += "`nPlease specify a full leaf file -Path specification and retry" ; 
                            if($samplefilename){
                                $smsg += "(possibly the url 'generic' filename:$($samplefilename).extension" ; 
                            } ; 
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                            else{ write-WARNING $smsg } ; 
                            throw $smsg ; 
                            break ; 
                        } ; 
                    } CATCH {
                        # or just do idiotproof: Write-Warning -Message $_.Exception.Message ;
                        $ErrTrapd=$Error[0] ;
                        $smsg = ("Couldn't get the file from {0}" -f $item) ; 
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                        else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                        $smsg = "$('*'*5)`nFailed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: `n$(($ErrTrapd|out-string).trim())`n$('-'*5)" ;
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                        else{ write-warning $smsg } ;
                    } ; 
                    
                } elseif( ($ErrTrapd.Exception -match '\(429\)') -OR ($ErrTrapd.Exception -match 'Too\sMany\sRequests')){
                    # choco throttling error returned:
                    <# [https://docs.chocolatey.org/en-us/troubleshooting#im-getting-a-429-too-many-requests-issue-when-attempting-to-use-the-community-package-repository](https://docs.chocolatey.org/en-us/troubleshooting#im-getting-a-429-too-many-requests-issue-when-attempting-to-use-the-community-package-repository)
                        This means your IP address has been flagged for too many requests. Please see Rate Limiting for details and actions.
                        Reference Errors:
                            Exception calling "DownloadFile" with "2" argument(s): The remote server returned an error: (429) Too Many Requests
                            The remote server returned an error: (429) Too Many Requests. Too Many Requests
                        [https://docs.chocolatey.org/en-us/community-repository/community-packages-disclaimer#rate-limiting](https://docs.chocolatey.org/en-us/community-repository/community-packages-disclaimer#rate-limiting)
                        Rate Limiting
                            NOTE
                            Purchasing licenses will not have any effect on rate limiting of the community package repository. Please read carefully below to understand why this was put in place and steps you can take to reduce issues if you run into it. HINT: It's not an attempt to get you to pay for commercial editions.
                            As a measure to increase site stability and prevent excessive use, the Chocolatey website uses rate limiting on requests for the community repository. Rate limiting was introduced in November 2018. Most folks typically won't hit rate limits unless they are automatically tagged for excessive use. If you do trigger the rate limit, you will see a (429) Too Many Requests. When attempting to install Chocolatey you will see the following:
                            If you go to a package page and attempt to use the download link in the left menu, you will see the following:
                            Error 1015 Ray ID ...xxx
                            You are being rate limited. 
                            The owner of this website (chocolatey.org) has banned you temporarily from accessing this website.
                        What To Do When You Are Rate Limited
                            NOTE
                            A rate limit will automatically expire after an hour, but if you hit the limit again, it will block for another hour.
                        If you have found that you have been rate limited, please see How To Avoid Excessive Use. Implementing best practices for organizational use will limit chances of being rate limited again in the future.
                            Individual users being rate limited should reach out as per the next section and let us know as we are constantly adjusting limits to find a happy medium and need to have as much data to work with as possible. In addition to providing the requested information, make sure to also mention you are "individual use" and provide details on what caused the rate limiting. We may ask you to provide logs for further inspection.
                            Organizational use will be asked to set up best practices for Chocolatey deployments.
                    #>
                    $smsg = "Exception:'$($ErrTrapd.Exception)' returned" ; 
                    if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                    $smsg = "SERVER THROTTLING!:`nException:'$($ErrTrapd.Exception)' returned" ; 
                    $smsg += "`nToo many requests too quickly, wait for block to expire and" ; 
                    $smsg += "`ntry increasing delay" ; 
                    $smsg += "(for choco, the throttling only reset after an HOUR!)" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                    else{ write-WARNING $smsg } ; 
                    throw $smsg ; 
                    # fatal, server is going to continue throttling for an HOUR: no point in using Continue
                    break ; 
                } else { 
                    $smsg = "Exception:'$($ErrTrapd.Exception)' returned" ; 
                    $smsg = "`nUnrecognized error, aborting further processing" ; 
                    $smsg += "`nPlease specify a full leaf file -Path specification and retry" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                    else{ write-WARNING $smsg } ; 
                    throw $smsg ; 
                    break ; 
                } ; 
            } CATCH {
                # or just do idiotproof: Write-Warning -Message $_.Exception.Message ;
                $ErrTrapd=$Error[0] ;
                $smsg = ("Couldn't get the file from {0}" -f $item) ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                $smsg = "$('*'*5)`nFailed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: `n$(($ErrTrapd|out-string).trim())`n$('-'*5)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                else{ write-warning $smsg } ;
                $smsg = "FULL ERROR TRAPPED (EXPLICIT CATCH BLOCK WOULD LOOK LIKE): } catch[$($ErrTrapd.Exception.GetType().FullName)]{" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level ERROR } #Error|Warn|Debug
                else{ write-host $smsg } ;
                Break #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
                throw $ErrTrapd ; 
            } ; 

            <# alts to trying to retrieve the filename:
                1) you can also have iopath cut the trailing /name and use it as a name:
                $filename = [System.IO.Path]::GetFileName($url) # returns 'chocolatey' from expl url
                $OutFilePath = Join-Path $Path -ChildPath $filename ; 
                # it's 'descriptive' of the dl, but in the choco case, completely loses the rev spec from the proper filename.
                2) you can use Start-BitsTransfer, if server supports it: *choco doesn't*:
                Import-Module BitsTransfer
                Start-BitsTransfer -source $url ; 
                Start-BitsTransfer : HTTP status 501: The server does not support the functionality required to fulfill the request.
                At line:1 char:1
                + Start-BitsTransfer -source $url
                + ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                    + CategoryInfo          : InvalidOperation: (:) [Start-BitsTransfer], Exception
                    + FullyQualifiedErrorId : StartBitsTransferCOMException,Microsoft.BackgroundIntelligentTransfer.Management.NewBitsTransferCommand
            #>

            TRY {
                if(-not $isDone){
                    if($OutFilePath){
                        $pltIWR=[ordered]@{
                            Uri=$item ;
                            OutFile = $OutFilePath ; 
                            erroraction = 'STOP' ;
                        } ;
                        $smsg = "Invoke-WebRequest w`n$(($pltIWR|out-string).trim())" ; 
                        if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                        #Invoke-WebRequest -Uri $item -OutFile $OutFilePath ; 
                        $ret = Invoke-WebRequest @pltIWR ; 
                        $isDone = $true ; 
                    } else { 
                        $smsg = "Unpopulated `$OutFilePath!`n$($OutFilePath)" ; 
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                        else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                        throw $smsg ; 
                        break ; 
                    } ; 
                } else { 
                    $smsg = "(url already pre-downloaded on initial attempt)" ; 
                    if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                } ; 
                # emit outfilepath to pipeline, as we've resolved the source, and may not know it
                if($isDone  -AND (test-path $OutFilePath)){
                    write-host "Validated download:" 
                    $OutFilePath | write-output ; 
                } ; 
                
            } CATCH {
                # or just do idiotproof: Write-Warning -Message $_.Exception.Message ;
                $ErrTrapd=$Error[0] ;
                $smsg = ("Got the filename, but couldn't download the file from {0} to {1}" -f $item, $OutFilePath) ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                $smsg = "$('*'*5)`nFailed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: `n$(($ErrTrapd|out-string).trim())`n$('-'*5)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                else{ write-warning $smsg } ;
            } ; 
            # if the throttle spec is pre-defined (profile level), pause to avoid throttling
            if($ThrottleDelay){
                start-sleep -Milliseconds $ThrottleDelay ; 
            } ; 
        } ;   # loop-E
    } ;  # if-PROC
}

#*------^ save-WebDownload.ps1 ^------


#*------v save-WebDownloadCurl.ps1 v------
function save-WebDownloadCurl {
    <#
    .SYNOPSIS
    save-WebDownloadCurl.ps1 - simple download wrapper around curl cmdline util
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2020-04-17
    FileName    : save-WebDownloadCurl.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell,Internet,Download,File
    REVISIONS
    *12:18 PM 3/7/2023 fixed underlying splatting break (had been trying to build [str] cmdline -> use array so-called spatting (not really a splatted hashtable); 
    added strong typing/cast to [uri], as pre-validation; ren download-filecurl -> save-WebDownloadCurl (aliased orig) ;
    ren $url->$uri, aliased url; ren'd DestinationName -> DestinationFile (aliased orig);
    11:31 AM 4/17/2020 added CBH
    .DESCRIPTION
    save-WebDownloadCurl.ps1 - simple download client, wraps cmdline curl executable (supports *nix as well).
    .PARAMETER uri
        Uri to be downloaded[-Uri https://community.chocolatey.org/api/v2/package/chocolatey]
        .PARAMETER DestinationFile
        Full path to destination file for download[-DestinationFile 'c:\path-to\']
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output
    .EXAMPLE
    save-WebDownloadCurl -uri https://xxx -DestinationFile c:\pathto\file.ext
    .LINK
    #>
    PARAM (
        [Parameter(Mandatory=$true,Position=0,
                HelpMessage="Uri to be downloaded[-Uri https://community.chocolatey.org/api/v2/package/chocolatey]")] 
            [Alias('url')]
            #[string]
            [uri]$uri, 
        [Parameter(Position=1,
                HelpMessage="Full path to destination file for download[-DestinationFile 'c:\path-to\']")] 
            [Alias('DestinationName')]
            [string]$DestinationFile
    )
    #$CurlArgument = "-o '$($DestinationFile)', --url '$($uri)'" ; 
    #$CurlArgument = '"$($uri)" -o "$($destinationfile)"' ; 

    #[string]$CurlArgument = "'$($uri.OriginalString)'" ; 
    #$CurlArgument += " -o '$($destinationfile)'" ; 
    # use splatting:
    <#$CurlArgument = '-u', 'xxx@gmail.com:yyyy',
                '-X', 'POST',
                'https://xxx.bitbucket.org/1.0/repositories/abcd/efg/pull-requests/2229/comments',
                '--data', 'content=success'
    #>
    $CurlArgument = '-s', '-L', '-o', "$($destinationfile)", "$($uri.OriginalString)"
    if (($PSVersionTable.PSEdition -eq 'Desktop') -OR ($IsCoreCLR -AND $IsWindows) -OR !$PSVersionTable.PSEdition) {$CURLEXE = "$env:windir\System32\curl.exe" } 
    elseif ($IsCoreCLR -AND $IsLinux) {$CURLEXE = 'curl'} ;
    & $CURLEXE @CurlArgument ;
}

#*------^ save-WebDownloadCurl.ps1 ^------


#*------v save-WebDownloadDotNet.ps1 v------
function save-WebDownloadDotNet {
        <#
        .SYNOPSIS
        save-WebDownloadDotNet.ps1 - simple download client
        .NOTES
        Version     : 1.0.0
        Author      : Todd Kadrie
        Website     : http://www.toddomation.com
        Twitter     : @tostka / http://twitter.com/tostka
        CreatedDate : 2020-04-17
        FileName    : save-WebDownloadDotNet.ps1
        License     : MIT License
        Copyright   : (c) 2020 Todd Kadrie
        Github      : https://github.com/verb-network
        Tags        : Powershell,Internet,Download,File
        REVISIONS
        * 11:36 AM 3/7/2023 validated; ren download-file -> save-WebDownloadDotNet (aliased orig) ; spliced over NoSSL support from download-fileNoSSL.ps1(retiring that func in favor of this) ;  add param specs, ren $url->$uri, aliased url; ren'd DestinationName -> DestinationFile (aliased orig); add position to params
        11:31 AM 4/17/2020 added CBH
        .DESCRIPTION
        save-WebDownloadDotNet.ps1 - simple .Net-based download client
        If no -DestinationFile specified, the content is returned to pipeline.
        .PARAMETER uri
        Uri to be downloaded[-Uri https://community.chocolatey.org/api/v2/package/chocolatey]
        .PARAMETER DestinationFile
        Full path to destination file for download[-DestinationFile 'c:\path-to\']
        .PARAMETER NoPing
        Switch to suppress Ping/Test-Connection pretest[-NoPing]
        .PARAMETER NoSSL
        Switch to suppress SSL requirement (for sites with failing certs)[-NoSSL]
        .INPUTS
        None. Does not accepted piped input.
        .OUTPUTS
        None. Returns no objects or output
        .EXAMPLE
        save-WebDownloadDotNet -url https://xxx -DestinationFile c:\pathto\file.ext
        .LINK
        http://blogs.technet.com/b/bshukla/archive/2010/04/12/ignoring-ssl-trust-in-powershell-system-net-webclient.aspx
        #>
        [CmdletBinding()]
        [Alias('download-file')]
        PARAM (
            [Parameter(Mandatory=$true,Position=0,
                HelpMessage="Uri to be downloaded[-Uri https://community.chocolatey.org/api/v2/package/chocolatey]")] 
            [Alias('url')]
            [string]$uri, 
            [Parameter(Position=1,
                HelpMessage="Full path to destination file for download[-DestinationFile 'c:\path-to\']")] 
            [Alias('DestinationName')]
            [string]$DestinationFile,
            [Parameter(
                HelpMessage="Switch to suppress Ping/Test-Connection pretest[-NoPing]")] 
            [switch]$NoPing,
            [Parameter(
                HelpMessage="Switch to suppress SSL requirement (for sites with failing certs)[-NoSSL]")] 
            [switch]$NoSSL
        )
        $rgxURLParse = "^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?" ;
        if ($uri -match $rgxURLParse) {
            if($NoSSL){
                write-warning "-NoSSL specified: disabling system.net.WebClient Certificate Validation!" ; 
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } ;
            } ; 
            $server = $matches[4] ;
            [boolean]$bPing = $false ; 
            if (-not $NoPing -AND (test-connection -ComputerName $server -count 1)) {
                $bPing = $true ;
            }elseif ($NoPing) {
                $bPing = $true ;
            } else {
                throw "unable to Ping $()" ;
            } ;
            if($bPing){
                $client = new-object system.net.WebClient
                $client.Headers.Add("user-agent", "PowerShell")
                if($DestinationFile){
                    write-host "-DestinationFile: Saving download to:`n$($DestinationFile)..." ; 
                    $client.downloadfile($uri, $DestinationFile)
                } else { 
                    write-verbose "streaming URI to pipeline..." ; 
                    $client.DownloadString($uri) | write-output ; 
                } ; 
            } ; 
            # not sure if toggle back is necesesary, but try it
            if($NoSSL){
                write-verbose "-NoSSL specified, re-enabling system.net.WebClient Certificate Validation" ; 
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $false } ;
            } ; 
        } else {
            throw "Unparsable url, to fqdn:$($uri)" ;
        } ;
    }

#*------^ save-WebDownloadDotNet.ps1 ^------


#*------v save-WebFaveIcon.ps1 v------
function save-WebFaveIcon {
    <#
    .SYNOPSIS
    save-WebFaveIcon - Download a website's default root favicon.ico file to a .jpg (assumed ext: actual downloaded filetype is *not* validated)
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2020-04-17
    FileName    : save-WebFaveIcon.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka/verb-network
    Tags        : Powershell,Internet,Download,File
    AddedCredit : poshftw
    AddedWebsite: https://old.reddit.com/r/PowerShell/comments/moxy5v/downloading_a_file_with_powershell_without/
    AddedTwitter: URL
    AddedCredit : Jimmy McNatt
    AddedWebsite: https://jmcnatt.net/quick-tips/powershell-capturing-a-redirected-url-from-a-web-request/
    AddedTwitter: @jmcnatt / https://twitter.com/jmcnatt
    REVISIONS
    6:09 PM 5/12/2023 initial vers 
    .DESCRIPTION
    save-WebFaveIcon - Download a website's default root favicon.ico file to a .jpg (assumed ext: actual downloaded filetype is *not* validated)

    Dependancies:
    - requires Box Prox's [get-FileSignature()](https://mcpmag.com/articles/2018/07/25/file-signatures-using-powershell.aspx)
    - requires gravejester (Øyvind Kallstad)'s [get-FileType()](https://gist.github.com/gravejester/803649515c2dd85ab37e)

    .PARAMETER Name
    Name string to be used for the downloaded favicon[-name 'SiteName']
    .PARAMETER Url
    Root web site from which to download the favicon[-Url https://community.chocolatey.org/]
    .PARAMETER Path
    Path to destination directory for favicon download (defaults to c:\temp\jpg)[-Path 'c:\path-to\']
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output
    .EXAMPLE
    PS> save-webfaveicon -name duckduckgo -url https://duckduckgo.com/ -Verbose
    Demo download of a duckduckgo.com's favicon (which has a relative favicon path)
    .EXAMPLE
    PS> save-webfaveicon -name proofpoint -url https://www.proofpoint.com/ -Verbose
    Demo download of a proofpoint.com's favicon (which has an absolute favicon path)
    .LINK
    https://github.com/tostka/verb-network
    #>
    ## [OutputType('bool')] # optional specified output type
    [CmdletBinding()]
    ###[Alias('Alias','Alias2')]
    PARAM (
        [Parameter(Mandatory=$false,Position=1,
            HelpMessage="Name string to be used for the downloaded favicon[-name 'SiteName']")] 
            [string]$name,
        [Parameter(Mandatory=$true,Position=0,
            HelpMessage="Root web site from which to download the favicon[-Url https://community.chocolatey.org/]")] 
            [uri[]]$url,
        [Parameter(Mandatory=$false,
            HelpMessage = "Path to destination directory for favicon download [-Path 'c:\path-to\']")]
            #[ValidateScript({Test-Path $_ -PathType 'Container'})]
            #[ValidateScript({Test-Path $_})]
            [string]$Path = "c:\temp\jpg"
    ) ; 
    BEGIN {
        #$rgxHeaders = 'filename=(?:\")*(?<filename>.+?)(?:\")*$' ; 
        #$rgxHtmlAnchor = '<a href="(.*)">' ; 
        $rgxFaveIcon = '<link\srel=.*shortcut\sicon|favicon\.ico' # target tag: <link rel="shortcut icon" href="/favicon.ico">
        #'shortcut\sicon|favicon\.ico' ; 
        $rgxURL = '(?i)\b((?:[a-z][\w-]+:(?:/{1,3}|[a-z0-9%])|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:.,<>?«»“”‘’]))' ; 
        $verbose = $($VerbosePreference -eq "Continue") ;

        TRY {
            if (Test-Path $Path) {}
            else { New-Item $Path -ItemType Directory -verbose:$true}

            # use cleaned [uri].host if $name is blank
            if(-not $name){
                if($url.host){
                    $name=[RegEx]::Replace($url.host, "[{0}]" -f ([RegEx]::Escape(-join [System.IO.Path]::GetInvalidFileNameChars())), '') ;
                    $smsg = "No -Name specified: Derived filename from -url Host value:`n$($name)" ; 
                    write-host -ForegroundColor yellow $smsg ; 
                } else { 
                    $smsg = "No -Name specified: But unable to parse [uri].host from specified -url value:`n$($url.OriginalString)" ; 
                    $smsg += "`nPlease rerun with an explicit -Name value" ; 
                    write-warning $smsg ; 
                    break ; 
                } ; 
            } ; 

        } CATCH {
                # or just do idiotproof: Write-Warning -Message $_.Exception.Message ;
                $ErrTrapd=$Error[0] ;
                $smsg = "$('*'*5)`nFailed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: `n$(($ErrTrapd|out-string).trim())`n$('-'*5)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                else{ write-warning $smsg } ;
                $smsg = "FULL ERROR TRAPPED (EXPLICIT CATCH BLOCK WOULD LOOK LIKE): } catch[$($ErrTrapd.Exception.GetType().FullName)]{" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level ERROR } #Error|Warn|Debug
                else{ write-host $smsg } ;
                throw $ErrTrapd ; 
                Break #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
        } ; 

    } ;  # BEGIN-E
    PROCESS {
        $Error.Clear() ; 

            $dfile =  $results = $null ; 
            
            write-verbose "Retrieving root site source..." ; 
            TRY {
                 $results = Invoke-WebRequest -Uri $url.absoluteuri -UseBasicParsing ; 
            }CATCH [System.Net.WebException]{
                $ErrTrapd=$Error[0] ;
                if($ErrTrapd.Exception -match '\(501\)'){
                    # choco returns 501 on both the -Method Head fail, and on lack of support for Start-BitsTransfer : HTTP status 501: The server does not support the functionality required to fulfill the request.
                    # on the 501 error - choco, which lacks header support - we can trap the redir for parsing:
                    $smsg = "Exception:'$($ErrTrapd.Exception)' returned" ; 
                    if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 

                    $smsg = "=>Remote server returned a 501 (not implemented error)" ; 
                    $smsg += "`n`n-->Re-Attempting:Obtain & parse redirection info for request..." ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                    else{ write-host $smsg } ;
                } elseif( ($ErrTrapd.Exception -match '\(429\)') -OR ($ErrTrapd.Exception -match 'Too\sMany\sRequests')){
                    # throttling error returned:
                    $smsg = "Exception:'$($ErrTrapd.Exception)' returned" ; 
                    if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                    $smsg = "SERVER THROTTLING!:`nException:'$($ErrTrapd.Exception)' returned" ; 
                    $smsg += "`nToo many requests too quickly, wait for block to expire and" ; 
                    $smsg += "`ntry increasing delay" ; 
                    $smsg += "(for choco, the throttling only reset after an HOUR!)" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                    else{ write-WARNING $smsg } ; 
                    throw $smsg ; 
                    # fatal, server is going to continue throttling for an HOUR: no point in using Continue
                    break ; 
                } else { 
                    $smsg = "Exception:'$($ErrTrapd.Exception)' returned" ; 
                    $smsg = "`nUnrecognized error, aborting further processing" ; 
                    $smsg += "`nPlease specify a full leaf file -Path specification and retry" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                    else{ write-WARNING $smsg } ; 
                    throw $smsg ; 
                    break ; 
                } ; 
            } CATCH {
                # or just do idiotproof: Write-Warning -Message $_.Exception.Message ;
                $ErrTrapd=$Error[0] ;
                $smsg = "$('*'*5)`nFailed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: `n$(($ErrTrapd|out-string).trim())`n$('-'*5)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                else{ write-warning $smsg } ;
                $smsg = "FULL ERROR TRAPPED (EXPLICIT CATCH BLOCK WOULD LOOK LIKE): } catch[$($ErrTrapd.Exception.GetType().FullName)]{" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level ERROR } #Error|Warn|Debug
                else{ write-host $smsg } ;
                Break #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
                throw $ErrTrapd ; 
            } ; 


            TRY {

                
                $Path = join-path -path $Path -childpath "$($name).jpg" ; 
                if(test-path -path $Path){
                    write-host "Pre-existing $($Path) file found, pre-clearing before run..." ; 
                    remove-item -path $Path -erroraction STOP; 
                } ; 
                
                write-verbose "parsing content for favicon link tag..." ; 
                $lines = $results.Content.Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries) ;
                # $rgxFaveIcon = '<link\srel=.*shortcut\sicon|favicon\.ico' # target tag: <link rel="shortcut icon" href="/favicon.ico">
                if($lines | ?{$_ -match $rgxFaveIcon}){
                    write-verbose "link line located" ; 
                    <# proofpoint has 2 hits on the favicon filter
                    <link rel="shortcut icon" href="/themes/custom/proofpoint/apps/drupal/favicon.ico" />
                    <link rel="icon" href="/themes/custom/proofpoint/apps/drupal/favicon.ico" type="image/vnd.microsoft.icon" />
                    same href, just different link rel label
                    #>
                    # so always take the first:
                    $ficonUrl = $lines | ?{$_ -match $rgxFaveIcon } | select-object -first 1 ; 
                    if ( ($ficonurl.tostring() -match '^http') -AND  ([boolean]([uri]$ficonurl.tostring())) ){
                        write-verbose "Absolute parsable URL http present" ; 
                        [uri]$ficonUrl = [regex]::match($ficonUrl,$rgxURL).captures.value.replace('"','') ; 
                        # https://a.mtstatic.com/@public/production/site_6638/1614630907-favicon.ico/
                    } else { 
                        $smsg = "Parsing apparant relative uri & building AbsoluteURI" ; 
                        $smsg += "`n$($ficonurl.tostring())" ; 
                        write-verbose $smsg ; 
                        $uriLeaf = [regex]::match($ficonUrl.split('=')[2],'"(.*)"').groups[1].value ; 
                        if($urileaf -match '^/'){
                            $urileaf =  $urileaf.Substring(1,$urileaf.length-1) ; 
                        } ; 
                        #$ub = new-object System.UriBuilder -argumentlist 'http', 'myhost.com', 80, 'mypath/query.aspx', '?param=value'
                        #$ub = new-object System.UriBuilder -argumentlist $url.Scheme, $url.Host, $url.Port, (-join ($url.AbsolutePath,'/',$uriLeaf)), '?param=value'
                        $arglist = @() ; 
                        $arglist += $url.Scheme 
                        $arglist += $url.Host ; 
                        $arglist += $url.Port ; 
                        #$arglist += (-join ($url.AbsolutePath,'/',$uriLeaf))
                        $arglist += (-join ($url.AbsolutePath,'/',$uriLeaf)).replace('//','/') ; 
                        $arglist += $url.Query ; 
                        write-verbose "`$arglist`n$(($arglist|out-string).trim())" ; 
                        $ub = new-object System.UriBuilder -argumentlist $arglist ; 

                        [uri]$ficonUrl = $ub.uri.AbsoluteUri ; 
                    } ; 
                    if($ficonUrl.AbsoluteUri){
                        write-verbose "Favicon link line parses to a valid URI:$($ficonUrl.AbsoluteUri)" ; 
                    } else {
                        $smsg = "Failed to match a URL from the matched line`n$(($lines | ?{$_ -match $rgxFaveIcon }|out-string).trim())" ; 
                        write-warning $smsg ; 
                    }; 
                } else { 
                    write-warning "Failed to locate a FaveIcon link tag:$($rgxFaveIcon)" ; 
                    Break ; 
                } ; 
            } CATCH {
                # or just do idiotproof: Write-Warning -Message $_.Exception.Message ;
                $ErrTrapd=$Error[0] ;
                $smsg = "$('*'*5)`nFailed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: `n$(($ErrTrapd|out-string).trim())`n$('-'*5)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                else{ write-warning $smsg } ;
                $smsg = "FULL ERROR TRAPPED (EXPLICIT CATCH BLOCK WOULD LOOK LIKE): } catch[$($ErrTrapd.Exception.GetType().FullName)]{" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level ERROR } #Error|Warn|Debug
                else{ write-host $smsg } ;
                Break #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
                throw $ErrTrapd ; 
            } ; 
            write-verbose "downloading resolved favicon file url:`n$(($ficonUrl.AbsoluteUri|out-string).trim())" ; 
            
            TRY {
                Invoke-WebRequest -UseBasicParsing -uri $ficonUrl.AbsoluteUri -outfile $Path ; 
            }CATCH [System.Net.WebException]{
                $ErrTrapd=$Error[0] ;
                if($ErrTrapd.Exception -match '\(501\)'){
                    # site returns 501 on both the -Method Head fail, and on lack of support for Start-BitsTransfer : HTTP status 501: The server does not support the functionality required to fulfill the request.
                    # on the 501 error - choco, which lacks header support - we can trap the redir for parsing:
                    $smsg = "Exception:'$($ErrTrapd.Exception)' returned" ; 
                    if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 

                    $smsg = "=>Remote server returned a 501 (not implemented error)" ; 
                    $smsg += "`n`n-->Re-Attempting:Obtain & parse redirection info for request..." ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                    else{ write-host $smsg } ;
                } elseif( ($ErrTrapd.Exception -match '\(429\)') -OR ($ErrTrapd.Exception -match 'Too\sMany\sRequests')){
                    # throttling error returned:
                    $smsg = "Exception:'$($ErrTrapd.Exception)' returned" ; 
                    if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                    $smsg = "SERVER THROTTLING!:`nException:'$($ErrTrapd.Exception)' returned" ; 
                    $smsg += "`nToo many requests too quickly, wait for block to expire and" ; 
                    $smsg += "`ntry increasing delay" ; 
                    $smsg += "(for choco, the throttling only reset after an HOUR!)" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                    else{ write-WARNING $smsg } ; 
                    throw $smsg ; 
                    # fatal, server is going to continue throttling for an HOUR: no point in using Continue
                    break ; 
                } else { 
                    $smsg = "Exception:'$($ErrTrapd.Exception)' returned" ; 
                    $smsg = "`nUnrecognized error, aborting further processing" ; 
                    $smsg += "`nPlease specify a full leaf file -Path specification and retry" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                    else{ write-WARNING $smsg } ; 
                    throw $smsg ; 
                    break ; 
                } ; 
            } CATCH {
                # or just do idiotproof: Write-Warning -Message $_.Exception.Message ;
                $ErrTrapd=$Error[0] ;
                $smsg = "$('*'*5)`nFailed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: `n$(($ErrTrapd|out-string).trim())`n$('-'*5)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                else{ write-warning $smsg } ;
                $smsg = "FULL ERROR TRAPPED (EXPLICIT CATCH BLOCK WOULD LOOK LIKE): } catch[$($ErrTrapd.Exception.GetType().FullName)]{" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level ERROR } #Error|Warn|Debug
                else{ write-host $smsg } ;
                Break #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
                throw $ErrTrapd ; 
            } ; 
            
            if($dfile = get-childitem -path $Path ){
                write-host -foregroundcolor green "Confirmed presence of downloaded file`n$(($dfile| ft -a Length,fullName|out-string).trim())`n(launching by assoication)" ; 
                #start $dfile.fullname ; 
                [array]$doFileTest = @() ; 
                'get-filesignature','get-filetype' | foreach-object{
                     if(-not (get-command $_ -ea 0)){
                        $doFileTest += $false ;
                     } else {
                        $doFileTest += $true ;
                    }; 
                } ; 
                if($doFileTest -contains $false){
                    $smsg = "Missing dependant: $($_) function" ; 
                    $smsg += "`nSkipping file type checks!" ; 
                    write-warning $smsg ; 
                } else {
                    # test filetype 
                    $Imagetype = get-FileType -Path $dfile.fullname -verbose:$($VerbosePreference -eq "Continue") ;
                    # Accommodate multi-extension filetypes by parsing output: split on /, and always take the first entry.
                    # 'Archive (ZIP/JAR)' == returns ZIP, vs JAR
                    $ImagetypeExtension = ([regex]::match($Imagetype.FileType,"\(.*\)").groups[0].captures[0].value.replace('(','').replace(')','').split('/'))[0]
                    if($dfile.extension -eq ".$($ImagetypeExtension)"){
                        write-verbose "Downloaded favicon file`n$($dfile.fullname)`nconfirms as a .jpg file" ; 
                    } else { 
                        $smsg = "Downloaded favicon file`n$($dfile.fullname)`ndetects from file header as a .$($ImagetypeExtension) file" ; 
                        $smsg += "`nRENAMING to suitable extension..." ; 
                        write-host -foregroundcolor yellow $smsg ; 
                        $pltRI = @{
                            Path = $dfile.fullname ;
                            NewName = $dfile.name.replace($dfile.extension,".$($ImagetypeExtension.tolower())") ; 
                            ErrorAction = 'STOP'
                            verbose = $($VerbosePreference -eq "Continue") ;
                        } ; 
                        write-verbose "rename-item w`n$(($pltri|out-string).trim())" ; 
                        TRY{
                            rename-item @pltri ; 
                        } CATCH {
                            $ErrTrapd=$Error[0] ;
                            $smsg = "$('*'*5)`nFailed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: `n$(($ErrTrapd|out-string).trim())`n$('-'*5)" ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                            else{ write-warning $smsg } ;
                            $smsg = "FULL ERROR TRAPPED (EXPLICIT CATCH BLOCK WOULD LOOK LIKE): } catch[$($ErrTrapd.Exception.GetType().FullName)]{" ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level ERROR } #Error|Warn|Debug
                            else{ write-host $smsg } ;
                            Break #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
                            throw $ErrTrapd ; 
                        } ; 
                    
                    } ; 
                } ; 
            } else {
                $smsg = "Unable to confirm presense of downloaded file!:" 
                $smsg += "`n$($Path)" ; 
                write-warning $smsg ; 
            }; ; 
    } ;  # if-PROC
}

#*------^ save-WebFaveIcon.ps1 ^------


#*------v Send-EmailNotif.ps1 v------
Function Send-EmailNotif {
    <#
    .SYNOPSIS
    Send-EmailNotif.ps1 - Mailer function (wraps send-mailmessage)
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website:	http://www.toddomation.com
    Twitter:	@tostka, http://twitter.com/tostka
    CreatedDate : 2014-08-21
    FileName    : 
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,Email,SMTP,Gmail
    AddedCredit : REFERENCE
    AddedWebsite:	URL
    AddedTwitter:	URL
    REVISIONS
    * 1:46 PM 5/23/2023 added test for dyn-ip workstations (skips submit, avoids lengthy port timeout wait on fail); added full pswlt support
    * 9:58 PM 11/7/2021 updated CBH with complete gmail example ; updated CBH with complete gmail example
    * 8:56 PM 11/5/2021 added $Credential & $useSSL param (to support gmail/a-smtp sends); added Param HelpMessage, added params to CBH
    * send-emailnotif.ps1: * 1:49 PM 11/23/2020 wrapped the email hash dump into a write-host cmd to get it streamed into the log at the point it's fired. 
    # 2:48 PM 10/13/2020 updated autodetect of htmltags to drive BodyAsHtml choice (in addition to explicit)
    # 1:12 PM 9/22/2020 pulled [string] type on $smtpAttachment (should be able to pass in an array of paths)
    # 12:51 PM 5/15/2020 fixed use of $global:smtpserver infra param for mybox/jumpboxes
    # 2:32 PM 5/14/2020 re-enabled & configured params - once it's in a mod, there's no picking up $script level varis (need explicits). Added -verbose support, added jumpbox alt mailing support
    # 1:14 PM 2/13/2019 Send-EmailNotif(): added $SmtpBody += "`$PassStatus triggers:: $($PassStatus)"
    # 11:04 AM 11/29/2018 added -ea 0 on the get-services, override abberant $mybox lacking new laptop
    # 1:09 PM 11/5/2018 reworked $email splat & attachment handling & validation, now works for multiple attachments, switched catch write-error's to write-hosts (was immed exiting)
    # 10:15 AM 11/5/2018 added test for MSExchangeADTopology service, before assuming running on an ex server
    #    also reworked $SMTPServer logic, to divert non-Mybox and non-EX (Lync) into vscan.
    # 9:50 PM 10/20/2017 just validating, this version has been working fine in prod
    # 10:35 AM 8/21/2014 always use a port; tested for $SMTPPort: if not spec'd defaulted to 25.
    # 10:17 AM 8/21/2014 added custom port spec for access to lynms650:8111 from my workstation
    .DESCRIPTION
    Send-EmailNotif.ps1 - Mailer function (wraps send-mailmessage)
    If using Gmail for mailings, pre-stock gmail cred file:
      To Setup a gmail app-password:
       - Google, logon, Security > 'Signing in to Google' pane:App Passwords > _Generate_:select app, Select device
       - reuse the app pw above in the credential prompt below, to store the apppassword as a credential in the current profile:
          get-credfile -PrefixTag gml -SignInAddress XXX@gmail.com -ServiceName Gmail -UserRole user
    .PARAMETER SMTPFrom
    Sender address
    .PARAMETER SmtpTo
    Recipient address
    .PARAMETER SMTPSubj
    Subject
    .PARAMETER server
    Server
    .PARAMETER SMTPPort
    Port number
    .PARAMETER useSSL
    Switch for SSL
    .PARAMETER SmtpBody
    Message Body
    .PARAMETER BodyAsHtml
    Switch for Body in Html format
    .PARAMETER SmtpAttachment
    array of attachement files
    .PARAMETER Credential
    Credential (PSCredential obj) [-credential XXXX]
    .EXAMPLE
    PS> # This normally gets triggered from Cleanup()
    # constants
    $smtpFrom = (($scriptBaseName.replace(".","-")) + "@toro.com") ;
    $smtpSubj= ("Daily Rpt: "+ (Split-Path $transcript -Leaf) + " " + [System.DateTime]::Now) ;
    #$smtpTo=$tormeta.NotificationDlUs2 ;
    #$smtpTo=$tormeta.NotificationDlUs ;
    # 1:02 PM 4/28/2017 hourly run, just send to me
    $smtpTo="dG9kZC5rYWRyaWVAdG9yby5jb20="| convertFrom-Base64String ; 
    # 12:09 PM 4/26/2017 need to email transcript before archiving it
    if($bdebug){ write-host -ForegroundColor Yellow "$((get-date).ToString('HH:mm:ss')):Mailing Report" };
    #Load as an attachment into the body text:
    #$body = (Get-Content "path-to-file\file.html" ) | converto-html ;
    #$SmtpBody += ("Pass Completed "+ [System.DateTime]::Now + "`nResults Attached: " +$transcript) ;
    $SmtpBody += "Pass Completed $([System.DateTime]::Now)`nResults Attached:($transcript)" ;
    if($PassStatus ){
        $SmtpBody += "`$PassStatus triggers:: $($PassStatus)" ;
    } ;
    $SmtpBody += ('-'*50) ;
    #$SmtpBody += (gc $outtransfile | ConvertTo-Html) ;
    # name $attachment for the actual $SmtpAttachment expected by Send-EmailNotif
    $SmtpAttachment=$transcript ;
    # 1:33 PM 4/28/2017 test for ERROR|CHANGE
    if($PassStatus ){
        $Email = @{
            smtpFrom = $SMTPFrom ;
            SMTPTo = $SMTPTo ;
            SMTPSubj = $SMTPSubj ;
            #SMTPServer = $SMTPServer ;
            SmtpBody = $SmtpBody ;
        } ;
        write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):Send-EmailNotif w`n$(($Email|out-string).trim())" ; 
        Send-EmailNotif @Email;
    } else {
        write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):No Email Report: `$Passstatus is $null ; " ;
    }  ;
    SMTP Send, using From, To, Subject & Body. 
    .EXAMPLE
    PS> $smtpToFailThru=convertFrom-Base64String -string "XXXXXXXXXXx"  ; 
    if(!$showdebug){
        if((Get-Variable  -name "$($TenOrg)Meta").value.NotificationAddr2){
            $smtpTo = (Get-Variable  -name "$($TenOrg)Meta").value.NotificationAddr2 ;
        #}elseif((Get-Variable  -name "$($TenOrg)Meta").value.NotificationAddr1){
        #   $smtpTo = (Get-Variable  -name "$($TenOrg)Meta").value.NotificationAddr1 ;
        } else {
            $smtpTo=$smtpToFailThru;
        } ;
    } else {
        # debug pass, variant to: NotificationAddr1    
        #if((Get-Variable  -name "$($TenOrg)Meta").value.NotificationDlUs){
        if((Get-Variable  -name "$($TenOrg)Meta").value.NotificationAddr1){
            $smtpTo = (Get-Variable  -name "$($TenOrg)Meta").value.NotificationAddr1 ;
        } else {
            $smtpTo=$smtpToFailThru ;
        } ;
    };
    if($tenOrg -eq 'HOM' ){
        $SMTPServer = "smtp.gmail.com" ; 
        $smtpFrom = $smtpTo ; # can only send via gmail from the auth address
    } else {
        $SMTPServer = $global:smtpserver ; 
        $smtpFromDom = (Get-Variable  -name "$($TenOrg)Meta").value.o365_OPDomain ; 
        $smtpFrom = (($CmdletName.replace(".","-")) + "@$( $smtpFromDom  )") ;
        $smtpFromDom = "gmail.com" ; 
    } ; 
    # -----------
    $smsg = "Mailing Report" ;
    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    # variant options:
    #$smtpSubj= "Proc Rpt:$($ScriptBaseName):$(get-date -format 'yyyyMMdd-HHmmtt')"   ;
    #Load as an attachment into the body text:
    #$body = (Get-Content "path-to-file\file.html" ) | converto-html ;
    #$SmtpBody += ("Pass Completed "+ [System.DateTime]::Now + "`nResults Attached: " +$transcript) ;
    # 4:07 PM 10/11/2018 giant transcript, no send
    #$SmtpBody += "Pass Completed $([System.DateTime]::Now)`nResults Attached:($transcript)" ;
    #$SmtpBody += "Pass Completed $([System.DateTime]::Now)`nTranscript:($transcript)" ;
    # group out the PassStatus_$($tenorg) strings into a report for eml body
    if($script:PassStatus){
        if($summarizeStatus){
            if(get-command -Name summarize-PassStatus -ea STOP){
                if($script:TargetTenants){
                    # loop the TargetTenants/TenOrgs and summarize each processed
                    #foreach($TenOrg in $TargetTenants){
                        $SmtpBody += "`n===Processing Summary: $($TenOrg):" ;
                        if((get-Variable -Name PassStatus_$($tenorg)).value){
                            if((get-Variable -Name PassStatus_$($tenorg)).value.split(';') |Where-Object{$_ -ne ''}){
                                $SmtpBody += (summarize-PassStatus -PassStatus (get-Variable -Name PassStatus_$($tenorg)).value -verbose:$($VerbosePreference -eq 'Continue') );
                            } ;
                        } else {
                            $SmtpBody += "(no processing of mailboxes in $($TenOrg), this pass)" ;
                        } ;
                        $SmtpBody += "`n" ;
                    #} ;
                } ;
                if($PassStatus){
                    if($PassStatus.split(';') |Where-Object{$_ -ne ''}){
                        $SmtpBody += (summarize-PassStatus -PassStatus $PassStatus -verbose:$($VerbosePreference -eq 'Continue') );
                    } ;
                } else {
                    $SmtpBody += "(no `$PassStatus updates, this pass)" ;
                } ;
            } else {
                $smsg = "Unable to gcm summarize-PassStatus!" ; ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN} #Error|Warn|Debug
                else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                throw $smsg
            }  ;
        } else {
            # dump PassStatus right into the email
            $SmtpBody += "`n`$script:PassStatus: $($script:PassStatus):" ;
        } ;
        if($outRpt -AND ($ProcMov.count -OR  $ProcTV.count) ){
            $smtpBody += $outRpt ;
        } ;
        if($SmtpAttachment){
            $smtpBody +="(Logs Attached)"
        };
        $SmtpBody += "`n$('-'*50)" ;
        # Incl $transcript in body, where fewer than limit of processed items logged in PassStatus
        # If using $Transcripts, there're 3 TenOrg-lvl transcripts, as an array, not approp
        if( ($script:PassStatus.split(';') |?{$_ -ne ''}|measure).count -lt $TranscriptItemsLimit){
            # add full transcript if less than limit entries in array
            $SmtpBody += "`nTranscript:$(gc $transcript)`n" ;
        } else {
            # attach $trans
            #if(!$ArchPath ){ $ArchPath = get-ArchivePath } ;
            $ArchPath = 'c:\tmp\' ;
            # path static trans from archpath
            #$archedTrans = join-path -path $ArchPath -childpath (split-path $transcript -leaf) ;
            # OR: if attaching array of transcripts (further down) - summarize fullname into body
            if($Alltranscripts){
                $Alltranscripts |ForEach-Object{
                    $archedTrans = join-path -path $ArchPath -childpath (split-path $_ -leaf) ;
                    $smtpBody += "`nTranscript accessible at:`n$($archedTrans)`n" ;
                } ;
            } ;
        };
    }
    $SmtpBody += "Pass Completed $([System.DateTime]::Now)" + "`n" + $MailBody ;
    # raw text body rendered in OL loses all CrLfs - do rendered html/css <pre/pre> approach
    $styleCSS = "<style>BODY{font-family: Arial; font-size: 10pt;}" ;
    $styleCSS += "TABLE{border: 1px solid black; border-collapse: collapse;}" ;
    $styleCSS += "TH{border: 1px solid black; background: #dddddd; padding: 5px; }" ;
    $styleCSS += "TD{border: 1px solid black; padding: 5px; }" ;
    $styleCSS += "</style>" ;
    $html = @"
    <html>
    <head>
    $($styleCSS)
    <title>$title</title></head>
    <body>
    <pre>
    $($smtpBody)
    </pre>
    </body>
    </html>
    "@ ;
    $smtpBody = $html ;
    # Attachment options:
    # 1. attach raw pathed transcript
    #$SmtpAttachment=$transcript ;
    # 2. IfMail: Test for ERROR
    #if($script:passstatus.split(';') -contains 'ERROR'){
    # 3. IfMail $PassStatus non-blank
    if([string]::IsNullOrEmpty($script:PassStatus)){
        $smsg = "No Email Report: `$script:PassStatus isNullOrEmpty" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    } else {
        $Email = @{
            smtpFrom = $SMTPFrom ;
            SMTPTo = $SMTPTo ;
            SMTPSubj = $SMTPSubj ;
            SMTPServer = $SMTPServer ;
            SmtpBody = $SmtpBody ;
            SmtpAttachment = $SmtpAttachment ;
            BodyAsHtml = $false ; # let the htmltag rgx in Send-EmailNotif flip on as needed
            verbose = $($VerbosePreference -eq "Continue") ;
        } ;
        # for gmail sends: add rqd params - note: GML requires apppasswords (non-user cred)
        $Email.add('Credential',$mailcred.value) ;
        $Email.add('useSSL',$true) ;
        $smsg = "Send-EmailNotif w`n$(($Email|out-string).trim())" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        Send-EmailNotif @Email ;
    } ;
    Full blown gmail mailer BP
    .LINK
    https://github.com/tostka/verb-Network
    #>
    <# Underlying available send-mailmessage params: (set up param aliases)
    Send-MailMessage [-To] <String[]> [-Subject] <String> [[-Body] <String>] [[-SmtpServer] <String>] [-Attachments
    <String[]>] [-Bcc <String[]>] [-BodyAsHtml] [-Cc <String[]>] [-Credential <PSCredential>]
    [-DeliveryNotificationOption <DeliveryNotificationOptions>] [-Encoding <Encoding>] [-Port <Int32>] [-Priority
    <MailPriority>] [-UseSsl] -From <String> [<CommonParameters>]
    #>
    [CmdletBinding(DefaultParameterSetName='SMTP')]
    PARAM(
        [parameter(Mandatory=$true,HelpMessage="Sender address")]
        [alias("from","SenderAddress")]
        [string] $SMTPFrom,
        [parameter(Mandatory=$true,HelpMessage="Recipient address")]
        [alias("To","RecipientAddress")]
        [string] $SmtpTo,
        [parameter(Mandatory=$true,HelpMessage="Subject")]
        [alias("Subject")]
        [string] $SMTPSubj,
        [parameter(HelpMessage="Server")]
        [alias("server")]
        [string] $SMTPServer,
        [parameter(HelpMessage="Port number")]
        [alias("port")]
        [int] $SMTPPort,
        [parameter(ParameterSetName='Smtp',HelpMessage="Switch for SSL")]        
        [parameter(ParameterSetName='Gmail',Mandatory=$true,HelpMessage="Switch for SSL")]
        [int] $useSSL,
        [parameter(Mandatory=$true,HelpMessage="Message Body")]
        [alias("Body")]
        [string] $SmtpBody,
        [parameter(HelpMessage="Switch for Body in Html format")]
        [switch] $BodyAsHtml,
        [parameter(HelpMessage="array of attachement files")]
        [alias("attach","Attachments","attachment")]
        $SmtpAttachment,
        [parameter(ParameterSetName='Gmail',HelpMessage="Switch to trigger stock Gmail send options (req Cred & useSSL)")]
        [switch] $GmailSend,
        [parameter(ParameterSetName='Smtp',HelpMessage="Credential (PSCredential obj) [-credential XXXX]")]        
        [parameter(ParameterSetName='Gmail',Mandatory=$true,HelpMessage="Credential (PSCredential obj) [-credential XXXX]")]
        [System.Management.Automation.PSCredential]$Credential
    )
    $verbose = ($VerbosePreference -eq "Continue") ; 
    if ($PSCmdlet.ParameterSetName -eq 'gmail') {
        $useSSL = $true; 
    } ;     
    # before you email conv to str & add CrLf:
    $SmtpBody = $SmtpBody | out-string
    # just default the port if missing, and always use it
    if ($SMTPPort -eq $null) {
        $SMTPPort = 25;
    }	 # if-block end

    if ( ($myBox -contains $env:COMPUTERNAME) -OR ($AdminJumpBoxes -contains $env:COMPUTERNAME) ) {
        $SMTPServer = $global:SMTPServer ;
        $SMTPPort = $smtpserverport ; # [infra file]
        $smsg = "Mailing:$($SMTPServer):$($SMTPPort)" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
    }
    elseif ((Get-Service -Name MSExchangeADTopology -ea 0 ) -AND (get-exchangeserver $env:computername | Where-Object {$_.IsHubTransportServer})) {
        $SMTPServer = $env:computername ;
        $smsg = "Mailing Locally:$($SMTPServer)" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
    }
    elseif ((Get-Service -Name MSExchangeADTopology -ea 0 ) ) {
        # non Hub Ex server, draw from local site
        $htsrvs = (Get-ExchangeServer | Where-Object {  ($_.Site -eq (get-exchangeserver $env:computername ).Site) -AND ($_.IsHubTransportServer) } ) ;
        $SMTPServer = ($htsrvs | get-random).name ;
        $smsg = "Mailing Random Hub:$($SMTPServer)" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
    }elseif( $rgxMyBoxW -AND ($env:COMPUTERNAME -match $rgxMyBoxW)){
        $smsg = "`$env:COMPUTERNAME -matches `$rgxMyBoxW: vscan UNREACHABLE" ; 
        $smsg += "`n(and dynamic IPs not configurable into restricted gateways)" ; 
        $smsg += "`nSkipping mail submission, no reachable destination" ; 
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent}
        else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
        Break ; 
    } else {
        # non-Ex servers, non-mybox: Lync etc, assume vscan access
        $smsg = "Non-Exch server, assuming Vscan access" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
        # but dyn ip workstations, not

        $SMTPServer = "vscan.toro.com" ;
    } ;

    # define/update variables into $Email splat for params
    $Email = @{
        From       = $SMTPFrom ;
        To         = $SMTPTo ;
        Subject    = $($SMTPSubj) ;
        SMTPServer = $SMTPServer ;
        Body       = $SmtpBody ;
        BodyAsHtml = $false ; 
        verbose = $verbose ; 
    } ;

    if($Credential){
        $smsg = "WVAdding specified credential" ; 
        $Email.add('Credential',$Credential) ; 
    } ; 
    
    if($useSSL){
        $smsg = "WVAdding specified credential" ; 
        $Email.add('useSSL',$useSSL) ; 
    } ; 
    
    [array]$validatedAttachments = $null ;
    if ($SmtpAttachment) {
        # attachment send
        if ($SmtpAttachment -isnot [system.array]) {
            if (test-path $SmtpAttachment) {$validatedAttachments += $SmtpAttachment }
            else {write-warning "$((get-date).ToString('HH:mm:ss')):UNABLE TO GCI ATTACHMENT:$($SmtpAttachment)" }
        }
        else {
            foreach ($attachment in $SmtpAttachment) {
                if (test-path $attachment) {$validatedAttachments += $attachment }
                else {write-warning "$((get-date).ToString('HH:mm:ss')):UNABLE TO GCI ATTACHMENT:$($attachment)" }  ;
            } ;
        } ;
    } ; 

    if ($host.version.major -ge 3) {$Email.add("Port", $($SMTPPort));}
    elseif ($SmtpPort -ne 25) {
        $smsg = "WWLess than Psv3 detected: send-mailmessage does NOT support -Port, defaulting (to 25) ";
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
        else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
    } ;

    # trigger html if body has html tags in it
    if ($BodyAsHtml -OR ($SmtpBody -match "\<[^\>]*\>")) {$Email.BodyAsHtml = $True } ;

    # dumping to pipeline appears out of sync in console put it into a write- command to keep in sync
    $smsg = "send-mailmessage w`n$(($email |out-string).trim())" ; 
    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
    if ($validatedAttachments) {
        $smsg = "`$validatedAttachments:$(($validatedAttachments|out-string).trim())" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
    } ;
    $error.clear()
    TRY {
        if ($validatedAttachments) {
            # looks like on psv2?v3 attachment is an array, can be pipelined in too
            $validatedAttachments | send-mailmessage @email ;
        }
        else {
            send-mailmessage @email
        } ;
    }
    Catch {
        $smsg = "Failed processing $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
        else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
    } ; 
    $error.clear() ;
}

#*------^ Send-EmailNotif.ps1 ^------


#*------v summarize-PassStatus.ps1 v------
function summarize-PassStatus {
    <#
    .SYNOPSIS
    summarize-PassStatus - Summarize $PassStatus string (semi-colon-delimited array) into a grouped formatted herestring report of the histogram of values. 
    .NOTES
    Version     : 1.0.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 20201012-0849AM
    FileName    : summarize-PassStatus
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka/
    REVISIONS
    * 8:49 AM 10/12/2020 init
    .DESCRIPTION
    summarize-PassStatus - Summarize $PassStatus string (semi-colon-delimited array) into a grouped formatted herestring report of the histogram of values. 
    .OUTPUTS
    System.String
    .EXAMPLE
    $SmtpBody += (summarize-PassStatus -PassStatus ';CHANGE;CHANGE;CHANGE;CHANGE;CHANGE;CHANGE;ERROR;ADD' )
    Returns a summary historgram of the specified semi-colon-delimited array of PassStatus values
    .EXAMPLE
    # group out the PassStatus_$($tenorg) strings into a report for eml body
    if($script:PassStatus){
        if($summarizeStatus){
            if($script:TargetTenants){
                # loop the TargetTenants/TenOrgs and summarize each processed
                foreach($TenOrg in $TargetTenants){
                    $SmtpBody += "`n===Processing Summary: $($TenOrg):" ; 
                    if((get-Variable -Name PassStatus_$($tenorg)).value){
                        if((get-Variable -Name PassStatus_$($tenorg)).value.split(';') |?{$_ -ne ''}){
                            $SmtpBody += (summarize-PassStatus -PassStatus (get-Variable -Name PassStatus_$($tenorg)).value -verbose:$($VerbosePreference -eq 'Continue') );
                        } ; 
                    } else {
                        $SmtpBody += "(no processing of mailboxes in $($TenOrg), this pass)" ; 
                    } ; 
                    $SmtpBody += "`n" ; 
                } ; 
            } ;
        } else { 
            # dump PassStatus right into the email
            $SmtpBody += "`n`$script:PassStatus: $($script:PassStatus):" ; 
        } ;
        if($SmtpAttachment){ 
            $smtpBody +="(Logs Attached)" 
        };
        $SmtpBody += "`n$('-'*50)" ;
    }
    .LINK
    https://github.com/tostka/verb-Network
    #>
    [CmdletBinding()] 
    Param(
        [Parameter(Position=0,Mandatory=$True,HelpMessage="Semi-colon-delimited string of PassStatus elements, to be summarized in a returned report[-PassStatus 'TEN1']")]
        [ValidateNotNullOrEmpty()]
        [string]$PassStatus
    ) ;
    BEGIN {$Verbose = ($VerbosePreference -eq 'Continue') } ;
    PROCESS {
        $Error.Clear() ;
        if($StatusElems = $PassStatus.split(';') |?{$_ -ne ''}){
        $Rpt = @"
    
`$PassStatus Triggers Summary::

$(($StatusElems | group | sort count -desc | ft -auto Count,Name|out-string).trim())
    
"@ ; 
        } else {
            $Rpt = @"
    
`$PassStatus Triggers Summary::

(no `$PassStatus elements passed)
    
"@ ; 
        } ; 
    } ;  # PROC-E
    END{
          $Rpt | write-output ; 
    } ;
}

#*------^ summarize-PassStatus.ps1 ^------


#*------v summarize-PassStatusHtml.ps1 v------
function summarize-PassStatusHtml {
    <#
    .SYNOPSIS
    summarize-PassStatusHtml - Summarize $PassStatus string (semi-colon-delimited array) into a grouped formatted HTML report of the histogram of values. 
    .NOTES
    Version     : 1.0.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 20201012-0849AM
    FileName    : summarize-PassStatusHtml
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka/
    REVISIONS
    * 8:49 AM 10/12/2020 init, half-implemented, untested, moved to another method instead
    .DESCRIPTION
    summarize-PassStatusHtml - Summarize $PassStatus string (semi-colon-delimited array) into a grouped formatted HTML (fragment) report of the histogram of values. 
    .OUTPUTS
    System.String
    .EXAMPLE
    $datatable = (summarize-PassStatusHtml -PassStatus ';CHANGE;CHANGE;CHANGE;CHANGE;CHANGE;CHANGE;ERROR;ADD' )
    $smtpBody = ConvertTo-HTML -Body "$datatable" -Title "" -PostContent "<p>(Creation Date: $((get-date -format 'yyyyMMdd-HHmmtt'))<p>" 
    Returns a summary historgram of the specified semi-colon-delimited array of PassStatus values
    .LINK
    https://github.com/tostka/
    #>
    
    [CmdletBinding()] 
    Param(
        [Parameter(Position=0,Mandatory=$True,HelpMessage="Semi-colon-delimited string of PassStatus elements, to be summarized in a returned report[-PassStatus 'TEN1']")]
        [ValidateNotNullOrEmpty()]
        [string]$PassStatus
    ) ;
    BEGIN {$Verbose = ($VerbosePreference -eq 'Continue') } ;
    PROCESS {
        $Error.Clear() ;
        if($StatusElems = $script:PassStatus.split(';') |?{$_ -ne ''}){

            $datatable = $StatusElems | group | sort count -desc  | ConvertTo-Html -Property count,Name -Fragment -PreContent "<h2>`$PassStatus Triggers Summary::</h2>" ; 
            # full html build in the return 
            #$Report = ConvertTo-HTML -Body "$datatable" -Title "`$PassStatus Triggers Summary::" -PostContent "<p>(Creation Date: $((get-date -format 'yyyyMMdd-HHmmtt'))<p>" 

            <#
            $Rpt = @"
    
`$PassStatus Triggers Summary::

$(($StatusElems | group | sort count -desc | ft -auto Count,Name|out-string).trim())
    
"@ ; 
#>
        } else {

            $datatable = "<h2>`$PassStatus Triggers Summary::</h2>(no `$PassStatus elements passed)<br>" ;

            <#
            $Rpt = @"
    
`$PassStatus Triggers Summary::

(no `$PassStatus elements passed)
    
"@ ; 
#>
        } ; 
    } ;  # PROC-E
    END{
          $datatable | write-output ; 
    } ;
}

#*------^ summarize-PassStatusHtml.ps1 ^------


#*------v test-Connection-T.ps1 v------
function test-Connection-T {
    <#
    .SYNOPSIS
    test-Connection-T - Endless test-Connection pings (simple equiv to ping -t)
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2020-04-17
    FileName    : test-Connection-T.ps1
    License     : MIT License
    Copyright   : (c) 2023 Todd Kadrie
    Github      : https://github.com/verb-Network
    Tags        : Powershell,Internet,Download,File
    AddedCredit : poshftw
    AddedWebsite: https://old.reddit.com/r/PowerShell/comments/moxy5v/downloading_a_file_with_powershell_without/
    AddedTwitter: URL
    AddedCredit : Patrick Gruenauer
    AddedWebsite: https://sid-500.com/2019/10/22/powershell-endless-ping-with-test-connection/
    AddedTwitter: @jmcnatt / https://twitter.com/jmcnatt
    REVISIONS
    * 1:07 PM 3/27/2023 built, added to verb-Network
    .DESCRIPTION
    test-Connection-T - Endless test-Connection pings (simple equiv to ping -t)
    Uses the [int32]::MaxValue to push the -count so high it's just about endless, as a single command, without a DoLoop
    From a simple -count param tweak recommended by Patrick Gruenauer, wrapped with a function
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output
    .EXAMPLE
    test-Connection-T someserver
    Demo endless 1/second ping. 
    .EXAMPLE
    test-Connection-T 1.1.1.1 -Delay 5;
    Demo endless ping, every 5secs
    .LINK
    https://github.com/verb-Network
    #>
    ## [OutputType('bool')] # optional specified output type
    [CmdletBinding()]
    ###[Alias('Alias','Alias2')]
    PARAM (
        [Parameter(Mandatory=$true,Position=0,HelpMessage = "Specifies the computers to ping. Type the computer names or type IP addresses in IPv4 or IPv6 format. Wildcard characters are not permitted. This parameter is required.")]
        [System.String[]]$ComputerName,
        [Parameter(HelpMessage = "Specifies the interval between pings, in seconds (max 60).")]
        [System.Int32]$Delay
    ) ; 
    PROCESS {
        $Error.Clear() ; 
        foreach($item in $Computername){
            Test-Connection $item -Count ([int32]::MaxValue) -Delay:$($Delay) ; 
        } ;   # loop-E
    } ;  # if-PROC
}

#*------^ test-Connection-T.ps1 ^------


#*------v Test-DnsDkimCnameToTxtKeyTDO.ps1 v------
function Test-DnsDkimCnameToTxtKeyTDO {
    <#
    .SYNOPSIS
    Test-DnsDkimCnameToTxtKeyTDO - Trace a local CNAME DKIM DNS record, to it's endpoint TXT DKIM key-holding record (and validate it's actually a DKIM key). 
    .NOTES
    Version     : 0.0.5
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2022-11-03
    FileName    : Test-DnsDkimCnameToTxtKeyTDO
    License     : MIT License
    Copyright   : (c) 2022 Todd Kadrie
    Github      : https://github.com/tostka/verb-network
    Tags        : Powershell
    REVISIONS
    * 5:41 PM 12/30/2022 expanded rgx public-key test, added dkim key tag 
        requirements doc, test is down to essential p=xxx public key only ;  updated 
        CBH demos w fancy EXO DKIM per-domain looped validation; ported to func, 
        working; init;  
    .DESCRIPTION
    Test-DnsDkimCnameToTxtKeyTDO - Trace a local CNAME DKIM DNS record, to it's endpoint TXT DKIM key-holding record (and validate it's actually a DKIM key). 

       Along the way, I did a *a fair amount* of coding logic...

        1. running looped CNAME resolve-dnsname's, 
        2. detecting a returned SOA type (when the next record was a TXT), 
        3. then switching resolution to a final TXT resolve-dnsname pass.
    
    ... to quickly deliver local domain CNAME to remote SAAS vendor DKIM key TXT validation
     (when, 'It NO WORKY!' tickets came through against 3rd-party operated services). 

    Had that version *working*, and *then* while testing, I noticed a 'feature' of resolve-dnsname:

    Feed a cname fqdn through resolve-dnsname, WITHOUT A TYPE spec, and it AUTO RECURSES!
        - If it's a CNAME -> CNAME -> TXT chain, you'll get back 3 records: CNAME, CNAME, SOA (fail indicator). 
        - Postfilter out the SOA, and you've got the series of initial hops to the TXT.
        - Then Run a final -type TXT on the last CNAME's NameHost, and you get the TXT back (with the DKIM key)
   
    > Note: have to strongly type output assignment as Array to get proper Op.addition support for the trailing TXT record.

    $results = @(resolve-dnsname CNAME.domain.tld  -server 1.1.1.1 |? type -ne 'SOA') ; 
    $results += @($results | select -last 1  | %{resolve-dnsname -type TXT -server 1.1.1.1 -name $_.namehost}) ; 

    => 99% of my prior non-reporting & content validating code, could be reduced down to the above 2 LINES! [facepalm]

    I've retained the rem'd out original code (in case they write the 'autorecurse' feature out, down the road), but boiled this down to that essential logic above.

    Uses my verb-IO module convertTo-MarkdownTable() to box-format the output, diverts to format-table -a when it's not available. 

    .PARAMETER DkimDNSName
    Local AcceptedDomain CNAME DKIM DNS record, to be trace-resolved to key-holding TXT record. [-DkimDNSName 'host.domain.com']
    .PARAMETER PublicDNSServerIP
    Public DNS server (defaults to Cloudflare's 1.1.1.1, could use Google's 8.8.8.8)[-PublicDNSServerIP '8.8.8.8']
    .PARAMETER outputObject
    Switch that triggers output of results to pipeline [-outputObject] 
    .INPUTS
    None. Does not accepted piped input.(.NET types, can add description)
    .OUTPUTS
    None. Returns no objects or output (.NET types)
    .EXAMPLE
    PS> Test-DnsDkimCnameToTxtKeyTDO -DkimDNSName HOST.DOMAIN.COM -verbose ;
    Demo resursive CNAME to TXT DKIM key resolve of DKIM CNAME DNS record name
    .EXAMPLE
    PS> Test-DnsDkimCnameToTxtKeyTDO -DkimDNSName 'selector1._domainkey.DOMAIN.TLD','HOST.DOMAIN.com' ; 
        11:25:09:#*======v Test-DnsDkimCnameToTxtKeyTDO v======
        11:25:09:
        #*------v PROCESSING : selector1._domainkey.DOMAIN.TLD v------
        11:25:09:

        ==HOP: 1: CNAME: selector1._domainkey.DOMAIN.TLD ==> selector1-domain-tld._domainkey.TENANT.onmicrosoft.com:
        | Type  | Name                            | NameHost                                               |
        | ----- | ------------------------------- | ------------------------------------------------------ |
        | CNAME | selector1._domainkey.DOMAIN.TLD | selector1-domain-tld._domainkey.TENANT.onmicrosoft.com |
        
        11:25:09:

        ==HOP: 2: TXT:Value record::

        | Type | Name                                                   |
        | ---- | ------------------------------------------------------ |
        | TXT  | selector1-domain-tld._domainkey.TENANT.onmicrosoft.com |

        | Strings         |
        | --------------- |
        | v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3D[TRIMMED]NcHJRPWbPisCiRFPfUGtCNQIDAQAB; |
        
        ===:TXT: selector1-domain-tld._domainkey.TENANT.onmicrosoft.com.strings *IS VALIDATED* to contain a DKIM key:
        
        11:25:09:
        #*------^ PROCESSING : selector1._domainkey.DOMAIN.TLD ^------
        11:25:09:
        #*------v PROCESSING : HOST.DOMAIN.com v------
        11:25:09:

        ==HOP: 1: CNAME: HOST.DOMAIN.com ==> HOST.vnnnnnnnn.nnnnnnnnnn.e.VENDOR.services:
        | Type  | Name            | NameHost                                    |
        | ----- | --------------- | ------------------------------------------- |
        | CNAME | HOST.DOMAIN.com | HOST.vnnnnnnnn.nnnnnnnnnn.e.VENDOR.services |
        
        11:25:09:

        ==HOP: 2: CNAME: HOST.vnnnnnnnn.nnnnnnnnnn.e.VENDOR.services ==> unnnnnnnn.wlnnn.sendgrid.net:
        | Type  | Name                                        | NameHost                     |
        | ----- | ------------------------------------------- | ---------------------------- |
        | CNAME | HOST.vnnnnnnnn.nnnnnnnnnn.e.VENDOR.services | unnnnnnnn.wlnnn.sendgrid.net |
        
        WARNING: 11:25:09:

        ==HOP: 3: TXT:Value record::

        | Type | Name                         |
        | ---- | ---------------------------- |
        | TXT  | unnnnnnnn.wlnnn.sendgrid.net |

        | Strings         |
        | --------------- |
        | v=spf1 ip4:167.11.11.96 ip4:167.11.11.1 ip4:167.11.11.100 ip4:167.11.11.102 -all |
        
        ===:TXT: unnnnnnnn.wlnnn.sendgrid.net.strings *DOES NOT VALIDATE* to contain a DKIM key!
        (strings should start with 'v=DKIM1')

        11:25:09:
        #*------^ PROCESSING : HOST.DOMAIN.com ^------
        11:25:09:#*======^ Test-DnsDkimCnameToTxtKeyTDO ^======

    Demo looping array of names, with one with a failure to validate ('cuz the vendor stuffed an SPF where a DKIM TXT record belonged!)
    .EXAMPLE
    PS>  $domains = Get-xoDkimSigningConfig |Where-Object {$_.Enabled -like "True" -AND $_.name -notlike '*.onmicrosoft.com'} ;
    PS>  foreach($domain in $domains){
    PS>      $dNow = Get-date ; 
    PS>      $lCNAMES1 = "$($domain.Selector1CNAME.split('-')[0])._domainkey.$($domain.Name)" ; 
    PS>      $lCNAMES2 = "$($domain.Selector2CNAME.split('-')[0])._domainkey.$($domain.Name)" ; 
    PS>      $PreRollSelector = $domain.SelectorBeforeRotateOnDate ; 
    PS>      $PostRollSelector = $domain.SelectorAfterRotateOnDate ; 
    PS>      If($($domain.RotateOnDate.ToUniversalTime()) -gt $($dNow.ToUniversalTime()) ){
    PS>          $whichSelector = "$($PreRollSelector)Cname" ; 
    PS>      } else{
    PS>          $whichSelector = "$($PostRollSelector)Cname" ; 
    PS>      } ; 
    PS>      $ActiveSelector = $domain."$whichSelector" ;
    PS>      $ActivelCNAME = @($lCNAMES1,$lCNAMES2) | ?{$_ -like "$($domain."$whichSelector".split('-')[0])*"} ; 
    PS>      $INActivelCNAME = @($lCNAMES1,$lCNAMES2) | ?{$_ -notlike "$($domain."$whichSelector".split('-')[0])*"} ; 
    PS>      $ActivelCNAME | Test-DnsDkimCnameToTxtKeyTDO ; 
    PS>      write-host "Validate *INACTIVE* local CNAME (exists in local External DNS, but won't be resolvable at vendor)" ; 
    PS>      $INActivelCNAME | Resolve-DnsName -Type CNAME -server 1.1.1.1 | ft -a 'Type','Name','NameHost' ;
    PS>  } ; 

        16:01:09:#*======v Test-DnsDkimCnameToTxtKeyTDO v======
        16:01:09:
        #*------v PROCESSING : selector2._domainkey.DOMAIN.TLD v------
        16:01:10:

        ==HOP: 1: CNAME: selector2._domainkey.DOMAIN.TLD ==> selector2-domain-tld._domainkey.TENANT.onmicrosoft.com:
        | Type  | Name                          | NameHost                                             |
        | ----- | ----------------------------- | ---------------------------------------------------- |
        | CNAME | selector2._domainkey.DOMAIN.TLD | selector2-domain-tld._domainkey.TENANT.onmicrosoft.com |


        16:01:10:

        ==HOP: 2: TXT:Value record::

        | Type | Name                                                 |
        | ---- | ---------------------------------------------------- |
        | TXT  | selector2-domain-tld._domainkey.TENANT.onmicrosoft.com |

        | Strings         |
        | --------------- |
        | v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUA[TRIMMED]4/EVxy78tKSfzdMoBV20IDO9GvGnDF1WLdOO48IUi+1Oa4bMoLqizt5Duv4WbgY/lXePnSA9iQIDAQAB; |

        --->TXT: selector2-domain-tld._domainkey.TENANT.onmicrosoft.com.strings *IS VALIDATED* to contain a DKIM key.

        16:01:10:
        #*------^ PROCESSING : selector2._domainkey.DOMAIN.TLD ^------
        16:01:10:#*======^ Test-DnsDkimCnameToTxtKeyTDO ^======
        Validate *INACTIVE* local CNAME (exists in local External DNS, but won't be resolvable at vendor)

         Type Name                          NameHost
         ---- ----                          --------
        CNAME selector1._domainkey.DOMAIN.TLD selector1-domain-tld._domainkey.TENANT.onmicrosoft.com
    
        # (above continues for each configured enabled domain)

    Fancier demo of walking the enabled EXO DkimSigningConfig domains (non-onmicrosoft, which have no local DNS validation), foreach:
        - resolve the pair of local CNAME hostnames (MS uses 2, rolled on key rollovers sequentially, only one active at a time).
        - calculate the active MS Selector, and the matching local CNAME
        - Then validating the chain from the active local CNAME through to the MS-hosted TXT record and validating it has a DKIM key.
    .LINK
    https://bitbucket.com/tostka/powershell
    #>
    # VALIDATORS: [ValidateNotNull()][ValidateNotNullOrEmpty()][ValidateLength(24,25)][ValidateLength(5)][ValidatePattern("some\sregex\sexpr")][ValidateSet("US","GB","AU")][ValidateScript({Test-Path $_ -PathType 'Container'})][ValidateScript({Test-Path $_})][ValidateRange(21,65)]#positiveInt:[ValidateRange(0,[int]::MaxValue)]#negativeInt:[ValidateRange([int]::MinValue,0)][ValidateCount(1,3)]
    ## [OutputType('bool')] # optional specified output type
    [CmdletBinding()]
    PARAM(
        [Parameter(Mandatory=$true,Position = 0,ValueFromPipeline = $True,HelpMessage="Array of local AcceptedDomain CNAME DKIM DNS record, to be trace-resolved to key-holding TXT record. [-DkimDNSName 'host.domain.com']")]
        [Alias('Name')]
        [string[]] $DkimDNSName,
        [Parameter(HelpMessage="Public DNS server (defaults to Cloudflare's 1.1.1.1, could use Google's 8.8.8.8)[-PublicDNSServerIP '8.8.8.8']")]
        [Alias('Server')]
        [ipaddress]$PublicDNSServerIP = '1.1.1.1',
        [Parameter(HelpMessage="Switch that triggers output of results to pipeline [-outputObject]")]
        [switch]$outputObject
    ) ;
    BEGIN{
        #region CONSTANTS-AND-ENVIRO #*======v CONSTANTS-AND-ENVIRO v======
        # function self-name (equiv to script's: $MyInvocation.MyCommand.Path) ;
        ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
        $verbose = ($VerbosePreference -eq "Continue") ;
        $PSParameters = New-Object -TypeName PSObject -Property $PSBoundParameters ;
        write-verbose "`$PSBoundParameters:`n$(($PSBoundParameters|out-string).trim())" ;

                                                                                                                                                                                                                                                                                                                                                                                                                                                                            
<# PRIOR CODE THAT HAS BEEN SUBSTANTIALLY REPLACED WITH THE DEMO IN THE CBH:

$pltRDNS=[ordered]@{
    Name= $null ;
    Type='CNAME' ;
    Server=$PublicDNSServerIP ;
    erroraction = 'SilentlyContinue' ;
} ;
$smsg = "Recursive CNAME -> TXT lookup..." ; 
if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level PROMPT } 
else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
#Levels:Error|Warn|Info|H1|H2|H3|Debug|Verbose|Prompt
$pltRDNS.Name= $DkimDNSName;
$pltRDNS.type = 'CNAME' ; 
$pltRDNS.erroraction = 'SilentlyContinue' ;
$depth = 0 ; 
$CNAMEEnd = $false ; 
$prpCNAME = 'Type','Name','NameHost' ; 
$prpTXT = 'Type','Name','Strings' ; 
$prpSOA = 'Type','Name','PrimaryServer' ; 
$TypeOrder = 'CNAME','TXT' ; 
$TypeCurr = 0 ; 
$ResolvedStack = @() ; 
$works = $null ; 
$rNo=1 ; 
Do {
    if($works -eq $null){
        $pltRDNS.Name = $DkimDNSName; 
    } else { 
        if(-not $works.namehost){
            $pltRDNS.name = $priorName
        } else {
            $pltRDNS.Name = $works.namehost
        } ; 
    } ; 
    $pltRDNS.type = $TypeOrder[$TypeCurr] ; 
    $depth ++ ; 
    $smsg = "==Hop:$($rNo):"
    $smsg += "Resolve-DnsName w`n$(($pltRDNS|out-string).trim())" ; 
    if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
    $works = $null ; 
    $works = Resolve-DnsName @pltRDNS ; 
    If($works){
        switch($works.type){
            $TypeOrder[$TypeCurr]{
                $smsg = "record.Type:$($works.Type) returned (expected for this query type)" ; 
                $smsg += "`n$(($works|out-string).trim())" ; 
                if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                $priorName = $works.NameHost ; 
                $ResolvedStack += $works ;
                if($works.Type -eq 'TXT'){
                    $CNAMEEnd = $true ;
                    Break ; 
                } ; 
                $rNo++ 
            } 
            default {
                $smsg = "($($TypeOrder[$TypeCurr]):attempted lookup fail: type:$($works.type) returned. Retrying as $($TypeOrder[$TypeCurr + 1]))" ; 
                if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                $TypeCurr++ ; 
            } 
        }  ; 
    } else {
        $smsg = "Resolution attempt FAILED to return populated data!" ; 
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } 
        else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
    } ;     
} Until ($CNAMEEnd -eq $true) ; 
$smsg = "(Lookup chain completed, $($rNo) Hops traced)" ; 
if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level PROMPT } 
else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
#Levels:Error|Warn|Info|H1|H2|H3|Debug|Verbose|Prompt
$rNo=0 ; 
foreach($rec in $ResolvedStack){
    $rNo++ ; 
    $smsg = "`n`n==HOP: $($rNo): " ;
    switch ($rec.type){
        'CNAME' {
            $smsg += "$($rec.Type): $($rec.Name) ==> $($rec.NameHost):" ; 
            #$smsg += "`n`n$(($rec | ft -a $prpCNAME |out-string).trim())`n" ; 
            $smsg += "`n" ; 
            $smsg += $rec | select $prpCNAME | Convertto-Markdowntable -Border ; 
            $smsg += "`n" ; 
        } 
        'TXT' { 
            $smsg += "$($rec.Type):Value record::`n" ; 
            #$smsg += "`n$(($rec | ft -a $prpTXT[0..1] |out-string).trim())" ; 
            #$smsg += "`nStrings(e.g KEY FIELD):`n$(($rec | ft -a $prpTXT[2] | out-string).trim())" ; 
            $smsg += "`n" ; 
            #$smsg += $rec | select $prpTXT | Convertto-Markdowntable -Border ; 
            $smsg += $rec | select $prpTXT[0..1] | Convertto-Markdowntable -Border ; 
            $smsg += "`n" ;
            $smsg += $rec | select $prpTXT[2] | Convertto-Markdowntable -Border ; 
            $smsg += "`n" ; 
            if($rec.Strings -match 'v=DKIM1;\sk=rsa;\sp='){
                $domainSummary.TXTActiveValid = $true ; 
                $smsg += "`n--->TXT: $($rec.Name).strings *IS VALIDATED* to contain a DKIM key.`n" ; 
            }else {
                $smsg += "`n`n--->TXT: $($rec.Name).strings *DOES NOT VALIDATE* to contain a DKIM key`n`n" ; 
                throw $smsg ; 
            }
       } 
       'SOA' {
            $smsg += "`nSOA/Lookup-FAIL record detected!" ; 
            $smsg += "`n$(($rec | ft -a $prpSOA | out-string).trim())" ; 
            throw $smsg ;
       }
       default {throw "Unrecognized record TYPE!" } 
    } ; 
    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
};
write-host " " ; 
    #>

        $prpCNAME = 'Type','Name','NameHost' ; 
        $prpTXT = 'Type','Name','Strings' ; 
        $prpSOA = 'Type','Name','PrimaryServer' ; 
        $sBnr="#*======v $($CmdletName) v======" ; 
        $whBnr = @{BackgroundColor = 'Magenta' ; ForegroundColor = 'Black' } ;
        write-host @whBnr -obj "$((get-date).ToString('HH:mm:ss')):$($sBnr)" ;
    } ; 
    PROCESS{
        foreach($item in $DkimDNSName){

            $sBnrS="`n#*------v PROCESSING : $($item) v------" ; 
            $whBnrS =@{BackgroundColor = 'Blue' ; ForegroundColor = 'Cyan' } ;
            write-host @whBnrS -obj "$((get-date).ToString('HH:mm:ss')):$($sBnrS)" ;
            [array]$results = @() ; 
            $results = @(resolve-dnsname $item -server $PublicDNSServerIP) ; 

            write-verbose "postfilter out the SOA result  (leaving CNAMES)" ; 
            $results = $results |? type -ne 'SOA' ; 

            write-verbose " then re-search and add the Namehost on the final CNAME as a TXT" ; 
            $results += @($results | select -last 1  | %{resolve-dnsname -type TXT -server $PublicDNSServerIP -name $_.namehost}) ; 

            write-verbose "Report the formatted/validated output" ;
            $rNo=0 ; 
            foreach($rec in $results){
                $rNo++ ; 
                $RecFail = $false ; 
                $smsg = "`n`n==HOP: $($rNo): " ;
                switch ($rec.type){
                    'CNAME' {
                        $smsg += "$($rec.Type): $($rec.Name) ==> $($rec.NameHost):" ; 
                        $smsg += "`n" ; 
                        if(get-command Convertto-Markdowntable -ea 0){
                            $smsg += $rec | select $prpCNAME | Convertto-Markdowntable -Border ; 
                        } else { 
                            $smsg += $rec | ft -a $prpCNAME  ; 
                        } ; 
                        $smsg += "`n" ; 
                    } 
                    'TXT' { 
                        $smsg += "$($rec.Type):Value record::`n" ; 
                        $smsg += "`n" ; 
                        if(get-command Convertto-Markdowntable -ea 0){
                            $smsg += $rec | select $prpTXT[0..1] | Convertto-Markdowntable -Border ; 
                            $smsg += "`n" ;
                            $smsg += $rec | select $prpTXT[2] | Convertto-Markdowntable -Border ; 
                        } else { 
                            $smsg += $rec | ft -a  $prpTXT[0..1] ; 
                            $smsg += "`n" ;
                            $smsg += $rec | ft -a $prpTXT[2] ; 
                        } ; 
                        $smsg += "`n" ; 
<# 
    # DKIM TAG REQUIREMENTS

    [DKIM DNS record overview – Validity Help Center - help.returnpath.com/](https://help.returnpath.com/hc/en-us/articles/222481088-DKIM-DNS-record-overview)

    ### Required tag

    -   p= is the public key used by a mailbox provider to match to the DKIM 
        signature generated using the private key. The value is a string of characters 
        representing the public key. It is generated along with its corresponding 
        private key during the DKIM set-up process

    ### Recommended optional tags
 
    -   v= is the version of the DKIM record. The value must be DKIM1 and be 
        the first tag in the DNS record

    -   t= indicates the domain is testing DKIM or is enforcing a domain 
        match in the signature header between the "i=" and "d=" tags

    -   t=y indicates the domain is testing DKIM.​ Senders use this tag 
        when first setting up DKIM to ensure the DKIM signature is verifying correctly. 
        Some mailbox providers ignore a DKIM signature in test mode, so this tag should 
        be removed prior to full deployment or changed to t=s if using the "i=" tag in 
        the DKIM signature header

    -   t=s indicates that any DKIM signature header using the "i=" tag 
        must have the same domain value on the right-hand side of the @ sign in the 
        "i=" tag and the "d=" tag (i= local-part@domain.com). The "i=" tag  domain must 
        not be a subdomain of the "d=" tag. Do not include this tag if the use of a 
        subdomain is required

    ### Optional tags
 
    -   g= is the granularity of the public key. The value must match the 
        local-part of the i= flag in the DKIM signature field (i= 
        local-part@domain.com) or contain a wildcard asterisk (\*). The use of this 
        flag is intended to constrain which signing address can use the selector 
        record

    -   h= indicates which hash algorithms are acceptable. The default 
        value is to allow for all algorithms but you can specify sha1 and sha256. 
        Signers and verifiers must support sha256. Verifiers must also support sha1

    -   k= indicates the key type. The default value is rsa which must be 
        supported by both signers and verifiers

    -   n= is a note field intended for administrators, not end users. 
        The default value is empty and may contain a note that an administrator may 
        want to read

    -   s= indicates the service type to which this record applies. The 
        default value is a wildcard asterisk (\*) which matches all service types. The 
        other acceptable value allowed is the word "email" which indicates that the 
        message is an electronic mail message. This tag is not the same as a selector record.
        It is intended to constrain the use of keys if DKIM is used for other 
        purposes other than email in the future. If used, it is included in the DKIM 
        DNS TXT record and not the DKIM signature. Should other service types be 
        defined in the future, verifiers will ignore the DKIM record if it does not 
        match the type of message sent

 

#>
                        #if($rec.Strings -match 'v=DKIM1;\sk=rsa;\sp='){
                        if($rec.Strings -match 'v=DKIM1;\sk=rsa;\sp='){
                            $smsg += "`n`n--->TXT: $($rec.Name).strings *IS VALIDATED* to contain a DKIM key.`n`n" ; 
                        }elseif($rec.Strings -match 'p=\w+'){
                            # per above, this matches only the bare minimum!
                            $smsg += "`n`n--->TXT: $($rec.Name).strings *IS VALIDATED* to contain a DKIM key.`n`n" ; 
                        }else {
                            $smsg += "`n`n--->TXT: $($rec.Name).strings *DOES NOT VALIDATE* to contain a DKIM key!`n(strings should start with 'v=DKIM1', or at minimum include a p=xxx public key)`n`n" ; 
                            #if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } 
                            #else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                            #write-host @whBnr -obj "$((get-date).ToString('HH:mm:ss')):$($sBnr.replace('=v','=^').replace('v=','^='))" ;
                            #throw $smsg ; 
                            #Break ; 
                            $RecFail = $true ; 
                        }
                   } 
                   'SOA' {
                        $smsg += "`nSOA/Lookup-FAIL record detected!" ; 
                        $smsg += "`n$(($rec | ft -a $prpSOA | out-string).trim())" ; 
                        #throw $smsg ;
                        $RecFail = $true ; 
                   }
                   default {throw "Unrecognized record TYPE!" ; $RecFail = $true ; } 
                } ; 

                if($RecFail -eq $true){
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } 
                    else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                } else { 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                } ; 

            };  # loop-E

            if($outputObject){
                $smsg = "(output results to pipeline)" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #Levels:Error|Warn|Info|H1|H2|H3|Debug|Verbose|Prompt
                $results | write-output ; 
            } ; 
            write-host @whBnrS -obj "$((get-date).ToString('HH:mm:ss')):$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;

        } ;  # loop-E
    }  # PROC-E
    END{
        write-host @whBnr -obj "$((get-date).ToString('HH:mm:ss')):$($sBnr.replace('=v','=^').replace('v=','^='))" ;
    } ;
}

#*------^ Test-DnsDkimCnameToTxtKeyTDO.ps1 ^------


#*------v test-IpAddressCidrRange.ps1 v------
function test-IpAddressCidrRange{
            <#
            .SYNOPSIS
            test-IpAddressCidrRange.ps1 - evaluate an IP Address specification as either IPAddress|CidrRange|IPAddressRange
            .NOTES
            Version     : 1.0.0
            Author      : Todd Kadrie
            Website     : http://www.toddomation.com
            Twitter     : @tostka / http://twitter.com/tostka
            CreatedDate : 2020-
            FileName    : 
            License     : (none asserted)
            Copyright   : (none asserted)
            Github      : https://github.com/tostka/verb-Network
            Tags        : Powershell,Network,IPAddress
            AddedCredit : cyruslab (from public forum post, cited as 'https://powershell.org/forums/topic/detecting-if-ip-address-entered/', now gone)
            AddedWebsite: https://cyruslab.net/2018/04/26/powershellcheck-valid-ip-address-subnet-or-ip-address-range/
            AddedTwitter: 
            REVISIONS
            * 10:51 AM 8/13/2021 added to verb-network ; updated base code to work with ip6 CIDR notation ; fixed 
            bug in if/then comparisions: need to coerce subnet mask to integer, for 
            comparison (esp under ip6) ; converted to function updated format to OTB, added 
            CBH, minor param inline help etc. 
            * 4/26/2016 cyruslab posted ps code from earlier unattributed powershell.org forums post (non-function)
            .DESCRIPTION
            test-IpAddressCidrRange.ps1 - evaluate an IP Address specification as either IPAddress|CidrRange|IPAddressRange
            .PARAMETER Address
            IPAddress, CIDR notation, or IP range specification to be tested[-Address 192.168.0.1]
            .INPUTS
            Does not accept piped input
            .OUTPUTS
            System.SystemObject with Type (IPAddress|CIDRRange|IPAddressRange) and boolean Valid properties
            .EXAMPLE
            PS> $ret= test-IpAddressCidrRange -Address 192.168.1.1 ;
            if(($ret.type -eq 'IPAddress' -AND $ret.valid){'Valid IP'} ; 
            Test IP Address
            .EXAMPLE
            PS> $ret= test-IpAddressCidrRange -Address 91.198.224.29/32
            if(( $ret.type -eq 'CIDRRange' -AND $ret.valid){'Valid CIDR'} ; 
            Test CIDR notation block
            .EXAMPLE
            PS> $ret= test-IpAddressCidrRange -Address '192.168.0.1-192.168.0.200' ;
            if($ret.type -eq 'IPAddressRange' -AND $ret.valid){'Valid CIDR'} ; 
            Test IP Address range
            .LINK
            https://github.com/tostka/verb-Network
            .LINK
            https://cyruslab.net/2018/04/26/powershellcheck-valid-ip-address-subnet-or-ip-address-range/
            #>            
            [CmdletBinding()]
            PARAM(
                [Parameter(HelpMessage="IPAddress, CIDR notation, or IP range specification to be tested[-Address 192.168.0.1]")]
                $Address
            ) ;
            $isIPAddr = ($Address -as [IPaddress]) -as [Bool] ;
            $report=[ordered]@{
                Type = $null ;
                Valid = $false ;
            } ;
            write-verbose "specified Address:$($Address)" ;
            if($isIPAddr){
                write-verbose "Valid ip address" ;
                $report.type = 'IPAddress' ;
                $report.Valid = $true ; 
            } elseif($Address -like "*/*" -or $Address -like "*-*"){
                $cidr = $Address.split("/") ;
                if($cidr){ 
                    $report.type = 'CIDRRange'
                } ;
                # ip4 CIDR range: 0 to 32
                # ip6 CIDR range: 0 to 128 - need to update to accomodate cidr ip6
                if($Address -like "*:*" -AND [int]$cidr[1] -ge 0 -AND [int]$cidr[1] -le 128){
                    # CIDR ip6
                    write-verbose "valid ipv6 CIDR subnet syntax" ;
                    $report.Valid = $true ; 
                } elseif([int]$cidr[1] -ge 0 -and [int]$cidr[1] -le 32){
                    write-verbose "valid ipv4 CIDR subnet syntax" ;
                    $report.Valid = $true ; 
                }elseif($Address -like "*-*"){
                    $report.type = 'IPAddressRange' ; 
                    $ip = $Address.split("-") ; 
                    $ip1 = $ip[0] -as [IPaddress] -as [Bool] ; 
                    $ip2 = $ip[1] -as [IPaddress] -as [Bool] ; 
                    if($ip -and $ip){
                        write-verbose "valid ip address range" ;
                        $report.Valid = $true ;
                    } else{
                        write-verbose "invalid range" ;
                        $report.Valid = $false ;
                    } ;
                } else {
                    $report.type = 'INVALID' ;
                    $report.Valid = $false ;
                    write-warning "invalid subnet" ;
                } ; 
            }else{
                $report.type = 'INVALID' ;
                $report.Valid = $false ;
                write-warning "not valid address" ;
            } ;
            New-Object PSObject -Property $report | write-output ;   
        }

#*------^ test-IpAddressCidrRange.ps1 ^------


#*------v Test-IPAddressInRange.ps1 v------
function Test-IPAddressInRange {
            <#
            .SYNOPSIS
            Test-IPAddressInRange - Test an array of IP Addreses for presence in specified CIDR-notated subnet range. 
            .NOTES
            Version     : 0.0.5
            Author      : Nick James (omniomi)
            Website     : http://www.toddomation.com
            Twitter     : @tostka / http://twitter.com/tostka
            CreatedDate : 2022-11-03
            FileName    : Test-IPAddressInRange
            License     : (none asserted)
            Copyright   : (none asserted)
            Github      : https://github.com/tostka/verb-network
            Tags        : Powershell
            AddedCredit : Todd Kadrie
            AddedWebsite: http://www.toddomation.com
            AddedTwitter: @tostka / http://twitter.com/tostka
            REVISIONS
            * 11:57 AM 1/5/2023 TSK flipped $IPAddress type from [string] to [ipaddress]; Added CBH, and example; converted to Adv Func syntax; 
            added pipeline support on the IPAddress input ; simplfied compound stmts ; added to verb-Network.
            * Apr 17, 2018 Nick James (omniomi) posted github version from: https://github.com/omniomi/PSMailTools/blob/v0.2.0/src/Private/spf/IPInRange.ps1
            .DESCRIPTION
            .SYNOPSIS
            Test-IPAddressInRange - Test an array of IP Addreses for presence in specified CIDR-notated subnet range.
            .PARAMETER 

            .INPUTS
            None. Does not accepted piped input.(.NET types, can add description)
            .OUTPUTS
            System.Boolean
            .EXAMPLE
            PS> IPInRange 10.10.10.230 10.10.10.10/24 ; 
                True
            Feed it an IP and a CIDR address and it returns true or false.
            .EXAMPLE
            PS>  if((Test-IPAddressInRange -IPAddress 10.10.10.230,10.10.11.230 -Range 10.10.10.10/24 -verbose) -contains $false){
            PS>      write-warning 'FAIL!';
            PS>  } else { write-host "TRUE!"} ;
                WARNING: FAIL!
            Test an array of ips against the specified CIDR subnet, and warn if any fails (outside of the subnet).
            .EXAMPLE
            PS> @('10.10.10.230','10.10.11.230') | Test-IPAddressInRange -Range 10.10.10.10/24 -verbose ;
            Pipeline demo, fed with array of ip's.
            .LINK
            https://github.com/tostka/verb-network
            .LINK
            https://github.com/omniomi/PSMailTools/blob/v0.2.0/src/Private/spf/IPInRange.ps1
            #>
            # VALIDATORS: [ValidateNotNull()][ValidateNotNullOrEmpty()][ValidateLength(24,25)][ValidateLength(5)][ValidatePattern("some\sregex\sexpr")][ValidateSet("US","GB","AU")][ValidateScript({Test-Path $_ -PathType 'Container'})][ValidateScript({Test-Path $_})][ValidateRange(21,65)]#positiveInt:[ValidateRange(0,[int]::MaxValue)]#negativeInt:[ValidateRange([int]::MinValue,0)][ValidateCount(1,3)]
            [outputtype([System.Boolean])]
            [CmdletBinding()]
            PARAM(
                [parameter(Mandatory=$true, Position=0,ValueFromPipeline = $True,HelpMessage="Array of IP Addresses to be compared to specified Range[-IPAddress 192.168.1.1")]
                [validatescript({([System.Net.IPAddress]$_).AddressFamily -eq 'InterNetwork'})]
                [ipaddress[]]$IPAddress,
                [parameter(Mandatory,Position=1,HelpMessage="CIDR-notated subnet specification[-Range 10.10.10.10/24")]
                [validatescript({
                    $IP,$Bits  = $_ -split '/' 
                     (([System.Net.IPAddress]($IP)).AddressFamily -eq 'InterNetwork') 
                    if (-not($Bits)) {
                        throw 'Missing CIDR notiation.' 
                    } elseif (-not(0..32 -contains [int]$Bits)) {
                        throw 'Invalid CIDR notation. The valid bit range is 0 to 32.' ; 
                    } ; 
                })]
                [alias('CIDR')]
                [string]$Range
            ) ;
            BEGIN{
                #region CONSTANTS-AND-ENVIRO #*======v CONSTANTS-AND-ENVIRO v======
                # function self-name (equiv to script's: $MyInvocation.MyCommand.Path) ;
                ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
                #region BANNER ; #*------v BANNER v------
                $sBnr="#*======v $(${CmdletName}): v======" ;
                $smsg = $sBnr ;
                write-verbose "$($smsg)"  ;
                #endregion BANNER ; #*------^ END BANNER ^------
                $verbose = ($VerbosePreference -eq "Continue") ;
                $PSParameters = New-Object -TypeName PSObject -Property $PSBoundParameters ;
                write-verbose -message "`$PSBoundParameters:`n$(($PSBoundParameters|out-string).trim())" ;
                #endregion CONSTANTS-AND-ENVIRO ; #*------^ END CONSTANTS-AND-ENVIRO ^------       

                write-verbose "Split range into the address and the CIDR notation" ; 
                [String]$CIDRAddress,[int]$CIDRBits = $Range.Split('/') ; 

                if ($PSCmdlet.MyInvocation.ExpectingInput) {
                    write-verbose -message "Data received from pipeline input: '$($InputObject)'" ; 
                } else {
                    #write-verbose "Data received from parameter input: '$($InputObject)'" ; 
                    write-verbose -message "(non-pipeline - param - input)" ; 
                } ; 
            } ; 
            PROCESS{
                foreach($item in $IPAddress){
                    $sBnrS="`n#*------v PROCESSING : $($item.IPAddressToString) v------" ; 
                    write-verbose -message "$($sBnrS)" ;
            
                    write-verbose "Address from range and the search address are converted to Int32 and the full mask is calculated from the CIDR notation."
                    [int]$BaseAddress    = [System.BitConverter]::ToInt32((([System.Net.IPAddress]::Parse($CIDRAddress)).GetAddressBytes()), 0) ; 
                    [int]$Address        = [System.BitConverter]::ToInt32(([System.Net.IPAddress]::Parse($item).GetAddressBytes()), 0) ; 
                    [int]$Mask           = [System.Net.IPAddress]::HostToNetworkOrder(-1 -shl ( 32 - $CIDRBits)) ; 

                    write-verbose "Determine whether the address is in the range. (-band == bitwise-AND)"
                    if (($BaseAddress -band $Mask) -eq ($Address -band $Mask)) {
                        $true ; 
                    } else {
                        $false ; 
                    } ;  
                    write-verbose -message "$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;

                } ;  # loop-E
            }  # PROC-E
            END{
                write-verbose -message "$($sBnr.replace('=v','=^').replace('v=','^='))" ;
            } ;
        }

#*------^ Test-IPAddressInRange.ps1 ^------


#*------v Test-Port.ps1 v------
function Test-Port {
    <#
    .SYNOPSIS
    Test-Port() - test the specified ip/fqdn port combo
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2022-04-12
    FileName    : test-port.ps1
    License     : MIT License
    Copyright   : (c) 2022 Todd Kadrie
    Github      : https://github.com/tostka/verb-XXX
    Tags        : Powershell
    REVISIONS
    # 12:28 PM 4/12/2022 prior was .net dependant, not psCore compliant: make it defer to and use the NetTCPIP:Test-NetConnection -ComputerName -Port alt, or psv6+ test-connection -targetname -tcpport, only fallback to .net when on Win and no other option avail); moved port valid to param block, rem'd out eapref; added position to params; updated CBH
    # 10:42 AM 4/15/2015 fomt cleanup, added help
    # vers: 8:42 AM 7/24/2014 added proper fail=$false
    # vers: 10:25 AM 7/23/2014 disabled feedback, added a return
    .DESCRIPTION
    Test-Port() - test the specified ip/fqdn port combo
    Excplicitly does not have pipeline support, to make it broadest backward-compatibile, as this func name has been in use goine way back in my code.
    .PARAMETER  Server
    Server fqdn, name, ip to be connected to
    .PARAMETER  port
    Port number to be connected to
    .EXAMPLE
    PS> test-port -ComputerName hostname -Port 1234 -verbose
    Check hostname port 1234, with verbose output
    .LINK
    https://github.com/tostka/verb-network
    #>
    PARAM(
        [parameter(Position=0,Mandatory=$true)]
        [alias("s",'ComputerName','TargetName')]
        [string]$Server,
        [parameter(Position=1,Mandatory=$true)]
        [alias("p",'TcpPort')]
        [ValidatePattern("^(6553[0-5]|655[0-2]\d|65[0-4]\d\d|6[0-4]\d{3}|[1-5]\d{4}|[1-9]\d{0,3}|0)$")]
        [int32]$Port
    )
    # tree down an if than and only use .net/win-specific netsockets if nothing else avail
    if($host.version.major -ge 6 -AND (gcm test-connection)){
        write-verbose "(Psv6+:using PS native:test-connection -Targetname  $($server) -tcpport $($port)...)" ; 
        # has *ugly* output and down-state handling, so wrap & control the output
        TRY {$PortTest = test-connection -targetname $Server -tcpport $port -Count 1 -ErrorAction SilentlyContinue -ErrorVariable Err } CATCH { $PortTest = $Null } ;
        if($PortTest -ne $null ){
            write-verbose "Success" ; 
            return $true ; 
        } else {
            write-verbose "Failure" ; 
            return $False;
        } ; 
    } elseif (gcm Test-NetConnection){
        write-verbose "(Psv5:using NetTCPIP:Test-NetConnection -computername $($server) -port $($port)...)" ; 
        # (test-netconnection  -computername boojum -port 3389 -verbose).PingSucceeded
        if( (Test-NetConnection -computername $Server -port $port).TcpTestSucceeded ){
            write-verbose "Success" ; 
            return $true ; 
        } else {
            write-verbose "Failure" ; 
            return $False;
        } ; 
    } elseif([System.Environment]::OSVersion.Platform -eq 'Win32NT'){ 
        write-verbose "(Falling back to PsWin:Net.Sockets.TcpClient)" ; 
        $Socket = new-object Net.Sockets.TcpClient
        $Socket.Connect($Server, $Port)
        if ($Socket.Connected){
            $Socket.Close()
            write-verbose "Success" ; 
            return $True;
        } else {
            write-verbose "Failure" ; 
            return $False;
        } # if-block end
        $Socket = $null
    } else {
        throw "Unsupported OS/Missing depedancy module! (missing PSCore6+, NetTCPIP, .net.sockets.tcpClient)! Aborting!" ;
    } ; 
    #} # if-E port-range valid
}

#*------^ Test-Port.ps1 ^------


#*------v test-PrivateIP.ps1 v------
function test-PrivateIP {
<#
    .SYNOPSIS
    test-PrivateIP.ps1 - Use to determine if a given IP address is within the IPv4 private address space ranges.
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2021-08-16
    FileName    : test-PrivateIP.ps1
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,Network,IP,Subnet
    AddedCredit : Mark Wragg
    AddedWebsite: https://github.com/markwragg
    AddedTwitter: 
    REVISIONS
    * 1:29 PM 8/12/2021 tweaked CBH, minor param inline help etc.
    * 9/10/2019 Mark Wragg posted rev (corresponds to PSG v1.1.14)
    .DESCRIPTION
    Use to determine if a given IP address is within the IPv4 private address space ranges.
    Returns $true or $false for a given IP address string depending on whether or not is is within the private IP address ranges.
    .PARAMETER IP
    The IP address to test[-IP 192.168.0.1]
    .EXAMPLE
    Test-PrivateIP -IP 172.16.1.2
    Result
    ------
    True
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://github.com/markwragg/PowerShell-Subnet/blob/master/Subnet/Public/Test-PrivateIP.ps1
    #>
    ##Requires -Modules DnsClient
    [CmdletBinding()]
    PARAM (
        [parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="The IP address to test[-IP 192.168.0.1]")]
        [string]$IP
    )
    BEGIN {
        ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
        $Verbose = ($VerbosePreference -eq 'Continue') ; 
    } ;  # BEG-E
    PROCESS {
        if ($IP -Match '(^127\.)|(^192\.168\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)') {
            $true ; 
        } else {
            $false ; 
        } ; 
    } ;  # PROC-E
    END {}
}

#*------^ test-PrivateIP.ps1 ^------


#*------v Test-RDP.ps1 v------
function Test-RDP {
    <#
    .SYNOPSIS
    Test-RDP() - determine if powershell is running within an RDP session
    .NOTES
    Author: Todd Kadrie
    Website:	http://toddomation.com
    Twitter:	http://twitter.com/tostka
    REVISIONS   :
    # 9:48 AM 9/25/2020 fixed to explicitly check for an RDP & clientname evari: wasn't properly firing on work box, $env:sessionname is blank, not 'Console' 
    # 3:45 PM 4/17/2020 added cbh
    # 10:45 AM 7/23/2014
    .DESCRIPTION
    Test-RDP() - determine if powershell is running within an RDP session
    RDP sets 2 environment variables on remote connect:
    $env:sessionname: RDP-Tcp#[session#]
    $env:clientname: [connecting client computername]
    If both are set, you're in an RDP 
    Proviso: unless Explorer Folder Option "Launch folder windows in a separate process" is enabled, 
    applications launched from an additional Explorer window do not have these e-varis.
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    System.Boolean
    .EXAMPLE
    if(Test-RDP){write-host "Running in RDP"} ; 
    .LINK
    #>
    # win10 on workbox doesn't have $env:SESSIONNAME -eq 'Console', below is false positive
    #if ($env:SESSIONNAME -ne 'Console') { return $True; }; 
    # better test is test match rgx on RDP-Tcp# string & $env:clientname populated 
    if(($env:sessionname -match 'RDP-Tcp#\d*') -AND ($env:clientname)){ return $True} ;
}

#*------^ Test-RDP.ps1 ^------


#*------v Convert-Int64toIP.ps1 v------
function convert-Int64toIP {
    <#
    .SYNOPSIS
    Convert-Int64toIP.ps1 - Converts 64bit Integer representation back to IPv4 Address
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2021-08-16
    FileName    : Convert-Int64toIP.ps1
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,Network,IP,Subnet
    AddedCredit : Mark Wragg
    AddedWebsite: https://github.com/markwragg
    AddedTwitter: 
    REVISIONS
        * 1:29 PM 8/12/2021 added CBH, minor param inline help etc.
    * 4/14/2019 Mark Wragg posted rev (corresponds to PSG v1.1.14)
    .DESCRIPTION
    Convert-Int64toIP.ps1 - Converts 64bit Integer representation back to IPv4 Address
    .PARAMETER IP
    The IP address to convert[-IP 192.168.0.1]
    .OUTPUT
    System.String
    .EXAMPLE
    convert-Int64toIP -int 3.3.335521
    Result
    ------
    192.168.0.1
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://github.com/markwragg/PowerShell-Subnet/blob/master/Subnet/Private/Convert-Int64toIP.ps1
    #>
    ###Requires -Modules DnsClient
    [CmdletBinding()]
    PARAM (
        [parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="64-bit integer IP address  representation, to be converted back to IP[-int 3.3.335521]")]
        [int64]$int
    )
    BEGIN {
        ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
        $Verbose = ($VerbosePreference -eq 'Continue') ; 
    } ;  # BEG-E
    PROCESS {
        (([math]::truncate($int / 16777216)).tostring() + "." + ([math]::truncate(($int % 16777216) / 65536)).tostring() + "." + ([math]::truncate(($int % 65536) / 256)).tostring() + "." + ([math]::truncate($int % 256)).tostring() )
    } ;  # PROC-E
    END {} ;
}

#*------^ Convert-Int64toIP.ps1 ^------


#*------v convert-IPtoInt64.ps1 v------
function Convert-IPtoInt64 {
<#
    .SYNOPSIS
    Convert-IPtoInt64.ps1 - Converts IP Address into a 64bit Integer representation
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2021-08-16
    FileName    : Convert-IPtoInt64.ps1
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,Network,IP,Subnet
    AddedCredit : Mark Wragg
    AddedWebsite: https://github.com/markwragg
    AddedTwitter: 
    REVISIONS
    * 1:29 PM 8/12/2021 added CBH, minor param inline help etc.
    * 4/14/2019 Mark Wragg posted rev (corresponds to PSG v1.1.14)
    .DESCRIPTION
    Convert-IPtoInt64.ps1 - Converts IP Address into a 64bit Integer representation
    .PARAMETER IP
    The IP address to convert[-IP 192.168.0.1]
    .OUTPUT
    System.Int64
    .EXAMPLE
    Convert-IPtoInt64 -IP 192.168.0.1
    Result
    ------
    3.3.335521
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://github.com/markwragg/PowerShell-Subnet/blob/master/Subnet/Private/Convert-IPtoInt64.ps1
    #>
    ###Requires -Modules DnsClient
    [CmdletBinding()]
    PARAM (
        [parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="The IP address to convert[-IP 192.168.0.1]")]
        [string]$IP
    )
    BEGIN {
        ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
        $Verbose = ($VerbosePreference -eq 'Continue') ; 
    } ;  # BEG-E
    PROCESS {
        $octets = $ip.split(".") ;
        [int64]([int64]$octets[0] * 16777216 + [int64]$octets[1] * 65536 + [int64]$octets[2] * 256 + [int64]$octets[3]) ; 
    } ;  # PROC-E
    END {} ;
}

#*------^ convert-IPtoInt64.ps1 ^------


#*======^ END FUNCTIONS ^======

Export-ModuleMember -Function Add-IntToIPv4Address,Connect-PSR,Disconnect-PSR,get-CertificateChainOfTrust,Get-DnsDkimRecord,get-DNSServers,get-IPSettings,Get-NetIPConfigurationLegacy,get-NetworkClass,get-NetworkSubnet,Get-RestartInfo,get-tsUsers,get-WebTableTDO,get-whoami,Invoke-BypassPaywall,New-RandomFilename,Invoke-SecurityDialog,Reconnect-PSR,Resolve-DNSLegacy.ps1,Resolve-SPFRecord,SPFRecord,SPFRecord,SPFRecord,test-IpAddressCidrRange,save-WebDownload,save-WebDownloadCurl,save-WebDownloadDotNet,save-WebFaveIcon,Send-EmailNotif,summarize-PassStatus,summarize-PassStatusHtml,test-Connection-T,Test-DnsDkimCnameToTxtKeyTDO,test-IpAddressCidrRange,Test-IPAddressInRange,Test-Port,test-PrivateIP,Test-RDP -Alias *




# SIG # Begin signature block
# MIIELgYJKoZIhvcNAQcCoIIEHzCCBBsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUQKl2/TmxgdCJRpdjHmTB+UTW
# 2KSgggI4MIICNDCCAaGgAwIBAgIQWsnStFUuSIVNR8uhNSlE6TAJBgUrDgMCHQUA
# MCwxKjAoBgNVBAMTIVBvd2VyU2hlbGwgTG9jYWwgQ2VydGlmaWNhdGUgUm9vdDAe
# Fw0xNDEyMjkxNzA3MzNaFw0zOTEyMzEyMzU5NTlaMBUxEzARBgNVBAMTClRvZGRT
# ZWxmSUkwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALqRVt7uNweTkZZ+16QG
# a+NnFYNRPPa8Bnm071ohGe27jNWKPVUbDfd0OY2sqCBQCEFVb5pqcIECRRnlhN5H
# +EEJmm2x9AU0uS7IHxHeUo8fkW4vm49adkat5gAoOZOwbuNntBOAJy9LCyNs4F1I
# KKphP3TyDwe8XqsEVwB2m9FPAgMBAAGjdjB0MBMGA1UdJQQMMAoGCCsGAQUFBwMD
# MF0GA1UdAQRWMFSAEL95r+Rh65kgqZl+tgchMuKhLjAsMSowKAYDVQQDEyFQb3dl
# clNoZWxsIExvY2FsIENlcnRpZmljYXRlIFJvb3SCEGwiXbeZNci7Rxiz/r43gVsw
# CQYFKw4DAh0FAAOBgQB6ECSnXHUs7/bCr6Z556K6IDJNWsccjcV89fHA/zKMX0w0
# 6NefCtxas/QHUA9mS87HRHLzKjFqweA3BnQ5lr5mPDlho8U90Nvtpj58G9I5SPUg
# CspNr5jEHOL5EdJFBIv3zI2jQ8TPbFGC0Cz72+4oYzSxWpftNX41MmEsZkMaADGC
# AWAwggFcAgEBMEAwLDEqMCgGA1UEAxMhUG93ZXJTaGVsbCBMb2NhbCBDZXJ0aWZp
# Y2F0ZSBSb290AhBaydK0VS5IhU1Hy6E1KUTpMAkGBSsOAwIaBQCgeDAYBgorBgEE
# AYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwG
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBTjVgQe
# Wlfq3DBnD51iBpEwchY5tTANBgkqhkiG9w0BAQEFAASBgHeTLi6oEC1Zdx90PILs
# MM1grpiUBKZTgrk/V4FcuHRKl2XBLtyQWJF9rs15JPXKbQyXpMG0GS27S6vs6aPG
# wUljZWCqOvqtLOYjgT5guhu9VBZPkoY1QtyXTQq3BONqfwvTbym8EJanA/QpcMk3
# iuVqKdYF3elvgBh1w/3s7WLK
# SIG # End signature block
