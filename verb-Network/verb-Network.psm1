﻿# verb-network.psm1


<#
.SYNOPSIS
verb-Network - Generic network-related functions
.NOTES
Version     : 5.4.0.0
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
    * 1:30 PM 9/5/2024 added  update-SecurityProtocolTDO() SB to begin
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
    PARAM( 
        [Parameter(Position=0,Mandatory=$True,HelpMessage="Server to Remote to")][Alias('__ServerName', 'Computer')]
        [string]$Server,
        [Parameter(HelpMessage="OptionalCommand Prefix for cmdlets from this session[PSR]")][string]$CommandPrefix,
        [Parameter(HelpMessage = 'Credential object')][System.Management.Automation.PSCredential]$Credential = $credTORSID,
        [Parameter(HelpMessage='Silent flag [-silent]')][switch]$silent
    )  ; 
    $Verbose = ($VerbosePreference -eq 'Continue')
    $CurrentVersionTlsLabel = [Net.ServicePointManager]::SecurityProtocol ; # Tls, Tls11, Tls12 ('Tls' == TLS1.0)  ;
    write-verbose "PRE: `$CurrentVersionTlsLabel : $($CurrentVersionTlsLabel )" ;
    # psv6+ already covers, test via the SslProtocol parameter presense
    if ('SslProtocol' -notin (Get-Command Invoke-RestMethod).Parameters.Keys) {
        $currentMaxTlsValue = [Math]::Max([Net.ServicePointManager]::SecurityProtocol.value__,[Net.SecurityProtocolType]::Tls.value__) ;
        write-verbose "`$currentMaxTlsValue : $($currentMaxTlsValue )" ;
        $newerTlsTypeEnums = [enum]::GetValues('Net.SecurityProtocolType') | Where-Object { $_ -gt $currentMaxTlsValue }
        if($newerTlsTypeEnums){
            write-verbose "Appending upgraded/missing TLS `$enums:`n$(($newerTlsTypeEnums -join ','|out-string).trim())" ;
        } else {
            write-verbose "Current TLS `$enums are up to date with max rev available on this machine" ;
        };
        $newerTlsTypeEnums | ForEach-Object {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor $_
        } ;
    } ;
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


#*------v convert-IPAddressToReverseTDO.ps1 v------
if(-not (get-command convert-IPAddressToReverseTDO -ea 0)){
            function convert-IPAddressToReverseTDO {
                <#
                .SYNOPSIS
                Reverse IP Address. 
                .NOTES
                Version     : 0.0.1
                Author      : Todd Kadrie
                Website     : http://www.toddomation.com
                Twitter     : @tostka / http://twitter.com/tostka
                CreatedDate : 2025-01-02
                FileName    : convert-IPAddressToReverseTDO.ps1
                License     : (none asserted)
                Copyright   : (none asserted)
                Github      : https://github.com/tostka/verb-Network
                Tags        : Powershell,TCP,IPAddress
                AddedCredit : REFERENCE
                AddedWebsite: URL
                AddedTwitter: URL
                * 4:44 PM 1/2/2025 replace borked Copilot ipv4 demo (didn't work, as expected, clearly [-1..1] isn't reverse array, it's pull last & first element); 
                    coded in solid ipv6 support (IP reverse process is diff ipv4 & ipv6)
                    ren Reverse-IP -> convert-IPAddressToReverseTDO, alias Reverse-IP
                * 8:58 AM 1/2/2025 generated source via Copilot
                .DESCRIPTION
                Reverse IPAddress Address (ipv4 or ipv6). 

                Was originally cheating my way to the IPv6 reverse by resolving a PTR, and cutting the returned PTR record name at .ipv6', and taking the left half. 
                But [Shortest Script Challenge - Convert IPv6 to nibble format : r/PowerShell](https://www.reddit.com/r/PowerShell/comments/6wcpfv/shortest_script_challenge_convert_ipv6_to_nibble/)
                outlined a series of algos to get to the same thing, wo the PTR resolution step.

                .PARAMETER IPAddress
                The IPAddress address to be used in macro expansion.
                .INPUTS
                None. The script does not accept pipeline input.
                .OUTPUTS
                System.String The Reversed IP Address
                .EXAMPLE
                PS> $IPRev = convert-IPAddressToReverseTDO -ipaddress 192.168.1.1 ; 
                Reverse an IPv4 addres
                .EXAMPLE
                PS> $IPAddress = (resolve-dnsname -name ipv6.google.com | ?{$_.Type -eq 'AAAA'} |select -expand ipaddress) ; 
                PS> $IPRev = convert-IPAddressToReverseTDO  -ipaddress $ipaddress.IPAddressToString ; 
                    
                    Ipv6 address specified:2607:f8b0:4009:817::200e

                PS> $IPRev ; 
                    
                    E.0.0.2.0.0.0.0.0.0.0.0.0.0.0.0.7.1.8.0.9.0.0.4.0.B.8.F.7.0.6.2

                Reverse an IPv6 address
                .LINK
                https://github.com/tostka/verb-Network
                #>    
                [CmdletBinding()]
                [Alias('Reverse-IP')]
                PARAM(
                    [Parameter(Mandatory=$TRUE,HelpMessage="IPAddress (supports ipv4 & ipv6)[-IPAddress 192.168.1.1]")]
                    [system.net.ipaddress]$IPAddress
                ) ; 
                switch($IPAddress.AddressFamily){
                    'InterNetwork' { 
                        write-verbose "Ipv4 address specified:$($IPAddress)" ; 
                        #return ($IPAddress -split '\.')[-1..0] -join '.' ; 
                        # Copilot's algo above didn't work properly :'P [-1..1] doesn't reverse the array, it pulls [last..first]. 
                        $IpParts = $IPAddress -split '\.' ; 
                        [array]::Reverse($IpParts);
                        return ($IpParts -join ".")
                    }
                    'InterNetworkV6' { 
                        write-verbose "Ipv6 address specified:$($IPAddress.IPAddressToString)" ; 
                        <# doing it by pulling a PTR, and cutting the trailing .ip6.. from the returned record Name (select unique)
                        if($resolvedPTR = resolve-dnsname -name $IPAddress.IPAddressToString -type PTR -server 1.1.1.1){
                            return (($resolvedPTR | select -unique name).name  -replace '.ip6.arpa')
                        } else {
                            $smsg = "Unable to:resolve-dnsname -name $($IPAddress.IPAddressToString) -type PTR -server 1.1.1.1!" ; 
                            write-warning $smsg ; 
                            throw $smsg ;
                            return $false ;
                        }; 
                        #>
                        # or doing it using the [Shortest Script Challenge - Convert IPv6 to nibble format : r/PowerShell](https://www.reddit.com/r/PowerShell/comments/6wcpfv/shortest_script_challenge_convert_ipv6_to_nibble/)
                        # param($i)
                        #((([ipaddress]$i)|% GetA*|%{('{0:x2}'-f$_)[0,1]})[31..0]-join'.')+".ip6.arpa"
                        # we don't need the ip6.arpa trailing bit, just the algo to flip the elements.
                        #return ((([ipaddress]$IPAddress.IPAddressToString)|% GetA*|%{('{0:x2}'-f$_)[0,1]})[31..0]-join'.') ; 
                        # expanded a bit, less compressed logic:
                        $i=[bitconverter]::ToString( [IPAddress]::Parse($IPAddress.IPAddressToString).GetAddressBytes()).Replace('-','').ToCharArray() ; 
                        [array]::Reverse($i);
                        return ($i -join ".") # +'.ip6.arpa' 
                        # dropped trailing string from the above linked example: the ip6.arpa is the PTR record name, we just want the reversed ipv6 IP, to use in the %{ir} macro replacements
                    }
                } ; 
            } ; 
        }

#*------^ convert-IPAddressToReverseTDO.ps1 ^------


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


#*------v push-TLSLatest.ps1 v------
function push-TLSLatest{
        <#
        .SYNOPSIS
        push-TLSLatest - Elevates TLS on Powershell connections to highest available local version
        .NOTES
        Version     : 0.0.
        Author      : Todd Kadrie
        Website     : http://www.toddomation.com
        Twitter     : @tostka / http://twitter.com/tostka
        CreatedDate : 2025-
        FileName    : test-ModulesAvailable.ps1
        License     : MIT License
        Copyright   : (c) 2025 Todd Kadrie
        Github      : https://github.com/tostka/verb-Network
        Tags        : Powershell
        AddedCredit : REFERENCE
        AddedWebsite: URL
        AddedTwitter: URL
        REVISIONS
        * 9:05 AM 6/2/2025 expanded CBH, copied over current call from psparamt
        * 4:41 PM 5/29/2025 init (replace scriptblock in psparamt)
        .DESCRIPTION
        push-TLSLatest - Elevates TLS on Powershell connections to highest available local version
        .PARAMETER ModuleSpecifications
        Array of semicolon-delimited module test specifications in format 'modulename;moduleurl;testcmdlet'[-ModuleSpecifications 'verb-logging;localRepo;write-log'
        .INPUTS
        None. Does not accepted piped input.
        .OUTPUTS
        None. 
        .EXAMPLE
        PS> push-TLSLatest ;     
        .LINK
        https://github.com/tostka/verb-Network      
        #>
        [CmdletBinding()]
        PARAM() ; 
        $CurrentVersionTlsLabel = [Net.ServicePointManager]::SecurityProtocol ; # Tls, Tls11, Tls12 ('Tls' == TLS1.0)  ;
        write-verbose "PRE: `$CurrentVersionTlsLabel : $($CurrentVersionTlsLabel )" ;
        # psv6+ already covers, test via the SslProtocol parameter presense
        if ('SslProtocol' -notin (Get-Command Invoke-RestMethod).Parameters.Keys) {
            $currentMaxTlsValue = [Math]::Max([Net.ServicePointManager]::SecurityProtocol.value__,[Net.SecurityProtocolType]::Tls.value__) ;
            write-verbose "`$currentMaxTlsValue : $($currentMaxTlsValue )" ;
            $newerTlsTypeEnums = [enum]::GetValues('Net.SecurityProtocolType') | Where-Object { $_ -gt $currentMaxTlsValue }
            if($newerTlsTypeEnums){
                write-verbose "Appending upgraded/missing TLS `$enums:`n$(($newerTlsTypeEnums -join ','|out-string).trim())" ;
            } else {
                write-verbose "Current TLS `$enums are up to date with max rev available on this machine" ;
            };
            $newerTlsTypeEnums | ForEach-Object {
                [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor $_
            } ;
        } ;
    }

#*------^ push-TLSLatest.ps1 ^------


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


#*------v Resolve-DnsSenderIDRecords.ps1 v------
function Resolve-DnsSenderIDRecords {
    <#
    .SYNOPSIS
    Resolve-DnsSenderIDRecords.ps1 - Function to resolve a given domain's SPF & DMARC records, and attempt to detect existing DKIM records (searching common selector host names)
    .NOTES
    Version     : 0.0.
    Author      :  (T13nn3s )
    Website     : https://binsec.nl
    Twitter     : @T13nn3s / https://twitter.com/T13nn3s
    CreatedDate : 2022-04-06
    FileName    : Resolve-DnsSenderIDRecords.ps1
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,DNS,Email,SPF
    AddedCredit : Todd Kadrie
    AddedWebsite: toddomation.com
    AddedTwitter: @tostka/https://twitter.com/tostka
    REVISIONS
    * 12:44 PM 6/28/2024 rejiggered dkim series post testing (wasn't really reporting on the hits, and fibbed were no hits). Worked fine for checking toro.com against a ticket.
    * 9:09 AM 6/27/2024 WIP, got the WHPASSFail block updated with winterm test
    * 5:34 PM 6/19/2024 spliced over code to do SPF egress testing, and ensure all spf clauses match into the core ip4, ip6 etc of a specified 
    * 9:57 AM 5/2/2024 updated to accomodate Sec's decision to start parking dmarcs on domains as cnames pointed at a common dmarc txt (recogs cname, resolves to txt, and returns both in output)
    * 9:24 AM 3/20/2024 rework output - dumping mix of record types into the pipeline - with mult dkim selectors is a confusing mismatch return: flip to a constructed object with SPF, DKIM & DMARC as sub-objects that can be examined in isolation.
    * 3:01 PM 3/19/2024 adapt to full range of SenderID resolution from get-DNSDkimRecord.ps1
    * 11/02/2022 T13nn3s posted rev v1.5.2 (DKIM expansion example)
    .DESCRIPTION
    Resolve-DnsSenderIDRecords.ps1 - Function to resolve a given domain's SPF & DMARC records, and attempt to detect existing DKIM records (searching common selector host names)

    Reasonable listing of common selectors here
    [Email Provider Commonly Used DKIM Selectors : Sendmarc - help.sendmarc.com/](https://help.sendmarc.com/support/solutions/articles/44001891845-email-provider-commonly-used-dkim-selectors)

    .PARAMETER Name
    Specifies the domain for resolving the DKIM-record.[-Name Domain.tld]
    .PARAMETER DkimSelector
    Specify a custom DKIM selector.[-DkimSelector myselector
    .PARAMETER Server
    DNS Server to use.[-Server 8.8.8.8]
    .PARAMETER SpfModelDomain
    DomainName from which to obtain model SPF string for comparison[-SpfModelDomain somdeomain.tld]
    .PARAMETER TestSPFEgress
    Switch to perform element by element SPF compairsons against specified SpfModelDomain's SPF record ip4|ip6 and all designator[-SpfModelDomain somdeomain.tld]
    .INPUTS
    Accepts piped input.
    .OUTPUTS
    System.object
    .EXAMPLE
    PS> $results = Resolve-DnsSenderIDRecords -name SOMEDOMAIN.com ;
    PS> write-verbose 'Display returned object properties'
    PS> $results | get-member ; 

            TypeName: System.Management.Automation.PSCustomObject

        Name        MemberType   Definition                                                                                                                             
        ----        ----------   ----------                                                                                                                             
        Equals      Method       bool Equals(System.Object obj)                                                                                                         
        GetHashCode Method       int GetHashCode()                                                                                                                      
        GetType     Method       type GetType()                                                                                                                         
        ToString    Method       string ToString()                                                                                                                      
        DKIM        NoteProperty System.Collections.Generic.List`1[[System.Object, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]] DKIM=  
        DMARC       NoteProperty System.Collections.Generic.List`1[[System.Object, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]] DMARC= 
        SPF         NoteProperty System.Collections.Generic.List`1[[System.Object, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]] SPF=   

    PS> write-verbose 'Includes SPF, DKIM, and DMARC information for specified domain' ; 
    PS> write-verbose "examine properties of SPF returned" ; 

        $return.spf

        Name                SPFRecord                                  ReturnedType
        ----                ---------                                  ------------
        mtidistributing.com Microsoft.DnsClient.Commands.DnsRecord_TXT          TXT
        $return.spf.spfrecord

    PS> write-verbose "Examine SPF record returned" ; 
    PS> $return.spf.spfrecord ; 

        Name                                     Type   TTL   Section    Strings                                  
        ----                                     ----   ---   -------    -------                                  
        mtidistributing.com                      TXT    3600  Answer     {v=spf1 ip4:64.16.11.232/32              
                                                                         ip4:64.16.11.233/32                      
                                                                         include:spf.termsync.com                 
                                                                         include:spf.protection.outlook.com       
                                                                         include:sendgrid.net -all}           
    PS> write-verbose "Examine DKIM summaries returned" ; 
    PS> $return.dkim

        Name         : mtidistributing.com
        DkimRecord   : Microsoft.DnsClient.Commands.DnsRecord_PTR
        DkimSelector : selector1
        ReturnedType : CNAME
        DKIMAdvisory : Located CNAME pointer

        Name         : mtidistributing.com
        DkimRecord   : v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCstQzRq+OSOJM8isy+RYnrVMmZrfXLujLs3e1z5eILA0Ya8MQFYGOQgJbj06nyNtC3Qb2vHWcvX6oU/hBJ5fLeaH3lIcgbG91p3cE/4gxh9rncprv/ICkfj0SqIalwoie2uEcWfPmkCMaAwNKIB77SGDEPnetgqt
                       SVC5XMFFTtJwIDAQAB;
        DkimSelector : selector1
        ReturnedType : TXT
        DKIMAdvisory : DKIM-record found.

        Name         : mtidistributing.com
        DkimRecord   : Microsoft.DnsClient.Commands.DnsRecord_PTR
        DkimSelector : selector2
        ReturnedType : CNAME
        DKIMAdvisory : Located CNAME pointer

    PS> write-verbose "Examine DKIM records returned" ; 
    PS> $return.dkim | %{write-host "`n`n$(($_.dkimrecord|out-string).trim())" ; }

        Name                           Type   TTL   Section    NameHost                                                                                                                                                                        
        ----                           ----   ---   -------    --------                                                                                                                                                                        
        selector1._domainkey.mtidistri CNAME  3600  Answer     selector1-mtidistributing-com._domainkey.mtidistributing.onmicrosoft.com                                                                                                        
        buting.com


        v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCstQzRq+OSOJM8isy+RYnrVMmZrfXLujLs3e1z5eILA0Ya8MQFYGOQgJbj06nyNtC3Qb2vHWcvX6oU/hBJ5fLeaH3lIcgbG91p3cE/4gxh9rncprv/ICkfj0SqIalwoie2uEcWfPmkCMaAwNKIB77SGDEPnetgqtSVC5XMFFTtJwIDAQ
        AB;


        Name                           Type   TTL   Section    NameHost                                                                                                                                                                        
        ----                           ----   ---   -------    --------                                                                                                                                                                        
        selector2._domainkey.mtidistri CNAME  3600  Answer     selector2-mtidistributing-com._domainkey.mtidistributing.onmicrosoft.com                                                                                                        
        buting.com

    PS> write-verbose "In this case two selector CNAMES were discovered, and a single functional DKIM TXT key record (not unusual: MS for example only makes one selector of the pair functional at a time, for key rotation process)"
    PS> write-verbose "Examine DMARC summaries returned" ; 
    PS> $return.dmarc


        Name               : mtidistributing.com
        DmarcRecord        : Microsoft.DnsClient.Commands.DnsRecord_TXT
        PolicyTag          : p=quarantine
        SubDomainPolicyTag : 
        PolicyInheritance  : SUBDOMAINS:Policy p=xxx with no sp=xxx subdomain pol: Subdomains inherit the p=xxx Policy
        ReturnedType       : TXT

    PS> write-verbose "Examine DMARC records returned" ; 
    PS> $return.dmarc.dmarcrecord

        Name                                     Type   TTL   Section    Strings                                  
        ----                                     ----   ---   -------    -------                                  
        _dmarc.mtidistributing.com               TXT    3600  Answer     {v=DMARC1; p=quarantine; pct=100}       

    Resolve SPF, DKIM, DMARC for on targeted domain, assign results to variable, then expand the returned object subproperties for each type of record.

    .EXAMPLE
    PS>  $result = Resolve-DnsSenderIDRecords -name DOMAIN.com -verbose -Selector hs1-20997172._domainkey ; 
    PS>  if($result.DKIM.DkimRecord){
    PS>      $smsg = "DKIM TXT/Key record returned on query:`n"  ; 
    PS>      $smsg += "`n$(($return.dkim | ?{$_.Returnedtype -eq 'TXT'} | select -expand DkimRecord) | format-list |out-string).trim())" ;
    PS>      write-host $smsg ; 
    PS>      if($pkey = ($return.dkim | ?{$_.ReturnedType -eq 'TXT'} | select -expand DkimRecord).split(';') | ?{$_ -match 'p=[a-zA-z0-9]+'}){
    PS>          $smsg = "`nMatched Public Key tag:`n$(($pkey | format-list |out-string).trim())" ;
    PS>          write-host $smsg ; 
    PS>      } else { 
    PS>          $smsg += "`nNO PUBLIC KEY MATCHED IN RETURNED RECORD!`n$(($pkey | format-list |out-string).trim())" ;
    PS>          write-warning $smsg ;
    PS>      } ; 
    PS>  } else { 
    PS>      $smsg = "`nNO DKIM RECORD RETURNED ON QUERY:`N"  ; 
    PS>      $smsg += "`n$(($result.DkimRecord | format-list |out-string).trim())" ;
    PS>      write-warning $smsg ; 
    PS>  } ; 

        DKIM TXT/Key record returned on query:

        v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCstQzRq+OSOJM8isy+xxxxxxxxxxxxxjLs3e1z5eILA0Ya8MQFYGOQgJbj06nyNtC3Qb2vHWcvX6oU/hBJ5fLeaH3lIcgbG91p3cE/4gxh9rncprv/ICkfj0SqIalwoie2uEcWfPmkCMaAwNKIB77SGDEPnetgqtSVC5XMFFTtJwIDAQ
        AB;
        .trim())

        Matched Public Key tag:
        p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCstQzRq+OSOJM8isy+RYnrVMmZrfXLuxxxxxxxxxxxxxxa8MQFYGOQgJbj06nyNtC3Qb2vHWcvX6oU/hBJ5fLeaH3lIcgbG91p3cE/4gxh9rncprv/ICkfj0SqIalwoie2uEcWfPmkCMaAwNKIB77SGDEPnetgqtSVC5XMFFTtJwIDAQAB

    Example processing the returned TXT DKIM record and outputing the public key tag.
    .EXAMPLE
    PS> $results = Resolve-DnsSenderIDRecords -name somedomain.tld -TestSPFEgress -verbose ;
    PS> foreach($result in $results){
    PS>     $sBnrS="`n#*------v DOMAIN: $($result.mx.name) v------" ; 
    PS>     $whBnrS =@{BackgroundColor = 'Blue' ; ForegroundColor = 'Cyan' } ;
    PS>     write-host @whBnrS -obj "$((get-date).ToString('HH:mm:ss')):$($sBnrS)" ;
    PS>     $hsReport = @"
  
    ==DomainName: 
$(($result.mx.name|out-string).trim()) 
    
    ==MX Record: 
$(($result.mx.MXRecord | ft -AutoSize|out-string).trim())
    
    ==SPF Record: 
$(($result.spf.SPFRecord | ft -AutoSize|out-string).trim())
    
    ==DKIM Record: 
$(
      
      $smsg = "`n`n" ; 
      foreach($rec in $result.dkim){
      
          $smsg += "`n`n$(($rec.dkimrecord | ft -AutoSize|out-string).trim())" ; 
          $smsg += "`n`n$(($rec.DKIMAdvisory |out-string).trim())" ; 
          
      } ; 
      $smsg |out-string
) 
    
    ==DMARC Record: 
$(
    ($result.dmarc.dmarcrecord | ft -AutoSize|out-string).trim()
 )   
        --PolicyTag:
$(   ($result.dmarc.policytag|out-string).trim()
)
      
        --SubDomainPolicyTag:
$(
  ($result.dmarc.SubDomainPolicyTag|out-string).trim()
)
     
        --PolicyInheritance:
$(   
  ($result.dmarc.PolicyInheritance|out-string).trim()
) 
     
"@ ; 
    PS>     write-host $hsReport ; 
    PS>     write-host @whBnrS -obj "$((get-date).ToString('HH:mm:ss')):$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;
    PS> } ; 
    Demos a pass with trailing looped reporting
    .LINK
    https://github.com/T13nn3s/Invoke-SpfDkimDmarc/blob/main/public/Get-DMARCRecord.ps1
    https://www.powershellgallery.com/packages/DomainHealthChecker/1.5.2/Content/public%5CResolve-DnsSenderIDRecords.ps1
    https://binsec.nl/powershell-script-for-spf-dmarc-and-dkim-validation/
    https://github.com/T13nn3s
    .LINK
    https://github.COM/tostka/verb-Network/
    #>
    [CmdletBinding()]
    # Set-Alias gdkim -Value Resolve-DnsSenderIDRecords   # move trailing alias here
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
            [string]$Server='1.1.1.1',
        [Parameter(Mandatory=$false,HelpMessage="DomainName from which to obtain model SPF string for comparison[-SpfModelDomain somdeomain.tld]")]
            [string]$SpfModelDomain = 'myturf.com',
        [Parameter(HelpMessage="Switch to perform element by element SPF compairsons against specified SpfModelDomain's SPF record ip4|ip6 and all designator[-SpfModelDomain somdeomain.tld]")]
            [switch]$TestSPFEgress
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
        
        $prpSPFDMARC = 'Name','Type';
        $prpDKIM = 'Type','Name','NameHost';
        
        #$whReportSub = @{BackgroundColor = 'Gray' ; ForegroundColor = 'DarkMagenta' } ;
        $whElement = @{BackgroundColor = 'Yellow' ; ForegroundColor = 'Black' } ;
        #$whQualifier = @{BackgroundColor = 'Blue' ; ForegroundColor = 'White' } ;

        $prpCNAME = 'Type','Name','NameHost' ; 
        $prpTXT = 'Type','Name','Strings' ; 
        $prpSOA = 'Type','Name','PrimaryServer' ; 

        # Custom list of DKIM-selectors
        # https://help.sendmarc.com/email-provider-commonly-used-dkim-selectors
        # https://www.reddit.com/r/DMARC/comments/1bffol7/list_of_most_common_dkim_selectors/
        # https://github.com/ryancdotorg/dkimscan/blob/master/dkimscan.pl#L313-L451
        $DKSelArray = 'selector1','selector2','s1','s2','k1','k2','sig1','smtp','default','mail','a1','a2','key1','key2',
            'kl','kl2','K1','K2','Default','smtpapi','dkim','domk','dk','smtpout','authsmtp','dkrnt','dkimrnt','private',
            'selector','publickey','proddkim','mail-in','key','ed-dkim','smtpauth','smtp','sl','primary','mdaemon',
            'mailrelay','mail-dkim','mailo','global','dksel','dkimmail','allselector','email' ;
        <#$DKSelArray = @(
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
        #>

        #region WHPASSFAIL ; #*------v WHPASSFAIL v------
        $whPASS = @{
        Object = "$([Char]8730) PASS" ;
        ForegroundColor = 'Green' ;
        NoNewLine = $true ;
        } ;
        $whFAIL = @{
            # light diagonal cross: ╳ U+2573 DOESN'T RENDER IN PS, use it if WinTerm
            'Object'= if ($env:WT_SESSION) { "$([Char]8730) FAIL"} else {' X FAIL'};
            ForegroundColor = 'RED' ;
            NoNewLine = $true ;
        } ;
        <#
        # inline pass/fail color-coded w char
        $smsg = "Testing:THING" ; 
        $Passed = $true ; 
        Write-Host "$($smsg)... " -NoNewline ; 
        if($Passed){Write-Host @whPASS} else {write-host @whFAIL} ; 
        Write-Host " (Done)" ;
        # out: Test:Thing... √ PASS (Done) | Test:Thing...  X FAIL (Done)
        #>
        #endregion WHPASSFAIL ; #*------^ END WHPASSFAIL ^------

        if ($PSCmdlet.MyInvocation.ExpectingInput) {
            write-verbose "Data received from pipeline input: '$($InputObject)'" ; 
        } else {
            #write-verbose "Data received from parameter input: '$($InputObject)'" ; 
            write-verbose "(non-pipeline - param - input)" ; 
        } ; 

        if($TestSPFEgress){
            write-verbose "resolve `$modelspf from `$SpfModelDomain ($($SpfModelDomain))" ; 
            TRY{
                $modelspf  =  resolve-dnsname -server $Server -type txt -name $SpfModelDomain ;
            }CATCH{} ;
            if($modelspf = $modelspf | ? Strings -Match "spf1"){
                write-verbose "split model spf into elements, on spaces" ; 
                $modelSPFElements = $modelspf.strings -split ' ' ; 
            }else{
                write-warning "-TestSPFEgress specified: Unable to resolve functional SPF record for specified -SpfModelDomain $($SpfModelDomain)`n(ABORT)" ; 
                break ; 
            } ; 
        } ; 

        $SPFObject = New-Object System.Collections.Generic.List[System.Object] ; 
        $DKimObject = New-Object System.Collections.Generic.List[System.Object] ; 
        $DMARCObject = New-Object System.Collections.Generic.List[System.Object] ; 
        $MXObject = New-Object System.Collections.Generic.List[System.Object] ; 
        
        $objReturn = [ordered]@{
            SPF = $null ; 
            DKIM = $null ; 
            DMARC = $null ; 
            MX = $null ; 
        } ; 

        if(-not $DkimSelector){
            $DkimSelector = $DKSelArray ; 
            $noSelectorSpecified = $true ; 
            #$smsg = "Running specified `Name:$($Name) through common selector names:" ; 
            $smsg = "Running with common selector names:" ; 
            $smsg += "`n($($DKSelArray -join '|'))..." ; 
            $smsg += "`n$(($DkimSelector |  measure | select -expand count |out-string).trim()) selector variants being checked" ; 
            #write-host -Object $smsg @whElement ; 
        } else {
            $noSelectorSpecified = $false ; 
            #$smsg = "Running specified `Name:$($Name) through specified -DkimSelector selector names:" ; 
            $smsg = "Running specified -DkimSelector selector names:" ; 
            $smsg += "`n($($DkimSelector -join '|'))..." ; 
            $smsg += "`n$(($DkimSelector |  measure | select -expand count |out-string).trim()) selector variants being checked" ; 
            #write-host -Object $smsg @whElement ;
        }; 
        write-host -Object $smsg @whElement ; 

    } ; 

    PROCESS { 
        $Error.Clear() ; 

        foreach($DomainName in $Name) {

            $steps = 0 ; 

            $sBnr="#*======v Name: $($DomainName) v======" ; 
            $whBnr = @{BackgroundColor = 'Magenta' ; ForegroundColor = 'Black' } ;
            write-host @whBnr -obj "$((get-date).ToString('HH:mm:ss')):$($sBnr)" ;

            $steps++ ; 

            $pltRvDN=[ordered]@{
                Type = $null ;
                Name = $DomainName  ;
                server = $server
                erroraction = 'SilentlyContinue' ;
            } ;
            
            $pltRvDN.Type= 'MX' ;
            $smsg = "`n$($steps). Resolve-DNSName MX type w`n$(($pltRvDN|out-string).trim())" ;
            write-host -foregroundcolor yellow $smsg  ;

            TRY{
                $MX  = Resolve-DNSName @pltRvDN ;
            }CATCH{} ;
            $MXReturnValues = New-Object psobject ;
            $MXReturnValues | Add-Member NoteProperty "Name" $DomainName ;

            #-=-=-=-=-=-=-=-=
            $prpMX = 'Name','Typ','TTL','Section','NameExchange','Preference' ; 
            if($MX){
                $rType = $MX.Type ;
                write-host @whPASS ; 
                $smsg = "`n=>Matched to MX:`n$(($MX|ft -a $prpMX | out-string).trim())" ;
                #$smsg += "`nStrings:`n$(($MX|select -expand Strings | out-string).trim())`n"
                write-host -foregroundcolor green $smsg ;
                $MXReturnValues | Add-Member NoteProperty "MXRecord" $MX ;
            } else {
                write-host @whFAIL ; 
                $smsg = "`n=>NO MX RECORD FOUND FOR DOMAIN:$($DomainName )`n" ;
                write-warning $smsg ;
                write-verbose "asserting MXRecord:`$null" ;
                $MXReturnValues | Add-Member NoteProperty "MXRecord" $null ;
                <#if($noSelectorSpecified){
                    $SpfAdvisory = $SpfAdvisory.replace('domain.',"domain, against a common Selectors list:`n($($DKSelArray -join '|')).") ;
                };
                #>
                $rType = $MX.Type ;
            } ;
            $MXReturnValues | Add-Member NoteProperty "ReturnedType" $rType ;
            #$MXReturnValues | Add-Member NoteProperty "DKIMAdvisory" $MXAdvisory ;
            $MXObject.Add($MXReturnValues) ;
            #$MXReturnValues | write-output ;

            $steps++ ;

            $pltRvDN.Type= 'TXT' ;
            $smsg = "`n$($steps). Resolve-DNSName $($pltRvDN.Type) type w`n$(($pltRvDN|out-string).trim())" ;
            write-host -foregroundcolor yellow $smsg  ;

            TRY{
                $SPF  = Resolve-DNSName @pltRvDN ;
            }CATCH{} ;
            $SpfReturnValues = New-Object psobject ;
            $SpfReturnValues | Add-Member NoteProperty "Name" $DomainName ;
             

            if($SPF = $SPF | ? Strings -Match "spf1"){
                $rType = $SPF.Type ;
                $smsg = "`n=>Matched to SPF:`n$(($SPF|ft -a $prpSPFDMARC | out-string).trim())" ;
                $smsg += "`nStrings:`n$(($SPF|select -expand Strings | out-string).trim())`n"
                write-host -foregroundcolor green $smsg ; 
                $SpfReturnValues | Add-Member NoteProperty "SPFRecord" $spf ;
                
                if($TestSPFEgress){
                    #$SpfModelDomain = 'myturf.com' ; 
                    #$DomainName = 'bossplow.com' ; 
                    write-host "==Separately validating key elements in $($SpfModelDomain) model spf are present (avoids ordering issues in full string tests):" ; 
                
                    $thisSPFElements = $spf.strings -split ' ' ; 
                    $FailCount = 0 ; 
                    $cacheFails = @() ; 
                    foreach($item in $modelSPFElements){
                        $smsg = "Test:$($item)..." ; 
                        write-host -foregroundcolor yellow $smsg  -NoNewline ; 
                        if($thisSPFElements | ?{$_ -match ([regex]::escape($item))} ){
                            #write-host -foregroundcolor green "SPF $($item) present" ; 
                            #Write-Host "$($smsg)... " -NoNewline ; 
                            #Write-Host " (Done)" ;
                            #if($Passed){Write-Host @whPASS} else {write-host @whFAIL} ; 
                            Write-Host @whPASS ; 
                        }else{
                            #write-warning "$item missing"
                            Write-Host @whFAIL ; 
                            $FailCount++ ; 
                            $cacheFails += @($item) ; 
                        }  ; 
                        write-host "" ; # assert a line wrap to finish the -nonewlines above
                    } ; 
                    write-verbose "Item tests completed" ;     
                } ; 
            } else {
                $smsg = "`n=>NO SPF RECORD FOUND FOR DOMAIN:$($DomainName )`n" ;
                write-warning $smsg ;

                write-verbose "asserting SPFRecord:`$null" ;
                $SpfReturnValues | Add-Member NoteProperty "SPFRecord" $null ;
                <#if($noSelectorSpecified){
                    $SpfAdvisory = $SpfAdvisory.replace('domain.',"domain, against a common Selectors list:`n($($DKSelArray -join '|')).") ; 
                };
                #> 
                $rType = $SPF.Type ;

            } ;
            $SpfReturnValues | Add-Member NoteProperty "ReturnedType" $rType ;
            #$SpfReturnValues | Add-Member NoteProperty "DKIMAdvisory" $SpfAdvisory ;
            $SpfObject.Add($SpfReturnValues) ;
            if($FailCount -gt 0){
                $SpfObject.Add($FailCount) ; 
            }  
            if($cacheFails.count -gt 0){
                $SpfObject.Add($cacheFails) ; 
            }  
            #$SpfReturnValues | write-output ;
            
            $steps++ ;
            write-host -fore yellow "`n$($steps). Attempt to resolve DKIMs (by checking common DKIM Selector host names)..." ;
            $pltRvDN.Type= 'CNAME' ;
            $foundSelector = $false ; 

            foreach ($DSel in $DkimSelector) {
                $pltRvDN.Name = "$($DSel)._domainkey.$($DomainName )" ;
                $smsg = "Resolve-DNSName DKIM $($pltRvDN.Type) type w`n$(($pltRvDN|out-string).trim())" ;
                write-host -foregroundcolor yellow $smsg ; 
                $DKIM  = $null ;
                $smsg = "Testing:DKIM" ; 
                TRY{
                    $DKIM  = Resolve-DNSName @pltRvDN ;
                }CATCH{write-host -nonewline '.'} ;
                if($DKIM){
                    Write-Host @whPASS ; 
                    switch($dkim.type){
                        'CNAME' {
                            write-host " : $($DKIM.type): $($DKIM.Name) => $($DKIM.NameHost)" 
                        }
                        'TXT' {
                            write-host " : $($DKIM.type): $($DKIM.Name) => $($DKIM.Strings)" 
                        }
                        'SOA'{
                            write-warning " : (invalid lookup)" ; 
                        }
                        default{
                            write-warning " : (invalid return)" ; 
                        }
                    }
                } else {
                    write-host @whFAIL ; Write-Host " " ;
                    # above doesn't accomodate custom SAAS vendor DKIMs and CNAMe pointers, so retry on selector.name
                    $smsg = "Fail on prior TXT qry" ; 
                    $smsg += "`nRetrying TXT qry:-Name $($DSel).$($DomainName)"
                    $smsg += "`nResolve-DnsName -Type TXT -Name $($DSel).$($DomainName)"  ;
                    write-verbose $smsg ; 
                    $DKIM = Resolve-DnsName -Type TXT -Name "$($DSel).$($DomainName)" @SplatParameters ; 
                } ;  
                write-host "`n" ; 
                
                if(($DKIM |  measure).count -gt 1){
                    write-host -foregroundcolor yellow "Multiple Records returned on qry: Likely resolution chain CNAME->(CNAME->)TXT`nuse the TXT record in the chain" ;   

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
                                    write-host @whPASS ; 
                                    $smsg += "`n`n--->TXT: $($rec.Name).strings *IS FULLY VALIDATED* to contain a DKIM key.`n`n" ; 
                                }elseif($rec.Strings -match 'v=DKIM1;\s.*;\sp='){
                                    # per above, this matches only the bare minimum!
                                    write-host @whPASS ; 
                                    $smsg += "`n`n--->TXT: $($rec.Name).strings *IS VALIDATED* to start with v=DKIM1 and contains a key (lacks k=rsa; tag, partial standard compliant).`n`n" ; 
                                }elseif($rec.Strings -match 'p=\w+'){
                                    write-host @whPASS ; 
                                    # per above, this matches only the bare minimum!
                                    $smsg += "`n`n--->TXT: $($rec.Name).strings *IS VALIDATED* to contain a DKIM key only (min standard compliant).`n`n" ; 
                                }else {
                                    write-host @whFAIL ; 
                                    $smsg += "`n`n--->TXT: $($rec.Name).strings *DOES NOT VALIDATE* to contain a DKIM key!" ;
                                    $smsg += "`n(strings should start with 'v=DKIM1', or at minimum include a p=xxx public key)`n`n" ; 
                                    $RecFail = $true ; 
                                } ; 
                            } 
                            'SOA' {
                                write-host @whFAIL ; 
                                $smsg += "`nSOA/Lookup-FAIL record detected!" ; 
                                $smsg += "`n$(($rec | ft -a $prpSOA | out-string).trim())" ; 
                                #throw $smsg ;
                                $RecFail = $true ; 
                            }
                            default {throw "Unrecognized record TYPE!" ; $RecFail = $true ; } 
                        } ; 

                        if($RecFail -eq $true){
                            write-host @whFAIL ; 
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } 
                            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                        } else { 
                            write-host @whPASS ; 
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
                            write-host @whFAIL ; 
                            $DkimAdvisory = "No DKIM-record found for selector $($DSel)._domainkey." ;
                        } elseif ($DKIM -match "v=DKIM1" -or $DKIM -match "k=") {
                            write-host @whPASS ; 
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
                                    write-host @whPASS ; 
                                    $foundSelector = $true ; ; 
                                } ; 
                        } else {;
                            write-host @whFAIL ; 
                            $DkimAdvisory = "We couldn't find a DKIM record associated with your domain." ;
                            $DkimAdvisory += "`n$($rType) record returned, unrecognized:" ; 
                            $DkimAdvisory += "`n$(($DKIM | format-list |out-string).trim())" ;
                        } ; 
                    } ;

                    $DkimReturnValues = New-Object psobject ;
                    $DkimReturnValues | Add-Member NoteProperty "Name" $DomainName ;
                    $DkimReturnValues | Add-Member NoteProperty "DkimRecord" $DKIM ;
                    $DkimReturnValues | Add-Member NoteProperty "DkimSelector" $DSel ;
                    $DkimReturnValues | Add-Member NoteProperty "ReturnedType" $DKIM.Type ;
                    $DkimReturnValues | Add-Member NoteProperty "DKIMAdvisory" "Located CNAME pointer" ;
                    $DkimObject.Add($DkimReturnValues) ;

                } elseif ($DKIM.Type -eq "CNAME") {
                    # record cnames ahead of txt resolution

                    $DkimReturnValues = New-Object psobject ;
                    $DkimReturnValues | Add-Member NoteProperty "Name" $DomainName ;
                    $DkimReturnValues | Add-Member NoteProperty "DkimRecord" $DKIM ;
                    $DkimReturnValues | Add-Member NoteProperty "DkimSelector" $DSel ;
                    $DkimReturnValues | Add-Member NoteProperty "ReturnedType" $DKIM.Type ;
                    $DkimReturnValues | Add-Member NoteProperty "DKIMAdvisory" "Located CNAME pointer" ;
                    $DkimObject.Add($DkimReturnValues) ;
                    #$DkimReturnValues | write-output ;
                    <#$objReturn = [ordered]@{
                        SPF = $null ; 
                        DKIM = $null ; 
                        DMARC =  = $null ; 
                    } ; 
                    #>
                    
                    while ($DKIM.Type -eq "CNAME") {
                        $DKIMCname = $DKIM.NameHost ; 
                        $DKIM = Resolve-DnsName -Type TXT -name "$DKIMCname" @SplatParameters ;
                        # 5:00 PM 3/19/2024 need to support non-functional selectors (MS only has one mounted hot at a time):
                        if(-not $DKIM){
                            <# 
                            $DkimReturnValues = New-Object psobject ;
                            $DkimReturnValues | Add-Member NoteProperty "Name" $DomainName ;
                            $DkimReturnValues | Add-Member NoteProperty "DkimRecord" $DKIMCname ;
                            $DkimReturnValues | Add-Member NoteProperty "DkimSelector" $DSel ;
                            $DkimReturnValues | Add-Member NoteProperty "ReturnedType" $DKIM.Type;
                            $DkimReturnValues | Add-Member NoteProperty "DKIMAdvisory" "Resolved TXT fail: non-functional selector target" ;
                            $DkimObject.Add($DkimReturnValues) ;
                            $DkimReturnValues | write-output ;
                            #>
                            break ; 

                        } elseif($DKIM.Type -eq "CNAME"){
                            $DkimReturnValues = New-Object psobject ;
                            $DkimReturnValues | Add-Member NoteProperty "Name" $DomainName ;
                            $DkimReturnValues | Add-Member NoteProperty "DkimRecord" $DKIM ;
                            $DkimReturnValues | Add-Member NoteProperty "DkimSelector" $DSel ;
                            $DkimReturnValues | Add-Member NoteProperty "ReturnedType" $DKIM.Type ;
                            $DkimReturnValues | Add-Member NoteProperty "DKIMAdvisory" "Located CNAME pointer" ;
                            $DkimObject.Add($DkimReturnValues) ;
                        }; 
                    } ; # loop-E
                    $rType = $DKIM.Type ; 
                    #$DkimAdvisory = _test-DkimString -DKIM $DKIM -selector $DSel
                    $DKIM = $DKIM | Select-Object -ExpandProperty Strings -ErrorAction SilentlyContinue ;
                    if ($DKIM -eq $null) {
                        $DkimAdvisory = "No leaf DKIM-record TXT found for selector $($DSel)._domainkey NameHost: " ;
                        $DkimAdvisory += "-> $($DKIMCname)" ; 
                        
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
                    $rType = $DKIM.Type ; 
                    $DKIM = $DKIM | Select-Object -ExpandProperty Strings -ErrorAction SilentlyContinue ;
                    if ($DKIM -eq $null) {
                        $DkimAdvisory = "No DKIM-record found for selector $($DSel)._domainkey." ;
                    } elseif ($DKIM -match "v=DKIM1" -or $DKIM -match "k=") {
                        $DkimAdvisory = "DKIM-record found." ;
                    } ;
                } ;

                $DkimReturnValues = New-Object psobject ;
                $DkimReturnValues | Add-Member NoteProperty "Name" $DomainName ;
                $DkimReturnValues | Add-Member NoteProperty "DkimRecord" $DKIM ;
                if($rType -eq 'SOA'){
                    write-verbose "asserting DkimSelector:`$null" ;
                    $DkimReturnValues | Add-Member NoteProperty "DkimSelector" $null ;
                    if($noSelectorSpecified){
                        $DkimAdvisory = $DkimAdvisory.replace('domain.',"domain, against a common Selectors list:`n($($DkimSelector -join '|')).") ; 
                    }; 
                } else { 
                    $DkimReturnValues | Add-Member NoteProperty "DkimSelector" $DSel ;
                } ; 
                $DkimReturnValues | Add-Member NoteProperty "ReturnedType" $rType ;
                $DkimReturnValues | Add-Member NoteProperty "DKIMAdvisory" $DkimAdvisory ;
                
                if($rType -match "CNAME|TXT"){
                    $DkimObject.Add($DkimReturnValues) ;
                    #$DkimReturnValues | write-output ;
                } else { 
                    # no return hit here                    
                } ; 
                if($foundSelector){
                    Break ; 
                } ; 
            } # loop-E DkimSelectors

            #if($DkimReturnValues.DKIMAdvisory -eq 'No DKIM-record found for selector email._domainkey.'){
            if($DKimObject){
                $prpDKIMSels = 'name','dkimselector','returnedtype','dkimadvisory' ; 

                foreach($ditem in $dkimobject){ 
                    $smsg = "`n====`n$(($ditem | ft -a $prpDKIMSels|out-string).trim())" ; 
                    switch($ditem.DkimRecord.type){
                        'CNAME' {
                            $smsg += "`n$($ditem.dkimrecord.type): $($ditem.dkimrecord.Name) => $($ditem.dkimrecord.NameHost)" 
                            write-host $smsg ; 
                        }
                        'TXT' {
                            $smsg += "`n$($ditem.dkimrecord.type): $($ditem.dkimrecord.Name) => $($ditem.dkimrecord.Strings)" 
                            write-host $smsg ; 
                        }
                        'SOA'{
                            $smsg += "`n(invalid lookup)" ; 
                            write-warning $smsg ; 
                        }
                        default{
                            # DKIM TXT'S ARE STORED AS THE STRING, NOT TYPE
                            if($ditem.DkimRecord -match 'v=DKIM1;'){
                                $smsg += "`n$($ditem.dkimselector) : dkim key string:`n`n$($ditem.DkimRecord)`n`n" 
                                write-host $smsg ; 
                            } ELSE { 
                                $smsg += "`n(invalid return)" ; 
                                write-warning $smsg ; 
                            } ; 
                        }
                    } ; 
                } ; 

                <#$smsg = "`n`n DKIM:`nThe following matched selector CNAME or TXT records were discovered (in $($DkimSelector|  measure | select -expand count ) names series run)" ; 
                $smsg = "`n$(($DKimObject | ft -a prpDKIMSels |out-string).trim())" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level PROMPT } 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)`n`n" } ;
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                #>
            } else {
                $smsg = "`n(No matching DKIM Selector found in series checked:" ; 
                if($DkimSelector){
                    $smsg += "`n$(($DkimSelector -join ', '|out-string).trim()))" ; 
                } else { 
                    $smsg += "`n$(($dkselarray -join ', '|out-string).trim()))" ; 
                } ; 
                write-host -foregroundcolor gray $smsg ; 
            } ; 

            $steps++ ;
            write-host "`n" ;
            $pltRvDN.Type= 'TXT' ;
            $pltRvDN.Name = "_dmarc.$($DomainName )" ;
            $smsg ="`n$($steps). Resolve-DNSName DMARC TXT type Matching '^v=DMARC1' w`n$(($pltRvDN|out-string).trim())" ;
            write-host -foregroundcolor GRAY $smsg  ;
            $pltRvDN.erroraction = 'SilentlyContinue' ;
            # 9:39 AM 5/2/2024 seeing sec park doms under cname pointed at _dmarc.parked.thetoroco.com, try through it
            $hit = Resolve-DNSName @pltRvDN ;
            if($hit -is [system.array]){
                if($hit[0].type -eq 'CNAME'){
                    $dmarcCname = $hit[0] ; 
                    #$smsg = "Existing DMARC -type CNAME pointer found:" ; 
                    #$smsg += "`n$(($dmarcCname|out-string).trim())" ; 
                    #write-warning $smsg ; 
                    $hit = $hit | select -last 1 
                } ; 
            }
            if($DMARC = $hit | ?{$_.Strings -Match '^v=DMARC1'}){
                if($dmarcCname){
                    $smsg = "`n=>Matched to DMARC CNAME pointer:"
                    $smsg += "`n$(($dmarcCname|out-string).trim())" ; 
                    $smsg += "`n=>Which resolves to DMARC domain record:`n$(($DMARC|ft -a $prpSPFDMARC | out-string).trim())" ;
                } else { 
                    $smsg = "`n=>Matched to DMARC domain record:`n$(($DMARC|ft -a $prpSPFDMARC | out-string).trim())" ;
                } ; 
                $smsg += "`nStrings:`n$(($hit|select -expand Strings | out-string).trim())`n"
                write-host -foregroundcolor green $smsg ;
                $PolTag = $hit.strings.split(';').trim() |?{$_ -match 'p='} ;
                $SubdomPol = $hit.strings.split(';').trim() |?{$_ -match 'sp='} ;
                $rType = $DMARC.Type ;

                $DmarcReturnValues = New-Object psobject ;
                $DmarcReturnValues | Add-Member NoteProperty "Name" $DomainName ;
                if($dmarcCname){
                    $DmarcReturnValues | Add-Member NoteProperty "DmarcRecord" @($dmarcCname,$Dmarc) ;
                } else {
                    $DmarcReturnValues | Add-Member NoteProperty "DmarcRecord" $Dmarc ;
                } ; 
                $DmarcReturnValues | Add-Member NoteProperty "PolicyTag" $PolTag ;
                $DmarcReturnValues | Add-Member NoteProperty "SubDomainPolicyTag" $SubdomPol ;

                $smsg = "Policy tag:$($PolTag)" ;
                $smsg += "`np=$($poltag.split('=')[1]): all traffic that doesn't pass either:"
                $smsg += "`n  -- SPF (egressed from an SPF IP)" ;
                $smsg += "`n  -- OR DKIM signing (stamped in message header with DKIM key)" ;
                switch($poltag.split('=')[1]){ 
                    'none'{
                        $smsg +="`np=none: => No action is taken/messages remain unexamined." ; 
                    } 
                    'quarantine'{
                        $smsg +="`np=quarantine: => Further examination (Quarantine/Junk folder)." ;  
                    }
                    'reject'{
                        $smsg +="`np=reject: => Reject those messages that fail DMARC authentication"
                    }
                    default {
                        $smsg +="`nUNCRECOGNIZED $($poltag.split('=')[1])! MISCONFIGURED DMARC?" ; 
                    }                
                }
                if($PolTag -AND -not $SubdomPol){
                    $smsg += "`n`nSUBDOMAINS:Policy p=xxx with NO sp=xxx subdomain pol: Subdomains inherit the p=xxx Policy" ;
                    $DmarcReturnValues | Add-Member NoteProperty "PolicyInheritance" "SUBDOMAINS:Policy p=xxx with no sp=xxx subdomain pol: Subdomains inherit the p=xxx Policy"  ;
                } elseif($PolTag -AND $SubdomPol){
                    if($SubdomPol -like '*=reject'){
                        $smsg += "`n`nSUBDOMAINS:Policy p=xxx AND sp=reject subdomain pol: Subdomains inherit the sp=reject Policy" ;
                        $smsg += "`n(unless subdomain has it's _own_ DMARC record with it's own p=xxx effective local policy)" ;
                        $DmarcReturnValues | Add-Member NoteProperty "PolicyInheritance" "SUBDOMAINS:Policy p=xxx AND sp=xxx subdomain pol: Subdomains inherit the sp=xxx Policy (unless subdomain has it's own DMARC record w a p= pol)" ;
                    } else { 
                        $smsg += "`n`nSUBDOMAINS:Policy p=xxx AND sp=xxx subdomain pol: Subdomains inherit the sp=xxx Policy" ;
                        $smsg += "`n(unless subdomain has it's _own_ DMARC record with it's own p=xxx effective local policy)" ;
                        $DmarcReturnValues | Add-Member NoteProperty "PolicyInheritance" "SUBDOMAINS:Policy p=xxx AND sp=xxx subdomain pol: Subdomains inherit the p=xxx Policy (unless subdomain has it's own DMARC record)" ;
                    } ; 
                } ;
                write-host -fore yellow $smsg ;

                
                <#if($rType -eq 'SOA'){
                    #write-verbose "asserting DkimSelector:`$null" ;
                    $DmarcReturnValues | Add-Member NoteProperty "DkimSelector" $null ;
                    if($noSelectorSpecified){
                        $DmarcAdvisory = $DmarcAdvisory.replace('domain.',"domain, against a common Selectors list:`n($($DKSelArray -join '|')).") ; 
                    };
                    
                } else { 
                    $DmarcReturnValues | Add-Member NoteProperty "DkimSelector" $DSel ;
                } ; 
                #>
                $DmarcReturnValues | Add-Member NoteProperty "ReturnedType" $rType ;
                #$DmarcReturnValues | Add-Member NoteProperty "DKIMAdvisory" $DmarcAdvisory ;

            } else {
                $smsg = "`n=>NO DMARC RECORD FOUND FOR DOMAIN:$($DomainName )`n" ;
                write-warning $smsg ;

                $DmarcReturnValues = New-Object psobject ;
                $DmarcReturnValues | Add-Member NoteProperty "Name" $DomainName ;
                $DmarcReturnValues | Add-Member NoteProperty "DmarcRecord" $null ;
            } ;
            $DmarcObject.Add($DmarcReturnValues) ;
            #$DmarcReturnValues | write-output ;

            # since we're comingling 3 types of record, doesn't pay to dump them into the pipeline: org them into a return object with a property per obj type
            <#$objReturn = [ordered]@{
                SPF = $null ; 
                DKIM = $null ; 
                DMARC =  = $null ; 
            } ; 
            #>
            $objReturn.SPF = $SpfObject ; 
            $objReturn.DKIM = $DKIMObject ; 
            $objReturn.DMARC = $DMARCObject ; 
            $objReturn.MX = $MXObject ; 
            write-host -foregroundcolor green "(returning summary object to pipeline)" ; 
            New-Object -TypeName PsObject -Property $objReturn | write-output ; 

            write-host @whBnr -obj "$((get-date).ToString('HH:mm:ss')):$($sBnr.replace('=v','=^').replace('v=','^='))" ;

        } # loop-E Name
    } END {
        
    } ;
}

#*------^ Resolve-DnsSenderIDRecords.ps1 ^------


#*------v resolve-networkLocalTDO.ps1 v------
Function resolve-NetworkLocalTDO {
        <#
        .SYNOPSIS
        resolve-NetworkLocalTDO.ps1 - Retrieve local network settings - interface descriptors and resolved ip address PTR -> A Record FQDN, also returns Domain/Workgroup info
        .NOTES
        Version     : 0.0.1
        Author      : Todd Kadrie
        Website     : http://www.toddomation.com
        Twitter     : @tostka / http://twitter.com/tostka
        CreatedDate : 2025-04-28
        FileName    : resolve-NetworkLocalTDO.ps1
        License     : MIT License
        Copyright   : (c) 2025 Todd Kadrie
        Github      : https://github.com/tostka/verb-XXX
        Tags        : Powershell
        AddedCredit : REFERENCE
        AddedWebsite: URL
        AddedTwitter: URL
        REVISIONS
        11:07 AM 5/15/2025 get-cim|wmiobject Win32_ComputerSystem wasn't returning a Domain or Workgroup property, unless |select -expand used, so tacked on 2 explicit queries for the properties.
        12:55 PM 5/13/2025 added get-CimInstance/get-WMIInstance fail through logic, added OS.Domain & .Workgroup properties to return
        .DESCRIPTION
        resolve-NetworkLocalTDO.ps1 - Retrieve local network settings - interface descriptors and resolved ip address PTR -> A Record FQDN, also returns Domain/Workgroup info
        .INPUTS
        None. Does not accepted piped input.(.NET types, can add description)
        .OUTPUTS
        System.PsCustomObject summary of useful Nic descriptors                
        .EXAMPLE
        PS> $netsettings = resolve-NetworkLocalTDO ; 
        Demo run
        .LINK
        https://github.com/tostka/verb-Network
        #>                
        [CmdletBinding()]
        Param () ;
        BEGIN{
            $rgxIP4Addr = "(?:\d{1,3}\.){3}\d{1,3}" ;
            $rgxIP6Addr = "^((([0-9A-Fa-f]{1,4}:){1,6}:)|(([0-9A-Fa-f]{1,4}:){7}))([0-9A-Fa-f]{1,4})$" ; 
            $rgxIP4AddrAuto = "169\.254\.\d{1,3}\.\d{1,3}" ;  
            $prpNS = 'DNSHostName','ServiceName',@{N="DNSServerSearchOrder";E={"$($_.DNSServerSearchOrder)"}}, 
                @{N='IPAddress';E={$_.IPAddress}},@{N='DefaultIPGateway';E={$_.DefaultIPGateway}} ;
        } ; 
        PROCESS {
            $netsettings = [ordered]@{ DNSHostName = $null ;  ServiceName = $null ;  DNSServerSearchOrder = $null ;  IPAddress = $null ;  DefaultIPGateway = $null ;  Fqdn = $null ; Domain = $null ; Workgroup = $null }  ;                    
            TRY{
                if(get-command get-ciminstance -ea 0){
                    $OS = (Get-ciminstance -class Win32_OperatingSystem -ea STOP) ; 
                    $netsettings.Domain = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Domain ; 
                    $netsettings.Workgroup = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Workgroup ; 
                    $nic = Get-ciminstance -class Win32_NetworkAdapterConfiguration -ComputerName localhost -ea STOP ;
                } else { 
                    $OS = (Get-WmiObject -Class Win32_ComputerSystem -ea STOP)
                    $netsettings.Domain = Get-WmiObject -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Domain ; 
                    $netsettings.Workgroup = Get-WmiObject -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Workgroup ; 
                    $nic = Get-WMIObject Win32_NetworkAdapterConfiguration -Computername localhost -ea STOP ;
                } ; 
                if($nic = $nic | ?{$_.IPEnabled -match "True"} | Select -property $prpNS){
                    $netsettings.DNSHostName = $nic.DNSHostName; 
                    $netsettings.ServiceName = $nic.ServiceName;  
                    $netsettings.DNSServerSearchOrder = $nic.DNSServerSearchOrder;  
                    $netsettings.IPAddress = $nic.IPAddress;  
                    $netsettings.DefaultIPGateway = $nic.DefaultIPGateway;  
                    if($netsettings.ipaddress | ?{$_ -MATCH $rgxIP4Addr -AND $_ -notmatch $rgxIP4AddrAuto} ){
                        $netsettings.fqdn = (resolve-dnsname -name ($netsettings.ipaddress | ?{$_ -MATCH $rgxIP4Addr -AND $_ -notmatch $rgxIP4AddrAuto} ) -type ptr).namehost | select -first 1 ;   
                    } ; 
                }else {
                    $smsg = "NO IPEnabled -match True NICS FOUND!" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                    else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                    throw $smsg ; 
                }
                # 9:45 AM 5/13/2025 add workgroup collection, if non-domain-joined
                if($env:Userdomain -eq $env:COMPUTERNAME){
                    $smsg = "%USERDOMAIN% -EQ %COMPUTERNAME%: $($env:computername) => non-domain-connected, likely edge role Ex server!" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                    else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                } ; 
                if($netsettings.Workgroup){
                    $smsg = "WorkgroupName:$($WorkgroupName)" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                } ; 
                [pscustomobject]$netsettings | write-output ; 
            } CATCH {
                $ErrTrapd=$Error[0] ;
                $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            } ;                     
        } ; 
    }

#*------^ resolve-networkLocalTDO.ps1 ^------


#*------v resolve-SMTPHeader.ps1 v------
function resolve-SMTPHeader {
    <#
    .SYNOPSIS
    resolve-SMTPHeader - Parse an SMTP message header stack into Name:Value combos for further analysis.
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2024-
    FileName    : resolve-SMTPHeader.ps1
    License     : MIT License
    Copyright   : (c) 2024 Todd Kadrie
    Github      : https://github.com/tostka/verb-XXX
    Tags        : Powershell
    AddedCredit : REFERENCE
    AddedWebsite: URL
    AddedTwitter: URL
    REVISIONS
    * 9:29 AM 4/16/2025 added -noTrim to read-MultiLineInputDialogAdvanced call when Header isn't specified (and test for indents in header - line-wrap detection requires indents!).
        fixed CBH input spec; cleaned
    * 12:59 PM 12/9/2024 init
    .DESCRIPTION
    resolve-SMTPHeader - Parse an SMTP message header stack into Name:Value combos for further analysis.
    .PARAMETER  Header
    SMTP Header [-Header `$headertext]
    .INPUTS
    System.String
    System.String[]
    Accepts piped input
    .OUTPUTS
    System.PSCustomObject 
    Returns summary object as an array of parsed Header Name:Value combos
    .EXAMPLE
    PS> $parseHdrs = resolve-SMTPHeader -header $headertext ;
    PS> write-verbose "Filter the Received: headers" ; 
    PS> $parsedHdrs | ?{$_.headername -match 'Received:'}

        HeaderName HeaderValue                                                                                                                                                                                                          
        ---------- -----------                                                                                                                                                                                                          
        Received:  {from CH2PR14CA0024.namprd14.prod.outlook.com (2603:10b6:610:60::34),  by SA6PR04MB9493.namprd04.prod.outlook.com (2603:10b6:806:444::18) with,  Microsoft SMTP Server (version=TLS1_2,,  cipher=TLS_ECDHE_RSA_WIT...
        Received:  {from CH3PEPF0000000A.namprd04.prod.outlook.com,  (2603:10b6:610:60:cafe::7c) by CH2PR14CA0024.outlook.office365.com,  (2603:10b6:610:60::34) with Microsoft SMTP Server (version=TLS1_3,,  cipher=TLS_AES_256_GCM...
        Received:  {from e226-11.smtp-out.us-east-2.amazonses.com (23.251.226.11) by,  CH3PEPF0000000A.mail.protection.outlook.com (10.167.244.37) with Microsoft,  SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15...

    PS> write-verbose "Filter the Authentication-Results: headers" ; 
    PS> $authResult = $parsedHdrs | ?{$_.headername -match 'Authentication-Results:'} ;
    PS> $authresult | %{ write-host "`n$($_.HeaderName):" ; write-host "$(($_.HeaderValue|out-string).trim())`n" ; } ;        

        Authentication-Results:
        spf=pass (sender IP is 23.251.226.11)
         smtp.mailfrom=us-east-2.amazonses.com; dkim=pass (signature was verified)
         header.d=amazonses.com;dmarc=fail action=quarantine
         header.from=toro.com;compauth=fail reason=000

    PS> PS> write-verbose "Filter the Received-SPF: headers" ; 
    PS> $parsedHdrs | ?{$_ -match 'Received-SPF:'} | fl ;

        HeaderName  : Received-SPF:
        HeaderValue : {Pass (protection.outlook.com: domain of us-east-2.amazonses.com,  designates 23.251.226.11 as permitted sender),  receiver=protection.outlook.com; client-ip=23.251.226.11;,  
                      helo=e226-11.smtp-out.us-east-2.amazonses.com; pr=C}
        HeaderIndex : 15

    PS> $DkimSigs = $parsedHdrs | ?{$_.headername -match 'DKIM-Signature:'} ;
    PS> $DkimSigs | %{ write-host "`n$($_.HeaderName)" ; write-host "$(($_.HeaderValue|out-string).trim())`n" ; } ; 

        DKIM-Signature:
        v=1; a=rsa-sha256; q=dns/txt; c=relaxed/simple;
	        s=xplzuhjr4seloozmmorg6obznvt7ijlt; d=amazonses.com; t=1733178897;
	        h=From:Reply-To:To:Subject:MIME-Version:Content-Type:Message-ID:Date:Feedback-ID;
	        bh=jxlsOZBqq0nUQqX5ofi0H+YQbyRMNFXWk4D+NdI3ZAo=;
	        b=rAOY09c+aUgCNF1gYH+bM0oElSuYLFgFpUsmUIJlq/lAU+TaRa5DIDFWsAkkAikR
	        R8USYlHlInRZ2nq71qgnz+MQpScHCTFKg10hC34MyfWiV5pV2QUCxFJJ/eWdSTBZPHB
	        aDjWnbOcBDzN80T4XyC9nIs2+nQ8Yqt0ePYBk8QY=

    PS> write-verbose "filter From:" ; 
    PS> $parsedHdrs | ?{$_.headername -match 'From:'} | %{"$($_.HeaderName) $($_.HeaderValue)"}

        From: walker.olson@toro.com

    PS> write-verbose "filter Return-Path:" ; 
    PS> $parsedHdrs | ?{$_.headername -match 'Return-Path:'} | %{"$($_.HeaderName) $($_.HeaderValue)"} ; 

        Return-Path:  010f0193898333b2-294e9589-d10c-43e6-94ba-4bc88a999262-000000@us-east-2.amazonses.com


    Typical usage
    .EXAMPLE
    PS> $parsedHdrs = $header | resolve-smtpHeader 
    Pipeline demo: Fed variable holding header in via pipeline.
    .LINK
    https://github.com/tostka/verb-Network
    #>
    ## [OutputType('bool')] # optional specified output type
    [CmdletBinding()]
    ## PSV3+ whatif support:[CmdletBinding(SupportsShouldProcess)]
    [Alias('parse-SMTPHeader')]
    PARAM(
        # Mandatory = $true,
        [Parameter(ValueFromPipeline=$true, HelpMessage="SMTP Header [-Header `$headertext]")]
            # if you want to default a value but ensure user doesn't override with null, don't use Mandetory, use...
            [ValidateNotNullOrEmpty()]
            #[string]
            $Header,
        [Parameter(HelpMessage="Run get-help on the cmdlet [-Help]")]
              [switch]$HELP
    )
    BEGIN{
        $Verbose = ($VerbosePreference -eq 'Continue') ; 
        
        # check if using Pipeline input or explicit params:
        if ($rPSCmdlet.MyInvocation.ExpectingInput) {
            $smsg = "Data received from pipeline input: '$($InputObject)'" ;
            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
        } else {
            # doesn't actually return an obj in the echo
            #$smsg = "Data received from parameter input: '$($InputObject)'" ;
            #if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
            #else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
        } ;

        #endregion SUBMAIN ; #*======^ END SUB MAIN ^======
    } ;  # BEGIN-E
    # ps1 faked:#endregion BEGIN ; #*------^ END BEGIN ^------
    PROCESS {

        $Error.Clear() ; 
        
        if(-not $HEADER){
            write-verbose 'Always pre-Enable DPI-Aware Windows Forms' ;

            TRY{[ProcessDPI] | out-null }catch{
                Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public class ProcessDPI {
    [DllImport("user32.dll", SetLastError=true)]
    public static extern bool SetProcessDPIAware();
}
'@
} ;
            $null = [ProcessDPI]::SetProcessDPIAware() ;
            #write-verbose "Normal Prompting (allows empty output) - Textbox mode - String output" ;
            # 8:59 AM 4/16/2025 appears this is trim()'ing, de-indenting the header: no indents are coming through!
            $pltRdMLIDA=[ordered]@{
                Message = "No -header specified: Paste header text into the dialog" ;
                WindowTitle = "Prompt: (Textbox: String return)" ;
                InboxType = "txt" ;
                ReturnType = "str" ;
                FixSquareBrkts = $false ;
                NoTrim = $true ; # added 9:22 AM 4/16/2025, recoded verb-io\read-MultilineInputDialogAdvanced to support
                ShowDebug = $true ;
            } ;
            $smsg = "read-MultiLineInputDialogAdvanced w`n$(($pltRdMLIDA|out-string).trim())" ;
            write-host -foregroundcolor green $smsg  ;
            $header = read-MultiLineInputDialogAdvanced @pltRdMLIDA ;
            write-host "`r`n-----Return-String:`r`n" + $header  + "`r`n-----End of Return" ;        
        } ; 

        #region PARAMHELP ; #*------v PARAMHELP  v------
        # if you want no params -OR -help to run get-help, use:
        #if ($help -OR (-not $rPSCmdlet.MyInvocation.ExpectingInput) -AND (($PSParameters| measure-object).count -eq 0)) {
        # on blank specific param -or -help
        #if (-not $Header -OR $HELP) {
        # if you only want -help to run get-help
        if ($HELP) {
            if($MyInvocation.MyCommand.Name.length -gt 0){
                Get-Help -Name "$($MyInvocation.MyCommand.Name)" -full ; 
                # also could run using native -? == get-help [command] (avoiding as invoke-expression is stigmatized for sec)
                # also note -? only runs default gh output, not full or some other variant. And cmdlet -? -full etc doesn't work
                #Invoke-Expression -Command "$($MyInvocation.MyCommand.Name) -?"
            }elseif($PSCommandPath.length -gt 0){
                Get-Help -Name "$($PSCommandPath)" -full ; 
            }elseif($CmdletName.length -gt 0){
                Get-Help -Name "$($CmdletName)" -full ; 
            } ; 
            break ; #Exit  ; 
        }; 
        #endregion PARAMHELP  ; #*------^ END PARAMHELP  ^------        

       <# Testing headers:
$hsHdr = @"
Received: from CH2PR14CA0024.namprd14.prod.outlook.com (2603:10b6:610:60::34)
 by SA6PR04MB9493.namprd04.prod.outlook.com (2603:10b6:806:444::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8207.18; Mon, 2 Dec
 2024 22:34:58 +0000
Received: from CH3PEPF0000000A.namprd04.prod.outlook.com
 (2603:10b6:610:60:cafe::7c) by CH2PR14CA0024.outlook.office365.com
 (2603:10b6:610:60::34) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.8207.18 via Frontend Transport; Mon,
 2 Dec 2024 22:34:58 +0000
Authentication-Results: spf=pass (sender IP is 23.251.226.11)
 smtp.mailfrom=us-east-2.amazonses.com; dkim=pass (signature was verified)
 header.d=amazonses.com;dmarc=fail action=quarantine
 header.from=xxxx.com;compauth=fail reason=000
Received-SPF: Pass (protection.outlook.com: domain of us-east-2.amazonses.com
 designates 23.251.226.11 as permitted sender)
 receiver=protection.outlook.com; client-ip=23.251.226.11;
 helo=e226-11.smtp-out.us-east-2.amazonses.com; pr=C
Received: from e226-11.smtp-out.us-east-2.amazonses.com (23.251.226.11) by
 CH3PEPF0000000A.mail.protection.outlook.com (10.167.244.37) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.8230.7
 via Frontend Transport; Mon, 2 Dec 2024 22:34:58 +0000
DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=relaxed/simple;
	s=xplzuhxxxxxxxxxxxxxxxxxxnvt7ijlt; d=amazonses.com; t=1733178897;
	h=From:Reply-To:To:Subject:MIME-Version:Content-Type:Message-ID:Date:Feedback-ID;
	bh=jxlsOZBqq0nUQqX5ofi0H+YQbyRMNFXWk4D+NdI3ZAo=;
	b=rAOY09c+aUgCNF1gYH+bM0oElSuYLFgFpUsmUIJlq/lAU+TaRa5DIDFWsAkkAikR
	R8USYlHlInRZ2nq71qgnz+MQpScHCTFKg10hC34MyfWiV5pV2QUCxFJJ/eWdSTBZPHB
	aDjWnbOcBDzN80T4XyC9nIs2+nQ8Yqt0ePYBk8QY=
From: xxxxxx.xxxxx@xxxx.com
Reply-To: xxxxxx.xxxxx@xxxx.com
To: xxxxxx.xxxxx@xxxx.com, xxxxxxxxxx@xxxxxxx.com
Subject: xxxx xxxxxxxx: xxxxxxx xxxxxxxxxxx
MIME-Version: 1.0
Content-Type: text/plain
Message-ID: <010f0193898333b2-294e9589-d10c-43e6-94ba-4bc88a999262-000000@us-east-2.amazonses.com>
Date: Mon, 2 Dec 2024 22:34:57 +0000
Feedback-ID: ::1.us-east-2.QyulnpM4L1IwuxomjV4UC071kbkHZsV18gSZ4yEZxG0=:AmazonSES
X-SES-Outgoing: 2024.12.02-23.251.226.11
Return-Path:
 010f0193898333b2-294e9589-d10c-43e6-94ba-4bc88a999262-000000@us-east-2.amazonses.com
X-EOPAttributedMessage: 0
X-EOPTenantAttributedMessage: 549366ae-e80a-44b9-8adc-52d0c29ba08b:0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PEPF0000000A:EE_|SA6PR04MB9493:EE_
X-MS-Office365-Filtering-Correlation-Id: 95c7a6f1-8e9f-4a75-156e-08dd13218d84
xxxxRule-ApplyExternalStamp: Rule triggered
X-Forefront-Antispam-Report:
 CIP:23.251.226.11;CTRY:US;LANG:en;SCL:5;SRV:;IPV:NLI;SFV:SPM;H:e226-11.smtp-out.us-east-2.amazonses.com;PTR:e226-11.smtp-out.us-east-2.amazonses.com;CAT:SPOOF;SFS:(13230040)(32142699015)(8096899003);DIR:INB;
X-Microsoft-Antispam: BCL:0;ARA:13230040|32142699015|8096899003;
X-Microsoft-Antispam-Message-Info:
 =?utf-8?B?ekdzcjV2YVU5alZycERMUUVITmJ5eTc3Nm9zLytESG1EWGpFMjdEU21iYUVv?=
 =?utf-8?B?UzdVQlFSa2VDNTVCTkhrQ1NwZTluMTRORi9naFoxYmQyTmpWMGFhZ0laZjZX?=
 =?utf-8?B?VzNlQTZYQmtxdFM0U3VsZWRpVFdpbmQ1UEFjdEFUamVEaFc1SkJIaWRBUkQ4?=
 =?utf-8?B?ZUJHK3RPdE9zY0VtUUNvcVhlVzV5YkY5cjJzZHJ0cm82M2plbXBkTno3Qkt2?=
 =?utf-8?B?U0Z0ZXZXV1RxMkhtUGZFajh0RXJETE5KYWRERW8zNjA5cFBXOXd3aGlIUy9O?=
 =?utf-8?B?RW8rRGpiQ1I1ZXdnUmM2bCtOSVhTeFduMDdsWnlvZGtjVzhwYmxtcGZrOExn?=
 =?utf-8?B?TFI4R3dCSE8wVTAzMGp4MGJ4SHFzS0M0WU96L1E0ZHFRVXpkRHlzZmVxNm5u?=
 =?utf-8?B?ZzBvQWNDMDBLTlk2SkxacGZPRDQ3NGIyT0VtWG0zR1JpaW8zeUJVMjUvcFVR?=
 =?utf-8?B?YUltNWxzZjJDbFVxcWptUWh2ZVZXaWRIOFhmTUIzWmtSemtXR1hHWmsrbHM5?=
 =?utf-8?B?Zi9TK2llWWMwZTcxYm1zWUJJUVZCZk4wNEU1dlcybjZIN3dnbTI2UWx3eUFI?=
 =?utf-8?B?ekR4eE5oM3hXVzhmUU9vOTlmSGlkWmd6Ly9JbWcxWDZ3dXlKNEhUNGlZeGlX?=
 =?utf-8?B?TytPVTJZTmJtUllNWE5tVWtOd0lONG14amNGd3FsLzk0STVlN1R6MzJuNXFY?=
 =?utf-8?B?TXpEQmJhZy9ndnZvQ3FzWFlrQmU3bzR1RFFPZkpidGFvMW5mUW9FNHM1Wklt?=
 =?utf-8?B?SWRWWTc5dFUwQlliZ2dPWWpxVXZJTGd6VmRnMG9ZejF0V1lNOEFWMlVDSkRD?=
 =?utf-8?B?MHlzWTFHQzBvTlJMSnB0MGZPWCtOc1lIR29hS2NrMTgvSDAvVzRYUk1Ja20y?=
 =?utf-8?B?dit1QTMwdkVZSUt1aFl5bDErbnZDSHZYaTdrZDgvdWFvbnZSaDZLTEg1U1F5?=
 =?utf-8?B?c2RCNmFEdVFnUWhCUHJpTHhTaEYzYStTZzk4czdCMzdVd1YwbkVKYm9WM0JG?=
 =?utf-8?B?MkphKy9Xb080OW1RNjg2VnZJMTlVOWV3dzgwT3A2ZjBzL05vTlU1Z2p0Z0Zp?=
 =?utf-8?B?M0RWRVZKaDYzaDF4TnhYQlloSlhTcEpVdCtubzVFZUNGUENXaGc3R2E2WktX?=
 =?utf-8?B?KzIwVGRRRDlldlJzN3o2OE9QY0tjR0ZER0FiN2ZPeGhadzZmSGpsejhKM0Mr?=
 =?utf-8?B?V0xCLzA2V2JPaTZxYWQvZU9MN3FmMEhpWXIvYlBHTTVldTFQc3ZZVytTajY3?=
 =?utf-8?B?dUVxS3FGSE1ueHRzSnYrVVF4cGJwSXh2aGFoME0wNW03ZFMwdEFYeU1WeHcv?=
 =?utf-8?B?VE4zMU1CS0t1R2VVb3Z5NDVyOFRDODFjVHdJUTM5UVQ1Y2lOWEg1bXBYanJS?=
 =?utf-8?B?WnZuYTNXRk5lMnZ6bUZkM3daVTJKYmtoQTZGUzdETmZXUjVLZEtYWUZwTkN2?=
 =?utf-8?B?WU5VN1ZFQkc0M3grZEw2d0RCeHlZNjdPeHFCSjZmQ1Zpd0JtWS81N2tKalpw?=
 =?utf-8?B?K3BVQ3ZrVUVRRHZxMUgyazFCejlWaWdjZE9DUjJmbzFGOG1pNkppYUg0NGJm?=
 =?utf-8?B?VWFxbngrem1Vc2RpMHduNHNCMWhMeUtkcDZxL2xiRzUxZk1NRExEWm1kWVA0?=
 =?utf-8?B?WWI5ajB4WHpseDI0V3JoK3pEbWJ6azF6RTBoRkNWL1lRZXg0aU1JUTJDOVRu?=
 =?utf-8?B?dDNiWDgrSDdyN01FVWFpN3U0QWZjVFdYeE15ZkREK25vendKNjV1YnYzSG11?=
 =?utf-8?B?VElibEJ5VjdPRkt2a1g4RHZUbXU4MjJKdUJEK0lCMkYxWldwTHpyc3NYTnUv?=
 =?utf-8?B?T2tOdUpZeWZXNGhNUzYwcGF6Zk9XZlZ1d3hZazZiNnE4WkR3cHNwQkZTV3E1?=
 =?utf-8?B?ejRoVnNvb1VHY2ZhV0VKL3dsNWJlUS90ZlF6R2J3VmR5Y3FWUEFvZ1FIbGtC?=
 =?utf-8?B?RkZqcnZFQklhUmQ4YXpYNmtSNFFMN3JCNWxGUzZtNndLb1UyYTRnL2lDVzdR?=
 =?utf-8?B?K3prK0h4cVNvZWE0TXUwRlk5aUVGblNTMTNuZS9rSG1aenJiMGt1WTR2WkUx?=
 =?utf-8?B?WDk1VE1oa3VRWVZ5Zm1XTzJucGdKYUN3TjlTYjFMdXJ6QU5kRjRYMFlIRzRv?=
 =?utf-8?B?SnMzQnNtdGFXWlpac1IvR2QxWmU0enBzK0pPbFFZdkwyRlpsdExoMjdubmtF?=
 =?utf-8?B?S0R0cVhRYjFFUDVadXAzZkwzYVVSMS9YSHRwOFlLOW5SUCtzb3oyb3RZdzlJ?=
 =?utf-8?B?cWcyeGdDVFV5xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxhSNTVoZkk4Y0huZmZm?=
 =?utf-8?B?eUxxZ0g3VW9pczhBUnVGWlh6WDR1SXZmY2hlUnZzM2dETG5OdUdtZ1dXYmlt?=
 =?utf-8?B?ZjZwR0FFSnIzdGorclFwRWl0N043Z0NDb2pScUZRajI1UnVINXRrNGhrUzdn?=
 =?utf-8?B?QXJGYzQycjM2dHZVYlRhRE1VQzdoRUtQWldWN0tqRG9sV0greEVycG9NS1Iw?=
 =?utf-8?B?c01vUXJXVFRsVDJFTlkwSFhzQSthcml0YnVoTFVJcUpITEczM25HM04rQm1N?=
 =?utf-8?B?QzRnSkZCVTIzLzhXQXBMZkRuSGM1bXVXTGdIVlVLR0J3bytvb3RrdkNXTzRo?=
 =?utf-8?B?NUZPaWhpak0xM3RxTTY1TTJ6TktaK004QXpHWHFwdk9VZ29oamxueCtuUDZ5?=
 =?utf-8?B?Ly95eU1TYzJuSTZnU2FQZXYycmlYSTlVd1BIZGt2Zk1yWFlLdnU3VkpTVDBN?=
 =?utf-8?B?b0QvOVNVQWlFc0x6RVFMKzdWRnVWTWl5NmhzZU1IR2VvdW5aeVc5WVhRUjli?=
 =?utf-8?B?d3ZoNG5DTGtFcHZ3UlFmWmR0ZmJMTWxmSnNldUNndkE3RHIvcHV6MkUwQkox?=
 =?utf-8?B?RGpKWmtLUWlsR2VnY24xZDJ0MHdadklUQkplYXNiZCtrbGtGb0lRVFdmS05x?=
 =?utf-8?B?N3prWTg3bmdqWExOVVM5OUI4VmFpZDRZcU1HM1g2TWtVdVJlQ0tMa2ZYMlpX?=
 =?utf-8?B?T0M5bGhKZXJaUWtLVy9BRTBCalV0Z2JQVFNaMk9TRzhzY0phWnJZZmx0Q20r?=
 =?utf-8?B?VzR3UmxabVJNK3FQWlRRL0l6V2Q3a05yNk0zSUtMNUdPcmZmYk8ycXNObnRi?=
 =?utf-8?B?eWdRZjRUL25tOEVmZm9La3BPMkZpYzZtd281b01lWkUzWGptYjAvQUI4eTJy?=
 =?utf-8?B?bXZkS0hydzI5QksySXQzQjNOdFVHSXdsZEs1Z3RnWXlHSGxPRnh3c25Oc1pI?=
 =?utf-8?Q?v6fwB7rq87VmbOLkv4GF+5kQOA=3D?=



"@.Split([Environment]::NewLine) | ?{$_} ;
    #>
        <#
$hsHdr = @"
Received: from MN2PR04MB6991.namprd04.prod.outlook.com (2603:10b6:208:1e1::17)
 by CH0PR04MB8147.namprd04.prod.outlook.com with HTTPS; Thu, 5 Dec 2024
 21:07:11 +0000
Received: from CH0PR03CA0304.namprd03.prod.outlook.com (2603:10b6:610:118::28)
 by MN2PR04MB6991.namprd04.prod.outlook.com (2603:10b6:208:1e1::17) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8230.12; Thu, 5 Dec
 2024 21:07:10 +0000
Received: from CH1PEPF0000AD83.namprd04.prod.outlook.com
 (2603:10b6:610:118:cafe::67) by CH0PR03CA0304.outlook.office365.com
 (2603:10b6:610:118::28) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.8230.12 via Frontend Transport; Thu,
 5 Dec 2024 21:07:10 +0000
Authentication-Results: spf=pass (sender IP is 123.123.123.123)
 smtp.mailfrom=xxxxxx.xxx; dkim=pass (signature was verified)
 header.d=xxxxxx.xxx;dmarc=pass action=none
 header.from=xxxxxx.xxx;compauth=pass reason=100
Received-SPF: Pass (protection.outlook.com: domain of xxxxxx.xxx designates
 123.123.123.123 as permitted sender) receiver=protection.outlook.com;
 client-ip=123.123.123.123; helo=mail-108-xxxxxx.xxxxxxx.xxx; pr=C
Received: from mail-108-xxxxxx.xxxxxxx.xxx (123.123.123.123) by
 CH1PEPF0000AD83.mail.protection.outlook.com (10.167.244.85) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.8230.7
 via Frontend Transport; Thu, 5 Dec 2024 21:07:09 +0000
Received: from xxxxxxxxx.xxxxxxx.xxx ([123.456.789.0] xxxxxxxxx.xxxxxxx.xxx)
 (Authenticated sender: mN4UYu2MZsgR)
 by mail-108-xxxxxx.xxxxxxx.xxx (ZoneMTA) with ESMTPSA id 19398a5d8640003e01.001
 for <xxxx.xxxxxx@xxxx.com>
 (version=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384);
 Thu, 05 Dec 2024 21:07:05 +0000
X-Zone-Loop: 4cb2588f304a7c1711c10a9b5c4913136ce484dc7f3c
X-Originating-IP: [123.456.789.0]
DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=relaxed/relaxed; d=xxxxxx.xxx;
	s=x; h=Content-Transfer-Encoding:Content-Type:MIME-Version:Message-ID:Subject
	:To:From:Date:Sender:Reply-To:Cc:Content-ID:Content-Description:Resent-Date:
	Resent-From:Resent-Sender:Resent-To:Resent-Cc:Resent-Message-ID:In-Reply-To:
	References:List-Id:List-Help:List-Unsubscribe:List-Subscribe:List-Post:
	List-Owner:List-Archive; bh=3BNWhTiaKphQvWfI/Drg+j+X2Bz/+YePgyVANN02pbo=; b=Q
	CKkMkhDEJO2ECib2gUxQtHNfw8xxxxxxxxxxxxxxxxxxxxxcx58xdnlGQnaeUWIQbzJ3+l4roPgRv
	Cep1RUvloULNEoV4IBgsfheJAusQrbMSjfdDK6I/oW5HfX6S6y53ghIIQp4hJeFrdqXaHlbIOZZy6
	DZvglDdwO6wjUWo8Hwk8ztXHVvMmqXahV9jWy3ngS7soL9w4z+gck2dziNrrcPELHpYJYNnWVb4zw
	NMx/4z8VJ5mjBNcC6tId3vZAI7TbqoqVCU+Aj/xZHHzYOODqPRi4HMn0o1K4IwCRbWjYqvSu3K/91
	mh3AvzVSDhzTnjdffEtp2nvGotlTeAGzA==;
Date: Thu, 05 Dec 2024 15:07:03 -0600
From: xxxx xxxxxx <xxxx@xxxxxx.xxx>
To: xxxx xxxxxx <xxxx.xxxxxx@xxxx.com>
Subject: Test message
Message-ID: <0C03B518-554F-4B18-BB6F-73D9B9E556E2@xxxxxx.xxx>
MIME-Version: 1.0
Content-Type: multipart/alternative;
 boundary=----O23DT15SDX1UZ783340ZO38BRXUIZ2
Content-Transfer-Encoding: 7bit
Autocrypt: addr=xxxx@xxxxxx.xxx; prefer-encrypt=mutual; keydata=
 mQGNBGJDpsgBDAD1Bj44kgvX2gMJx6fg4GeGOk6+NpRx/Zmkxffl/+YZ8tNmXhGvaMAd32EKJIM/
 Yj9jeTQ+Xw3PsELRCFQSRZxXHfxcId187+RHurvXX8+1tMNLnRzJIx0buZQUiZ/7Xf4tIjIBrkyR
 r20vR+UH+DFwenY7UUFVSsrZAMc7PQ67Lx2WPNhRiRh6Ujq7QoUVkxU6A6ymcoFbZFFoV69bUoBw
 PQdiNymKhdzt4GKUh5G1TZ77d6vlyWoydVY4jj+w+wS+uYVZBRZwqwVIL3G+sEaVZThWS06wqGW5
 Cz0hZH9LKgLDMlzxJsTljgK4WkNOYdB4yHRItWXZ0C6Z8kxy17rzskqqyOXZKjOe8twLpp9qlq31
 qFVSPxLV21D8llXf1hRQaTbSBmPBtDHfLrhKBvuFI4OBDD2FqqJzn1q/2QtbAcM7NAr5AQ1T/rEM
 80xma85oPRUPdpHH3mEVVM35DaTtJnzM7+/1in9ZpXpteMq1Q2xFO4PEa96mbkazUZeDef0AEQEA
 AbQhVG9kZEBrYWRyaWUubmV0IDx0b2RkQGthZHJpZS5uZXQ+iQGwBBMBCgAaBAsJCAcCFQoCFgEC
 GQEFgmJDpsgCngECmwMACgkQiJXYdsDmuqw81wv/Rhy0IhuqtsHL4UjnT3yAzmcx18mRBT6odss1
 wFro+dzyiDZLt4DFmL+WYDCSDS0icYeXXhINM0tSaSpWT7NKsHZ3dv1MGqdwfOvq87Xvw8utgiaf
 EiVkVpLdh6wJHGJLIpR9XHTRweqx9kBznTzup6Bjhp3/NgQaTyyNzVIaTNPoa0t9voZvIse8OuUY
 PEG5CFc5msOWtVZzn8Z1Ol0a8cNf1fDWkAdBE3dRvxtD6OpshpnRtS/o4CUMoZX6ZS01Tn15TK5T
 VnmxhaRAYkmODalZxELbaxxxxxxxxxxxxx/xxxxxxxxxOGCtu639OKA6o0CoKNGXPth3VmohsLkZ
 kUI/6IMPc7fhpj8Od81hBMSsG9EOEaTsiPYXvbnN6b8B8sIPb3Op/33Bm7US08V4tAyzMKLL2KNg
 lXXr1N565YkbeaMA52wFyvzPbS/zjlraITZ2al1O6WSkb3A2Y4ha35hUkFYBNxDO2qlYENnT8kkI
 JgZpN6zJzUe8ZQ+PIrFJuQGNBGJDpsgBDADLzyYquLjGWdb3QPSNLvwiioH1+aLp9Sj+Lo2VXXbh
 +q07gDg7gyKWMX7KfGKDbmlQ5U3V+UDD6h0ZO70UznDu1jnM6npvgxrkZNwvZEQL8SzWYLLSY2vm
 hPG8VWjo4vGnr7BBGa6K4piiXYEJi/FEoWrdRoGKiCDyPU3WnewLI9glgP6IEoTyBtW8bLG7Gphp
 EPkge5oVciQpdeo1zH/olfhiH3kxmQA+sTgQaQQjWfyynBNi/VnUqu448Kn2pUoue57BzWbmG1cY
 jo36POHtLkG1G9M+QLsTxV9IsbUasqYSP9Nb3jlugeXpifBVaW05F9yAFvf7qOJQcGWFsYWUXgXO
 kiiWiIxQa808smPNZE/2PCsNUH6gqb5tzOQpqRYgPzQ1JjgQQl/TZetIJ1VW4O0+xAS5Gp4kK5kq
 d2MNHFCZHPI5Vg+p3PT3jywjZe7kPLbeFDTeiINt7JEU2x4lEKKTe3tVoh8GRWEQySr01P7EHCiI
 kRjSzNlRoqUnb80AEQEAAYkBnwQYAQoACQWCYkOmyAKbDAAKCRCIldh2wOa6rKdpC/0QmqWys1b6
 9J69n3UuDPTbr37AbCLPQnn6FOqeDcNUhohB3GcorwErUMJI/WpU+E3f5e4oasxDoeblvlY06WK+
 sgOtxuqxj47Q+KreCU3ooYe8djyA/wiD16qLno7m6LScnd1FEkA42olOyM1ge0LQUuSS5z7KSHU3
 Sy54ljJhaPFjDqx7Q/3rW2pecF1R/ssth1KKhG3VkeHQD9uC3FkeIO5+w2b+nrF2s+cVdO/v3PE9
 1Mz5ayfh3OEf9pXXzIiWL80kWegMCsmohSYIbyslAWbnWltL2riVbfhwnp4kDG5o1tfHQk+gYJAR
 cikfMlFBWQHJLSWbauTQveb1u15oFFkkkZ1Zzwpm5NmGEI2mOIhUD8TngsmJ3q32UMZzqR7b5gQo
 IjO1pc4+1aSZUak7VMGdYcuJl7SltKaixOEwW9FUq2Ovu60MZ1LOGX2QdoKYSOfrfvSZnuQpdxdJ
 XBrYgeM7G2d4tPz/xuW5cRjyzINzR5RvJsSleqhFVKbbzxQ=
X-Authenticated-Id: xxxx@xxxxxx.xxx
Return-Path: xxxx@xxxxxx.xxx
X-MS-Exchange-Organization-ExpirationStartTime: 05 Dec 2024 21:07:09.9059
 (UTC)
X-MS-Exchange-Organization-ExpirationStartTimeReason: OriginalSubmit
X-MS-Exchange-Organization-ExpirationInterval: 1:00:00:00.0000000
X-MS-Exchange-Organization-ExpirationIntervalReason: OriginalSubmit
X-MS-Exchange-Organization-Network-Message-Id:
 9f29b644-9c23-4b7f-fa55-08dd1570c864
X-EOPAttributedMessage: 0
X-EOPTenantAttributedMessage: 549366ae-e80a-44b9-8adc-52d0c29ba08b:0
X-MS-Exchange-Organization-MessageDirectionality: Incoming
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic:
 CH1PEPF0000AD83:EE_|MN2PR04MB6991:EE_|CH0PR04MB8147:EE_
X-MS-Exchange-Organization-AuthSource:
 CH1PEPF0000AD83.namprd04.prod.outlook.com
X-MS-Exchange-Organization-AuthAs: Anonymous
X-MS-Office365-Filtering-Correlation-Id: 9f29b644-9c23-4b7f-fa55-08dd1570c864
X-MS-Exchange-Organization-SCL: 1
X-Microsoft-Antispam: BCL:0;ARA:13230040|8096899003;
X-Forefront-Antispam-Report:
 CIP:123.123.123.123;CTRY:US;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:mail-108-xxxxxx.xxxxxxx.xxx;PTR:mail-108-xxxxxx.xxxxxxx.xxx;CAT:NONE;SFS:(13230040)(8096899003);DIR:INB;
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 05 Dec 2024 21:07:09.8278
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 9f29b644-9c23-4b7f-fa55-08dd1570c864
X-MS-Exchange-CrossTenant-Id: 549366ae-e80a-44b9-8adc-52d0c29ba08b
X-MS-Exchange-CrossTenant-AuthSource:
 CH1PEPF0000AD83.namprd04.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: Internet
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MN2PR04MB6991
X-MS-Exchange-Transport-EndToEndLatency: 00:00:02.0330872
X-MS-Exchange-Processed-By-BccFoldering: 15.20.8230.010
X-Microsoft-Antispam-Mailbox-Delivery:
	ucf:0;jmr:0;auth:0;dest:I;ENG:(910001)(944506478)(944626604)(920097)(930097)(140003);
X-Microsoft-Antispam-Message-Info:
	=?us-ascii?Q?lZHj5tE4CMKO9jgvVglid+/HLKrgiX+4J+hVZrUelUdYMU1qazmsb71of+Dt?=
 =?us-ascii?Q?wBDUMaNY/FjXBB12XyU6IxYt2oMVbwtK62k5LKlMJ4zYdqt5JYzG2h7AHieB?=
 =?us-ascii?Q?uyUvGIl6pPS2ZehfNevEWcaNR10rg5kZN/BD3J4Fvbfka3REUiFG9Kng0kpT?=
 =?us-ascii?Q?08tNnmYtMhKXDAYVjfLxfroCayzLj7f6/mo57N3dVq5EREQIoyZORv7v4eHL?=
 =?us-ascii?Q?DVV+NH/mz5bv4JqUQA3BO0FAjtBoUDiFcytH0WxIXjwKl0sgeF9o3mBEgkyj?=
 =?us-ascii?Q?UcOOboEXdUUVdaKfOnEO0sC+68xfXcyRCjU/qYxITfFne8Ft+kTZeMtgy/WC?=
 =?us-ascii?Q?cqhy9TKeQQTWlef/gEwTHCmhklsenstXfbEKqMGQfCmNvBRLBb5AcZuGJEFu?=
 =?us-ascii?Q?ittAMpW6Zv7zuX00pkGmquBlBg+8T3dHLQdkZfRStcGUJNy/SGK5qOifCYo8?=
 =?us-ascii?Q?JMNZf/C61U1I8YfisPPIey0wDO2oQsL5Za2hdM6GcLZqJXj7lOxt2cWOnvtr?=
 =?us-ascii?Q?k+mOZI7Gn9RpHsa6Ma8A4WMLyrEuujSpSulVQfsexb2fRl77VU47bVVWooC1?=
 =?us-ascii?Q?vlvHDSdwIu17jCdEHv2sM5d20oGoSkGR70drNtF5QIcveFVivyR1e2trrs5j?=
 =?us-ascii?Q?kraiiQBKDW6At8Z0o9bTgD6QREWA1cZmDrjO1N0+xrelBdB6XjyTm2r0Mxhx?=
 =?us-ascii?Q?xt7Wk8spUi2r1Cj1O+rDFTgbwCBQ9tZRfcaI6off4EsZQRPdaC9hv0nXxEOn?=
 =?us-ascii?Q?HYqBnBYQp/T86IzVzGB5w+emPbSM7P9U1xCn8fzdi80+L+QkCU4iXW/LVxKq?=
 =?us-ascii?Q?7bg+UPvk2Q6NpPeQxA2JB5iMwqkr5Grk1gapp6nJv5hlUhWOSmWutqwY1FoL?=
 =?us-ascii?Q?M6cnSbgK1y4ww7ixxxxxxxxxxxxxxxxxxxxxxx5OCVwXZm26rdqkJH3IYG46?=
 =?us-ascii?Q?nWmr9wz2u5kkw8exgsdR7uD/QuvSPuN2TUcaTR2oZDtV1yIMVuUMfBoF+2mb?=
 =?us-ascii?Q?vbO+Q/ri/sWp3tCWElFW+F2C1WV/D9L3JtXqM8MeggmHlqQiLz3kGGCCIcix?=
 =?us-ascii?Q?vB/qvYza1+9xxwKvN6x6twDtwfa+GPSIL8vh9MUHez+q7E3UsTtp8/bIpokL?=
 =?us-ascii?Q?DxHJWieHmdu5VGybG8PBY1BCjCPljy5mxgNpWyeO0ofStpzEvG8qrcO55cXS?=
 =?us-ascii?Q?twtPlnxaPgh9uZ6H+vJYeOIyeL2JGvkysBPwrCqVRz31TqKPzF0VtQAOTiCU?=
 =?us-ascii?Q?Me7qKqhUmkb13H8kxQ2RM3IEHQHPNZQkvTlXxGQH+CpnGEe0VLd/y94HJGQF?=
 =?us-ascii?Q?bfaJZLuvpxWyOhqC9dSxGQRM9/iogrXYiz/K3+Ugf3xzF2W0bQ2aHN6Umzzh?=
 =?us-ascii?Q?KNVxWjzG1gDF4EyGxG03Aw0KFrlkdjDJWZBIC0hX7XKiiae8klb5FBoHNTlS?=
 =?us-ascii?Q?KwUzulwwl7smlEFmTUDuS6MWbp2lRI8aCryD9JcIGbi9cFqg7xaC/0S8zbWv?=
 =?us-ascii?Q?AC1XENqN7ckDZtfgU/YdMFPr5LFx7t3qR9HlI1jns6Nh5ugQiS3zan9hKf3I?=
 =?us-ascii?Q?kpN9ANusl0UmHlWGYm5D4AU01c0Wg3FU4OYZX/VEEy23tG1eFgRlCWfsEnH9?=
 =?us-ascii?Q?6eeaWGZzPjUfNW6R1i7t+9jpyi/MXCCDvzCMSRcXvyQ5kgSFHY3dnmw5XQdo?=
 =?us-ascii?Q?xhUaappTKsND+nD2ONNrktKRgltS1cagM/zmQ4AGkRqOLnKAsIvT6+noWo9F?=
 =?us-ascii?Q?b51KMJal4zkbnk/j+DklDuGs+9qAcA6Yy53ekIT+IxnhkGmwq6cuAab9959A?=
 =?us-ascii?Q?xBLr2MzBvBGva+1TOoMXLrVDKGK1NXagS/uesbkUFUXK8QQKZcGGfAEs?=
"@.Split([Environment]::NewLine) | ?{$_} ;
    #>

        switch ($header.gettype().fullname){
            'System.String'{
                write-verbose '-Header likely herestring: splitting on crlfs & removing empty lines'
                [string[]]$header = $header.Split([Environment]::NewLine)|?{$_} ;  
            } ;
            'System.String[]'{
                write-verbose '-Header is a string array'
            }
            default{
                write-verbose '-Header of unrecognized type, attempting default string processing'
            }
        } ; 
        # sanity test for indents: wo indents you can't unwrap line-spanning headers
        if($header -match '^\s+.*$'){
            write-verbose "indents validated present in header"
        } else { 
            $smsg = "Header provided has *no* indented lines: May result in failure to detect line-wrapped headers!"
            $smsg += "`n(re-run, ensuring that no .trim() or other leading/line removal is being performed on your input text header)" ;
        } ; 


        $ttl = $header |  measure | select -expand count ;  
        $Prcd = 0 ; 
        # pulled PIPELINE_PROCESSINGLOOP
        $ttl = $header |  measure | select -expand count ;             
        $aggHdr = @() ; 
        $hdrSumm = [ordered]@{
            HeaderName=$null ; 
            HeaderValue=$null ; 
            HeaderIndex = $null ; 
        } ;
        foreach($ln in $header){
            $Prcd ++ ; 
            #if($ln -eq 'X-Microsoft-Antispam-Message-Info:'){ 
            if($ln -match '(X-MS-Exchange-Organization-Network-Message-Id:|X-MS-TrafficTypeDiagnostic:|X-MS-Exchange-Organization-AuthSource:|X-Forefront-Antispam-Report:|X-MS-Exchange-CrossTenant-AuthSource:|X-Microsoft-Antispam-Mailbox-Delivery:)'){
                #write-host 'BOO'
                write-verbose "dbg: '$($ln)'" ;
            } ; 
            if($ln -match 'X-Microsoft-Antispam-Message-Info:'){ 
                write-verbose "dbg: '$($ln)'" ;
            } ; 
            if($ln.length -eq 0){
                write-host "skipping empty line #$($Prcd):`n'$($ln)'" ; 
            #}elseif($ln | ?{$_ -match '^\S+'}){  # matches *not* leading with a space+
            #}elseif($ln  -match '^([A-Za-z0-9-]+):\s+(.*)$'){
            }elseif($ln  -match '^([A-Za-z0-9-]+):\s+(.*)$' -OR $ln -match '^([A-Za-z0-9-]+):$((\s)*)$'){
                write-verbose "line is new HeaderName: #$($Prcd):`n'$($ln)'" ; 
                if($hdrSumm.HeaderName){
                    $aggHdr+= [pscustomobject]$hdrSumm ; 
                } ; 
                $hdrSumm = [ordered]@{
                    HeaderName=$null ; 
                    HeaderValue=$null ; 
                    HeaderIndex = $Prcd ; 
                } ;
                #if($null -eq $matches[2]){
                if(-not $matches[2]){
                    write-verbose "(Header has wrapped value, next line): #$($Prcd):`n'$($ln)'" ; 
                    if($matches[1]){
                        $hdrSumm.HeaderName = "$($matches[1]):" ;
                    } else {
                        throw "blank HeaderName header match!" ; 
                    } ; 
                } else { 
                    $hdrSumm.HeaderName = "$($matches[1]):" ;
                    $hdrSumm.HeaderValue += @($matches[2]) ;  
                } ; 
            }elseif($ln  -match '^\s+.*$'){
                # indented HeaderValue continues...
                $hdrSumm.HeaderValue += @($matches[0]) ;  
            } else { 
                write-warning "no match!: #$($Prcd):`n'$($ln)'" ; 
            }
        } ; 
        if($hdrSumm.HeaderValue -ne $aggHdr[-1].HeaderName){
            $aggHdr+= [pscustomobject]$hdrSumm ; 
        } ; 
        $smsg = "Returning $($agghdr|  measure | select -expand count ) summarized Headers to pipeline:$(($aggHdr |out-string).trim())" ; 
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        $aggHdr | write-output  ; 
    } #  # PROC-E
}

#*------^ resolve-SMTPHeader.ps1 ^------


#*------v resolve-SPFMacros.ps1 v------
function resolve-SPFMacros {
    <#
    .SYNOPSIS
    resolve-SPFMacros - Expand macros in provided SPF specification string
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2024-
    FileName    : resolve-SPFMacros
    License     : MIT License
    Copyright   : (c) 2024 Todd Kadrie
    Github      : https://github.com/tostka/verb-XXX
    Tags        : Powershell,SenderID,SPF,DNS,SenderPolicyFramework
    AddedCredit : REFERENCE
    AddedWebsite: URL
    AddedTwitter: URL
    REVISIONS
    * 4:10 PM 12/16/2024 questions about header sources for various tests: went back to RFC source, and dug out the detailed mechaism engring specs. Then worked through pphosted & salesforce macro expansion, 
    added them to expls. 
    * 9:31 AM 12/13/2024 adapted from resolve-SPFMacros, stip it down to just a Macro replace/expansion func, on passed strings (as Macros are expanded to final form, before eval of the subject record against sending Host occurs)
    * 11:05 AM 12/12/2024 ren: test-SPFMacroEgressIPs -> resolve-SPFMacros; 
        revised to permit a fully pre-resolved SPF record input, to skip the inital resolution step
    * 3:06 PM 12/10/2024 port to a verb-network function, REN test-SPFMacroEgressIPs -> test-SPFMacroIPs
    *4:47 PM 6/6/2024 init vers; works for validating the ppthosted record
    .DESCRIPTION
    resolve-SPFMacros - Expand macros in provided SPF specification string

    Ref:
    [dns spf "Modifier" "mechanism" when are macro replaced - Google Search](https://www.google.com/search?q=dns+spf+%22Modifier%22+%22mechanism%22+when+are+macro+replaced)

        #-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        AI Overview
        Learn more
        In a DNS SPF record, macros are replaced immediately before the SPF record is evaluated, meaning that when the receiving mail server looks up the SPF record, the macro variables like "%{i}" (representing the sender's IP address) are substituted with their actual values before any checks against the specified mechanisms are performed. 
        Key points about macro replacement in SPF:

            Dynamic substitution:
            Macros allow for dynamic insertion of contextual information like the sender's IP address or domain name directly into the SPF record.

        Mechanism evaluation:
        Once the macros are replaced, the SPF record is then evaluated based on the specified mechanisms (like "ip4", "mx", "exists") using the substituted values. 
        No separate lookup:
        The macro expansion happens during the initial DNS lookup of the SPF record, so there's no additional DNS query needed to retrieve the macro values.

        Example:
        Code

        v=spf1 include:subdomain.example.com ~all

            Without macros:
            This would simply check if the sending IP address is listed within the "subdomain.example.com" domain's SPF record.
            With macros:
                v=spf1 exists:%{i}.%{v}.arpa._spf.example.com ~all
                Here, "%{i}" would be replaced with the sender's IP address, allowing for a reverse DNS lookup on that specific IP to check if it's allowed to send mail on behalf of "example.com". 
        #-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

        Ref: 
        When a DNS record is stated as:
        IN TXT "v=spf1 include:example.com include:example.org -all"
        "IN" indicates the Internet, eg. the ip address is an internet ip address
        "The CLASS of a record is set to IN (for Internet) for common DNS records involving Internet hostnames, servers, or IP addresses.)"

        [Automating SPF macro management with scripting and APIs: a step-by-step guide - AutoSPF - Automatic SPF flattening](https://autospf.com/blog/automating-spf-macro-management-with-scripting-apis-step-by-step-guide/)
        #-=-=-=-=-=-=-=-=
        Here are the commonly integrated SPF macros–
            %{i}: Represents the IP address of the sender
            %{s}: Represents the sender's email address (the "MAIL FROM" address).
            %{h}: Represents the HELO/EHLO domain of the SMTP server.
            %{d}: Represents the domain of the sender's email address.
            %{p}: Represents the validated domain name of the sender's IP address.
            %{v}: Represents the literal string "in-addr" or "ip6", depending on whether the sender's IP address is IPv4 or IPv6.
            %{l}: Represents the local part of the sender's email address (the part before the "@" symbol).
            %{o}: Represents the domain part of the "MAIL FROM" address (the part after the "@" symbol).
            %{r}: Represents the domain of the recipient.
            %{t}: Represents the current timestamp in Unix time.

        #-=-=-=-=-=-=-=-=

        [RFC 4408 Sender Policy Framework (SPF) for Authorizing Use of Domains in Email, Version 1](https://www.rfc-editor.org/rfc/rfc7208)

        - <Sender> is checked against 1) The HELO Identity (full fqdn from HELO/EHLO greeting sent by client, if enabled on server), 
            or 2) the Mail From:/Envelope-From:/Return-Path:/5321.MailFrom:

        - 3.3.  Multiple Strings in a Single DNS Record
            As defined in [RFC1035], Sections 3.3 and 3.3.14, a single text DNS record can 
            be composed of more than one string.  If a published record contains multiple 
            character-strings, then the record MUST be treated as if those strings are 
            concatenated together without adding spaces.  For example: 

              IN TXT "v=spf1 .... first" "second string..."

            is equivalent to:
              IN TXT "v=spf1 .... firstsecond string..."

            TXT records containing multiple strings are useful in constructing records that would exceed the 255-octet maximum length of a character-string within a single TXT record.            

        - 3.4.  Record Size

            The published SPF record for a given domain name SHOULD remain small enough 
            that the results of a query for it will fit within 512 octets. Otherwise, there 
            is a possibility of exceeding a DNS protocol limit. This UDP limit is defined 
            in [RFC1035], Section 2.3.4, although it was raised by [RFC2671].  Staying 
            below 512 octets ought to prevent older DNS implementations from failing over 
            to TCP and will work with UDP in the absence of EDNS0 [RFC6891] support.  Since 
            the answer size is dependent on many things outside the scope of this document, 
            it is only possible to give this guideline: If the size of the DNS message, the 
            combined length of the DNS name and the text of all the records of a given type 
            is under 450 octets, then DNS answers ought to fit in UDP packets.  Records 
            that are too long to fit in a single UDP packet could be silently ignored by 
            SPF verifiers due to firewall and other issues that interfere with the 
            operation of DNS over TCP or using ENDS0.  

            Note that when computing the sizes for replies to queries of the TXT format, 
            one has to take into account any other TXT records published at the domain name.
             Similarly, the sizes for replies to all queries related to SPF have to 
            be evaluated to fit in a single 512-octet UDP packet (i.e., DNS message size 
            limited to 450 octets). 

        - 4.6.1.  Term Evaluation
            
            o two types of terms: mechanisms (defined in Section 5) and modifiers (defined in Section 6)
            o directive = [ qualifier ] mechanism
            o qualifier = "+" / "-" / "?" / "~"
            o mechanism  = ( all / include / a / mx / ptr / ip4 / ip6 / exists )
                Most mechanisms allow a ":" or "/" character after the name.
                Each mechanism is considered in turn from left to right.  If there are no more mechanisms, the result is the default result as described in Section 4.7.
                When a mechanism is evaluated, one of three things can happen: it can match, not match, or return an exception. 
                If it matches, processing ends and the qualifier value is returned as the 
                result of that record.  If it does not match, processing continues with the 
                next mechanism.  If it returns an exception, mechanism processing ends and the 
                exception value is returned. The possible qualifiers, and the results they 
                cause check_host() to return, are as follows: "+" pass|  "-" fail|  "~" 
                softfail|  "?" neutral|
 
                The qualifier is optional and defaults to "+"

                When a mechanism matches and the qualifier is "-", then a "fail" result 
                is returned and the explanation string is computed as described in Section 6.2. 

            o modifier = redirect / explanation / unknown-modifier
                Modifiers always contain an equals ('=') character immediately after the name, 
                and before any ":" or "/" characters that might be part of the macro-string.  
                Modifiers are not mechanisms.  They do not return match or not-match. Instead, 
                they provide additional information.  Although modifiers do not directly affect 
                the evaluation of the record, the "redirect" modifier has an effect after all 
                the mechanisms have been evaluated.  
            o unknown-modifier = name "=" macro-string
                      ; where name is not any known modifier
            o name = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )

        - 4.6.4.  DNS Lookup Limits
            - The following terms cause DNS queries: the "include", "a", "mx", "ptr", and 
            "exists" mechanisms, and the "redirect" modifier

            - SPF implementations MUST limit the total number of those terms to 10
            during SPF evaluation, to avoid unreasonable load on the DNS

            - the "all", "ip4", and "ip6" mechanisms, and the "exp" modifier -- do 
            not cause DNS queries at the time of SPF evaluation (the "exp" modifier 
            only causes a lookup at a later time), and their use is not subject to 
            this limit. 

            - When evaluating the "mx" mechanism, the number of "MX" resource records queried 
            is included in the overall limit of 10 mechanisms/ modifiers that cause DNS 
            lookups as described above.  In addition to that limit, the evaluation of each 
            "MX" record MUST NOT result in querying more than 10 address records -- either 
            "A" or "AAAA" resource records. If this limit is exceeded, the "mx" mechanism MUST 
            produce a "permerror" result.

            - When evaluating the "ptr" mechanism or the %{p} macro, the number of "PTR" 
            resource records queried is included in the overall limit of 10 
            mechanisms/modifiers that cause DNS lookups as described above.  In addition to 
            that limit, the evaluation of each "PTR" record MUST NOT result in querying 
            more than 10 address records -- either "A" or "AAAA" resource records.  If this 
            limit is exceeded, all records other than the first 10 MUST be ignored. 

            The reason for the disparity is that the set of and contents of the
            MX record are under control of the publishing ADMD, while the set of
            and contents of PTR records are under control of the owner of the IP
            address actually making the connection.

            These limits are per mechanism or macro in the record, and are in
            addition to the lookup limits specified above.

            - MTAs or other processors SHOULD impose a limit on the maximum amount
            of elapsed time to evaluate check_host().  Such a limit SHOULD allow
            at least 20 seconds.  If such a limit is exceeded, the result of
            authorization SHOULD be "temperror".
            
        - 4.8 Domain Specification
            - The <domain-spec> string is subject to macro expansion
            - The resulting string is the common presentation form of 
                a fully qualified DNS name: a series of labels separated by periods.
                This domain is called the <target-name> in the rest of this document.

            - For several mechanisms, the <domain-spec> is optional.  If it is not
            provided, the <domain> from the check_host() arguments (see Section 4.1) 
            is used as the <target-name>.  "domain" and <domain-spec> are syntactically 
            identical after macro expansion.
            "domain" is an input value for check_host(), while <domain-spec> is
            computed by check_host()
        
        - 5.  Mechanism Definitions
            -When any mechanism fetches host addresses to compare with <ip>, 
                o when <ip> is an IPv4, "A" records are fetched;
                o when <ip> is an IPv6 address, "AAAA" records are fetched.  

            - "a" An address lookup is done on the <target-name>/domain-spec/domain using the type of
                lookup (A or AAAA) appropriate for the connection type (IPv4 or
                IPv6).  The <ip> is compared to the returned address(es).  If any
                address matches, the mechanism matches.
            - "mx" performs an MX lookup on the <target-name>/domain-spec/domain 
                Then performs an address lookup on each MX name returned.
                The <ip> is compared to each returned IP address.
                e.g.: resolve domain MX's, then resolve the NameHost of each records 'A' on the Namehost, to the underlying IP Addresses: compare the sending server IP against those IPs
                resolve-dnsname -type 'A' -name (resolve-dnsname -type mx -name toro.com -server 1.1.1.1).NameExchange -server 1.1.1.1 | select -expand ipaddress
                    52.101.194.17
                    52.101.8.44
                    52.101.41.58
                    52.101.42.10
           - "ptr" (do not use)
                The <ip>'s name is looked up using this procedure:
                o  Perform a DNS reverse-mapping for <ip>: 
                        Look up the corresponding PTR record in "in-addr.arpa." if the address is an IPv4 address and in "ip6.arpa." if it is an IPv6 address.
                o  For each record returned, validate the domain name by looking up its IP addresses.  
                o  If <ip> is among the returned IP addresses, then that domain name is validated.
                e.g: Resolve the sender server IP to the PTR, then resolve the A record for the prior's Namehost, back to it's IP address, and compare senderserver IP to the IP from trhe expansions
                resolve-dnsname -name (resolve-dnsname -type ptr -name 170.92.7.36 -server 1.1.1.1).namehost -type A -server 1.1.1.1 | select -expand ipaddress
                    170.92.7.36
            - "ip4" and "ip6" 
                The <ip> is compared to the given network.  If CIDR prefix length high-order bits match, the mechanism matches.
                If ip4-cidr-length is omitted - only an IP is listed - it is taken to be "/32".  If ip6-cidr-length is omitted - only an ip6 IP is listed - it is taken to be "/128".  
                    e.g. go ahead and append /32 & /128 to single IPs in ip4 & ip6 entries
            - "exists" This mechanism is used to construct an arbitrary domain name that is 
                used for a DNS A record query.  It allows for complicated schemes involving 
                arbitrary parts of the mail envelope to determine what is permitted. 
                The <domain-spec> is expanded as per above (including macros etc).  
                The resulting domain name is used for a DNS A RR lookup - == resolve the A record to the IP - (even when the connection type is IPv6).  
                If any A record is returned, this mechanism matches.
                Domains can use this mechanism to specify arbitrarily complex queries.  For example, suppose example.com publishes the record:
                    v=spf1 exists:%{ir}.%{l1r+-}._spf.%{d} -all

                The <target-name> might expand to
                    "1.2.0.192.someuser._spf.example.com".  
                This makes fine-grained decisions possible at the level of the user and client IP address.


    This is specifically tuned to resolve & lookup dynamic per-host DNS records, over validating standard include or other records
    .PARAMETER SpfRecord
    Optional Pre-resolved SpfRecord specification string to be evaluated (skips initial resolution pass; used to recycle from Resolve-SPFRecord() call[-SpfRecord `$spfRec]
    .PARAMETER IPAddress
    Sending server IP Address to be tested against the domain SPF record[-IPAddress 192.168.1.1]
    .PARAMETER DomainName
    DomainName for which SPF records should be retrieved and tested against[-DomainName domain.com]
    .PARAMETER SenderAddress
    Optional SenderAddress to use for '%{d}','%{s}','%{s}','%{o}' SenderAddress based macros[-SenderAddress email@domain.tld]
    .PARAMETER SenderHeloName
    Optional Sending server HELO name, to use for '%{h}' macro substitution [-SenderHeloName SERVER.DOMAIN.TLD]
    .INPUTS
    None. Does not accepted piped input.(.NET types, can add description)
    .OUTPUTS
    None. Returns no objects or output (.NET types)
    System.Boolean
    [| get-member the output to see what .NET obj TypeName is returned, to use here]
    .EXAMPLE
    PS> $spfspec = Resolve-DnsName -name _spf.salesforce.com -server 1.1.1.1 -type TXT | ? strings -match '^v=spf1' | select -expand strings ; 
    PS> $spfspec ; 

        v=spf1 exists:%{i}._spf.mta.salesforce.com -all

    PS> $resolvedSPFString = resolve-SPFMacros -SpfRecord $spfspec -IPAddress 52.88.39.26 -DomainName salesforce.com -SenderAddress PartsClaims@toro.com

        VERBOSE: 15:50:48:===> Specified $SpfRecord:
        v=spf1 exists:%{i}._spf.mta.salesforce.com -all
        has been resolved to:
        v=spf1 exists:52.88.39.26._spf.mta.salesforce.com -all
        (sending to pipeline)

    PS> $resolvedSPFString  ; 

        v=spf1 exists:52.88.39.26._spf.mta.salesforce.com -all

    PS> write-verbose "Resolve the include:36.7.92.170.in-addr.toro.com.spf.has.pphosted.com name to A record" ; 
    PS> resolve-dnsname -name ($resolvedSPFString.split(' ') | ?{$_ -match 'exists:'}).replace('exists:','') -type A -server 1.1.1.1 ; 

        Name                                           Type   TTL   Section    IPAddress                                
        ----                                           ----   ---   -------    ---------                                
        52.88.39.26._spf.mta.salesforce.com            A      3600  Answer     52.88.39.26            

    PS> write-verbose "A matching A record was returned for the macro expanded name => the SPF lookup passes.
    Demo retrieving an SPF record, expanding macros present, and then re-resolving the updated include: hostname to an existing A record (which therefore passes the SPF test).
    .EXAMPLE
    PS> $spfspec = resolve-dnsname -name toro.com -type TXT -server 1.1.1.1 | ? strings -match 'spf' | select -expand strings
    PS> $spfspec ; 

        v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com ~all

    PS> $resolvedSPFString = resolve-SPFMacros -SpfRecord $spfspec -IPAddress 170.92.7.36 -DomainName toro.com -SenderAddress PartsClaims@toro.com -SenderHeloName mymailoutlyn0.toro.com -verbose ;

        VERBOSE: 15:50:48:===> Specified $SpfRecord:
        v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com ~all
        has been resolved to:
        v=spf1 include:36.7.92.170.in-addr.toro.com.spf.has.pphosted.com ~all
        (sending to pipeline)

    PS> $resolvedSPFString  ; 

        v=spf1 include:36.7.92.170.in-addr.toro.com.spf.has.pphosted.com ~all

    PS> write-verbose "Resolve the include:36.7.92.170.in-addr.toro.com.spf.has.pphosted.com name to A record" ; 
    PS> resolve-dnsname -name ($xpanded.split(' ') | ?{$_ -match 'include:'}).replace('include:','') -type A -server 1.1.1.1

        Name                                           Type   TTL   Section    IPAddress                                
        ----                                           ----   ---   -------    ---------                                
        36.7.92.170.in-addr.toro.com.spf.has.pphosted. A      3600  Answer     127.0.0.2                                
        com        

    PS> write-verbose "A matching A record was returned for the macro expanded name => the SPF lookup passes.
    Demo retrieving an SPF record (in this case utilizes the include: mechanism), expanding macros present, and then re-resolving the updated include: hostname to an existing A record (which therefore passes the SPF test).
    
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://bitbucket.org/tostka/powershell/
    .LINK
    [ name related topic(one keyword per topic), or http://|https:// to help, or add the name of 'paired' funcs in the same niche (enable/disable-xxx)]
    #>
    <#List of Eggress IP addresses to resolve against SPF macro settings
    IPAddress
    DomainName to be tested for SPF validity
    DomainName
    #>
    #[Alias('ConvertTo-CanonicalName')]
    PARAM(
        [Parameter(Mandatory=$True,HelpMessage="Optional Pre-resolved SpfRecord specification string to be evaluated (skips initial resolution pass; used to recycle from Resolve-SPFRecord() call[-SpfRecord `$spfRec]")]
            <# 8:58 AM 12/13/2024 prob don't have to eval the v=spf for full spf compliance - not this func''s role, and it may be handling substrings of a full spf, so just sub through the sent text and send updated back
            [ValidateScript({
                ($_ -is [string])
                if($_ -match '^v=spf'){$true}else{
                    throw "specified SPF Record does not have a leading '^v=spf' string`nensure you are passing the expanded SPF specification, and not the entire retrieved DNS record" ; 
                } ; 
            })]
            #>
            #[string]
            [string[]]$SpfRecord, # make it an array to accomodate stacked strings, and crlf-split herestrings
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="Sending server IP Address(es) to be tested for '%{i}','%{ir}','%{v}','%{p}' IP-based macros in the DomainName SPF record[-IPAddress '192.168.1.1','192.168.1.2']")]
            #[ValidateNotNullOrEmpty()]
            #[Alias('ALIAS1', 'ALIAS2')]
            #[string[]]
            #if doing a single submitting server eval, this should be a single ip string, better, [system.net.ipaddress]
            [system.net.ipaddress]$IPAddress, # =  @($Tormeta.OP_ExEgressIPs + $CMWMeta.OP_ExEgressIPs) ,
        [Parameter(Mandatory=$True,HelpMessage="DomainName for which SPF records should be retrieved and tested against[-DomainName DOMAIN.COM]")]
            [ValidateNotNullOrEmpty()]
            [Alias('Domain','Name')]
            [string]$DomainName,
        [Parameter(Mandatory=$True,HelpMessage="Required SenderAddress to use for '%{d}','%{s}','%{l}','%{o}' SenderAddress based macros[-SenderAddress EMAIL@DOMAIN.TLD]")]
            [ValidateNotNullOrEmpty()]
            #[Alias('ALIAS1', 'ALIAS2')]
            [string]$SenderAddress,
        [Parameter(Mandatory=$false,HelpMessage="Optional Sending server HELO name, to use for '%{h}' macro substitution [-SenderHeloName SERVER.DOMAIN.TLD]")]
            [ValidateNotNullOrEmpty()]
            #[Alias('ALIAS1', 'ALIAS2')]
            [string]$SenderHeloName
    ) ; 
    BEGIN { 
        #region CONSTANTS_AND_ENVIRO #*======v CONSTANTS_AND_ENVIRO v======
        #region ENVIRO_DISCOVER ; #*------v ENVIRO_DISCOVER v------
        $Verbose = ($VerbosePreference -eq 'Continue') ; 
        # Debugger:proxy automatic variables that aren't directly accessible when debugging (must be assigned and read back from another vari) ; 
        $rPSCmdlet = $PSCmdlet ; 
        ${CmdletName} = $rPSCmdlet.MyInvocation.MyCommand.Name ; # function self-name (equiv to script's: $MyInvocation.MyCommand.Path) ;
            #region PsParams ; #*------v PsParams v------
        $PSParameters = New-Object -TypeName PSObject -Property $rPSBoundParameters ;
        write-verbose "`$rPSBoundParameters:`n$(($rPSBoundParameters|out-string).trim())" ;
        # pre psv2, no $rPSBoundParameters autovari to check, so back them out:
        if($rPSCmdlet.MyInvocation.InvocationName){
            if($rPSCmdlet.MyInvocation.InvocationName  -match '^\.'){
                $smsg = "detected dot-sourced invocation: Skipping `$PSCmdlet.MyInvocation.InvocationName-tied cmds..." ; 
                if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
            } else { 
                write-verbose 'Collect all non-default Params (works back to psv2 w CmdletBinding)'
                $ParamsNonDefault = (Get-Command $rPSCmdlet.MyInvocation.InvocationName).parameters | Select-Object -expand keys | Where-Object{$_ -notmatch '(Verbose|Debug|ErrorAction|WarningAction|ErrorVariable|WarningVariable|OutVariable|OutBuffer)'} ;
            } ; 
        } else { 
            $smsg = "(blank `$rPSCmdlet.MyInvocation.InvocationName, skipping Parameters collection)" ; 
            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
        } ; 
        #endregion PsParams ; #*------^ END PsParams ^------
        #endregion ENVIRO_DISCOVER ; #*------^ END ENVIRO_DISCOVER ^------
        #region COMMON_CONSTANTS ; #*------v COMMON_CONSTANTS v------
    
        if(-not $DoRetries){$DoRetries = 4 } ;    # # times to repeat retry attempts
        if(-not $RetrySleep){$RetrySleep = 10 } ; # wait time between retries
        if(-not $RetrySleep){$DawdleWait = 30 } ; # wait time (secs) between dawdle checks
        if(-not $DirSyncInterval){$DirSyncInterval = 30 } ; # AADConnect dirsync interval
        if(-not $ThrottleMs){$ThrottleMs = 50 ;}
        if(-not $rgxDriveBanChars){$rgxDriveBanChars = '[;~/\\\.:]' ; } ; # ;~/\.:,
        if(-not $rgxCertThumbprint){$rgxCertThumbprint = '[0-9a-fA-F]{40}' } ; # if it's a 40char hex string -> cert thumbprint  
        if(-not $rgxSmtpAddr){$rgxSmtpAddr = "^([0-9a-zA-Z]+[-._+&'])*[0-9a-zA-Z]+@([-0-9a-zA-Z]+[.])+[a-zA-Z]{2,63}$" ; } ; # email addr/UPN
        if(-not $rgxDomainLogon){$rgxDomainLogon = '^[a-zA-Z][a-zA-Z0-9\-\.]{0,61}[a-zA-Z]\\\w[\w\.\- ]+$' } ; # DOMAIN\samaccountname 
        if(-not $exoMbxGraceDays){$exoMbxGraceDays = 30} ; 
        if(-not $XOConnectionUri ){$XOConnectionUri = 'https://outlook.office365.com'} ; 
        if(-not $SCConnectionUri){$SCConnectionUri = 'https://ps.compliance.protection.outlook.com'} ; 

        #region LOCAL_CONSTANTS ; #*------v LOCAL_CONSTANTS v------

        #endregion LOCAL_CONSTANTS ; #*------^ END LOCAL_CONSTANTS ^------  
        #endregion CONSTANTS_AND_ENVIRO ; #*------^ END CONSTANTS_AND_ENVIRO ^------

        #endregion CONSTANTS_AND_ENVIRO ; #*------^ END CONSTANTS_AND_ENVIRO ^------

        #region FUNCTIONS ; #*======v FUNCTIONS v======

        #endregion FUNCTIONS ; #*======^ END FUNCTIONS ^======

        #region BANNER ; #*------v BANNER v------
        $sBnr="#*======v $(${CmdletName}): v======" ;
        $smsg = $sBnr ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H1 } #Error|Warn|Debug
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        #endregion BANNER ; #*------^ END BANNER ^------

        # check if using Pipeline input or explicit params:
        if ($rPSCmdlet.MyInvocation.ExpectingInput) {
            $smsg = "Data received from pipeline input: '$($InputObject)'" ;
            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
        } else {
            # doesn't actually return an obj in the echo
            #$smsg = "Data received from parameter input: '$($InputObject)'" ;
            #if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
            #else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
        } ;

        if(-not $IPAddress){
            throw "Empty `!: (should contain `$Tormeta.OP_ExEgressIPs,`$CMWMeta.OP_ExEgressIPs)" ; 
            break ; 
        } else {
            #$IPAddress = $IPAddress | select -unique ; 
    
            $smsg = "`n`n==Processing:`$IPAddress:`n$(($IPAddress.IPAddressToString|out-string).trim())" ; 
            $smsg += "`nagainst DomainName: $($DomainName)`n`n" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

        } ;  ;
        if($SpfRecord){
            $smsg = "-SpfRecord specified: Using passed spf specification string" ; 
            $smsg = "`n$(($SpfRecord|out-string).trim())" ; 
            write-host -foregroundcolor yellow $smsg ; 
            $SpfRec = $SpfRecord ; 
        }else {
            #write-verbose "Resolve DNS SPF record: resolve-dnsname -name $($DomainName) -type TXT -server 1.1.1.1" ; 
            #$SpfRec = resolve-dnsname -name $DomainName -type TXT -server 1.1.1.1  -ea STOP| ? strings  -match '^v=spf' | select -expand strings ; 
            $smsg = "Missing REQUIRED -SpfRecord spec!" ; 
            throw $smsg ;
        } ; 

        #write-host -foregroundcolor green "Resolved $($DomainName) SPF strings:`n$(($SpfRec|out-string).trim())" ; 

        # check for macros syntax in spf record
        if($SpfRec -notmatch '%\{[slodipvh]}' ){
            #$smsg = "DomainName:$($DomainName) retrieved SPF record" ; 
            $smsg = "Provided SPF record (or substring)" ; 
            $smsg +="`nDOES NOT USE ANY SPF MACROS that act against dynamic per-host records" ; 
            $smsg +="`nThis script does not apply to this domain. ABORTING" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
            Break; 
        } ; 
        # $IPAddress
        if($SpfRec -match '%\{[ivp]}'){
            if(-not $IPAddress){
                $smsg = "SPF Record specified:" 
                $smsg += "`n$(($SpfRecord|out-string).trim())" ; 
                $smsg += "Includes IPAddress-dependant Macros '%{i}','%{ir}','%{v}','%{p}'" ; 
                $smsg += "`n but *no* `$IPAddress has been specified!" ; 
                $smsg += "`nPlease retry with a suitable `$IPAddress specification"
                throw $smsg ; 
                BREAK ; 
            } else{
                write-verbose  "SPF Record specified:Includes IPAddress-dependant Macros '%{i}','%{ir}','%{v}','%{p}', and an `$IPAddress has been specified ($($IPAddress.IPAddressToString))" ; 
            } ; 
        }; 
        # $SenderAddress
        if($SpfRec -match '%\{[dslo]}'){
            if(-not $SenderAddress){
                $smsg = "SPF Record specified:" 
                $smsg += "`n$(($SenderAddress|out-string).trim())" ; 
                $smsg += "Includes SenderAddress-dependant Macros '%{d}','%{s}','%{l}','%{o}'" ; 
                $smsg += "`n but *no* `$SenderAddress has been specified!" ; 
                $smsg += "`nPlease retry with a suitable `$SenderAddress specification"
                throw $smsg ; 
                BREAK ; 
            } else{
                write-verbose  "SPF Record specified:Includes SenderAddress-dependant Macros '%{d}','%{s}','%{l}','%{o}', and an `$SenderAddress has been specified ($($SenderAddress))" ; 
            } ; 
        }; 
        # $SenderHeloName
        if($SpfRec -match '%\{[h]}'){
            if(-not $IPAddress){
                $smsg = "SPF Record specified:" 
                $smsg += "`n$(($SenderAddress|out-string).trim())" ; 
                $smsg += "Includes Sender Server HELO name dependant Macro '%{h}'" ; 
                $smsg += "`n but *no* `$SenderHeloName has been specified!" ; 
                $smsg += "`nPlease retry with a suitable `$SenderHeloName specification"
                throw $smsg ; 
                BREAK ; 
            } else{
                write-verbose  "SPF Record specified:Includes Sender Server HELO name dependant Macro '%{h}', and a `$SenderHeloName has been specified ($($SenderHeloName))" ;
            } ; 
        }; 
    } ;  # BEGIN-E
    PROCESS {
        #Foreach($Computer in $IPAddress[-1] ){
        Foreach($Computer in $IPAddress.IPAddressToString ){
            $sBnrS="`n#*------v PROCESSING $($Computer): v------" ; 
            write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($sBnrS)" ;
            #region Resolve_Information ; #*------v Resolve_Information v------
            $isIPv4 = $isIPv6 = $isFQDN = $isNBName = $false ; 
            TRY{if(([ipaddress]$Computer).AddressFamily -eq 'InterNetwork'){ $isIpv4 = $true  } ; } CATCH {} ; 
            TRY{if(([ipaddress]$Computer).AddressFamily -eq 'InterNetworkV6'){ $isIPv6 = $true  } ; } CATCH {} ; 
            if( -not ($isIPv4 -OR $isIPv6) -AND (6 -le $Computer.length -le 253) -AND ($Computer -match '^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$') ){
                $isFQDN = $true ; 
            }  ;
            <#[ValidateLength(1, 15)]
            [ValidateScript({$PSItem -replace '\\|/|:|\*|\?|"||\||\.' -eq $PSItem})]
            #>
            if( -not ($isIPv4 -OR $isIPv6) -AND  (1 -le $Computer.length -le 15) -AND ($Computer -replace '\\|/|:|\*|\?|"||\||\.' -eq $Computer) ){
                $isNBName = $true ; 
            }  ;
            #$Computer = 'NAME.SUB.DOMAIN.com' ; 
            #$SenderAddress = 'SENDER@DOMAIN.com' ; 
            TRY{
                $cachedName = $null ; 
                $cachedName = $Computer ; 
                if($isIPv4 -OR $isIPv6){
                    write-verbose "Resolve IP to FQDN (PTR): `nresolve-dnsname -name $($Computer) -type PTR -ea STOP -server 1.1.1.1 | select -expand namehost" ; 
                    $Computer = resolve-dnsname -name $Computer -type PTR -ea STOP -server 1.1.1.1 | select -expand namehost; 
                } ; 
                if($isNBName){
                    write-verbose "Resolve NBName to FQDN (A): `nresolve-dnsname -name $($Computer) -type A -ea STOP -server 1.1.1.1 | select -expand Name" ; 
                    $Computer = resolve-dnsname -name $Computer -type A -ea STOP -server 1.1.1.1 | select -expand Name
                } ; 
            
                write-verbose "Resolve IP A Record: resolve-dnsname -name $($Computer) -type A: `nresolve-dnsname -name $($Computer) -type A  -ea STOP | select -first 1 " ; 
                TRY{
                    $ComputerARec = resolve-dnsname -name $Computer -type A  -ea STOP -server 1.1.1.1 | select -first 1  ; 
                    write-host -foregroundcolor green "Resolved $($Computer) A Record:`n$(($ComputerARec|out-string).trim())" ; 
                    $SendIP = $ComputerARec.IPAddress ; 
                    write-verbose "`$SendIP: $($SendIP)" ; 
                }CATCH{
                    $smsg = "Failed to:resolve-dnsname -name $($Computer) -type A " ; 
                    $smsg += "`nFalling back to original cached identifier: $($cachedName)" ; 
                    $smsg += "`n and reattempting resolution of that value" ; 
                    write-warning $smsg ; 
                    $Computer = $cachedName  ; 
                    if($isIPv4 -OR $isIPv6){$SendIP = $cachedName} ; 
                    # if non IPv4 or IPv6 and computer length is 6-253 chars, and is an fqdn, resolve fqdn to IPaddress
                    if( -not ($isIPv4 -OR $isIPv6) -AND (6 -le $Computer.length -le 253) -AND ($Computer -match '^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$') ){
                        write-verbose "resolve-dnsname -name $($Computer) -server 1.1.1.1 | select -first 1 | select -expand IPAddress" ; 
                        $SendIP = resolve-dnsname -name $Computer -ea stop -server 1.1.1.1 | select -first 1 | select -expand IPAddress
                    }  ;
                    # if non IPv4 or IPv6 and computer length is 1-15 chars, and is an nbname matching the input $IPAddress (computer), resolve the name to IPAddress
                    if( -not ($isIPv4 -OR $isIPv6) -AND  (1 -le $Computer.length -le 15) -AND ($Computer -replace '\\|/|:|\*|\?|"||\||\.' -eq $Computer) ){
                        write-verbose "resolve-dnsname -name $($Computer) -ea stop | select -first 1 | select -expand IPAddress" ; 
                        $SendIP = resolve-dnsname -name $Computer -ea stop -server 1.1.1.1 | select -first 1 | select -expand IPAddress
                    }  ;
                    write-verbose "`$SendIP: $($SendIP)" ; 
                } ; 
        
                #endregion Resolve_Information ; #*------^ END Resolve_Information ^------
                #region Macro_Expansion  ; #*------v Macro_Expansion v------
                $StepNo = 0 ; 

                #if($SpfRec -match '%\{[dslo]}'){
                if($SpfRec -match '%\{[i]}'){
                    write-verbose "$($StepNo++; $StepNo). Replace %{i} with with sender IP" ; 
                    #$SpfRec = $SpfRec
                    $SpfRec = $SpfRec.replace('%{i}',$SendIP) ; 
                } 
                if($SpfRec -match '%\{ir}'){
                    write-verbose "$($StepNo++; $StepNo). reverse the SendBox IP" ; 
                    $SendPTR = resolve-dnsname -name $SendIP -type PTR  -ea STOP -server 1.1.1.1 ; 
                    $SendIPRev = (($SendPTR | select -expand name) -split '.in-addr.')[0] ; 
                    write-verbose "$($StepNo++; $StepNo). Replace %{ir} with with reversed sender IP" ; 
                    #$SpfRecResolved = $SpfRec.replace('%{ir}',$SendIPRev) ; 
                    $SpfRec = $SpfRec.replace('%{ir}',$SendIPRev) ; 
                } ; 

                if($SpfRec -match '%\{v}'){
                    write-verbose "$($StepNo++; $StepNo). Replace %{v} with with sender IP version" ; 
                    switch(([ipaddress]$sendip).addressfamily){
                      'InterNetwork' { 
                          write-verbose "$($StepNo++; $StepNo). Replace %{v} with with in-addr for ipv4 IP" ; 
                          $SpfRec = $SpfRec.replace('%{v}','in-addr') 
                      }
                      'InterNetworkV6' {
                          write-verbose "$($StepNo++; $StepNo). Replace %{v} with with ip6 for ipv6 IP" ; 
                          $SpfRec = $SpfRec.replace('%{v}','ip6')
                      }
                    };
                } ; 

                #SenderAddress: '%{d}','%{s}','%{s}','%{o}'
                #'%\{d}','%\{s}','%\{s}','%\{o}' :::  '%\{[dslo]}'

                if($SpfRec -match '%\{d}' ){
                    write-host -foregroundcolor gray "Note: SPF Record conains SenderAddress-related Macros:`n$($SpfRec)" ; 
                    write-verbose "$($StepNo++; $StepNo). Replace %{d} with SPF sender domain" ; 
                    if(-not $SenderAddress -AND $DomainName){
                        write-verbose "$($StepNo++; $StepNo). Replace %{d} with SPF sender DomainName" ; 
                        $SpfRec = $SpfRec.replace('%{d}',$DomainName) ; 
                    } elseif($SenderAddress){
                        write-verbose "$($StepNo++; $StepNo). Replace %{d} with SPF split SenderAddress Domain" ; 
                        $SpfRec = $SpfRec.replace('%{d}',($SenderAddress.split('@')[1])) ; 
                    } ; 
                } ; 

                #if($SpfRec -match '%\{[dslo]}' ){
                if($SpfRec -match '%\{[slo]}' ){
                    write-warning "SPF Record conains SenderAddress-related Macros:`n$($SpfRec)" ; 
                    if(-not $SenderAddress){
                        $smsg = "$($StepNo++; $StepNo). WARN! No -SenderAddress specified from which to calculate SenderAddres macros!" ; 
                        write-warning $smsg ; 
                        throw $smsg ; 
                        break ; 
                    } else {
                        write-verbose "$($StepNo++; $StepNo). Replace %{s} with with sender address" ; 
                        $SpfRec = $SpfRec.replace('%{s}',$SenderAddress) ; 
                        write-verbose "$($StepNo++; $StepNo). Replace %{l} with with SenderAddress local part" ; 
                        $SpfRec = $SpfRec.replace('%{l}',$SenderAddress.split('@')[0]) ; 
                        write-verbose "$($StepNo++; $StepNo). Replace %{o} with with sender domain" ; 
                        $SpfRec = $SpfRec.replace('%{o}',$SenderAddress.split('@')[1]) ; 
                    } ; 
                } ; 

                if($SpfRec -match '%\{p}'){
                    <# 	%{p}: The validated reverse-DNS domain of the source IP, 
                        e.g. if example.com IN A is 203.0.113.1 and 1.113.0.203.in-addr.arpa IN PTR is example.com, 
                        the validated domain will be example.com.
                        if 170.92.7.36, sending server IP, resolves as -PTR -> 36.7.92.170.in-addr.arpa

                        [Automating SPF macro management with scripting and APIs: a step-by-step guide - AutoSPF - Automatic SPF flattening](https://autospf.com/blog/automating-spf-macro-management-with-scripting-apis-step-by-step-guide/)
                        %{p}: Represents the validated domain name of the sender’s IP address.

                    #>
                    #throw "$($StepNo++; $StepNo). $(SpfRec) contains the %{p} macro (replace HELO name from last conn)`ncannot emulate that state in a vacuum" ; 
                    #break ; 
                    # $SenderHeloName             
                    <#$smsg = "SPF Record specified:" 
                    $smsg += "`n$(($SenderAddress|out-string).trim())" ; 
                    $smsg += "Includes Sender Server HELO name dependant Macro '%{p}'" ; 
                    $smsg += "`n but *no* `$SenderHeloName has been specified!" ; 
                    $smsg += "`nPlease retry with a suitable `$SenderHeloName specification"       
                    #>
                    write-warning "SPF Record conains Sender Server HELO name dependant Macro '%{p}':`n$($SpfRec)" ; 
                    write-verbose "$($StepNo++; $StepNo). Replace %{p} with SPF sender domain" ; 
                    $SpfRec = $SpfRec.replace('%{p}',(($sendptr.namehost.split('.') | select -skip 1 ) -join '.')) ; 
                    if(-not $SenderHeloName){
                        $smsg = "$($StepNo++; $StepNo). WARN! No -SenderHeloName specified from which to replace %{p} macros!" ; 
                        write-warning $smsg ; 
                        throw $smsg ; 
                        break ; 
                    } ; 
                } ; 
                
                if($SpfRec -match '%\{h}'){
                    #throw "$($StepNo++; $StepNo). $(SpfRec) contains the %{h} macro (replace HELO name from last conn)`ncannot emulate that state in a vacuum" ; 
                    #break ; 
                    # $SenderHeloName             
                    <#$smsg = "SPF Record specified:" 
                    $smsg += "`n$(($SenderAddress|out-string).trim())" ; 
                    $smsg += "Includes Sender Server HELO name dependant Macro '%{h}'" ; 
                    $smsg += "`n but *no* `$SenderHeloName has been specified!" ; 
                    $smsg += "`nPlease retry with a suitable `$SenderHeloName specification"       
                    #>
                    write-warning "SPF Record conains Sender Server HELO name dependant Macro '%{h}':`n$($SpfRec)" ; 
                    write-verbose "$($StepNo++; $StepNo). Replace %{h} with SPF sender domain" ; 
                    $SpfRec = $SpfRec.replace('%{h}',$SenderHeloName) ; 
                    if(-not $SenderHeloName){
                        $smsg = "$($StepNo++; $StepNo). WARN! No -SenderHeloName specified from which to replace %{h} macros!" ; 
                        write-warning $smsg ; 
                        throw $smsg ; 
                        break ; 
                    } ; 
                } ; 

                $smsg = "===> Specified `$SpfRecord:" ; 
                $smsg += "`n$(($SpfRecord|out-string).trim())" ; 
                $smsg += "`nhas been resolved to:"
                $smsg += "`n$(($SpfRec|out-string).trim())" ; 
                $smsg += "`n(sending to pipeline)" ; 
                if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 

                $SpfRec | write-output ;

            } CATCH {
                $ErrTrapd=$Error[0] ;
                $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;
                write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" ;
            } ; 
            write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($sBnrS.replace('-v','-^').replace('v-','^-'))`n" ;
        } ;  # loop-E
    }  # PROC-E
    END{
        $smsg = "$($sBnr.replace('=v','=^').replace('v=','^='))" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level H1 } #Error|Warn|Debug
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        $stopResults = try {Stop-transcript -ErrorAction stop} catch {} ;
        if($stopResults){
            $smsg = "Stop-transcript:$($stopResults)" ; 
            # Opt:verbose
            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
            # # Opt:pswlt
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
        } ; 
    } ;
}

#*------^ resolve-SPFMacros.ps1 ^------


#*------v resolve-SPFMacrosTDO.ps1 v------
function resolve-SPFMacrosTDO {
    <#
    .SYNOPSIS
    resolve-SPFMacrosTDO - Expand macros in provided SPF specification string
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2024-
    FileName    : resolve-SPFMacrosTDO
    License     : MIT License
    Copyright   : (c) 2024 Todd Kadrie
    Github      : https://github.com/tostka/verb-XXX
    Tags        : Powershell,SenderID,SPF,DNS,SenderPolicyFramework
    AddedCredit : REFERENCE
    AddedWebsite: URL
    AddedTwitter: URL
    REVISIONS
    * 4:33 PM 1/2/2025
        recoded & expanded convert-IPAddressToReverseTDO, to support ipv6 reversal; 
         $DomainName/Name update $Name/Domainname regex to make the CN portion optional (fails toro.com, but has to accomodate recursive include:calls to resolve _spf.salesforce.com)
             add: %{t}: Represents the current timestamp in Unix time.
    * 2:11 PM 12/31/2024 moved IP transformations up above macro loop - only gets done once per IPAddress (and only supports one SenderIP for expansions);  moved the IP DNS transformations up to a single block, regardless of if %{i}, %{iv} %{p} etc
        fixed %{p} validated reverse domainname replacement macro (had the %{h} heloname code still in place). 
        Penciled through both PTR.NameNost.fqdn -eq ARec.Name.fqdn, and just the domainname portions, comparisons, went with domainname spec
        Key point is the RFC 7208: 
                p = the validated domain name of <ip> (do not use) !!!! 
        so %{p} shouldn't be in use anyway (exceesive DNS lookups generated).

    * 2:36 PM 12/30/2024 alias: resolve-SPFMacros -> ren'd resolve-SPFMacrosTDO() ; 
        added -Server 1.1.1.1, controllable param; removed broad rem's and end stop-transcript; turned down most w-h's as this is a util, not a main script;
        expanded CBH on helo host name rfc specs ref; added validatepattern's for SenderEmailAddress, DomainName, and SenderHeloName (covering [ip4][Ipv6:ip6]|fqdn); 
        rearranged, segmented expansion to types: ip macros, senderaddress macros, domainname macros, only apply ip-resolution code to ip-macro-tied spf entries;
flipped some params to non-mandetory (SenderAddress), test and prompt as needed instead (avoid need to push Helo host unless there's an %{h} macro), 
        added prompts to demand missing params as needed; pulled pipeline support, for submitter tests we're testing a single host/IP/PTR here; loop test a broad set if neededat cmdline
        tested OK on toro.com.
    * 4:10 PM 12/16/2024 questions about header sources for various tests: went back to RFC source, and dug out the detailed mechaism engring specs. Then worked through pphosted & salesforce macro expansion, 
    added them to expls. 
    * 9:31 AM 12/13/2024 adapted from resolve-SPFMacros, stip it down to just a Macro replace/expansion func, on passed strings (as Macros are expanded to final form, before eval of the subject record against sending Host occurs)
    * 11:05 AM 12/12/2024 ren: test-SPFMacroEgressIPs -> resolve-SPFMacros; 
        revised to permit a fully pre-resolved SPF record input, to skip the inital resolution step
    * 3:06 PM 12/10/2024 port to a verb-network function, REN test-SPFMacroEgressIPs -> test-SPFMacroIPs
    *4:47 PM 6/6/2024 init vers; works for validating the ppthosted record
    .DESCRIPTION
    resolve-SPFMacrosTDO - Expand macros in provided SPF specification string

    Ref:
    [dns spf "Modifier" "mechanism" when are macro replaced - Google Search](https://www.google.com/search?q=dns+spf+%22Modifier%22+%22mechanism%22+when+are+macro+replaced)

        #-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        AI Overview
        Learn more
        In a DNS SPF record, macros are replaced immediately before the SPF record is evaluated, meaning that when the receiving mail server looks up the SPF record, the macro variables like "%{i}" (representing the sender's IP address) are substituted with their actual values before any checks against the specified mechanisms are performed. 
        Key points about macro replacement in SPF:

            Dynamic substitution:
            Macros allow for dynamic insertion of contextual information like the sender's IP address or domain name directly into the SPF record.

        Mechanism evaluation:
        Once the macros are replaced, the SPF record is then evaluated based on the specified mechanisms (like "ip4", "mx", "exists") using the substituted values. 
        No separate lookup:
        The macro expansion happens during the initial DNS lookup of the SPF record, so there's no additional DNS query needed to retrieve the macro values.

        Example:
        Code

        v=spf1 include:subdomain.example.com ~all

            Without macros:
            This would simply check if the sending IP address is listed within the "subdomain.example.com" domain's SPF record.
            With macros:
                v=spf1 exists:%{i}.%{v}.arpa._spf.example.com ~all
                Here, "%{i}" would be replaced with the sender's IP address, allowing for a reverse DNS lookup on that specific IP to check if it's allowed to send mail on behalf of "example.com". 
        #-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

        Ref: 
        When a DNS record is stated as:
        IN TXT "v=spf1 include:example.com include:example.org -all"
        "IN" indicates the Internet, eg. the ip address is an internet ip address
        "The CLASS of a record is set to IN (for Internet) for common DNS records involving Internet hostnames, servers, or IP addresses.)"

        [Automating SPF macro management with scripting and APIs: a step-by-step guide - AutoSPF - Automatic SPF flattening](https://autospf.com/blog/automating-spf-macro-management-with-scripting-apis-step-by-step-guide/)
        #-=-=-=-=-=-=-=-=
        Here are the commonly integrated SPF macros–
            %{i}: Represents the IP address of the sender
            %{s}: Represents the sender's email address (the "MAIL FROM" address).
            %{h}: Represents the HELO/EHLO domain of the SMTP server.
            %{d}: Represents the domain of the sender's email address.
            %{p}: Represents the validated domain name of the sender's IP address.
            %{v}: Represents the literal string "in-addr" or "ip6", depending on whether the sender's IP address is IPv4 or IPv6.
            %{l}: Represents the local part of the sender's email address (the part before the "@" symbol).
            %{o}: Represents the domain part of the "MAIL FROM" address (the part after the "@" symbol).
            %{r}: Represents the domain of the recipient.
            %{t}: Represents the current timestamp in Unix time.

        #-=-=-=-=-=-=-=-=
        Ref: More specific, esp in re:%{h}:
        #-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        [SPF Macros - Simplifying Your SPF Record Implementation](https://powerdmarc.com/spf-macros-everything-you-need-to-know/)

        ## Types of SPF Macros

        SPF macros are denoted by different single alphabets or characters that are enclosed by curly braces {  } and prepended by a percent (%) sign, that refers to specific mechanisms within your SPF record. Here are the core macros. 

        -   %{s}: The "s" Macro represents the sender's email address. Example- Mark@domain.com.
        -   %{l}: It's used to denote the local part of the sender. Example- Mark.
        -   %{o}: This highlights the sender's domain. Example: domain.com.
        -   %{d}: Similar to "o", this Macro represents the authoritative sending domain. In most cases it is the same as the sender's domain however, it may differ in some cases. 
        -   %{i}: It's used to extract the IP address of the sender of the message, e.g. 192.168.1.100 
        -   %{h}: The hostname specified by the HELO or EHLO command used during the SMTP connection when the message is being sent is referred to by the %{h} macro.

        There are many more Macros that can be specified in your record, however, we listed some common ones.
        #-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        => %{h}: _The hostname_ specified by the HELO or EHLO command used during the SMTP connection when the message is being sent is referred to by the %{h} macro.
        NOT the DomainName!


        [RFC 4408 Sender Policy Framework (SPF) for Authorizing Use of Domains in Email, Version 1](https://www.rfc-editor.org/rfc/rfc7208)

        - <Sender> is checked against 1) The HELO Identity (full fqdn from HELO/EHLO greeting sent by client, if enabled on server), 
            or 2) the Mail From:/Envelope-From:/Return-Path:/5321.MailFrom:

        - 3.3.  Multiple Strings in a Single DNS Record
            As defined in [RFC1035], Sections 3.3 and 3.3.14, a single text DNS record can 
            be composed of more than one string.  If a published record contains multiple 
            character-strings, then the record MUST be treated as if those strings are 
            concatenated together without adding spaces.  For example: 

              IN TXT "v=spf1 .... first" "second string..."

            is equivalent to:
              IN TXT "v=spf1 .... firstsecond string..."

            TXT records containing multiple strings are useful in constructing records that would exceed the 255-octet maximum length of a character-string within a single TXT record.            

        - 3.4.  Record Size

            The published SPF record for a given domain name SHOULD remain small enough 
            that the results of a query for it will fit within 512 octets. Otherwise, there 
            is a possibility of exceeding a DNS protocol limit. This UDP limit is defined 
            in [RFC1035], Section 2.3.4, although it was raised by [RFC2671].  Staying 
            below 512 octets ought to prevent older DNS implementations from failing over 
            to TCP and will work with UDP in the absence of EDNS0 [RFC6891] support.  Since 
            the answer size is dependent on many things outside the scope of this document, 
            it is only possible to give this guideline: If the size of the DNS message, the 
            combined length of the DNS name and the text of all the records of a given type 
            is under 450 octets, then DNS answers ought to fit in UDP packets.  Records 
            that are too long to fit in a single UDP packet could be silently ignored by 
            SPF verifiers due to firewall and other issues that interfere with the 
            operation of DNS over TCP or using ENDS0.  

            Note that when computing the sizes for replies to queries of the TXT format, 
            one has to take into account any other TXT records published at the domain name.
             Similarly, the sizes for replies to all queries related to SPF have to 
            be evaluated to fit in a single 512-octet UDP packet (i.e., DNS message size 
            limited to 450 octets). 

        - 4.6.1.  Term Evaluation
            
            o two types of terms: mechanisms (defined in Section 5) and modifiers (defined in Section 6)
            o directive = [ qualifier ] mechanism
            o qualifier = "+" / "-" / "?" / "~"
            o mechanism  = ( all / include / a / mx / ptr / ip4 / ip6 / exists )
                Most mechanisms allow a ":" or "/" character after the name.
                Each mechanism is considered in turn from left to right.  If there are no more mechanisms, the result is the default result as described in Section 4.7.
                When a mechanism is evaluated, one of three things can happen: it can match, not match, or return an exception. 
                If it matches, processing ends and the qualifier value is returned as the 
                result of that record.  If it does not match, processing continues with the 
                next mechanism.  If it returns an exception, mechanism processing ends and the 
                exception value is returned. The possible qualifiers, and the results they 
                cause check_host() to return, are as follows: "+" pass|  "-" fail|  "~" 
                softfail|  "?" neutral|
 
                The qualifier is optional and defaults to "+"

                When a mechanism matches and the qualifier is "-", then a "fail" result 
                is returned and the explanation string is computed as described in Section 6.2. 

            o modifier = redirect / explanation / unknown-modifier
                Modifiers always contain an equals ('=') character immediately after the name, 
                and before any ":" or "/" characters that might be part of the macro-string.  
                Modifiers are not mechanisms.  They do not return match or not-match. Instead, 
                they provide additional information.  Although modifiers do not directly affect 
                the evaluation of the record, the "redirect" modifier has an effect after all 
                the mechanisms have been evaluated.  
            o unknown-modifier = name "=" macro-string
                      ; where name is not any known modifier
            o name = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )

        - 4.6.4.  DNS Lookup Limits
            - The following terms cause DNS queries: the "include", "a", "mx", "ptr", and 
            "exists" mechanisms, and the "redirect" modifier

            - SPF implementations MUST limit the total number of those terms to 10
            during SPF evaluation, to avoid unreasonable load on the DNS

            - the "all", "ip4", and "ip6" mechanisms, and the "exp" modifier -- do 
            not cause DNS queries at the time of SPF evaluation (the "exp" modifier 
            only causes a lookup at a later time), and their use is not subject to 
            this limit. 

            - When evaluating the "mx" mechanism, the number of "MX" resource records queried 
            is included in the overall limit of 10 mechanisms/ modifiers that cause DNS 
            lookups as described above.  In addition to that limit, the evaluation of each 
            "MX" record MUST NOT result in querying more than 10 address records -- either 
            "A" or "AAAA" resource records. If this limit is exceeded, the "mx" mechanism MUST 
            produce a "permerror" result.

            - When evaluating the "ptr" mechanism or the %{p} macro, the number of "PTR" 
            resource records queried is included in the overall limit of 10 
            mechanisms/modifiers that cause DNS lookups as described above.  In addition to 
            that limit, the evaluation of each "PTR" record MUST NOT result in querying 
            more than 10 address records -- either "A" or "AAAA" resource records.  If this 
            limit is exceeded, all records other than the first 10 MUST be ignored. 

            The reason for the disparity is that the set of and contents of the
            MX record are under control of the publishing ADMD, while the set of
            and contents of PTR records are under control of the owner of the IP
            address actually making the connection.

            These limits are per mechanism or macro in the record, and are in
            addition to the lookup limits specified above.

            - MTAs or other processors SHOULD impose a limit on the maximum amount
            of elapsed time to evaluate check_host().  Such a limit SHOULD allow
            at least 20 seconds.  If such a limit is exceeded, the result of
            authorization SHOULD be "temperror".
            
        - 4.8 Domain Specification
            - The <domain-spec> string is subject to macro expansion
            - The resulting string is the common presentation form of 
                a fully qualified DNS name: a series of labels separated by periods.
                This domain is called the <target-name> in the rest of this document.

            - For several mechanisms, the <domain-spec> is optional.  If it is not
            provided, the <domain> from the check_host() arguments (see Section 4.1) 
            is used as the <target-name>.  "domain" and <domain-spec> are syntactically 
            identical after macro expansion.
            "domain" is an input value for check_host(), while <domain-spec> is
            computed by check_host()
        
        - 5.  Mechanism Definitions
            -When any mechanism fetches host addresses to compare with <ip>, 
                o when <ip> is an IPv4, "A" records are fetched;
                o when <ip> is an IPv6 address, "AAAA" records are fetched.  

            - "a" An address lookup is done on the <target-name>/domain-spec/domain using the type of
                lookup (A or AAAA) appropriate for the connection type (IPv4 or
                IPv6).  The <ip> is compared to the returned address(es).  If any
                address matches, the mechanism matches.
            - "mx" performs an MX lookup on the <target-name>/domain-spec/domain 
                Then performs an address lookup on each MX name returned.
                The <ip> is compared to each returned IP address.
                e.g.: resolve domain MX's, then resolve the NameHost of each records 'A' on the Namehost, to the underlying IP Addresses: compare the sending server IP against those IPs
                resolve-dnsname -type 'A' -name (resolve-dnsname -type mx -name toro.com -server 1.1.1.1).NameExchange -server 1.1.1.1 | select -expand ipaddress
                    52.101.194.17
                    52.101.8.44
                    52.101.41.58
                    52.101.42.10
           - "ptr" (do not use)
                The <ip>'s name is looked up using this procedure:
                o  Perform a DNS reverse-mapping for <ip>: 
                        Look up the corresponding PTR record in "in-addr.arpa." if the address is an IPv4 address and in "ip6.arpa." if it is an IPv6 address.
                o  For each record returned, validate the domain name by looking up its IP addresses.  
                o  If <ip> is among the returned IP addresses, then that domain name is validated.
                e.g: Resolve the sender server IP to the PTR, then resolve the A record for the prior's Namehost, back to it's IP address, and compare senderserver IP to the IP from trhe expansions
                resolve-dnsname -name (resolve-dnsname -type ptr -name 170.92.7.36 -server 1.1.1.1).namehost -type A -server 1.1.1.1 | select -expand ipaddress
                    170.92.7.36
            - "ip4" and "ip6" 
                The <ip> is compared to the given network.  If CIDR prefix length high-order bits match, the mechanism matches.
                If ip4-cidr-length is omitted - only an IP is listed - it is taken to be "/32".  If ip6-cidr-length is omitted - only an ip6 IP is listed - it is taken to be "/128".  
                    e.g. go ahead and append /32 & /128 to single IPs in ip4 & ip6 entries
            - "exists" This mechanism is used to construct an arbitrary domain name that is 
                used for a DNS A record query.  It allows for complicated schemes involving 
                arbitrary parts of the mail envelope to determine what is permitted. 
                The <domain-spec> is expanded as per above (including macros etc).  
                The resulting domain name is used for a DNS A RR lookup - == resolve the A record to the IP - (even when the connection type is IPv6).  
                If any A record is returned, this mechanism matches.
                Domains can use this mechanism to specify arbitrarily complex queries.  For example, suppose example.com publishes the record:
                    v=spf1 exists:%{ir}.%{l1r+-}._spf.%{d} -all

                The <target-name> might expand to
                    "1.2.0.192.someuser._spf.example.com".  
                This makes fine-grained decisions possible at the level of the user and client IP address.

        ## %{h}: Represents the HELO/EHLO domain of the SMTP server.

            [domain name system - What exactly should HELO say? - Server Fault](https://serverfault.com/questions/305925/what-exactly-should-helo-say)

            Cite from [RFC 5321](http://www.ietf.org/rfc/rfc5321.txt) 4.1.1.1. Extended HELLO (`EHLO`) or HELLO (`HELO`)

                > The argument field contains the fully-qualified domain name of the SMTP client if one is available.

            In other words it should be the FQDN which resolves into the IP address you're sending mail from.

            So, if you are sending mail from the IP address `12.34.56.78` 
            and `mail.domain.com` resolves into `12.34.56.78` 
            (and the `DNS` `PTR` for `12.34.56.78` is set to `mail.domain.com`) 
            you should use `mail.domain.com` as the parameters for `HELO` (`EHLO`).

            [domain name system - What exactly should HELO say? - Server Fault](https://serverfault.com/questions/305925/what-exactly-should-helo-say)

            In the immortal words of [RFC2821](http://www.ietf.org/rfc/rfc2821.txt) (emphasis added):
            > These commands are used to identify the SMTP client to the SMTP server. 
            > The argument field **contains the fully-qualified domain name of the SMTP client if one is available**. 
            > In situations in which the SMTP client system does not have a meaningful domain name 
            > (e.g., when its address is dynamically allocated and no reverse mapping record is available), 
            > the client SHOULD send an address literal (see section 4.1.3), optionally followed by information 
            > that will help to identify the client system. The SMTP server identifies itself to the SMTP client
            > in the connection greeting reply and in the response to this command.
            
           (the "address literal" is the address in brackets (`[192.0.2.1]`), or for v6 the address with an `IPv6` prefix (`[IPv6:fe80::1]`))

    This is specifically tuned to resolve & lookup dynamic per-host DNS records, over validating standard include or other records
    .PARAMETER SpfRecord
    Optional Pre-resolved SpfRecord specification string to be evaluated (skips initial resolution pass; used to recycle from Resolve-SPFRecord() call[-SpfRecord `$spfRec]
    .PARAMETER IPAddress
    Sending server IP Address to be expanded into '%{i}','%{ir}','%{v}','%{p}' IP-based macros in the DomainName SPF record[-IPAddress '192.168.1.1']
    .PARAMETER DomainName
    DomainName for which SPF records should be tested[-DomainName DOMAIN.COM]
    .PARAMETER SenderAddress
    SenderAddress to use for '%{d}','%{s}','%{l}','%{o}' SenderAddress based macros[-SenderAddress EMAIL@DOMAIN.TLD]
    .PARAMETER SenderHeloName
    Optional Sending client SMTP server HELO/EHLO hostname FQDN, to use for '%{h}' macro substitution (should be an FQDN or where Dyn-ip & no PTR, a squarebracketed ip4 ip, or prefixed ip6 ip: [192.0.2.1] or [IPv6:fe80::1]) [-SenderHeloName SERVER.DOMAIN.TLD]
    .PARAMETER Server
    DNS Server to query (defaults to Cloudflare public resolver 1.1.1.1)[-Server 1.0.0.1]
    .INPUTS
    None. Does not accepted piped input.(.NET types, can add description)
    .OUTPUTS
    None. Returns no objects or output (.NET types)
    System.Boolean
    [| get-member the output to see what .NET obj TypeName is returned, to use here]
    .EXAMPLE
    PS> $spfspec = Resolve-DnsName -name _spf.salesforce.com -server 1.1.1.1 -type TXT | ? strings -match '^v=spf1' | select -expand strings ; 
    PS> $spfspec ; 

        v=spf1 exists:%{i}._spf.mta.salesforce.com -all

    PS> $resolvedSPFString = resolve-SPFMacrosTDO -SpfRecord $spfspec -IPAddress 52.88.39.26 -DomainName salesforce.com -SenderAddress PartsClaims@toro.com

        VERBOSE: 15:50:48:===> Specified $SpfRecord:
        v=spf1 exists:%{i}._spf.mta.salesforce.com -all
        has been resolved to:
        v=spf1 exists:52.88.39.26._spf.mta.salesforce.com -all
        (sending to pipeline)

    PS> $resolvedSPFString  ; 

        v=spf1 exists:52.88.39.26._spf.mta.salesforce.com -all

    PS> write-verbose "Resolve the include:36.7.92.170.in-addr.toro.com.spf.has.pphosted.com name to A record" ; 
    PS> resolve-dnsname -name ($resolvedSPFString.split(' ') | ?{$_ -match 'exists:'}).replace('exists:','') -type A -server 1.1.1.1 ; 

        Name                                           Type   TTL   Section    IPAddress                                
        ----                                           ----   ---   -------    ---------                                
        52.88.39.26._spf.mta.salesforce.com            A      3600  Answer     52.88.39.26            

    PS> write-verbose "A matching A record was returned for the macro expanded name => the SPF lookup passes.
    Demo retrieving an SPF record, expanding macros present, and then re-resolving the updated include: hostname to an existing A record (which therefore passes the SPF test).
    .EXAMPLE
    PS> $spfspec = resolve-dnsname -name toro.com -type TXT -server 1.1.1.1 | ? strings -match 'spf' | select -expand strings
    PS> $spfspec ; 

        v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com ~all

    PS> $resolvedSPFString = resolve-SPFMacrosTDO -SpfRecord $spfspec -IPAddress 170.92.7.36 -DomainName toro.com -SenderAddress PartsClaims@toro.com -SenderHeloName mymailoutlyn0.toro.com -verbose ;

        VERBOSE: 15:50:48:===> Specified $SpfRecord:
        v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com ~all
        has been resolved to:
        v=spf1 include:36.7.92.170.in-addr.toro.com.spf.has.pphosted.com ~all
        (sending to pipeline)

    PS> $resolvedSPFString  ; 

        v=spf1 include:36.7.92.170.in-addr.toro.com.spf.has.pphosted.com ~all

    PS> write-verbose "Resolve the include: to A record" ; 
    PS> resolve-dnsname -name ($xpanded.split(' ') | ?{$_ -match 'include:'}).replace('include:','') -type A -server 1.1.1.1

        Name                                           Type   TTL   Section    IPAddress                                
        ----                                           ----   ---   -------    ---------                                
        36.7.92.170.in-addr.toro.com.spf.has.pphosted. A      3600  Answer     127.0.0.2                                
        com        

    PS> write-verbose "A matching A record was returned for the macro expanded name => the SPF lookup passes.
    Demo retrieving an SPF record (in this case utilizes the include: mechanism), expanding macros present, and then re-resolving the updated include: hostname to an existing A record (which therefore passes the SPF test).
    
    .EXAMPLE
    PS> $pltDomSpecs = [ordered]@{
    PS>     DomainName = 'toro.com' ;
    PS>     IPAddress = '170.92.7.36' ;
    PS>     SenderAddress = 'todd.kadrie@toro.com' ;
    PS>     SenderHeloName = 'mymailoutlyn0.toro.com' ;
    PS> } ; 
    PS> write-verbose "remove empty value keys" ; 
    PS> $mts = $pltDomSpecs.GetEnumerator() | ?{ -NOT ($_.Value -AND $_.value.length)} 
    PS> $mts | ForEach-Object { $pltDomSpecs.remove($_.Key) } ; 
    PS> $tspf = resolve-dnsname -name $pltDomSpecs.DomainName -type TXT -server 1.1.1.1 | ? strings -match 'spf' | select -expand strings ; 
    PS> write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($pltDomSpecs.DomainName) Matched DNS SPF Record w`n$(($tspf|out-string).trim())" ; 
    PS> if($tspf -match "%[{%-_]"){
    PS>     write-host -foregroundcolor yellow "Macro syntax directive detected, running expansion (resolve-SPFMacrosTDO)" ; 
    PS>     #$xpanded = resolve-SPFMacrosTDO -SpfRecord $tspf -verbose -DomainName $pltDomSpecs.DomainName -IPAddress $pltDomSpecs.IPAddress -SenderAddress todd.kadrie@toro.com ;
    PS>     $xpanded = resolve-SPFMacrosTDO -SpfRecord $tspf -verbose @pltDomSpecs ; 
    PS>     write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):DNS SPF Record expanded by resolve-SPFMacrosTDO`n$(($xpanded|out-string).trim())" ; 
    PS> } else {
    PS>     $xpanded = $tspf ; 
    PS> } ; 
    Wrapped call of spf retrieval, and macro replacement
    .EXAMPLE
    PS> if($PSBoundParameters){
    PS>         $pltRvSPFMacr = [ordered]@{} ; 
    PS>         $pltRvSPFMacr.add('DomainName',$Name) ;
    PS>         $pltRvSPFMacr.add('SpfRecord',$SPFDirective) ;
    PS>         $PSBoundParameters.GetEnumerator() | ?{ $_.key -notmatch $rgxBoundParamsExcl} | foreach-object { $pltRvSPFMacr.add($_.key,$_.value)  } ;
    PS>         write-host -foregroundcolor green "resolve-SPFMacros w`n$(($pltRvSPFMacr|out-string).trim())" ; 
    PS>         $SPFDirective = resolve-SPFMacros @pltRvSPFMacr  ;
    PS> } else {
    PS>     $smsg = "unpopulated `$PSBoundParameters!" ; 
    PS>     write-warning $smsg ; 
    PS>     throw $smsg ; 
    PS> }; 
    Demo call leveraging $PSBoundParameters
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://bitbucket.org/tostka/powershell/
    .LINK
    [ name related topic(one keyword per topic), or http://|https:// to help, or add the name of 'paired' funcs in the same niche (enable/disable-xxx)]
    #>
    <#List of Eggress IP addresses to resolve against SPF macro settings
    IPAddress
    DomainName to be tested for SPF validity
    DomainName
    #>
    [Alias('resolve-SPFMacros')]
    PARAM(
        [Parameter(Mandatory=$True,HelpMessage="Optional Pre-resolved SpfRecord specification string to be evaluated (skips initial resolution pass; used to recycle from Resolve-SPFRecord() call[-SpfRecord `$spfRec]")]
            <# 8:58 AM 12/13/2024 prob don't have to eval the v=spf for full spf compliance - not this func''s role, and it may be handling substrings of a full spf, so just sub through the sent text and send updated back
            [ValidateScript({
                ($_ -is [string])
                if($_ -match '^v=spf'){$true}else{
                    throw "specified SPF Record does not have a leading '^v=spf' string`nensure you are passing the expanded SPF specification, and not the entire retrieved DNS record" ; 
                } ; 
            })]
            #>
            [Alias('MacroString')]
            #[string]
            [string[]]$SpfRecord, # make it an array to accomodate stacked strings, and crlf-split herestrings
        # assumes IPAddress is required on every expansion (as the macro expansion loop lops out the ipaddresses and does relevent updates)
        #[Parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="Sending server IP Address(es) to be tested for '%{i}','%{ir}','%{v}','%{p}' IP-based macros in the DomainName SPF record[-IPAddress '192.168.1.1','192.168.1.2']")]
        [Parameter(Mandatory=$true,HelpMessage="Sending server IP Address to be expanded into '%{i}','%{ir}','%{v}','%{p}' IP-based macros in the DomainName SPF record[-IPAddress '192.168.1.1']")]
            #[ValidateNotNullOrEmpty()]
            [Alias('SenderIPAddress','SenderIP')]
            #[string[]]
            #if doing a single submitting server eval, this should be a single ip string, better, [system.net.ipaddress]
            [system.net.ipaddress]$IPAddress, # =  @($Tormeta.OP_ExEgressIPs + $CMWMeta.OP_ExEgressIPs) ,
        [Parameter(Mandatory=$True,HelpMessage="DomainName for which SPF records should be tested[-DomainName DOMAIN.COM]")]
            [ValidateNotNullOrEmpty()]
            #[ValidatePattern("^([-0-9a-zA-Z]+[.])+[a-zA-Z]{2,63}$")] # email domain name restrictions
            #[ValidatePattern("^([-0-9a-zA-Z_]+[.])+([-0-9a-zA-Z]+[.])+[a-zA-Z]{2,63}$")] # DNS -type TXT permits underscores, but not in the DomainName portion on the right 
            # make the CN machinename optional: 
            [ValidatePattern("^((([-0-9a-zA-Z_]+[.])+)*)([-0-9a-zA-Z]+[.])+[a-zA-Z]{2,63}$")] # DNS -type TXT permits underscores, but not in the DomainName portion on the right 
            # Note: -type SRV also permit leading _ on records
            [Alias('Domain')]
            [string]$DomainName,
        [Parameter(Mandatory=$False,HelpMessage="SenderAddress to use for '%{d}','%{s}','%{l}','%{o}' SenderAddress based macros[-SenderAddress EMAIL@DOMAIN.TLD]")]
            #[ValidateNotNullOrEmpty()]
            [ValidatePattern("^([0-9a-zA-Z]+[-._+&'])*[0-9a-zA-Z]+@([-0-9a-zA-Z]+[.])+[a-zA-Z]{2,63}$")]
            [Alias('Sender')]
            [string]$SenderAddress,
        [Parameter(Mandatory=$false,HelpMessage="Optional Sending client SMTP server HELO/EHLO hostname FQDN, to use for '%{h}' macro substitution (should be an FQDN or where Dyn-ip & no PTR, a squarebracketed ip4 ip, or prefixed ip6 ip: [192.0.2.1] or [IPv6:fe80::1]) [-SenderHeloName SERVER.DOMAIN.TLD]")]
            #[ValidateNotNullOrEmpty()] # rgx below matches all three: server.sub.domain.com|[192.0.2.1]|[IPv6:fe80::1]
            [ValidatePattern("^((?=.{1,254}$)(^(?:(?!\d+\.|-)[a-zA-Z0-9_\-]{1,63}(?<!-)\.?)+(?:[a-zA-Z]{2,}))|\[(IPv6:((([0-9A-Fa-f]{1,4}:){1,6}:)|(([0-9A-Fa-f]{1,4}:){7}))([0-9A-Fa-f]{1,4})|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})])$")]
            #[Alias('ALIAS1', 'ALIAS2')]
            [string]$SenderHeloName,
        [Parameter(Mandatory = $false,HelpMessage="DNS Server to query (defaults to Cloudflare public resolver 1.1.1.1)[-Server 1.0.0.1]")]
            [string]$Server = "1.1.1.1"
    ) ; 
    BEGIN { 
        #region CONSTANTS_AND_ENVIRO #*======v CONSTANTS_AND_ENVIRO v======
        #region ENVIRO_DISCOVER ; #*------v ENVIRO_DISCOVER v------
        $Verbose = ($VerbosePreference -eq 'Continue') ; 
        # Debugger:proxy automatic variables that aren't directly accessible when debugging (must be assigned and read back from another vari) ; 
        $rPSCmdlet = $PSCmdlet ; 
        ${CmdletName} = $rPSCmdlet.MyInvocation.MyCommand.Name ; # function self-name (equiv to script's: $MyInvocation.MyCommand.Path) ;
            #region PsParams ; #*------v PsParams v------
        $PSParameters = New-Object -TypeName PSObject -Property $rPSBoundParameters ;
        write-verbose "`$rPSBoundParameters:`n$(($rPSBoundParameters|out-string).trim())" ;
        # pre psv2, no $rPSBoundParameters autovari to check, so back them out:
        if($rPSCmdlet.MyInvocation.InvocationName){
            if($rPSCmdlet.MyInvocation.InvocationName  -match '^\.'){
                $smsg = "detected dot-sourced invocation: Skipping `$PSCmdlet.MyInvocation.InvocationName-tied cmds..." ; 
                if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
            } else { 
                write-verbose 'Collect all non-default Params (works back to psv2 w CmdletBinding)'
                $ParamsNonDefault = (Get-Command $rPSCmdlet.MyInvocation.InvocationName).parameters | Select-Object -expand keys | Where-Object{$_ -notmatch '(Verbose|Debug|ErrorAction|WarningAction|ErrorVariable|WarningVariable|OutVariable|OutBuffer)'} ;
            } ; 
        } else { 
            $smsg = "(blank `$rPSCmdlet.MyInvocation.InvocationName, skipping Parameters collection)" ; 
            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
        } ; 
        #endregion PsParams ; #*------^ END PsParams ^------
        #endregion ENVIRO_DISCOVER ; #*------^ END ENVIRO_DISCOVER ^------
        #region COMMON_CONSTANTS ; #*------v COMMON_CONSTANTS v------
    
        if(-not $DoRetries){$DoRetries = 4 } ;    # # times to repeat retry attempts
        if(-not $RetrySleep){$RetrySleep = 10 } ; # wait time between retries
        if(-not $RetrySleep){$DawdleWait = 30 } ; # wait time (secs) between dawdle checks
        if(-not $DirSyncInterval){$DirSyncInterval = 30 } ; # AADConnect dirsync interval
        if(-not $ThrottleMs){$ThrottleMs = 50 ;}
        if(-not $rgxDriveBanChars){$rgxDriveBanChars = '[;~/\\\.:]' ; } ; # ;~/\.:,
        if(-not $rgxCertThumbprint){$rgxCertThumbprint = '[0-9a-fA-F]{40}' } ; # if it's a 40char hex string -> cert thumbprint  
        if(-not $rgxSmtpAddr){$rgxSmtpAddr = "^([0-9a-zA-Z]+[-._+&'])*[0-9a-zA-Z]+@([-0-9a-zA-Z]+[.])+[a-zA-Z]{2,63}$" ; } ; # email addr/UPN
        if(-not $rgxDomainLogon){$rgxDomainLogon = '^[a-zA-Z][a-zA-Z0-9\-\.]{0,61}[a-zA-Z]\\\w[\w\.\- ]+$' } ; # DOMAIN\samaccountname 
        if(-not $exoMbxGraceDays){$exoMbxGraceDays = 30} ; 
        if(-not $XOConnectionUri ){$XOConnectionUri = 'https://outlook.office365.com'} ; 
        if(-not $SCConnectionUri){$SCConnectionUri = 'https://ps.compliance.protection.outlook.com'} ; 

        #region LOCAL_CONSTANTS ; #*------v LOCAL_CONSTANTS v------

        #endregion LOCAL_CONSTANTS ; #*------^ END LOCAL_CONSTANTS ^------  
        #endregion CONSTANTS_AND_ENVIRO ; #*------^ END CONSTANTS_AND_ENVIRO ^------

        #endregion CONSTANTS_AND_ENVIRO ; #*------^ END CONSTANTS_AND_ENVIRO ^------

        #region FUNCTIONS ; #*======v FUNCTIONS v======

        #*------v Function convert-IPAddressToReverseTDO v------
        if(-not (get-command convert-IPAddressToReverseTDO -ea 0)){
            function convert-IPAddressToReverseTDO {
                <#
                .SYNOPSIS
                Reverse IP Address. 
                .NOTES
                Version     : 0.0.1
                Author      : Todd Kadrie
                Website     : http://www.toddomation.com
                Twitter     : @tostka / http://twitter.com/tostka
                CreatedDate : 2025-01-02
                FileName    : convert-IPAddressToReverseTDO.ps1
                License     : (none asserted)
                Copyright   : (none asserted)
                Github      : https://github.com/tostka/verb-Network
                Tags        : Powershell,TCP,IPAddress
                AddedCredit : REFERENCE
                AddedWebsite: URL
                AddedTwitter: URL
                * 4:44 PM 1/2/2025 replace borked Copilot ipv4 demo (didn't work, as expected, clearly [-1..1] isn't reverse array, it's pull last & first element); 
                    coded in solid ipv6 support (IP reverse process is diff ipv4 & ipv6)
                    ren Reverse-IP -> convert-IPAddressToReverseTDO, alias Reverse-IP
                * 8:58 AM 1/2/2025 generated source via Copilot
                .DESCRIPTION
                Reverse IPAddress Address (ipv4 or ipv6). 

                Was originally cheating my way to the IPv6 reverse by resolving a PTR, and cutting the returned PTR record name at .ipv6', and taking the left half. 
                But [Shortest Script Challenge - Convert IPv6 to nibble format : r/PowerShell](https://www.reddit.com/r/PowerShell/comments/6wcpfv/shortest_script_challenge_convert_ipv6_to_nibble/)
                outlined a series of algos to get to the same thing, wo the PTR resolution step.

                .PARAMETER IPAddress
                The IPAddress address to be used in macro expansion.
                .INPUTS
                None. The script does not accept pipeline input.
                .OUTPUTS
                System.String The Reversed IP Address
                .EXAMPLE
                PS> $IPRev = convert-IPAddressToReverseTDO -ipaddress 192.168.1.1 ; 
                Reverse an IPv4 addres
                .EXAMPLE
                PS> $IPAddress = (resolve-dnsname -name ipv6.google.com | ?{$_.Type -eq 'AAAA'} |select -expand ipaddress) ; 
                PS> $IPRev = convert-IPAddressToReverseTDO  -ipaddress $ipaddress.IPAddressToString ; 
                    
                    Ipv6 address specified:2607:f8b0:4009:817::200e

                PS> $IPRev ; 
                    
                    E.0.0.2.0.0.0.0.0.0.0.0.0.0.0.0.7.1.8.0.9.0.0.4.0.B.8.F.7.0.6.2

                Reverse an IPv6 address
                .LINK
                https://github.com/tostka/verb-Network
                #>    
                [CmdletBinding()]
                [Alias('Reverse-IP')]
                PARAM(
                    [Parameter(Mandatory=$TRUE,HelpMessage="IPAddress (supports ipv4 & ipv6)[-IPAddress 192.168.1.1]")]
                    [system.net.ipaddress]$IPAddress
                ) ; 
                switch($IPAddress.AddressFamily){
                    'InterNetwork' { 
                        write-verbose "Ipv4 address specified:$($IPAddress)" ; 
                        #return ($IPAddress -split '\.')[-1..0] -join '.' ; 
                        # Copilot's algo above didn't work properly :'P [-1..1] doesn't reverse the array, it pulls [last..first]. 
                        $IpParts = $IPAddress -split '\.' ; 
                        [array]::Reverse($IpParts);
                        return ($IpParts -join ".")
                    }
                    'InterNetworkV6' { 
                        write-verbose "Ipv6 address specified:$($IPAddress.IPAddressToString)" ; 
                        <# doing it by pulling a PTR, and cutting the trailing .ip6.. from the returned record Name (select unique)
                        if($resolvedPTR = resolve-dnsname -name $IPAddress.IPAddressToString -type PTR -server 1.1.1.1){
                            return (($resolvedPTR | select -unique name).name  -replace '.ip6.arpa')
                        } else {
                            $smsg = "Unable to:resolve-dnsname -name $($IPAddress.IPAddressToString) -type PTR -server 1.1.1.1!" ; 
                            write-warning $smsg ; 
                            throw $smsg ;
                            return $false ;
                        }; 
                        #>
                        # or doing it using the [Shortest Script Challenge - Convert IPv6 to nibble format : r/PowerShell](https://www.reddit.com/r/PowerShell/comments/6wcpfv/shortest_script_challenge_convert_ipv6_to_nibble/)
                        # param($i)
                        #((([ipaddress]$i)|% GetA*|%{('{0:x2}'-f$_)[0,1]})[31..0]-join'.')+".ip6.arpa"
                        # we don't need the ip6.arpa trailing bit, just the algo to flip the elements.
                        #return ((([ipaddress]$IPAddress.IPAddressToString)|% GetA*|%{('{0:x2}'-f$_)[0,1]})[31..0]-join'.') ; 
                        # expanded a bit, less compressed logic:
                        $i=[bitconverter]::ToString( [IPAddress]::Parse($IPAddress.IPAddressToString).GetAddressBytes()).Replace('-','').ToCharArray() ; 
                        [array]::Reverse($i);
                        return ($i -join ".") # +'.ip6.arpa' 
                        # dropped trailing string from the above linked example: the ip6.arpa is the PTR record name, we just want the reversed ipv6 IP, to use in the %{ir} macro replacements
                    }
                } ; 
            } ; 
        } ; 
        #*------^ END Function convert-IPAddressToReverseTDO ^------

        #endregion FUNCTIONS ; #*======^ END FUNCTIONS ^======

        #region BANNER ; #*------v BANNER v------
        $sBnr="#*======v $(${CmdletName}): v======" ;
        $smsg = $sBnr ;
        if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
        #endregion BANNER ; #*------^ END BANNER ^------

        <# pulled pipeline support
        # check if using Pipeline input or explicit params:
        if ($rPSCmdlet.MyInvocation.ExpectingInput) {
            $smsg = "Data received from pipeline input: '$($InputObject)'" ;
            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
        } else {
            # doesn't actually return an obj in the echo
            #$smsg = "Data received from parameter input: '$($InputObject)'" ;
            #if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
            #else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
        } ;
        #>
        if($SpfRecord){
            $smsg = "-SpfRecord specified: Using passed spf specification string" ; 
            $smsg = "`n$(($SpfRecord|out-string).trim())" ; 
            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
            $SpfRec = $SpfRecord ; 
        }else {
            #write-verbose "Resolve DNS SPF record: resolve-dnsname -name $($DomainName) -type TXT -server $Server" ; 
            #$SpfRec = resolve-dnsname -name $DomainName -type TXT -server $Server  -ea STOP| ? strings  -match '^v=spf' | select -expand strings ; 
            $smsg = "Missing REQUIRED -SpfRecord spec!" ; 
            throw $smsg ;
        } ; 

        # check for macros syntax in spf record
        if($SpfRec -notmatch '%\{[slodipvh]}' ){
            #$smsg = "DomainName:$($DomainName) retrieved SPF record" ; 
            $smsg = "Provided SPF record (or substring)" ; 
            $smsg +="`nDOES NOT USE ANY SPF MACROS that act against dynamic per-host records" ; 
            # make it smoothly accomodate unneeded passes
            #$smsg +="`nThis script does not apply to this domain. ABORTING" ; 
            #if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
            #else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
            #Break; 
            $smsg +="`n(returning unmodified SPF spec to pipeline)" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
        } ; 
        # $IPAddress
        if($SpfRec -match '%\{[ivp]}'){
            if(-not $IPAddress){
                $smsg = "SPF Record specified:" 
                $smsg += "`n$(($SpfRecord|out-string).trim())" ; 
                $smsg += "Includes IPAddress-dependant Macros '%{i}','%{ir}','%{v}','%{p}'" ; 
                $smsg += "`n but *no* `$IPAddress has been specified!" ; 
                #$smsg += "`nPlease retry with a suitable `$IPAddress specification"
                $smsg += "`nPrompting for an address" ; 
                $smsg = "" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Prompt } 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                #throw $smsg ; 
                #BREAK ; 
                $IPAddress = Read-Host "Specify a suitable IPAddress for '%{i}','%{iv}','%{p}' expansion" ; 
            } else{
                write-verbose  "SPF Record specified:Includes IPAddress-dependant Macros '%{i}','%{ir}','%{v}','%{p}', and an `$IPAddress has been specified ($($IPAddress.IPAddressToString))" ; 
                $smsg = "`n`n==Processing:`$IPAddress:`n$(($IPAddress.IPAddressToString|out-string).trim())" ; 
                $smsg += "`nagainst DomainName: $($DomainName)`n`n" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            } ; 
        }; 
        # $SenderAddress
        if($SpfRec -match '%\{[dslo]}'){
            if(-not $SenderAddress){
                $smsg = "SPF Record specified:" 
                $smsg += "`n$(($SpfRecord|out-string).trim())" ; 
                $smsg += "Includes SenderAddress-dependant Macros '%{d}','%{s}','%{l}','%{o}'" ; 
                $smsg += "`n but *no* `$SenderAddress has been specified!" ; 
                #$smsg += "`nPlease retry with a suitable `$SenderAddress specification"
                $smsg += "`nPrompting for an address" ; 
                #throw $smsg ; 
                #BREAK ; 
                $SenderAddress = Read-Host "Specify a suitable SenderAddress for '%{d}','%{s}','%{l}','%{o}' expansion" ; 
            } else{
                write-verbose  "SPF Record specified:Includes SenderAddress-dependant Macros '%{d}','%{s}','%{l}','%{o}', and an `$SenderAddress has been specified ($($SenderAddress))" ; 
            } ; 
        }; 
        # $SenderHeloName
        if($SpfRec -match '%\{[h]}'){
            if(-not $SenderHeloName){
                $smsg = "SPF Record specified:" 
                $smsg += "`n$(($SpfRecord|out-string).trim())" ; 
                $smsg += "Includes Sender Server HELO name dependant Macro '%{h}'" ; 
                $smsg += "`n but *no* `$SenderHeloName has been specified!" ; 
                #$smsg += "`nPlease retry with a suitable `$SenderHeloName specification"
                $smsg += "`nPrompting for an address" ; 
                #throw $smsg ; 
                #BREAK ; 
                $SenderHeloName = Read-Host "Specify a suitable SenderHeloName for '%{h}' expansion" ; 
            } else{
                write-verbose  "SPF Record specified:Includes Sender Server HELO name dependant Macro '%{h}', and a `$SenderHeloName has been specified ($($SenderHeloName))" ;
            } ; 
        }; 

        
        # precheck for IP-tied DNS pre-expansions on $IPAddress
        if(($SpfRec -match '%\{[ivp]}') -OR ($SpfRec -match 'ptr:')){
            write-verbose "$($SpfRec):IP-dependant Tests found:Doing IP-test DNS transforms" ; 

            #region Resolve_Information ; #*------v Resolve_Information v------
            $isIPv4 = $isIPv6 = $isFQDN = $isNBName = $false ; 
            $SendNameHost = $ComputerARec =  $SendIP =  $SendPTR =  $SendIPRev =  $SendAddressfamily = $null ; 
            # string
            #$Computer = $IPAddress ; 
            #ipaddr
            $Computer = $IPAddress.IPAddressToString
            TRY{
                # for [string] IP spec
                #$SendAddressfamily = ([ipaddress]$IPAddress).addressfamily ; # InterNetwork|InterNetworkV6
                # for [ipaddress] IP spec
                $SendAddressfamily = $IPAddress.addressfamily ; # InterNetwork|InterNetworkV6
                switch($SendAddressfamily){
                    'InterNetwork' { $isIpv4 = $true  }
                    'InterNetworkV6' { $isIPv6 = $true  }
                }
            } CATCH {
                $ErrTrapd=$Error[0] ;
                $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;
                write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" ;
            } ; 

            if( -not ($isIPv4 -OR $isIPv6) -AND (6 -le $Computer.length -le 253) -AND ($Computer -match '^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$') ){
                $isFQDN = $true ; 
            }  ;
            <#[ValidateLength(1, 15)]
            [ValidateScript({$PSItem -replace '\\|/|:|\*|\?|"||\||\.' -eq $PSItem})]
            #>
            if( -not ($isIPv4 -OR $isIPv6) -AND  (1 -le $Computer.length -le 15) -AND ($Computer -replace '\\|/|:|\*|\?|"||\||\.' -eq $Computer) ){
                $isNBName = $true ; 
            }  ;
            #$Computer = 'NAME.SUB.DOMAIN.com' ; 
            #$SenderAddress = 'SENDER@DOMAIN.com' ; 
            TRY{
                $cachedName = $null ; 
                $cachedName = $Computer ; 
                if($isIPv4 -OR $isIPv6){
                    write-verbose "Resolve IP to FQDN (PTR): `nresolve-dnsname -name $($Computer) -type PTR -ea STOP -server $($Server) | select -expand namehost" ; 
                    $SendNameHost = $Computer = resolve-dnsname -name $Computer -type PTR -ea STOP -server $Server | select -expand namehost; 
                } ; 
                if($isNBName){
                    write-verbose "Resolve NBName to FQDN (A): `nresolve-dnsname -name $($Computer) -type A -ea STOP -server $($Server)| select -expand Name" ; 
                    $SendNameHost = $Computer = resolve-dnsname -name $Computer -type A -ea STOP -server $Server | select -expand Name
                } ; 
            
                write-verbose "Resolve IP A Record: resolve-dnsname -name $($Computer) -type A: `nresolve-dnsname -name $($Computer) -type A  -server $($Server) -ea STOP | select -first 1 " ; 
                TRY{
                    #$ComputerARec = resolve-dnsname -name $Computer -type A  -ea STOP -server $Server | select -first 1  ; 
                    $ComputerARec = resolve-dnsname -name $SendNameHost  -type A  -ea STOP -server $Server | select -first 1  ; 
                    write-host -foregroundcolor green "Resolved $($SendNameHost ) A Record:`n$(($ComputerARec|out-string).trim())" ; 
                    $SendIP = $ComputerARec.IPAddress ; 
                    write-verbose "`$SendIP: $($SendIP)" ; 
                }CATCH{
                    $smsg = "Failed to:resolve-dnsname -name $($Computer) -type A " ; 
                    $smsg += "`nFalling back to original cached identifier: $($cachedName)" ; 
                    $smsg += "`n and reattempting resolution of that value" ; 
                    write-warning $smsg ; 
                    $ComputerARec = $null ; 
                    $Computer = $cachedName  ; 
                    if($isIPv4 -OR $isIPv6){$SendIP = $cachedName} ; 
                    # if non IPv4 or IPv6 and computer length is 6-253 chars, and is an fqdn, resolve fqdn to IPaddress
                    if( -not ($isIPv4 -OR $isIPv6) -AND (6 -le $Computer.length -le 253) -AND ($Computer -match '^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$') ){
                        write-verbose "resolve-dnsname -name $($Computer) -server $($Server) | select -first 1 | select -expand IPAddress" ; 
                        # no -type returns any type matched, regardless of type; mult, the first should be primary
                        $SendIP = resolve-dnsname -name $Computer -ea stop -server $Server | select -first 1 | select -expand IPAddress
                    }  ;
                    # if non IPv4 or IPv6 and computer length is 1-15 chars, and is an nbname matching the input $IPAddress (computer), resolve the name to IPAddress
                    if( -not ($isIPv4 -OR $isIPv6) -AND  (1 -le $Computer.length -le 15) -AND ($Computer -replace '\\|/|:|\*|\?|"||\||\.' -eq $Computer) ){
                        write-verbose "resolve-dnsname -name $($Computer) -ea stop | select -first 1 | select -expand IPAddress" ; 
                        $SendIP = resolve-dnsname -name $Computer -ea stop -server $Server | select -first 1 | select -expand IPAddress
                    }  ;
                    write-verbose "`$SendIP: $($SendIP)" ; 
                } ; 
                $SendAddressfamily = ([ipaddress]$sendip).addressfamily ; # InterNetwork|InterNetworkV6
                # move PTR etc up here, this isn't a 10-limited SenderID check, it's a manual all-encompassing test; may as well always do the queries and populate the values
                if($SendPTR = resolve-dnsname -name $SendIP -type PTR -server $Server){ # pull the -ea STOP , dyns etc won't properly PTR
                    #$SendIPRev = (($SendPTR | select -expand name) -split '.in-addr.')[0] ; 
                }else {
                    $smsg = "UNABLE TO PTR!:resolve-dnsname -name $($SendIP) -type PTR -server $($Server)`n(-> `$SendPTR blank as well)" ; 
                    write-WARNING $smsg ;  
                } ; 
                $SendIPRev = (convert-IPAddressToReverseTDO -IPAddress $SendIP) 
                $smsg = "Resolved:"
                $smsg += "`n`$SendPTR`n$(($SendPTR|out-string).trim())" ; 
                $smsg += "`n`$SendIPRev: $($SendIPRev)" ; 
                write-verbose $smsg ; 

                #endregion Resolve_Information ; #*------^ END Resolve_Information ^------
            } CATCH {
                $ErrTrapd=$Error[0] ;
                $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;
                write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" ;
            } ; 
        } ; 

    } ;  # BEGIN-E
    PROCESS {
        
        if($SpfRec -match '%\{[ivp]}'){ 
             #IP-based tests
             Foreach($Computer in $IPAddress.IPAddressToString ){
                $sBnrS="`n#*------v PROCESSING $($Computer): v------" ; 
                write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($sBnrS)" ;
                
                TRY{
                    #region Macro_Expansion  ; #*------v Macro_Expansion v------
                    $StepNo = 0 ; 

                    if($SpfRec -match '%\{[i]}'){
                        write-verbose "$($StepNo++; $StepNo). Replace %{i} with with sender IP" ; 
                        #$SpfRec = $SpfRec
                        $SpfRec = $SpfRec.replace('%{i}',$SendIP) ; 
                    } 
                    if($SpfRec -match '%\{ir}'){
                        write-verbose "$($StepNo++; $StepNo). reverse the SendBox IP" ; 
                        # moved the math up to central block
                        #$SendPTR = resolve-dnsname -name $SendIP -type PTR  -ea STOP -server $Server ; 
                        #$SendIPRev = (($SendPTR | select -expand name) -split '.in-addr.')[0] ; 
                        write-verbose "$($StepNo++; $StepNo). Replace %{ir} with with reversed sender IP" ; 
                        if($SendPTR -AND $SendIPRev){
                        #$SpfRecResolved = $SpfRec.replace('%{ir}',$SendIPRev) ; 
                        $SpfRec = $SpfRec.replace('%{ir}',$SendIPRev) ; 
                        }else {
                            $smsg = "missing `$SendPTR/`$SendIPRev! Unable to perform macro replace: '%{ir}',`$SendIPRev " ; 
                            write-WARNING $smsg 
                            throw $smsg ; 
                        } ; 
                    } ; 

                    if($SpfRec -match '%\{v}'){
                        write-verbose "$($StepNo++; $StepNo). Replace %{v} with with sender IP version" ; 
                        switch($SendAddressfamily){
                          'InterNetwork' { 
                              write-verbose "$($StepNo++; $StepNo). Replace %{v} with with in-addr for ipv4 IP" ; 
                              $SpfRec = $SpfRec.replace('%{v}','in-addr') 
                          }
                          'InterNetworkV6' {
                              write-verbose "$($StepNo++; $StepNo). Replace %{v} with with ip6 for ipv6 IP" ; 
                              $SpfRec = $SpfRec.replace('%{v}','ip6')
                          }
                        };
                    } ; 

                    if($SpfRec -match '%\{p}'){
                        <# [RFC 7208 - Sender Policy Framework (SPF) for Authorizing Use of Domains in Email, Version 1](https://datatracker.ietf.org/doc/html/rfc7208#section-7)
                            The following macro letters are expanded in term arguments:
                            ...
                            p = the validated domain name of <ip> (do not use) !!!!
                            ...
                        #>
                        <# 	%{p}: The validated reverse-DNS domain of the source IP, 
                            e.g. if example.com IN A is 203.0.113.1 and 1.113.0.203.in-addr.arpa IN PTR is example.com, 
                            the validated domain will be example.com.
                            if 170.92.7.36, sending server IP, resolves as -PTR -> 36.7.92.170.in-addr.arpa

                            [Automating SPF macro management with scripting and APIs: a step-by-step guide - AutoSPF - Automatic SPF flattening](https://autospf.com/blog/automating-spf-macro-management-with-scripting-apis-step-by-step-guide/)
                            %{p}: Represents the validated domain name of the sender’s IP address.

                            ---

                            AI Example:
 
                            If a message is sent from the IP address 192.168.1.100, a reverse DNS lookup 
                            would attempt to find the associated domain name. If the lookup finds that the 
                            domain name "example.com" is associated with that IP address, and the 
                            validation confirms this association, then "example.com" would be the validated 
                            reverse-DNS domain of the source IP

                            Trying to emulate what's described:
                            $ip = '170.92.7.36' ; 
                            $ptr = resolve-dnsname -name $ip -type PTR -server 1.1.1.1 ; 
                            $PTR ; 

                                Name                           Type   TTL   Section    NameHost                                                                                                                                                                 
                                ----                           ----   ---   -------    --------                                                                                                                                                                 
                                36.7.92.170.in-addr.arpa       PTR    86360 Answer     mymailoutlyn0.toro.com  

                            $ARec = resolve-dnsname -name $PTR.Namehost -type A -server 1.1.1.1

                            $ARec

                                Name                                           Type   TTL   Section    IPAddress                                
                                ----                                           ----   ---   -------    ---------                                
                                mymailoutlyn0.toro.com                         A      85036 Answer     170.92.7.36    

                            $Arec.IPAddress

                                170.92.7.36

                            $ptr.NameHost -eq $Arec.Name

                                True

                            if 'Domain Name' means a common ref: DOMAIN.TLD (where in an FQDN the 1st element is the machinename), we could back it out of each as:
                            
                            (($ptr.namehost.split('.') | select -skip 1 ) -join '.')
                            
                                toro.com

                            ($ARec.name.split('.') | select -skip 1 ) -join '.'
                            
                                toro.com

                            Which would Test: 
                            if((($ptr.namehost.split('.') | select -skip 1 ) -join '.') -eq (($ARec.name.split('.') | select -skip 1 ) -join '.')){
                                $SpfRec = $SpfRec.replace('%{p}',(($SendPTR.namehost.split('.') | select -skip 1 ) -join '.')) ; 
                            }


                        #>
                        $smsg = "SPF Record contains Macro '%{p}' which tests SenderIP PTR'd to NameHost,"
                        $smsg += "`nwhich is resolved to a matching -Type A Name,"
                        $smsg += "`nTest is A.Name -eq PTR.NameHost:`n$($SpfRec)" ; 
                        $smsg += "`nRFC 7208 *EXPLICITLY* TAGS: %{p} = the validated domain name of <ip> (*do not use*) " ; 
                        $smsg += "`n(generates excessive DNS queries, deprecated)" ; 
                        write-warning $smsg ; 
                        write-verbose "$($StepNo++; $StepNo). Replace %{p} with SPF sender domain" ; 

                        if($SendPTR){
                            if($ReversedA = resolve-dnsname -name $SendPTR.Namehost -type A -server $Server){
                                # the spec is unclear on what a 'Domain Name' is: 
                                # a) comparing fqdns would be:
                                <#
                                if($SendPTR.NameHost -eq $ReversedA.Name){
                                    $SpfRec = $SpfRec.replace('%{p}',$ReversedA.Name) ;
                                } else {
                                    $smsg = "PTR.Namehost ($($SendPTR.NameHost)) -ne `$ReversedA.Name ($($ReversedA.Name))!" ; 
                                    $smsg = "Fails the 'validated domain name' comparison (doesn't resolve cleanly from PTR back to same A Host)" ; 
                                    write-warning $smsg ;                                
                                } ;  
                                #>
                                # going with the 'DomainName' portion, vs full FQDN.
                                # b) comparing the non-hostname portion of the fqdn as Domain Name would be:
                                if( (($SendPTR.NameHost.split('.') | select -skip 1 ) -join '.') -eq (($ReversedA.Name.split('.') | select -skip 1) -join '.') ){
                                    $SpfRec = $SpfRec.replace('%{p}',(($ReversedA.Name.split('.') | select -skip 1) -join '.') )  ;
                                } else {
                                    $smsg = "PTR.NameHost.DomainName $(($SendPTR.NameHost.split('.') | select -skip 1 ) -join '.') -NE `$ReversedA.Name.DomainName $(($ReversedA.Name.split('.') | select -skip 1) -join '.') !" ; 
                                    $smsg = "Fails the 'validated domain name' comparison (doesn't resolve cleanly from PTR back to same A Host)" ; 
                                    write-warning $smsg ;                                
                                } ; 

                            } else { 
                                $smsg = "Unable to ReverseA the SendPTR.NameHost to an A!" ; 
                                $smsg += "`nresolve-dnsname -name $($SendPTR.Namehost) -type A -server $($Server)" ; 
                                write-warning $smsg ; 
                                throw $smsg ; 
                            } ; 

                            $SpfRec = $SpfRec.replace('%{p}',(($SendPTR.namehost.split('.') | select -skip 1 ) -join '.')) ; 
                        } ; 


                        if(-not $SenderHeloName){
                            $smsg = "$($StepNo++; $StepNo). WARN! No -SenderHeloName specified from which to replace %{p} macros!" ; 
                            write-warning $smsg ; 
                            throw $smsg ; 
                            break ; 
                        } ; 
                    } ; 
                
                } CATCH {
                    $ErrTrapd=$Error[0] ;
                    $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;
                    write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" ;
                } ; 

                write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($sBnrS.replace('-v','-^').replace('v-','^-'))`n" ;
            } ;  # loop-E

        } ; 

        #region SenderAddressDomain_Macros ; #*------v SenderAddressDomain_Macros v------
        #SenderAddress: '%{d}','%{s}','%{s}','%{o}'
        #'%\{d}','%\{s}','%\{s}','%\{o}' :::  '%\{[dslo]}'

        if($SpfRec -match '%\{d}' ){
            write-host -foregroundcolor gray "Note: SPF Record contains SenderAddress-DomainName-related Macros:`n$($SpfRec)" ; 
            write-verbose "$($StepNo++; $StepNo). Replace %{d} with SPF sender domain" ; 
            if(-not $SenderAddress -AND $DomainName){
                write-verbose "$($StepNo++; $StepNo). Replace %{d} with SPF sender DomainName" ; 
                $SpfRec = $SpfRec.replace('%{d}',$DomainName) ; 
            } elseif($SenderAddress){
                write-verbose "$($StepNo++; $StepNo). Replace %{d} with SPF split SenderAddress Domain" ; 
                $SpfRec = $SpfRec.replace('%{d}',($SenderAddress.split('@')[1])) ; 
            } ; 
        } ; 
        #endregion SenderAddressDomain_Macros ; #*------^ END SenderAddressDomain_Macros ^------
        #region SenderAddress_Macros ; #*------vSenderAddress_Macros  v------
        if($SpfRec -match '%\{[slo]}' ){
            write-warning "SPF Record contains SenderAddress-related Macros:`n$($SpfRec)" ; 
            if(-not $SenderAddress){
                $smsg = "$($StepNo++; $StepNo). WARN! No -SenderAddress specified from which to calculate SenderAddres macros!" ; 
                write-warning $smsg ; 
                throw $smsg ; 
                break ; 
            } else {
                write-verbose "$($StepNo++; $StepNo). Replace %{s} with with sender address" ; 
                $SpfRec = $SpfRec.replace('%{s}',$SenderAddress) ; 
                write-verbose "$($StepNo++; $StepNo). Replace %{l} with with SenderAddress local part" ; 
                $SpfRec = $SpfRec.replace('%{l}',$SenderAddress.split('@')[0]) ; 
                write-verbose "$($StepNo++; $StepNo). Replace %{o} with with sender domain" ; 
                $SpfRec = $SpfRec.replace('%{o}',$SenderAddress.split('@')[1]) ; 
            } ; 
        } ; 
        #endregion SenderAddress_Macros ; #*------^ END SenderAddress_Macros ^------
        #region SenderHELOName_Macros ; #*------v SenderHELOName_Macros v------
        if($SpfRec -match '%\{h}'){
            #throw "$($StepNo++; $StepNo). $(SpfRec) contains the %{h} macro (replace HELO name from last conn)`ncannot emulate that state in a vacuum" ; 
            #break ; 
            # $SenderHeloName             
            <#$smsg = "SPF Record specified:" 
            $smsg += "`n$(($SenderAddress|out-string).trim())" ; 
            $smsg += "Includes Sender Server HELO name dependant Macro '%{h}'" ; 
            $smsg += "`n but *no* `$SenderHeloName has been specified!" ; 
            $smsg += "`nPlease retry with a suitable `$SenderHeloName specification"       
            #>
            write-warning "SPF Record contains Sender Server HELO name dependant Macro '%{h}':`n$($SpfRec)" ; 
            write-verbose "$($StepNo++; $StepNo). Replace %{h} with SPF sender domain" ; 
            $SpfRec = $SpfRec.replace('%{h}',$SenderHeloName) ; 
            if(-not $SenderHeloName){
                $smsg = "$($StepNo++; $StepNo). WARN! No -SenderHeloName specified from which to replace %{h} macros!" ; 
                write-warning $smsg ; 
                throw $smsg ; 
                break ; 
            } ; 
        } ; 
        #endregion SenderHELOName_Macros ; #*------^ END SenderHELOName_Macros ^------
        #region UnixTimestamp_Macros ; #*------v UnixTimestamp_Macros v------
        # %{t}: Represents the current timestamp in Unix time.
        if($SpfRec -match '%\{t}'){
            write-warning "SPF Record contains Macro '%{t}' (replace with the current timestamp in Unix time):`n$($SpfRec)" ; 
            write-verbose "$($StepNo++; $StepNo). Replace %{t} with the current timestamp in Unix time" ; 
            $SpfRec = $SpfRec -replace '%{t}', [int][double]::Parse((Get-Date -UFormat %s))
        } ; 
        #endregion UnixTimestamp_Macros ; #*------^ END UnixTimestamp_Macros ^------

        $smsg = "===> Specified `$SpfRecord:" ; 
        $smsg += "`n$(($SpfRecord|out-string).trim())" ; 
        $smsg += "`nhas been resolved to:"
        $smsg += "`n$(($SpfRec|out-string).trim())" ; 
        $smsg += "`n(sending to pipeline)" ; 
        if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 

        $SpfRec | write-output ;


    }  # PROC-E
    END{
        $smsg = "$($sBnr.replace('=v','=^').replace('v=','^='))" ;
        if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
    } ;
}

#*------^ resolve-SPFMacrosTDO.ps1 ^------


#*------v Resolve-SPFRecord.ps1 v------
function Resolve-SPFRecord {
    <#
    .SYNOPSIS
    resolve-SPFRecord.ps1 - This expands the specified domainName's SPF record: 1. Expands any discovered SPF macros, 2. Accumulates all ip[46]: IP specifications; 3. Recursively expands nested include:'s; and 4. Adds expanded IP range specification for 'exists':, 'mx:' & 'a:' mechanisms. Then returns the resulting assembled IP range specifications to the pipeline. 
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
    REVISION
    * 4:28 PM 1/3/2025 finally rounded out, to return full stack of Pass Subnet IP specifications, for post-review and test-IPAddressInRange() checking
    * 2:21 PM 1/2/2025 $DomainName/Name update $Name/Domainname regex to make the CN portion optional (fails toro.com, but has to accomodate recursive include:calls to resolve _spf.salesforce.com)
    * 12:36 PM 12/12/2024 add: alias:Resolve-DNSNameSPF, param alias: $name: 'DomainName', 'Domain'
    * 4:11 PM 12/10/2024 added explicit write-output's, a few w-v's, some comments to make the logic more clear. 
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
    resolve-SPFRecord.ps1 - This expands the specified domainName's SPF record: 1. Expands any discovered SPF macros, 2. Accumulates all ip[46]: IP specifications; 3. Recursively expands nested include:'s; and 4. Adds expanded IP range specification for 'exists':, 'mx:' & 'a:' mechanisms. Then returns the resulting assembled IP range specifications to the pipeline. 
    
    Started from posted, somewhat incomplete code at below (lacked Macro, and range of less common mechanisms, support)

        #-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
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
            - Macros
            - Usage
     
        Optionally, the Server (DNS) parameter can be used. Defaults to cloudflare resolver: 1.1.1.1 (secondary is 1.0.0.1)
        documented here: [Introducing DNS Resolver, 1.1.1.1 (not a joke) - blog.cloudflare.com/](https://blog.cloudflare.com/dns-resolver-1-1-1-1/)
    
        Specify explicit DNS server to be queried. Useful, if you want to test the DNS changes directly on your own root name server shortly after the update, or if there are restrictions on which DNS server your client is allowed to query.
        #-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

    - Added Macro-expansion support (via verb-network\resolve-SpfMacrosTDO()). 
    - added exists:, and sketched in ptr: support pulled core RFC docs that firmly indicate deprecated option 
        
    .PARAMETER Name
    Domain Name[-Name some.tld]
    .PARAMETER Server
    DNS Server to use (defaults to Cloudflare public resolver 1.1.1.1)[-Server 1.0.0.1]
    .PARAMETER Referrer
    If called nested provide a referrer to build valid objects[-Referrer referrer]
    .PARAMETER IPAddress
    OptionalSending server IP Address to be tested against the domain SPF record (required to attempt to expand macros)[-IPAddress 192.168.1.1]
    .PARAMETER SenderAddress
    Optional SenderAddress to use for '%{d}','%{s}','%{s}','%{o}' SenderAddress based macros (required to attempt to expand macros)[-SenderAddress email@domain.tld]
    .PARAMETER RawOutput
    Switch to return the raw resolved strings to the pipeline (vs summary [pscustomobject])
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
    PS> $spfs| ft -a

        SPFSourceDomain               IPAddress               Referrer     Qualifier Include
        ---------------               ---------               --------     --------- -------
        domain.com                    148.163.146.158                      softfail    False
        domain.com                    148.163.142.153                      softfail    False
        domain.com                    170.92.0.0/16                        softfail    False
        spf.protection.outlook.com    40.92.0.0/15            domain.com   fail         True
        spf.protection.outlook.com    40.107.0.0/16           domain.com   fail         True
        spf.protection.outlook.com    52.100.0.0/15           domain.com   fail         True
        spf.protection.outlook.com    52.102.0.0/16           domain.com   fail         True
        spf.protection.outlook.com    52.103.0.0/17           domain.com   fail         True
        spf.protection.outlook.com    104.47.0.0/17           domain.com   fail         True
        spf.protection.outlook.com    2a01:111:f400::/48      domain.com   fail         True
        spf.protection.outlook.com    2a01:111:f403::/49      domain.com   fail         True
        spf.protection.outlook.com    2a01:111:f403:8000::/51 domain.com   fail         True
        spf.protection.outlook.com    2a01:111:f403:c000::/51 domain.com   fail         True
        spf.protection.outlook.com    2a01:111:f403:f000::/52 domain.com   fail         True
        111368.spf10.hubspotemail.net 3.93.157.0/24           domain.com   fail         True
        ...
        111368.spf10.hubspotemail.net 216.139.64.0/19         domain.com   fail         True

    .EXAMPLE
    PS> $spfs = Resolve-SPFRecord -name domain.com ; 
    PS> write-verbose "group referrers" ; 
    PS> $spfs | group referrer | ft -auto count,name ;
     
        Count Name                      
        ----- ----                      
            3                           
            10 domain.com                  
            9 spf.protection.outlook.com

    PS> write-verbose "output ip summary for a specific referrer"
    PS> $spfs|?{$_.Referrer  -eq 'spf.protection.outlook.com'} | ft -auto ipaddress,referrer ; 

        IPAddress                Referrer                  
        ---------                --------                  
        51.4.72.0/24             spf.protection.outlook.com

    Broader example, group/profile returned referrers, dump summaries on referrers
    .EXAMPLE
    PS> write-verbose "Define inputs, and Macro-expansion-dependant specifications" ; 
    PS> $pltDomSpecs = [ordered]@{
    PS>     DomainName = 'bossplow.com' ;
    PS>     IPAddress = '170.92.7.36' ;
    PS>     SenderAddress = 'todd.kadrie@bossplow.com' ;
    PS>     SenderHeloName = 'mymailoutlyn0.toro.com' ;
    PS>     verbose = $true ;
    PS> } ;
    PS> write-verbose "Resolve populated specifications above, and process through Resolve-SPFRecord" ; 
    PS> $mts = $pltDomSpecs.GetEnumerator() | ?{ -NOT ($_.Value -AND $_.value.length)}
    PS> $mts | ForEach-Object { $pltDomSpecs.remove($_.Key) } ;
    PS> write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):Resolve-SPFRecord w`n$(($pltDomSpecs|out-string).trim())" ;
    PS> $results = Resolve-SPFRecord @pltDomSpecs ;
    PS> write-verbose "Process returned results, checking for specified IPAddress above within returned 'pass' subnets : => Approved SPF deliveries for host" ; 
    PS> $PassSubnets = $results.ipaddress ;
    PS> $smsg = "==$($pltDomSpecs.DomainName) expanded SPF returned $($PassSubnets|  measure | select -expand count) 'Pass' subnets" ;
    PS> $smsg += "`n$(($PassSubnets |out-string).trim())" ;
    PS> write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)"  ;
    PS> write-host "Processing the list in order, for IPAddress:$($pltDomSpecs.IPAddress) within each..." ;
    PS> $foundPass = $false ;
    PS> $pltTIpInSub=[ordered]@{
    PS>     IPAddress = $pltDomSpecs.IPAddress ;
    PS>     Range = $null ;
    PS>     Verbose = ($PSBoundParameters['Verbose'] -eq $true)
    PS> } ;
    PS> foreach($subn in $PassSubnets){
    PS>     $smsg = $sBnrS="`n#*------v TESTING $($pltDomSpecs.IPAddress) against:$($subn) v------" ;
    PS>     write-verbose $smsg ; 
    PS>     $pltTIpInSub.Range = $subn ;
    PS>     $smsg = "Test-IPAddressInRange  w`n$(($pltTIpInSub|out-string).trim())" ;
    PS>     if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE }
    PS>     else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
    PS>     if(Test-IPAddressInRange @pltTIpInSub){
    PS>         $foundPass = $true ;
    PS>         $smsg = "==> Matched $($pltDomSpecs.IPAddress) against:$($subn) !" ;
    PS>         write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" ;
    PS>         break ; 
    PS>         write-verbose "rem/remove the break above, to process and report entire list (vs abort at first pass)" ; 
    PS>     }else{
    PS>         $smsg = "(didn't match $($pltDomSpecs.IPAddress) against:$($subn))" ;
    PS>         if($verbose){write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" }  ;
    PS>     }
    PS>     $smsg = "$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;
    PS>     write-verbose $smsg ; 
    PS> } ;     
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://cloudbrothers.info/en/powershell-tip-resolve-spf/
    #>
    #Requires -Modules DnsClient
    [CmdletBinding()]
    [Alias('Resolve-DNSNameSPF')]
    PARAM (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 1,HelpMessage="Domain Name[-Name some.tld]")]
            [ValidateNotNullOrEmpty()]
            #[ValidatePattern("^([-0-9a-zA-Z]+[.])+[a-zA-Z]{2,63}$")] # email domain name restrictions
            #[ValidatePattern("^([-0-9a-zA-Z_]+[.])+([-0-9a-zA-Z]+[.])+[a-zA-Z]{2,63}$")] # DNS -type TXT permits underscores, but not in the DomainName portion on the right 
            # make the CN machinename optional: 
            [ValidatePattern("^((([-0-9a-zA-Z_]+[.])+)*)([-0-9a-zA-Z]+[.])+[a-zA-Z]{2,63}$")] # DNS -type TXT permits underscores, but not in the DomainName portion on the right 
            # Note: -type SRV also permit leading _ on records
            [Alias('DomainName', 'Domain')]
            [string]$Name,
        [Parameter(Mandatory = $false,Position = 2,HelpMessage="DNS Server to use (defaults to Cloudflare public resolver 1.1.1.1)[-Server 1.0.0.1]")]
            [string]$Server = "1.1.1.1",
        [Parameter(Mandatory = $false,HelpMessage="If called nested provide a referrer to build valid objects[-Referrer referrer]")]
            [string]$Referrer,
        [Parameter(Position=0,Mandatory=$false,ValueFromPipeline=$true,
            HelpMessage="OptionalSending server IP Address to be tested against the domain SPF record (required to attempt to expand macros)[-IPAddress 192.168.1.1]")]
            #[ValidateNotNullOrEmpty()]
            [ValidateScript({
                TRY{[system.net.ipaddress]$_}CATCH{throw "non-IP Address!"}
            })]
            [Alias('SenderIPAddress','SenderIP')]
            #[string[]]
            [string]$IPAddress, # =  @($Tormeta.OP_ExEgressIPs + $CMWMeta.OP_ExEgressIPs) ,
        [Parameter(Mandatory=$False,HelpMessage="SenderAddress to use for '%{d}','%{s}','%{l}','%{o}' SenderAddress based macros[-SenderAddress EMAIL@DOMAIN.TLD]")]
            #[ValidateNotNullOrEmpty()]
            [ValidatePattern("^([0-9a-zA-Z]+[-._+&'])*[0-9a-zA-Z]+@([-0-9a-zA-Z]+[.])+[a-zA-Z]{2,63}$")]
            #[Alias('ALIAS1', 'ALIAS2')]
            [string]$SenderAddress,
        [Parameter(Mandatory=$false,HelpMessage="Optional Sending server HELO/EHLO name, to use for '%{h}' macro substitution (should be an FQDN or where Dyn-ip & no PTR, a squarebracketed ip4 ip, or prefixed ip6 ip: [192.0.2.1] or [IPv6:fe80::1]) [-SenderHeloName SERVER.DOMAIN.TLD]")]
            #[ValidateNotNullOrEmpty()] # rgx below matches all three: server.sub.domain.com|[192.0.2.1]|[IPv6:fe80::1]
            [ValidatePattern("^((?=.{1,254}$)(^(?:(?!\d+\.|-)[a-zA-Z0-9_\-]{1,63}(?<!-)\.?)+(?:[a-zA-Z]{2,}))|\[(IPv6:((([0-9A-Fa-f]{1,4}:){1,6}:)|(([0-9A-Fa-f]{1,4}:){7}))([0-9A-Fa-f]{1,4})|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})])$")]
            #[Alias('ALIAS1', 'ALIAS2')]
            [string]$SenderHeloName,
        [Parameter(HelpMessage="Switch to return the raw resolved strings to the pipeline (vs summary [pscustomobject])[-RawOutput")]
            [switch]$RawOutput
    ) ; 
    BEGIN {
        #*======v CLASSES v======
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
        #*======^ END CLASSES ^======

        #region CONSTANTS_AND_ENVIRO #*======v CONSTANTS_AND_ENVIRO v======
        #region ENVIRO_DISCOVER ; #*------v ENVIRO_DISCOVER v------
        $Verbose = ($VerbosePreference -eq 'Continue') ; 
        # Debugger:proxy automatic variables that aren't directly accessible when debugging (must be assigned and read back from another vari) ; 
        $rPSCmdlet = $PSCmdlet ; 
        $rPSScriptRoot = $PSScriptRoot ; 
        $rPSCommandPath = $PSCommandPath ; 
        $rMyInvocation = $MyInvocation ; 
        $rPSBoundParameters = $PSBoundParameters ; 
        [array]$score = @() ; 
        if($rPSCmdlet.MyInvocation.InvocationName){
            if($rPSCmdlet.MyInvocation.InvocationName -match '\.ps1$'){
                $score+= 'ExternalScript' 
            }elseif($rPSCmdlet.MyInvocation.InvocationName  -match '^\.'){
                write-warning "dot-sourced invocation detected!:$($rPSCmdlet.MyInvocation.InvocationName)`n(will be unable to leverage script path etc from MyInvocation objects)" ; 
                # dot sourcing is implicit scripot exec
                $score+= 'ExternalScript' ; 
            } else {$score+= 'Function' };
        } ; 
        if($rPSCmdlet.CommandRuntime){
            if($rPSCmdlet.CommandRuntime.tostring() -match '\.ps1$'){$score+= 'ExternalScript' } else {$score+= 'Function' }
        } ; 
        $score+= $rMyInvocation.MyCommand.commandtype.tostring() ; 
        $grpSrc = $score | group-object -NoElement | sort count ;
        if( ($grpSrc |  measure | select -expand count) -gt 1){
            write-warning  "$score mixed results:$(($grpSrc| ft -a count,name | out-string).trim())" ;
            if($grpSrc[-1].count -eq $grpSrc[-2].count){
                write-warning "Deadlocked non-majority results!" ;
            } else {
                $runSource = $grpSrc | select -last 1 | select -expand name ;
            } ;
        } else {
            write-verbose "consistent results" ;
            $runSource = $grpSrc | select -last 1 | select -expand name ;
        };
        write-verbose  "Calculated `$runSource:$($runSource)" ;
        'score','grpSrc' | get-variable | remove-variable ; # cleanup temp varis
        ${CmdletName} = $rPSCmdlet.MyInvocation.MyCommand.Name ; # function self-name (equiv to script's: $MyInvocation.MyCommand.Path) ;
        #region PsParams ; #*------v PsParams v------
        $PSParameters = New-Object -TypeName PSObject -Property $rPSBoundParameters ;
        write-verbose "`$rPSBoundParameters:`n$(($rPSBoundParameters|out-string).trim())" ;
        # pre psv2, no $rPSBoundParameters autovari to check, so back them out:
        if($rPSCmdlet.MyInvocation.InvocationName){
            if($rPSCmdlet.MyInvocation.InvocationName  -match '^\.'){
                $smsg = "detected dot-sourced invocation: Skipping `$PSCmdlet.MyInvocation.InvocationName-tied cmds..." ; 
                if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
            } else { 
                write-verbose 'Collect all non-default Params (works back to psv2 w CmdletBinding)'
                $ParamsNonDefault = (Get-Command $rPSCmdlet.MyInvocation.InvocationName).parameters | Select-Object -expand keys | Where-Object{$_ -notmatch '(Verbose|Debug|ErrorAction|WarningAction|ErrorVariable|WarningVariable|OutVariable|OutBuffer)'} ;
            } ; 
        } else { 
            $smsg = "(blank `$rPSCmdlet.MyInvocation.InvocationName, skipping Parameters collection)" ; 
            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
        } ; 
        #endregion PsParams ; #*------^ END PsParams ^------
        #endregion ENVIRO_DISCOVER ; #*------^ END ENVIRO_DISCOVER ^------
        # rgx for filtering $rPSBoundParameters for params to pass on in recursive calls (excludes keys matching below)
        $rgxBoundParamsExcl = '^(Name|RawOutput|Server|Referrer)$' ; 

        #region FUNCTIONS ; #*======v FUNCTIONS v======
        
         #*------v Function convert-IPAddressToReverseTDO v------
        if(-not (get-command convert-IPAddressToReverseTDO -ea 0)){
            function convert-IPAddressToReverseTDO {
                <#
                .SYNOPSIS
                Reverse IP Address. 
                .NOTES
                Version     : 0.0.1
                Author      : Todd Kadrie
                Website     : http://www.toddomation.com
                Twitter     : @tostka / http://twitter.com/tostka
                CreatedDate : 2025-01-02
                FileName    : convert-IPAddressToReverseTDO.ps1
                License     : (none asserted)
                Copyright   : (none asserted)
                Github      : https://github.com/tostka/verb-Network
                Tags        : Powershell,TCP,IPAddress
                AddedCredit : REFERENCE
                AddedWebsite: URL
                AddedTwitter: URL
                * 4:44 PM 1/2/2025 replace borked Copilot ipv4 demo (didn't work, as expected, clearly [-1..1] isn't reverse array, it's pull last & first element); 
                    coded in solid ipv6 support (IP reverse process is diff ipv4 & ipv6)
                    ren Reverse-IP -> convert-IPAddressToReverseTDO, alias Reverse-IP
                * 8:58 AM 1/2/2025 generated source via Copilot
                .DESCRIPTION
                Reverse IPAddress Address (ipv4 or ipv6). 

                Was originally cheating my way to the IPv6 reverse by resolving a PTR, and cutting the returned PTR record name at .ipv6', and taking the left half. 
                But [Shortest Script Challenge - Convert IPv6 to nibble format : r/PowerShell](https://www.reddit.com/r/PowerShell/comments/6wcpfv/shortest_script_challenge_convert_ipv6_to_nibble/)
                outlined a series of algos to get to the same thing, wo the PTR resolution step.

                .PARAMETER IPAddress
                The IPAddress address to be used in macro expansion.
                .INPUTS
                None. The script does not accept pipeline input.
                .OUTPUTS
                System.String The Reversed IP Address
                .EXAMPLE
                PS> $IPRev = convert-IPAddressToReverseTDO -ipaddress 192.168.1.1 ; 
                Reverse an IPv4 addres
                .EXAMPLE
                PS> $IPAddress = (resolve-dnsname -name ipv6.google.com | ?{$_.Type -eq 'AAAA'} |select -expand ipaddress) ; 
                PS> $IPRev = convert-IPAddressToReverseTDO  -ipaddress $ipaddress.IPAddressToString ; 
                    
                    Ipv6 address specified:2607:f8b0:4009:817::200e

                PS> $IPRev ; 
                    
                    E.0.0.2.0.0.0.0.0.0.0.0.0.0.0.0.7.1.8.0.9.0.0.4.0.B.8.F.7.0.6.2

                Reverse an IPv6 address
                .LINK
                https://github.com/tostka/verb-Network
                #>    
                [CmdletBinding()]
                [Alias('Reverse-IP')]
                PARAM(
                    [Parameter(Mandatory=$TRUE,HelpMessage="IPAddress (supports ipv4 & ipv6)[-IPAddress 192.168.1.1]")]
                    [system.net.ipaddress]$IPAddress
                ) ; 
                switch($IPAddress.AddressFamily){
                    'InterNetwork' { 
                        write-verbose "Ipv4 address specified:$($IPAddress)" ; 
                        #return ($IPAddress -split '\.')[-1..0] -join '.' ; 
                        # Copilot's algo above didn't work properly :'P [-1..1] doesn't reverse the array, it pulls [last..first]. 
                        $IpParts = $IPAddress -split '\.' ; 
                        [array]::Reverse($IpParts);
                        return ($IpParts -join ".")
                    }
                    'InterNetworkV6' { 
                        write-verbose "Ipv6 address specified:$($IPAddress.IPAddressToString)" ; 
                        <# doing it by pulling a PTR, and cutting the trailing .ip6.. from the returned record Name (select unique)
                        if($resolvedPTR = resolve-dnsname -name $IPAddress.IPAddressToString -type PTR -server 1.1.1.1){
                            return (($resolvedPTR | select -unique name).name  -replace '.ip6.arpa')
                        } else {
                            $smsg = "Unable to:resolve-dnsname -name $($IPAddress.IPAddressToString) -type PTR -server 1.1.1.1!" ; 
                            write-warning $smsg ; 
                            throw $smsg ;
                            return $false ;
                        }; 
                        #>
                        # or doing it using the [Shortest Script Challenge - Convert IPv6 to nibble format : r/PowerShell](https://www.reddit.com/r/PowerShell/comments/6wcpfv/shortest_script_challenge_convert_ipv6_to_nibble/)
                        # param($i)
                        #((([ipaddress]$i)|% GetA*|%{('{0:x2}'-f$_)[0,1]})[31..0]-join'.')+".ip6.arpa"
                        # we don't need the ip6.arpa trailing bit, just the algo to flip the elements.
                        #return ((([ipaddress]$IPAddress.IPAddressToString)|% GetA*|%{('{0:x2}'-f$_)[0,1]})[31..0]-join'.') ; 
                        # expanded a bit, less compressed logic:
                        $i=[bitconverter]::ToString( [IPAddress]::Parse($IPAddress.IPAddressToString).GetAddressBytes()).Replace('-','').ToCharArray() ; 
                        [array]::Reverse($i);
                        return ($i -join ".") # +'.ip6.arpa' 
                        # dropped trailing string from the above linked example: the ip6.arpa is the PTR record name, we just want the reversed ipv6 IP, to use in the %{ir} macro replacements
                    }
                } ; 
            } ; 
        } ; 
        #*------^ END Function convert-IPAddressToReverseTDO ^------

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

        #endregion FUNCTIONS ; #*======^ END FUNCTIONS ^======
               
        $SPFRawAggreg  = @() ; 

        #Aggregate all ip46
        #$aggrIp46Specs = @() ; 
        <# 3:19 PM 1/3/2025 add test support
            Run each as they occur
            '^a:
            '^exists:
            '^mx:
            '^ptr:

            Aggregate results by type, testing against SenderIP/IPAddress/Domain/SenderAddress etc
        #>
        <#
        $aggrATests = @() ; 
        $aggrExistsTests = @() ; 
        $aggrMxTests = @() ; 
        $aggrPtrTests = @() ; 
        #>
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
            <# [The SPF redirect explained - Mailhardener blog](https://www.mailhardener.com/blog/spf-redirect-explained)
                A redirect is a pointer to another domain name that hosts an SPF policy, it 
                allows for multiple domains to share the same SPF policy. It is useful when 
                working with a large amount of domains that share the same email 
                infrastructure

                1: The redirect is not an SPF _mechanism_ it is known as a _modifier_

                    - Modifiers differ in syntax from mechanisms:
 
                        O must always contain a value, as opposed to mechanisms where values are 
                    often optional

                        O have a different key/value separator: modifiers use the equal sign 
                    (=), whereas mechanisms use a colon (:)

                        O do not use a prefix (+, -, ~ or ?)

                        example: the v=spf, at the beginning of the record, is actually 
                            Modifier (based on it's = key/value delimiter)
 
                    - The mechanisms in an SPF record are evaluated from left to right. Since 
                    redirect is not a mechanism, it is always evaluated after the mechanisms, 
                    regardless of where you place it

                        It is therefore recommended, but not required to place the redirect at 
                        the very end of the SPF record, to clarify that it is only used if the 
                        preceding mechanisms didn't match

                2: mechanisms overrule a redirect: The redirect modifier is _only used if no other mechanism matches_

                    - important: the 'all' mechanism *always matches* : So if there is an all 
                    mechanism anywhere in the record, the redirect is *completely ignored*. An SPF 
                    record with a redirect should not contain the all mechanism

                3: redirect changes the domain name:
 
                    - For mechanisms a, mx and ptr the value is optional == If no value is set it 
                    defaults to the current domain

                    - But when a redirect is used, the a, mx or ptr mechanism will point _to 
                    the redirected domain_
 
                4: redirect affects the all mechanism:
 
                    - the redirect modifier will cause the all mechanism of the redirected domain 
                    to be used (because when working with the redirect modifier, the origin domain 
                    is not supposed to have the all modifier set.)
 
                5: redirect retains error state:
 
                    - Normally, if a domain has no SPF record, the SPF evaluation will return a 
                    none error, meaning that the receiver will take a neutral stance in examining 
                    the email

                    - If you redirect to a domain that does not have an SPF policy, or the 
                    SPF policy contains a syntax error, the SPF validation will fail with a 
                    permerror error. This usually results in the email failing SPF validation

                    - With the include mechanism if the included policy does not exist or 
                    contains a syntax error, the evaluation continues. A softerror may be reported 
                    with DMARC, but a sender can still pass SPF validation if it matches any other 
                    mechanism

                6: redirect counts as a DNS query: (counts toward the 10 additional DNS 
                queries limit)
 

            #>
            # WITH A REDIRECT, NO OTHER ITEMS ARE EVALUATED, PROCESSING STOPS HERE, AND THE RECORD IS DROPPED INTO PIPELINE
            if ( $SPFDirectives -match "redirect" ) {
                $RedirectRecord = $SPFDirectives -match "redirect" -replace "redirect=" ; 
                Write-Verbose "[REDIRECT]`t$RedirectRecord" ; 
                # Follow the REDIRECT "include" and resolve the include
                #Resolve-SPFRecord -Name "$RedirectRecord" -Server $Server -Referrer $Name | write-output ; 
                # Resolve-SPFRecord | write-output : leverage $rPSBoundParameters post-filtered instead
                if($rPSBoundParameters){
                        $pltRvSPFRec = [ordered]@{} ;
                        # add the specific Name for this call, and Server spec (which defaults, is generally not 
                        $pltRvSPFRec.add('Name',"$RedirectRecord" ) ;
                        $pltRvSPFRec.add('Referrer',$Name) ; 
                        $pltRvSPFRec.add('Server',$Server ) ;
                        $rPSBoundParameters.GetEnumerator() | ?{ $_.key -notmatch $rgxBoundParamsExcl} | foreach-object { $pltRvSPFRec.add($_.key,$_.value)  } ;
                        write-host "Resolve-SPFRecord w`n$(($pltRvSPFRec|out-string).trim())" ;
                        Resolve-SPFRecord @pltRvSPFRec  | write-output ;
                } else {
                    $smsg = "unpopulated `$rPSBoundParameters!" ;
                    write-warning $smsg ;
                    throw $smsg ;
                }; 
            } else {
                # Extract the qualifier
                $Qualifier = switch ( $SPFDirectives -match "^[+-?~]all$" -replace "all" ) {
                    "+" { "pass" }
                    "-" { "fail" }
                    "~" { "softfail" }
                    "?" { "neutral" }
                } ; 
                write-verbose "detected Qualifier:$($Qualifier)" ; 

                # precheck for IP-tied DNS pre-expansions on $IPAddress
                # use $spfRec for resolve-spfMacrosTDO()
                # use $SPFString for resolve-SPfRecord()
                if(($SPFString -match '%\{[ivp]}') -OR ($SPFString -match 'ptr:')){
                    write-verbose "$($SPFString):IP-dependant Tests found:Doing IP-test DNS transforms" ;

                    #region Resolve_Information ; #*------v Resolve_Information v------
                    $isIPv4 = $isIPv6 = $isFQDN = $isNBName = $false ; 
                    $SendNameHost = $ComputerARec =  $SendIP =  $SendPTR =  $SendIPRev =  $SendAddressfamily = $null ; 
                    # string
                    $Computer = $IPAddress ; 
                    #ipaddr
                    #$Computer = $IPAddress.IPAddressToString
                    TRY{
                        # for [string] IP spec
                        $SendAddressfamily = ([ipaddress]$IPAddress).addressfamily ; # InterNetwork|InterNetworkV6
                        # for [ipaddress] IP spec
                        #$SendAddressfamily = $IPAddress.addressfamily ; # InterNetwork|InterNetworkV6
                        switch($SendAddressfamily){
                            'InterNetwork' { $isIpv4 = $true  }
                            'InterNetworkV6' { $isIPv6 = $true  }
                        }
                    } CATCH {
                        $ErrTrapd=$Error[0] ;
                        $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;
                        write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" ;
                    } ;

                    if( -not ($isIPv4 -OR $isIPv6) -AND (6 -le $Computer.length -le 253) -AND ($Computer -match '^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$') ){
                        $isFQDN = $true ; 
                    }  ;
                    <#[ValidateLength(1, 15)]
                    [ValidateScript({$PSItem -replace '\\|/|:|\*|\?|"||\||\.' -eq $PSItem})]
                    #>
                    if( -not ($isIPv4 -OR $isIPv6) -AND  (1 -le $Computer.length -le 15) -AND ($Computer -replace '\\|/|:|\*|\?|"||\||\.' -eq $Computer) ){
                        $isNBName = $true ; 
                    }  ;
                    #$Computer = 'NAME.SUB.DOMAIN.com' ; 
                    #$SenderAddress = 'SENDER@DOMAIN.com' ; 
                    TRY{
                        $cachedName = $null ; 
                        $cachedName = $Computer ; 
                        if($isIPv4 -OR $isIPv6){
                            write-verbose "Resolve IP to FQDN (PTR): `nresolve-dnsname -name $($Computer) -type PTR -ea STOP -server $($Server) | select -expand namehost" ; 
                            $SendNameHost = $Computer = resolve-dnsname -name $Computer -type PTR -ea STOP -server $Server | select -expand namehost; 
                        } ; 
                        if($isNBName){
                            write-verbose "Resolve NBName to FQDN (A): `nresolve-dnsname -name $($Computer) -type A -ea STOP -server $($Server)| select -expand Name" ; 
                            $SendNameHost = $Computer = resolve-dnsname -name $Computer -type A -ea STOP -server $Server | select -expand Name
                        } ; 
            
                        write-verbose "Resolve IP A Record: resolve-dnsname -name $($Computer) -type A: `nresolve-dnsname -name $($Computer) -type A  -server $($Server) -ea STOP | select -first 1 " ; 
                        TRY{
                            #$ComputerARec = resolve-dnsname -name $Computer -type A  -ea STOP -server $Server | select -first 1  ; 
                            $ComputerARec = resolve-dnsname -name $SendNameHost  -type A  -ea STOP -server $Server | select -first 1  ; 
                            write-host -foregroundcolor green "Resolved $($SendNameHost ) A Record:`n$(($ComputerARec|out-string).trim())" ; 
                            $SendIP = $ComputerARec.IPAddress ; 
                            write-verbose "`$SendIP: $($SendIP)" ; 
                        }CATCH{
                            $smsg = "Failed to:resolve-dnsname -name $($Computer) -type A " ; 
                            $smsg += "`nFalling back to original cached identifier: $($cachedName)" ; 
                            $smsg += "`n and reattempting resolution of that value" ; 
                            write-warning $smsg ; 
                            $ComputerARec = $null ; 
                            $Computer = $cachedName  ; 
                            if($isIPv4 -OR $isIPv6){$SendIP = $cachedName} ; 
                            # if non IPv4 or IPv6 and computer length is 6-253 chars, and is an fqdn, resolve fqdn to IPaddress
                            if( -not ($isIPv4 -OR $isIPv6) -AND (6 -le $Computer.length -le 253) -AND ($Computer -match '^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$') ){
                                write-verbose "resolve-dnsname -name $($Computer) -server $($Server) | select -first 1 | select -expand IPAddress" ; 
                                # no -type returns any type matched, regardless of type; mult, the first should be primary
                                $SendIP = resolve-dnsname -name $Computer -ea stop -server $Server | select -first 1 | select -expand IPAddress
                            }  ;
                            # if non IPv4 or IPv6 and computer length is 1-15 chars, and is an nbname matching the input $IPAddress (computer), resolve the name to IPAddress
                            if( -not ($isIPv4 -OR $isIPv6) -AND  (1 -le $Computer.length -le 15) -AND ($Computer -replace '\\|/|:|\*|\?|"||\||\.' -eq $Computer) ){
                                write-verbose "resolve-dnsname -name $($Computer) -ea stop | select -first 1 | select -expand IPAddress" ; 
                                $SendIP = resolve-dnsname -name $Computer -ea stop -server $Server | select -first 1 | select -expand IPAddress
                            }  ;
                            write-verbose "`$SendIP: $($SendIP)" ; 
                        } ; 
                        $SendAddressfamily = ([ipaddress]$sendip).addressfamily ; # InterNetwork|InterNetworkV6
                        # move PTR etc up here, this isn't a 10-limited SenderID check, it's a manual all-encompassing test; may as well always do the queries and populate the values
                        if($SendPTR = resolve-dnsname -name $SendIP -type PTR -server $Server){ # pull the -ea STOP , dyns etc won't properly PTR
                            #$SendIPRev = (($SendPTR | select -expand name) -split '.in-addr.')[0] ; 
                        }else {
                            $smsg = "UNABLE TO PTR!:resolve-dnsname -name $($SendIP) -type PTR -server $($Server)`n(-> `$SendPTR blank as well)" ; 
                            write-WARNING $smsg ;  
                        } ; 
                        $SendIPRev = (convert-IPAddressToReverseTDO -IPAddress $SendIP) 
                        $smsg = "Resolved:"
                        $smsg += "`n`$SendPTR`n$(($SendPTR|out-string).trim())" ; 
                        $smsg += "`n`$SendIPRev: $($SendIPRev)" ; 
                        write-verbose $smsg ;

                        #endregion Resolve_Information ; #*------^ END Resolve_Information ^------
                    } CATCH {
                        $ErrTrapd=$Error[0] ;
                        $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;
                        write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" ;
                    } ; 
                } ; 

                write-host -foregroundcolor green "Processing SPFDirectives:`n$(($SPFDirectives|out-string).trim())" ; 
                $hasMacros = $false ; 
                $ReturnValues = foreach ($SPFDirective in $SPFDirectives) {
                    write-verbose "process:$($SPFDirective)" ; 
                    if($SPFDirective -eq 'include:_spf.salesforce.com'){
                        write-verbose "gotcha!" ; 
                    } ;
                    switch -Regex ($SPFDirective) {
                        # 9:59 AM 8/13/2021 add case for version spec, otherwise it throws:WARNING: [v=spf1]	 Unknown directive
                        "v=spf\d" {
                            write-verbose "Spf Version modifier: $($SPFDirective)" ;
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
                            <#
                                macro syntax %{a} etc
                                rplace each %{x} with approp resolved submitter info (ip, rev IP, SenderAddress, SenderDomainName, HeloHostname)
                                before running any directive
                                this is being examined 3rd, after v=spf & all
                            #>
                            if( get-command -name resolve-SPFMacrosTDO -ea 0){
                                $hasMacros = $true ; 
                                # deps check
                                # $IPAddress
                                if($SPFDirective -match '%\{[ivp]}'){
                                    if(-not $IPAddress){
                                        $smsg = "SPF Directive specified:"
                                        $smsg += "`n$(($SPFDirective|out-string).trim())" ;
                                        $smsg += "Includes IPAddress-dependant Macros '%{i}','%{ir}','%{v}','%{p}'" ;
                                        $smsg += "`n but *no* `$IPAddress has been specified!" ;
                                        #$smsg += "`nPlease retry with a suitable `$IPAddress specification"
                                        $smsg += "`nPrompting for an address" ;
                                        $smsg = "" ;
                                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Prompt }
                                        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                        #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                                        #throw $smsg ;
                                        #BREAK ;
                                        $IPAddress = Read-Host "Specify a suitable IPAddress for '%{i}','%{iv}','%{p}' expansion" ;
                                    } else{
                                        write-verbose  "SPF Directive specified:Includes IPAddress-dependant Macros '%{i}','%{ir}','%{v}','%{p}', and an `$IPAddress has been specified ($($IPAddress.IPAddressToString))" ;
                                        #$smsg = "`n`n==Processing:`$IPAddress:`n$(($IPAddress.IPAddressToString|out-string).trim())" ;
                                        # ip in this func is a string, not [ipaddress]
                                        $smsg = "`n`n==Processing:`$IPAddress:`n$($IPAddress)" ;
                                        $smsg += "`nagainst DomainName: $($DomainName)`n`n" ;
                                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
                                        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                                    } ;
                                };
                                # $SenderAddress
                                if($SPFDirective -match '%\{[dslo]}'){
                                    if(-not $SenderAddress){
                                        $smsg = "SPF Directive specified:"
                                        $smsg += "`n$(($SPFDirective|out-string).trim())" ;
                                        $smsg += "Includes SenderAddress-dependant Macros '%{d}','%{s}','%{l}','%{o}'" ;
                                        $smsg += "`n but *no* `$SenderAddress has been specified!" ;
                                        #$smsg += "`nPlease retry with a suitable `$SenderAddress specification"
                                        $smsg += "`nPrompting for an address" ;
                                        #throw $smsg ;
                                        #BREAK ;
                                        $SenderAddress = Read-Host "Specify a suitable SenderAddress for '%{d}','%{s}','%{l}','%{o}' expansion" ;
                                    } else{
                                        write-verbose  "SPF Directive specified:Includes SenderAddress-dependant Macros '%{d}','%{s}','%{l}','%{o}', and a `$SenderAddress has been specified ($($SenderAddress))" ;
                                    } ;
                                };
                                # $SenderHeloName
                                if($SPFDirective -match '%\{[h]}'){
                                    if(-not $SenderHeloName){
                                        $smsg = "SPF Directive specified:"
                                        $smsg += "`n$(($SPFDirective|out-string).trim())" ;
                                        $smsg += "Includes Sender Server HELO name dependant Macro '%{h}'" ;
                                        $smsg += "`n but *no* `$SenderHeloName has been specified!" ;
                                        #$smsg += "`nPlease retry with a suitable `$SenderHeloName specification"
                                        $smsg += "`nPrompting for an address" ;
                                        #throw $smsg ;
                                        #BREAK ;
                                        $SenderHeloName = Read-Host "Specify a suitable SenderHeloName for '%{h}' expansion" ;
                                    } else{
                                        write-verbose  "SPF Directive specified:Includes Sender Server HELO name dependant Macro '%{h}', and a `$SenderHeloName has been specified ($($SenderHeloName))" ;
                                    } ;
                                }; 
                                <#$pltDomSpecs = [ordered]@{
                                    SpfRecord = $SPFDirective ; 
                                    DomainName = $Name ;
                                    IPAddress = $IPAddress ;
                                    SenderAddress = $SenderAddress ;
                                    SenderHeloName = $SenderHeloName ;
                                    Verbose = $($PSBoundParameters['Verbose'] -eq $true) ; 
                                    #Verbose = $($PSBoundParameters.Verbose -eq $true) ;
                                } ;
                                $mts = $pltDomSpecs.GetEnumerator() | ?{ -NOT ($_.Value -AND $_.value.length)} 
                                $mts | ForEach-Object { $pltDomSpecs.remove($_.Key) } ; 
                                write-host -foregroundcolor green "resolve-SPFMacros w`n$(($pltDomSpecs|out-string).trim())" ; 
                                #>
                                # resolve-SPFMacros call: build splat on filtered $rPSBoundParameters
                                if($rPSBoundParameters){
                                      $pltRvSPFMacr = [ordered]@{} ; 
                                      # add the specific domainname for this call
                                      $pltRvSPFMacr.add('DomainName',$Name) ;
                                      $pltRvSPFMacr.add('SpfRecord',$SPFDirective) ;
                                      $rPSBoundParameters.GetEnumerator() | ?{ $_.key -notmatch $rgxBoundParamsExcl} | foreach-object { $pltRvSPFMacr.add($_.key,$_.value)  } ;
                                      write-host -foregroundcolor green "resolve-SPFMacros w`n$(($pltRvSPFMacr|out-string).trim())" ; 
                                      $SPFDirective = resolve-SPFMacros @pltRvSPFMacr  ;
                                } else {
                                    $smsg = "unpopulated `$rPSBoundParameters!" ; 
                                    write-warning $smsg ; 
                                    throw $smsg ; 
                                }; 
                            }else {
                                Write-Warning "[$_]`tMacro sytax detected:Macros validation/expansion is not supported by this function. For more information, see https://tools.ietf.org/html/rfc7208#section-7" ;  
                                Continue ; 
                            } ; 
                        }
                        
                        
                        "^exp:.*$" {
                            Write-Warning "[$_]`texp: Explanation syntax detected:Explanation validation/expansion is not supported by this function. For more information, see https://tools.ietf.org/html/rfc7208#section-6.2" ; 
                            Continue ; 
                        }
                        '^include:.*$' {
                            # Follow the include and resolve the include
                            Write-Verbose "[include]`tSPF entry: $SPFDirective (recursing)" ; 
                            #Resolve-SPFRecord -Name ( $SPFDirective -replace "^include:" ) -Server $Server -Referrer $Name | write-output ; 
                            # Resolve-SPFRecord | write-output : leverage $rPSBoundParameters post-filtered instead
                            if($rPSBoundParameters){
                                    $pltRvSPFRec = [ordered]@{} ;
                                    # add the specific Name for this call, and Server spec (which defaults, is generally not 
                                    $pltRvSPFRec.add('Name',( $SPFDirective -replace "^include:" ) ) ;
                                    $pltRvSPFRec.add('Referrer',$Name) ; 
                                    $pltRvSPFRec.add('Server',$Server ) ;
                                    $rPSBoundParameters.GetEnumerator() | ?{ $_.key -notmatch $rgxBoundParamsExcl} | foreach-object { $pltRvSPFRec.add($_.key,$_.value)  } ;
                                    write-host "Resolve-SPFRecord w`n$(($pltRvSPFRec|out-string).trim())" ;
                                    Resolve-SPFRecord @pltRvSPFRec  | write-output ;
                            } else {
                                $smsg = "unpopulated `$rPSBoundParameters!" ;
                                write-warning $smsg ;
                                throw $smsg ;
                            }; 
                        }
                        '^ip[46]:.*$' {
                            Write-Verbose "[IP]`tSPF entry: $SPFDirective" ; 
                            $SPFObject = [SPFRecord]::New( ($SPFDirective -replace "^ip[46]:"), $Name, $Qualifier) ; 
                            #if ( $PSBoundParameters.ContainsKey('Referrer') ) {
                            if ( $PSParameters.psobject.Properties.name -contains 'Referrer' ) {
                                $SPFObject.Referrer = $Referrer ; 
                                $SPFObject.Include = $true ; 
                            } ; 
                            <# just do subnets & other raw IP aggregates into the stack, no active local tests)
                            $subSpec = [ordered]@{
                                Subnet = ($SPFDirective -replace "^ip[46]:")
                                Name = $Name ; 
                                Qualifier = $Qualifier ; 
                                SenderPassed = $null ; 
                            } ; 
                            if ( $PSParameters.psobject.Properties.name -contains 'Referrer' ) {
                                $subSpec.add('Referrer',$Referrer) ; 
                                $subSpec.add('Include',$true) ; 
                            } ; 
                            #$aggrIp46Specs += [pscustomobject]$subSpec ; 
                            #>

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
                                        write-host -foregroundcolor green "`n$($smsg)" ; 
                                    } ; 
                                } else {
                                    write-warning "invalid IP specification:$($ret.type) is unsupported format" ;
                                } ;       
                            } else { 
                                write-warning "invalid IP specification:$($SPFDirective.replace('ip4:',''))" ;
                            } ; 

                            # do a test Test-IPAddressInRange agains the $SenderIP, now NOPE
                            <#
                            PS> if(Test-IPAddressInRange -IPAddress "2001:0db8:85.4.0000:0000:8a2e:0370:7334" -Range "2001:0db8:85a3::/48" -verbose){
                            PS>     write-host -foregroundcolor green  "is in range!" 
                            PS> } else { write-host -foregroundcolor yellow "Is NOT in range"} ;
                            #>
                            <# skip, we're appending the discovered A's into the stack for later SenderIP compaire
                            if(Test-IPAddressInRange -IPAddress $IPAddress -Range $subSpec.Subnet -Verbose:($PSBoundParameters['Verbose'] -eq $true)){
                                $subSpec.SenderPassed = $true ; 
                            }else{
                                $subSpec.SenderPassed = $false ; 
                            }
                            $aggrIp46Specs += [pscustomobject]$subSpec ; 
                            #>

                            $SPFObject | write-output  ; 
                        } 
                        '^a:.*$' {
                            <#
                                The "a" mechanism 
                                a
                                a/<prefix-length>
                                a:<domain>
                                a:<domain>/<prefix-length>
                                All the A records for domain are tested. If the client IP is found among them, 
                                this mechanism matches. If the connection is made over IPv6, then an AAAA 
                                lookup is performed instead. 
                                If domain is not specified, the current-domain is used. 
                                The A records have to match the client IP 
                                exactly, unless a prefix-length is provided, in which case each IP address 
                                returned by the A lookup will be expanded to its corresponding CIDR prefix, and 
                                the client IP will be sought within that subnet.                                 
                            #>
                            Write-Verbose "[A]`tSPF entry: $SPFDirective"
                            $DNSRecords = Resolve-DnsName -Server $Server -Name $Name -Type A ; 
                            # Check SPF record
                            foreach ($IPAddress in ($DNSRecords.IPAddress) ) {
                                $SPFObject = [SPFRecord]::New( $IPAddress, ($SPFDirective -replace "^a:"), $Qualifier) ; 
                                #if ( $PSBoundParameters.ContainsKey('Referrer') ) {
                                if ( $PSParameters.psobject.Properties.name -contains 'Referrer' ) {
                                    $SPFObject.Referrer = $Referrer ; 
                                    $SPFObject.Include = $true ; 
                                }
                                
                                $SPFObject | write-output  ; 
                            } ;  # loop-E
                        }
                        '^exists:.*$' {
                             <#
                                The "exists" mechanism (edit)
                                exists:<domain>
                                Perform an A query on the provided domain. If a result is found, this constitutes a match. It doesn't matter what the lookup result is – it could be 127.0.0.2.
                                When you use macros with this mechanism, you can perform RBL-style reversed-IP lookups, or set up per-user exceptions.
                            #>
                            # as macro replace occurs first, before mechanisms, any macros should already be swapped by the time it gets to here
                            Write-Verbose "[A]`tSPF entry: $SPFDirective"
                            # this is a simple: $DNSRecords = Resolve-DnsName -Name ( $SPFDirective -replace "^exists:" ) -Server $Server $Name -Type A ; 
                            # *not* a run back through Resolve-SpfRecord() (which only does Type TXT SPF explicit processing)
                            <#
                            #$DNSRecords = Resolve-DnsName -Server $Server -Name $Name -Type A ; 
                            #$DNSRecords = Resolve-SPFRecord -Name ( $SPFDirective -replace "^exists:" ) -Server $Server -Referrer $Name | write-output ; 
                            #$DNSRecords = Resolve-SPFRecord -Name ( $SPFDirective -replace "^exists:" ) -Server $Server -Referrer $Referrer | write-output ; 
                            #$DNSRecords = Resolve-SPFRecord -Name ( $SPFDirective -replace "^exists:" ) -Type A -Server $Server -Referrer $Referrer 
                            # $DNSRecords = Resolve-SPFRecord : leverage $rPSBoundParameters post-filtered instead
                            if($rPSBoundParameters){
                                    $pltRvSPFRec = [ordered]@{} ;
                                    # add the specific Name for this call, and Server spec (which defaults, is generally not
                                    $pltRvSPFRec.add('Name',( $SPFDirective -replace "^exists:" ) ) ;
                                     $pltRvSPFRec.add('Type','A') ; 
                                    $pltRvSPFRec.add('Referrer',$Name) ;
                                    $pltRvSPFRec.add('Server',$Server ) ;
                                    $rPSBoundParameters.GetEnumerator() | ?{ $_.key -notmatch $rgxBoundParamsExcl} | foreach-object { $pltRvSPFRec.add($_.key,$_.value)  } ;
                                    write-host "Resolve-SPFRecord w`n$(($pltRvSPFRec|out-string).trim())" ;
                                    $DNSRecords = Resolve-SPFRecord @pltRvSPFRec ;
                                    # Resolve-SPFRecord isn't written to do -Type (A); have to do directly
                            } else {
                                $smsg = "unpopulated `$rPSBoundParameters!" ;
                                write-warning $smsg ;
                                throw $smsg ;
                            };
                            #>

                            $pltRvDNSName=[ordered]@{
                                Name = ( $SPFDirective -replace "^exists:" ) ;
                                Server = $Server ;
                                Type = 'A' ;                                
                                erroraction = 'silentlycontinue' ; # flip to silentlycontinue - let it drop, they'll frequently not be present
                            } ;
                            $smsg = "Resolve-DnsName w`n$(($pltRvDNSName|out-string).trim())" ; 
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                            #$DNSRecords = Resolve-DnsName -Name ( $SPFDirective -replace "^exists:" ) -Server $Server $Name -Type A ; 
                            $DNSRecords = Resolve-DnsName @pltRvDNSName ; 

                            <## Check SPF record
                            foreach ($IPAddress in ($DNSRecords.IPAddress) ) {
                                $SPFObject = [SPFRecord]::New( $IPAddress, ($SPFDirective -replace "^a:"), $Qualifier) ; 
                                #if ( $PSBoundParameters.ContainsKey('Referrer') ) {
                                if ( $PSParameters.psobject.Properties.name -contains 'Referrer' ) {
                                    $SPFObject.Referrer = $Referrer ; 
                                    $SPFObject.Include = $true ; 
                                }
                                
                                $SPFObject | write-output  ; 
                            } ;  # loop-E
                            #>
                            if($DNSRecords){
                                # hit on the exists: pass - add the IPAddress, Directive & Qualifier into the returned SPfObject (will be avail to match with the SenderIP later)
                                $SPFObject = [SPFRecord]::New( $IPAddress, ($SPFDirective -replace "^exists:"), $Qualifier) ; 
                                #if ( $PSBoundParameters.ContainsKey('Referrer') ) {
                                if ( $PSParameters.psobject.Properties.name -contains 'Referrer' ) {
                                    $SPFObject.Referrer = $Referrer ; 
                                    $SPFObject.Include = $true ; 
                                }
                                
                                $SPFObject | write-output  ;
                            } else {
                                # fail on the A: fail
                            } ; 
                        }
                        '^mx:.*$' {
                            <#
                                The "mx" mechanism (edit)
                                mx
                                mx/<prefix-length>
                                mx:<domain>
                                mx:<domain>/<prefix-length>
                                All the A records for all the MX records for domain are tested in order of MX priority. If the client IP is found among them, this mechanism matches.
                                If domain is not specified, the current-domain is used.
                                The A records have to match the client IP exactly, unless a prefix-length is provided, in which case each IP address returned by the A lookup will be expanded to its corresponding CIDR prefix, and the client IP will be sought within that subnet.
                            #>
                            Write-Verbose "[MX]`tSPF entry: $SPFDirective" ; 
                            $DNSRecords = Resolve-DnsName -Server $Server -Name $Name -Type MX ; 
                            # same as the A: & exists: discoveries: append the discovered IPAddress, Directive, and Qualifier into the SenderIP eval stack
                            foreach ($MXRecords in ($DNSRecords.NameExchange) ) {
                                # Check SPF record
                                $DNSRecords = Resolve-DnsName -Server $Server -Name $MXRecords -Type A ; 
                                foreach ($IPAddress in ($DNSRecords.IPAddress) ) {
                                    $SPFObject = [SPFRecord]::New( $IPAddress, ($SPFDirective -replace "^mx:"), $Qualifier) ; 
                                    #if ( $PSBoundParameters.ContainsKey('Referrer') ) {
                                    if ( $PSParameters.psobject.Properties.name -contains 'Referrer' ) {
                                        $SPFObject.Referrer = $Referrer ; 
                                        $SPFObject.Include = $true ; 
                                    } ; 
                                    
                                   $SPFObject | write-output  ; 
                                } ; 
                            } ; 
                        }
                        '^ptr:.*$' {
                            <#
                                The "ptr" mechanism
                                ptr
                                ptr:<domain>
                                The hostname or hostnames for the client IP are looked up using PTR queries. 
                                The hostnames are then validated: at least one of the A records for a PTR 
                                hostname must match the original client IP. Invalid hostnames are discarded. If 
                                a valid hostname ends in domain, this mechanism matches. 
                                If domain is not specified, the current-domain is used.
                                If at all possible, you should avoid using this mechanism in your SPF record, because it will result in a larger number of expensive DNS lookups.

                                [PTR mechanisms in SPF records - dmarcian](https://dmarcian.com/ptr-mechanisms-in-spf-records/)
                                When an email receiver gets a piece of email and the PTR mechanism is in the 
                                sender's SPF record, the receiver will look at the incoming IP address and do a 
                                "PTR" lookup

                                For example, if the sender is sending email from IP address 1.2.3.4, the 
                                receiver will perform a PTR lookup of 1.2.3.4 to attempt to retrieve a hostname.
                                 Lastly, if a hostname is discovered for IP address 1.2.3.4, then 
                                that hostname's domain is compared to the domain that was originally used to 
                                lookup the SPF record. 

                                The PTR mechanism has been deprecated.  See the relevant RFC for more info

                                The SPF Surveyor cannot resolve PTR mechanisms because a real 
                                connection from a real sender is necessary to complete the lookup

                                MOST IMPORTANTLY: Some large receivers will skip the mechanism – or 
                                worse they'll skip the entire SPF record – because such mechanisms cannot be 
                                easily cached.  Imagine a large receiver doing a PTR lookup for millions of 
                                different connections… the size of the local cache explodes. 

                            #>
                            Write-Warning "[$_]`tptr: PTR syntax detected:PTR validation/expansion is not supported by this function (and is DEPRECATED UNDER RFC). For more information, see https://tools.ietf.org/html/rfc7208#section-6.2" ; 
                            Continue ;
                        }
                        Default {
                            Write-Warning "[$_]`t Unknown directive" ; 
                        }
                    } ; 
                } ; 
                # 3:40 PM 12/30/2024 actually, macro's get replcd in mechanisms/directives *before* running the test, so I updated the SpfDirective above, and assigned it back to itself 
                # below should be unnecc
                <#
                if($hasMacros){
                    write-host -foregroundcolor yellow "SPF Macros detected, running test-SPFMacroSpecificationTDO() expansion attempt" ; 
                    # #test-SPFMacroSpecificationTDO -SpfRecord -DomainName -SenderAddress -IPAddress
                    $pltRvSPFMacros=[ordered]@{
                        SpfRecord = $ReturnValues  # need to reformat these to the raw entries
                        DomainName = $Name ; 
                        #Verbose = ($PSBoundParameters['Verbose'] -eq $true)
                        Verbose = $($PSParameters.verbose -eq $true)
                        erroraction = 'STOP' ;
                        whatif = $($whatif) ;
                    } ;
                    if($SenderAddress){
                        $pltRvSPFMacros.add('SenderAddress',$SenderAddress) ; 
                    } ; 
                    if($IPAddress){
                        $pltRvSPFMacros.add('IPAddress',$IPAddress) ; 
                    } ; 
                    $smsg = "test-SPFMacroSpecificationTDO w`n$(($pltRvSPFMacros|out-string).trim())" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                    $ReturnValues += @(
                        test-SPFMacroSpecificationTDO @pltRvSPFMacros ; 
                    ); 
                } ; 
                #>
                $DNSQuerySum = $ReturnValues | Select-Object -Unique SPFSourceDomain | Measure-Object | Select-Object -ExpandProperty Count ; 
                if ( $DNSQuerySum -le 6) {
                    write-host -foregroundcolor yellow "($DNSQuerySum) DNS queries made  (Must not exceed 10 DNS queries)." ; 
                }elseif ( $DNSQuerySum -gt 6) {
                    Write-Warning "Watch your includes!`nThe maximum number of DNS queries is 10 and you have already $DNSQuerySum.`nCheck https://tools.ietf.org/html/rfc7208#section-4.6.4" ; 
                } ; 
                if ( $DNSQuerySum -gt 10) {
                    Write-Error "Too many DNS queries made ($DNSQuerySum).`nMust not exceed 10 DNS queries.`nCheck https://tools.ietf.org/html/rfc7208#section-4.6.4" ; 
                } ; 

                if($RawOutput){
                    foreach ($dir in $returnvalues){
                        if($dir.IPAddress){
                            if($dir.IPAddress.contains('.')){
                                $SPFRawAggreg += "ip4:$($dir.IPAddress)" ;
                            }elseif($dir.IPAddress.contains(':')){
                               $SPFRawAggreg += "ip6:$($dir.IPAddress)" ;
                            } ; 
                        } ;
                    } ; 
                    $SPFRawAggreg += switch ($Qualifier){
                        "pass" { '+all'}
                        "fail" { '-all'}
                        "softfail" { '~all'}
                        "neutral" { '?all'}
                    } ; 
                    #$SPFRawAggreg -join " " | write-output  ; 
                    # either output unwrapped ^ or as is as an array:
                    $SPFRawAggreg | write-output  ; 
                } else { 
                    $ReturnValues | write-output ; 
                } ; 
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
    * 3:02 PM 1/12/2024 fix non-unique param Position (3): 
    * 3:58 PM 3/7/2023 revalidated choco works with discovery;  rem'd out prior 
    path<file/dir code - it's not used with explicit params ; seems to work; fliped 
    the iwr's to use splats; the redir resolve also relies on -ea 0, not STOP or it 
    fails; ; rounded out, added missing code to detect successful first dl attempt. 
    * 2:56 PM 3/3/2023 finally generated throttling '(429) Too Many Requests.' from choco. 
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
        [Parameter(Mandatory=$false,Position=3,
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
        * 1:56 PM 5/25/2025 add: regions outter brackets;  ps> prefixed expls; indented params; updated local ex detect code; added pretest for gcm get-exchangeserver, before trying;  tightened up
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
          
        # Underlying available send-mailmessage params: (set up param aliases)
        Send-MailMessage [-To] <String[]> [-Subject] <String> [[-Body] <String>] [[-SmtpServer] <String>] [-Attachments
        <String[]>] [-Bcc <String[]>] [-BodyAsHtml] [-Cc <String[]>] [-Credential <PSCredential>]
        [-DeliveryNotificationOption <DeliveryNotificationOptions>] [-Encoding <Encoding>] [-Port <Int32>] [-Priority
        <MailPriority>] [-UseSsl] -From <String> [<CommonParameters>]
    
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
        .PARAMETER StripBodyHtml
        Switch to remove any html tags in `$Smtpbody
        .PARAMETER SmtpAttachment
        array of attachement files
        .PARAMETER Credential
        Credential (PSCredential obj) [-credential XXXX]
        .EXAMPLE
        PS> $smtpFrom = (($scriptBaseName.replace(".","-")) + "@toro.com") ;
        PS> $smtpSubj= ("Daily Rpt: "+ (Split-Path $transcript -Leaf) + " " + [System.DateTime]::Now) ;
        PS> #$smtpTo=$tormeta.NotificationDlUs2 ;
        PS> #$smtpTo=$tormeta.NotificationDlUs ;
        PS> # 1:02 PM 4/28/2017 hourly run, just send to me
        PS> $smtpTo="dG9kZC5rYWRyaWVAdG9yby5jb20="| convertFrom-Base64String ; 
        PS> # 12:09 PM 4/26/2017 need to email transcript before archiving it
        PS> if($bdebug){ write-host -ForegroundColor Yellow "$((get-date).ToString('HH:mm:ss')):Mailing Report" };
        PS> #Load as an attachment into the body text:
        PS> #$body = (Get-Content "path-to$s-file\file.html" ) | converto-html ;
        PS> #$SmtpBody += ("Pass Completed "+ [System.DateTime]::Now + "`nResults Attached: " +$transcript) ;
        PS> $SmtpBody += "Pass Completed $([System.DateTime]::Now)`nResults Attached:($transcript)" ;
        PS> if($PassStatus ){
        PS>     $SmtpBody += "`$PassStatus triggers:: $($PassStatus)" ;
        PS> } ;
        PS> $SmtpBody += ('-'*50) ;
        PS> #$SmtpBody += (gc $outtransfile | ConvertTo-Html) ;
        PS> # name $attachment for the actual $SmtpAttachment expected by Send-EmailNotif
        PS> $SmtpAttachment=$transcript ;
        PS> # 1:33 PM 4/28/2017 test for ERROR|CHANGE
        PS> if($PassStatus ){
        PS>     $Email = @{
        PS>         smtpFrom = $SMTPFrom ;
        PS>         SMTPTo = $SMTPTo ;
        PS>         SMTPSubj = $SMTPSubj ;
        PS>         #SMTPServer = $SMTPServer ;
        PS>         SmtpBody = $SmtpBody ;
        PS>     } ;
        PS>     write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):Send-EmailNotif w`n$(($Email|out-string).trim())" ; 
        PS>     Send-EmailNotif @Email;
        PS> } else {
        PS>     write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):No Email Report: `$Passstatus is $null ; " ;
        PS> }  ;
        SMTP Send, using From, To, Subject & Body (as triggered from Cleanup())
        .EXAMPLE
        PS> $smtpToFailThru=convertFrom-Base64String -string "XXXXXXXXXXx"  ; 
        PS> if(!$showdebug){
        PS>     if((Get-Variable  -name "$($TenOrg)Meta").value.NotificationAddr2){
        PS>         $smtpTo = (Get-Variable  -name "$($TenOrg)Meta").value.NotificationAddr2 ;
        PS>     #}elseif((Get-Variable  -name "$($TenOrg)Meta").value.NotificationAddr1){
        PS>     #   $smtpTo = (Get-Variable  -name "$($TenOrg)Meta").value.NotificationAddr1 ;
        PS>     } else {
        PS>         $smtpTo=$smtpToFailThru;
        PS>     } ;
        PS> } else {
        PS>     # debug pass, variant to: NotificationAddr1    
        PS>     #if((Get-Variable  -name "$($TenOrg)Meta").value.NotificationDlUs){
        PS>     if((Get-Variable  -name "$($TenOrg)Meta").value.NotificationAddr1){
        PS>         $smtpTo = (Get-Variable  -name "$($TenOrg)Meta").value.NotificationAddr1 ;
        PS>     } else {
        PS>         $smtpTo=$smtpToFailThru ;
        PS>     } ;
        PS> };
        PS> if($tenOrg -eq 'HOM' ){
        PS>     $SMTPServer = "smtp.gmail.com" ; 
        PS>     $smtpFrom = $smtpTo ; # can only send via gmail from the auth address
        PS> } else {
        PS>     $SMTPServer = $global:smtpserver ; 
        PS>     $smtpFromDom = (Get-Variable  -name "$($TenOrg)Meta").value.o365_OPDomain ; 
        PS>     $smtpFrom = (($CmdletName.replace(".","-")) + "@$( $smtpFromDom  )") ;
        PS>     $smtpFromDom = "gmail.com" ; 
        PS> } ; 
        PS> $smsg = "Mailing Report" ;
        PS> if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
        PS> else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        PS> # variant options:
        PS> #$smtpSubj= "Proc Rpt:$($ScriptBaseName):$(get-date -format 'yyyyMMdd-HHmmtt')"   ;
        PS> #Load as an attachment into the body text:
        PS> #$body = (Get-Content "path-to-file\file.html" ) | converto-html ;
        PS> #$SmtpBody += ("Pass Completed "+ [System.DateTime]::Now + "`nResults Attached: " +$transcript) ;
        PS> # 4:07 PM 10/11/2018 giant transcript, no send
        PS> #$SmtpBody += "Pass Completed $([System.DateTime]::Now)`nResults Attached:($transcript)" ;
        PS> #$SmtpBody += "Pass Completed $([System.DateTime]::Now)`nTranscript:($transcript)" ;
        PS> # group out the PassStatus_$($tenorg) strings into a report for eml body
        PS> if($script:PassStatus){
        PS>     if($summarizeStatus){
        PS>         if(get-command -Name summarize-PassStatus -ea STOP){
        PS>             if($script:TargetTenants){
        PS>                 # loop the TargetTenants/TenOrgs and summarize each processed
        PS>                 #foreach($TenOrg in $TargetTenants){
        PS>                     $SmtpBody += "`n===Processing Summary: $($TenOrg):" ;
        PS>                     if((get-Variable -Name PassStatus_$($tenorg)).value){
        PS>                         if((get-Variable -Name PassStatus_$($tenorg)).value.split(';') |Where-Object{$_ -ne ''}){
        PS>                             $SmtpBody += (summarize-PassStatus -PassStatus (get-Variable -Name PassStatus_$($tenorg)).value -verbose:$($VerbosePreference -eq 'Continue') );
        PS>                         } ;
        PS>                     } else {
        PS>                         $SmtpBody += "(no processing of mailboxes in $($TenOrg), this pass)" ;
        PS>                     } ;
        PS>                     $SmtpBody += "`n" ;
        PS>                 #} ;
        PS>             } ;
        PS>             if($PassStatus){
        PS>                 if($PassStatus.split(';') |Where-Object{$_ -ne ''}){
        PS>                     $SmtpBody += (summarize-PassStatus -PassStatus $PassStatus -verbose:$($VerbosePreference -eq 'Continue') );
        PS>                 } ;
        PS>             } else {
        PS>                 $SmtpBody += "(no `$PassStatus updates, this pass)" ;
        PS>             } ;
        PS>         } else {
        PS>             $smsg = "Unable to gcm summarize-PassStatus!" ; ;
        PS>             if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN} #Error|Warn|Debug
        PS>             else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        PS>             throw $smsg
        PS>         }  ;
        PS>     } else {
        PS>         # dump PassStatus right into the email
        PS>         $SmtpBody += "`n`$script:PassStatus: $($script:PassStatus):" ;
        PS>     } ;
        PS>     if($outRpt -AND ($ProcMov.count -OR  $ProcTV.count) ){
        PS>         $smtpBody += $outRpt ;
        PS>     } ;
        PS>     if($SmtpAttachment){
        PS>         $smtpBody +="(Logs Attached)"
        PS>     };
        PS>     $SmtpBody += "`n$('-'*50)" ;
        PS>     # Incl $transcript in body, where fewer than limit of processed items logged in PassStatus
        PS>     # If using $Transcripts, there're 3 TenOrg-lvl transcripts, as an array, not approp
        PS>     if( ($script:PassStatus.split(';') |?{$_ -ne ''}|measure).count -lt $TranscriptItemsLimit){
        PS>         # add full transcript if less than limit entries in array
        PS>         $SmtpBody += "`nTranscript:$(gc $transcript)`n" ;
        PS>     } else {
        PS>         # attach $trans
        PS>         #if(!$ArchPath ){ $ArchPath = get-ArchivePath } ;
        PS>         $ArchPath = 'c:\tmp\' ;
        PS>         # path static trans from archpath
        PS>         #$archedTrans = join-path -path $ArchPath -childpath (split-path $transcript -leaf) ;
        PS>         # OR: if attaching array of transcripts (further down) - summarize fullname into body
        PS>         if($Alltranscripts){
        PS>             $Alltranscripts |ForEach-Object{
        PS>                 $archedTrans = join-path -path $ArchPath -childpath (split-path $_ -leaf) ;
        PS>                 $smtpBody += "`nTranscript accessible at:`n$($archedTrans)`n" ;
        PS>             } ;
        PS>         } ;
        PS>     };
        PS> }
        PS> $SmtpBody += "Pass Completed $([System.DateTime]::Now)" + "`n" + $MailBody ;
        PS> # raw text body rendered in OL loses all CrLfs - do rendered html/css <pre/pre> approach
        PS> $styleCSS = "<style>BODY{font-family: Arial; font-size: 10pt;}" ;
        PS> $styleCSS += "TABLE{border: 1px solid black; border-collapse: collapse;}" ;
        PS> $styleCSS += "TH{border: 1px solid black; background: #dddddd; padding: 5px; }" ;
        PS> $styleCSS += "TD{border: 1px solid black; padding: 5px; }" ;
        PS> $styleCSS += "</style>" ;
        PS> $html = @"
        PS> <html>
        PS> <head>
        PS> $($styleCSS)
        PS> <title>$title</title></head>
        PS> <body>
        PS> <pre>
        PS> $($smtpBody)
        PS> </pre>
        PS> </body>
        PS> </html>
        PS> "@ ;
        PS> $smtpBody = $html ;
        PS> # Attachment options:
        PS> # 1. attach raw pathed transcript
        PS> #$SmtpAttachment=$transcript ;
        PS> # 2. IfMail: Test for ERROR
        PS> #if($script:passstatus.split(';') -contains 'ERROR'){
        PS> # 3. IfMail $PassStatus non-blank
        PS> if([string]::IsNullOrEmpty($script:PassStatus)){
        PS>     $smsg = "No Email Report: `$script:PassStatus isNullOrEmpty" ;
        PS>     if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
        PS>     else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        PS> } else {
        PS>     $Email = @{
        PS>         smtpFrom = $SMTPFrom ;
        PS>         SMTPTo = $SMTPTo ;
        PS>         SMTPSubj = $SMTPSubj ;
        PS>         SMTPServer = $SMTPServer ;
        PS>         SmtpBody = $SmtpBody ;
        PS>         SmtpAttachment = $SmtpAttachment ;
        PS>         BodyAsHtml = $false ; # let the htmltag rgx in Send-EmailNotif flip on as needed
        PS>         verbose = $($VerbosePreference -eq "Continue") ;
        PS>     } ;
        PS>     # for gmail sends: add rqd params - note: GML requires apppasswords (non-user cred)
        PS>     $Email.add('Credential',$mailcred.value) ;
        PS>     $Email.add('useSSL',$true) ;
        PS>     $smsg = "Send-EmailNotif w`n$(($Email|out-string).trim())" ;
        PS>     if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
        PS>     else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        PS>     Send-EmailNotif @Email ;
        PS> } ;
        Full blown gmail mailer BP
        .LINK
        https://github.com/tostka/verb-Network
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
            [parameter(HelpMessage="Switch to remove any html tags in `$Smtpbody")]
                [switch] $StripBodyHtml,
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
        $rgxSmtpHTMLTags = "</(pre|body|html|title|style)>" ;   
        # before you email conv to str & add CrLf:
        $SmtpBody = $SmtpBody | out-string ; 
        #if ($BodyAsHtml -OR ($SmtpBody -match "\<[^\>]*\>")) {$Email.BodyAsHtml = $True } ;
        if(-not $StripBodyHtml -AND ($SmtpBody -match "\<[^\>]*\>")){
            $BodyAsHtml = $true ; 
        } ;  
        if($StripBodyHtml){
            $smsg = "-StripBodyHtml:stripping any detected html in the body" ; 
            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
            $smtpBody = [regex]::Replace($smtpBody, "\<[^\>]*\>", '') ;
        } ; 
        if($smtpBody -match "</(pre|body|html|title|style)>"){
            $smsg = "`$smtpBody already contains one or more single-use html tags: $($rgxSmtpHTMLTags)" ; 
            $smsg += "`n(using as is, no html updates)" ;
            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
        }elseif($BodyAsHtml){
            $styleCSS = "<style>BODY{font-family: Arial; font-size: 10pt;}" ;
            $styleCSS += "TABLE{border: 1px solid black; border-collapse: collapse;}" ;
            $styleCSS += "TH{border: 1px solid black; background: #dddddd; padding: 5px; }" ;
            $styleCSS += "TD{border: 1px solid black; padding: 5px; }" ;
            $styleCSS += "</style>" ;
            $html = "<html><head>$($styleCSS)<title>$($title)</title></head><body><pre>$($smtpBody)</pre></body></html>" ;
            $smtpBody = $html ;
        } ; 
        if ($SMTPPort -eq $null) {
            $SMTPPort = 25; # just default the port if missing, and always use it
        }	 ;
        if ( ($myBox -contains $env:COMPUTERNAME) -OR ($AdminJumpBoxes -contains $env:COMPUTERNAME) ) {
            $SMTPServer = $global:SMTPServer ;
            $SMTPPort = $smtpserverport ; # [infra file]
            $smsg = "Mailing:$($SMTPServer):$($SMTPPort)" ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        }elseif(get-command Get-ExchangeServer -ea 0){
            if ((get-service MSEx* -ea 0) -AND (get-exchangeserver $env:computername | Where-Object {$_.IsHubTransportServer -OR $_.IsEdgeServer})) {
                $SMTPServer = $env:computername ;
                $smsg = "Mailing Locally:$($SMTPServer)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;                    
            }elseif ((get-service MSEx* -ea 0)  -AND (gcm Get-ExchangeServer -ea 0)) {
                # non Hub Ex server, draw from local site
                $htsrvs = (Get-ExchangeServer | Where-Object {  ($_.Site -eq (get-exchangeserver $env:computername ).Site) -AND ($_.IsHubTransportServer -OR $_.IsEdgeServer) } ) ;
                $SMTPServer = ($htsrvs | get-random).name ;
                $smsg = "Mailing Random Hub:$($SMTPServer)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;                    
            }
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
            # but dyn ip workstations, not
            $SMTPServer = "vscan.toro.com" ;
        } ;
        $sdMM = @{
            From       = $SMTPFrom ;
            To         = $SMTPTo ;
            Subject    = $($SMTPSubj) ;
            SMTPServer = $SMTPServer ;
            Body       = $SmtpBody ;
            BodyAsHtml = $($BodyAsHtml) ; 
            verbose = $verbose ; 
        } ;
        if($Credential){
            $sdMM.add('Credential',$Credential) ; 
        } ; 
        if($useSSL){
            $sdMM.add('useSSL',$useSSL) ; 
        } ; 
        [array]$validatedAttachments = $null ;
        if ($SmtpAttachment) {
            if ($SmtpAttachment -isnot [system.array]) {
                if (test-path $SmtpAttachment) {$validatedAttachments += $SmtpAttachment }
                else {write-warning "$((get-date).ToString('HH:mm:ss')):UNABLE TO GCI ATTACHMENT:$($SmtpAttachment)" }
            } else {
                foreach ($attachment in $SmtpAttachment) {
                    if (test-path $attachment) {$validatedAttachments += $attachment }
                    else {write-warning "$((get-date).ToString('HH:mm:ss')):UNABLE TO GCI ATTACHMENT:$($attachment)" }  ;
                } ;
            } ;
        } ; 
        if ($host.version.major -ge 3) {$sdMM.add("Port", $($SMTPPort))}
        elseif ($SmtpPort -ne 25) {
            $smsg = "Less than Psv3 detected: send-mailmessage does NOT support -Port, defaulting (to 25) ";
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
        } ;
        $smsg = "send-mailmessage w`n$(($sdMM |out-string).trim())" ; 
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;            
        if ($validatedAttachments) {
            $smsg = "`$validatedAttachments:$(($validatedAttachments|out-string).trim())" ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;               
        } ;
        $error.clear()
        TRY {
            if ($validatedAttachments) {
                # looks like on psv2?v3 attachment is an array, can be pipelined in too
                $validatedAttachments | send-mailmessage @sdMM ;
            } else {
                send-mailmessage @sdMM
            } ;
        }CATCH {
            $smsg = "Failed processing $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
        } ; 
        $error.clear() ;
    }

#*------^ Send-EmailNotif.ps1 ^------


#*------v split-DnsTXTRecord.ps1 v------
function split-DnsTXTRecord{
    <#
    .SYNOPSIS
    split-DnsTXTRecord - Splits long TXT DNS record strings into quote-space delimited substrings (to permit the record to exceed the DNS Bind '255-character per single string' limit)
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2024-
    FileName    : split-DnsTXTRecord.ps1
    License     : MIT License
    Copyright   : (c) 2024 Todd Kadrie
    Github      : https://github.com/tostka/verb-XXX
    Tags        : Powershell
    AddedCredit : REFERENCE
    AddedWebsite: URL
    AddedTwitter: URL
    REVISIONS
    * 4:52 PM 7/17/2024 init
    .DESCRIPTION
    split-DnsTXTRecord - Splits long TXT DNS record strings into quote-space delimited substrings (to permit the record to exceed the DNS Bind '255-character per single string' limit)


    ### Creating TXT records

    Key points to remember:

    -   A TXT record contains one or more strings that are enclosed in double quotation marks (").
    -   You can enter a value of up to 255 characters in one string in a TXT record.
    -   You can add multiple strings of 255 characters in a single TXT record.
    -   The maximum length of a value in a TXT record is 4,000 characters.
    -   TXT record values are case-sensitive.

    For values that exceed 255 characters, break the value into strings of 255 characters or less. Enclose each string in double quotation marks (") using the following syntax: 
    **Domain name TXT "String 1" "String 2" "String 3"….."String N"**.

    [easyDmarc Raw Record Pre-publishing validator]([SPF Validator and Raw Checker | EasyDMARC](https://easydmarc.com/tools/spf-record-raw-check-validate)
     
     Note: The above will test the _raw_ un quote-spaced version of the record. It will _not_ properly handle long, 255char+, records that have been split up into "string" "string2" "string3"' strings to exceed the 255-char substring limit (which this function outputs)
     For that matter, it won't even complain about records that are longer than the 255char single string limit.

    .PARAMETER TextRecord
    Raw full length desired TXT record[-TextRecord `$spfFullRecord]
    .INPUTS
    None. Does not accepted piped input.(.NET types, can add description)
    .OUTPUTS
    System.String space quote-wrapped returned to pipeline
    .EXAMPLE
    PS> $dkimString = $instring = "v=DKIM1;k=rsa;p=MIIBIjANBgkqhkiG1w1BAQEFAAOCAQ1AMIIBCgKCAQEAh111KTmtf+f1GCrdVKydz1x1NDs1Cx/g/AYIlx1QcyOpXzd1DNC1saykKjfwYEIGq11UdnLQdJztINPu1QsphwSnpQiGqV11EltNp1poNNeUwSno1vrUTQI11vkD1OosCh+yLVD1AWCqxOr1l1C1kp1UuXvEc1zANPQrbOuVABmGf1nLFvcR1iswFC1JpLOdZr111BelASlU1WApIeDK/a1Qo111WzpFCeFtamIxZFkeHdCSmrS1zrtDrxxvXzYhXIFharkWeY1cXKzZ1vUGR11Zie1gzNzoz1NoibngkBH1dw1C11lU1ynVwx+/U+TCEKOZu1X1K/ZC1/1NrsW11QIDAQAB" ;
    PS> $outformated = split-DnsTXTRecord -TextRecord  $instring -verbose ;
    PS> write-host "`n`$outformated:`n$(($outformated|out-string).trim())`n" ; 
    PS> if($instring.contains(' ')){
    PS>   $reconstitute = ($outformated -split '\s' | %{$_ -replace '["]',''} ) -join ' ' ; 
    PS> } else { 
    PS>   $reconstitute = ($outformated -split '\s' | %{$_ -replace '["]',''} ) -join '' ; 
    PS> } ; 
    PS> if($reconstitute -eq $instring ){$isPass = $true } else { $isPass = $false } ; 
    PS> if($isPass){
    PS>     $smsg = "$([Char]8730) Confirmed reconstited matches original!" ;
    PS> } else { $smsg = "`n`$reconstitute <> `$outformated" } 
    PS> $smsg += "`n`$reconstitute:`n$($reconstitute)" ; 
    PS> $smsg += "`n`n`$instring:`n$($instring)" ; 
    PS> if($isPass){ write-host -foregroundcolor green $smsg } else { write-warning $smsg } ; 

        $outformated:
        "v=DKIM1;k=rsa" ";p=MIIBIjANBgkqhkiG1w1BAQEFAAOCAQ1AMIIBCgKCAQEAh111KTmtf+f1GCrdVKydz1x1NDs1Cx/g/AYIlx1QcyOpXzd1DNC1saykKjfwYEIGq11UdnLQdJztINPu1QsphwSnpQiGqV11EltNp1poNNeUwSno1vrUTQI11vkD1OosCh+yLVD1AWCqxOr1l1C1kp1UuXvEc1zAN
        PQrbOuVABmGf1nLFvcR1iswFC1JpLOdZr111BelASlU1W" "ApIeDK/a1Qo111WzpFCeFtamIxZFkeHdCSmrS1zrtDrxxvXzYhXIFharkWeY1cXKzZ1vUGR11Zie1gzNzoz1NoibngkBH1dw1C11lU1ynVwx+/U+TCEKOZu1X1K/ZC1/1NrsW11QIDAQAB"

        √ Confirmed reconstited matches original!
        $reconstitute:
        v=DKIM1;k=rsa;p=MIIBIjANBgkqhkiG1w1BAQEFAAOCAQ1AMIIBCgKCAQEAh111KTmtf+f1GCrdVKydz1x1NDs1Cx/g/AYIlx1QcyOpXzd1DNC1saykKjfwYEIGq11UdnLQdJztINPu1QsphwSnpQiGqV11EltNp1poNNeUwSno1vrUTQI11vkD1OosCh+yLVD1AWCqxOr1l1C1kp1UuXvEc1zANPQrb
        OuVABmGf1nLFvcR1iswFC1JpLOdZr111BelASlU1WApIeDK/a1Qo111WzpFCeFtamIxZFkeHdCSmrS1zrtDrxxvXzYhXIFharkWeY1cXKzZ1vUGR11Zie1gzNzoz1NoibngkBH1dw1C11lU1ynVwx+/U+TCEKOZu1X1K/ZC1/1NrsW11QIDAQAB

        $instring:
        v=DKIM1;k=rsa;p=MIIBIjANBgkqhkiG1w1BAQEFAAOCAQ1AMIIBCgKCAQEAh111KTmtf+f1GCrdVKydz1x1NDs1Cx/g/AYIlx1QcyOpXzd1DNC1saykKjfwYEIGq11UdnLQdJztINPu1QsphwSnpQiGqV11EltNp1poNNeUwSno1vrUTQI11vkD1OosCh+yLVD1AWCqxOr1l1C1kp1UuXvEc1zANPQrb
        OuVABmGf1nLFvcR1iswFC1JpLOdZr111BelASlU1WApIeDK/a1Qo111WzpFCeFtamIxZFkeHdCSmrS1zrtDrxxvXzYhXIFharkWeY1cXKzZ1vUGR11Zie1gzNzoz1NoibngkBH1dw1C11lU1ynVwx+/U+TCEKOZu1X1K/ZC1/1NrsW11QIDAQAB

    Demo reformatting of a public key-holding DKIM TXT record string
    .EXAMPLE
    PS> $spfString = $instring = "v=spf1 ip4:111.111.111.111 ip4:111.111.111.111 ip4:111.11.1.111 ip4:111.11.1.111 ip4:111.11.11.11 ip4:111.11.11.11 ip4:111.11.1.11 ip4:111.11.1.11 ip4:111.111.111.11 include:spf.protection.outlook.com include:_spf.vendor.com include:111111.spf11.vendor.net ~all" ;
    PS> $outformated = split-DnsTXTRecord -TextRecord  $instring -verbose ;
    PS> write-host "`n`$outformated:`n$(($outformated|out-string).trim())`n" ; 
    PS> if($instring.contains(' ')){
    PS>   $reconstitute = ($outformated -split '\s' | %{$_ -replace '["]',''} ) -join ' ' ; 
    PS> } else { 
    PS>   $reconstitute = ($outformated -split '\s' | %{$_ -replace '["]',''} ) -join '' ; 
    PS> } ; 
    PS> if($reconstitute -eq $instring ){$isPass = $true } else { $isPass = $false } ; 
    PS> if($isPass){
    PS>     $smsg = "$([Char]8730) Confirmed reconstited matches original!" ;
    PS> } else { $smsg = "`n`$reconstitute <> `$outformated" } 
    PS> $smsg += "`n`$reconstitute:`n$($reconstitute)" ; 
    PS> $smsg += "`n`n`$instring:`n$($instring)" ; 
    PS> if($isPass){ write-host -foregroundcolor green $smsg } else { write-warning $smsg } ;  

        $outformated:
        "v=spf1 ip4:111.111.111.111 ip4:111.111.111.111 ip4:111.11.1.111 ip4:111.11.1.111 ip4:111.11.11.11 ip4:111.11.11.11 ip4:111.11.1.11 ip4:111.11.1.11 ip4:111.111.111.11 include:spf.protection.outlook.com include:_spf.vendor
        .com" "include:111111.spf11.somedomain.net ~all"

        √ Confirmed reconstited matches original!
        $reconstitute:
        v=spf1 ip4:111.111.111.111 ip4:111.111.111.111 ip4:111.11.1.111 ip4:111.11.1.111 ip4:111.11.11.11 ip4:111.11.11.11 ip4:111.11.1.11 ip4:111.11.1.11 ip4:111.111.111.11 include:spf.protection.outlook.com include:_spf.vendor.
        com include:111111.spf11.somedomain.net ~all

        $instring:
        v=spf1 ip4:111.111.111.111 ip4:111.111.111.111 ip4:111.11.1.111 ip4:111.11.1.111 ip4:111.11.11.11 ip4:111.11.11.11 ip4:111.11.1.11 ip4:111.11.1.11 ip4:111.111.111.11 include:spf.protection.outlook.com include:_spf.vendor.
        com include:111111.spf11.somedomain.net ~all

    Demo reformatting of a an SPF TXT record string
    .LINK
    https://bitbucket.org/tostka/powershell/
    .LINK
    https://kb.isc.org/docs/aa-00356
    .LINK
    https://datatracker.ietf.org/doc/html/rfc1035
    .LINK
    https://easydmarc.com/tools/spf-record-raw-check-validate
    #>
    [CmdletBinding()]
    ## PSV3+ whatif support:[CmdletBinding(SupportsShouldProcess)]
    ###[Alias('Alias','Alias2')]
    PARAM(
        [Parameter(Mandatory=$True,HelpMessage="Raw full length desired TXT record[-TextRecord `$spfFullRecord]")]
            [ValidateNotNullOrEmpty()]
            #[Alias('ALIAS1', 'ALIAS2')]
            [string]$TextRecord
    ) ; 
    $substringMaxChars = 255 ; 
    $TXTRecordMaxChars = 4000 ; 
    
    #region WHPASSFAIL ; #*------v WHPASSFAIL v------
    $whPASS = @{
    Object = "$([Char]8730) PASS" ;
    ForegroundColor = 'Green' ;
    NoNewLine = $true ;
    } ;
    $whFAIL = @{
        # light diagonal cross: â•³ U+2573 DOESN'T RENDER IN PS, use it if WinTerm
        'Object'= if ($env:WT_SESSION) { "$([Char]8730) FAIL"} else {' X FAIL'};
        ForegroundColor = 'RED' ;
        NoNewLine = $true ;
    } ;
    <#
    # inline pass/fail color-coded w char
    $smsg = "Testing:THING" ; 
    $Passed = $true ; 
    Write-Host "$($smsg)... " -NoNewline ; 
    if($Passed){Write-Host @whPASS} else {write-host @whFAIL} ; 
    Write-Host " (Done)" ;
    # out: Test:Thing... âˆš PASS (Done) | Test:Thing...  X FAIL (Done)
    #>
    $psPASS = "$([Char]8730) PASS" ; 
    $psFAIL = if ($env:WT_SESSION) { "$([Char]8730) FAIL"} else {' X FAIL'} ;
    #if($true){write-host -foregroundcolor green $psPASS} else {write-warning $psFAIL } ; 
    #endregion WHPASSFAIL ; #*------^ END WHPASSFAIL ^------

    # precheck for existing compliance
    $smsg = "Testing:-TextRecord.length -lt $($TXTRecordMaxChars) : " ;
    Write-Host "$($smsg)... " -NoNewline ; 
    if($TextRecord.length -gt $TXTRecordMaxChars){
        write-host @whFail ; 
        $smsg = " : Record length - $($TextRecord.length) - is ABOVE the $($TXTRecordMaxChars) max!" ; 
        $smsg += "`nMUST BE REFACTORED TO FEWER CHARACTERS (CIDR SUBNETS, 2NDARY INCLUDES TC)" ; 
        write-host $smsg ; 
    } else {
        Write-Host @whPASS ; 
        write-host " : Record length - $($TextRecord.length) - is below the $($TXTRecordMaxChars) max" ; 
    }; 
    
    if($TextRecord.Contains('"')){
        $smsg = "-TextRecord contains existing quotation marks (`"): Appears to be a pre-reformated record" 
        $smsg += "`n$(($TextRecord|out-string).trim())`n" ; 
        write-host -foregroundcolor yellow $smsg ;

        $smsg = "Testing:quoted substrings are -lt $($substringMaxChars) :" ;
        Write-Host "$($smsg)... " -NoNewline ; 
        #if($Passed){Write-Host @whPASS} else {write-host @whFAIL} ; 
        #Write-Host " (Done)" ;
        if($badsubstrings = ($outformated -split '\"\s\"')|%{$_.replace('"','') | ?{$_.length -gt $substringMaxChars}}){
            write-host @whFail ; 
            write-host " : substrings are within the record, that are -gt than the $($substringMaxChars) DNS BIND substring limit!" ; 
        } else { 
            Write-Host @whPASS
            write-host " : All substrings within the record are -lt than the $($substringMaxChars) DNS BIND substring limit" ; 
        } ; 

        # reconstitute quoted to original raw text string:
        write-host "Reconstituting quoted substrings to flattened unquoted record for reporcessing" ; 
        if($TextRecord.contains(' ')){
            $reconstitute = ($TextRecord -split '\s' | %{$_ -replace '["]',''} ) -join ' ' ; 
        } else { 
            $reconstitute = ($TextRecord -split '\s' | %{$_ -replace '["]',''} ) -join '' ; 
        } ; 
        $TextRecord = $reconstitute ; 
    }else{
        # test for non-quote-split pre-compliant -lt 255char
        $smsg = "Testing already compliant:-TextRecord.length -le $($substringMaxChars) : " ;
        Write-Host "$($smsg)... " -NoNewline ; 
        if($TextRecord.length -gt $substringMaxChars){
            write-host @whFail ; 
            $smsg = " : Record length - $($TextRecord.length) - is ABOVE the $($substringMaxChars) max!" ; 
            $smsg += "`nMUST BE REFACTORED TO FEWER CHARACTERS (CIDR SUBNETS, 2NDARY INCLUDES TC)" ; 
            write-host $smsg ; 
        } else {
            Write-Host @whPASS ; 
            $smsg = " : Record length - $($TextRecord.length) - is already below the $($substringMaxChars) max" ; 
            $smsg += "`nNo further revisions of the record are necessary to a provide a compliant TXT record" ; 
            $smsg += "`n(EXITING)" ; 
            #$TextRecord | write-output ;
            return $TextRecord ; 
            break ; 
        }; 
    }
    
    [string[]]$FinishedStrs = $WorkingStrings = @() ; 
    [string]$WorkingStrings = $TextRecord ; 
    $cutchar = ' ' ; 
    [string[]]$strArray = @() ;  
    if($WorkingStrings.Contains($cutchar)){
        write-verbose "WorkingStrings includes '$($cutchar)' characters: Splitting into substrings at those characters"
        if($substrs = $WorkingStrings -split $cutchar ){
            $sPad = $sTextO = "";
            foreach ($substr in $substrs) {
                $prospect = (@($sPad,$substr)|?{$_}) -join $cutchar ; 
                write-verbose "`$prospect:`n$($prospect)" ; 
                if ($prospect.length -gt $substringMaxChars) {
                    #$sTextO = '"' + $((@($sTextO,$sPad)|?{$_}) -join $cutchar) + '"'  ; 
                    # put off quot wrap until done
                    $strArray += @($((@($sTextO,$sPad)|?{$_}) -join $cutchar))
                    $sPad = $substr ;
                }else {
                    $sPad = $prospect; 
                } ;
            }  ;
            if ($sPad.length -ne 0) {
                if($cutchar -ne ' '){
                    # final delim will be spaces, we don't need extras
                    $strArray += @("$($cutchar)$($sPad)") ; 
                } else {
                    $strArray += @($sPad) ; 
                }; 
            };
            [string[]]$WorkingStrings = $strArray|?{$_.length -gt $substringMaxChars} ; 
            [string[]]$FinishedStrs += $strArray|?{$_.length -le $substringMaxChars} ; 
        } ; 
    }; 

    #} else {
    if($WorkingStrings){
        #write-verbose "No spaces in string, performing cuts at arbitrary locations" ; 
        $cutchar = ';' 
        [string[]]$strArray = @() ;  
        if($WorkingStrings.Contains($cutchar)){
            write-verbose "WorkingStrings includes '$($cutchar)' characters: Splitting into substrings at those characters"
            if($substrs = $WorkingStrings -split $cutchar ){
                $sPad = $sTextO = "";
                foreach ($substr in $substrs) {
                    $prospect = (@($sPad,$substr)|?{$_}) -join $cutchar ; 
                    write-verbose "`$prospect:`n$($prospect)" ; 
                    if ($prospect.length -gt $substringMaxChars) {
                        $strArray += @($((@($sTextO,$sPad)|?{$_}) -join $cutchar))
                        $sPad = $substr ;
                    }else {
                        $sPad = $prospect; 
                    } ;
                }  ;
                if ($sPad.length -ne 0) {
                    if($cutchar -ne ' '){
                        # final delim will be spaces, we don't need extras
                        $strArray += @("$($cutchar)$($sPad)") ; 
                    } else {
                        $strArray += @($sPad) ; 
                    }; 
                };
            } ; 
        }; 

        #[string[]]$WorkingStrings = $strArray|?{$_.length -gt $substringMaxChars} ; 
        #[string[]]$PreHandled = $strArray|?{$_.length -le $substringMaxChars} ; 

        [string[]]$WorkingStrings = $strArray|?{$_.length -gt $substringMaxChars} ; 
        [string[]]$FinishedStrs += $strArray|?{$_.length -le $substringMaxChars} ;

        if($WorkingStrings){
            # been through \s & ; splits; -> split long substrings at arbitrary points to get -lt $($substringMaxChars)
            $cutchar = '' ;
            #if($Chars = $WorkingStrings.ToCharArray()){
            #if($Chars = $WorkingStrings -split $cutchar){
            if($Chars = $WorkingStrings -split $cutchar |?{$_}){
                $sPad = $sTextO = "";
                foreach ($char in $chars) {
                    #if (($sPad + $char).length -gt ($substringMaxChars-2)) {
                    $prospect = (@($sPad,$char)|?{$_}) -join $cutchar ;
                    write-verbose "`$prospect:`n$($prospect)" ; 
                    if ($prospect.length -gt $substringMaxChars - 2) {
                        $FinishedStrs += $((@($sTextO,$sPad)|?{$_}) -join $cutchar)
                        $sPad = $char ;
                    }else {
                        $sPad = $prospect; 
                    } ;
                                        <#    $sTextO = '"' + $sTextO + $sPad + '"'  ; 
                    $sPad = $char ;
                }else {
                    $sPad = ($sPad + $char).trim() ; 
                } ;
                #>
                }  ;
                if ($sPad.length -ne 0) {
                    #$sTextO = $sTextO + (' "' + $sPad + '"') ;
                    #$PreHandled += $sPad ; 
                    $FinishedStrs += $sPad ; 
                };
            } else { 
                throw "Unable to split specified string into characters" ; 
            } ; 
        } ;
    } ; 
    #if($FinishedStrs -AND $sTextO){
    if($FinishedStrs ){
        $FinishedStrs = $FinishedStrs | select -unique ; 
        [string]$strReturn = $( ($FinishedStrs | %{ '"' + $_ + '"'} ) -join ' ') ; 
    } ; 
    if($strReturn.length -lt $TXTRecordMaxChars){
        $strReturn  | write-output ; 
        #return $strReturn  ; 
    } else {
        throw "Aggregate length is -gt than $($TXTRecordMaxChars)char max TXT record size limit!" ; 
    } ;
}

#*------^ split-DnsTXTRecord.ps1 ^------


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


#*------v test-ADComputerName.ps1 v------
Function test-ADComputerName{
    <#
    .SYNOPSIS
    test-ADComputerName.ps1 - Validate that passed string is an ADComputer object name
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2024-
    FileName    : test-ADComputerName.ps1
    License     : MIT License
    Copyright   : (c) 2024 Todd Kadrie
    Github      : https://github.com/tostka/verb-XXX
    Tags        : Powershell
    AddedCredit : Luc Fullenwarth
    AddedWebsite: https://gravatar.com/fullenw1
    AddedTwitter: twitter.com/LFullenwarth
    REVISIONS
    * 2:03 PM 6/6/2024 rounded out param validation sample to full function
    * 8/5/20 LF posted arti
    .DESCRIPTION
    test-ADComputerName.ps1 - Validate that passed string is an ADComputer object name
    .PARAMETER  ComputerName
    ComputerName string to be validated[-ComputerName SomeBox]
    .INPUTS
    System.String Accepts piped input
    .OUTPUTS
    System.Boolean
    .EXAMPLE
    PS> test-ADComputerName.ps1 -ComputerName $env:computername
    Demo simple test
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://bitbucket.org/tostka/powershell/
    .LINK
    https://itluke.online/2020/08/05/validating-computer-names-with-powershell/
    #>    
    #Requires -Modules ActiveDirectory
    PARAM(
        [Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$true,HelpMessage="ComputerName string to be validated[-ComputerName SomeBox]")]
            [ValidateScript({Get-ADComputer -Identity $PSItem})]
            [ValidateNotNullOrEmpty()]
            [string]$ComputerName
    )
    write-output $true ; 
}

#*------^ test-ADComputerName.ps1 ^------


#*------v test-CertificateTDO.ps1 v------
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
}

#*------^ test-CertificateTDO.ps1 ^------


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
            Author      : Todd Kadrie
            Website     : http://www.toddomation.com
            Twitter     : @tostka / http://twitter.com/tostka
            CreatedDate : 2022-11-03
            FileName    : Test-IPAddressInRange
            License     : (none asserted)
            Copyright   : (none asserted)
            Github      : https://github.com/tostka/verb-network
            Tags        : Powershell,Network,Ipv6,Ipv4,Subnet,Validate
            AddedCredit : Nick James (omniomi)
            AddedWebsite: https://github.com/omniomi/PSMailTools/blob/v0.2.0/src/Private/spf/IPInRange.ps1
            AddedTwitter: 
            REVISIONS
            * 4:08 PM 12/11/2024 updated to support Ipv6 addresses & CIDR subnets; also supports auto-flipping inbound -Range as non-cidr notated single IP, into proper ipv4 /32 or ipv6 /128 single-ip CIDR subnet notation,
            to support pipeing resolved/expanded SPF record for valiating spf support for sending server IPs.
            * 11:57 AM 1/5/2023 TSK flipped $IPAddress type from [string] to [ipaddress]; Added CBH, and example; converted to Adv Func syntax; 
            added pipeline support on the IPAddress input ; simplfied compound stmts ; added to verb-Network.
            * Apr 17, 2018 Nick James (omniomi) posted github version from: https://github.com/omniomi/PSMailTools/blob/v0.2.0/src/Private/spf/IPInRange.ps1
            .DESCRIPTION
            Test-IPAddressInRange - Test an array of IP Addreses for presence in specified CIDR-notated subnet range. 

            If an ip address - ipv4 or ipv6 - is specified as the -Range (wo CIDR subnet), as is the case for testing against SPF ip-records, the Range specification is auto-updated to the equiv single-IP CIDR subnet (/32 for ipv4, /128 for ipv6).

            .SYNOPSIS
            Test-IPAddressInRange - Test an array of IP Addreses for presence in specified CIDR-notated subnet range.
            .PARAMETER IPAddress
            Array of ipv4 or ipv6 IP Addresses to be compared to specified Range[-IPAddress 192.168.1.1]
            .PARAMETER Range
            CIDR-notated subnet specification (non-CIDR single ip addresses are auto-patched into equiv /32 or /128 ipv4/ipv6 CIDR single-ip notation)[-Range 10.10.10.10/24

            .INPUTS
            System.String.Array Accepts piped input 
            .OUTPUTS
            System.Boolean
            .EXAMPLE
            PS> Test-IPAddressInRange 10.10.10.230 10.10.10.10/24 ; 
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
            Pipeline demo, fed with array of ip's, loops each through a test on the specified cidr range.
            .EXAMPLE
            PS> if(Test-IPAddressInRange -IPAddress "2001:0db8:85.4.0000:0000:8a2e:0370:7334" -Range "2001:0db8:85a3::/48" -verbose){
            PS>     write-host -foregroundcolor green  "is in range!" 
            PS> } else { write-host -foregroundcolor yellow "Is NOT in range"} ;
            Test ipv6 IP Address & CIDR subnet
            .EXAMPLE
            PS> write-verbose "Resolve expanded SPF record specificaitons for domain" ; 
            PS> $spfs = Resolve-SPFRecord -Name DOMAIN.COM  ; 
            PS> $ipaddress = '170.92.7.105','fe80::5859:395f:7987:9bc8' ; 
            PS> $verbose= $false ; 
            PS> write-verbose "Test `$ipaddress list entries, against each of the SPF specifications returned" ; 
            PS> foreach($ip in $ipaddress){
            PS>   write-host -foregroundcolor yellow "==Test-IPAddressInRange IP:$($ip)" ; 
            PS>   #$spfs.ipaddress |%{ 
            PS>   foreach($spf in $spfs.ipaddress){
            PS>       $range = $spf ;
            PS>       write-host "==Test in Range:$($range):" ;
            PS>       if(Test-IPAddressInRange -IPAddress $ip -Range $range -Verbose:$($verbose)){
            PS>         write-host -foregroundcolor green "$($ip) is in range:$($range)";
            PS>         break ; 
            PS>       } else{write-host "-"} ;
            PS>   } ;
            PS> } ; 
            Demo resolving out expanded SPF ip specifications, and then testing a series of IP Addresses against those returned spf specifications 
            (non-CIDR single addresses from SPF record are auto-patched by this script into equiv /32 or /128 ipv4/ipv6 CIDR single-ip notation inputs).
            .LINK
            https://github.com/tostka/verb-network
            .LINK
            https://github.com/omniomi/PSMailTools/blob/v0.2.0/src/Private/spf/IPInRange.ps1
            #>
            # VALIDATORS: [ValidateNotNull()][ValidateNotNullOrEmpty()][ValidateLength(24,25)][ValidateLength(5)][ValidatePattern("some\sregex\sexpr")][ValidateSet("US","GB","AU")][ValidateScript({Test-Path $_ -PathType 'Container'})][ValidateScript({Test-Path $_})][ValidateRange(21,65)]#positiveInt:[ValidateRange(0,[int]::MaxValue)]#negativeInt:[ValidateRange([int]::MinValue,0)][ValidateCount(1,3)]
            [outputtype([System.Boolean])]
            [Alias('test-IPInRange')]
            [CmdletBinding()]
            PARAM(
                [parameter(Mandatory=$true, Position=0,ValueFromPipeline = $True,HelpMessage="Array of ipv4 or ipv6 IP Addresses to be compared to specified Range[-IPAddress 192.168.1.1]")]
                    #[validatescript({([System.Net.IPAddress]$_).AddressFamily -eq 'InterNetwork'})] # covers solely ipv4
                    # cover both ipv4 & ipv6
                    [validatescript({([System.Net.IPAddress]$_).AddressFamily -match '^(InterNetwork|InterNetworkV6)$'})]
                    [ipaddress[]]$IPAddress,
                [parameter(Mandatory,Position=1,HelpMessage="CIDR-notated subnet specification (non-CIDR single ip addresses are auto-patched into equiv /32 or /128 ipv4/ipv6 CIDR single-ip notation)[-Range 10.10.10.10/24")]
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

                #*======v FUNCTIONS v======

                #*------v Function Test-IPAddressInRangeIp6 v------
                if(-not (get-command Test-IPAddressInRangeIp6 -ea 0)){
                    function Test-IPAddressInRangeIp6 {
                        <#
                        .SYNOPSIS
                        Test-IPAddressInRangeIp6  Tests if an IPv6 address is within a specified CIDR range.
                        .NOTES
                        Version     : 0.0.1
                        Author      : Todd Kadrie
                        Website     : http://www.toddomation.com
                        Twitter     : @tostka / http://twitter.com/tostka
                        CreatedDate : 2024-12-11
                        FileName    : Test-IPAddressInRangeIp6.ps1
                        License     : (non asserted)
                        Copyright   : (non asserted)
                        Github      : https://github.com/tostka/verb-Network
                        Tags        : Powershell,Network,Ipv6,Subnet,Validate
                        AddedCredit : Google AI snippet (returned on Google search)
                        AddedWebsite: https://www.google.com/search?q=powershell+test+ipv6+address+is+in+cidr+range
                        AddedTwitter: URL
                        REVISIONS
                        * 3:16 PM 12/11/2024 init rev
                        .DESCRIPTION
                        This function checks if a given IPv6 address falls within a specified CIDR-notation subnet. .

                        Expanded from Google AI offered snippet from search.

                        .PARAMETER IPAddress
                        IPv6 IP Address to be tested (e.g., "2001:0db8:85.4.0000:0000:8a2e:0370:7334").
                        .PARAMETER CIDR
                        IPv6 CIDR-notation Subnet to be tested against (e.g., "2001:0db8:85a3::/48").
                        .INPUTS
                        None. The function does not accept pipeline input.
                        .OUTPUTS
                        System.Boolean. Returns $true if the IP address is within the CIDR range, otherwise $false.
                        .EXAMPLE
                        PS> Test-IPAddressInRangeIp6 -IPAddress "2001:0db8:85.4.0000:0000:8a2e:0370:7334" -CIDR "2001:0db8:85a3::/48"
                        .LINK
                        https://github.com/tostka/verb-Network
                        #>
                        [CmdletBinding()]
                        [Alias('Test-IPv6InCIDR','Alias2')]
                        PARAM(
                            [Parameter(Mandatory=$True,HelpMessage="IPv6 IP Address to be tested [-Ticket ;'2001:0db8:85.4.0000:0000:8a2e:0370:7334']")]
                                [string]$IPAddress,
                            [Parameter(Mandatory=$True,HelpMessage="IPv6 CIDR-notation Subnet to be tested against[-Ipv6 CIDR  '2001:0db8:85a3::/48']")]
                                [string]$CIDR
                        )
                        # Split the CIDR into the network address and prefix length
                        $network, $prefixLength = $CIDR.Split('/')
                        # Convert the IP address and network address to byte arrays
                        $ipBytes = [System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes()
                        $networkBytes = [System.Net.IPAddress]::Parse($network).GetAddressBytes()
                        # Calculate the mask
                        $maskBytes = New-Object byte[] 16
                        for ($i = 0; $i -lt 16; $i++) {
                            #if ($i * 8 < $prefixLength) {
                            if ($i * 8 -lt $prefixLength) {
                                $maskBytes[$i] = 255 ; 
                            #} elseif ($i * 8 < $prefixLength + 8) {
                            } elseif ($i * 8 -lt $prefixLength + 8) {
                                $maskBytes[$i] = [byte](256 - [Math]::Pow(2, 8 - ($prefixLength % 8))) ; 
                            } ; 
                        } ; 
                        # Check if the IP address is in the range
                        for ($i = 0; $i -lt 16; $i++) {
                            if (($ipBytes[$i] -band $maskBytes[$i]) -ne ($networkBytes[$i] -band $maskBytes[$i])) {
                                return $false ; 
                            } ; 
                        } ; 
                        return $true ; 
                    } ; 
                } ; 
                #*------^ END Function Test-IPAddressInRangeIp6 ^------

                #*======^ END FUNCTIONS ^======

                # $CIDR, feeding these in from SPF records, some are raw single IP, so detect them and tack a single-IP CIDR /32 on them
                <# In most modern routers (post 1998) have classless routing, (CIDR) in classless routing is a single IP address 1.2.3.4 equivalent to 1.2.3.4/32
                for IPV6 single IP it's a /128 e.g. fe80::1/128 or ::/128 or 2001:db8:3973:08ef:08ef:c7ba:96a6:49c8/128/128
                #>
                # 9:47 AM 12/11/2024 moved validation here: validation reapplies on any update of the vary, and fails flipping from IP to /32 CIDR subnet.
                #if($Range -notcontains '/'){
                if($Range.Contains('/')){
                    write-verbose "-range:$($Range) confirmed has an Address and Bitmask w / delimiter" ; 
                }else{
                    TRY{
                        if($Range -like "*.*" -AND  ([System.Net.IPAddress]($Range)).AddressFamily -eq 'InterNetwork'){
                            write-host "Range is single ip4 IP: Coercing -Range:$($Range) to single IP ip4 '/32' CIDR range input:`n$($Range)/32" ; 
                            $Range = "$($Range)/32"
                        #}elseif((($Range -like "*:*" -AND [System.Net.IPAddress]($IP)).AddressFamily -eq 'InterNetworkV6'){
                        }elseif($Range -like "*:*" -AND ([System.Net.IPAddress]($Range)).AddressFamily -eq 'InterNetworkV6'){
                            write-host "Range is single ip6 IP: Coercing -Range:$($Range) to single IP ip6 '/128' CIDR range input:`n$($Range)/128" ; 
                            $Range = "$($Range)/128"
                        }  ; 
                    }CATCH{write-warning "-range:$($Range) has no Bitmask / delimiter, and doesn't convert cleanly to [ipaddress]" } ; 
                } ;
                # moving active validation down here.
                <#$IP,$Bits  = $Range -split '/' 
                    if(([System.Net.IPAddress]($IP)).AddressFamily -match 'InterNetwork|InterNetworkV6'){}else{
                        $smsg = "resolved -Range $($range) IP - $($IP), does not resolve to ipv4 (AddressFamily:InterNetwork) or ipv6 (AddressFamily:InterNetworkV6)!" ; 
                        throw $smsg ; 
                        break ; 
                    } ;
                if (-not($Bits)) {
                    throw 'Missing CIDR notiation.' 
                #} elseif (-not(0..32 -contains [int]$Bits)) { # ipv4 cidr rang
                } elseif (-not(0..128 -contains [int]$Bits)) {
                    #throw 'Invalid CIDR notation. The valid bit range is 0 to 32.' ; 
                    throw 'Invalid CIDR notation. The valid bit range is 0 to 128.' ; 
                } ; 
                #>
                <#
                if($Range -notcontains '/'){
                    if(([System.Net.IPAddress]($Range)).AddressFamily -eq 'InterNetwork'){
                        $Range = "$($Range)/32"
                        write-host "Range is single ip4 IP: Coercing -Range:$($Range) to single IP ip4 '/32' CIDR range input:`n$($Range)" ; 
                    }elseif( ($Range -like "*:*") -AND ([System.Net.IPAddress]($IP)).AddressFamily -eq 'InterNetworkV6'){
                        $Range = "$($Range)/128"
                        write-host "Range is single ip6 IP: Coercing -Range:$($Range) to single IP ip6 '/128' CIDR range input:`n$($Range)" ; 
                        
                    }  ; 
                }
                #>

                write-verbose "Split Range into the address and the CIDRBits notation" ; 
                [String]$CIDRAddress,[int]$CIDRBits = $Range.Split('/') ; 
                if(([System.Net.IPAddress]($CIDRAddress)).AddressFamily -match 'InterNetwork|InterNetworkV6'){}else{
                    $smsg = "resolved -Range $($range) IP - $($CIDRAddress), does not resolve to ipv4 (AddressFamily:InterNetwork) or ipv6 (AddressFamily:InterNetworkV6)!" ; 
                    throw $smsg ; 
                    break ; 
                } ;
                if (-not($CIDRBits)) {
                    throw 'Missing CIDR notiation.' 
                #} elseif (-not(0..32 -contains [int]$CIDRBits)) { # ipv4 cidr rang
                } elseif (-not(0..128 -contains [int]$CIDRBits)) {
                    #throw 'Invalid CIDR notation. The valid bit range is 0 to 32.' ; 
                    throw 'Invalid CIDR notation. The valid bit range is 0 to 32 (ipv4) 0 to 128 (ipv6).' ; 
                } ; 

                # ip4 CIDR range: 0 to 32
                # ip6 CIDR range: 0 to 128 - need to update to accomodate cidr ip6
                $CIDRisIp6 = $CIDRisIp4 = $false ;
                if($CIDRAddress -like "*:*" -AND [int]$CIDRBits -ge 0 -AND [int]$CIDRBits -le 128){
                    # CIDR ip6
                    write-verbose "valid ipv6 CIDR subnet syntax" ;
                    #$report.Valid = $true ; 
                    $CIDRisIp6 = $true ; 
                } elseif([int]$CIDRBits -ge 0 -and [int]$CIDRBits -le 32){
                    write-verbose "valid ipv4 CIDR subnet syntax" ;
                    #$report.Valid = $true ; 
                    $CIDRisIp4 = $true ; 
                }

                if ($PSCmdlet.MyInvocation.ExpectingInput) {
                    write-verbose -message "Data received from pipeline input: '$($InputObject)'" ; 
                } else {
                    #write-verbose "Data received from parameter input: '$($InputObject)'" ; 
                    write-verbose -message "(non-pipeline - param - input)" ; 
                } ; 
            } ; 
            PROCESS{
                foreach($item in $IPAddress){
                    $sBnrS="`n#*------v PROCESSING : $($item.IPAddressToString) against CIDR range: $($Range) v------" ; 
                    write-verbose -message "$($sBnrS)" ;
                    if($CIDRisIp4){
                        write-verbose "Address from range and the search address are converted to Int32 and the full mask is calculated from the CIDR notation."
                        [int]$BaseAddress    = [System.BitConverter]::ToInt32((([System.Net.IPAddress]::Parse($CIDRAddress)).GetAddressBytes()), 0) ; 
                        [int]$Address        = [System.BitConverter]::ToInt32(([System.Net.IPAddress]::Parse($item).GetAddressBytes()), 0) ; 
                        [int]$Mask           = [System.Net.IPAddress]::HostToNetworkOrder(-1 -shl ( 32 - $CIDRBits)) ; 

                        write-verbose "Determine whether the address is in the range. (-band == bitwise-AND)"
                        if (($BaseAddress -band $Mask) -eq ($Address -band $Mask)) {
                            $true | write-output ; 
                        } else {
                            #$false | write-output  ; # 1:12 PM 12/11/2024 no return unless true
                        } ;  
                    }elseif($CIDRisIp6){
                        <# having trouble getting ported to work, passes everything, defer to the canned function
                        # Convert to byte arrays
                        $ipBytes = [System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes() ; 
                        $networkBytes = [System.Net.IPAddress]::Parse($CIDRAddress).GetAddressBytes() ; 
                        # Calculate the mask
                        $maskBytes = New-Object byte[] 16 ; 
                        for ($i = 0; $i -lt 16; $i++) {
                            #if ($i * 8 < $prefixLength) {
                            if ($i * 8 -lt $prefixLength) {
                                $maskBytes[$i] = 255 ; 
                            #} elseif ($i * 8 < $CIDRBits+ 8) {
                            } elseif ($i * 8 -lt $CIDRBits+ 8) {
                                $maskBytes[$i] = [byte](256 - [Math]::Pow(2, 8 - ($CIDRBits% 8))) ; 
                            } ; 
                        } ; 
                        # Check IP address in range
                        for ($i = 0; $i -lt 16; $i++) {
                            if (($ipBytes[$i] -band $maskBytes[$i]) -ne ($networkBytes[$i] -band $maskBytes[$i])) {
                                return $false ; 
                            } ; 
                        } ; 
                        return $true ; 
                        #>

                        if(Test-IPAddressInRangeIp6 -IPAddress $item.IPAddressToString -CIDR $Range -Verbose:($PSBoundParameters['Verbose'] -eq $true)){
                            $true | write-output 
                        } 
                    } ;
                    write-verbose -message "$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;

                } ;  # loop-E
            }  # PROC-E
            END{
                write-verbose -message "$($sBnr.replace('=v','=^').replace('v=','^='))" ;
            } ;
        }

#*------^ Test-IPAddressInRange.ps1 ^------


#*------v Test-IPAddressInRangeIp6.ps1 v------
function Test-IPAddressInRangeIp6 {
    <#
    .SYNOPSIS
    Test-IPAddressInRangeIp6  Tests if an IPv6 address is within a specified CIDR range.
    .NOTES
    Version     : 0.0.1
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2024-12-11
    FileName    : Test-IPAddressInRangeIp6.ps1
    License     : (non asserted)
    Copyright   : (non asserted)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,Network,Ipv6,Subnet,Validate
    AddedCredit : Google AI snippet (returned on Google search)
    AddedWebsite: https://www.google.com/search?q=powershell+test+ipv6+address+is+in+cidr+range
    AddedTwitter: URL
    REVISIONS
    * 4:13 PM 12/11/2024 init rev
    .DESCRIPTION
    This function checks if a given IPv6 address falls within a specified CIDR-notation subnet. It splits the CIDR into the network address and prefix length, converts the IP address and network address to byte arrays, calculates the mask, and then checks if the IP address is in the range.

    Expanded from Google AI offered snippet from search.
    .PARAMETER IPAddress
    IPv6 IP Address to be tested (e.g., "2001:0db8:85.4.0000:0000:8a2e:0370:7334").
    .PARAMETER CIDR
    IPv6 CIDR-notation Subnet to be tested against (e.g., "2001:0db8:85a3::/48").
    .INPUTS
    None. The function does not accept pipeline input.
    .OUTPUTS
    System.Boolean. Returns $true if the IP address is within the CIDR range, otherwise $false.
    .EXAMPLE
    PS> Test-IPAddressInRangeIp6 -IPAddress "2001:0db8:85.4.0000:0000:8a2e:0370:7334" -CIDR "2001:0db8:85a3::/48"
    .LINK
    https://github.com/tostka/verb-Network
    #>
    [CmdletBinding()]
    [Alias('Test-IPv6InCIDR','Alias2')]
    PARAM(
        [Parameter(Mandatory=$True,HelpMessage="IPv6 IP Address to be tested [-Ticket ;'2001:0db8:85.4.0000:0000:8a2e:0370:7334']")]
            [string]$IPAddress,
        [Parameter(Mandatory=$True,HelpMessage="IPv6 CIDR-notation Subnet to be tested against[-Ipv6 CIDR  '2001:0db8:85a3::/48']")]
            [string]$CIDR
    )
    # Split the CIDR into the network address and prefix length
    $network, $prefixLength = $CIDR.Split('/')
    # Convert the IP address and network address to byte arrays
    $ipBytes = [System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes()
    $networkBytes = [System.Net.IPAddress]::Parse($network).GetAddressBytes()
    # Calculate the mask
    $maskBytes = New-Object byte[] 16
    for ($i = 0; $i -lt 16; $i++) {
        #if ($i * 8 < $prefixLength) {
        if ($i * 8 -lt $prefixLength) {
            $maskBytes[$i] = 255 ; 
        #} elseif ($i * 8 < $prefixLength + 8) {
        } elseif ($i * 8 -lt $prefixLength + 8) {
            $maskBytes[$i] = [byte](256 - [Math]::Pow(2, 8 - ($prefixLength % 8))) ; 
        } ; 
    } ; 
    # Check if the IP address is in the range
    for ($i = 0; $i -lt 16; $i++) {
        if (($ipBytes[$i] -band $maskBytes[$i]) -ne ($networkBytes[$i] -band $maskBytes[$i])) {
            return $false ; 
        } ; 
    } ; 
    return $true ; 
}

#*------^ Test-IPAddressInRangeIp6.ps1 ^------


#*------v test-isADComputerName.ps1 v------
Function test-isADComputerName{
    <#
    .SYNOPSIS
    test-isADComputerName.ps1 - Validate that passed string is an ADComputer object name
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2024-
    FileName    : test-isADComputerName.ps1
    License     : MIT License
    Copyright   : (c) 2024 Todd Kadrie
    Github      : https://github.com/tostka/verb-XXX
    Tags        : Powershell
    AddedCredit : Luc Fullenwarth
    AddedWebsite: https://gravatar.com/fullenw1
    AddedTwitter: twitter.com/LFullenwarth
    REVISIONS
    * 2:03 PM 6/6/2024 rounded out param validation sample to full function
    * 8/5/20 LF posted arti
    .DESCRIPTION
    test-isADComputerName.ps1 - Validate that passed string is an ADComputer object name
    .PARAMETER  ComputerName
    ComputerName string to be validated[-ComputerName SomeBox]
    .INPUTS
    System.String Accepts piped input
    .OUTPUTS
    System.Boolean
    .EXAMPLE
    PS> test-isADComputerName.ps1 -ComputerName $env:computername
    Demo simple test
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://bitbucket.org/tostka/powershell/
    .LINK
    https://itluke.online/2020/08/05/validating-computer-names-with-powershell/
    #>    
    #Requires -Modules ActiveDirectory
    PARAM(
        [Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$true,HelpMessage="ComputerName string to be validated[-ComputerName SomeBox]")]
            [ValidateScript({Get-ADComputer -Identity $PSItem})]
            [ValidateNotNullOrEmpty()]
            [string]$ComputerName
    )
    write-output $true ; 
}

#*------^ test-isADComputerName.ps1 ^------


#*------v test-isComputerDNSRegistered.ps1 v------
Function test-isComputerDNSRegistered{
    <#
    .SYNOPSIS
    test-isComputerDNSRegistered.ps1 - Validate that passed string is a DNS Registered Computer
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2024-
    FileName    : test-isComputerDNSRegistered.ps1
    License     : MIT License
    Copyright   : (c) 2024 Todd Kadrie
    Github      : https://github.com/tostka/verb-XXX
    Tags        : Powershell
    AddedCredit : Luc Fullenwarth
    AddedWebsite: https://gravatar.com/fullenw1
    AddedTwitter: twitter.com/LFullenwarth
    REVISIONS
    * 2:03 PM 6/6/2024 rounded out param validation sample to full function
    * 8/5/20 LF's posted vers (article)
    .DESCRIPTION
    test-isComputerDNSRegistered.ps1 - Validate that passed string is a DNS Registered Computer
    
    .PARAMETER  ComputerName
    ComputerName string to be validated[-ComputerName SomeBox]
    .INPUTS
    System.String Accepts piped input
    .OUTPUTS
    System.Boolean
    .EXAMPLE
    PS> test-isComputerDNSRegistered -ComputerName $env:computername
    Demo simple test
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://bitbucket.org/tostka/powershell/
    .LINK
    https://itluke.online/2020/08/05/validating-computer-names-with-powershell/
    #>    
    #Requires -Modules ActiveDirectory
    PARAM(
        [Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$true,HelpMessage="ComputerName string to be validated[-ComputerName SomeBox]")]
            [ValidateScript({Resolve-DnsName -Name $PSItem})]
            [ValidateNotNullOrEmpty()]
            [string]$ComputerName
    )
    write-output $true ; 
}

#*------^ test-isComputerDNSRegistered.ps1 ^------


#*------v test-isComputerNameFQDN.ps1 v------
Function test-isComputerNameFQDN{
    <#
    .SYNOPSIS
    test-isComputerNameFQDN.ps1 - Validate that passed string is a valid Computer name fqdn specification (regex test)
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2024-
    FileName    : test-isComputerNameFQDN.ps1
    License     : MIT License
    Copyright   : (c) 2024 Todd Kadrie
    Github      : https://github.com/tostka/verb-XXX
    Tags        : Powershell
    AddedCredit : Luc Fullenwarth
    AddedWebsite: https://gravatar.com/fullenw1
    AddedTwitter: twitter.com/LFullenwarth
    REVISIONS
    * 2:03 PM 6/6/2024 rounded out param validation sample to full function
    * 8/5/20 LF's posted vers (article)
    .DESCRIPTION
    test-isComputerNameFQDN.ps1 - Validate that passed string is a valid Computer name fqdn specification (regex test)
    Doesn't confirm existing machine, just that the string complies with fqdn name restrictions
    .PARAMETER  ComputerName
    ComputerName string to be validated[-ComputerName SomeBox]
    .INPUTS
    System.String Accepts piped input
    .OUTPUTS
    System.Boolean
    .EXAMPLE
    PS> test-isComputerNameFQDN -ComputerName $env:computername
    Demo simple test
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://bitbucket.org/tostka/powershell/
    .LINK
    https://itluke.online/2020/08/05/validating-computer-names-with-powershell/
    #>    
    #Requires -Modules ActiveDirectory
    PARAM(
        [Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$true,HelpMessage="ComputerName string to be validated[-ComputerName SomeBox]")]
        [ValidateLength(6, 253)]
        [validatePattern('^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$')]
        [ValidateNotNullOrEmpty()]
            [string]$ComputerName
    )
    write-output $true ; 
}

#*------^ test-isComputerNameFQDN.ps1 ^------


#*------v test-isComputerNameNetBios.ps1 v------
Function test-isComputerNameNetBios{
    <#
    .SYNOPSIS
    test-isComputerNameNetBios.ps1 - Validate that passed string is a valid Netbios Computer name specification (regex test)
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2024-
    FileName    : test-isComputerNameNetBios.ps1
    License     : MIT License
    Copyright   : (c) 2024 Todd Kadrie
    Github      : https://github.com/tostka/verb-XXX
    Tags        : Powershell
    AddedCredit : Luc Fullenwarth
    AddedWebsite: https://gravatar.com/fullenw1
    AddedTwitter: twitter.com/LFullenwarth
    REVISIONS
    * 2:03 PM 6/6/2024 rounded out param validation sample to full function
    * 8/5/20 LF's posted vers (article)
    .DESCRIPTION
    test-isComputerNameNetBios - Validate that passed string is a valid Netbios Computer name specification (regex test)
    Doesn't confirm existing machine, just that the string complies with NB name restrictions
    .PARAMETER  ComputerName
    ComputerName string to be validated[-ComputerName SomeBox]
    .INPUTS
    System.String Accepts piped input
    .OUTPUTS
    System.Boolean
    .EXAMPLE
    PS> test-isComputerNameNetBios -ComputerName $env:computername
    Demo simple test
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://bitbucket.org/tostka/powershell/
    .LINK
    https://itluke.online/2020/08/05/validating-computer-names-with-powershell/
    #>    
    #Requires -Modules ActiveDirectory
    PARAM(
        [Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$true,HelpMessage="ComputerName string to be validated[-ComputerName SomeBox]")]
            [ValidateLength(1, 15)]
            [ValidateScript({$PSItem -replace '\\|/|:|\*|\?|"||\||\.' -eq $PSItem})]
            [ValidateNotNullOrEmpty()]
            [string]$ComputerName
    )
    write-output $true ; 
}

#*------^ test-isComputerNameNetBios.ps1 ^------


#*------v test-isComputerPSRemoteable.ps1 v------
Function test-isComputerSMBCapable{
    <#
    .SYNOPSIS
    test-isComputerSMBCapable.ps1 - Validate specified computer is SMB mappable (passes Test-NetConnection -ComputerName  -CommonTCPPort 'SMB' test)
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2024-
    FileName    : test-isComputerSMBCapable.ps1
    License     : MIT License
    Copyright   : (c) 2024 Todd Kadrie
    Github      : https://github.com/tostka/verb-XXX
    Tags        : Powershell
    AddedCredit : Luc Fullenwarth
    AddedWebsite: https://gravatar.com/fullenw1
    AddedTwitter: twitter.com/LFullenwarth
    REVISIONS
    * 2:03 PM 6/6/2024 rounded out param validation sample to full function
    * 8/5/20 LF's posted vers (article)
    .DESCRIPTION
    test-isComputerSMBCapable.ps1 - Validate specified computer is SMB mappable (passes Test-NetConnection -ComputerName  -CommonTCPPort 'SMB' test)
    
    .PARAMETER  ComputerName
    ComputerName string to be validated[-ComputerName SomeBox]
    .INPUTS
    System.String Accepts piped input
    .OUTPUTS
    System.Boolean
    .EXAMPLE
    PS> test-isComputerSMBCapable -ComputerName $env:computername
    Demo simple test
    .EXAMPLE
    PS>  TRY{test-isComputerSMBCapable -ComputerName unreachablebox -ea 0 ; write-host 'Remotable' }CATCH{write-warning 'Not remotable'} ; 
    Wrap the test in try catch (as this doesn't return `$false; it throws a parameter validation error)
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://bitbucket.org/tostka/powershell/
    .LINK
    https://itluke.online/2020/08/05/validating-computer-names-with-powershell/
    #>    
    #Requires -Modules ActiveDirectory
    PARAM(
        [Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$true,HelpMessage="ComputerName string to be validated[-ComputerName SomeBox]")]
            [ValidateScript({(Test-NetConnection -ComputerName $PSItem -CommonTCPPort 'SMB').TcpTestSucceeded})]
            [ValidateNotNullOrEmpty()]
            [string]$ComputerName
    )
    write-output $true ; 
}

#*------^ test-isComputerPSRemoteable.ps1 ^------


#*------v test-isRDPSession.ps1 v------
function test-isRDPSession {
    <#
    .SYNOPSIS
    test-isRDPSession() - determine if powershell is running within an RDP session
    .NOTES
    Author: Todd Kadrie
    Website:	http://toddomation.com
    Twitter:	http://twitter.com/tostka
    CreatedDate : 2025-01-24
    FileName    : test-isRDPSession.ps1
    License     : MIT License
    Copyright   : (c) 2024 Todd Kadrie
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,RDP,TsClient
    REVISIONS   :
    # 9:49 AM 1/24/2025 rename test-Rdp -> test-isRDPSession, and alias the original name (orig name could be confused for testing is rdp server accessible); added min reqs for advfunc
    # 9:48 AM 9/25/2020 fixed to explicitly check for an RDP & clientname evari: wasn't properly firing on work box, $env:sessionname is blank, not 'Console' 
    # 3:45 PM 4/17/2020 added cbh
    # 10:45 AM 7/23/2014
    .DESCRIPTION
    test-isRDPSession() - determine if powershell is running within an RDP session
    
    RDP sets 2 environment variables on remote connect:
    $env:sessionname: RDP-Tcp#[session#]
    $env:clientname: [connecting client computername]
    
    If both are set, you're in an RDP 
    
    Proviso: unless Explorer Folder Option "Launch folder windows in a separate process" is enabled, 
    applications launched from an additional Explorer window do not have these e-varis.

    Old approach:
    if ($env:SESSIONNAME -ne 'Console') { return $True; }; 
    -> win10 on my workbox doesn't have $env:SESSIONNAME -eq 'Console', evals false positive
    
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    System.Boolean
    .EXAMPLE
    PS> if(test-isRDPSession){write-host "Running in RDP"} ; 
    Simple test for execution within an RDP seession.
    .LINK
    https://github.com/tostka/verb-network
    #>
    
    # better test is test match rgx on RDP-Tcp# string & $env:clientname populated 
    [CmdletBinding()]
    [alias("Test-RDP")]
    PARAM()
    if(($env:sessionname -match 'RDP-Tcp#\d*') -AND ($env:clientname)){ return $True} ;
}

#*------^ test-isRDPSession.ps1 ^------


#*------v Test-NetAddressIpv4TDO.ps1 v------
function Test-NetAddressIpv4TDO {
    <#
    .SYNOPSIS
    Test-NetAddressIpv4TDO.ps1 - Test if a given string is an IPv4 Network Address
    .NOTES
    Version     : 0.0.1
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2024-03-22
    FileName    : Test-NetAddressIpv4TDO.ps1
    License     : MIT License
    Copyright   : (c) 2024 Todd Kadrie
    Github      : https://github.com/tostka/verb-XXX
    Tags        : Powershell,Network,Address
    AddedCredit : REFERENCE
    AddedWebsite: URL
    AddedTwitter: URL
    REVISIONS
    * 2:49 PM 3/22/2024 init, wrapped simple [IPAddress] type accelerator test
    .DESCRIPTION
    Test-NetAddressIpv4TDO.ps1 - Test if a given string is an IPv4 Network Address
    .PARAMETER  Address
    String array to be tested for IPv4 format.
    .INPUTS
    String Accepts piped input
    .OUTPUTS
    System.Boolean
    .EXAMPLE
    PS> Test-NetAddressIpv4TDO -Address '2603:10b6:610:9f::16'
    
        True

    Test speciried string as an IPv4 Address
    .LINK
    https://github.com/tostka/verb-Network
    #>
    [CmdletBinding()]
    [Alias('Test-NetAddressIpv4')]
    [OutputType([bool])]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0,HelpMessage="Address to be validated")]
        [string[]]$Address
    ) ;
    PROCESS{
        foreach($item in $Address){
            [IPAddress]$item = $item -as [IPAddress] ; 
            [boolean]($item.AddressFamily -eq 'InterNetwork') | write-output ;
        } ;
    } ;
}

#*------^ Test-NetAddressIpv4TDO.ps1 ^------


#*------v Test-NetAddressIpv6TDO.ps1 v------
function Test-NetAddressIpv6TDO {
    <#
    .SYNOPSIS
    Test-NetAddressIpv6TDO.ps1 - Test if a given string is an IPv6 Network Address
    .NOTES
    Version     : 0.0.1
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2024-03-22
    FileName    : Test-NetAddressIpv6TDO.ps1
    License     : MIT License
    Copyright   : (c) 2024 Todd Kadrie
    Github      : https://github.com/tostka/verb-XXX
    Tags        : Powershell,Network,Address
    AddedCredit : REFERENCE
    AddedWebsite: URL
    AddedTwitter: URL
    REVISIONS
    * 2:49 PM 3/22/2024 init, wrapped simple [IPAddress] type accelerator test
    .DESCRIPTION
    Test-NetAddressIpv6TDO.ps1 - Test if a given string is an IPv6 Network Address
    .PARAMETER  Address
    String array to be tested for IPv6 format.
    .INPUTS
    String Accepts piped input
    .OUTPUTS
    System.Boolean
    .EXAMPLE
    PS> Test-NetAddressIpv6TDO -Address '2603:10b6:610:9f::16'
    
        True

    Test speciried string as an IPv6 Address
    .LINK
    https://github.com/tostka/verb-Network
    #>
    [CmdletBinding()]
    [Alias('Test-NetAddressIpv6')]
    [OutputType([bool])]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0,HelpMessage="Address to be validated")]
        [string[]]$Address
    ) ;
    PROCESS{
        foreach($item in $Address){
            [IPAddress]$item = $item -as [IPAddress] ; 
            [boolean]($item.AddressFamily -eq 'InterNetworkV6') | write-output ;
        } ; 
    } ; 
}

#*------^ Test-NetAddressIpv6TDO.ps1 ^------


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
    # 9:11 AM 1/24/2025 added -ea 0 to the gcm's; expanded gcms; added try/catch to the Net.Sockets.TcpClient code (output friendly error fail); added CBH demo rdp users poll
        ; removed aliases 's' & 'p' (they're already usable as abbrev $server & $port, no other conflicting params ); flip 1st expl to commonly used 3389 (rdp) port; added cmdletbinding (full adv func/verbose support); added alias test-portTDO
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
    PS> test-port -ComputerName hostname -Port 3389 -verbose
    Check hostname port 3389 (rdp server), with verbose output
    .EXAMPLE
    PS> 'SERVER1','SERVER2'|%{
    PS>     $ts = $_ ;
    PS>     write-host "`n`n==$($ts)" ;
    PS>     if(test-port -server $ts -port 3389){
    PS>         quser.exe /server:$ts
    PS>     } else {
    PS>         write-warning "$($ts):TSCPort 3389 unavailable! (check ping...)" ;
    PS>         $ctest = $null ; 
    PS>         TRY{$ctest = test-connection -ComputerName $ts -Count 1 -ErrorAction stop} CATCH {write-warning $Error[0].Exception.Message} 
    PS>         if($ctest){
    PS>             write-warning "$($ts):_Pingable_, but TSCPort 3389 unavailable!" ;
    PS>         }else {
    PS>             write-warning "$($ts):UNPINGABLE!" ;
    PS>         };
    PS>     };
    PS> } ; 
    Scriptblock that stacks test-port 3389 (rdp server) & test-connection against series of computers, to conditionally exec a query (run quser.exe rdp-user report)
    .LINK
    https://github.com/tostka/verb-network
    #>
    [CmdletBinding()]
    [alias("test-portTDO")]
    PARAM(
        [parameter(Position=0,Mandatory=$true)]
            [alias('ComputerName','TargetName')]
            [string]$Server,
        [parameter(Position=1,Mandatory=$true)]
            [alias('TcpPort')]
            [ValidatePattern("^(65.4.0-5]|655[0-2]\d|65[0-4]\d\d|6[0-4]\d{3}|[1-5]\d{4}|[1-9]\d{0,3}|0)$")]
            [int32]$Port
    )
    if($host.version.major -ge 6 -AND (get-command test-connection -ea STOP)){
        write-verbose "(Psv6+:using PS native:test-connection -Targetname  $($server) -tcpport $($port)...)" ; 
        TRY {$PortTest = test-connection -targetname $Server -tcpport $port -Count 1 -ErrorAction SilentlyContinue -ErrorVariable Err } CATCH { $PortTest = $Null } ;
        if($PortTest -ne $null ){
            write-verbose "Success" ; 
            return $true ; 
        } else {
            write-verbose "Failure" ; 
            return $False;
        } ; 
    } elseif (get-command Test-NetConnection -ea STOP){
        write-verbose "(Psv5:using NetTCPIP:Test-NetConnection -computername $($server) -port $($port)...)" ; 
        if( (Test-NetConnection -computername $Server -port $port).TcpTestSucceeded ){
            write-verbose "Success" ; 
            return $true ; 
        } else {
            write-verbose "Failure" ; 
            return $False;
        } ; 
    } elseif([System.Environment]::OSVersion.Platform -eq 'Win32NT'){ 
        write-verbose "(Falling back to PsWin:Net.Sockets.TcpClient)" ; 
        $Socket = new-object Net.Sockets.TcpClient ; 
        TRY{ $Socket.Connect($Server, $Port) }CATCH{ write-warning "FAILED:($Socket).Connect(($Server), ($Port)" };
        if ($Socket.Connected){
            $Socket.Close() ; 
            write-verbose "Success" ; 
            return $True;
        } else {
            write-verbose "Failure" ; 
            return $False;
        } # if-block end
        $Socket = $null
    } else {
        throw "Unsupported OS/Missing depedancy! (missing PSCore6+, NetTCPIP, or even .net.sockets.tcpClient)! Aborting!" ;
    } ; 
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


#*------v update-SecurityProtocolTDO.ps1 v------
function update-SecurityProtocolTDO {
    <#
    .SYNOPSIS
    update-SecurityProtocolTDO -  Polls available 'Net.SecurityProtocolType' TLS revisions, above the current Max TLS type, and updates the Net.ServicePointManager.SecurityProtocol to include those revised types
    .NOTES
    Version     : 0.63
    Author      : rmbolger
    Website     : https://www.reddit.com/r/PowerShell/comments/ozr6ye/psa_enabling_tls12_and_you/
    Twitter     : 
    CreatedDate : 2024-09-04
    FileName    : update-SecurityProtocolTDO.ps1
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,Network,Security,TLS
    AddedCredit : Todd Kadrie
    AddedWebsite: http://www.toddomation.com
    AddedTwitter: @tostka / http://twitter.com/tostka
    REVISIONS
    * 12:03 PM 9/4/2024 init expanded the sample SB into a function, added to verb-Network
    * 2021 - rmbolger's reddit r/Powershell scriptblock demo that appends latest TLS revs to the current list 
    .DESCRIPTION
    update-SecurityProtocolTDO -  Polls available 'Net.SecurityProtocolType' TLS revisions, above the current Max TLS type, and updates the Net.ServicePointManager.SecurityProtocol to include those revised types

    Works around random authentication errors from MS o365 etc, due to windows Powershell (5.x)'s default use of TLS1.0, even when higher revs are mounted in the OS
    
    Sample error (from Exchange Online): 
    "The specified value is not valid in the 'SslProtocolType' enumeration."

    Basic usage is to run update-SecurityProtocolTDO(), to ensure the Powershell (winPS5.5) TLS ciphers are fully up to date in use, *before* opening connections to MS services (EXO, https, smtp etc - anything that uses TLS for connectivity, could fail with 
    Discussion on r/Powershell:

        [Ecrofirt](https://www.reddit.com/user/Ecrofirt/)

        • [3y ago](https://www.reddit.com/r/PowerShell/comments/ozr6ye/comment/h81pslu/) • Edited 3y ago

 
        I have found it easier to follow Microsoft's guide to enabling TLS 1.2 in .NET. 
        that change is system-wide, which has meant I haven't needed to put this line 
        in every script using HTTPS

 
        [https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/security/enable-tls-1-2-client#bkmk\_net](https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/security/enable-tls-1-2-client#bkmk_net)
        ```
        \[HKEY\_LOCAL\_MACHINE\\SOFTWARE\\Microsoft\\.NETFramework\\v2.0.50727\]
                "SystemDefaultTlsVersions" = dword:00000001
                "SchUseStrongCrypto" = dword:00000001

        \[HKEY\_LOCAL\_MACHINE\\SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319\]
            "SystemDefaultTlsVersions" = dword:00000001
            "SchUseStrongCrypto" = dword:00000001        
            ```

        [joeykins82](https://www.reddit.com/user/joeykins82/)

        • [3y ago](https://www.reddit.com/r/PowerShell/comments/ozr6ye/comment/h81um1e/)

        You don't need `SchUseStrongCrypto` if you've set `SystemDefaultTlsVersions`

        For full compatibility/consistency you should also set the same entries in 
        `HKLM:\SOFTWARE\WOW6432Node\...`: it's generally less important on servers but 
        while there's still the odd 32-bit application floating around there's no 
        downside in ensuring that 32-bit applications making .NET HTTPS calls are also 
        using the SCHANNEL defaults for TLS
 
        Also also if you're running WinSvr2012 (Win6.2) or you need to tell 
        WinHTTP to use TLS 1.2 via the `DefaultSecureProtocols` subkey, and also also 
        also if you still have 2008 R2 or Win7 laying around you have to do that AND 
        configure SCHANNEL itself. 


    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    This script return general info about certificate chain status 
    .EXAMPLE
    PS> update-SecurityProtocolTDO ; 
    PS> $mod = 'ExchangeOnlineManagement' ; Try {Get-Module $mod -ErrorAction Stop | out-null } Catch {Import-Module -Name $mod -MinimumVersion '3.1.0' -ErrorAction Stop  } ;
    PS> $Status = Get-ConnectionInformation -ErrorAction SilentlyContinue
    PS> If (-not ($Status)) {Connect-ExchangeOnline -prefix xo -SkipLoadingCmdletHelp -ShowBanner:$false ; }; 
    demo pre-updating PS TLS rev to latest OS-defined ciphers, before initiating EXO connection
    .LINK
    https://www.reddit.com/r/PowerShell/comments/ozr6ye/psa_enabling_tls12_and_you/
    .LINK
    https://github.com/tostka/verb-network
    #>
    #requires -Version 2.0
    [CmdletBinding()]
    #[Alias('','')]
    PARAM() ;
    BEGIN {
        $Verbose = ($VerbosePreference -eq 'Continue')        
        $CurrentVersionTlsLabel = [Net.ServicePointManager]::SecurityProtocol ; # Tls, Tls11, Tls12 ('Tls' == TLS1.0)  ;
        write-verbose "PRE: `$CurrentVersionTlsLabel : $($CurrentVersionTlsLabel )" ; 
        # psv6+ already covers, test via the SslProtocol parameter presense
        if ('SslProtocol' -notin (Get-Command Invoke-RestMethod).Parameters.Keys) {
            $currentMaxTlsValue = [Math]::Max([Net.ServicePointManager]::SecurityProtocol.value__,[Net.SecurityProtocolType]::Tls.value__) ; 
            write-verbose "`$currentMaxTlsValue : $($currentMaxTlsValue )" ; 
            $newerTlsTypeEnums = [enum]::GetValues('Net.SecurityProtocolType') | Where-Object { $_ -gt $currentMaxTlsValue }
            if($newerTlsTypeEnums){
                write-verbose "Appending upgraded/missing TLS `$enums:`n$(($newerTlsTypeEnums -join ','|out-string).trim())" ; 
            } else {
                write-verbose "Current TLS `$enums are up to date with max rev available on this machine" ; 
            }; 
            $newerTlsTypeEnums | ForEach-Object {
                [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor $_
            } ; 
        } ; 
    } ;
    PROCESS {} ;  # loop-E $Certificate
    END {write-verbose "POST: Current TLS `$enums:$(([Net.ServicePointManager]::SecurityProtocol |out-string).trim())" ; } ; 
}

#*------^ update-SecurityProtocolTDO.ps1 ^------


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
    convert-Int64toIP -int 3232235521
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
        [parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="64-bit integer IP address  representation, to be converted back to IP[-int 3232235521]")]
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
    3232235521
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

Export-ModuleMember -Function Add-IntToIPv4Address,Connect-PSR,convert-IPAddressToReverseTDO,Disconnect-PSR,get-CertificateChainOfTrust,Get-DnsDkimRecord,get-DNSServers,get-IPSettings,Get-NetIPConfigurationLegacy,get-NetworkClass,get-NetworkSubnet,Get-RestartInfo,get-tsUsers,get-WebTableTDO,get-whoami,Invoke-BypassPaywall,New-RandomFilename,Invoke-SecurityDialog,push-TLSLatest,Reconnect-PSR,Resolve-DNSLegacy.ps1,Resolve-DnsSenderIDRecords,resolve-NetworkLocalTDO,resolve-SMTPHeader,resolve-SPFMacros,resolve-SPFMacrosTDO,convert-IPAddressToReverseTDO,Resolve-SPFRecord,SPFRecord,SPFRecord,SPFRecord,convert-IPAddressToReverseTDO,test-IpAddressCidrRange,save-WebDownload,save-WebDownloadCurl,save-WebDownloadDotNet,save-WebFaveIcon,Send-EmailNotif,split-DnsTXTRecord,summarize-PassStatus,summarize-PassStatusHtml,test-ADComputerName,test-CertificateTDO,_getstatus_,test-Connection-T,Test-DnsDkimCnameToTxtKeyTDO,test-IpAddressCidrRange,Test-IPAddressInRange,Test-IPAddressInRangeIp6,Test-IPAddressInRangeIp6,test-isADComputerName,test-isComputerDNSRegistered,test-isComputerNameFQDN,test-isComputerNameNetBios,test-isComputerSMBCapable,test-isRDPSession,Test-NetAddressIpv4TDO,Test-NetAddressIpv6TDO,Test-Port,test-PrivateIP,Test-RDP,update-SecurityProtocolTDO -Alias *




# SIG # Begin signature block
# MIIELgYJKoZIhvcNAQcCoIIEHzCCBBsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUsE8NJqioPqXx2KqRM+eVEdI2
# vDWgggI4MIICNDCCAaGgAwIBAgIQWsnStFUuSIVNR8uhNSlE6TAJBgUrDgMCHQUA
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
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBS/eXlG
# OLEe9WnhCch5zGgZ95ltcTANBgkqhkiG9w0BAQEFAASBgHBD4iDR38WggSWN0x17
# zxnK4Vv3aO96ul5v1OFjPGmrJAnWhy92ihiHdKjh7m2IOOyIsmMchcPqXzbI0AqR
# Bo0Tfard3MNSYgRNptbcaPGMV2kMw10lZc7XHaAHE6OP3/wHa5bvfJkfizo4SnzK
# qBASKCeFUYGCclVXlZfCGDri
# SIG # End signature block
