# verb-network.psm1


<#
.SYNOPSIS
verb-Network - Generic network-related functions
.NOTES
Version     : 1.0.18.0
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

#*======v FUNCTIONS v======



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

#*------v download-file.ps1 v------
function download-file {
    <#
    .SYNOPSIS
    download-file.ps1 - simple download client
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2020-04-17
    FileName    : download-file.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell,Internet,Download,File
    REVISIONS
    11:31 AM 4/17/2020 added CBH
    .DESCRIPTION
    download-file.ps1 - simple download client
    .PARAMETER  url
    Url to be downloaded
    .PARAMETER  DestinationName
    Full path to destiontion file for download
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output
    .EXAMPLE
    download-file -url https://xxx -destinationname c:\pathto\file.ext
    .LINK
    #>
        [CmdletBinding()]
        PARAM ([string]$url, [string]$DestinationName)
        $rgxURLParse = "^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?" ;
        if ($url -match $rgxURLParse) {
            $host = $matches[4] ;
            if (test-connection -ComputerName $host -count 1) {
                $client = new-object system.net.WebClient
                $client.Headers.Add("user-agent", "PowerShell")
                $client.downloadfile($url, $DestinationName)
            }
            else {
                throw "unable to Ping $()" ;
            } ;
        }
        else {
            throw "Unparsable url, to fqdn:$($url)" ;
        } ;
    }

#*------^ download-file.ps1 ^------

#*------v download-filecurl.ps1 v------
function download-filecurl {
    <#
    .SYNOPSIS
    download-filecurl.ps1 - simple download wrapper around curl cmdline util
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2020-04-17
    FileName    : download-filecurl.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell,Internet,Download,File
    REVISIONS
    11:31 AM 4/17/2020 added CBH
    .DESCRIPTION
    download-filecurl.ps1 - simple download client
    .PARAMETER  url
    Url to be downloaded
    .PARAMETER  DestinationName
    Full path to destiontion file for download
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output
    .EXAMPLE
    download-filecurl -url https://xxx -destinationname c:\pathto\file.ext
    .LINK
    #>
    PARAM ([string]$url, [string]$DestinationName)
    $CurlArgument = '-o $($DestinationName)', '$($url)' ;
    if (($PSVersionTable.PSEdition -eq 'Desktop') -OR ($IsCoreCLR -AND $IsWindows) -OR !$PSVersionTable.PSEdition) {$CURLEXE = "$env:windir\System32\curl.exe" } ; 
    elseif ($IsCoreCLR -AND $IsLinux) {$CURLEXE = 'curl'} ;
    & $CURLEXE @CurlArgument ;
}

#*------^ download-filecurl.ps1 ^------

#*------v download-fileNoSSL.ps1 v------
function download-fileNoSSLNoSSL {
    <#
    .SYNOPSIS
    download-fileNoSSLNoSSL.ps1 - simple download client - overridding the SSL trust requirement to get the file (insecure, for testing)
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2020-04-17
    FileName    : download-fileNoSSL.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell,Internet,Download,File
    REVISIONS
    * 11:31 AM 4/17/2020 added CBH
    * 3:04 PM 8/13/2014
    .DESCRIPTION
    download-fileNoSSL.ps1 - simple download client - overridding the SSL trust requirement to get the file (insecure, for testing)
    .PARAMETER  url
    Url to be downloaded
    .PARAMETER  DestinationName
    Full path to destiontion file for download
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output
    .EXAMPLE
    $url = "http://www.cs.wisc.edu/~ballard/bofh/excuses" ; 
    $DestinationName = "c:\temp\temp.html" ; 
    download-file $url $DestinationName
    .LINK
    http://blogs.technet.com/b/bshukla/archive/2010/04/12/ignoring-ssl-trust-in-powershell-system-net-webclient.aspx
    #>
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } ;
        $client = new-object system.net.WebClient ;
        if ($DestinationName) {
            $client.DownloadString($url) | out-file -FilePath $local;
        }
        else {
            # stream to console
            $client.DownloadString($url) ;
        } # if-block end
        # not sure if toggle back is necesesary, but try it
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $false } ;
    }

#*------^ download-fileNoSSL.ps1 ^------

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

#*------v Send-EmailNotif.ps1 v------
Function Send-EmailNotif {
    <#
    .SYNOPSIS
    Send-EmailNotif.ps1 - Mailer function (wraps send-mailmessage)
    .NOTES
    Author: Todd Kadrie
    Website:	http://www.toddomation.com
    Twitter:	@tostka, http://twitter.com/tostka
    Website:	URL
    Twitter:	URL
    REVISIONS   :
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
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output.
    .EXAMPLE
        # This normally gets triggered from Cleanup()
        # constants
        $smtpFrom = (($scriptBaseName.replace(".","-")) + "@toro.com") ;
        $smtpSubj= ("Daily Rpt: "+ (Split-Path $transcript -Leaf) + " " + [System.DateTime]::Now) ;
        #$smtpTo="emailadmin@toro.com" ;
        #$smtpTo="LYNDLISMessagingReports@toro.com" ;
        # 1:02 PM 4/28/2017 hourly run, just send to me
        $smtpTo="todd.kadrie@toro.com" ;
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
    .LINK
    #>

    <# send-mailmessage params: (set up param aliases)
    Send-MailMessage [-To] <String[]> [-Subject] <String> [[-Body] <String>] [[-SmtpServer] <String>] [-Attachments
    <String[]>] [-Bcc <String[]>] [-BodyAsHtml] [-Cc <String[]>] [-Credential <PSCredential>]
    [-DeliveryNotificationOption <DeliveryNotificationOptions>] [-Encoding <Encoding>] [-Port <Int32>] [-Priority
    <MailPriority>] [-UseSsl] -From <String> [<CommonParameters>]
    #>
    [CmdletBinding()]
    PARAM(
        [parameter(Mandatory=$true)]
        [alias("from")]
        [string] $SMTPFrom,
        [parameter(Mandatory=$true)]
        [alias("To")]
        [string] $SmtpTo,
        [parameter(Mandatory=$true)]
        [alias("subj","Subject")]
        [string] $SMTPSubj,
        [parameter(Mandatory=$false)]
        [alias("server")]
        [string] $SMTPServer,
        [parameter(Mandatory=$false)]
        [alias("port")]
        [string] $SMTPPort,
        [parameter(Mandatory=$true)]
        [alias("Body")]
        [string] $SmtpBody,
        [parameter(Mandatory=$false)]
        [string] $BodyAsHtml,
        [parameter(Mandatory=$false)]
        [alias("attach","Attachments","attachment")]
        $SmtpAttachment
    )
    $verbose = ($VerbosePreference -eq "Continue") ; 
    # before you email conv to str & add CrLf:
    $SmtpBody = $SmtpBody | out-string
    # just default the port if missing, and always use it
    if ($SMTPPort -eq $null) {
        $SMTPPort = 25;
    }	 # if-block end

    if ( ($myBox -contains $env:COMPUTERNAME) -OR ($AdminJumpBoxes -contains $env:COMPUTERNAME) ) {
        $SMTPServer = $global:SMTPServer ;
        $SMTPPort = $smtpserverport ; # [infra file]
        write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):Mailing:$($SMTPServer):$($SMTPPort)" ;
    }
    elseif ((Get-Service -Name MSExchangeADTopology -ea 0 ) -AND (get-exchangeserver $env:computername | Where-Object {$_.IsHubTransportServer})) {
        $SMTPServer = $env:computername ;
        write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):Mailing Locally:$($SMTPServer)" ;
    }
    elseif ((Get-Service -Name MSExchangeADTopology -ea 0 ) ) {
        # non Hub Ex server, draw from local site
        $htsrvs = (Get-ExchangeServer | Where-Object {  ($_.Site -eq (get-exchangeserver $env:computername ).Site) -AND ($_.IsHubTransportServer) } ) ;
        $SMTPServer = ($htsrvs | get-random).name ;
        write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):Mailing Random Hub:$($SMTPServer)" ;
    }
    else {
        # non-Ex servers, non-mybox: Lync etc, assume vscan access
        write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):Non-Exch server, assuming Vscan access" ;
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
        write-warning "$((get-date).ToString('HH:mm:ss')):Less than Psv3 detected: send-mailmessage does NOT support -Port, defaulting (to 25) ";
    } ;

    # trigger html if body has html tags in it
    if ($BodyAsHtml -OR ($SmtpBody -match "\<[^\>]*\>")) {$Email.BodyAsHtml = $True } ;

    # dumping to pipeline appears out of sync in console put it into a write- command to keep in sync
    write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):send-mailmessage w`n$(($email |out-string).trim())" ; 
    if ($validatedAttachments) {write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):`$validatedAttachments:$(($validatedAttachments|out-string).trim())" } ;
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
        Write-Warning "$(get-date -format 'HH:mm:ss'): Failed processing $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ;
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

#*------v Test-Port.ps1 v------
function Test-Port {

    <#
    .SYNOPSIS
    Test-Port() - test the specified ip/fqdn port combo
    .NOTES
    Author: Todd Kadrie
    Website:	http://toddomation.com
    Twitter:	http://twitter.com/tostka

    REVISIONS   :
    # call: Test-Port $server $port
    # 10:42 AM 4/15/2015 fomt cleanup, added help
    # vers: 8:42 AM 7/24/2014 added proper fail=$false
    # vers: 10:25 AM 7/23/2014 disabled feedback, added a return
    .PARAMETER  Server
    Server fqdn, name, ip to be connected to
    .PARAMETER  port
    Port number to be connected to
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output.
    .EXAMPLE
    .EXAMPLE
    .LINK
    *----------^ END Comment-based Help  ^---------- #>

    PARAM(
        [parameter(Mandatory=$true)]
        [alias("s")]
        [string]$Server,
        [parameter(Mandatory=$true)]
        [alias("p")]
        [int]$Port
    )

    # 10:46 AM 4/15/2015 validate port in supported range: 0 -65536
    if( $Port -notmatch "^(6553[0-5]|655[0-2]\d|65[0-4]\d\d|6[0-4]\d{3}|[1-5]\d{4}|[1-9]\d{0,3}|0)$" ) {
        throw "$($Port) is an INVALID port. ABORTING";
    } else {
        $ErrorActionPreference = "SilentlyContinue"
        $Socket = new-object Net.Sockets.TcpClient
        $Socket.Connect($Server, $Port)

        if ($Socket.Connected){
            #write-host "We have successfully connected to the server" -ForegroundColor Yellow -BackgroundColor Black
            $Socket.Close()
            # 9:54 AM 7/23/2014 added return true/false
            return $True;
        } else {
            #write-host "The port seems to be closed or you cannot connect to it" -ForegroundColor Red -BackgroundColor Black
            return $False;
        } # if-block end
        $Socket = $null
    } # if-E port-range valid
}

#*------^ Test-Port.ps1 ^------

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

#*======^ END FUNCTIONS ^======

Export-ModuleMember -Function Connect-PSR,Disconnect-PSR,download-file,download-filecurl,download-fileNoSSLNoSSL,get-IPSettings,get-whoami,Reconnect-PSR,Send-EmailNotif,summarize-PassStatus,summarize-PassStatusHtml,Test-Port,Test-RDP -Alias *


# SIG # Begin signature block
# MIIELgYJKoZIhvcNAQcCoIIEHzCCBBsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU9GRMb39Kz7fTFZ79dNlHphLE
# VqCgggI4MIICNDCCAaGgAwIBAgIQWsnStFUuSIVNR8uhNSlE6TAJBgUrDgMCHQUA
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
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQRqo2E
# e8BrcJeBMwjMTyiaItDaxjANBgkqhkiG9w0BAQEFAASBgKVwJEtOfaEycwcwdFBW
# 7lw76NiLFlSzbOdeupNgDKvzkVNurwEQMBIl3CLkHpDNkRWUiSHkK2gNFClPlgvj
# LSmMLFKn/2vSv9y42nToJeoqjxlO6y6gK2FtpYwkQ837Ncra9hSZLSbXKZer5Sq6
# Zfn3/GEkieFksuPI/qxWOe5d
# SIG # End signature block
