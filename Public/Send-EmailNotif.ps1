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
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output.
    .EXAMPLE
        # This normally gets triggered from Cleanup()
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
        [parameter(HelpMessage="Switch for SSL")]
        [int] $useSSL,
        [parameter(Mandatory=$true,HelpMessage="Message Body")]
        [alias("Body")]
        [string] $SmtpBody,
        [parameter(HelpMessage="Switch for Body in Html format")]
        [string] $BodyAsHtml,
        [parameter(HelpMessage="array of attachement files")]
        [alias("attach","Attachments","attachment")]
        $SmtpAttachment,
        [Parameter(HelpMessage="Credential (PSCredential obj) [-credential XXXX]")]
        [System.Management.Automation.PSCredential]$Credential
    )
    
    $verbose = ($VerbosePreference -eq "Continue") ; 
    # before you email conv to str & add CrLf:
    $SmtpBody = $SmtpBody | out-string
    # just default the port if missing, and always use it
    if ($SMTPPort -eq $null) {
        $SMTPPort = 25;
    }	 # if-block end
    if(-not $SMTPServer){
        if ( ($myBox -contains $env:COMPUTERNAME) -OR ($AdminJumpBoxes -contains $env:COMPUTERNAME) ) {
            $SMTPServer = $global:SMTPServer ;
            $SMTPPort = $smtpserverport ; # [infra file]
            write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):Mailing:$($SMTPServer):$($SMTPPort)" ;
        }elseif ((Get-Service -Name MSExchangeADTopology -ea 0 ) -AND (get-exchangeserver $env:computername | Where-Object {$_.IsHubTransportServer})) {
            $SMTPServer = $env:computername ;
            write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):Mailing Locally:$($SMTPServer)" ;
        }elseif ((Get-Service -Name MSExchangeADTopology -ea 0 ) ) {
            # non Hub Ex server, draw from local site
            $htsrvs = (Get-ExchangeServer | Where-Object {  ($_.Site -eq (get-exchangeserver $env:computername ).Site) -AND ($_.IsHubTransportServer) } ) ;
            $SMTPServer = ($htsrvs | get-random).name ;
            write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):Mailing Random Hub:$($SMTPServer)" ;
        }else {
            # non-Ex servers, non-mybox: Lync etc, assume vscan access
            write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):Non-Exch server, assuming Vscan access" ;
            $SMTPServer = "vscan.toro.com" ;
        } ;
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
        write-verbose "Adding specified credential" ; 
        $Email.add('Credential',$Credential) ; 
    } ; 
    
    if($useSSL){
        write-verbose "Adding specified credential" ; 
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