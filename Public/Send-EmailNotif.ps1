Function Send-EmailNotif {
    <#
    .SYNOPSIS
    Send-EmailNotif.ps1 - Mailer function (wraps send-mailmessage)
    .NOTES
    Author: Todd Kadrie
    Website:	http://www.toddomation.com
    Twitter:	@tostka, http://twitter.com/tostka
    Additional Credits: REFERENCE
    Website:	URL
    Twitter:	URL
    REVISIONS   :
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
            Send-EmailNotif ;
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
    # by remming the below, they inherit out of params set in global scope - prolly should recast them lowercase, to reflect global scope
    <#
    PARAM(
    [parameter(Mandatory=$true)]
    [alias("from")]
    [string] $SMTPFrom,
    [parameter(Mandatory=$true)]
    [alias("To")]
    [string] $SmtpTo,
    [parameter(Mandatory=$true)]
    [parameter(Mandatory=$true)]
    [alias("subj","Subject")]
    [string] $SMTPSubj,
    [parameter(Mandatory=$true)]
    [alias("server","SmtpServer")]
    [string] $SMTPServer,
    [parameter(Mandatory=$true)]
    [alias("port")]
    [string] $SMTPPort,
    [parameter(Mandatory=$true)]
    [alias("Body")]
    [string] $SmtpBody,
    [parameter(Mandatory=$false)]
    [string] $BodyAsHtml,
    [parameter(Mandatory=$false)]
    [alias("attach","Attachments","attachment")]
    [string] $SmtpAttachment
    )
    #>

    # before you email conv to str & add CrLf:
    $SmtpBody = $SmtpBody | out-string
    # just default the port if missing, and always use it
    if ($SMTPPort -eq $null) {
        $SMTPPort = 25;
    }	 # if-block end

    #if ( ($myBox -contains $env:COMPUTERNAME) -OR ($env:COMPUTERNAME -match $rgxLyncServers) ) {
    # 2:19 PM 4/26/2017 lync doesn't need 8111, has vscan access
    # 11:04 AM 11/29/2018 added -ea 0 on the get-services
    if ( ($myBox -contains $env:COMPUTERNAME) ) {
        #$SMTPServer = [infra file]
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
    } ; # if-block end

    if ($host.version.major -ge 3) {
        $Email.add("Port", $($SMTPPort));
    }
    elseif ($SmtpPort -ne 25) {
        write-warning "$((get-date).ToString('HH:mm:ss')):Less than Psv3 detected: send-mailmessage does NOT support -Port, defaulting (to 25) ";
    } ;

    if ($BodyAsHtml) {
        $Email.BodyAsHtml = $True;
    } # if-E
    <# 11:59 AM 8/28/2013 mailing debugging code
    write-host  -ForegroundColor Yellow "Emailing with following parameters:"
    $Email
    write-host "body:"
    $SmtpBody
    write-host ("-" * 5)
    write-host "body.length: " $SmtpBody.length
    #>

    write-host "sending mail..."
    $email | out-string ;
    if ($validatedAttachments) {write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):`$validatedAttachments:$(($validatedAttachments|out-string).trim())" } ;
    $error.clear()
    TRY {
        if ($validatedAttachments) {
            # 12:14 PM 11/5/2018 looks like on psv2?v3 attachment is an array, can be pipelined in too
            $validatedAttachments | send-mailmessage @email ;
        }
        else {
            send-mailmessage @email
        } ;
    }
    Catch {
        write-host -red  "$((get-date).ToString('HH:mm:ss')): Failed send-mailmessage attempt"
        write-host -red  "$((get-date).ToString('HH:mm:ss')): Error in $($_.InvocationInfo.ScriptName)."
        write-host -red  "$((get-date).ToString('HH:mm:ss')): -- Error information"
        write-host -red  "$((get-date).ToString('HH:mm:ss')): Line Number: $($_.InvocationInfo.ScriptLineNumber)"
        write-host -red  "$((get-date).ToString('HH:mm:ss')): Offset: $($_.InvocationInfo.OffsetInLine)"
        write-host -red  "$((get-date).ToString('HH:mm:ss')): Command: $($_.InvocationInfo.MyCommand)"
        write-host -red  "$((get-date).ToString('HH:mm:ss')): Line: $($_.InvocationInfo.Line)"
        write-host -red  "$((get-date).ToString('HH:mm:ss')): Error Details: $($_)"
    } ; # try/catch-E

    # then pipe just the errors out to console
    #if($error.count -gt 0){write-host $error }

}
