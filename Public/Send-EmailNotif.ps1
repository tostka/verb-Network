# Send-EmailNotif.ps1

#region SEND_EMAILNOTIF ; #*------v Send-EmailNotif v------
#if(-not(gi function:Send-EmailNotif -ea 0){
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
        PS> #$body = (Get-Content "path-to-file\file.html" ) | converto-html ;
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
        }	 ;
        if ( ($myBox -contains $env:COMPUTERNAME) -OR ($AdminJumpBoxes -contains $env:COMPUTERNAME) ) {
            $SMTPServer = $global:SMTPServer ;
            $SMTPPort = $smtpserverport ; # [infra file]
            $smsg = "Mailing:$($SMTPServer):$($SMTPPort)" ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
        }elseif(get-command Get-ExchangeServer -ea 0){
            if ((get-service MSEx* -ea 0) -AND (get-exchangeserver $env:computername | Where-Object {$_.IsHubTransportServer -OR $_.IsEdgeServer})) {
                $SMTPServer = $env:computername ;
                $smsg = "Mailing Locally:$($SMTPServer)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
            }elseif ((get-service MSEx* -ea 0)  -AND (gcm Get-ExchangeServer -ea 0) {
                # non Hub Ex server, draw from local site
                $htsrvs = (Get-ExchangeServer | Where-Object {  ($_.Site -eq (get-exchangeserver $env:computername ).Site) -AND ($_.IsHubTransportServer -OR $_.IsEdgeServer) } ) ;
                $SMTPServer = ($htsrvs | get-random).name ;
                $smsg = "Mailing Random Hub:$($SMTPServer)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
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
            #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
            # but dyn ip workstations, not
            $SMTPServer = "vscan.toro.com" ;
        } ;
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
            $Email.add('Credential',$Credential) ; 
        } ; 
        if($useSSL){
            $Email.add('useSSL',$useSSL) ; 
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
        if ($host.version.major -ge 3) {$Email.add("Port", $($SMTPPort))}
        elseif ($SmtpPort -ne 25) {
            $smsg = "WWLess than Psv3 detected: send-mailmessage does NOT support -Port, defaulting (to 25) ";
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
        } ;
        # trigger html if body has html tags in it
        if ($BodyAsHtml -OR ($SmtpBody -match "\<[^\>]*\>")) {$Email.BodyAsHtml = $True } ;
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
            } else {
                send-mailmessage @email
            } ;
        }CATCH {
            $smsg = "Failed processing $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ;
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
        } ; 
        $error.clear() ;
    } ;
} ; 
#endregion SEND_EMAILNOTIF ; #*------^ END Send-EmailNotif ^------
