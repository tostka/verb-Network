# show-SerMtaLogFormattedOutput.ps1

#*----------v Function show-SerMtaLogFormattedOutput() v----------
function show-SerMtaLogFormattedOutput {
    <#
    .SYNOPSIS
    show-SerMtaLogFormattedOutput.ps1 - Takes Proofpoint SER Logs (from clipboard) and Reports > Log Viewer  'MTA' Log File Type output, and parses it to provide an unwrapped display for readability of the output data (which tends to have random line breaks, and partial lines)
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2026-03-19
    FileName    : show-SerMtaLogFormattedOutput.ps1
    License     : MIT License
    Copyright   : (c) 2026 Todd Kadrie
    Github      : https://github.com/tostka/verb-network
    Tags        : Powershell,Proofpoint,SecureEmailRelay,SER,Log,MessageTrace
    AddedCredit : REFERENCE
    AddedWebsite: URL
    AddedTwitter: URL
    REVISIONS
    * 12:04 PM 3/19/2026 init
    .DESCRIPTION
    show-SerMtaLogFormattedOutput.ps1 - Takes Proofpoint SER Logs (from clipboard) and Reports > Log Viewer  'MTA' Log File Type output, and parses it to provide an unwrapped display for readability of the output data (which tends to have random line breaks, and partial lines)
    
    .PARAMETER LogText
    The raw Filter Log output text report
    .PARAMETER masterserver
    Array containing OnPrem Master Server nbname,serverIP (used to resolve hosts)
    .PARAMETER agentserver
    Array containing OnPrem Agent Server nbname,serverIP (used to resolve hosts)
    .INPUTS
    None. Does not accepted piped input.(.NET types, can add description)
    .OUTPUTS
    None. Returns no objects or output (.NET types)
    .EXAMPLE
    PS> $hsLogOutput = @"
		2026-03-18T15:06:22.652742-07:00 SIT-PPAGENT-01 queued-ser[26103]: 62IM6FMg026103: from=<Aaaaaaa@aaaa.aaa>, size=21724, class
=0, nrcpts=1, msgid=<b7d44227-e0da-4648-9a0e-fcaa469c0c0f@LYNMS651.aaaaaa.aa.aaaa.aaa>, proto=ESMTP, daemon=MTA, tls_verify=N
ONE, tls_version=NONE, cipher=NONE, auth=NONE, relay=SIT-PPAGENT-01.toro.com [127.0.0.1]
2026-03-18T15:06:23.253533-07:00 SIT-PPAGENT-01 queued-ser[26108]: 62IM6FMg026103: to=<aaaaaaaa9@AaAaaa.aaa>, delay=00:00:01,
xdelay=00:00:01, mailer=esmtp, tls_verify=OK, tls_version=TLSv1.2, cipher=ECDHE-RSA-AES256-GCM, pri=141724, relay=smtp-us.se
r.proofpoint.com. [99.999.999.999], dsn=2.0.0, stat=Sent (2z1ywXGjAvJb72z1zwkOzm mail accepted for delivery)
"@ ; 
    PS> show-SerMtaLogFormattedOutput -LogText $hsLogOutput
    
        2026-03-18T15:06:22.652742-07:00 SIT-PPAGENT-01 queued-ser[26103]: 62IM6FMg026103: from=<Aaaaaaa@aaaa.aaa>
         size=21724
         class=0
         nrcpts=1
         msgid=<b7d44227-e0da-4648-9a0e-fcaa469c0c0f@AAAAA999.aaaaaa.aa.aaaa.aaa>
         proto=ESMTP
         daemon=MTA
         tls_verify=NONE
         tls_version=NONE
         cipher=NONE
         auth=NONE
         relay=SIT-PPAGENT-01.aaaa.aaa [127.0.0.1]

        2026-03-18T15:06:23.253533-07:00 SIT-PPAGENT-01 queued-ser[26108]: 62IM6FMg026103: to=<aaaaaa.aa.aaaa.aaa>
         delay=00:00:01
        xdelay=00:00:01
         mailer=esmtp
         tls_verify=OK
         tls_version=TLSv1.2
         cipher=ECDHE-RSA-AES256-GCM
         pri=141724
         relay=smtp-us.ser.proofpoint.com. [99.999.999.999]
         dsn=2.0.0
         stat=Sent (2z1ywXGjAvJb72z1zwkOzm mail accepted for delivery)
             
    Demo that uses -jlogfile param with a pre-populated herre string
    .EXAMPLE
    PS> show-SerMtaLogFormattedOutput
    Demo that uses default clipboard source for input LogText
    .LINK
    https://github.com/tostka/verb-network
    #>
    # VALIDATORS: [ValidateNotNull()][ValidateNotNullOrEmpty()][ValidateLength(24,25)][ValidateLength(5)][ValidatePattern("some\sregex\sexpr")][ValidateSet("US","GB","AU")][ValidateScript({Test-Path $_ -PathType 'Container'})][ValidateScript({Test-Path $_})][ValidateRange(21,65)]#positiveInt:[ValidateRange(0,[int]::MaxValue)]#negativeInt:[ValidateRange([int]::MinValue,0)][ValidateCount(1,3)]
    ## [OutputType('bool')] # optional specified output type
    [CmdletBinding()]
    ###[Alias('Alias','Alias2')]
    PARAM(
        [Parameter(HelpMessage="The raw Filter Log output text report")]
            #[ValidateNotNullOrEmpty()]
            #[Alias('ALIAS1', 'ALIAS2')]
            [string[]]$LogText
            #,
        <#[Parameter(HelpMessage="Array containing OnPrem Master Server nbname,serverIP (used to resolve hosts)")]
            #[ValidateNotNullOrEmpty()]
            #[Alias('ALIAS1', 'ALIAS2')]
            [string[]]$masterserver = $tormeta.seropmaster,
        [Parameter(HelpMessage="Array containing OnPrem Agent Server nbname,serverIP (used to resolve hosts)")]
            #[ValidateNotNullOrEmpty()]
            #[Alias('ALIAS1', 'ALIAS2')]
            [string[]]$agentserver = $tormeta.seropagent    
        #>
    ) ;
    TRY{
        IF(-NOT $logtext){
            $bRet=Read-Host "COPY THE RAW FILTER LOG VIEWER OUTPUT TO CLIPBOARD!(press any key to continue)"  ;        
            $sermta = (Microsoft.PowerShell.Management\get-clipboard -raw -ea STOP ) ; 
        } else {
            $sermta = $logtext ; 
        } ; ;         
        #$sermta = (Microsoft.PowerShell.Management\get-clipboard -raw -ea STOP ) -replace [Environment]::NewLine," " -replace "(\[)","`r`n[" -split "`r?`n" ;
        #$sermta = $sermta  -replace ([Environment]::NewLine),"" -replace "(\d{4}-\d{2}-\w{5}:\d{2}:\d{2}\.\d{6}-\d{2}:\d{2})",'|$1' -replace "\|","`r`n").Split([Environment]::NewLine) |  ?{$_} ;
        $sermta = $sermta -replace ([Environment]::NewLine),"" ; 
        $sermta = $sermta -replace "(\d{4}-\d{2}-\w{5}:\d{2}:\d{2}\.\d{6}-\d{2}:\d{2})",'|$1'  ; 
        $sermta = $sermta -replace "\|","`r`n" ; 
        $sermta = $sermta.Split([Environment]::NewLine) |  ?{$_} ;
        $smsg = $null ;
        $sermta | %{ $smsg += "`n`n" ; $smsg+= ($_ -replace ",","`r`n")} ;
        $smsg | write-output ;
        $smsg | Microsoft.PowerShell.Management\set-clipboard ;
        write-host "`n(report copied to clipboard)" ;
    } CATCH {$ErrTrapd=$Error[0] ;
       write-host -foregroundcolor gray "TargetCatch:} CATCH [$($ErrTrapd.Exception.GetType().FullName)] {"  ;
       $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;
       write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" ;
    } ;    
} ;  
#*------^ END Function show-SerMtaLogFormattedOutput ^------
