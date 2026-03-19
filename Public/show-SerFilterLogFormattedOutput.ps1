# show-SerFilterLogFormattedOutput.ps1

#*----------v Function show-SerFilterLogFormattedOutput() v----------
function show-SerFilterLogFormattedOutput {
    <#
    .SYNOPSIS
    show-SerFilterLogFormattedOutput.ps1 - Takes Proofpoint SER Logs (from clipboard) and Reports > Log Viewer  'Filter' Log File Type output, and parses it for the focused cmd=send lines, and lip= lines, to assemble a targeted set of QID-specific search steps for the MTA log (the next step in a trace)
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2026-03-19
    FileName    : show-SerFilterLogFormattedOutput.ps1
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
    show-SerFilterLogFormattedOutput.ps1 - Takes Proofpoint SER Logs (from clipboard) and Reports > Log Viewer  'Filter' Log File Type output, and parses it for the focused cmd=send lines, and lip= lines, to assemble a targeted set of QID-specific search steps for the MTA log (the next step in a trace)
    
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
	[2026-03-18 07:52:30.007522 -0500] rprt s=4cwtbdrj71 mod=session cmd=disconnect module= rule= action= helo=SERVER.DOMAIN
.com msgs=1 rcpts=1 routes=allow_relay duration=0.096 elapsed=0.524
...[TRIMMED]...
[2026-03-18 07:52:29.487175 -0500] rprt s=4cwtbdrj71 mod=session cmd=connect ip=123.456.789.012 country=us lip=123.456.789.013 prot
=smtp:smtp hops_active=f routes= notroutes=default_inbound,firewallsafe,internalnet,outbound,pp_spoofsafe,spfsafe,tls,xclient
_trusted perlwait=0.003    
"@ ; 
    PS> show-SerFilterLogFormattedOutput -LogText $hsLogOutput
    Demo that uses -jlogfile param with a pre-populated herre string
    .EXAMPLE
    PS> show-SerFilterLogFormattedOutput
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
            [string[]]$LogText,
        [Parameter(HelpMessage="Array containing OnPrem Master Server nbname,serverIP (used to resolve hosts)")]
            #[ValidateNotNullOrEmpty()]
            #[Alias('ALIAS1', 'ALIAS2')]
            [string[]]$masterserver = $tormeta.seropmaster,
        [Parameter(HelpMessage="Array containing OnPrem Agent Server nbname,serverIP (used to resolve hosts)")]
            #[ValidateNotNullOrEmpty()]
            #[Alias('ALIAS1', 'ALIAS2')]
            [string[]]$agentserver = $tormeta.seropagent    
    ) ;
    TRY{
        IF(-NOT $logtext){
            $bRet=Read-Host "COPY THE RAW FILTER LOG VIEWER OUTPUT TO CLIPBOARD!(press any key to continue)"  ;        
            $serlines = (Microsoft.PowerShell.Management\get-clipboard -raw -ea STOP ) ; 
        } else {
            $serlines = $logtext ; 
        } ; ;         
        #$serlines = (Microsoft.PowerShell.Management\get-clipboard -raw -ea STOP ) -replace [Environment]::NewLine," " -replace "(\[)","`r`n[" -split "`r?`n" ;
        $serlines = $serlines -replace [Environment]::NewLine," " -replace "(\[)","`r`n[" -split "`r?`n" ;
        $serverIP = [regex]::match(($serlines |?{$_ -match 'lip='}).split(' '),'lip=(\d+\.\d+\.\d+\.\d+)').groups[1].value ; 
        switch($serverIP){            
            $masterServer[1]  {$server = $masterServer[0]}
            $agentserver[1] {$server = $agentserver[0]}
            default{
                throw "Unrecogized, or unconfigured Server IP Address!" ; 
            } ; 
        } ; 
        $sendline = $serlines |?{$_ -match 'cmd=send'} ;
        if($sendQID = [regex]::match(($serlines |?{$_ -match 'cmd=send'}).split(' '),'qid=([\w]{14})').groups[1].value){
            $smsg = "cmd=send QID resolved: $($sendQID)" ;
            $smsg += "`nRun MTA Search:`nLogs & reports > Log Viewer`nServer:$($server)`nLog Type Filter: MTA`nFind: $($sendQID)`n, click SEARCH" ;
            write-host -foregroundcolor yellow $smsg ;
            $smsg | Microsoft.PowerShell.Management\set-clipboard ;
            write-host "(report copied to clipboard)" ; 
        } else {write-warning "No line with both 'cmd=send' & 'qid=([\w]{14})' found: Unable to resolve QID for MTA search" } ; 
    } CATCH {$ErrTrapd=$Error[0] ;
       write-host -foregroundcolor gray "TargetCatch:} CATCH [$($ErrTrapd.Exception.GetType().FullName)] {"  ;
       $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;
       write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" ;
    } ;    
} ;  
#*------^ END Function show-SerFilterLogFormattedOutput ^------
