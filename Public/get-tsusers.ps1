#*------v Function get-tsUsers v------
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
} ; 
#*------^ END Function get-tsUsers ^------