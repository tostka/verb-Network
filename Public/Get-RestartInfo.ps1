# Get-RestartInfo

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
} #end of Function