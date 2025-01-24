#*------v Function Test-Port v------
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
        ; removed aliases 's' & 'p' (they're already usable as abbrev $server & $port, no other conflicting params )
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
    [alias("test-portTDO")]
    PARAM(
        [parameter(Position=0,Mandatory=$true)]
            [alias('ComputerName','TargetName')]
            [string]$Server,
        [parameter(Position=1,Mandatory=$true)]
            [alias('TcpPort')]
            [ValidatePattern("^(6553[0-5]|655[0-2]\d|65[0-4]\d\d|6[0-4]\d{3}|[1-5]\d{4}|[1-9]\d{0,3}|0)$")]
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
            $Socket.Close()
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
} ;
#*------^ END Function Test-Port ^------
