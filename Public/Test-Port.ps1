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
