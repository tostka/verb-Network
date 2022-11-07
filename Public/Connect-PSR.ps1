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
