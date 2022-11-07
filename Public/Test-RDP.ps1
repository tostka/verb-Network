#*------v Function Test-RDP v------
function Test-RDP {
    <#
    .SYNOPSIS
    Test-RDP() - determine if powershell is running within an RDP session
    .NOTES
    Author: Todd Kadrie
    Website:	http://toddomation.com
    Twitter:	http://twitter.com/tostka
    REVISIONS   :
    # 9:48 AM 9/25/2020 fixed to explicitly check for an RDP & clientname evari: wasn't properly firing on work box, $env:sessionname is blank, not 'Console' 
    # 3:45 PM 4/17/2020 added cbh
    # 10:45 AM 7/23/2014
    .DESCRIPTION
    Test-RDP() - determine if powershell is running within an RDP session
    RDP sets 2 environment variables on remote connect:
    $env:sessionname: RDP-Tcp#[session#]
    $env:clientname: [connecting client computername]
    If both are set, you're in an RDP 
    Proviso: unless Explorer Folder Option "Launch folder windows in a separate process" is enabled, 
    applications launched from an additional Explorer window do not have these e-varis.
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    System.Boolean
    .EXAMPLE
    if(Test-RDP){write-host "Running in RDP"} ; 
    .LINK
    #>
    # win10 on workbox doesn't have $env:SESSIONNAME -eq 'Console', below is false positive
    #if ($env:SESSIONNAME -ne 'Console') { return $True; }; 
    # better test is test match rgx on RDP-Tcp# string & $env:clientname populated 
    if(($env:sessionname -match 'RDP-Tcp#\d*') -AND ($env:clientname)){ return $True} ;
};
#*------^ END Function  ^------
