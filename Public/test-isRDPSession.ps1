#*------v Function test-isRDPSession v------
function test-isRDPSession {
    <#
    .SYNOPSIS
    test-isRDPSession() - determine if powershell is running within an RDP session
    .NOTES
    Author: Todd Kadrie
    Website:	http://toddomation.com
    Twitter:	http://twitter.com/tostka
    CreatedDate : 2025-01-24
    FileName    : test-isRDPSession.ps1
    License     : MIT License
    Copyright   : (c) 2024 Todd Kadrie
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,RDP,TsClient
    REVISIONS   :
    # 9:49 AM 1/24/2025 rename test-Rdp -> test-isRDPSession, and alias the original name (orig name could be confused for testing is rdp server accessible); added min reqs for advfunc
    # 9:48 AM 9/25/2020 fixed to explicitly check for an RDP & clientname evari: wasn't properly firing on work box, $env:sessionname is blank, not 'Console' 
    # 3:45 PM 4/17/2020 added cbh
    # 10:45 AM 7/23/2014
    .DESCRIPTION
    test-isRDPSession() - determine if powershell is running within an RDP session
    
    RDP sets 2 environment variables on remote connect:
    $env:sessionname: RDP-Tcp#[session#]
    $env:clientname: [connecting client computername]
    
    If both are set, you're in an RDP 
    
    Proviso: unless Explorer Folder Option "Launch folder windows in a separate process" is enabled, 
    applications launched from an additional Explorer window do not have these e-varis.

    Old approach:
    if ($env:SESSIONNAME -ne 'Console') { return $True; }; 
    -> win10 on my workbox doesn't have $env:SESSIONNAME -eq 'Console', evals false positive
    
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    System.Boolean
    .EXAMPLE
    PS> if(test-isRDPSession){write-host "Running in RDP"} ; 
    Simple test for execution within an RDP seession.
    .LINK
    https://github.com/tostka/verb-network
    #>
    
    # better test is test match rgx on RDP-Tcp# string & $env:clientname populated 
    [CmdletBinding()]
    [alias("Test-RDP")]
    PARAM()
    if(($env:sessionname -match 'RDP-Tcp#\d*') -AND ($env:clientname)){ return $True} ;
};
#*------^ END Function test-isRDPSession ^------
