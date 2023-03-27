#*------v Function test-Connection-T v------
function test-Connection-T {
    <#
    .SYNOPSIS
    test-Connection-T - Endless test-Connection pings (simple equiv to ping -t)
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2020-04-17
    FileName    : test-Connection-T.ps1
    License     : MIT License
    Copyright   : (c) 2023 Todd Kadrie
    Github      : https://github.com/verb-Network
    Tags        : Powershell,Internet,Download,File
    AddedCredit : poshftw
    AddedWebsite: https://old.reddit.com/r/PowerShell/comments/moxy5v/downloading_a_file_with_powershell_without/
    AddedTwitter: URL
    AddedCredit : Patrick Gruenauer
    AddedWebsite: https://sid-500.com/2019/10/22/powershell-endless-ping-with-test-connection/
    AddedTwitter: @jmcnatt / https://twitter.com/jmcnatt
    REVISIONS
    * 1:07 PM 3/27/2023 built, added to verb-Network
    .DESCRIPTION
    test-Connection-T - Endless test-Connection pings (simple equiv to ping -t)
    Uses the [int32]::MaxValue to push the -count so high it's just about endless, as a single command, without a DoLoop
    From a simple -count param tweak recommended by Patrick Gruenauer, wrapped with a function
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output
    .EXAMPLE
    test-Connection-T someserver
    Demo endless 1/second ping. 
    .EXAMPLE
    test-Connection-T 1.1.1.1 -Delay 5;
    Demo endless ping, every 5secs
    .LINK
    https://github.com/verb-Network
    #>
    ## [OutputType('bool')] # optional specified output type
    [CmdletBinding()]
    ###[Alias('Alias','Alias2')]
    PARAM (
        [Parameter(Mandatory=$true,Position=0,HelpMessage = "Specifies the computers to ping. Type the computer names or type IP addresses in IPv4 or IPv6 format. Wildcard characters are not permitted. This parameter is required.")]
        [System.String[]]$ComputerName,
        [Parameter(HelpMessage = "Specifies the interval between pings, in seconds (max 60).")]
        [System.Int32]$Delay
    ) ; 
    PROCESS {
        $Error.Clear() ; 
        foreach($item in $Computername){
            Test-Connection $item -Count ([int32]::MaxValue) -Delay:$($Delay) ; 
        } ;   # loop-E
    } ;  # if-PROC
} ; 
#*------^ END Function test-Connection-T ^------
