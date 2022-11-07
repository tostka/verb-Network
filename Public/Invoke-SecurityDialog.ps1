#*------v Function Invoke-SecurityDialog v------
function Invoke-SecurityDialog {
    <#
    .SYNOPSIS
    Invoke-SecurityDialog.ps1 - Open Windows System Security dialog via powershell (for Password changes etc) - handy for nested RDP/TermServ sessions where normal Ctrl+Alt+Del/Ctrl+Alt+End(remote) triggers don't work (hotkey, remote triggers only outtermost RDP sec dlg). 
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2021-11-23
    FileName    : 
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell
    AddedCredit : 
    AddedWebsite: 
    AddedTwitter: 
    REVISIONS
    * 9:16 AM 11/23/2021 init
    .DESCRIPTION
    Invoke-SecurityDialog.ps1 - Open system Security dialog via powershell - handy for nested RDP/TermServ sessions where normal Ctrl+Alt+Del/Ctrl+Alt+End (remote) triggers don't work. 
    .INPUTS
    Accepts piped input
    .OUTPUTS
    None. Returns no objects or output (.NET types)
    .EXAMPLE
    PS> Invoke-SecurityDialog
    For the query of the corresponding TXT records in the DNS only the paramater name is needed
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://cloudbrothers.info/en/powershell-tip-resolve-spf/
    #>
    #Requires -Modules DnsClient
    [CmdletBinding()]
    PARAM () ; 
    write-host "Triggering local Windows Security Dialog (requires RAA)...`n(cmd.exe RAA, alt:`nexplorer.exe shell:::{2559a1f2-21d7-11d4-bdaf-00c04f60b9f0}`n)" ; 
    (New-Object -COM Shell.Application).WindowsSecurity() ;
} ; 
#*------^ END Function Invoke-SecurityDialog ^------
