#*------v Function download-filecurl v------
function download-filecurl {
    <#
    .SYNOPSIS
    download-filecurl.ps1 - simple download wrapper around curl cmdline util
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2020-04-17
    FileName    : download-filecurl.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell,Internet,Download,File
    REVISIONS
    11:31 AM 4/17/2020 added CBH
    .DESCRIPTION
    download-filecurl.ps1 - simple download client
    .PARAMETER  url
    Url to be downloaded
    .PARAMETER  DestinationName
    Full path to destiontion file for download
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output
    .EXAMPLE
    download-filecurl -url https://xxx -destinationname c:\pathto\file.ext
    .LINK
    #>
    PARAM ([string]$url, [string]$DestinationName)
    $CurlArgument = '-o $($DestinationName)', '$($url)' ;
    if (($PSVersionTable.PSEdition -eq 'Desktop') -OR ($IsCoreCLR -AND $IsWindows) -OR !$PSVersionTable.PSEdition) {$CURLEXE = "$env:windir\System32\curl.exe" } ; 
    elseif ($IsCoreCLR -AND $IsLinux) {$CURLEXE = 'curl'} ;
    & $CURLEXE @CurlArgument ;
} ; 
#*------^ END Function download-filecurl ^------