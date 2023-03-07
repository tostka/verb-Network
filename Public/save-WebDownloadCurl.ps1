#*------v Function save-WebDownloadCurl v------
function save-WebDownloadCurl {
    <#
    .SYNOPSIS
    save-WebDownloadCurl.ps1 - simple download wrapper around curl cmdline util
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2020-04-17
    FileName    : save-WebDownloadCurl.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell,Internet,Download,File
    REVISIONS
    *12:18 PM 3/7/2023 fixed underlying splatting break (had been trying to build [str] cmdline -> use array so-called spatting (not really a splatted hashtable); 
    added strong typing/cast to [uri], as pre-validation; ren download-filecurl -> save-WebDownloadCurl (aliased orig) ;
    ren $url->$uri, aliased url; ren'd DestinationName -> DestinationFile (aliased orig);
    11:31 AM 4/17/2020 added CBH
    .DESCRIPTION
    save-WebDownloadCurl.ps1 - simple download client, wraps cmdline curl executable (supports *nix as well).
    .PARAMETER uri
        Uri to be downloaded[-Uri https://community.chocolatey.org/api/v2/package/chocolatey]
        .PARAMETER DestinationFile
        Full path to destination file for download[-DestinationFile 'c:\path-to\']
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output
    .EXAMPLE
    save-WebDownloadCurl -uri https://xxx -DestinationFile c:\pathto\file.ext
    .LINK
    #>
    PARAM (
        [Parameter(Mandatory=$true,Position=0,
                HelpMessage="Uri to be downloaded[-Uri https://community.chocolatey.org/api/v2/package/chocolatey]")] 
            [Alias('url')]
            #[string]
            [uri]$uri, 
        [Parameter(Position=1,
                HelpMessage="Full path to destination file for download[-DestinationFile 'c:\path-to\']")] 
            [Alias('DestinationName')]
            [string]$DestinationFile
    )
    #$CurlArgument = "-o '$($DestinationFile)', --url '$($uri)'" ; 
    #$CurlArgument = '"$($uri)" -o "$($destinationfile)"' ; 

    #[string]$CurlArgument = "'$($uri.OriginalString)'" ; 
    #$CurlArgument += " -o '$($destinationfile)'" ; 
    # use splatting:
    <#$CurlArgument = '-u', 'xxx@gmail.com:yyyy',
                '-X', 'POST',
                'https://xxx.bitbucket.org/1.0/repositories/abcd/efg/pull-requests/2229/comments',
                '--data', 'content=success'
    #>
    $CurlArgument = '-s', '-L', '-o', "$($destinationfile)", "$($uri.OriginalString)"
    if (($PSVersionTable.PSEdition -eq 'Desktop') -OR ($IsCoreCLR -AND $IsWindows) -OR !$PSVersionTable.PSEdition) {$CURLEXE = "$env:windir\System32\curl.exe" } 
    elseif ($IsCoreCLR -AND $IsLinux) {$CURLEXE = 'curl'} ;
    & $CURLEXE @CurlArgument ;
} ; 
#*------^ END Function save-WebDownloadCurl ^------
