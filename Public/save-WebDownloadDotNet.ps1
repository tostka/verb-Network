    #*------v Function save-WebDownloadDotNet v------
    function save-WebDownloadDotNet {
        <#
        .SYNOPSIS
        save-WebDownloadDotNet.ps1 - simple download client
        .NOTES
        Version     : 1.0.0
        Author      : Todd Kadrie
        Website     : http://www.toddomation.com
        Twitter     : @tostka / http://twitter.com/tostka
        CreatedDate : 2020-04-17
        FileName    : save-WebDownloadDotNet.ps1
        License     : MIT License
        Copyright   : (c) 2020 Todd Kadrie
        Github      : https://github.com/verb-network
        Tags        : Powershell,Internet,Download,File
        REVISIONS
        * 11:36 AM 3/7/2023 validated; ren download-file -> save-WebDownloadDotNet (aliased orig) ; spliced over NoSSL support from download-fileNoSSL.ps1(retiring that func in favor of this) ;  add param specs, ren $url->$uri, aliased url; ren'd DestinationName -> DestinationFile (aliased orig); add position to params
        11:31 AM 4/17/2020 added CBH
        .DESCRIPTION
        save-WebDownloadDotNet.ps1 - simple .Net-based download client
        If no -DestinationFile specified, the content is returned to pipeline.
        .PARAMETER uri
        Uri to be downloaded[-Uri https://community.chocolatey.org/api/v2/package/chocolatey]
        .PARAMETER DestinationFile
        Full path to destination file for download[-DestinationFile 'c:\path-to\']
        .PARAMETER NoPing
        Switch to suppress Ping/Test-Connection pretest[-NoPing]
        .PARAMETER NoSSL
        Switch to suppress SSL requirement (for sites with failing certs)[-NoSSL]
        .INPUTS
        None. Does not accepted piped input.
        .OUTPUTS
        None. Returns no objects or output
        .EXAMPLE
        save-WebDownloadDotNet -url https://xxx -DestinationFile c:\pathto\file.ext
        .LINK
        http://blogs.technet.com/b/bshukla/archive/2010/04/12/ignoring-ssl-trust-in-powershell-system-net-webclient.aspx
        #>
        [CmdletBinding()]
        [Alias('download-file')]
        PARAM (
            [Parameter(Mandatory=$true,Position=0,
                HelpMessage="Uri to be downloaded[-Uri https://community.chocolatey.org/api/v2/package/chocolatey]")] 
            [Alias('url')]
            [string]$uri, 
            [Parameter(Position=1,
                HelpMessage="Full path to destination file for download[-DestinationFile 'c:\path-to\']")] 
            [Alias('DestinationName')]
            [string]$DestinationFile,
            [Parameter(
                HelpMessage="Switch to suppress Ping/Test-Connection pretest[-NoPing]")] 
            [switch]$NoPing,
            [Parameter(
                HelpMessage="Switch to suppress SSL requirement (for sites with failing certs)[-NoSSL]")] 
            [switch]$NoSSL
        )
        $rgxURLParse = "^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?" ;
        if ($uri -match $rgxURLParse) {
            if($NoSSL){
                write-warning "-NoSSL specified: disabling system.net.WebClient Certificate Validation!" ; 
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } ;
            } ; 
            $server = $matches[4] ;
            [boolean]$bPing = $false ; 
            if (-not $NoPing -AND (test-connection -ComputerName $server -count 1)) {
                $bPing = $true ;
            }elseif ($NoPing) {
                $bPing = $true ;
            } else {
                throw "unable to Ping $()" ;
            } ;
            if($bPing){
                $client = new-object system.net.WebClient
                $client.Headers.Add("user-agent", "PowerShell")
                if($DestinationFile){
                    write-host "-DestinationFile: Saving download to:`n$($DestinationFile)..." ; 
                    $client.downloadfile($uri, $DestinationFile)
                } else { 
                    write-verbose "streaming URI to pipeline..." ; 
                    $client.DownloadString($uri) | write-output ; 
                } ; 
            } ; 
            # not sure if toggle back is necesesary, but try it
            if($NoSSL){
                write-verbose "-NoSSL specified, re-enabling system.net.WebClient Certificate Validation" ; 
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $false } ;
            } ; 
        } else {
            throw "Unparsable url, to fqdn:$($uri)" ;
        } ;
    } ; #*------^ END Function save-WebDownloadDotNet ^------
