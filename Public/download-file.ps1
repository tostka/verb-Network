    #*------v Function download-file v------
    function download-file {
    <#
    .SYNOPSIS
    download-file.ps1 - simple download client
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2020-04-17
    FileName    : download-file.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell,Internet,Download,File
    REVISIONS
    11:31 AM 4/17/2020 added CBH
    .DESCRIPTION
    download-file.ps1 - simple download client
    .PARAMETER  url
    Url to be downloaded
    .PARAMETER  DestinationName
    Full path to destiontion file for download
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output
    .EXAMPLE
    download-file -url https://xxx -destinationname c:\pathto\file.ext
    .LINK
    #>
        [CmdletBinding()]
        PARAM ([string]$url, [string]$DestinationName)
        $rgxURLParse = "^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?" ;
        if ($url -match $rgxURLParse) {
            $host = $matches[4] ;
            if (test-connection -ComputerName $host -count 1) {
                $client = new-object system.net.WebClient
                $client.Headers.Add("user-agent", "PowerShell")
                $client.downloadfile($url, $DestinationName)
            }
            else {
                throw "unable to Ping $()" ;
            } ;
        }
        else {
            throw "Unparsable url, to fqdn:$($url)" ;
        } ;
    } ; #*------^ END Function download-file ^------
