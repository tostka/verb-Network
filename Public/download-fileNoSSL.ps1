    #*------v Function download-fileNoSSL v------
    function download-fileNoSSLNoSSL {
    <#
    .SYNOPSIS
    download-fileNoSSLNoSSL.ps1 - simple download client - overridding the SSL trust requirement to get the file (insecure, for testing)
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2020-04-17
    FileName    : download-fileNoSSL.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell,Internet,Download,File
    REVISIONS
    * 11:31 AM 4/17/2020 added CBH
    * 3:04 PM 8/13/2014
    .DESCRIPTION
    download-fileNoSSL.ps1 - simple download client - overridding the SSL trust requirement to get the file (insecure, for testing)
    .PARAMETER  url
    Url to be downloaded
    .PARAMETER  DestinationName
    Full path to destiontion file for download
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output
    .EXAMPLE
    $url = "http://www.cs.wisc.edu/~ballard/bofh/excuses" ; 
    $DestinationName = "c:\temp\temp.html" ; 
    download-file $url $DestinationName
    .LINK
    http://blogs.technet.com/b/bshukla/archive/2010/04/12/ignoring-ssl-trust-in-powershell-system-net-webclient.aspx
    #>
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } ;
        $client = new-object system.net.WebClient ;
        if ($DestinationName) {
            $client.DownloadString($url) | out-file -FilePath $local;
        }
        else {
            # stream to console
            $client.DownloadString($url) ;
        } # if-block end
        # not sure if toggle back is necesesary, but try it
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $false } ;
    } #*------^ END Function download-fileNoSSL ^------
