# test-LocalDrivePathTDO.ps1

#region TEST_LOCALDRIVEPATHTDO ; #*------v test-LocalDrivePathTDO v------
function test-LocalDrivePathTDO{
    <#
    .SYNOPSIS
    test-LocalDrivePathTDO.ps1 - Evaluate specified path, to determine if it points to _locally stored_ content: That is, not a remote-network-mapped drive (e.g. passes, even if it's a UNC path, back to the local host)
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2025-
    FileName    : test-LocalDrivePathTDO.ps1
    License     : MIT License
    Copyright   : (c) 2025 Todd Kadrie
    Github      : https://github.com/tostka/verb-XXX
    Tags        : Powershell
    AddedCredit : REFERENCE
    AddedWebsite: URL
    AddedTwitter: URL
    REVISIONS
    * 1:37 PM 8/20/2025 added region tags; adding to xopBuildLibrary.ps1 as well
    3:44 PM 7/10/2025 made the rgx case-insensitive; fixed $filepath refs -> $item
    * 3:46 PM 7/9/2025 init
    .DESCRIPTION
    test-LocalDrivePathTDO.ps1 - Evaluate specified path, to determine if it points to _locally stored_ content: That is, not a remote-network-mapped drive (e.g. passes, even if it's a UNC path, back to the local host)

    Performs the following tests and comparisons: 

    - Collects all locally-mapped drives _without_ a network UNC path (which is stored in the associated DisplayRoot property).
        get-psdrive -PSProvider FileSystem | ?{-not $_.displayroot}
    - Builds a comparitive regex of the matching Root properties (which correspond to the 'C:\' drive letter & root directory string), then checks the specified -Path for a match to the collected known 'local' drive roots
    - uses the [uri] type on the path to check status of:
        IsUnc: indicates a UNC path, which *may* indicate remote-stored content
        IsAbsoluteUri: indicates a full, non-relative path specification (used to differentiate relative path from full paths).
    - where an isUNC:$true is found, it then checks the [uri].host value against the $env:COMPUTERNAME environment variable for the local host, and also checks it against the Resolved DNS A Record for the host (if a DNS A is configured for the host): 
        If either matches, the path is classified as 'local' content.

    .PARAMETER  Path
    Path [-path c:\path-to\file.ext]
    .INPUTS
    System.String path. Accepts piped input.
    .OUTPUTS
    System.Boolean
    .EXAMPLE    
    PS> test-LocalDrivePathTDO.ps1 -path 'D:\cab\FILE.pfx' ; 
    Demo testing a full absolute local path1 
    .EXAMPLE
    PS> test-LocalDrivePathTDO.ps1 -path .\FILE.pfx 
    Demo testing a relative path    
    .EXAMPLE
    PS> test-LocalDrivePathTDO -path '\\SERVER.SUB.DOM.DOMAIN.COM\D$\cab\FILE.pfx' -verbose     
    Demo of testing a UNC path, that resolves back to the local host resolved DNS A fqdn 
    .EXAMPLE
    PS> test-LocalDrivePathTDO -path '\\SERVER\D$\cab\FILE.pfx' -verbose     
    Demo of testing a UNC path, that resolves back to the local host nbname
    .LINK
    https://github.com/tostka/verb-IO
    .LINK
    #>
    [CmdletBinding()]
    PARAM(
        [Parameter(Mandatory = $False,Position = 0,ValueFromPipeline = $True, HelpMessage = 'Path to be tested[-path c:\pathto\file.ext]')]
            [string[]]$path
    ) ;
    BEGIN{
        # Filesystem psdrives with DisplayRoot: Gets or sets the UNC path of the drive. This property would be populated only if the created PSDrive is targeting a network drive or else this property would be null.
        #[regex]$rgxlocDriveRoots = ('^(?i:' + ((get-psdrive -PSProvider FileSystem | ?{-not $_.displayroot} | select -expand root |%{[regex]::escape($_)}) -join '|') + ')') ;
        [regex]$rgxlocDriveRoots = ('^(?i:(' + ((get-psdrive -PSProvider FileSystem | ?{-not $_.displayroot} | select -expand root |%{[regex]::escape($_)}) -join '|') + '))') ;
    }
    PROCESS{
        foreach($item in $Path){
            if(test-path $item -PathType leaf){
                [system.io.fileinfo[]]$item = $item ; 
            } elseif(test-path $item -PathType Container){
                [System.IO.DirectoryInfo[]]$item = $item ; 
            } ; 
            $nonNetwork = $false ;         
            $uriPath = [uri]$item.fullname ; 
            if($item.fullname -match $rgxlocDriveRoots){
                write-verbose "matches local Drive Roots" ; 
                $nonNetwork = $true ; 
            } elseif($uriPath.IsUnc) {
                if (($uriPath.host -eq $env:computername) -OR ($uriPath.host -eq (resolve-dnsname -name $uriPath.host -type A -ErrorAction 0| select -unique Name | select -expand name)) ) {
                    write-verbose "isUnc: with computername or FQDN as host" ; 
                    $nonNetwork = $true ;
                } else { 
                    $nonNetwork = $false ; 
                } ; 
            } elseif($uriPath.IsAbsoluteUri -eq $false){
                write-verbose "IsAbsoluteUri:false: relative path" ; 
                $nonNetwork = $true ; 
            } 
            #write-host "`$nonNetwork:$($nonNetwork)" ; 
            $nonNetwork | write-output  ; 
        } ; 
    } ; 
} ; 
#endregion TEST_LOCALDRIVEPATHTDO ; #*------^ END test-LocalDrivePathTDO ^------