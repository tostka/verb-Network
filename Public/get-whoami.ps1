    #*------v Function get-whoami v------
    function get-whoami {
        <#
        .SYNOPSIS
        get-whoami.ps1 - assemble & return DOMAIN\LOGON string from local eVaris
        .NOTES
        Version     : 1.0.0
        Author      : Todd Kadrie
        Website     : http://www.toddomation.com
        Twitter     : @tostka / http://twitter.com/tostka
        CreatedDate : 2020-04-17
        FileName    : get-whoami.ps1
        License     : MIT License
        Copyright   : (c) 2020 Todd Kadrie
        Github      : https://github.com/tostka
        Tags        : Powershell,Internet,Download,File
        REVISIONS
        11:31 AM 4/17/2020 added CBH
        .DESCRIPTION
        get-whoami.ps1 - assemble & return DOMAIN\LOGON string from local eVaris
        .INPUTS
        None. Does not accepted piped input.
        .OUTPUTS
        System.String 
        .EXAMPLE
        $logon = get-whoami
        .LINK
        #>
        [CmdletBinding()]
        PARAM ()
        return (get-content env:\userdomain).ToLower() + "\" + (get-content env:\username).ToLower() ;
    } ; #*------^ END Function get-whoami ^------