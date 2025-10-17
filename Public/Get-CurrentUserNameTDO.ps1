# Get-CurrentUserNameTDO.ps1


#region GET_CURRENTUSERNAMETDO ; #*------v Get-CurrentUserNameTDO v------
function Get-CurrentUserNameTDO{
    <#
        .SYNOPSIS
        Get-CurrentUserNameTDO - Returns local machine's windows security principal 'DOMAIN\logon' string
        .NOTES
        Version     : 0.0.1
        Author      : Todd Kadrie
        Website     : http://www.toddomation.com
        Twitter     : @tostka / http://twitter.com/tostka
        CreatedDate : 20250917-0114PM
        FileName    : Get-CurrentUserNameTDO.ps1
        License     : (none asserted)
        Copyright   : (none asserted)
        Github      : https://github.com/tostka/verb-io
        Tags        : Powershell,ActiveDirectory,Account,Credential
        AddedCredit : Michel de Rooij / michel@eightwone.com
        AddedWebsite: http://eightwone.com
        AddedTwitter: URL        
        REVISIONS
        * 9:19 AM 10/17/2025 hadn't actually copied in the raw code, now fully populated, and covers fallback to env varis, and supports non-domain-connected boxese
        * 1:14 PM 9/17/2025 port to vnet from xopBuildLibrary; add CBH, and Adv Function specs
        .DESCRIPTION
        Get-CurrentUserNameTDO - Returns local machine's windows security principal 'DOMAIN\logon' string
                
        .INPUTS
        None, no piped input.
        .OUTPUTS
        System.String windows security principal in 'DOMAIN\logon' format
        .EXAMPLE ; 
        PS> if($Username = Get-CurrentUserNameTDO){
        PS>     write-host -foregroundcolor green "UserName:$($UserName)" ; 
        PS> } else {
        PS>     write-warning "Unable to get local windows security principal name" ; 
        PS> }; 
        .LINK
        https://github.org/tostka/verb-Network/
        #>
    [CmdletBinding()]
    [alias('Get-CurrentUserName')]
    PARAM(
        [Parameter(HelpMessage = "UserName (defaults to current desktop user)")]
            [Alias('AdminAccount','logon')]
            [string]$UserName,
        [Parameter(HelpMessage = "Account password (securestring)")]
            [Alias('AdminPassword')]
            [System.Security.SecureString]$Password
    ) ;
    if([System.Security.Principal.WindowsIdentity]::GetCurrent().Name){
        return [System.Security.Principal.WindowsIdentity]::GetCurrent().Name 
    }else{
        $smsg = "Unpopulated[System.Security.Principal.WindowsIdentity]:`nfallback to `$env:USERDOMAIN & USERNAME checks" ; 
        if($VerbosePreference -eq "Continue"){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
        else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
        if($env:USERDOMAIN -eq $env:COMPUTERNAME){
            if($env:USERNAME){
                $smsg = "Non-Domain-connected system, returning non-Domain local `$env:USERNAME string" ; 
                if($VerbosePreference -eq "Continue"){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                return $env:USERNAME ; 
            }else{
                $smsg = "Unpopulated `$env:USERNAME!" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                throw $smsg ; 
            } 
        }else{
            $smsg = "Returning ``$env:USERDOMAIN\$env:USERNAME string: $($env:USERDOMAIN)\$($env:USERNAME)" ; 
            if($VerbosePreference -eq "Continue"){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
            return "$($env:USERDOMAIN)\$($env:USERNAME)" ; 
        }

    } ; 
}
#endregion GET_CURRENTUSERNAMETDO ; #*------^ END Get-CurrentUserNameTDO ^------

