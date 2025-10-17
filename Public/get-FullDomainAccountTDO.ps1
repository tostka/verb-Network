# get-FullDomainAccountTDO.ps1


#region GET_FULLDOMAINACCOUNTTDO ; #*------v get-FullDomainAccountTDO v------
Function get-FullDomainAccountTDO {
    <#
    .SYNOPSIS
    get-FullDomainAccountTDO - Validates an account logon specification string is either a UserPrincipalName (acct@DOMAIN.TLD) or legacy format (DOMAIN\Account) specification. If no domain is specified (just an accountname), it substitutes the local UserDomain environment variable as the Domain specification. The resolved UPN or Legacy spec is passed through (UPN -> UPN; legacy -> legacy)
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 20250711-0423PM
    FileName    : get-FullDomainAccountTDO.ps1
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/verb-ex2010
    Tags        : Powershell,Exchange,ExchangeServer,Install,Patch,Maintenance
    AddedCredit : Michel de Rooij / michel@eightwone.com
    AddedWebsite: http://eightwone.com
    AddedTwitter: URL
    REVISIONS
    * 4:33 PM 10/16/2025 reworked logic to make self-contained, no-dep, updated cbh demo; replaced all of MdR's original logic
    * 1:14 PM 9/17/2025 port to vnet from xopBuildLibrary; add CBH, and Adv Function specs
    * 1:58 PM 8/8/2025 added CBH; init; renamed AdminAccount -> Account, aliased  orig param and logon variant. ren: get-FullDomainAccountTDO -> get-FullDomainAccountTDO, aliased orig name
    .DESCRIPTION
    get-FullDomainAccountTDO - Validates an account logon specification string is either a UserPrincipalName (acct@DOMAIN.TLD) or legacy format (DOMAIN\Account) specification. If no domain is specified (just an accountname), it substitutes the local UserDomain environment variable as the Domain specification. The resolved UPN or Legacy spec is passed through (UPN -> UPN; legacy -> legacy)
        
    .INPUTS
    None, no piped input.
    .OUTPUTS
    System.Object summary of Exchange server descriptors, and service statuses.
    .EXAMPLE
    PS> $tcred = get-credential ; 
    PS> $rvLogon = get-FullDomainAccountTDO -Account $tcred.username
    .LINK
    https://github.org/tostka/verb-io/
    #>
    [CmdletBinding()]
    [alias('get-FullDomainAccount')]
    PARAM(
        [Parameter(Mandatory=$true,HelpMessage = "Account specification")]
            [Alias('AdminAccount','logon','credential')]
            [string]$Account
    ) ;
        $PlainTextAccount= $Account;        
    switch -regex ($PlainTextAccount){
        '(.*)\\(.*)' {
            $Parts = $PlainTextAccount.split('\') ; 
            $FullPlainTextAccount = "$($Parts[0].ToUpper())\$($Parts[1])" ; write-host  "Account is in Legacy format" ; 
            return $FullPlainTextAccount ;
            break ; 
        } ; 
        '(.*)@(.*)' {
            write-host  "Account is in UPN format"  ; 
            $FullPlainTextAccount = $PlainTextAccount ;              
            return $FullPlainTextAccount ;
            #break ;
        }
        default{
            if($env:USERDOMAIN){
                $FullPlainTextAccount = "$($env:USERDOMAIN)\$($PlainTextAccount)" ; 
                write-host  "simple string: Assuming Logon, asserting `$env:USERDOMAIN for domain in legacy format" ; 
                return $FullPlainTextAccount ; 
                break ;
            } else{
                throw "Unrecognized -Account format:$($PlainTextAccount)" ; 
            };
            break ;  
        } ; 
    } ; 
}
#endregion GET_FULLDOMAINACCOUNTTDO ; #*------^ END get-FullDomainAccountTDO ^------

