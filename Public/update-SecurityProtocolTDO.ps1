# update-SecurityProtocolTDO

#*------v Function update-SecurityProtocolTDO v------
function update-SecurityProtocolTDO {
    <#
    .SYNOPSIS
    update-SecurityProtocolTDO -  Polls available 'Net.SecurityProtocolType' TLS revisions, above the current Max TLS type, and updates the Net.ServicePointManager.SecurityProtocol to include those revised types
    .NOTES
    Version     : 0.63
    Author      : rmbolger
    Website     : https://www.reddit.com/r/PowerShell/comments/ozr6ye/psa_enabling_tls12_and_you/
    Twitter     : 
    CreatedDate : 2024-09-04
    FileName    : update-SecurityProtocolTDO.ps1
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,Network,Security,TLS
    AddedCredit : Todd Kadrie
    AddedWebsite: http://www.toddomation.com
    AddedTwitter: @tostka / http://twitter.com/tostka
    REVISIONS
    * 12:03 PM 9/4/2024 init expanded the sample SB into a function, added to verb-Network
    * 2021 - rmbolger's reddit r/Powershell scriptblock demo that appends latest TLS revs to the current list 
    .DESCRIPTION
    update-SecurityProtocolTDO -  Polls available 'Net.SecurityProtocolType' TLS revisions, above the current Max TLS type, and updates the Net.ServicePointManager.SecurityProtocol to include those revised types

    Works around random authentication errors from MS o365 etc, due to windows Powershell (5.x)'s default use of TLS1.0, even when higher revs are mounted in the OS
    
    Sample error (from Exchange Online): 
    "The specified value is not valid in the 'SslProtocolType' enumeration."

    Basic usage is to run update-SecurityProtocolTDO(), to ensure the Powershell (winPS5.5) TLS ciphers are fully up to date in use, *before* opening connections to MS services (EXO, https, smtp etc - anything that uses TLS for connectivity, could fail with 
    Discussion on r/Powershell:

        [Ecrofirt](https://www.reddit.com/user/Ecrofirt/)

        • [3y ago](https://www.reddit.com/r/PowerShell/comments/ozr6ye/comment/h81pslu/) • Edited 3y ago
 
        I have found it easier to follow Microsoft's guide to enabling TLS 1.2 in .NET. 
        that change is system-wide, which has meant I haven't needed to put this line 
        in every script using HTTPS

 
        [https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/security/enable-tls-1-2-client#bkmk\_net](https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/security/enable-tls-1-2-client#bkmk_net)
        ```
        \[HKEY\_LOCAL\_MACHINE\\SOFTWARE\\Microsoft\\.NETFramework\\v2.0.50727\]
                "SystemDefaultTlsVersions" = dword:00000001
                "SchUseStrongCrypto" = dword:00000001

        \[HKEY\_LOCAL\_MACHINE\\SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319\]
            "SystemDefaultTlsVersions" = dword:00000001
            "SchUseStrongCrypto" = dword:00000001        
            ```

        [joeykins82](https://www.reddit.com/user/joeykins82/)

        • [3y ago](https://www.reddit.com/r/PowerShell/comments/ozr6ye/comment/h81um1e/)

        You don't need `SchUseStrongCrypto` if you've set `SystemDefaultTlsVersions`

        For full compatibility/consistency you should also set the same entries in 
        `HKLM:\SOFTWARE\WOW6432Node\...`: it's generally less important on servers but 
        while there's still the odd 32-bit application floating around there's no 
        downside in ensuring that 32-bit applications making .NET HTTPS calls are also 
        using the SCHANNEL defaults for TLS 
        Also also if you're running WinSvr2012 (Win6.2) or you need to tell 
        WinHTTP to use TLS 1.2 via the `DefaultSecureProtocols` subkey, and also also 
        also if you still have 2008 R2 or Win7 laying around you have to do that AND 
        configure SCHANNEL itself. 


    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    This script return general info about certificate chain status 
    .EXAMPLE
    PS> update-SecurityProtocolTDO ; 
    PS> $mod = 'ExchangeOnlineManagement' ; Try {Get-Module $mod -ErrorAction Stop | out-null } Catch {Import-Module -Name $mod -MinimumVersion '3.1.0' -ErrorAction Stop  } ;
    PS> $Status = Get-ConnectionInformation -ErrorAction SilentlyContinue
    PS> If (-not ($Status)) {Connect-ExchangeOnline -prefix xo -SkipLoadingCmdletHelp -ShowBanner:$false ; }; 
    demo pre-updating PS TLS rev to latest OS-defined ciphers, before initiating EXO connection
    .LINK
    https://www.reddit.com/r/PowerShell/comments/ozr6ye/psa_enabling_tls12_and_you/
    .LINK
    https://github.com/tostka/verb-network
    #>
    #requires -Version 2.0
    [CmdletBinding()]
    #[Alias('','')]
    PARAM() ;
    BEGIN {
        $Verbose = ($VerbosePreference -eq 'Continue')        
        $CurrentVersionTlsLabel = [Net.ServicePointManager]::SecurityProtocol ; # Tls, Tls11, Tls12 ('Tls' == TLS1.0)  ;
        write-verbose "PRE: `$CurrentVersionTlsLabel : $($CurrentVersionTlsLabel )" ; 
        # psv6+ already covers, test via the SslProtocol parameter presense
        if ('SslProtocol' -notin (Get-Command Invoke-RestMethod).Parameters.Keys) {
            $currentMaxTlsValue = [Math]::Max([Net.ServicePointManager]::SecurityProtocol.value__,[Net.SecurityProtocolType]::Tls.value__) ; 
            write-verbose "`$currentMaxTlsValue : $($currentMaxTlsValue )" ; 
            $newerTlsTypeEnums = [enum]::GetValues('Net.SecurityProtocolType') | Where-Object { $_ -gt $currentMaxTlsValue }
            if($newerTlsTypeEnums){
                write-verbose "Appending upgraded/missing TLS `$enums:`n$(($newerTlsTypeEnums -join ','|out-string).trim())" ; 
            } else {
                write-verbose "Current TLS `$enums are up to date with max rev available on this machine" ; 
            }; 
            $newerTlsTypeEnums | ForEach-Object {
                [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor $_
            } ; 
        } ; 
    } ;
    PROCESS {} ;  # loop-E $Certificate
    END {write-verbose "POST: Current TLS `$enums:$(([Net.ServicePointManager]::SecurityProtocol |out-string).trim())" ; } ; 
} ; 
#*------^ END Function update-SecurityProtocolTDO ^------
