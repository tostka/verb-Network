
#region PUSH_TLSLATEST ; #*------v push-TLSLatest v------
#if(-not(gi function:push-TLSLatest -ea 0)){
    function push-TLSLatest{
        <#
        .SYNOPSIS
        push-TLSLatest - Elevates TLS on Powershell connections to highest available local version
        .NOTES
        Version     : 0.0.
        Author      : Todd Kadrie
        Website     : http://www.toddomation.com
        Twitter     : @tostka / http://twitter.com/tostka
        CreatedDate : 2025-
        FileName    : test-ModulesAvailable.ps1
        License     : MIT License
        Copyright   : (c) 2025 Todd Kadrie
        Github      : https://github.com/tostka/verb-Network
        Tags        : Powershell
        AddedCredit : REFERENCE
        AddedWebsite: URL
        AddedTwitter: URL
        REVISIONS
        * 9:05 AM 6/2/2025 expanded CBH, copied over current call from psparamt
        * 4:41 PM 5/29/2025 init (replace scriptblock in psparamt)
        .DESCRIPTION
        push-TLSLatest - Elevates TLS on Powershell connections to highest available local version
        .PARAMETER ModuleSpecifications
        Array of semicolon-delimited module test specifications in format 'modulename;moduleurl;testcmdlet'[-ModuleSpecifications 'verb-logging;localRepo;write-log'
        .INPUTS
        None. Does not accepted piped input.
        .OUTPUTS
        None. 
        .EXAMPLE
        PS> push-TLSLatest ;     
        .LINK
        https://github.com/tostka/verb-Network      
        #>
        [CmdletBinding()]
        PARAM() ; 
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
#} ; 
#endregion PUSH_TLSLATEST ; #*------^ END push-TLSLatest ^------