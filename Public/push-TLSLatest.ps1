# push-TLSLatest

    #region PUSH_TLSLATEST ; #*------v push-TLSLatest v------
    if (-not(gi function:push-TLSLatest -ea 0)) {
        function push-TLSLatest {
            <#
        .SYNOPSIS
        push-TLSLatest - Elevates TLS on Powershell connections to highest available local version
        .NOTES
        Version     : 0.0.
        Author      : Todd Kadrie
        Website     : http://www.toddomation.com
        Twitter     : @tostka / http://twitter.com/tostka
        CreatedDate : 2025-
        FileName    : push-TLSLatest.ps1
        License     : MIT License
        Copyright   : (c) 2025 Todd Kadrie
        Github      : https://github.com/tostka/verb-Network
        Tags        : Powershell,Security,TLS,protocol,Encryption
        AddedCredit : REFERENCE
        AddedWebsite: URL
        AddedTwitter: URL
        REVISIONS        
        * 12:46 PM 9/17/2025 spliced orig expanded CBH over, brought up to date
        * 9:05 AM 6/2/2025 expanded CBH, copied over current call from psparamt
        * 4:41 PM 5/29/2025 init (replace scriptblock in psparamt)
        .DESCRIPTION
        push-TLSLatest - Elevates TLS on Powershell connections to highest available local version        
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
            $smsg = "PRE: `$CurrentVersionTlsLabel : $($CurrentVersionTlsLabel )" ;
            if($VerbosePreference -eq "Continue"){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
            # psv6+ already covers, test via the SslProtocol parameter presense
            if ('SslProtocol' -notin (Get-Command Invoke-RestMethod).Parameters.Keys) {
                $currentMaxTlsValue = [Math]::Max([Net.ServicePointManager]::SecurityProtocol.value__, [Net.SecurityProtocolType]::Tls.value__) ;
                $smsg = "`$currentMaxTlsValue : $($currentMaxTlsValue )" ;
                if($VerbosePreference -eq "Continue"){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                $newerTlsTypeEnums = [enum]::GetValues('Net.SecurityProtocolType') | Where-Object { $_ -gt $currentMaxTlsValue }
                if ($newerTlsTypeEnums) {
                    $smsg = "Appending upgraded/missing TLS `$enums:`n$(($newerTlsTypeEnums -join ','|out-string).trim())" ;
                    if($VerbosePreference -eq "Continue"){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                } else {
                    $smsg = "Current TLS `$enums are up to date with max rev available on this machine" ;
                    if($VerbosePreference -eq "Continue"){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                };
                $newerTlsTypeEnums | ForEach-Object {
                    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor $_
                } ;
            } ;
        } ;
    } ;
    #endregion PUSH_TLSLATEST ; #*------^ END push-TLSLatest ^------