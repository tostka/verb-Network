# test-RDPDriveRedirectionTDO.ps1

    #region TEST_RDPDRIVEREDIRECTIONTDO ; #*------v test-RDPDriveRedirectionTDO v------
    function test-RDPDriveRedirectionTDO {
        <#
        .SYNOPSIS
        test-RDPDriveRedirectionTDO.ps1 - From RDP desktop, test for available drives redirected into \\tsclient mappings
        .NOTES
        Version     : 0.0.1
        Author      : Todd Kadrie
        Website     : http://www.toddomation.com
        Twitter     : @tostka / http://twitter.com/tostka
        CreatedDate : 2025-07-17
        FileName    : test-RDPDriveRedirectionTDO.ps1
        License     : MIT License
        Copyright   : (c) 2025 Todd Kadrie
        Github      : https://github.com/tostka/verb-XXX
        Tags        : Powershell
        AddedCredit : REFERENCE
        AddedWebsite: URL
        AddedTwitter: URL
        REVISIONS
        * 12:41 PM 9/17/2025 removed write-my* calls: implemented support in vio\write-log() instead (avoids all this manual updating)
        * 10:45 AM 8/6/2025 added write-myOutput|Warning|Verbose support (for xopBuildLibrary/install-Exchange15.ps1 compat)
        * 1:16 PM 7/17/2025 init
        .DESCRIPTION
        test-RDPDriveRedirectionTDO.ps1 - From RDP desktop, test for available drives redirected into \\tsclient mappings
        
        MS provides sample code for testing local redirected drives in RDP at link below. 
        I haven't been able to get it to work in Win Server 2016, so I wrapped net use, and have a -useLegacy param, that can be overridden
        -- -useLegacy:$false -- to divert into the non-functional MS code.

        ## Ref: 

            * [Configure fixed, removable, and network drive redirection over the Remote Desktop Protocol | Microsoft Learn](https://learn.microsoft.com/en-us/azure/virtual-desktop/redirection-configure-drives-storage?tabs=intune&pivots=azure-virtual-desktop)
            * [Supported RDP properties | Microsoft Learn](https://learn.microsoft.com/en-us/azure/virtual-desktop/rdp-properties#device-redirection)
                - [drivestoredirect](https://learn.microsoft.com/en-us/azure/virtual-desktop/rdp-properties#drivestoredirect)

                > ### `drivestoredirect`
                > 
                > -   **Syntax**: `drivestoredirect:s:<value>`
                >     
                > -   **Description**: Determines which fixed, removable, and network drives on the local device will be redirected and available in a remote session.
                >     
                > -   **Supported values**:
                >     
                >     -   _Empty_: Don't redirect any drives.
                >     -   `*`: Redirect all drives, including drives that are connected later.
                >     -   `DynamicDrives`: Redirect any drives that are connected later.
                >     -   `drivestoredirect:s:C:\;E:\;`: Redirect the specified drive letters for one or more drives, such as this example.
                > -   **Default value**: _`Empty`_
                >     
                > -   **Applies to**:
                >     
                >     -   Azure Virtual Desktop
                >     -   Remote Desktop Services
                >     -   Remote PC connections

                Note: I'd previously defined (in Create-RDP.ps1 templates) that this was supported syntax:
                ```text
                drivestoredirect:s:Windows (C:);
                ```                    

                But as of 7/17/2025 it's demonstrably not functional. Given the docs only mention drive letters, and what mstsc writes to files is:
                drivestoredirect:s:C:\;
                drivestoredirect:s:C:\;D:\;
                Use of a semi-colon-delimited list appears to be the limit of the supported syntax.    

        .INPUTS
        None. Does not accepted piped input.
        .OUTPUTS
        System.Object[]
        .EXAMPLE        
        PS> if((test-RDPDriveRedirectionTDO).clientdriveletter -contains 'C:'){write-host -foregroundcolor green "C: is mapped" }

            C: is mapped

        Demo test for local C drive redirection as \\tsclient\c on remote host.
        .LINK
        https://github.com/tostka/verb-IO
        #>
        [CmdletBinding()]
        PARAM([Parameter(ValueFromPipelineByPropertyName = $true, HelpMessage = "Message is the content that you wish to add to the log file")]
            [switch]$useLegacy = $true
        ) ;
        BEGIN{
            if($env:SESSIONNAME -ne 'Console'){$bRDP=$True;}else{
                $smsg = "Session/Desktop is *not* running over RDP/Termserve!(Exiting)" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                $smsg += "`n(`$env:SESSIONNAME -ne 'Console':$($env:SESSIONNAME) -ne 'Console'" ;
                write-verbose $smsg ; 
                Break ; 
            }; 
        }
        PROCESS{
            if($useLegacy){
                # having issues with the MS sample code - no results; but net use always works, so wrap it and move on
                $smsg = "-useLegacy: using parsed CMD> net use output" ; 
                if($VerbosePreference -eq "Continue"){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ;
                $Results = @() ; 
                (net use).trim() -match '\\\\TSCLIENT\\[A-Z]'  | foreach-object{
                    if($_ -match '\\\\TSCLIENT\\[A-Z]'){
                        $thismatch = $matches; 
                        $summary = [ordered]@{
                            ClientDriveLetter = "$($thismatch.Values -replace '\\\\tsclient\\',''):" ; 
                            LocalMapping = $($thismatch.Values) ; 
                            Description = "Remote Client Drive $($thismatch.Values -replace '\\\\tsclient\\',''):\ is mapped locally to $($thismatch.Values)" ; 
                        }; 
                        write-verbose  $summary.description ;  
                        $results += [pscustomobject]$summary ; 
                    } ; 
                } ; 
                $results | write-output ; 

            }else{
                # ms demo code that doesn't work for me, so far on Win Server 2016, so we defer to net use above
                # given below doesn't work, I haven't bothered to emulate the outputs from the above net use parsing...
                $CLSIDs = @() ;
                foreach($registryKey in (Get-ChildItem "Registry::HKEY_CLASSES_ROOT\CLSID" -Recurse)){
                    If (($registryKey.GetValueNames() | foreach-object {$registryKey.GetValue($_)}) -eq "Drive or folder redirected using Remote Desktop") {
                        $CLSIDs += $registryKey ;
                    } ;
                } ;
                $drives = @() ;
                foreach ($CLSID in $CLSIDs.PSPath) {
                    $drives += (Get-ItemProperty $CLSID)."(default)" ;
                } ;
                #Write-Output "These are the local drives redirected to the remote session:`n" ;
                $smsg = "These are the local drives redirected to the remote session:`n$(($drives|out-string).trim())" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                $drives | write-output ;     
            } ;            
        }
    } ;
    #endregion TEST_RDPDRIVEREDIRECTIONTDO ; #*------^ END test-RDPDriveRedirectionTDO ^------