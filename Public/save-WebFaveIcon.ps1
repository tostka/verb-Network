#*------v Function save-WebFaveIcon v------
function save-WebFaveIcon {
    <#
    .SYNOPSIS
    save-WebFaveIcon - Download a website's default root favicon.ico file to a .jpg (assumed ext: actual downloaded filetype is *not* validated)
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2020-04-17
    FileName    : save-WebFaveIcon.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka/verb-network
    Tags        : Powershell,Internet,Download,File
    AddedCredit : poshftw
    AddedWebsite: https://old.reddit.com/r/PowerShell/comments/moxy5v/downloading_a_file_with_powershell_without/
    AddedTwitter: URL
    AddedCredit : Jimmy McNatt
    AddedWebsite: https://jmcnatt.net/quick-tips/powershell-capturing-a-redirected-url-from-a-web-request/
    AddedTwitter: @jmcnatt / https://twitter.com/jmcnatt
    REVISIONS
    6:09 PM 5/12/2023 initial vers 
    .DESCRIPTION
    save-WebFaveIcon - Download a website's default root favicon.ico file to a .jpg (assumed ext: actual downloaded filetype is *not* validated)

    Dependancies:
    - requires Box Prox's [get-FileSignature()](https://mcpmag.com/articles/2018/07/25/file-signatures-using-powershell.aspx)
    - requires gravejester (Øyvind Kallstad)'s [get-FileType()](https://gist.github.com/gravejester/803649515c2dd85ab37e)

    .PARAMETER Name
    Name string to be used for the downloaded favicon[-name 'SiteName']
    .PARAMETER Url
    Root web site from which to download the favicon[-Url https://community.chocolatey.org/]
    .PARAMETER Path
    Path to destination directory for favicon download (defaults to c:\temp\jpg)[-Path 'c:\path-to\']
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output
    .EXAMPLE
    PS> save-webfaveicon -name duckduckgo -url https://duckduckgo.com/ -Verbose
    Demo download of a duckduckgo.com's favicon (which has a relative favicon path)
    .EXAMPLE
    PS> save-webfaveicon -name proofpoint -url https://www.proofpoint.com/ -Verbose
    Demo download of a proofpoint.com's favicon (which has an absolute favicon path)
    .LINK
    https://github.com/tostka/verb-network
    #>
    ## [OutputType('bool')] # optional specified output type
    [CmdletBinding()]
    ###[Alias('Alias','Alias2')]
    PARAM (
        [Parameter(Mandatory=$false,Position=1,
            HelpMessage="Name string to be used for the downloaded favicon[-name 'SiteName']")] 
            [string]$name,
        [Parameter(Mandatory=$true,Position=0,
            HelpMessage="Root web site from which to download the favicon[-Url https://community.chocolatey.org/]")] 
            [uri[]]$url,
        [Parameter(Mandatory=$false,
            HelpMessage = "Path to destination directory for favicon download [-Path 'c:\path-to\']")]
            #[ValidateScript({Test-Path $_ -PathType 'Container'})]
            #[ValidateScript({Test-Path $_})]
            [string]$Path = "c:\temp\jpg"
    ) ; 
    BEGIN {
        #$rgxHeaders = 'filename=(?:\")*(?<filename>.+?)(?:\")*$' ; 
        #$rgxHtmlAnchor = '<a href="(.*)">' ; 
        $rgxFaveIcon = '<link\srel=.*shortcut\sicon|favicon\.ico' # target tag: <link rel="shortcut icon" href="/favicon.ico">
        #'shortcut\sicon|favicon\.ico' ; 
        $rgxURL = '(?i)\b((?:[a-z][\w-]+:(?:/{1,3}|[a-z0-9%])|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:.,<>?«»“”‘’]))' ; 
        $verbose = $($VerbosePreference -eq "Continue") ;

        TRY {
            if (Test-Path $Path) {}
            else { New-Item $Path -ItemType Directory -verbose:$true}

            # use cleaned [uri].host if $name is blank
            if(-not $name){
                if($url.host){
                    $name=[RegEx]::Replace($url.host, "[{0}]" -f ([RegEx]::Escape(-join [System.IO.Path]::GetInvalidFileNameChars())), '') ;
                    $smsg = "No -Name specified: Derived filename from -url Host value:`n$($name)" ; 
                    write-host -ForegroundColor yellow $smsg ; 
                } else { 
                    $smsg = "No -Name specified: But unable to parse [uri].host from specified -url value:`n$($url.OriginalString)" ; 
                    $smsg += "`nPlease rerun with an explicit -Name value" ; 
                    write-warning $smsg ; 
                    break ; 
                } ; 
            } ; 

        } CATCH {
                # or just do idiotproof: Write-Warning -Message $_.Exception.Message ;
                $ErrTrapd=$Error[0] ;
                $smsg = "$('*'*5)`nFailed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: `n$(($ErrTrapd|out-string).trim())`n$('-'*5)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                else{ write-warning $smsg } ;
                $smsg = "FULL ERROR TRAPPED (EXPLICIT CATCH BLOCK WOULD LOOK LIKE): } catch[$($ErrTrapd.Exception.GetType().FullName)]{" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level ERROR } #Error|Warn|Debug
                else{ write-host $smsg } ;
                throw $ErrTrapd ; 
                Break #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
        } ; 

    } ;  # BEGIN-E
    PROCESS {
        $Error.Clear() ; 

            $dfile =  $results = $null ; 
            
            write-verbose "Retrieving root site source..." ; 
            TRY {
                 $results = Invoke-WebRequest -Uri $url.absoluteuri -UseBasicParsing ; 
            }CATCH [System.Net.WebException]{
                $ErrTrapd=$Error[0] ;
                if($ErrTrapd.Exception -match '\(501\)'){
                    # choco returns 501 on both the -Method Head fail, and on lack of support for Start-BitsTransfer : HTTP status 501: The server does not support the functionality required to fulfill the request.
                    # on the 501 error - choco, which lacks header support - we can trap the redir for parsing:
                    $smsg = "Exception:'$($ErrTrapd.Exception)' returned" ; 
                    if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 

                    $smsg = "=>Remote server returned a 501 (not implemented error)" ; 
                    $smsg += "`n`n-->Re-Attempting:Obtain & parse redirection info for request..." ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                    else{ write-host $smsg } ;
                } elseif( ($ErrTrapd.Exception -match '\(429\)') -OR ($ErrTrapd.Exception -match 'Too\sMany\sRequests')){
                    # throttling error returned:
                    $smsg = "Exception:'$($ErrTrapd.Exception)' returned" ; 
                    if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                    $smsg = "SERVER THROTTLING!:`nException:'$($ErrTrapd.Exception)' returned" ; 
                    $smsg += "`nToo many requests too quickly, wait for block to expire and" ; 
                    $smsg += "`ntry increasing delay" ; 
                    $smsg += "(for choco, the throttling only reset after an HOUR!)" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                    else{ write-WARNING $smsg } ; 
                    throw $smsg ; 
                    # fatal, server is going to continue throttling for an HOUR: no point in using Continue
                    break ; 
                } else { 
                    $smsg = "Exception:'$($ErrTrapd.Exception)' returned" ; 
                    $smsg = "`nUnrecognized error, aborting further processing" ; 
                    $smsg += "`nPlease specify a full leaf file -Path specification and retry" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                    else{ write-WARNING $smsg } ; 
                    throw $smsg ; 
                    break ; 
                } ; 
            } CATCH {
                # or just do idiotproof: Write-Warning -Message $_.Exception.Message ;
                $ErrTrapd=$Error[0] ;
                $smsg = "$('*'*5)`nFailed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: `n$(($ErrTrapd|out-string).trim())`n$('-'*5)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                else{ write-warning $smsg } ;
                $smsg = "FULL ERROR TRAPPED (EXPLICIT CATCH BLOCK WOULD LOOK LIKE): } catch[$($ErrTrapd.Exception.GetType().FullName)]{" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level ERROR } #Error|Warn|Debug
                else{ write-host $smsg } ;
                Break #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
                throw $ErrTrapd ; 
            } ; 


            TRY {

                
                $Path = join-path -path $Path -childpath "$($name).jpg" ; 
                if(test-path -path $Path){
                    write-host "Pre-existing $($Path) file found, pre-clearing before run..." ; 
                    remove-item -path $Path -erroraction STOP; 
                } ; 
                
                write-verbose "parsing content for favicon link tag..." ; 
                $lines = $results.Content.Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries) ;
                # $rgxFaveIcon = '<link\srel=.*shortcut\sicon|favicon\.ico' # target tag: <link rel="shortcut icon" href="/favicon.ico">
                if($lines | ?{$_ -match $rgxFaveIcon}){
                    write-verbose "link line located" ; 
                    <# proofpoint has 2 hits on the favicon filter
                    <link rel="shortcut icon" href="/themes/custom/proofpoint/apps/drupal/favicon.ico" />
                    <link rel="icon" href="/themes/custom/proofpoint/apps/drupal/favicon.ico" type="image/vnd.microsoft.icon" />
                    same href, just different link rel label
                    #>
                    # so always take the first:
                    $ficonUrl = $lines | ?{$_ -match $rgxFaveIcon } | select-object -first 1 ; 
                    if ( ($ficonurl.tostring() -match '^http') -AND  ([boolean]([uri]$ficonurl.tostring())) ){
                        write-verbose "Absolute parsable URL http present" ; 
                        [uri]$ficonUrl = [regex]::match($ficonUrl,$rgxURL).captures.value.replace('"','') ; 
                        # https://a.mtstatic.com/@public/production/site_6638/1614630907-favicon.ico/
                    } else { 
                        $smsg = "Parsing apparant relative uri & building AbsoluteURI" ; 
                        $smsg += "`n$($ficonurl.tostring())" ; 
                        write-verbose $smsg ; 
                        $uriLeaf = [regex]::match($ficonUrl.split('=')[2],'"(.*)"').groups[1].value ; 
                        if($urileaf -match '^/'){
                            $urileaf =  $urileaf.Substring(1,$urileaf.length-1) ; 
                        } ; 
                        #$ub = new-object System.UriBuilder -argumentlist 'http', 'myhost.com', 80, 'mypath/query.aspx', '?param=value'
                        #$ub = new-object System.UriBuilder -argumentlist $url.Scheme, $url.Host, $url.Port, (-join ($url.AbsolutePath,'/',$uriLeaf)), '?param=value'
                        $arglist = @() ; 
                        $arglist += $url.Scheme 
                        $arglist += $url.Host ; 
                        $arglist += $url.Port ; 
                        #$arglist += (-join ($url.AbsolutePath,'/',$uriLeaf))
                        $arglist += (-join ($url.AbsolutePath,'/',$uriLeaf)).replace('//','/') ; 
                        $arglist += $url.Query ; 
                        write-verbose "`$arglist`n$(($arglist|out-string).trim())" ; 
                        $ub = new-object System.UriBuilder -argumentlist $arglist ; 

                        [uri]$ficonUrl = $ub.uri.AbsoluteUri ; 
                    } ; 
                    if($ficonUrl.AbsoluteUri){
                        write-verbose "Favicon link line parses to a valid URI:$($ficonUrl.AbsoluteUri)" ; 
                    } else {
                        $smsg = "Failed to match a URL from the matched line`n$(($lines | ?{$_ -match $rgxFaveIcon }|out-string).trim())" ; 
                        write-warning $smsg ; 
                    }; 
                } else { 
                    write-warning "Failed to locate a FaveIcon link tag:$($rgxFaveIcon)" ; 
                    Break ; 
                } ; 
            } CATCH {
                # or just do idiotproof: Write-Warning -Message $_.Exception.Message ;
                $ErrTrapd=$Error[0] ;
                $smsg = "$('*'*5)`nFailed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: `n$(($ErrTrapd|out-string).trim())`n$('-'*5)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                else{ write-warning $smsg } ;
                $smsg = "FULL ERROR TRAPPED (EXPLICIT CATCH BLOCK WOULD LOOK LIKE): } catch[$($ErrTrapd.Exception.GetType().FullName)]{" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level ERROR } #Error|Warn|Debug
                else{ write-host $smsg } ;
                Break #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
                throw $ErrTrapd ; 
            } ; 
            write-verbose "downloading resolved favicon file url:`n$(($ficonUrl.AbsoluteUri|out-string).trim())" ; 
            
            TRY {
                Invoke-WebRequest -UseBasicParsing -uri $ficonUrl.AbsoluteUri -outfile $Path ; 
            }CATCH [System.Net.WebException]{
                $ErrTrapd=$Error[0] ;
                if($ErrTrapd.Exception -match '\(501\)'){
                    # site returns 501 on both the -Method Head fail, and on lack of support for Start-BitsTransfer : HTTP status 501: The server does not support the functionality required to fulfill the request.
                    # on the 501 error - choco, which lacks header support - we can trap the redir for parsing:
                    $smsg = "Exception:'$($ErrTrapd.Exception)' returned" ; 
                    if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 

                    $smsg = "=>Remote server returned a 501 (not implemented error)" ; 
                    $smsg += "`n`n-->Re-Attempting:Obtain & parse redirection info for request..." ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                    else{ write-host $smsg } ;
                } elseif( ($ErrTrapd.Exception -match '\(429\)') -OR ($ErrTrapd.Exception -match 'Too\sMany\sRequests')){
                    # throttling error returned:
                    $smsg = "Exception:'$($ErrTrapd.Exception)' returned" ; 
                    if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                    $smsg = "SERVER THROTTLING!:`nException:'$($ErrTrapd.Exception)' returned" ; 
                    $smsg += "`nToo many requests too quickly, wait for block to expire and" ; 
                    $smsg += "`ntry increasing delay" ; 
                    $smsg += "(for choco, the throttling only reset after an HOUR!)" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                    else{ write-WARNING $smsg } ; 
                    throw $smsg ; 
                    # fatal, server is going to continue throttling for an HOUR: no point in using Continue
                    break ; 
                } else { 
                    $smsg = "Exception:'$($ErrTrapd.Exception)' returned" ; 
                    $smsg = "`nUnrecognized error, aborting further processing" ; 
                    $smsg += "`nPlease specify a full leaf file -Path specification and retry" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                    else{ write-WARNING $smsg } ; 
                    throw $smsg ; 
                    break ; 
                } ; 
            } CATCH {
                # or just do idiotproof: Write-Warning -Message $_.Exception.Message ;
                $ErrTrapd=$Error[0] ;
                $smsg = "$('*'*5)`nFailed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: `n$(($ErrTrapd|out-string).trim())`n$('-'*5)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                else{ write-warning $smsg } ;
                $smsg = "FULL ERROR TRAPPED (EXPLICIT CATCH BLOCK WOULD LOOK LIKE): } catch[$($ErrTrapd.Exception.GetType().FullName)]{" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level ERROR } #Error|Warn|Debug
                else{ write-host $smsg } ;
                Break #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
                throw $ErrTrapd ; 
            } ; 
            
            if($dfile = get-childitem -path $Path ){
                write-host -foregroundcolor green "Confirmed presence of downloaded file`n$(($dfile| ft -a Length,fullName|out-string).trim())`n(launching by assoication)" ; 
                #start $dfile.fullname ; 
                [array]$doFileTest = @() ; 
                'get-filesignature','get-filetype' | foreach-object{
                     if(-not (get-command $_ -ea 0)){
                        $doFileTest += $false ;
                     } else {
                        $doFileTest += $true ;
                    }; 
                } ; 
                if($doFileTest -contains $false){
                    $smsg = "Missing dependant: $($_) function" ; 
                    $smsg += "`nSkipping file type checks!" ; 
                    write-warning $smsg ; 
                } else {
                    # test filetype 
                    $Imagetype = get-FileType -Path $dfile.fullname -verbose:$($VerbosePreference -eq "Continue") ;
                    # Accommodate multi-extension filetypes by parsing output: split on /, and always take the first entry.
                    # 'Archive (ZIP/JAR)' == returns ZIP, vs JAR
                    $ImagetypeExtension = ([regex]::match($Imagetype.FileType,"\(.*\)").groups[0].captures[0].value.replace('(','').replace(')','').split('/'))[0]
                    if($dfile.extension -eq ".$($ImagetypeExtension)"){
                        write-verbose "Downloaded favicon file`n$($dfile.fullname)`nconfirms as a .jpg file" ; 
                    } else { 
                        $smsg = "Downloaded favicon file`n$($dfile.fullname)`ndetects from file header as a .$($ImagetypeExtension) file" ; 
                        $smsg += "`nRENAMING to suitable extension..." ; 
                        write-host -foregroundcolor yellow $smsg ; 
                        $pltRI = @{
                            Path = $dfile.fullname ;
                            NewName = $dfile.name.replace($dfile.extension,".$($ImagetypeExtension.tolower())") ; 
                            ErrorAction = 'STOP'
                            verbose = $($VerbosePreference -eq "Continue") ;
                        } ; 
                        write-verbose "rename-item w`n$(($pltri|out-string).trim())" ; 
                        TRY{
                            rename-item @pltri ; 
                        } CATCH {
                            $ErrTrapd=$Error[0] ;
                            $smsg = "$('*'*5)`nFailed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: `n$(($ErrTrapd|out-string).trim())`n$('-'*5)" ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                            else{ write-warning $smsg } ;
                            $smsg = "FULL ERROR TRAPPED (EXPLICIT CATCH BLOCK WOULD LOOK LIKE): } catch[$($ErrTrapd.Exception.GetType().FullName)]{" ;
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level ERROR } #Error|Warn|Debug
                            else{ write-host $smsg } ;
                            Break #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
                            throw $ErrTrapd ; 
                        } ; 
                    
                    } ; 
                } ; 
            } else {
                $smsg = "Unable to confirm presense of downloaded file!:" 
                $smsg += "`n$($Path)" ; 
                write-warning $smsg ; 
            }; ; 
    } ;  # if-PROC
} ; 
#*------^ END Function save-WebFaveIcon ^------
