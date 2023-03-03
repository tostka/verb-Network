#*------v Function save-WebDownload v------
function save-WebDownload {
    <#
    .SYNOPSIS
    save-WebDownload - Download Uri file from Inet (via Invoke-WebRequest iwr), without need to know destination filename (parses filename out of headers of the download).
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2020-04-17
    FileName    : save-WebDownload.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell,Internet,Download,File
    AddedCredit : poshftw
    AddedWebsite: https://old.reddit.com/r/PowerShell/comments/moxy5v/downloading_a_file_with_powershell_without/
    AddedTwitter: URL
    AddedCredit : Jimmy McNatt
    AddedWebsite: https://jmcnatt.net/quick-tips/powershell-capturing-a-redirected-url-from-a-web-request/
    AddedTwitter: @jmcnatt / https://twitter.com/jmcnatt
    REVISIONS
    * 2:56 PM 3/3/2023 finally generated throttling '(429) Too Many Requests.' from choco. 
    Reworked -path logic; replaced param with 2 params: -Destination (dir to target dl's into, w dynamic download file resolution) -DestinationFile (full path to download file -outputpath)
    Reworked a lot of the echos, added wlt support for all echos. 
    Only seems to occur pulling pkgs; when running installs, they run for minutes between dl's which seems to avoid issue.
    * 3:50 PM 2/24/2023 add: relative-path resolution on inbound $Path; code 
    [system.io.fileinfo] code to differntiate Leaf file from Container status of 
    Path ;  Logic to validate functional combo of existing/leaf/container -Path. Expanded wlt support throughout.
    * 11:46 AM 2/23/2023 retooled poshftw's original concept, expanding to fail back to obtain a redir for parsing. 
    .DESCRIPTION
    save-WebDownload - Download Uri file from Inet (via Invoke-WebRequest iwr), without need to know destination filename (parses filename out of headers of the download).

    Uses two levels of logic to try to obtain remote download filename (where it's a redirect or v-dir as a target uri):
    1) Leverages poshftw's Invoke-WebRequest -Method Head parse code, to pre-retrieve the Header and back out the target filename 
        (which is then used as final Invoke-WebRequest -Outfile). 
    2) And for sites that don't support -Header (chocolatey.org throws 501 not implemented), it falls back to to 
        trying to obtain and parse a redirect with the full file target present and detectable.
        (leveraging redirect-grabing specs pointed out by Jimmy McNatt in his post [PowerShell – Capturing a Redirected URL from a Web Request – JMCNATT.NET - jmcnatt.net/](https://jmcnatt.net/quick-tips/powershell-capturing-a-redirected-url-from-a-web-request/)
    
    Where the above fail though, you're just going to have to spec a generic -Outfile/DestinationFile, 
    if you really can't pre-determine what the version etc returned remotely is going to be.

    .PARAMETER Uri
    Uri to be downloaded[-Uri https://community.chocolatey.org/api/v2/package/chocolatey]")] 
    .PARAMETER Destination
    Path to destination for dynamic filename download(defaults to pwd)[-Destination 'c:\path-to\']
    .PARAMETER DestinationFile
    Full path to destination file for download[-PathFile 'c:\path-to\']
    .PARAMETER ThrottleDelay
    Delay in milliseconds to be applied between a series of downloads(1000 = 1sec)[-ThrottleDelay 1000]
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output
    .EXAMPLE
    save-webdownload -Uri https://community.chocolatey.org/api/v2/package/chocolatey -Destination c:\tmp\ -verbose
    Demo download of a redirected generic url, to the derived filename into c:\tmp dir.
    .EXAMPLE
    save-webdownload -Uri https://fqdn/dir -Path c:\tmp\file.ext ;
    Demo standard Path-specified download
    .EXAMPLE
    $dlpkgs = 'https://community.chocolatey.org/api/v2/package/PowerShell/5.1.14409.20180811','https://community.chocolatey.org/api/v2/package/powershell-core/7.3.2','https://community.chocolatey.org/api/v2/package/vscode/1.75.1','https://community.chocolatey.org/api/v2/package/path-copy-copy/20.0','https://community.chocolatey.org/api/v2/package/choco-cleaner/0.0.8.4','https://community.chocolatey.org/api/v2/package/networkmonitor/3.4.0.20140224','https://community.chocolatey.org/api/v2/package/wireshark/4.0.3','https://community.chocolatey.org/api/v2/package/fiddler/5.0.20211.51073','https://community.chocolatey.org/api/v2/package/pal/2.7.6.0','https://community.chocolatey.org/api/v2/package/logparser/2.2.0.1','https://community.chocolatey.org/api/v2/package/logparserstudio/2.2','https://community.chocolatey.org/api/v2/package/bind-toolsonly/9.16.28','https://community.chocolatey.org/api/v2/package/WinPcap/4.1.3.20161116','https://community.chocolatey.org/api/v2/package/microsoft-message-analyzer/1.4.0.20160625' ; 
    $dlpkgs | save-webdownload -Destination C:\tmp\2023-02-23 -verbose  ;
    Demo pkgs array in variable, pipelined in, with destination folder (implies will attempt to obtain download file name from headers).
    .LINK
    #>
    ## [OutputType('bool')] # optional specified output type
    [CmdletBinding()]
    ###[Alias('Alias','Alias2')]
    PARAM (
        #[Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0,
            HelpMessage="Uri to be downloaded[-Uri https://community.chocolatey.org/api/v2/package/chocolatey]")] 
            [uri[]]$Uri,
        [Parameter(Mandatory=$false,Position=1,
            HelpMessage = "Path to destination for dynamic filename download(defaults to pwd)[-Destination 'c:\path-to\']")]
            [string]$Destination,
        [Parameter(Mandatory=$false,Position=2,
            HelpMessage = "Full path to destination file for download[-PathFile 'c:\path-to\']")]
            [string]$DestinationFile,
        #$ThrottleMs
        [Parameter(Mandatory=$false,Position=2,
            HelpMessage = "Delay in milliseconds to be applied between a series of downloads(1000 = 1sec)[-ThrottleDelay 1000]")]
            [int]$ThrottleDelay
    ) ; 
    BEGIN {
        $rgxHeaders = 'filename=(?:\")*(?<filename>.+?)(?:\")*$' ; 
        $rgxHtmlAnchor = '<a href="(.*)">' ; 

        if(-not $ThrottleDelay -AND ((get-variable -name ThrottleMs -ea 0).value)){
            $ThrottleDelay = $ThrottleMs ; 
            $smsg = "(no -ThrottleDelay specified, but found & using `$global:ThrottleMs:$($ThrottleMs)ms" ; 
            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
        } ; 

        $verbose = $($VerbosePreference -eq "Continue") ;


        if($Destination  -AND $DestinationFile){
            $smsg = "BOTH: -Destination & -DestinationFile specified!" ; 
            $smsg += "`nPlease choose one or the other, NOT BOTH!" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
            else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
            throw $smsg ; 
            BREAK ; 
        } ; 

        if(-not $Destination -AND -not $DestinationFile){
            $Destination = (Get-Location).Path
        } ; 

        TRY {
            $smsg = "Normalized out any relative paths to absolute:" ; 
            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 

            # Src: x0n | https://stackoverflow.com/users/6920/x0n |  Jun 14, 2010 at 21:12 | [Powershell: resolve path that might not exist? - Stack Overflow - stackoverflow.com/](https://stackoverflow.com/questions/3038337/powershell-resolve-path-that-might-not-exist)
            # Advantage: works with PSPaths (vs dot/native filesystem paths). A PSPath may not map 1-1 to a filesystem path, for example if you mount a psdrive with a multi-letter drive name.
            #$Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($path) ;
            if($Destination ){
                $Destination = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Destination) ;
            } ; 
            if($DestinationFile){
                $DestinationFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DestinationFile) ;
            } ; 
            <#
            # alt: hack of resolve-path (which norm can't resolve non-exist paths), grabbing resolved path out of the error of a fail, as TargetObject prop.
            # Src: joshuapoehls | https://stackoverflow.com/users/31308/joshuapoehls | Sep 26, 2012 at 15:56 | [Powershell: resolve path that might not exist? - Stack Overflow - stackoverflow.com/](https://stackoverflow.com/questions/3038337/powershell-resolve-path-that-might-not-exist)
            $Path = Resolve-Path $path -ErrorAction SilentlyContinue -ErrorVariable _frperror ; 
            if (-not($Destination)) {$Destination = $_frperror[0].TargetObject} ; 
            #>
            
            $smsg = "Cast `$Destination/`$DestinationFile to [system.io.fileinfo]" ; 
            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 

            if($Destination){
                [system.io.fileinfo]$Destination = $Destination ;
            } ; 
            if($DestinationFile){
                [system.io.fileinfo]$DestinationFile = $DestinationFile ;
            } ; 

            [boolean]$PathIsFile = [boolean]$PathExists = $false ; 


            if($Destination -and (test-path -path $Destination)){
                # we should *require* that dirs exist, if doing dyn paths
                $PathExists = $true
                # so if exists, check it's type:
                #if(test-path -PathType Leaf){
                $tobj = get-item -path  $Destination -ea STOP; 
                $PathIsFile =  -not($tobj.PSIsContainer) ; 
                if($PathExists -AND $PathIsFile -eq $false){
                    $Path = $Destination
                } ; 
            } elseif($Destination -AND -not (test-path -path $Destination)){
                $smsg = "NON-EXISTANT -Destination specified!" ; 
                $smsg += "`n$(($Destination.fullname|out-string).trim())" 
                #$smsg += "`nNOTE: -Destination should be an existing DIRECTORY (not file)" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                #throw $smsg ; 
                #BREAK ; 
                # PLAN B: CREATE THE MISSING PROMPTED
                $smsg = "`n`nDO YOU WANT TO *CREATE* THE MISSING SPECIFIED -DESTINATION!?" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Prompt } 
                else{ write-host -foregroundcolor YELLOW "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                $bRet=Read-Host "Enter YYY to continue. Anything else will exit"  ; 
                if ($bRet.ToUpper() -eq "YYY") {
                    $smsg = "(Moving on)" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                    else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

                    #New-Item -ItemType "directory" -Path "c:\ps-test\scripts"
                    $pltNI = @{
                        ItemType ="directory" ;
                        Path = $Destination.fullname ; 
                        erroraction = 'STOP' ;
                        whatif = $($whatif) ;
                    } ;
                    $smsg = "New-Item  w`n$(($pltNI|out-string).trim())" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;

                    $Path = new-item @pltNI ; 

                } else {
                     $smsg = "Invalid response. Exiting" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } 
                    else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                    #exit 1
                    break ; 
                }  ; 

            } elseif($DestinationFile -AND (test-path -path $DestinationFile)){
                # existing file spec, overwrite default
                $Path = $DestinationFile ; 
            } elseif($DestinationFile -AND -not (test-path -path $DestinationFile)){
                # non-existant file spec
                # does interrum dir exist?    
                $throwWarn = $false ; 
                if(-not $Destination){
                    $Destination = split-path $DestinationFile ; 
                    $smsg = "blank `$Destination w populated `$DestinationFile:`nderived $Destination from `$DestinationFile" ; 
                    if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
                } ; 
                $smsg = "-DestinationFile as specified`n$($DestinationFile)`n...is *non-existant* file path:"
                if(test-path $Destination  ){
                    $smsg += "`nConfirmed presence of specified parent dir:`n$($Destination.fullname)" ; 

                    $path = $DestinationFile ; 

                } else {
                    $smsg += "`n*COULD NOT* Confirm presence of specified parent dir:`n$($Destination.fullname)" ; 
                    $smsg += "`nA PRE-EXISTING parent is required for -DestinationFile downloads!" ; 
                    $throwWarn = $true ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                    else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                    throw $smsg ; 
                    break ; 
                } ; 
                if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 

            }
            
            $smsg = "Current `$Path:`n$($Path)" ; 
            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 

            if($Path){

                # eval curr $path spec, 
                if($path.name -eq '' -AND ($path.DirectoryName -ne $path.name) -AND $path.Attributes -contains 'Directory'){
                    $smsg =  "Detected `$Path is pre-existing valid directory path (specified with trailing '\')" ;     
                    $PathIsFile = $false ; 
                    $PathExists = $true  ;
                } elseif($path.name -AND ($path.DirectoryName -ne $path.name) -AND $path.Attributes -contains 'Directory'){
                    $smsg =  "Detected `$Path is pre-existing valid directory path (specified without a trailing '\')" ; 
                    $PathIsFile = $false ; 
                    $PathExists = $true  ;
                # issue, both non-exist dir wo trailing \ and non-exist file have same pop'd Name, DirName & Dir, and dir/dirname -ne Name, and Exi8sts always $false
                # prim diff, the dir will have d in the mode, even if not-existing:Mode              : darhsl
                # need to pretest mode -match 'd', for Dir, before testing as file. (attribs are -1 in both cases, only mode has a marker)
                # NOPE! both file in existing dir, and non-exist dir have mode: darhsl
                # 2:31 PM 2/27/2023 newlogic: 1) if the path exists, then test status
                # 2) if doesn't exist, then assume it's a dir. Try to create it 
                #} elseif($path.name -AND ($path.DirectoryName -ne $path.name) -AND $path.mode -match 'd'){
                # Mode: d test covers both non-exist full file spec and non-exist dir have it, so test $DestinationFile & $Destation on this case
                } elseif($path.name -AND ($path.DirectoryName -ne $path.name) -AND $DestinationFile){
                    $smsg =  "Detected `$Path is non-existant valid full file path" ; 
                    $PathIsFile = $true ; 
                    $PathExists = $false  ;
                } elseif($path.name -AND ($path.DirectoryName -ne $path.name) -AND -not $path.exists){
                    $smsg = "Detected `$Path is non-existant valid file path" ; 
                    $PathIsFile = $true ; 
                    $PathExists = $false  ; 
                } elseif($path.name -AND ($path.DirectoryName -ne $path.name) -AND $path.exists){
                    $smsg = "Detected `$Path is pre-existing valid file path" ; 
                    $PathIsFile = $true ; 
                    $PathExists = $true  ;
                } elseif($path.name -eq '' -AND ($path.DirectoryName -ne $path.name) -AND -not $path.exists){
                    $smsg =  "Detected `$Path is non-existant valid directory path" ; 
                    $PathIsFile = $false ; 
                    $PathExists = $false  ;
                } else {
                    $smsg =  "UNRECOGNIZED COMBO OF [SYSTEM.IO.FILEINFO] ATTRIBUTES!" ; 
                    $smsg +=  "`nUnable to differentiate if specified -Path is File, Container, or if it exists" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                    else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                    throw $smsg ; 
                };


                $smsg +=  "`n$($path.fullname)" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success

            } else { 
                $smsg = "`$Path is unpopulated!`n$($Path)" ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                throw $smsg ; 
                break ; 
            }

        } CATCH {
                # or just do idiotproof: Write-Warning -Message $_.Exception.Message ;
                $ErrTrapd=$Error[0] ;
                $smsg = "$('*'*5)`nFailed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: `n$(($ErrTrapd|out-string).trim())`n$('-'*5)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                else{ write-warning $smsg } ;
                #$smsg = $ErrTrapd.Exception.Message ;
                #if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                #else{ write-warning $smsg } ;
                $smsg = "FULL ERROR TRAPPED (EXPLICIT CATCH BLOCK WOULD LOOK LIKE): } catch[$($ErrTrapd.Exception.GetType().FullName)]{" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level ERROR } #Error|Warn|Debug
                else{ write-host $smsg } ;
                throw $ErrTrapd ; 
                Break #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
        } ; 
    } ;  # BEGIN-E
    PROCESS {
        $Error.Clear() ; 

        foreach($item in $Uri){
            TRY {
                #[uri]$item = $item ; 
                if($PathIsFile){
                    $smsg = "(-Path detected as Leaf object: Using as destination filename)" ; 
                    if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                    else{ write-verbose $smsg } ; } ; 
                    Invoke-WebRequest -Uri $item -OutFile $Path ; 
                } elseif(-not $PathIsFile -AND -not $PathExists) { 
                    $smsg = "-Path detected as NON-EXISTANT Container object:" ; 
                    $smsg += "`n a pre-existing Container (or full path to file) must be specified for this function to work properly" ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                    else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                    throw $smsg ; 
                } else { 
                    $smsg = "-Path detected as existing Container object: Attempting to derive the target filename from download Headers..." ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                    else{ write-host $smsg } ;
                    #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success

                    $iwr = Invoke-WebRequest -Uri $item -Method Head ; 
                    if ($iwr.Headers['Content-Disposition'] -match $rgxHeaders) {
                        $OutFilePath = Join-Path $Path $Matches['filename'] ; 
                        $smsg = "Derived filename/OutFilePath:`n" ; 
                        $smsg += "`n$($OutFilePath)" ; 
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                        else{ write-host $smsg } ;
                        #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                    }  else {
                        $smsg = ("Couldn't derive the filename from {0}" -f $item) ; 
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                        else{ write-WARNING $smsg } ; 
                        throw $smsg ; 
                    } ; 
                } ; 
            }CATCH [System.Net.WebException]{
                $ErrTrapd=$Error[0] ;
                if($ErrTrapd.Exception -match '\(501\)'){
                    # on the 501 error - choco, which lacks header support - we can trap the redir for parsing:
                    $smsg = "Exception:'$($ErrTrapd.Exception)' returned" ; 
                    if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
                    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 

                    $smsg = "=>Remote server returned a 501 (not implemented error)" ; 
                    $smsg += "`n`n-->Re-Attempting:Obtain & parse redirection info for request..." ; 
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                    else{ write-host $smsg } ;

                    TRY{
                        if($Results = Invoke-WebRequest -Method Get -Uri $item -MaximumRedirection 0 -ErrorAction SilentlyContinue){
                            $lines = $results.Content.Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries) ; 
                            if($lines = $lines | ?{$_ -like '*href*'}){
                                if([uri]$RedirUrl = [regex]::match($lines,$rgxHtmlAnchor).groups[1].captures[0].value){
                                    #if($OutFilePath = Join-Path $Path -childpath [System.IO.Path]::GetFileName($RedirUrl)){
                                    if($OutFilePath = Join-Path $Path -childpath $RedirUrl.LocalPath.replace('/','')){
                                        $smsg = "Resolved redirect to a filename, for OutputPath:" ;
                                        $smsg += "`n$($OutFilePath)" ;  
                                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } 
                                        else{ write-host $smsg } ;
                                        #Levels:Error|Warn|Info|H1|H2|H3|H4|H5|Debug|Verbose|Prompt|Success
                                    } else { 
                                        $smsg += "Unable to Construct a workable `$OutputFilePath from returned data:" ; 
                                        $smsg += "`nPlease specify a full leaf file -Path specification and retry (even a dummy filename will work)" ; 
                                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                                        else{ write-WARNING $smsg } ; 
                                        throw $smsg ; 
                                        break ; 
                                    } ; 
                                } ; 
                            } else { 
                                $smsg += "Unable to locate a `$returned.Content line containing an '*href*', for further parsing. Aborting" ; 
                                $smsg += "`nPlease specify a full leaf file -Path specification and retry" ; 
                                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                                else{ write-WARNING $smsg } ; 
                                throw $smsg ; 
                                break ; 
                            } ; 

                        } else { 
                            $smsg += "Unable to obtain useful Redirect info to parse. Aborting" ; 
                            $smsg += "`nPlease specify a full leaf file -Path specification and retry" ; 
                            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                            else{ write-WARNING $smsg } ; 
                            throw $smsg ; 
                            break ; 
                        } ; 
                    } CATCH {
                        # or just do idiotproof: Write-Warning -Message $_.Exception.Message ;
                        $ErrTrapd=$Error[0] ;
                        $smsg = ("Couldn't get the file from {0}" -f $item) ; 
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                        else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                        $smsg = "$('*'*5)`nFailed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: `n$(($ErrTrapd|out-string).trim())`n$('-'*5)" ;
                        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                        else{ write-warning $smsg } ;
                    } ; 
                    <# 
                    $results
                    StatusCode        : 302
                    StatusDescription : Found
                    Content           : <html><head><title>Object moved</title></head><body>
                                        <h2>Object moved to <a href="https://packages.chocolatey.org/chocolatey.1.3.0.nupkg">here</a>.</h2>
                                        </body></html>
                    RawContent        : HTTP/1.1 302 Found
                                        Transfer-Encoding: chunked
                                        Connection: keep-alive
                                        X-AspNetMvc-Version: 3.0
                                        X-Frame-Options: deny
                                        CF-Cache-Status: DYNAMIC
                                        Strict-Transport-Security: max-age=12960000
                                        X-Conten...
                    Forms             : {}
                    Headers           : {[Transfer-Encoding, chunked], [Connection, keep-alive], [X-AspNetMvc-Version, 3.0], [X-Frame-Options, deny]...}
                    Images            : {}
                    InputFields       : {}
                    Links             : {@{innerHTML=here; innerText=here; outerHTML=<A href="https://packages.chocolatey.org/chocolatey.1.3.0.nupkg">here</A>;
                                        outerText=here; tagName=A; href=https://packages.chocolatey.org/chocolatey.1.3.0.nupkg}}
                    ParsedHtml        : mshtml.HTMLDocumentClass
                    RawContentLength  : 171
                    #>
                } elseif( ($ErrTrapd.Exception -match '\(429\)') -OR ($ErrTrapd.Exception -match 'Too\sMany\sRequests')){
                    <# [https://docs.chocolatey.org/en-us/troubleshooting#im-getting-a-429-too-many-requests-issue-when-attempting-to-use-the-community-package-repository](https://docs.chocolatey.org/en-us/troubleshooting#im-getting-a-429-too-many-requests-issue-when-attempting-to-use-the-community-package-repository)
                        his means your IP address has been flagged for too many requests. Please see Rate Limiting for details and actions.
                        Reference Errors:
                            Exception calling "DownloadFile" with "2" argument(s): The remote server returned an error: (429) Too Many Requests
                            The remote server returned an error: (429) Too Many Requests. Too Many Requests
                        [https://docs.chocolatey.org/en-us/community-repository/community-packages-disclaimer#rate-limiting](https://docs.chocolatey.org/en-us/community-repository/community-packages-disclaimer#rate-limiting)
                        Rate Limiting
                            NOTE
                            Purchasing licenses will not have any effect on rate limiting of the community package repository. Please read carefully below to understand why this was put in place and steps you can take to reduce issues if you run into it. HINT: It's not an attempt to get you to pay for commercial editions.
                            As a measure to increase site stability and prevent excessive use, the Chocolatey website uses rate limiting on requests for the community repository. Rate limiting was introduced in November 2018. Most folks typically won't hit rate limits unless they are automatically tagged for excessive use. If you do trigger the rate limit, you will see a (429) Too Many Requests. When attempting to install Chocolatey you will see the following:
                            If you go to a package page and attempt to use the download link in the left menu, you will see the following:
                            Error 1015 Ray ID ...xxx
                            You are being rate limited. 
                            The owner of this website (chocolatey.org) has banned you temporarily from accessing this website.
                        What To Do When You Are Rate Limited
                            NOTE
                            A rate limit will automatically expire after an hour, but if you hit the limit again, it will block for another hour.
                        If you have found that you have been rate limited, please see How To Avoid Excessive Use. Implementing best practices for organizational use will limit chances of being rate limited again in the future.
                            Individual users being rate limited should reach out as per the next section and let us know as we are constantly adjusting limits to find a happy medium and need to have as much data to work with as possible. In addition to providing the requested information, make sure to also mention you are "individual use" and provide details on what caused the rate limiting. We may ask you to provide logs for further inspection.
                            Organizational use will be asked to set up best practices for Chocolatey deployments.
                    #>
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
                    # fatal, server is going to continue throttling for quite a while: no point in using Continue
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
                $smsg = ("Couldn't get the file from {0}" -f $item) ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                $smsg = "$('*'*5)`nFailed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: `n$(($ErrTrapd|out-string).trim())`n$('-'*5)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                else{ write-warning $smsg } ;
                #$smsg = $ErrTrapd.Exception.Message ;
                #if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                #else{ write-warning $smsg } ;
                $smsg = "FULL ERROR TRAPPED (EXPLICIT CATCH BLOCK WOULD LOOK LIKE): } catch[$($ErrTrapd.Exception.GetType().FullName)]{" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level ERROR } #Error|Warn|Debug
                else{ write-host $smsg } ;
                Break #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
                throw $ErrTrapd ; 
            } ; 

            # you can also have iopath cut the trailing /name and use it as a name:
            #$filename = [System.IO.Path]::GetFileName($url) # returns 'chocolatey' from expl url
            #$OutFilePath = Join-Path $Path -ChildPath $filename ; 
            # it's 'descriptive' of the dl, but in the choco case, completely loses the rev spec from the proper filename.
            <# you can use Start-BitsTransfer, if server supports it choco doesn't:
            Import-Module BitsTransfer
            Start-BitsTransfer -source $url ; 
            Start-BitsTransfer : HTTP status 501: The server does not support the functionality required to fulfill the request.
            At line:1 char:1
            + Start-BitsTransfer -source $url
            + ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                + CategoryInfo          : InvalidOperation: (:) [Start-BitsTransfer], Exception
                + FullyQualifiedErrorId : StartBitsTransferCOMException,Microsoft.BackgroundIntelligentTransfer.Management.NewBitsTransferCommand
            #>

            TRY {
                Invoke-WebRequest -Uri $item -OutFile $OutFilePath ; 
            } CATCH {
                # or just do idiotproof: Write-Warning -Message $_.Exception.Message ;
                $ErrTrapd=$Error[0] ;
                $smsg = ("Got the filename, but couldn't download the file from {0} to {1}" -f $item, $OutFilePath) ; 
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} 
                else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                $smsg = "$('*'*5)`nFailed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: `n$(($ErrTrapd|out-string).trim())`n$('-'*5)" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN } #Error|Warn|Debug
                else{ write-warning $smsg } ;
            } ; 
            # if the throttle spec is pre-defined (profile level), pause to avoid throttling
            if($ThrottleDelay){
                start-sleep -Milliseconds $ThrottleDelay ; 
            } ; 
        } ;   # loop-E
    } ;  # if-PROC
} ; 
#*------^ END Function save-WebDownload ^------
