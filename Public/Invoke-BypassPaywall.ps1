# Invoke-BypassPaywall.ps1

#*------v Function Invoke-BypassPaywall v------
function Invoke-BypassPaywall{
    <#
    .SYNOPSIS
    Invoke-BypassPaywall.ps1 - open a webpage locally, bypassing a paywall
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2022-07-18
    FileName    : 
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/verb-network
    Tags        : Powershell
    AddedCredit : cybercastor
    AddedWebsite:	https://www.reddit.com/user/cybercastor
    AddedTwitter:	
    REVISIONS
    * 2:25 PM 7/20/2022 added/expanded CBH, spliced in his later posted new-RandomFilename dependant function.
    * 7/18/22 cybercastor posted rev
    .DESCRIPTION
    Invoke-BypassPaywall.ps1 - open a webpage locally, bypassing a paywall

    [Invoke-BypassPaywall](https://www.reddit.com/r/PowerShell/comments/w1ypp2/invokebypasspaywall_open_a_webpage_locally/)
    Invoke-BypassPaywall : open a webpage locally, bypassing a paywall
    Script Sharing
    Invoke-BypassPaywall : open a webpage locally, bypassing a paywall
    EDIT
    Update: for those who asked about the cmdlet New-RandomFilename . It's indeed a function I made in one of my module. sorry about that.
    Core module Miscellaneous.ps1
    .EXAMPLE
    PS> Invoke-BypassPaywall 'https://www.washingtonpost.com/world/2022/07/15/eu-russia-sanctions-ukraine/'
    washingtonpost.com demo
    .EXAMPLE
    PS> .Invoke-BypassPaywall 'https://www.theatlantic.com/ideas/archive/2022/07/russian-invasion-ukraine-democracy-changes/661451'
    theatlantic.com demo
    .LINK
    https://github.com/tostka/verb-XXX
    https://www.reddit.com/r/PowerShell/comments/w1ypp2/invokebypasspaywall_open_a_webpage_locally/
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="url", Position=0)]
        [string]$Url
    )
    BEGIN{
        if(-not (get-command New-RandomFilename)){
            #*------v Function New-RandomFilename v------
            function New-RandomFilename{
                <#
                SYNOPSIS
                New-RandomFilename.ps1 - Create a RandomFilename
                .NOTES
                Version     : 1.0.0
                Author      : Todd Kadrie
                Website     :	http://www.toddomation.com
                Twitter     :	@tostka / http://twitter.com/tostka
                CreatedDate : 2022-07-18
                FileName    : 
                License     : (none asserted)
                Copyright   : (none asserted)
                Github      : https://github.com/tostka/verb-io
                Tags        : Powershell
                AddedCredit : cybercastor
                AddedWebsite:	https://www.reddit.com/user/cybercastor
                AddedTwitter:	
                REVISIONS
                * 2:25 PM 7/20/2022 added/expanded CBH, spliced in his later posted new-RandomFilename dependant function ; subst ValidateRange for $maxlen tests.
                * 7/18/22 cybercastor posted rev
                .DESCRIPTION
                New-RandomFilename.ps1 - Create a new random filename

                [Invoke-BypassPaywall](https://www.reddit.com/r/PowerShell/comments/w1ypp2/invokebypasspaywall_open_a_webpage_locally/)
    
                .PARAMETER Path
                Host directory for new file (defaults `$ENV:Temp)
                .PARAMETER Extension
                Extension for new file (defaults 'tmp')
                .PARAMETER MaxLen
                Length of new file name (defaults 6, 4-36 range)
                .PARAMETER CreateFile
                Switch to create new empty file matching the specification.
                .PARAMETER CreateDirectory
                Switch to create a new hosting directory below `$Path,  with a random (guid) name (which will be 36chars long).
                .EXAMPLE
                PS> $fn = New-RandomFilename -Extension 'html'
                Create a new randomfilename with html ext
                .EXAMPLE
                PS> .Invoke-BypassPaywall 'https://www.theatlantic.com/ideas/archive/2022/07/russian-invasion-ukraine-democracy-changes/661451'
                theatlantic.com demo
                .LINK
                https://github.com/tostka/verb-IO
                https://www.reddit.com/r/PowerShell/comments/w1ypp2/invokebypasspaywall_open_a_webpage_locally/               
                #>
                [CmdletBinding(SupportsShouldProcess)]
                param(
                    [Parameter(Mandatory=$false)]
                    [string]$Path = "$ENV:Temp",
                    [Parameter(Mandatory=$false)]
                    [string]$Extension = 'tmp',
                    [Parameter(Mandatory=$false)]
                    [ValidateRange(4,36)]
                    [int]$MaxLen = 6,
                    [Parameter(Mandatory=$false)]
                    [switch]$CreateFile,
                    [Parameter(Mandatory=$false)]
                    [switch]$CreateDirectory
                )    
                try{
                    #if($MaxLen -lt 4){throw "MaxLen must be between 4 and 36"}
                    #if($MaxLen -gt 36){throw "MaxLen must be between 4 and 36"}
                    [string]$filepath = $Null
                    [string]$rname = (New-Guid).Guid
                    Write-Verbose "Generated Guid $rname"
                    [int]$rval = Get-Random -Minimum 0 -Maximum 9
                    Write-Verbose "Generated rval $rval"
                    [string]$rname = $rname.replace('-',"$rval")
                    Write-Verbose "replace rval $rname"
                    [string]$rname = $rname.SubString(0,$MaxLen) + '.' + $Extension
                    Write-Verbose "Generated file name $rname"
                    if($CreateDirectory -eq $true){
                        [string]$rdirname = (New-Guid).Guid
                        $newdir = Join-Path "$Path" $rdirname
                        Write-Verbose "CreateDirectory option: creating dir: $newdir"
                        $Null = New-Item -Path $newdir -ItemType "Directory" -Force -ErrorAction Ignore
                        $filepath = Join-Path "$newdir" "$rname"
                    }
                    $filepath = Join-Path "$Path" $rname
                    Write-Verbose "Generated filename: $filepath"

                    if($CreateFile -eq $true){
                        Write-Verbose "CreateFile option: creating file: $filepath"
                        $Null = New-Item -Path $filepath -ItemType "File" -Force -ErrorAction Ignore 
                    }
                    return $filepath
                
                }catch{
                    Show-ExceptionDetails $_ -ShowStack
                }
            }
            #*------^ END Function New-RandomFilename ^------
        } ; 
    } ; 
    PROCESS{
        $fn = New-RandomFilename -Extension 'html'
      
        Write-Host -n -f DarkRed "[BypassPaywall] " ; Write-Host -f DarkYellow "Invoke-WebRequest -Uri `"$Url`""

        $Content = Invoke-WebRequest -Uri "$Url"
        $sc = $Content.StatusCode    
        if($sc -eq 200){
            $cnt = $Content.Content
            Write-Host -n -f DarkRed "[BypassPaywall] " ; Write-Host -f DarkGreen "StatusCode $sc OK"
            Set-Content -Path "$fn" -Value "$cnt"
            Write-Host -n -f DarkRed "[BypassPaywall] " ; Write-Host -f DarkGreen "start-process $fn"
            start-process "$fn"
        }else{
            Write-Host -n -f DarkRed "[BypassPaywall] " ; Write-Host -f DarkYellow "ERROR StatusCode $sc"
        }
    } ; 
}; 
#*------^ END Function Invoke-BypassPaywall ^------
