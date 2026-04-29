# test-RDPFileSignatureTDO.ps1

#region TEST_RDPFILESIGNATURETDO ; #*------v test-RDPFileSignatureTDO v------
function test-RDPFileSignatureTDO {
    <#
    .SYNOPSIS
    test-RDPFileSignatureTDO - Superfically test (check for signature tags in file), Digitally signed status on rdp TermServ connection files
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2026-04-29
    FileName    : set-RDPFileSignatureTDO.ps1
    License     : MIT License
    Copyright   : (c) 2026 Todd Kadrie
    Github      : https://github.com/tostka/verb-XXX
    Tags        : Powershell
    AddedCredit : REFERENCE
    AddedWebsite: URL
    AddedTwitter: URL
    * 10:07 AM 4/29/2026 fixed bvorked help parsing: removed leading periods from all RDP file ext refs (confused parser on dotted help keywords) ; 
    * 12:59 PM 4/28/2026 init
    .DESCRIPTION
    test-RDPFileSignatureTDO - Superfically test (check for signature tags in file), Digitally signed status on rdp TermServ connection files

    Only mstsc.exe can currently validate a signed file (by loading and displaying the file without prompts). 
    
    All this function does is check for an rdpsign.exe applied signature & signscope tag in the file. 
    Verbose output will return the matched lines in the rdp file

    .PARAMETER Path
    rdp File paths[-path c:\pathto\file.rdp]
    .INPUTS
    Accepts piped input Path 
    .OUTPUTS
    Returns string path to properly signed rdp files (and $false for unsigned files)
    .EXAMPLE
    PS> $results = test-RDPFileSignatureTDO -path 'C:\Users\aaaaaAAA\Desktop\rdp-faves\AAAAAAAAAAA-AAA-Ex16-Mbx1-1024x768-SID.RDP' ;
    PS> $results ; 

        C:\Users\aaaaaAAA\Desktop\rdp-faves\AAAAAAAAAAA-AAA-Ex16-Mbx1-1024x768-SID.RDP: confirmed '^(signature|signscope) applied 

    Test and report results of test
    .LINK
    https://github.com/tostka/verb-io
    #>
    [CmdletBinding()]
    [Alias('test-RdpFile','test-RdpFileTDO')]
    PARAM(
        [Parameter(Mandatory = $False,Position = 0,ValueFromPipeline = $True, HelpMessage = '.Rdp File paths[-path c:\pathto\file.rdp]')]
            [Alias('PsPath')]
            [ValidateScript({Test-Path $_})]
            [ValidateScript({ if([IO.Path]::GetExtension($_) -ne ".rdp") { throw "Path must point to an .rdp file" } $true })]
            [system.io.fileinfo[]]$Path
    ) ; 
    BEGIN {
        ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;

        if ($PSCmdlet.MyInvocation.ExpectingInput) {
            write-verbose "Data received from pipeline input: '$($InputObject)'" ; 
        } else {
            #write-verbose "Data received from parameter input: '$($InputObject)'" ; 
            write-verbose "(non-pipeline - param - input)" ; 
        } ; 
    } ;  # BEGIN-E
    PROCESS {
        $Error.Clear() ; 
        foreach ($item in $Path){
            TRY{
                Write-Verbose "Checking RDP file: $($item.fullname)" ; 
                if($sigs = gc $item.fullname | Where-Object { $_ -match "^signature" -or $_ -match "^signscope" }){
                    write-host "$($item.fullname): confirmed '^(signature|signscope) applied" ; 
                    write-verbose "`nSignatures`n$(($sigs|out-string).trim())" ; 
                    $item.fullname | write-output 
                }else{
                    $smsg = "$($item.fullname): MISSING '^(signature|signscope)!" ; 
                    write-host $smsg ; 
                    $false | write-output  ; 
                }
            } CATCH {$ErrTrapd=$Error[0] ;
                write-host -foregroundcolor gray "TargetCatch:} CATCH [$($ErrTrapd.Exception.GetType().FullName)] {"  ;
                $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;
                write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" ;
            } ;
        } ;  # loop-E
    }  # if-E PROC
    END{} ; 
} ; 
#endregion TEST_RDPFILESIGNATURETDO ; #*------^ END test-RDPFileSignatureTDO ^------