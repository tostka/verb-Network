# test-isComputerNameNetBios_func.ps1

Function test-isComputerNameNetBios{
    <#
    .SYNOPSIS
    test-isComputerNameNetBios.ps1 - Validate that passed string is a valid Netbios Computer name specification (regex test)
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2024-
    FileName    : test-isComputerNameNetBios.ps1
    License     : MIT License
    Copyright   : (c) 2024 Todd Kadrie
    Github      : https://github.com/tostka/verb-XXX
    Tags        : Powershell
    AddedCredit : Luc Fullenwarth
    AddedWebsite: https://gravatar.com/fullenw1
    AddedTwitter: twitter.com/LFullenwarth
    REVISIONS
    * 2:03 PM 6/6/2024 rounded out param validation sample to full function
    * 8/5/20 LF's posted vers (article)
    .DESCRIPTION
    test-isComputerNameNetBios - Validate that passed string is a valid Netbios Computer name specification (regex test)
    Doesn't confirm existing machine, just that the string complies with NB name restrictions
    .PARAMETER  ComputerName
    ComputerName string to be validated[-ComputerName SomeBox]
    .INPUTS
    System.String Accepts piped input
    .OUTPUTS
    System.Boolean
    .EXAMPLE
    PS> test-isComputerNameNetBios -ComputerName $env:computername
    Demo simple test
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://bitbucket.org/tostka/powershell/
    .LINK
    https://itluke.online/2020/08/05/validating-computer-names-with-powershell/
    #>    
    #Requires -Modules ActiveDirectory
    PARAM(
        [Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$true,HelpMessage="ComputerName string to be validated[-ComputerName SomeBox]")]
            [ValidateLength(1, 15)]
            [ValidateScript({$PSItem -replace '\\|/|:|\*|\?|"||\||\.' -eq $PSItem})]
            [ValidateNotNullOrEmpty()]
            [string]$ComputerName
    )
    write-output $true ; 
} ; 

