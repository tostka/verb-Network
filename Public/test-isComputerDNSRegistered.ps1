# test-isComputerDNSRegistered_func.ps1
#*------v Function test-isComputerDNSRegistered v------
Function test-isComputerDNSRegistered{
    <#
    .SYNOPSIS
    test-isComputerDNSRegistered.ps1 - Validate that passed string is a DNS Registered Computer
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2024-
    FileName    : test-isComputerDNSRegistered.ps1
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
    test-isComputerDNSRegistered.ps1 - Validate that passed string is a DNS Registered Computer
    
    .PARAMETER  ComputerName
    ComputerName string to be validated[-ComputerName SomeBox]
    .INPUTS
    System.String Accepts piped input
    .OUTPUTS
    System.Boolean
    .EXAMPLE
    PS> test-isComputerDNSRegistered -ComputerName $env:computername
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
            [ValidateScript({Resolve-DnsName -Name $PSItem})]
            [ValidateNotNullOrEmpty()]
            [string]$ComputerName
    )
    write-output $true ; 
} ; 
#*------^ END Function test-isComputerDNSRegistered ^------
