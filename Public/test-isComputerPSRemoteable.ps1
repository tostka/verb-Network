# test-isComputerSMBCapable_func.ps1
#*------v Function test-isComputerSMBCapable v------
Function test-isComputerSMBCapable{
    <#
    .SYNOPSIS
    test-isComputerSMBCapable.ps1 - Validate specified computer is SMB mappable (passes Test-NetConnection -ComputerName  -CommonTCPPort 'SMB' test)
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2024-
    FileName    : test-isComputerSMBCapable.ps1
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
    test-isComputerSMBCapable.ps1 - Validate specified computer is SMB mappable (passes Test-NetConnection -ComputerName  -CommonTCPPort 'SMB' test)
    
    .PARAMETER  ComputerName
    ComputerName string to be validated[-ComputerName SomeBox]
    .INPUTS
    System.String Accepts piped input
    .OUTPUTS
    System.Boolean
    .EXAMPLE
    PS> test-isComputerSMBCapable -ComputerName $env:computername
    Demo simple test
    .EXAMPLE
    PS>  TRY{test-isComputerSMBCapable -ComputerName unreachablebox -ea 0 ; write-host 'Remotable' }CATCH{write-warning 'Not remotable'} ; 
    Wrap the test in try catch (as this doesn't return `$false; it throws a parameter validation error)
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
            [ValidateScript({(Test-NetConnection -ComputerName $PSItem -CommonTCPPort 'SMB').TcpTestSucceeded})]
            [ValidateNotNullOrEmpty()]
            [string]$ComputerName
    )
    write-output $true ; 
} ; 
#*------^ END Function test-isComputerSMBCapable ^------
