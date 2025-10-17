# Test-LocalCredentialTDO.ps1


#region TEST_LOCALCREDENTIALTDO ; #*------v Test-LocalCredentialTDO v------
function Test-LocalCredentialTDO {
        <#
        .SYNOPSIS
        Test-LocalCredentialTDO - tests provided UserName & ComputerName combo against local machine accounts
        .NOTES
        Version     : 0.0.
        Author      : Todd Kadrie
        Website     : http://www.toddomation.com
        Twitter     : @tostka / http://twitter.com/tostka
        CreatedDate : 20250711-0423PM
        FileName    : Test-LocalCredential.ps1
        License     : MIT License
        Copyright   : (c) 2025 Todd Kadrie
        Github      : https://github.com/tostka/verb-ex2010
        Tags        : Powershell,Exchange,ExchangeServer,Install,Patch,Maintenance
        AddedCredit : Microsoft
        AddedWebsite: https://gallery.technet.microsoft.com/scriptcenter/Verify-the-Local-User-1e365545
        AddedTwitter: URL
        REVISIONS
        * 1:04 PM 9/17/2025 remove write-my*() calls (write-log has native defer support now)
        * 2:27 PM 8/8/2025 ren Test-LocalCredential821 -> Test-LocalCredentialTDO (alias orig name)
        * 10:45 AM 8/6/2025 added write-myOutput|Warning|Verbose support (for xopBuildLibrary/install-Exchange15.ps1 compat)
        * 9:03 AM 7/18/2025 lifted copy of sub from install-Ex15; works
        .DESCRIPTION
        Test-LocalCredentialTDO - tests provided UserName & ComputerName combo against local machine accounts

        #From https://gallery.technet.microsoft.com/scriptcenter/Verify-the-Local-User-1e365545
        .PARAMETER UserName
        Account to be tested
        .PARAMETER ComputerName
        Computer name to test against (defaults to COMPUTERNAME environment variable)
        .PARAMETER Password
        Account Password (plaintext)
        .INPUTS
        None, no piped input.
        .OUTPUTS
        System.Object summary of Exchange server descriptors, and service statuses.
        .EXAMPLE
        PS> $tcred = get-credential ; 
        PS> if(Test-LocalCredentialTDO -UserName $tcred.UserName -Password $tcred.GetNetworkCredential().Password){
        PS>     write-host -foregroundcolor green "Validated functional credentials" ; 
        PS> } ; 
        .LINK
        https://github.org/tostka/verb-ex2010/
        #>
        [CmdletBinding()]
        [alias('Test-LocalCredential821','Test-LocalCredentials')]
        Param( 
            [Parameter(HelpMessage = "Account to be tested")]
                [Alias('Account','logon')]
                [string]$UserName,
            [Parameter(HelpMessage = "Computer name to test against (defaults to COMPUTERNAME environment variable)")]
                [string]$ComputerName = $env:COMPUTERNAME,
            [Parameter(HelpMessage = "Account password to be used for install (plaintext)")]
                [string]$Password
        )
        if (!($UserName) -or !($Password)) {
            $smsg = "Test-LocalCredential: Please specify both user name and password"
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
        } else {
            TRY {   # Wrap in a try-catch in case we try to add this type twice.
                Add-Type -AssemblyName System.DirectoryServices.AccountManagement
            } CATCH {} ; 
            $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('machine',$ComputerName)
            $DS.ValidateCredentials($UserName, $Password)
        }
    }
#endregion TEST_LOCALCREDENTIALTDO ; #*------^ END Test-LocalCredentialTDO ^------

