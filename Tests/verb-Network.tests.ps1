# verb-Network.Tests.ps1

BeforeAll {
    <#
    .SYNOPSIS
    verb-Network.ps1 - verb-Network Pester Tests
    .NOTES
    Version     : 1.0.1
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-
    FileName    : verb-Network.Tests.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell,Pester,Testing,Development
    REVISIONS
    * 9:23 AM 4/1/2020 updated to include workaround for Test-ModuleManifest failure to reload updated psd1s (uses a force loaded copy of current file), now storing the output of the import-module -force passthrugh ; also added Pester tests for: Author, CompanyName, LicenseURI, PowerShellVersion,CopyRight, !RequiredModule,!ExportedFormatFiles,Prefix,comparre missing Exported functions (to determine which unexported), more detailed checking of Exports, and check CBH for Synopsis,Description & 1+ Example (several are remmed by default), restored guid template text
    * 7:49 AM 3/4/2020 version debugged to work with Psv5.1/ISE/VSC
    .DESCRIPTION
    verb-Network.ps1 - verb-Network Pester Tests
    Note, two different PSSA settings files are included, edit the $scriptStylePath to suit (and/or edit the files to suit)
    .EXAMPLE
    cd c:\sc\verb-Network\ ;
    .\verb-Network.Tests.ps1
    Run in default config
    .EXAMPLE
    cd c:\sc\verb-Network\ ;
    .\verb-Network.Tests.ps1 -verbose
    Run with Verbose outputs
    .LINK
    https://github.com/tostka
    #>


    [CmdletBinding()]
    PARAM() ;
    $Verbose = ($VerbosePreference -eq 'Continue') ;

    <#
    # patch in ISE support
    if ($psISE){
        $ScriptDir = Split-Path -Path $psISE.CurrentFile.FullPath ;
        $ScriptBaseName = split-path -leaf $psise.currentfile.fullpath ;
        $ScriptNameNoExt = [system.io.path]::GetFilenameWithoutExtension($psise.currentfile.fullpath) ;
        $PSScriptRoot = $ScriptDir ;
        if($PSScriptRoot -ne $ScriptDir){ write-warning "UNABLE TO UPDATE BLANK `$PSScriptRoot TO CURRENT `$ScriptDir!"} ;
        $PSCommandPath = $psise.currentfile.fullpath ;
        if($PSCommandPath -ne $psise.currentfile.fullpath){ write-warning "UNABLE TO UPDATE BLANK `$PSCommandPath TO CURRENT `$psise.currentfile.fullpath!"} ;
    }
    #>
    if ($PSScriptRoot -eq "") {
        if ($psISE){
            $ScriptName = $psISE.CurrentFile.FullPath ; 
        } elseif ($context = $psEditor.GetEditorContext()) {
            $ScriptName = $context.CurrentFile.Path ;  
        } elseif($host.version.major -lt 3){
            $ScriptName = $MyInvocation.MyCommand.Path ; 
            $PSScriptRoot = Split-Path $ScriptName -Parent ;
            $PSCommandPath = $ScriptName ;
        } else {
            if($MyInvocation.MyCommand.Path) {
                $ScriptName = $MyInvocation.MyCommand.Path ; 
                $PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent ;
            } else {
                throw "UNABLE TO POPULATE SCRIPT PATH, EVEN `$MyInvocation IS BLANK!" ;
            } ;
        }; 
        $ScriptDir = Split-Path -Parent $ScriptName ; 
        $ScriptBaseName = split-path -leaf $ScriptName ;
        $ScriptNameNoExt = [system.io.path]::GetFilenameWithoutExtension($ScriptName) ;
    } else {
        $ScriptDir = $PSScriptRoot ;
        if($PSCommandPath){
            $ScriptName = $PSCommandPath ; 
        } else {
            $ScriptName = $myInvocation.ScriptName
            $PSCommandPath = $ScriptName ;
        } ;
        $ScriptBaseName = (Split-Path -Leaf ((&{$myInvocation}).ScriptName))  ;
        $ScriptNameNoExt = [system.io.path]::GetFilenameWithoutExtension($MyInvocation.InvocationName) ;
    } ; 


    $ModuleName = Split-Path (Resolve-Path "$ScriptDir\..\" ) -Leaf ; 
    $ModuleManifest = (Resolve-Path "$ScriptDir\..\$ModuleName\$ModuleName.psd1").path ; 
    # work around 'never-reloads' bug in Test-ModuleManifest, by force-loading a fresh hash of *curr* manifest, for use in all but *initial* TMM tests
    $Script:ManifestHash = Invoke-Expression (Get-Content $ModuleManifest -Raw)
    $ProjectRoot = (Resolve-path "$ScriptDir\..\").path ; 
    if(!(test-path $ProjectRoot\README.md)){
        throw "Unable to resolve ProjectRoot!" ;
    }
    $moduleComponents = Get-ChildItem $ProjectRoot  -Include *.psd1, *.psm1, *.ps1 -Exclude *.tests.ps1,PPoShScriptingStyle.psd1 -Recurse
    $projectScripts = $moduleComponents | ?{$_.extension -eq '.ps1'} | sort name ;
    $projectModules = $moduleComponents | ?{$_.extension -eq '.psm1'} | sort name ;
    $projectDatafiles = $moduleComponents | ?{$_.extension -eq '.psd1'} | sort name ;
    # enable to suit pref
    #$scriptStylePath = (Resolve-Path "$ProjectRoot\Tests\PPoShScriptingStyle.psd1").path ;
    $scriptStylePath = (Resolve-Path "$ProjectRoot\Tests\ToddomationScriptingStyle-medium.psd1").path ;

    $smsg=@"

        ==Current Config:
        `$ModuleName:$ModuleName
        `$ProjectRoot :$ProjectRoot
        `$ModuleManifest:$ModuleManifest
        `$scriptStylePath:$scriptStylePath

        `$moduleComponents:
        $(($moduleComponents.fullname|ft -a | out-string).trim())" ;

        `$projectScripts:
        $(($projectScripts.fullname|ft -a | out-string).trim())" ;

        `$projectModules:
        $(($projectModules.fullname|ft -a | out-string).trim())" ;

        `$projectDatafiles:
        $(($projectDatafiles.fullname|ft -a | out-string).trim())" ;

"@ ;
    write-verbose -verbose:$verbose $smsg ;

    # Force Import the module and store the information about the module
    Get-Module $ModuleName | Remove-Module
    $ModuleInformation = Import-Module $ModuleManifest -Force -PassThru ; 
}

Describe 'Module Information' -Tags 'Command'{
    Context 'Manifest Testing' {
        It 'Valid Module Manifest' {
            {
                $Script:Manifest = Test-ModuleManifest -Path $ModuleManifest -ErrorAction Stop -WarningAction SilentlyContinue
            } | Should -Not -Throw
        }
        # Name & Version are not values in psd1 - they're *asserted* by TMM, don't use the hash for these tests
        It 'Valid Manifest Name' {
            $Script:Manifest.Name | Should -Be $ModuleName
        }
        It 'Generic Version Check' {
            $Script:Manifest.Version -as [Version] | Should -Not -BeNullOrEmpty
        }
        <#
        It 'Valid PowerShellVersion value' {
            $Script:ManifestHash.PowerShellVersion | Should Not BeNullOrEmpty
        }
        #>
        It "Valid Author"{
            $Script:ManifestHash.Author | Should -not -BeNullOrEmpty
        }
        It "Valid Company Name"{
            $Script:ManifestHash.CompanyName | Should -not -BeNullOrEmpty
        }
        It "Valid License"{
            $ModuleInformation.LicenseURI | Should -not -BeNullOrEmpty
        }
        <#
        It "has a valid copyright" {
          $Script:ManifestHash.CopyRight | Should Not BeNullOrEmpty
        }
        #>
        It 'Valid Manifest Description' {
            $Script:ManifestHash.Description | Should -Not -BeNullOrEmpty
        }
        <# via New-ModuleManifest -Tags 
        It "Valid Tags"{
            @($Script:ManifestHash.PrivateData.PSData.Tags).Count -gt 0 | Should Be $true
        }
        #>
        It 'Valid Manifest Root Module' {
            $Script:ManifestHash.RootModule | Should -Be "$ModuleName.psm1"
        }
        It 'Valid Manifest GUID' {
            $Script:ManifestHash.Guid | Should -Be "e4ae475a-9185-49d3-a3b5-50c06a4f323a"
        }
        <#
        It 'No Format File' {
            $Script:ManifestHash.ExportedFormatFiles | Should BeNullOrEmpty
        }
        #>
        # added from https://powershell.getchell.org/2016/05/16/generic-pester-tests/
        It 'Required Modules' {
            $Script:ManifestHash.RequiredModules | Should -BeNullOrEmpty
        }
        
        <# extra mani tests:
        # prefix is the prop if fed from TMM, DefaultPrefix is the raw hash key, both are defaulted commandprefixes
        It "has a valid prefix" {
          $Script:ManifestHash.DefaultCommandPrefix | Should Not BeNullOrEmpty
        }
        #>
    }

    Context 'Exported Functions' {
        It 'Proper Number of Functions Exported' {
            $Exported = Get-Command -Module $ModuleName ;
            $ExportedCount = $Exported | Measure-Object | Select-Object -ExpandProperty Count

            $Files = Get-ChildItem -Path "$ProjectRoot\Public" -Filter *.ps1 -Recurse
            $FileCount = $Files | Measure-Object | Select-Object -ExpandProperty Count

            $smsg=@"

    ==Exported Details:
    `$ExportedCount:$ExportedCount
    $($Exported|out-string)
    `$FileCount:$FileCount
    $($Files|out-string)


"@ ;
            write-verbose -verbose:$verbose $smsg ;
            

            $ExportedCount | Should -be $FileCount
        }
        
        # another approach
        It "Exports All Public Functions" {
            $ExFunctions = $Script:ManifestHash.FunctionsToExport
            $FunctionFiles = Get-ChildItem -Path "$ProjectRoot\Public" -Filter *.ps1 -Recurse |
                Select-Object -ExpandProperty BaseName
            $FunctionNames = $FunctionFiles
            foreach ($FunctionName in $FunctionNames){
                $ExFunctions -contains $FunctionName | Should -Be $true
            }
        }
        # https://lazywinadmin.com/2016/05/using-pester-to-test-your-manifest-file.html
        It "Compare Missing Functions"{
            if (-not ($ExportedCount -eq $FileCount))
            {
                $Compare = Compare-Object -ReferenceObject $ExFunctions -DifferenceObject $FunctionFiles
                $Compare.inputobject -join ',' | Should -BeNullOrEmpty
            }
        }
        
    }


}

<# Help Tests, functions should have Synopsis,Description & an Example
https://powershell.getchell.org/2016/05/16/generic-pester-tests/
#>
Get-Command -Module $ModuleName | ForEach-Object {
    Describe 'Help' -Tags 'Help' {
        Context "Function - $_" { 
            It 'Synopsis' {
                Get-Help $_ | Select-Object -ExpandProperty synopsis | should -not -benullorempty
            }
            It 'Description' {
                Get-Help $_ | Select-Object -ExpandProperty Description | should -not -benullorempty
            }
            It 'Examples' {
                $Examples = Get-Help $_ | Select-Object -ExpandProperty Examples | Measure-Object 
                $Examples.Count -gt 0 | Should -be $true
            }
        }
    }
}

Describe 'General - Testing all scripts and modules against the Script Analyzer Rules' {
    Context "Checking files to test exist and Invoke-ScriptAnalyzer cmdLet is available" {
        It "Checking files exist to test." {
            $moduleComponents.count | Should -Not -Be 0
        }
        It "Checking Invoke-ScriptAnalyzer exists." {
            { Get-Command Invoke-ScriptAnalyzer -ErrorAction Stop } | Should -Not -Throw
        }
    }
} 

#region PSSA Testing
<# Calling PS Script analyzer with Pester : PowerShell - https://www.reddit.com/r/PowerShell/comments/6tmprp/calling_ps_script_analyzer_with_pester/
Shepherd_Ra, 2018
#>
<#
Describe -Tags 'PSSA' -Name 'Testing against PSScriptAnalyzer rules' {
    Context 'PSSA Standard Rules' {
        $ScriptAnalyzerSettings = Get-Content -Path $scriptStylePath | Out-String | Invoke-Expression
        #$AnalyzerIssues = Invoke-ScriptAnalyzer -Path "$PSScriptRoot\..\MyScript.ps1" -Settings "$PSScriptRoot\..\ScriptAnalyzerSettings.psd1"
        $AnalyzerIssues = Invoke-ScriptAnalyzer -Path $ProjectRoot -Recurse -Settings $scriptStylePath
        $ScriptAnalyzerRuleNames = Get-ScriptAnalyzerRule | Select-Object -ExpandProperty RuleName
        forEach ($Rule in $ScriptAnalyzerRuleNames) {
            $Skip = @{Skip=$False}
            if ($ScriptAnalyzerSettings.ExcludeRules -notcontains $Rule) {
                # We still want it in the tests, but since it doesn't actually get tested we will skip
                $Skip = @{Skip = $True}
            }
            It "Should pass $Rule" @Skip {
                $Failures = $AnalyzerIssues | Where-Object -Property RuleName -EQ -Value $rule
                ($Failures | Measure-Object).Count | Should Be 0
            }
        }
    }
}
#>
<# above extended with updated rule skip logic - shows *all* rules, marks skips
#>
Describe -Tags 'PSSA' -Name 'Testing against PSScriptAnalyzer rules' {
    Context 'PSSA Standard Rules' {
        #$ScriptAnalyzerSettings = Get-Content -Path $scriptStylePath | Out-String | Invoke-Expression
        # avoiding use invoke-expr (which is a pssa violation), leveraging Import-PowerShellDataFile instead
        $ScriptAnalyzerSettings = Import-PowerShellDataFile -path $scriptStylePath 
        #$AnalyzerIssues = Invoke-ScriptAnalyzer -Path "$PSScriptRoot\..\MyScript.ps1" -Settings "$PSScriptRoot\..\ScriptAnalyzerSettings.psd1"
        $AnalyzerIssues = Invoke-ScriptAnalyzer -Path $ProjectRoot -Recurse -Settings $scriptStylePath
        # $moduleComponents
        #$AnalyzerIssues = Invoke-ScriptAnalyzer -Path $moduleComponents -Settings $scriptStylePath
        $ScriptAnalyzerRuleNames = Get-ScriptAnalyzerRule | Select-Object -ExpandProperty RuleName
        forEach ($Rule in $ScriptAnalyzerRuleNames) {
            $Skip = $false ; 
            if($ScriptAnalyzerSettings.IncludeRules -contains $Rule){$skip=$false } ; 
            if($ScriptAnalyzerSettings.ExcludeRules -contains $Rule){$Skip = $true } ;
            <#$Skip = $ScriptAnalyzerSettings.IncludeRules -notcontains $Rule
            $Skip = $ScriptAnalyzerSettings.ExcludeRules -contains $Rule
            #>
            It "Should pass $Rule" -Skip:$Skip {
                $Failures = $AnalyzerIssues | Where-Object -Property RuleName -EQ -Value $rule
                ($Failures | Measure-Object).Count | Should -Be 0
            }
        }
    }
}

<#
Describe 'Testing against ScriptAnalyzer rules' {
    Context "Rules:$scriptStylePath" {
        $report = Invoke-ScriptAnalyzer -Path $ProjectRoot -Recurse -Settings $scriptStylePath
        #$scriptAnalyzerRules = Get-ScriptAnalyzerRule
        $rulesHash = Import-PowerShellDataFile -path $scriptStylePath ;
        #forEach ($rule in $scriptAnalyzerRules) {
        forEach ($rule in $ruleshash.IncludeRules) {        
            It "Should pass $rule" {
                If ($report.RuleName -contains $rule) {
                    $report |
                    Where RuleName -EQ $rule -outvariable failures |
                    Out-Default
                    $failures.Count | Should Be 0
                }
            }
        }
    }
}
#>

<#
Describe 'General - Testing all scripts and modules against the Script Analyzer Rules' {
    Context "Checking files to test exist and Invoke-ScriptAnalyzer cmdLet is available" {
        It "Checking files exist to test." {
            $moduleComponents.count | Should Not Be 0
        }
        It "Checking Invoke-ScriptAnalyzer exists." {
            { Get-Command Invoke-ScriptAnalyzer -ErrorAction Stop } | Should Not Throw
        }
    }

    Context "Checking component files against settings:$scriptStylePath" {
        #write-verbose -verbose:$verbose "Using Settings:$($scriptStylePath)"
        

        $Report = Invoke-ScriptAnalyzer -Path $ProjectRoot -Recurse -Settings $scriptStylePath ;

        $Report.count | Should Be 0

        if ($verbose) {
            write-verbose -verbose:$verbose "`n`$Report | group severity" 
            "$(($report | group severity | sort count | ft -auto count,name|out-string).trim())`n" ;

            write-verbose -verbose:$verbose "`n`$Report | group rulename"
            "$(($report | group rulename | sort count | ft -auto count,name|out-string).trim())`n" ;

            write-verbose -verbose:$verbose "`n`$Report | group scriptname"
            "$(($report | group scriptpath | sort -desc count | ft -auto count,name|out-string).trim())`n" ;

            write-verbose -verbose:$verbose "`n Detailed per script report:" ;
            foreach ($scriptrpt in $scriptreported ) {
                $sBnrS = "`n#*------v $($scriptrpt): v------" ;
                "$($sBnrS)" ;
                "$(($report |?{$_.scriptname -eq $scriptrpt} | sort rulename,message | ft -auto Severity,Line,RuleName,Message|out-string).trim())`n" ;
                "$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;
            } ;
        };
    }

    #>

# Pester Test for resolve-SMTPHeader function

Describe "resolve-SMTPHeader Function Tests" {
    # Sample SMTP header for testing
    $sampleHeader = @"
Received: from CH2PR14CA0024.namprd14.prod.outlook.com (2603:10b6:610:60::34)
 by SA6PR04MB9493.namprd04.prod.outlook.com (2603:10b6:806:444::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8207.18; Mon, 2 Dec
 2024 22:34:58 +0000
Received: from CH3PEPF0000000A.namprd04.prod.outlook.com
 (2603:10b6:610:60:cafe::7c) by CH2PR14CA0024.outlook.office365.com
 (2603:10b6:610:60::34) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.8207.18 via Frontend Transport; Mon,
 2 Dec 2024 22:34:58 +0000
Authentication-Results: spf=pass (sender IP is 23.251.226.11)
 smtp.mailfrom=us-east-2.amazonses.com; dkim=pass (signature was verified)
 header.d=amazonses.com;dmarc=fail action=quarantine
 header.from=toro.com;compauth=fail reason=000
Received-SPF: Pass (protection.outlook.com: domain of us-east-2.amazonses.com
 designates 23.251.226.11 as permitted sender)
 receiver=protection.outlook.com; client-ip=23.251.226.11;
 helo=e226-11.smtp-out.us-east-2.amazonses.com; pr=C
Received: from e226-11.smtp-out.us-east-2.amazonses.com (23.251.226.11) by
 CH3PEPF0000000A.mail.protection.outlook.com (10.167.244.37) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.8230.7
 via Frontend Transport; Mon, 2 Dec 2024 22:34:58 +0000
DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=relaxed/simple;
 s=xplzuhjr4seloozmmorg6obznvt7ijlt; d=amazonses.com; t=1733178897;
 h=From:Reply-To:To:Subject:MIME-Version:Content-Type:Message-ID:Date:Feedback-ID;
 bh=jxlsOZBqq0nUQqX5ofi0H+YQbyRMNFXWk4D+NdI3ZAo=;
 b=rAOY09c+aUgCNF1gYH+bM0oElSuYLFgFpUsmUIJlq/lAU+TaRa5DIDFWsAkkAikR
 R8USYlHlInRZ2nq71qgnz+MQpScHCTFKg10hC34MyfWiV5pV2QUCxFJJ/eWdSTBZPHB
 aDjWnbOcBDzN80T4XyC9nIs2+nQ8Yqt0ePYBk8QY=
From: sender.name@domain.com
"@

    It "Should parse the SMTP header into Name:Value pairs" {
        $result = resolve-SMTPHeader -Header $sampleHeader
        $result | Should -Not -BeNullOrEmpty
        $result | Should -FileContentMatch @{ HeaderName = "Received:"; HeaderValue = "from CH2PR14CA0024.namprd14.prod.outlook.com (2603:10b6:610:60::34) by SA6PR04MB9493.namprd04.prod.outlook.com (2603:10b6:806:444::18) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8207.18; Mon, 2 Dec 2024 22:34:58 +0000" }
        $result | Should -FileContentMatch @{ HeaderName = "Authentication-Results:"; HeaderValue = "spf=pass (sender IP is 23.251.226.11) smtp.mailfrom=us-east-2.amazonses.com; dkim=pass (signature was verified) header.d=amazonses.com;dmarc=fail action=quarantine header.from=toro.com;compauth=fail reason=000" }
        $result | Should -FileContentMatch @{ HeaderName = "DKIM-Signature:"; HeaderValue = "v=1; a=rsa-sha256; q=dns/txt; c=relaxed/simple; s=xplzuhjr4seloozmmorg6obznvt7ijlt; d=amazonses.com; t=1733178897; h=From:Reply-To:To:Subject:MIME-Version:Content-Type:Message-ID:Date:Feedback-ID; bh=jxlsOZBqq0nUQqX5ofi0H+YQbyRMNFXWk4D+NdI3ZAo=; b=rAOY09c+aUgCNF1gYH+bM0oElSuYLFgFpUsmUIJlq/lAU+TaRa5DIDFWsAkkAikR R8USYlHlInRZ2nq71qgnz+MQpScHCTFKg10hC34MyfWiV5pV2QUCxFJJ/eWdSTBZPHB aDjWnbOcBDzN80T4XyC9nIs2+nQ8Yqt0ePYBk8QY=" }
        $result | Should -FileContentMatch @{ HeaderName = "From:"; HeaderValue = "sender.name@domain.com" }
    }

    It "Should handle empty header input gracefully" {
        $result = resolve-SMTPHeader -Header ""
        $result | Should -BeNullOrEmpty
    }

    It "Should handle null header input gracefully" {
        $result = resolve-SMTPHeader -Header $null
        $result | Should -BeNullOrEmpty
    }
}

$ofile = join-path -path (split-path $scriptStylePath) -child "ScriptAnalyzer-Results-$(get-date -format 'yyyyMMdd-HHmmtt').xml" ;
$AnalyzerIssues | export-clixml -path $ofile
write-verbose -verbose:$verbose  "ScriptAnalyzer Report written to:`n$($ofile)" ;

#endregion

# SIG # Begin signature block
# MIIELgYJKoZIhvcNAQcCoIIEHzCCBBsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUykDSw2ZyNt/k5IupdX+BUvsj
# 4DegggI4MIICNDCCAaGgAwIBAgIQWsnStFUuSIVNR8uhNSlE6TAJBgUrDgMCHQUA
# MCwxKjAoBgNVBAMTIVBvd2VyU2hlbGwgTG9jYWwgQ2VydGlmaWNhdGUgUm9vdDAe
# Fw0xNDEyMjkxNzA3MzNaFw0zOTEyMzEyMzU5NTlaMBUxEzARBgNVBAMTClRvZGRT
# ZWxmSUkwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALqRVt7uNweTkZZ+16QG
# a+NnFYNRPPa8Bnm071ohGe27jNWKPVUbDfd0OY2sqCBQCEFVb5pqcIECRRnlhN5H
# +EEJmm2x9AU0uS7IHxHeUo8fkW4vm49adkat5gAoOZOwbuNntBOAJy9LCyNs4F1I
# KKphP3TyDwe8XqsEVwB2m9FPAgMBAAGjdjB0MBMGA1UdJQQMMAoGCCsGAQUFBwMD
# MF0GA1UdAQRWMFSAEL95r+Rh65kgqZl+tgchMuKhLjAsMSowKAYDVQQDEyFQb3dl
# clNoZWxsIExvY2FsIENlcnRpZmljYXRlIFJvb3SCEGwiXbeZNci7Rxiz/r43gVsw
# CQYFKw4DAh0FAAOBgQB6ECSnXHUs7/bCr6Z556K6IDJNWsccjcV89fHA/zKMX0w0
# 6NefCtxas/QHUA9mS87HRHLzKjFqweA3BnQ5lr5mPDlho8U90Nvtpj58G9I5SPUg
# CspNr5jEHOL5EdJFBIv3zI2jQ8TPbFGC0Cz72+4oYzSxWpftNX41MmEsZkMaADGC
# AWAwggFcAgEBMEAwLDEqMCgGA1UEAxMhUG93ZXJTaGVsbCBMb2NhbCBDZXJ0aWZp
# Y2F0ZSBSb290AhBaydK0VS5IhU1Hy6E1KUTpMAkGBSsOAwIaBQCgeDAYBgorBgEE
# AYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwG
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBSCxXlk
# xTAoZK42J/dbdsmU9K6/jDANBgkqhkiG9w0BAQEFAASBgINYEXCO18m4nBgDgYMs
# JjXrp9JKhkWUmRyAyfLH1FVpF2NgiJp54/ttt+uUUMaJu6utZJ3noAwWjC2PsS38
# NDyPGobibucfYig+GHI1ZhDx1aPevYTmyz3qpmnxc5PP/26QXvd6fYN7x3gNaye2
# PrRj7H0S4bnxtAgCAOtP8/DE
# SIG # End signature block
