# resolve-SMTPHeader.ps1
# d:\tmp\tmp20241206-0249PM.ps1
#*------v Function resolve-SMTPHeader v------
function resolve-SMTPHeader {
    <#
    .SYNOPSIS
    resolve-SMTPHeader.ps1 - Parse an SMTP message header stack into Name:Value combos for further analysis.
    .NOTES
    Version     : 0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2024-
    FileName    : resolve-SMTPHeader.ps1
    License     : MIT License
    Copyright   : (c) 2024 Todd Kadrie
    Github      : https://github.com/tostka/verb-XXX
    Tags        : Powershell
    AddedCredit : REFERENCE
    AddedWebsite: URL
    AddedTwitter: URL
    REVISIONS
    * 12:59 PM 12/9/2024 init
    .DESCRIPTION
    resolve-SMTPHeader.ps1 - Parse an SMTP message header stack into Name:Value combos for further analysis.
    .PARAMETER  Header
    SMTP Header [-Header `$headertext]
    .INPUTS
    None. Does not accepted piped input.(.NET types, can add description)
    .OUTPUTS
    System.PSCustomObject Returns summary object as an array of parsed Header Name:Value combos
    .EXAMPLE
    PS> $parseHdrs = resolve-SMTPHeader.ps1 -header $headertext ;
    PS> write-verbose "Filter the Received: headers" ; 
    PS> $parsedHdrs | ?{$_.headername -match 'Received:'}

        HeaderName HeaderValue                                                                                                                                                                                                          
        ---------- -----------                                                                                                                                                                                                          
        Received:  {from CH2PR14CA0024.namprd14.prod.outlook.com (2603:10b6:610:60::34),  by SA6PR04MB9493.namprd04.prod.outlook.com (2603:10b6:806:444::18) with,  Microsoft SMTP Server (version=TLS1_2,,  cipher=TLS_ECDHE_RSA_WIT...
        Received:  {from CH3PEPF0000000A.namprd04.prod.outlook.com,  (2603:10b6:610:60:cafe::7c) by CH2PR14CA0024.outlook.office365.com,  (2603:10b6:610:60::34) with Microsoft SMTP Server (version=TLS1_3,,  cipher=TLS_AES_256_GCM...
        Received:  {from e226-11.smtp-out.us-east-2.amazonses.com (23.251.226.11) by,  CH3PEPF0000000A.mail.protection.outlook.com (10.167.244.37) with Microsoft,  SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15...

    PS> write-verbose "Filter the Authentication-Results: headers" ; 
    PS> $authResult = $parsedHdrs | ?{$_.headername -match 'Authentication-Results:'} ;
    PS> $authresult | %{ write-host "`n$($_.HeaderName):" ; write-host "$(($_.HeaderValue|out-string).trim())`n" ; } ;        

        Authentication-Results:
        spf=pass (sender IP is 23.251.226.11)
         smtp.mailfrom=us-east-2.amazonses.com; dkim=pass (signature was verified)
         header.d=amazonses.com;dmarc=fail action=quarantine
         header.from=toro.com;compauth=fail reason=000

    PS> PS> write-verbose "Filter the Received-SPF: headers" ; 
    PS> $parsedHdrs | ?{$_ -match 'Received-SPF:'} | fl ;

        HeaderName  : Received-SPF:
        HeaderValue : {Pass (protection.outlook.com: domain of us-east-2.amazonses.com,  designates 23.251.226.11 as permitted sender),  receiver=protection.outlook.com; client-ip=23.251.226.11;,  
                      helo=e226-11.smtp-out.us-east-2.amazonses.com; pr=C}
        HeaderIndex : 15

    PS> $DkimSigs = $parsedHdrs | ?{$_.headername -match 'DKIM-Signature:'} ;
    PS> $DkimSigs | %{ write-host "`n$($_.HeaderName)" ; write-host "$(($_.HeaderValue|out-string).trim())`n" ; } ; 

        DKIM-Signature:
        v=1; a=rsa-sha256; q=dns/txt; c=relaxed/simple;
	        s=xplzuhjr4seloozmmorg6obznvt7ijlt; d=amazonses.com; t=1733178897;
	        h=From:Reply-To:To:Subject:MIME-Version:Content-Type:Message-ID:Date:Feedback-ID;
	        bh=jxlsOZBqq0nUQqX5ofi0H+YQbyRMNFXWk4D+NdI3ZAo=;
	        b=rAOY09c+aUgCNF1gYH+bM0oElSuYLFgFpUsmUIJlq/lAU+TaRa5DIDFWsAkkAikR
	        R8USYlHlInRZ2nq71qgnz+MQpScHCTFKg10hC34MyfWiV5pV2QUCxFJJ/eWdSTBZPHB
	        aDjWnbOcBDzN80T4XyC9nIs2+nQ8Yqt0ePYBk8QY=

    PS> write-verbose "filter From:" ; 
    PS> $parsedHdrs | ?{$_.headername -match 'From:'} | %{"$($_.HeaderName) $($_.HeaderValue)"}

        From: walker.olson@toro.com

    PS> write-verbose "filter Return-Path:" ; 
    PS> $parsedHdrs | ?{$_.headername -match 'Return-Path:'} | %{"$($_.HeaderName) $($_.HeaderValue)"} ; 

        Return-Path:  010f0193898333b2-294e9589-d10c-43e6-94ba-4bc88a999262-000000@us-east-2.amazonses.com


    Typical usage
    .EXAMPLE
    PS> $parsedHdrs = $header | resolve-smtpHeader 
    Pipeline demo: Fed variable holding header in via pipeline.
    .LINK
    https://github.com/tostka/verb-Network
    #>
    ## [OutputType('bool')] # optional specified output type
    [CmdletBinding()]
    ## PSV3+ whatif support:[CmdletBinding(SupportsShouldProcess)]
    ###[Alias('Alias','Alias2')]
    PARAM(
        # Mandatory = $true,
        [Parameter(ValueFromPipeline=$true, HelpMessage="SMTP Header [-Header `$headertext]")]
            # if you want to default a value but ensure user doesn't override with null, don't use Mandetory, use...
            [ValidateNotNullOrEmpty()]
            #[string]
            $Header,
        [Parameter(HelpMessage="Run get-help on the cmdlet [-Help]")]
              [switch]$HELP
    )
    BEGIN{
        $Verbose = ($VerbosePreference -eq 'Continue') ; 
        
        # check if using Pipeline input or explicit params:
        if ($rPSCmdlet.MyInvocation.ExpectingInput) {
            $smsg = "Data received from pipeline input: '$($InputObject)'" ;
            if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
            else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
        } else {
            # doesn't actually return an obj in the echo
            #$smsg = "Data received from parameter input: '$($InputObject)'" ;
            #if($verbose){if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level VERBOSE } 
            #else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; } ; 
        } ;

        #endregion SUBMAIN ; #*======^ END SUB MAIN ^======
    } ;  # BEGIN-E
    # ps1 faked:#endregion BEGIN ; #*------^ END BEGIN ^------
    PROCESS {

        $Error.Clear() ; 
        
        if(-not $HEADER){
            write-verbose 'Always pre-Enable DPI-Aware Windows Forms' ;

            TRY{[ProcessDPI] | out-null }catch{
                Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public class ProcessDPI {
    [DllImport("user32.dll", SetLastError=true)]
    public static extern bool SetProcessDPIAware();
}
'@
} ;
            $null = [ProcessDPI]::SetProcessDPIAware() ;
            #write-verbose "Normal Prompting (allows empty output) - Textbox mode - String output" ;
            $pltRdMLIDA=[ordered]@{
                Message = "No -header specified: Paste header text into the dialog" ;
                WindowTitle = "Prompt: (Textbox: String return)" ;
                InboxType = "txt" ;
                ReturnType = "str" ;
                ShowDebug = $true ;
            } ;
            $smsg = "read-MultiLineInputDialogAdvanced w`n$(($pltRdMLIDA|out-string).trim())" ;
            write-host -foregroundcolor green $smsg  ;
            $header = read-MultiLineInputDialogAdvanced @pltRdMLIDA ;
            write-host "`r`n-----Return-String:`r`n" + $header  + "`r`n-----End of Return" ;        
        } ; 

        #region PARAMHELP ; #*------v PARAMHELP  v------
        # if you want no params -OR -help to run get-help, use:
        #if ($help -OR (-not $rPSCmdlet.MyInvocation.ExpectingInput) -AND (($PSParameters| measure-object).count -eq 0)) {
        # on blank specific param -or -help
        #if (-not $Header -OR $HELP) {
        # if you only want -help to run get-help
        if ($HELP) {
            if($MyInvocation.MyCommand.Name.length -gt 0){
                Get-Help -Name "$($MyInvocation.MyCommand.Name)" -full ; 
                # also could run using native -? == get-help [command] (avoiding as invoke-expression is stigmatized for sec)
                # also note -? only runs default gh output, not full or some other variant. And cmdlet -? -full etc doesn't work
                #Invoke-Expression -Command "$($MyInvocation.MyCommand.Name) -?"
            }elseif($PSCommandPath.length -gt 0){
                Get-Help -Name "$($PSCommandPath)" -full ; 
            }elseif($CmdletName.length -gt 0){
                Get-Help -Name "$($CmdletName)" -full ; 
            } ; 
            break ; #Exit  ; 
        }; 
        #endregion PARAMHELP  ; #*------^ END PARAMHELP  ^------        
        <#
$hsHdr = @"
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
From: walker.olson@toro.com
Reply-To: walker.olson@toro.com
To: walker.olson@toro.com, walkdude99@hotmail.com
Subject: Fuel Tracking: Machine Provisioned
MIME-Version: 1.0
Content-Type: text/plain
Message-ID: <010f0193898333b2-294e9589-d10c-43e6-94ba-4bc88a999262-000000@us-east-2.amazonses.com>
Date: Mon, 2 Dec 2024 22:34:57 +0000
Feedback-ID: ::1.us-east-2.QyulnpM4L1IwuxomjV4UC071kbkHZsV18gSZ4yEZxG0=:AmazonSES
X-SES-Outgoing: 2024.12.02-23.251.226.11
Return-Path:
 010f0193898333b2-294e9589-d10c-43e6-94ba-4bc88a999262-000000@us-east-2.amazonses.com
X-EOPAttributedMessage: 0
X-EOPTenantAttributedMessage: 549366ae-e80a-44b9-8adc-52d0c29ba08b:0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PEPF0000000A:EE_|SA6PR04MB9493:EE_
X-MS-Office365-Filtering-Correlation-Id: 95c7a6f1-8e9f-4a75-156e-08dd13218d84
ToroRule-ApplyExternalStamp: Rule triggered
X-Forefront-Antispam-Report:
 CIP:23.251.226.11;CTRY:US;LANG:en;SCL:5;SRV:;IPV:NLI;SFV:SPM;H:e226-11.smtp-out.us-east-2.amazonses.com;PTR:e226-11.smtp-out.us-east-2.amazonses.com;CAT:SPOOF;SFS:(13230040)(32142699015)(8096899003);DIR:INB;
X-Microsoft-Antispam: BCL:0;ARA:13230040|32142699015|8096899003;
X-Microsoft-Antispam-Message-Info:
 =?utf-8?B?ekdzcjV2YVU5alZycERMUUVITmJ5eTc3Nm9zLytESG1EWGpFMjdEU21iYUVv?=
 =?utf-8?B?UzdVQlFSa2VDNTVCTkhrQ1NwZTluMTRORi9naFoxYmQyTmpWMGFhZ0laZjZX?=
 =?utf-8?B?VzNlQTZYQmtxdFM0U3VsZWRpVFdpbmQ1UEFjdEFUamVEaFc1SkJIaWRBUkQ4?=
 =?utf-8?B?ZUJHK3RPdE9zY0VtUUNvcVhlVzV5YkY5cjJzZHJ0cm82M2plbXBkTno3Qkt2?=
 =?utf-8?B?U0Z0ZXZXV1RxMkhtUGZFajh0RXJETE5KYWRERW8zNjA5cFBXOXd3aGlIUy9O?=
 =?utf-8?B?RW8rRGpiQ1I1ZXdnUmM2bCtOSVhTeFduMDdsWnlvZGtjVzhwYmxtcGZrOExn?=
 =?utf-8?B?TFI4R3dCSE8wVTAzMGp4MGJ4SHFzS0M0WU96L1E0ZHFRVXpkRHlzZmVxNm5u?=
 =?utf-8?B?ZzBvQWNDMDBLTlk2SkxacGZPRDQ3NGIyT0VtWG0zR1JpaW8zeUJVMjUvcFVR?=
 =?utf-8?B?YUltNWxzZjJDbFVxcWptUWh2ZVZXaWRIOFhmTUIzWmtSemtXR1hHWmsrbHM5?=
 =?utf-8?B?Zi9TK2llWWMwZTcxYm1zWUJJUVZCZk4wNEU1dlcybjZIN3dnbTI2UWx3eUFI?=
 =?utf-8?B?ekR4eE5oM3hXVzhmUU9vOTlmSGlkWmd6Ly9JbWcxWDZ3dXlKNEhUNGlZeGlX?=
 =?utf-8?B?TytPVTJZTmJtUllNWE5tVWtOd0lONG14amNGd3FsLzk0STVlN1R6MzJuNXFY?=
 =?utf-8?B?TXpEQmJhZy9ndnZvQ3FzWFlrQmU3bzR1RFFPZkpidGFvMW5mUW9FNHM1Wklt?=
 =?utf-8?B?SWRWWTc5dFUwQlliZ2dPWWpxVXZJTGd6VmRnMG9ZejF0V1lNOEFWMlVDSkRD?=
 =?utf-8?B?MHlzWTFHQzBvTlJMSnB0MGZPWCtOc1lIR29hS2NrMTgvSDAvVzRYUk1Ja20y?=
 =?utf-8?B?dit1QTMwdkVZSUt1aFl5bDErbnZDSHZYaTdrZDgvdWFvbnZSaDZLTEg1U1F5?=
 =?utf-8?B?c2RCNmFEdVFnUWhCUHJpTHhTaEYzYStTZzk4czdCMzdVd1YwbkVKYm9WM0JG?=
 =?utf-8?B?MkphKy9Xb080OW1RNjg2VnZJMTlVOWV3dzgwT3A2ZjBzL05vTlU1Z2p0Z0Zp?=
 =?utf-8?B?M0RWRVZKaDYzaDF4TnhYQlloSlhTcEpVdCtubzVFZUNGUENXaGc3R2E2WktX?=
 =?utf-8?B?KzIwVGRRRDlldlJzN3o2OE9QY0tjR0ZER0FiN2ZPeGhadzZmSGpsejhKM0Mr?=
 =?utf-8?B?V0xCLzA2V2JPaTZxYWQvZU9MN3FmMEhpWXIvYlBHTTVldTFQc3ZZVytTajY3?=
 =?utf-8?B?dUVxS3FGSE1ueHRzSnYrVVF4cGJwSXh2aGFoME0wNW03ZFMwdEFYeU1WeHcv?=
 =?utf-8?B?VE4zMU1CS0t1R2VVb3Z5NDVyOFRDODFjVHdJUTM5UVQ1Y2lOWEg1bXBYanJS?=
 =?utf-8?B?WnZuYTNXRk5lMnZ6bUZkM3daVTJKYmtoQTZGUzdETmZXUjVLZEtYWUZwTkN2?=
 =?utf-8?B?WU5VN1ZFQkc0M3grZEw2d0RCeHlZNjdPeHFCSjZmQ1Zpd0JtWS81N2tKalpw?=
 =?utf-8?B?K3BVQ3ZrVUVRRHZxMUgyazFCejlWaWdjZE9DUjJmbzFGOG1pNkppYUg0NGJm?=
 =?utf-8?B?VWFxbngrem1Vc2RpMHduNHNCMWhMeUtkcDZxL2xiRzUxZk1NRExEWm1kWVA0?=
 =?utf-8?B?WWI5ajB4WHpseDI0V3JoK3pEbWJ6azF6RTBoRkNWL1lRZXg0aU1JUTJDOVRu?=
 =?utf-8?B?dDNiWDgrSDdyN01FVWFpN3U0QWZjVFdYeE15ZkREK25vendKNjV1YnYzSG11?=
 =?utf-8?B?VElibEJ5VjdPRkt2a1g4RHZUbXU4MjJKdUJEK0lCMkYxWldwTHpyc3NYTnUv?=
 =?utf-8?B?T2tOdUpZeWZXNGhNUzYwcGF6Zk9XZlZ1d3hZazZiNnE4WkR3cHNwQkZTV3E1?=
 =?utf-8?B?ejRoVnNvb1VHY2ZhV0VKL3dsNWJlUS90ZlF6R2J3VmR5Y3FWUEFvZ1FIbGtC?=
 =?utf-8?B?RkZqcnZFQklhUmQ4YXpYNmtSNFFMN3JCNWxGUzZtNndLb1UyYTRnL2lDVzdR?=
 =?utf-8?B?K3prK0h4cVNvZWE0TXUwRlk5aUVGblNTMTNuZS9rSG1aenJiMGt1WTR2WkUx?=
 =?utf-8?B?WDk1VE1oa3VRWVZ5Zm1XTzJucGdKYUN3TjlTYjFMdXJ6QU5kRjRYMFlIRzRv?=
 =?utf-8?B?SnMzQnNtdGFXWlpac1IvR2QxWmU0enBzK0pPbFFZdkwyRlpsdExoMjdubmtF?=
 =?utf-8?B?S0R0cVhRYjFFUDVadXAzZkwzYVVSMS9YSHRwOFlLOW5SUCtzb3oyb3RZdzlJ?=
 =?utf-8?B?cWcyeGdDVFV5MWd2Vk9KRXBMdTVDM2ZXekpFTHJ4aUhSNTVoZkk4Y0huZmZm?=
 =?utf-8?B?eUxxZ0g3VW9pczhBUnVGWlh6WDR1SXZmY2hlUnZzM2dETG5OdUdtZ1dXYmlt?=
 =?utf-8?B?ZjZwR0FFSnIzdGorclFwRWl0N043Z0NDb2pScUZRajI1UnVINXRrNGhrUzdn?=
 =?utf-8?B?QXJGYzQycjM2dHZVYlRhRE1VQzdoRUtQWldWN0tqRG9sV0greEVycG9NS1Iw?=
 =?utf-8?B?c01vUXJXVFRsVDJFTlkwSFhzQSthcml0YnVoTFVJcUpITEczM25HM04rQm1N?=
 =?utf-8?B?QzRnSkZCVTIzLzhXQXBMZkRuSGM1bXVXTGdIVlVLR0J3bytvb3RrdkNXTzRo?=
 =?utf-8?B?NUZPaWhpak0xM3RxTTY1TTJ6TktaK004QXpHWHFwdk9VZ29oamxueCtuUDZ5?=
 =?utf-8?B?Ly95eU1TYzJuSTZnU2FQZXYycmlYSTlVd1BIZGt2Zk1yWFlLdnU3VkpTVDBN?=
 =?utf-8?B?b0QvOVNVQWlFc0x6RVFMKzdWRnVWTWl5NmhzZU1IR2VvdW5aeVc5WVhRUjli?=
 =?utf-8?B?d3ZoNG5DTGtFcHZ3UlFmWmR0ZmJMTWxmSnNldUNndkE3RHIvcHV6MkUwQkox?=
 =?utf-8?B?RGpKWmtLUWlsR2VnY24xZDJ0MHdadklUQkplYXNiZCtrbGtGb0lRVFdmS05x?=
 =?utf-8?B?N3prWTg3bmdqWExOVVM5OUI4VmFpZDRZcU1HM1g2TWtVdVJlQ0tMa2ZYMlpX?=
 =?utf-8?B?T0M5bGhKZXJaUWtLVy9BRTBCalV0Z2JQVFNaMk9TRzhzY0phWnJZZmx0Q20r?=
 =?utf-8?B?VzR3UmxabVJNK3FQWlRRL0l6V2Q3a05yNk0zSUtMNUdPcmZmYk8ycXNObnRi?=
 =?utf-8?B?eWdRZjRUL25tOEVmZm9La3BPMkZpYzZtd281b01lWkUzWGptYjAvQUI4eTJy?=
 =?utf-8?B?bXZkS0hydzI5QksySXQzQjNOdFVHSXdsZEs1Z3RnWXlHSGxPRnh3c25Oc1pI?=
 =?utf-8?Q?v6fwB7rq87VmbOLkv4GF+5kQOA=3D?=



"@.Split([Environment]::NewLine) | ?{$_} ;
    #>
        <#
$hsHdr = @"
Received: from MN2PR04MB6991.namprd04.prod.outlook.com (2603:10b6:208:1e1::17)
 by CH0PR04MB8147.namprd04.prod.outlook.com with HTTPS; Thu, 5 Dec 2024
 21:07:11 +0000
Received: from CH0PR03CA0304.namprd03.prod.outlook.com (2603:10b6:610:118::28)
 by MN2PR04MB6991.namprd04.prod.outlook.com (2603:10b6:208:1e1::17) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8230.12; Thu, 5 Dec
 2024 21:07:10 +0000
Received: from CH1PEPF0000AD83.namprd04.prod.outlook.com
 (2603:10b6:610:118:cafe::67) by CH0PR03CA0304.outlook.office365.com
 (2603:10b6:610:118::28) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.8230.12 via Frontend Transport; Thu,
 5 Dec 2024 21:07:10 +0000
Authentication-Results: spf=pass (sender IP is 136.175.108.142)
 smtp.mailfrom=kadrie.net; dkim=pass (signature was verified)
 header.d=kadrie.net;dmarc=pass action=none
 header.from=kadrie.net;compauth=pass reason=100
Received-SPF: Pass (protection.outlook.com: domain of kadrie.net designates
 136.175.108.142 as permitted sender) receiver=protection.outlook.com;
 client-ip=136.175.108.142; helo=mail-108-mta142.mxroute.com; pr=C
Received: from mail-108-mta142.mxroute.com (136.175.108.142) by
 CH1PEPF0000AD83.mail.protection.outlook.com (10.167.244.85) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.8230.7
 via Frontend Transport; Thu, 5 Dec 2024 21:07:09 +0000
Received: from filter006.mxroute.com ([136.175.111.3] filter006.mxroute.com)
 (Authenticated sender: mN4UYu2MZsgR)
 by mail-108-mta142.mxroute.com (ZoneMTA) with ESMTPSA id 19398a5d8640003e01.001
 for <Todd.Kadrie@toro.com>
 (version=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384);
 Thu, 05 Dec 2024 21:07:05 +0000
X-Zone-Loop: 4cb2588f304a7c1711c10a9b5c4913136ce484dc7f3c
X-Originating-IP: [136.175.111.3]
DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=relaxed/relaxed; d=kadrie.net;
	s=x; h=Content-Transfer-Encoding:Content-Type:MIME-Version:Message-ID:Subject
	:To:From:Date:Sender:Reply-To:Cc:Content-ID:Content-Description:Resent-Date:
	Resent-From:Resent-Sender:Resent-To:Resent-Cc:Resent-Message-ID:In-Reply-To:
	References:List-Id:List-Help:List-Unsubscribe:List-Subscribe:List-Post:
	List-Owner:List-Archive; bh=3BNWhTiaKphQvWfI/Drg+j+X2Bz/+YePgyVANN02pbo=; b=Q
	CKkMkhDEJO2ECib2gUxQtHNfw8fkhl5Ursfy08kExgyso0ccx58xdnlGQnaeUWIQbzJ3+l4roPgRv
	Cep1RUvloULNEoV4IBgsfheJAusQrbMSjfdDK6I/oW5HfX6S6y53ghIIQp4hJeFrdqXaHlbIOZZy6
	DZvglDdwO6wjUWo8Hwk8ztXHVvMmqXahV9jWy3ngS7soL9w4z+gck2dziNrrcPELHpYJYNnWVb4zw
	NMx/4z8VJ5mjBNcC6tId3vZAI7TbqoqVCU+Aj/xZHHzYOODqPRi4HMn0o1K4IwCRbWjYqvSu3K/91
	mh3AvzVSDhzTnjdffEtp2nvGotlTeAGzA==;
Date: Thu, 05 Dec 2024 15:07:03 -0600
From: Todd Kadrie <todd@kadrie.net>
To: Todd Kadrie <Todd.Kadrie@toro.com>
Subject: Test message
Message-ID: <0C03B518-554F-4B18-BB6F-73D9B9E556E2@kadrie.net>
MIME-Version: 1.0
Content-Type: multipart/alternative;
 boundary=----O23DT15SDX1UZ783340ZO38BRXUIZ2
Content-Transfer-Encoding: 7bit
Autocrypt: addr=todd@kadrie.net; prefer-encrypt=mutual; keydata=
 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
X-Authenticated-Id: todd@kadrie.net
Return-Path: todd@kadrie.net
X-MS-Exchange-Organization-ExpirationStartTime: 05 Dec 2024 21:07:09.9059
 (UTC)
X-MS-Exchange-Organization-ExpirationStartTimeReason: OriginalSubmit
X-MS-Exchange-Organization-ExpirationInterval: 1:00:00:00.0000000
X-MS-Exchange-Organization-ExpirationIntervalReason: OriginalSubmit
X-MS-Exchange-Organization-Network-Message-Id:
 9f29b644-9c23-4b7f-fa55-08dd1570c864
X-EOPAttributedMessage: 0
X-EOPTenantAttributedMessage: 549366ae-e80a-44b9-8adc-52d0c29ba08b:0
X-MS-Exchange-Organization-MessageDirectionality: Incoming
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic:
 CH1PEPF0000AD83:EE_|MN2PR04MB6991:EE_|CH0PR04MB8147:EE_
X-MS-Exchange-Organization-AuthSource:
 CH1PEPF0000AD83.namprd04.prod.outlook.com
X-MS-Exchange-Organization-AuthAs: Anonymous
X-MS-Office365-Filtering-Correlation-Id: 9f29b644-9c23-4b7f-fa55-08dd1570c864
X-MS-Exchange-Organization-SCL: 1
X-Microsoft-Antispam: BCL:0;ARA:13230040|8096899003;
X-Forefront-Antispam-Report:
 CIP:136.175.108.142;CTRY:US;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:mail-108-mta142.mxroute.com;PTR:mail-108-mta142.mxroute.com;CAT:NONE;SFS:(13230040)(8096899003);DIR:INB;
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 05 Dec 2024 21:07:09.8278
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 9f29b644-9c23-4b7f-fa55-08dd1570c864
X-MS-Exchange-CrossTenant-Id: 549366ae-e80a-44b9-8adc-52d0c29ba08b
X-MS-Exchange-CrossTenant-AuthSource:
 CH1PEPF0000AD83.namprd04.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: Internet
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MN2PR04MB6991
X-MS-Exchange-Transport-EndToEndLatency: 00:00:02.0330872
X-MS-Exchange-Processed-By-BccFoldering: 15.20.8230.010
X-Microsoft-Antispam-Mailbox-Delivery:
	ucf:0;jmr:0;auth:0;dest:I;ENG:(910001)(944506478)(944626604)(920097)(930097)(140003);
X-Microsoft-Antispam-Message-Info:
	=?us-ascii?Q?lZHj5tE4CMKO9jgvVglid+/HLKrgiX+4J+hVZrUelUdYMU1qazmsb71of+Dt?=
 =?us-ascii?Q?wBDUMaNY/FjXBB12XyU6IxYt2oMVbwtK62k5LKlMJ4zYdqt5JYzG2h7AHieB?=
 =?us-ascii?Q?uyUvGIl6pPS2ZehfNevEWcaNR10rg5kZN/BD3J4Fvbfka3REUiFG9Kng0kpT?=
 =?us-ascii?Q?08tNnmYtMhKXDAYVjfLxfroCayzLj7f6/mo57N3dVq5EREQIoyZORv7v4eHL?=
 =?us-ascii?Q?DVV+NH/mz5bv4JqUQA3BO0FAjtBoUDiFcytH0WxIXjwKl0sgeF9o3mBEgkyj?=
 =?us-ascii?Q?UcOOboEXdUUVdaKfOnEO0sC+68xfXcyRCjU/qYxITfFne8Ft+kTZeMtgy/WC?=
 =?us-ascii?Q?cqhy9TKeQQTWlef/gEwTHCmhklsenstXfbEKqMGQfCmNvBRLBb5AcZuGJEFu?=
 =?us-ascii?Q?ittAMpW6Zv7zuX00pkGmquBlBg+8T3dHLQdkZfRStcGUJNy/SGK5qOifCYo8?=
 =?us-ascii?Q?JMNZf/C61U1I8YfisPPIey0wDO2oQsL5Za2hdM6GcLZqJXj7lOxt2cWOnvtr?=
 =?us-ascii?Q?k+mOZI7Gn9RpHsa6Ma8A4WMLyrEuujSpSulVQfsexb2fRl77VU47bVVWooC1?=
 =?us-ascii?Q?vlvHDSdwIu17jCdEHv2sM5d20oGoSkGR70drNtF5QIcveFVivyR1e2trrs5j?=
 =?us-ascii?Q?kraiiQBKDW6At8Z0o9bTgD6QREWA1cZmDrjO1N0+xrelBdB6XjyTm2r0Mxhx?=
 =?us-ascii?Q?xt7Wk8spUi2r1Cj1O+rDFTgbwCBQ9tZRfcaI6off4EsZQRPdaC9hv0nXxEOn?=
 =?us-ascii?Q?HYqBnBYQp/T86IzVzGB5w+emPbSM7P9U1xCn8fzdi80+L+QkCU4iXW/LVxKq?=
 =?us-ascii?Q?7bg+UPvk2Q6NpPeQxA2JB5iMwqkr5Grk1gapp6nJv5hlUhWOSmWutqwY1FoL?=
 =?us-ascii?Q?M6cnSbgK1y4ww7ise0pnj7foNZ8GEG1VcHg8jM5OCVwXZm26rdqkJH3IYG46?=
 =?us-ascii?Q?nWmr9wz2u5kkw8exgsdR7uD/QuvSPuN2TUcaTR2oZDtV1yIMVuUMfBoF+2mb?=
 =?us-ascii?Q?vbO+Q/ri/sWp3tCWElFW+F2C1WV/D9L3JtXqM8MeggmHlqQiLz3kGGCCIcix?=
 =?us-ascii?Q?vB/qvYza1+9xxwKvN6x6twDtwfa+GPSIL8vh9MUHez+q7E3UsTtp8/bIpokL?=
 =?us-ascii?Q?DxHJWieHmdu5VGybG8PBY1BCjCPljy5mxgNpWyeO0ofStpzEvG8qrcO55cXS?=
 =?us-ascii?Q?twtPlnxaPgh9uZ6H+vJYeOIyeL2JGvkysBPwrCqVRz31TqKPzF0VtQAOTiCU?=
 =?us-ascii?Q?Me7qKqhUmkb13H8kxQ2RM3IEHQHPNZQkvTlXxGQH+CpnGEe0VLd/y94HJGQF?=
 =?us-ascii?Q?bfaJZLuvpxWyOhqC9dSxGQRM9/iogrXYiz/K3+Ugf3xzF2W0bQ2aHN6Umzzh?=
 =?us-ascii?Q?KNVxWjzG1gDF4EyGxG03Aw0KFrlkdjDJWZBIC0hX7XKiiae8klb5FBoHNTlS?=
 =?us-ascii?Q?KwUzulwwl7smlEFmTUDuS6MWbp2lRI8aCryD9JcIGbi9cFqg7xaC/0S8zbWv?=
 =?us-ascii?Q?AC1XENqN7ckDZtfgU/YdMFPr5LFx7t3qR9HlI1jns6Nh5ugQiS3zan9hKf3I?=
 =?us-ascii?Q?kpN9ANusl0UmHlWGYm5D4AU01c0Wg3FU4OYZX/VEEy23tG1eFgRlCWfsEnH9?=
 =?us-ascii?Q?6eeaWGZzPjUfNW6R1i7t+9jpyi/MXCCDvzCMSRcXvyQ5kgSFHY3dnmw5XQdo?=
 =?us-ascii?Q?xhUaappTKsND+nD2ONNrktKRgltS1cagM/zmQ4AGkRqOLnKAsIvT6+noWo9F?=
 =?us-ascii?Q?b51KMJal4zkbnk/j+DklDuGs+9qAcA6Yy53ekIT+IxnhkGmwq6cuAab9959A?=
 =?us-ascii?Q?xBLr2MzBvBGva+1TOoMXLrVDKGK1NXagS/uesbkUFUXK8QQKZcGGfAEs?=
"@.Split([Environment]::NewLine) | ?{$_} ;
    #>
        switch ($header.gettype().fullname){
            'System.String'{
                write-verbose '-Header likely herestring: splitting on crlfs & removing empty lines'
                [string[]]$header = $header.Split([Environment]::NewLine)|?{$_} ;  
            } ;
            'System.String[]'{
                write-verbose '-Header is a string array'
            }
            default{
                write-verbose '-Header of unrecognized type, attempting default string processing'
            }
        } ; 

        $ttl = $header |  measure | select -expand count ;  
        $Prcd = 0 ; 
        #region PIPELINE_PROCESSINGLOOP ; #*------v PIPELINE_PROCESSINGLOOP v------
        #foreach($HDR in $Header) {
            #$ttl = $HDR |  measure | select -expand count ; 
            $ttl = $header |  measure | select -expand count ;             
            $aggHdr = @() ; 
            $hdrSumm = [ordered]@{
                HeaderName=$null ; 
                HeaderValue=$null ; 
                HeaderIndex = $null ; 
            } ;
            foreach($ln in $header){
                $Prcd ++ ; 
                #if($ln -eq 'X-Microsoft-Antispam-Message-Info:'){ 
                if($ln -match '(X-MS-Exchange-Organization-Network-Message-Id:|X-MS-TrafficTypeDiagnostic:|X-MS-Exchange-Organization-AuthSource:|X-Forefront-Antispam-Report:|X-MS-Exchange-CrossTenant-AuthSource:|X-Microsoft-Antispam-Mailbox-Delivery:)'){
                    #write-host 'BOO'
                    write-verbose "dbg: '$($ln)'" ;
                } ; 
                if($ln -match 'X-Microsoft-Antispam-Message-Info:'){ 
                    write-verbose "dbg: '$($ln)'" ;
                } ; 
                if($ln.length -eq 0){
                    write-host "skipping empty line #$($Prcd):`n'$($ln)'" ; 
                #}elseif($ln | ?{$_ -match '^\S+'}){  # matches *not* leading with a space+
                #}elseif($ln  -match '^([A-Za-z0-9-]+):\s+(.*)$'){
                }elseif($ln  -match '^([A-Za-z0-9-]+):\s+(.*)$' -OR $ln -match '^([A-Za-z0-9-]+):$((\s)*)$'){
                    write-verbose "line is new HeaderName: #$($Prcd):`n'$($ln)'" ; 
                    if($hdrSumm.HeaderName){
                        $aggHdr+= [pscustomobject]$hdrSumm ; 
                    } ; 
                    $hdrSumm = [ordered]@{
                        HeaderName=$null ; 
                        HeaderValue=$null ; 
                        HeaderIndex = $Prcd ; 
                    } ;
                    #if($null -eq $matches[2]){
                    if(-not $matches[2]){
                        write-verbose "(Header has wrapped value, next line): #$($Prcd):`n'$($ln)'" ; 
                        if($matches[1]){
                            $hdrSumm.HeaderName = "$($matches[1]):" ;
                        } else {
                            throw "blank HeaderName header match!" ; 
                        } ; 
                    } else { 
                        $hdrSumm.HeaderName = "$($matches[1]):" ;
                        $hdrSumm.HeaderValue += @($matches[2]) ;  
                    } ; 
                }elseif($ln  -match '^\s+.*$'){
                    # indented HeaderValue continues...
                    $hdrSumm.HeaderValue += @($matches[0]) ;  
                } else { 
                    write-warning "no match!: #$($Prcd):`n'$($ln)'" ; 
                }
            } ; 
            if($hdrSumm.HeaderValue -ne $aggHdr[-1].HeaderName){
                $aggHdr+= [pscustomobject]$hdrSumm ; 
            } ; 
            $smsg = "Returning $($agghdr|  measure | select -expand count ) summarized Headers to pipeline:$(($aggHdr |out-string).trim())" ; 
            if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug 
            else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
            $aggHdr | write-output  ; 
        #} ;  # loop-E
    } #  # PROC-E
} ; 
#*------^ END Function resolve-SMTPHeader ^------
