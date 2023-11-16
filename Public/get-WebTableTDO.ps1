# get-WebTableTDO.ps1
#*----------v Function get-WebTableTDO() v----------

function get-WebTableTDO {
	<#
	.SYNOPSIS
	get-WebTableTDO.ps1 - Extract Tables from Web pages (via PowerShellInvoke-WebRequest)
	.NOTES
	Version     : 1.0.0
	Author      : Todd Kadrie
	Website     :	http://www.toddomation.com
	Twitter     :	@tostka / http://twitter.com/tostka
	CreatedDate : 2023-
	FileName    : 
	License     : MIT License
	Copyright   : (c) 2023 Todd Kadrie
	Github      : https://github.com/tostka/verb-XXX
	Tags        : Powershell
	AddedCredit : REFERENCE
	AddedWebsite:	URL
	AddedTwitter:	URL
	REVISIONS
	* 9:25 AM 11/8/2023 ported over from ImportExcel:get-HtmlTable, which is adapted version of Lee Holmes' Get-WebRequestTable.ps1 demo code. 
	add: -Summary param, which dumps a short index#|Summary (leading textcontent[0..56] string)
	add: param detailed out, helpmessage, CBH
	add: strongly typed params
	* 10/12/23 dfinke's adapted variant of LH's original code into ImportExcel:get-htmlTabl(): [PowerShell Gallery | ImportExcel 7.8.6](https://www.powershellgallery.com/packages/ImportExcel/7.8.6) (adds 
	* 1/5/2015 LH's posted code from https://www.leeholmes.com/extracting-tables-from-powershells-invoke-webrequest/
	.DESCRIPTION
	get-WebTableTDO.ps1 - Extract Tables from Web pages (via PowerShellInvoke-WebRequest)

	Original code: [Lee Holmes | Extracting Tables from PowerShell's Invoke-WebRequest](https://www.leeholmes.com/extracting-tables-from-powershells-invoke-webrequest/)
	By way of dFinke's ImportExcel:get-HtmlTable v7.8.6 [ImportExcel/Public/Get-HtmlTable.ps1 at master · dfinke/ImportExcel · GitHub](https://github.com/dfinke/ImportExcel/blob/master/Public/Get-HtmlTable.ps1)
	
	.PARAMETER Url
	Specifies the Uniform Resource Identifier (URI) of the Internet resource to which the web request is sent. Enter a URI. This parameter supports HTTP, HTTPS, FTP, and FILE values.[-Url https://somewebserver/page]
	.PARAMETER TableIndex
	Index number of the table from target URL, to be returned (defaults 0)[-TableIndex 2]
	.PARAMETER Header
	Table header properties to be substituted for the resulting table
	.PARAMETER FirstDataRow
	Index Row of table from which to begin returning data (defaults 0)[-FirstDataRow 2]
	.PARAMETER Summary
	Indicates that the cmdlet should return a summary of all tables currently on the subject URL page.[-summary]
	.PARAMETER UseDefaultCredentials
	Indicates that the cmdlet uses the credentials of the current user to send the web request.
	.EXAMPLE
	PS> get-WebTableTDO -URL "https://en.wikipedia.org/wiki/List_of_Star_Trek:_The_Original_Series_episodes" -UseDefaultCredentials:$false ;
	OPTSAMPLEOUTPUT
	OPTDESCRIPTION
	.EXAMPLE
	PS> .\get-WebTableTDO.ps1 -VERBOSE
	OPTSAMPLEOUTPUT
	OPTDESCRIPTION
	.LINK
	https://github.com/tostka/verb-XXX
	.LINK
	https://github.com/dfinke/ImportExcel/blob/master/Public/Get-HtmlTable.ps1
	.LINK
	https://www.leeholmes.com/extracting-tables-from-powershells-invoke-webrequest/
	#>
	[CmdletBinding()]
	[Alias('Get-WebRequestTable')]
    PARAM(
        [Parameter(Mandatory=$true,HelpMessage='Specifies the Uniform Resource Identifier (URI) of the Internet resource to which the web request is sent. Enter a URI. This parameter supports HTTP, HTTPS, FTP, and FILE values.[-Url https://somewebserver/page]')]
			[System.Uri]$Url,
        [Parameter(Mandatory=$true,HelpMessage='Index number of the table from target URL, to be returned (defaults 0)[-TableIndex 2]')]
        [Alias('index')]
			[int]$TableIndex=0,
        [Parameter(Mandatory=$true,HelpMessage='Table header properties to be substituted for the resulting table')]
			$Header,
        [Parameter(Mandatory=$true,HelpMessage='Index Row of table from which to begin returning data (defaults 0)[-FirstDataRow 2]')]
			[int]$FirstDataRow=0,
		[Parameter(Mandatory=$true,HelpMessage='Indicates that the cmdlet should return a summary of all tables currently on the subject URL page.[-summary]')]
			[Switch]$Summary,
        [Parameter(Mandatory=$true,HelpMessage='Indicates that the cmdlet uses the credentials of the current user to send the web request.')]
			[Switch]$UseDefaultCredentials
    ) ; 
    if ($PSVersionTable.PSVersion.Major -gt 5 -and -not (Get-Command ConvertFrom-Html -ErrorAction SilentlyContinue)) {
         # Invoke-WebRequest on .NET core doesn't have ParsedHtml so we need HtmlAgilityPack or similiar Justin Grote's PowerHTML wraps that nicely
         throw "This version of PowerShell needs the PowerHTML module to process HTML Tables."
    }

    $r = Invoke-WebRequest $Url -UseDefaultCredentials: $UseDefaultCredentials
    $propertyNames = $Header

    if ($PSVersionTable.PSVersion.Major -le 5) {
		if(-not $Summary){
			$table = $r.ParsedHtml.getElementsByTagName("table")[$TableIndex]
        } else { 
			write-verbose "Returning target URL table summary"
			if($tbls = $r.ParsedHtml.getElementsByTagName("table")){
				"Index#`t:`ttextContent"  | write-output ; 
				"------`t:`t-----------"  | write-output ; 
				$idx = 0 ; $tbls | foreach-object{ 
					$idx++ ; 
					"$($idx)`t:`t$(($_.textcontent)[0..50] -join '')"  | write-output ; 
				} ; 
				break ; 
			} else { 
			
			} ;
        } ; 
        $totalRows=@($table.rows).count

        for ($idx = $FirstDataRow; $idx -lt $totalRows; $idx++) {

            $row = $table.rows[$idx]
            $cells = @($row.cells)

            if(!$propertyNames) {
                if($cells[0].tagName -eq 'th') {
                    $propertyNames = @($cells | ForEach-Object {$_.innertext -replace ' ',''})
                } else  {
                    $propertyNames =  @(1..($cells.Count + 2) | Foreach-Object { "P$_" })
                }
                continue
            }

            $result = [ordered]@{}

            for($counter = 0; $counter -lt $cells.Count; $counter++) {
                $propertyName = $propertyNames[$counter]

                if(!$propertyName) { $propertyName= '[missing]'}
                $result.$propertyName= $cells[$counter].InnerText
            }

            [PSCustomObject]$result | write-output ; 
        }
    }
    else {
        $h    = ConvertFrom-Html -Content $r.Content
        if ($TableIndex -is [valuetype]) { $TableIndex += 1}
        $rows =    $h.SelectNodes("//table[$TableIndex]//tr")
        if (-not $rows) {Write-Warning "Could not find rows for `"//table[$TableIndex]`" in $Url ."}
        if ( -not  $propertyNames) {
            if (   $tableHeaders  = $rows[$FirstDataRow].SelectNodes("th")) {
                   $propertyNames = $tableHeaders.foreach({[System.Web.HttpUtility]::HtmlDecode( $_.innerText ) -replace '\W+','_' -replace '(\w)_+$','$1' })
                   $FirstDataRow += 1
            }
            else {
                   $c = 0
                   $propertyNames = $rows[$FirstDataRow].SelectNodes("td") | Foreach-Object { "P$c" ; $c ++ }
            }
        }
        Write-Verbose ("Property names: " + ($propertyNames -join ","))
        foreach ($n in $FirstDataRow..($rows.Count-1)) {
            $r      = $rows[$n].SelectNodes("td|th")
            if ($r -and $r.innerText -ne "" -and $r.count -gt $rows[$n].SelectNodes("th").count  ) {
                $c      = 0
                $newObj = [ordered]@{}
                foreach ($p in $propertyNames) {
                    $n  = $null
                    #Join descentandts for cases where the text in the cell is split (e.g with a <BR> ). We also want to remove HTML codes, trim and convert unicode minus sign to "-"
                    $cellText = $r[$c].Descendants().where({$_.NodeType -eq "Text"}).foreach({[System.Web.HttpUtility]::HtmlDecode( $_.innerText ).Trim()}) -Join " " -replace "\u2212","-"
                    if ([double]::TryParse($cellText, [ref]$n)) {$newObj[$p] = $n     }
                    else                                        {$newObj[$p] = $cellText }
                    $c ++
                }
                [pscustomObject]$newObj
            }
        }
    }
}
