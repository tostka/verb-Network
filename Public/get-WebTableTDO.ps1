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
    * 3:25 PM 11/27/2023 added expanded CBH examples
	* 9:25 AM 11/8/2023 ported over from ImportExcel:get-HtmlTable, which is adapted version of Lee Holmes' Get-WebRequestTable.ps1 demo code. 
	add: -Summary param, which dumps a short index#|Summary (leading textcontent[0..56] string)
	add: param detailed out, helpmessage, CBH
	add: strongly typed params
	* 10/12/23 dfinke's adapted variant of LH's original code into ImportExcel:get-htmlTabl(): [PowerShell Gallery | ImportExcel 7.8.6](https://www.powershellgallery.com/packages/ImportExcel/7.8.6) (adds 
	* 1/5/2015 LH's posted code from https://www.leeholmes.com/extracting-tables-from-powershells-invoke-webrequest/
	.DESCRIPTION
	get-WebTableTDO.ps1 - Extract Tables from Web pages (via PowerShellInvoke-WebRequest)

	Original code: [Lee Holmes | Extracting Tables from PowerShell's Invoke-WebRequest](https://www.leeholmes.com/extracting-tables-from-powershells-invoke-webrequest/)
	By way of dFinke's ImportExcel:get-HtmlTable v7.8.6 [ImportExcel/Public/Get-HtmlTable.ps1 at master Â· dfinke/ImportExcel Â· GitHub](https://github.com/dfinke/ImportExcel/blob/master/Public/Get-HtmlTable.ps1)
	
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
	Default output, non specified -TableIndex, which returns contents of first table:
	.EXAMPLE
	PS> get-WebTableTDO -URL "https://en.wikipedia.org/wiki/List_of_Star_Trek:_The_Original_Series_episodes" ; 
	
        Season      Episodes
        ------      --------
        First aired Last aired
        1           29
        2           26
        3           24
    
	Default output, without explicit -TableIndex, outputs the 0'th/first table found on the url.
	.EXAMPLE
	PS> get-WebTableTDO -URL "https://en.wikipedia.org/wiki/List_of_Star_Trek:_The_Original_Series_episodes" -summary
	

            Index#  :       textContent
            ------  :       -----------
            1       :       SeasonEpisodesOriginally airedFirst airedLast aired
            2       :       TitleDirected byWritten byOriginal air date [23][25
            3       :       No.overallNo. inseasonTitleDirected byWritten byOri
            4       :       No.overallNo. inseasonTitleDirected byWritten byOri
            5       :       No.overallNo. inseasonTitleDirected byWritten byOri
            6       :       Pilots 01"The Cage" 02a"Where No Man Has Gone Befor
            7       :       Season 1 02b"Where No Man Has Gone Before" 03"The C
            8       :       Season 2 30"Catspaw" 31"Metamorphosis" 32"Friday's
            9       :       Season 3 56"Spectre of the Gun" 57"Elaan of Troyius
            10      :       This section needs additional citations for verific
            11      :       vteStar Trek: The Original Series episodesSeasons 1
            12      :       vteStar Trek: The Original SeriesEpisodesSeason 1 2
            13      :       vteStar TrekOutline Timeline Canon ListsTelevision
            14      :       Live-actionThe Original Series episodesThe Next Gen
            15      :       The Original SeriesThe Motion Picture The Wrath of
            16      :       CharactersA–F G–M N–S T–ZCrossoversConceptsGames Ko

	Retrieve tables list and echo simple heading summary of each table (useful to determine which -tableIndex # to use for specific table retrieval).
	.EXAMPLE
    PS> get-WebTableTDO -URL "https://en.wikipedia.org/wiki/List_of_Star_Trek:_The_Original_Series_episodes" -index 2 | format-table -a ;

        No.          No.in         Title                             Directedby                    Writtenby
        overall      season
        ------------ ------------- -----                             ----------                    ---------
        1            1             "The Man Trap"                    Marc Daniels                  George Clayton Johnson
        2            2             "Charlie X"                       Lawrence Dobkin               Story by : Gene Roddenberry...
        3            3             "Where No Man Has Gone Before"    James Goldstone               Samuel A. Peeples
       ...TRIMMED...
        27           27            "The Alternative Factor"          Gerd Oswald                   Don Ingalls
        28           28            "The City on the Edge of Forever" Joseph Pevney                 Harlan Ellison
        29           29            "Operation -- Annihilate!"        Herschel Daugherty            Steven W. Carabatsos

    Retrieve the index 2 ("third") table on the specified page, and output format-table -auto, to align data into columns.
    .EXAMPLE
    PS> $data = get-WebTableTDO -Url $Url -TableIndex $Index -Header $Header -FirstDataRow $FirstDataRow -UseDefaultCredentials: $UseDefaultCredentials
    PS> $data | Export-Excel $xlFile -Show -AutoSize ; 
    Demo conversion, with export-excel exporting xlsx, and opening ase temp file in Excel
    .LINK
	https://github.com/tostka/verb-Network
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
        [Parameter(HelpMessage='Index number of the table from target URL, to be returned (defaults 0)[-TableIndex 2]')]
        [Alias('index')]
			[int]$TableIndex=0,
        [Parameter(HelpMessage='Table header properties to be substituted for the resulting table')]
			$Header,
        [Parameter(HelpMessage='Index Row of table from which to begin returning data (defaults 0)[-FirstDataRow 2]')]
			[int]$FirstDataRow=0,
		[Parameter(HelpMessage='Indicates that the cmdlet should return a summary of all tables currently on the subject URL page.[-summary]')]
			[Switch]$Summary,
        [Parameter(HelpMessage='Indicates that the cmdlet uses the credentials of the current user to send the web request.')]
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
