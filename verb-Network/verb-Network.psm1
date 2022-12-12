﻿# verb-network.psm1


<#
.SYNOPSIS
verb-Network - Generic network-related functions
.NOTES
Version     : 2.2.0.0
Author      : Todd Kadrie
Website     :	https://www.toddomation.com
Twitter     :	@tostka
CreatedDate : 4/8/2020
FileName    : verb-Network.psm1
License     : MIT
Copyright   : (c) 4/8/2020 Todd Kadrie
Github      : https://github.com/tostka
REVISIONS
* 4/8/2020 - 1.0.0.0
# 12:44 PM 4/8/2020 pub cleanup
# 8:20 AM 3/31/2020 shifted Send-EmailNotif fr verb-smtp.ps1
# 11:38 AM 12/30/2019 ran vsc alias-expan
# 11:41 AM 11/1/2017 initial version
.DESCRIPTION
verb-Network - Generic network-related functions
.LINK
https://github.com/tostka/verb-Network
#>


    $script:ModuleRoot = $PSScriptRoot ;
    $script:ModuleVersion = (Import-PowerShellDataFile -Path (get-childitem $script:moduleroot\*.psd1).fullname).moduleversion ;
    $runningInVsCode = $env:TERM_PROGRAM -eq 'vscode' ;

#*======v FUNCTIONS v======




#*------v Add-IntToIPv4Address.ps1 v------
function Add-IntToIPv4Address {
<#
    .SYNOPSIS
    Add-IntToIPv4Address.ps1 - Add an integer to an IP Address and get the new IP Address.
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2021-08-16
    FileName    : Add-IntToIPv4Address.ps1
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,Network,IP,Subnet
    AddedCredit :  Brian Farnsworth
    AddedWebsite: https://codeandkeep.com/
    AddedTwitter: 
    REVISIONS
    * 1:29 PM 8/12/2021 tweaked CBH, minor param inline help etc.
    * 9/10/2019 Mark Wragg posted rev (corresponds to PSG v1.1.14)
    .DESCRIPTION
    Add an integer to an IP Address and get the new IP Address.
    .PARAMETER IP
    The IP Address to add an integer to [-IP 192.168.0.1]
    .PARAMETER Integer
    An integer to add to the IP Address. Can be a positive or negative number[-integer 1].
    .EXAMPLE
    .EXAMPLE
    Add-IntToIPv4Address -IPv4Address 10.10.0.252 -Integer 10
    10.10.1.6
    Description
    -----------
    This command will add 10 to the IP Address 10.10.0.1 and return the new IP Address.
    .EXAMPLE
    Add-IntToIPv4Address -IPv4Address 192.168.1.28 -Integer -100
    192.168.0.184
    Description
    -----------
    This command will subtract 100 from the IP Address 192.168.1.28 and return the new IP Address.
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://codeandkeep.com/PowerShell-Get-Subnet-NetworkID/
    #>
    ##Requires -Modules DnsClient
    [CmdletBinding()]
    Param(
      [parameter(HelpMessage="The IP address to test[-IP 192.168.0.1]")]
      [String]$IP,
      [parameter(HelpMessage="An integer to add to the IP Address. Can be a positive or negative number[-integer 1]")]
      [int64]$Integer
    )
    BEGIN {
        ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
        $Verbose = ($VerbosePreference -eq 'Continue') ; 
    } ;  # BEG-E
    PROCESS {
        Try{
            #$ipInt=ConvertIPv4ToInt -IP $IP  -ErrorAction Stop ; 
            $ipInt=Convert-IPtoInt64 -IP $IP  -ErrorAction Stop ; 
            $ipInt+=$Integer ; 
            #ConvertIntToIPv4 -Integer $ipInt ; 
            convert-Int64toIP -int $ipInt  |write-output ; 
        }Catch{
              Write-Error -Exception $_.Exception -Category $_.CategoryInfo.Category ; 
        } ; 
    } ;  # PROC-E
    END {}
}

#*------^ Add-IntToIPv4Address.ps1 ^------


#*------v Connect-PSR.ps1 v------
Function Connect-PSR {
    <#
    .SYNOPSIS
    Connect-PSR - Setup Remote Powershell connection
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-06-09
    FileName    : Reconnect-PSR.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell,Remote
    REVISIONS
    * 8:56 AM 6/9/2020 added to verb-Network ; added verbose echo
    * 9:34 AM 12/21/2016 port to Powershell remote
    * 12:09 PM 12/9/2016 implented and debugged as part of verb-PSR set
    * 2:37 PM 12/6/2016 ported to local EMSRemote
    * 2/10/14 posted version 
    .DESCRIPTION
    Connect-PSR - Setup Remote Powershell connection
    $Credential can leverage a global: $Credential = $global:SIDcred
    .PARAMETER  Server
    Server to Remote to
    .PARAMETER CommandPrefix
    No console feedback 
    .PARAMETER Silent
    No console feedback 
    .PARAMETER  Credential
    Credential object
    .EXAMPLE
    # -----------
    try{    
        $reqMods="Connect-PSR;Reconnect-PSR;Disconnect-PSR;Disconnect-PssBroken;Cleanup".split(";") ; 
        $reqMods | % {if( !(test-path function:$_ ) ) {write-error "$((get-date).ToString("yyyyMMdd HH:mm:ss")):Missing $($_) function. EXITING." } } ; 
        Reconnect-PSR ; 
    } CATCH {
        Write-Warning "$(get-date -format 'HH:mm:ss'): Failed processing $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ;
        Exit #STOP(debug)|EXIT(close)|Continue(move on in loop cycle) ; 
    } ; 
    # -----------
    .LINK
    #>
    [CmdletBinding()]
    [Alias('cPSR')]
    Param( 
        [Parameter(Position=0,Mandatory=$True,HelpMessage="Server to Remote to")][Alias('__ServerName', 'Computer')]
        [string]$Server,
        [Parameter(HelpMessage="OptionalCommand Prefix for cmdlets from this session[PSR]")][string]$CommandPrefix,
        [Parameter(HelpMessage = 'Credential object')][System.Management.Automation.PSCredential]$Credential = $credTORSID,
        [Parameter(HelpMessage='Silent flag [-silent]')][switch]$silent
    )  ; 
    $verbose = ($VerbosePreference -eq "Continue") ; 
    if(!$silent){
        write-verbose -verbose:$true  "$((get-date).ToString("yyyyMMdd HH:mm:ss")):Adding Remote PS (connecting to $($Server))..." ; 
    } ; 
    
    $PSRsplat=@{ComputerName=$server ; Name="PSR"} ;
    # credential support
    if($Credential){ $PSRsplat.Add("Credential",$Credential) } ; 
    # -Authentication Basic only if specif needed: for Ex configured to connect via IP vs hostname)
    write-verbose "$((get-date).ToString('HH:mm:ss')):New-PSSession w`n$(($PSRsplat|out-string).trim())" ; 
    $error.clear() ;
    TRY {
      $Global:PSRSess = New-PSSession @PSRSplat -ea stop ;
    } CATCH {
      $ErrTrapd = $_ ; 
      write-warning "$(get-date -format 'HH:mm:ss'): Failed processing $($ErrTrapd.Exception.ItemName). `nError Message: $($ErrTrapd.Exception.Message)`nError Details: $($ErrTrapd)" ;
    } ;
}

#*------^ Connect-PSR.ps1 ^------


#*------v Disconnect-PSR.ps1 v------
Function Disconnect-PSR {
    <# 
    .SYNOPSIS
    Disconnect-PSR - Clear Remote Powershell connection
    .NOTES
    Author: Todd Kadrie
    Website:	http://tinstoys.blogspot.com
    Twitter:	http://twitter.com/tostka
    Inspired By: ExactMike Perficient, Global Knowl... (Partner)  
    Website:	https://social.technet.microsoft.com/Forums/msonline/en-US/f3292898-9b8c-482a-86f0-3caccc0bd3e5/exchange-powershell-monitoring-remote-sessions?forum=onlineservicesexchange
    REVISIONS   :
    * 2:56 PM 12/21/2016 add a pretest suppress not found error
    * 9:34 AM 12/21/2016 port to Powershell remote
    * 12:54 PM 12/9/2016 cleaned up, add pshelp
    * 12:09 PM 12/9/2016 implented and debugged as part of verb-PSR set
    * 2:37 PM 12/6/2016 ported to local EMSRemote
    * 2/10/14 posted version 
    .DESCRIPTION
    Disconnect-PSR - Clear Remote Powershell connection
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output.
    .EXAMPLE
    Disconnect-PSR ; 
    .LINK
    #>
        <#
    .SYNOPSIS
    Disconnect-PSR - Clear Remote Powershell connection
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-06-09
    FileName    : Disconnect-PSR .ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell,Remote
    REVISIONS
    * 2:56 PM 12/21/2016 add a pretest suppress not found error ; port to Powershell remote
    * 12:54 PM 12/9/2016 cleaned up, add pshelp ;implented and debugged as part of verb-PSR set
    * 2:37 PM 12/6/2016 ported to local EMSRemote
    .DESCRIPTION
    Disconnect-PSR - Clear Remote Powershell connection
    .EXAMPLE
    .\Disconnect-PSR .ps1
    .EXAMPLE
    .\Disconnect-PSR .ps1
    .LINK
    #>
    [CmdletBinding()]
    [Alias('dPSR')]
    Param() ;
    $verbose = ($VerbosePreference -eq "Continue") ; 
    if($Global:PSRSess){$Global:PSRSess | Remove-PSSession ; } ; 
    # kill any other sessions using my distinctive name; add verbose, to ensure they're echo'd that they were missed
    Get-PSSession |? {$_.name -eq 'PSR'} | Remove-PSSession -verbose ;
}

#*------^ Disconnect-PSR.ps1 ^------


#*------v download-file.ps1 v------
function download-file {
    <#
    .SYNOPSIS
    download-file.ps1 - simple download client
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2020-04-17
    FileName    : download-file.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell,Internet,Download,File
    REVISIONS
    11:31 AM 4/17/2020 added CBH
    .DESCRIPTION
    download-file.ps1 - simple download client
    .PARAMETER  url
    Url to be downloaded
    .PARAMETER  DestinationName
    Full path to destiontion file for download
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output
    .EXAMPLE
    download-file -url https://xxx -destinationname c:\pathto\file.ext
    .LINK
    #>
        [CmdletBinding()]
        PARAM ([string]$url, [string]$DestinationName)
        $rgxURLParse = "^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?" ;
        if ($url -match $rgxURLParse) {
            $host = $matches[4] ;
            if (test-connection -ComputerName $host -count 1) {
                $client = new-object system.net.WebClient
                $client.Headers.Add("user-agent", "PowerShell")
                $client.downloadfile($url, $DestinationName)
            }
            else {
                throw "unable to Ping $()" ;
            } ;
        }
        else {
            throw "Unparsable url, to fqdn:$($url)" ;
        } ;
    }

#*------^ download-file.ps1 ^------


#*------v download-filecurl.ps1 v------
function download-filecurl {
    <#
    .SYNOPSIS
    download-filecurl.ps1 - simple download wrapper around curl cmdline util
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2020-04-17
    FileName    : download-filecurl.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell,Internet,Download,File
    REVISIONS
    11:31 AM 4/17/2020 added CBH
    .DESCRIPTION
    download-filecurl.ps1 - simple download client
    .PARAMETER  url
    Url to be downloaded
    .PARAMETER  DestinationName
    Full path to destiontion file for download
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output
    .EXAMPLE
    download-filecurl -url https://xxx -destinationname c:\pathto\file.ext
    .LINK
    #>
    PARAM ([string]$url, [string]$DestinationName)
    $CurlArgument = '-o $($DestinationName)', '$($url)' ;
    if (($PSVersionTable.PSEdition -eq 'Desktop') -OR ($IsCoreCLR -AND $IsWindows) -OR !$PSVersionTable.PSEdition) {$CURLEXE = "$env:windir\System32\curl.exe" } ; 
    elseif ($IsCoreCLR -AND $IsLinux) {$CURLEXE = 'curl'} ;
    & $CURLEXE @CurlArgument ;
}

#*------^ download-filecurl.ps1 ^------


#*------v download-fileNoSSL.ps1 v------
function download-fileNoSSLNoSSL {
    <#
    .SYNOPSIS
    download-fileNoSSLNoSSL.ps1 - simple download client - overridding the SSL trust requirement to get the file (insecure, for testing)
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2020-04-17
    FileName    : download-fileNoSSL.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell,Internet,Download,File
    REVISIONS
    * 11:31 AM 4/17/2020 added CBH
    * 3:04 PM 8/13/2014
    .DESCRIPTION
    download-fileNoSSL.ps1 - simple download client - overridding the SSL trust requirement to get the file (insecure, for testing)
    .PARAMETER  url
    Url to be downloaded
    .PARAMETER  DestinationName
    Full path to destiontion file for download
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output
    .EXAMPLE
    $url = "http://www.cs.wisc.edu/~ballard/bofh/excuses" ; 
    $DestinationName = "c:\temp\temp.html" ; 
    download-file $url $DestinationName
    .LINK
    http://blogs.technet.com/b/bshukla/archive/2010/04/12/ignoring-ssl-trust-in-powershell-system-net-webclient.aspx
    #>
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } ;
        $client = new-object system.net.WebClient ;
        if ($DestinationName) {
            $client.DownloadString($url) | out-file -FilePath $local;
        }
        else {
            # stream to console
            $client.DownloadString($url) ;
        } # if-block end
        # not sure if toggle back is necesesary, but try it
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $false } ;
    }

#*------^ download-fileNoSSL.ps1 ^------


#*------v get-DNSServers.ps1 v------
function get-DNSServers{
    <#
    .SYNOPSIS
    get-DNSServers.ps1 - Get the DNS servers list of each IP enabled network connection
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2021-01-14
    FileName    : get-DNSServers.ps1
    License     : (non specified)
    Copyright   : (non specified)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,Network,DNS
    AddedCredit : Sitaram Pamarthi
    AddedWebsite:	http://techibee.com
    REVISIONS
    * 2:42 PM 11/2/2021 scratch refactor borked CBH, fixed
    * 3:00 PM 1/14/2021 updated CBH, minor revisions & tweaking
    .DESCRIPTION
    get-DNSServers.ps1 - Get the DNS servers list of each IP enabled network connection
    .Parameter ComputerName
    Computer Name(s) from which you want to query the DNS server details. If this
    parameter is not used, the the script gets the DNS servers from local computer network adapaters.
    .EXAMPLE
    Get-DNSServers -ComputerName MYTESTPC21 ;
    Get the DNS servers information from a remote computer MYTESTPC21.
    .LINK
    https://github.com/tostka/verb-Network
    #>
    [cmdletbinding()]
    param (
      [parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
      [string[]] $ComputerName = $env:computername
    )
    begin {}
    process {
      foreach($Computer in $ComputerName) {
        Write-Verbose "Working on $Computer"
        if(Test-Connection -ComputerName $Computer -Count 1 -ea 0) {
          try {
            $Networks = Get-WmiObject -Class Win32_NetworkAdapterConfiguration  -Filter IPEnabled=TRUE  -ComputerName $Computer  -ErrorAction Stop ; 
          } catch {
            Write-Verbose "Failed to Query $Computer. Error details: $_"
            continue
          }
          foreach($Network in $Networks) {
            $DNSServers = $Network.DNSServerSearchOrder
            $NetworkName = $Network.Description
            If(!$DNSServers) {
              $PrimaryDNSServer = "Notset"
              $SecondaryDNSServer = "Notset"
            } elseif($DNSServers.count -eq 1) {
              $PrimaryDNSServer = $DNSServers[0]
              $SecondaryDNSServer = "Notset"
            } else {
              $PrimaryDNSServer = $DNSServers[0]
              $SecondaryDNSServer = $DNSServers[1]
            }
            If($network.DHCPEnabled) {
              $IsDHCPEnabled = $true
            }
            $OutputObj  = New-Object -Type PSObject
            $OutputObj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $Computer.ToUpper()
            $OutputObj | Add-Member -MemberType NoteProperty -Name PrimaryDNSServers -Value $PrimaryDNSServer
            $OutputObj | Add-Member -MemberType NoteProperty -Name SecondaryDNSServers -Value $SecondaryDNSServer
            $OutputObj | Add-Member -MemberType NoteProperty -Name IsDHCPEnabled -Value $IsDHCPEnabled
            $OutputObj | Add-Member -MemberType NoteProperty -Name NetworkName -Value $NetworkName
            $OutputObj
          }
        } else {
          Write-Verbose "$Computer not reachable"
        }
      }
    }
    end {} ; 
}

#*------^ get-DNSServers.ps1 ^------


#*------v get-IPSettings.ps1 v------
function get-IPSettings {
    <#
    .SYNOPSIS
    get-IPSettings.ps1 - retrieve DNSHostName, ServiceName(nic), DNSServerSearchOrder, IPAddress & DefaultIPGateway for localhost
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2020-04-17
    FileName    : get-IPSettings.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell,Internet,Download,File
    REVISIONS
    11:31 AM 4/17/2020 added CBH
    .DESCRIPTION
    get-IPSettings.ps1 - retrieve DNSHostName, ServiceName(nic), DNSServerSearchOrder, IPAddress & DefaultIPGateway for localhost
    by iteself it returns the set as the object $OPSpecs
    .PARAMETER  url
    Url to be downloaded
    .PARAMETER  DestinationName
    Full path to destiontion file for download
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    Selected.System.Management.ManagementObject
    .EXAMPLE
    get-IPSettings
    Return the complete set of values
    .EXAMPLE
    (get-ipsettings).IPAddress
    Return solely the IPAddress value
    .LINK
    #>
        [CmdletBinding()]
        PARAM ()
$IPSpecs = Get-WMIObject Win32_NetworkAdapterConfiguration -Computername localhost | where { $_.IPEnabled -match "True" } | Select -property DNSHostName, ServiceName, @{N = "DNSServerSearchOrder"; E = { "$($_.DNSServerSearchOrder)" } }, @{N = 'IPAddress'; E = { $_.IPAddress } }, @{N = 'DefaultIPGateway'; E = { $_.DefaultIPGateway } } ;
    return $IPSpecs;
}

#*------^ get-IPSettings.ps1 ^------


#*------v Get-NetIPConfigurationLegacy.ps1 v------
function Get-NetIPConfigurationLegacy {
    <#
    .SYNOPSIS
    Get-NetIPConfigurationLegacy.ps1 - Wrapper for ipconfig, as Legacy/alt version of PSv3+'s 'get-NetIPConfiguration' cmdlet (to my knowledge) by get-NetIPConfiguration.
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 20210114-1055AM
    FileName    : 
    License     : MIT License
    Copyright   : (c) 2021 Todd Kadrie
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,Network,Ipconfig,Legacy
    AddedCredit : REFERENCE
    AddedWebsite:	URL
    AddedTwitter:	URL
    REVISIONS
    * 2:29 PM 11/2/2021 # flip $nic[dot]description to alt syntax: I think it's breaking CBH get-help parsing. ; refactored cbh from scra6tch, trying to get the get-help support to work properly, I'll bet you it's: $nic[period]Description = (
    * 11:02 AM 1/14/2021 initial vers. Still needs to accomodate Wins Servers (aren't config'd on my box):
    Connection-specific DNS Suffix  . :
       Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
       Physical Address. . . . . . . . . : 00-50-56-9D-93-7E
       DHCP Enabled. . . . . . . . . . . : No
       Autoconfiguration Enabled . . . . : Yes
       IPv4 Address. . . . . . . . . . . : 170.92.16.155(Preferred)
       Subnet Mask . . . . . . . . . . . : 255.255.255.0
       Default Gateway . . . . . . . . . : 170.92.16.254
       DNS Servers . . . . . . . . . . . : 170.92.16.157
                                           170.92.48.249
       Primary WINS Server . . . . . . . : 170.92.17.42
       Secondary WINS Server . . . . . . : 170.92.16.44
       NetBIOS over Tcpip. . . . . . . . : Enabled
    .DESCRIPTION
    Get-NetIPConfigurationLegacy.ps1 - Wrapper for ipconfig, as Legacy/alt version of PSv3+'s 'get-NetIPConfiguration' cmdlet (to my knowledge) by get-NetIPConfiguration.
    .INPUT
    Does not accept pipeline input
    .OUTPUT
    System.Object[]
    .EXAMPLE
    $nics = Get-NetIPConfigurationLegacy ; 
    Return an object summarizing the specs on all nics
    .EXAMPLE
    $DNSServer = (Get-NetIPConfigurationLegacy | ?{$_.DNSServers -AND $_.AdapterName -like 'PPP*'}).DNSServers[0] ; 
    Retrieve the first configured 'DNS Servers' entry on the Adapter named like 'PPP*'
    .LINK
    https://github.com/tostka/verb-Network
    #>
    [CmdletBinding()]
    Param () ; 
    $nicprops = [ordered]@{
        AdapterName = "" ;
        ConnectionspecificDNSSuffix  = "" ;
        MediaState = "" ;
        Description = "" ;
        MacAddress = "" ;
        DHCPEnabled = "" ;
        AutoconfigurationEnabled = "" ;
        IPv4Address = @("") ;
        SubnetMask = "" ;
        DefaultGateway = "" ;
        DNSServers = @("") ;
        NetBIOSoverTcpip = "" ;
        ConnectionspecificDNSSuffixSearchList = @("") ;
        BindingOrder = 0 ; 
    } ;
    $nics = @(); 
    $rgxIPv4='\b(?:\d{1,3}\.){3}\d{1,3}\b' ; 
    $error.clear() ;
    TRY {
        $output = ipconfig /all ;
        $bindingorder = 0 ; 
        for($i=0; $i -le ($output.Count -1); $i++) {
            if ($output[$i] -match 'Connection-specific\sDNS\sSuffix\s\s\.'){
                if ($output[$i-1] -match 'Media\sState\s\.\s\.\s\.\s\.\s\.\s\.\s\.\s\.\s\.\s\.\s\.'){
                    $nic = New-Object -TypeName psobject -Property $nics2 ;            
                    $nic.AdapterName =($output[$i - 3] -split -split ": ")[0].trim()  ;            
                    $nic.MediaState = ($output[$i-1] -split -split ": ")[1].trim()  ;
                    if($nic.MediaState -eq 'Media disconnected'){$nic.MediaState = 'disconnected' } else { $nic.MediaState = 'connected'} ;
                    $nic.ConnectionspecificDNSSuffix  = ($output[$i] -split -split ": ")[1].trim()  ;
                    # flip [dot]description to alt syntax: I think it's breaking CBH get-help parsing.
                    $nic["Description"] = ($output[$i+1] -split -split ": ")[1].trim() ;
                    $nic.MacAddress = ($output[$i+2] -split -split ": ")[1].trim() ;
                    $nic.DHCPEnabled = [boolean](($output[$i+3] -split -split ": ")[1].trim() -eq 'Yes') ; 
                    $nic.AutoconfigurationEnabled = [boolean](($output[$i+4] -split -split ": ")[1].trim() -eq 'Yes') ;  ;
                    $nic.BindingOrder = [int]$bindingorder ; 
                    $bindingorder++ ; 
                    $nics += $nic ;
                } elseif ($output[$i+1] -match 'Description\s\.\s\.\s\.\s\.\s\.\s\.\s\.\s\.\s\.\s\.\s\.') {
                    $nic = New-Object -TypeName psobject -Property $nicprops ;
                    $nic.AdapterName = ($output[$i-2] -split -split ": ")[0].trim()  ;
                    $nic.ConnectionspecificDNSSuffix  = ($output[$i] -split -split ": ")[1].trim()  ;
                    $nic["Description"] = ($output[$i+1] -split -split ": ")[1].trim() ;
                    $nic.MacAddress = ($output[$i+2] -split -split ": ")[1].trim() ;
                    $nic.DHCPEnabled = [boolean](($output[$i+3] -split -split ": ")[1].trim() -eq 'Yes') ;
                    $nic.AutoconfigurationEnabled = ($output[$i+4] -split -split ": ")[1].trim() ;
                    $nic.AutoconfigurationEnabled = [boolean]($nic.AutoconfigurationEnabled -eq 'Yes') ; 
                    $nic.IPv4Address = ($output[$i+5] -split ": ")[1].trim().replace('(Preferred)','(Pref)') ;
                    $nic.SubnetMask = ($output[$i+6] -split ": ")[1].trim() ;
                    $nic.DefaultGateway = ($output[$i+7] -split ": ")[1].trim() ;
                    $nic.DNSServers = @(($output[$i+8] -split ": ")[1].trim()) ;
                    for($j=$i+9;; $j++) {
                        # walk list until NetBios line
                        if($output[$j] -notmatch 'NetBIOS\sover\sTcpip\.\s\.\s\.\s\.\s\.\s\.\s\.\s\.'){
                            $nic.DNSServers+=$output[$j].trim() ; 
                        } else {break}; 
                    } ; 
                    $i = $j ; 
                    $nic.NetBIOSoverTcpip = [boolean](($output[$i] -split ": ")[1].trim() -eq 'Enabled') ; 
                    if($output[$i+1] -match 'Connection-specific\sDNS\sSuffix\sSearch\sList'){
                        #walk list until first line *not* containing an ipaddr
                        $nic.ConnectionspecificDNSSuffixSearchList = @($output[$i+2].trim()) ;
                        for($j=$i+3;; $j++) {
                            if($output[$j].trim -match $rgxIPv4){
                                $nic.ConnectionspecificDNSSuffixSearchList+=$output[$j].trim() ;
                            } else {break}; 
                        } ; 
                    } ; 
                    $nic.BindingOrder = [int]$bindingorder ; 
                    $bindingorder++ ; 
                    $nics += $nic ;
                };
            } else {
                continue 
            } ;
        } ;
        $nics | sort bindingorder | write-output ; 
    } CATCH {
        Write-Warning "$(get-date -format 'HH:mm:ss'): Failed processing $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ;
        $smsg = "FULL ERROR TRAPPED (EXPLICIT CATCH BLOCK WOULD LOOK LIKE): } catch[$($Error[0].Exception.GetType().FullName)]{" ; 
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level ERROR } #Error|Warn|Debug 
        else{ write-warning "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        Exit #Opts: STOP(debug)|EXIT(close)|CONTINUE(move on in loop cycle)|BREAK(exit loop iteration)|THROW $_/'CustomMsg'(end script with Err output)
    } ; 
}

#*------^ Get-NetIPConfigurationLegacy.ps1 ^------


#*------v get-NetworkClass.ps1 v------
function get-NetworkClass {
    <#
    .SYNOPSIS
    get-NetworkClass.ps1 - Use to determine the network class of a given IP address.
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2021-08-16
    FileName    : get-NetworkClass.ps1
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,Network,IP,Subnet
    AddedCredit : Mark Wragg
    AddedWebsite: https://github.com/markwragg
    AddedTwitter: 
    REVISIONS
    * 2:49 PM 11/2/2021 refactor/fixed CBH
    * 1:29 PM 8/12/2021 tweaked CBH, minor param inline help etc.
    * 9/10/2019 Mark Wragg posted rev (corresponds to PSG v1.1.14)
    .DESCRIPTION
    get-NetworkClass.ps1 - Use to determine the network class of a given IP address.
    .PARAMETER IP
    The IP address to test[-IP 192.168.0.1]
    .EXAMPLE
    '10.1.1.1' | Get-NetworkClass
    Result
    ------
    A
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://github.com/markwragg/PowerShell-Subnet/blob/master/Subnet/Public/Test-PrivateIP.ps1
    #>

    ###Requires -Modules DnsClient
    [CmdletBinding()]
    PARAM (
        [parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="The IP address to test[-IP 192.168.0.1]")]
        [string]$IP
    )
    BEGIN {
        ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
        $Verbose = ($VerbosePreference -eq 'Continue') ; 
    } ;  # BEG-E
    PROCESS {
        switch ($IP.Split('.')[0]) {
            { $_ -in 0..127 } { 'A' }
            { $_ -in 128..191 } { 'B' }
            { $_ -in 192..223 } { 'C' }
            { $_ -in 224..239 } { 'D' }
            { $_ -in 240..255 } { 'E' }
        } ;
    } ;  # PROC-E
    END {}
}

#*------^ get-NetworkClass.ps1 ^------


#*------v Get-RestartInfo.ps1 v------
function Get-RestartInfo {
    <#
    .SYNOPSIS
    Get-RestartInfo.ps1 - Returns reboot / restart event log info for specified computer
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2022-
    FileName    : 
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell
    AddedCredit : Mike Kanakos/compwiz32 
    AddedWebsite: https://www.commandline.ninja
    AddedTwitter:	
    REVISIONS
    * 2:14 PM 8/22/2022 expanded, have it dynamically locate a manual reboot in last $MaxDay days; runs setuplog evts & summary, and app log msinstaller evts summar; added minior formatting updates & CBH expansion
    * CREATED: 2016-09-27
    * LASTEDIT: 2019-12-17
    * CREDIT: Biswajit Biswas
    .DESCRIPTION
    Queries the system event log and returns all log entries related to reboot & shutdown events (event ID 1074)
    MISC: Function based on script found at:
    https://social.technet.microsoft.com/wiki/contents/articles/17889.powershell-script-for-shutdownreboot-events-tracker.aspx
    .PARAMETER ComputerName
    Specifies a computer to add the users to. Multiple computers can be specified with commas and single quotes
    (-Computer 'Server01','Server02')
    .PARAMETER Credential
    Specifies the user you would like to run this function as
    .PARAMETER MaxDays
    Maximum days ago, that a manual reboot should be checked for (drives logic between manual reboot detection, and finding last reboot of *any* type).
    .EXAMPLE
    Get-RestartInfo
    This command will return all the shutdown/restart eventlog info for the local computer.
    PS C:\Scripts\> Get-RestartInfo
    Computer : localhost
    Date     : 1/7/2019 5:16:50 PM
    Action   : shutdown
    Reason   : No title for this reason could be found
    User     : NWTRADERS.MSFT\Tom_Brady
    Process  : C:\WINDOWS\system32\shutdown.exe (CRDNAB-PC06LY52)
    Comment  :
    Computer : localhost
    Date     : 1/4/2019 5:36:58 PM
    Action   : shutdown
    Reason   : No title for this reason could be found
    User     : NWTRADERS.MSFT\Tom_Brady
    Process  : C:\WINDOWS\system32\shutdown.exe (CRDNAB-PC06LY52)
    Comment  :
    Computer : localhost
    Date     : 1/4/2019 9:10:11 AM
    Action   : restart
    Reason   : Operating System: Upgrade (Planned)
    User     : NT AUTHORITY\SYSTEM
    Process  : C:\WINDOWS\servicing\TrustedInstaller.exe (CRDNAB-PC06LY52)
    Comment  :
    .EXAMPLE
    PS> Get-RestartInfo SERVER01 | Format-Table -AutoSize
            Computer    Date                  Action  Reason                                  User
            --------    ----                  ------  ------                                  ----
            SERVER01    12/15/2018 6:21:45 AM restart No title for this reason could be found NT AUTHORITY\SYSTEM
            SERVER01    11/17/2018 6:57:53 AM restart No title for this reason could be found NT AUTHORITY\SYSTEM
            SERVER01    9/29/2018  6:47:50 AM restart No title for this reason could be found NT AUTHORITY\SYSTEM
            Example using the default original code 
    .EXAMPLE
    PS> get-restartinfo -ComputerName 'SERVER1','SERVER2' -Verbose ;
        14:09:10:
        #*======v Get-RestartInfo:SERVER1 v======
        VERBOSE: (pulling reboot events System 1074)
        VERBOSE: Constructed structured query:
        <QueryList><Query Id="0" Path="system"><Select Path="system">*[(System/EventID=1074)]</Select></Query></QueryList>.
        Manual Reboot detected!
        TimeCreated  : 8/21/2022 10:02:26 PM
        ProviderName : USER32
        Id           : 1074
        Message      : The process C:\Windows\system32\winlogon.exe (SERVER1) has initiated the restart of computer SERVER1 on behalf of user DOMAIN\ACCOUNT for the following reason: No title for this reason could be found
                        Reason Code: 0x500ff
                        Shutdown Type: restart
                        Comment:
        VERBOSE: (calculating Start & End as -/+ 20 mins of newest 1074)
        14:09:12:
        #*------v $SetupEvts : v------
        VERBOSE: Constructed structured query:
        <QueryList><Query Id="0" Path="setup"><Select Path="setup">*[(System/TimeCreated[@SystemTime&gt;='2022-08-22T02:42:26.000Z' and @SystemTime&lt;='2022-08-22T03:22:26.000Z'])]</Select></Query></QueryList>.

        Date                  EventID Process                          Reason
        ----                  ------- -------                          ------
        8/21/2022 9:58:32 PM        4 Update for Windows (KB2775511)
        8/21/2022 9:58:33 PM        2 "Update for Windows (KB2775511)"
        8/21/2022 10:03:43 PM       2 KB2775511                        Installed


        14:09:12:
        #*------^ $SetupEvts : ^------
        14:09:12:
        #*------v $patchevts : v------
        14:09:12:Get-WinEvent w
        Name                           Value
        ----                           -----
        EndTime                        8/21/2022 10:22:26 PM
        LogName                        Application
        ProviderName                   {MsiInstaller, Microsoft-Windows-RestartManager}
        StartTime                      8/21/2022 9:42:26 PM
        id                             {1033, 1035, 1036, 1040...}
        VERBOSE: Found matching provider: MsiInstaller
        VERBOSE: The MsiInstaller provider writes events to the Application log.
        VERBOSE: Found matching provider: Microsoft-Windows-RestartManager
        VERBOSE: The Microsoft-Windows-RestartManager provider writes events to the Application log.
        VERBOSE: The Microsoft-Windows-RestartManager provider writes events to the Microsoft-Windows-RestartManager/Operational log.
        VERBOSE: Constructed structured query:
        <QueryList><Query Id="0" Path="application"><Select Path="application">*[System/Provider[@Name='msiinstaller' or @Name='microsoft-windows-restartmanager'] and (System/TimeCreated[@SystemTime&gt;='2022-08-22T02:42:26.000Z' and
        @SystemTime&lt;='2022-08-22T03:22:26.000Z']) and ((System/EventID=1033) or (System/EventID=1035) or (System/EventID=1036) or (System/EventID=1040) or (System/EventID=1042) or (System/EventID=100000) or (System/EventID=100001))]</Select></Query></QueryList>.
        14:09:13:PatchEvts 1035|1036: w
        Date                  EventID Process                      Reason Message
        ----                  ------- -------                      ------ -------
        8/21/2022 10:03:40 PM    1035 Configuration Manager Client 1033   Windows Installer reconfigured the product. Product Name: Configuration Manager Client. Product Version: 4.00.6487.2000. Product Language: 1033. Manufacturer: Microsoft Corporation. Reconfigura...

        14:09:13:
        #*------^ $patchevts : ^------
        14:09:13:
        #*======^ Get-RestartInfo:SERVER1 ^======
    Example running an array of computers, verbose, demo'ing typical manual reboot System setup & Application patch-related events summary
    .LINK
    https://github.com/tostka/verb-IO
    https://github.com/compwiz32
    #>
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [alias("Name","MachineName","Computer")]
        [string[]]
        $ComputerName = 'localhost',
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,
        [int]$MaxDays = 7 
    )
    
    BEGIN {
        ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
        $prpSU = 'Date','EventID','Process','Reason' ; 
    }
    PROCESS {
        Foreach($Computer in $ComputerName){
            
            $sBnr="`n#*======v $($CmdletName):$($Computer) v======" ; 
            write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($sBnr)" ;

            $Connection = Test-Connection $Computer -Quiet -Count 2
            If(!$Connection) {
                Write-Warning "Computer: $Computer appears to be offline!"
            } Else {
                write-verbose "(pulling reboot events System 1074)" ; 
                if(($sevts = Get-WinEvent -computername $computer -FilterHashtable @{logname = 'System'; id = 1074} -MaxEvents 1) -AND ((new-timespan -start $sevts.TimeCreated -End (get-date)).TotalDays -lt $MaxDays)){ 
                    <# TimeCreated  : 8/22/2022 2:09:47 AM
                    ProviderName : USER32
                    ProviderId   :
                    Id           : 1074
                    Message      : The process C:\Windows\system32\winlogon.exe (LYNMS640) has initiated the restart of computer SERVER o
                                    n behalf of user DOMAIN\ADMIN for the following reason: No title for this reason could be found
                                    Reason Code: 0x500ff
                                    Shutdown Type: restart
                                    Comment:
                    #>

                    write-host -foregroundcolor green "Manual Reboot detected!`n$(($sevts[0] | fl $prpRbt|out-string).trim())" ; 
                    write-verbose "(calculating Start & End as -/+ 20 mins of newest 1074)" ; 
                    $start = (get-date $sevts[0].TimeCreated).addminutes(-20) ; 
                    $end = (get-date $sevts[0].TimeCreated).addminutes(20) ;
                    $sBnrS="`n#*------v `$SetupEvts : v------" ; 
                    write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($sBnrS)" ;

                    $sfltr = @{ LogName = "Setup"; StartTime = $start; EndTime = $end ; };
            
                    #Get-WinEvent -ComputerName $computer -FilterHashtable @{logname = 'System'; id = 1074,6005,6006,6008}  |
                    $SetupEvts = Get-WinEvent -ComputerName $computer -FilterHashtable $sfltr | 
                        ForEach-Object {
                            $EventData = New-Object PSObject | Select-Object Date, EventID, User, Action, Reason, ReasonCode, Comment, Computer, Message, Process
                            $EventData.Date = $_.TimeCreated
                            $EventData.User = $_.Properties[6].Value
                            $EventData.Process = $_.Properties[0].Value
                            $EventData.Action = $_.Properties[4].Value
                            $EventData.Reason = $_.Properties[2].Value
                            $EventData.ReasonCode = $_.Properties[3].Value
                            $EventData.Comment = $_.Properties[5].Value
                            $EventData.Computer = $Computer
                            $EventData.EventID = $_.id
                            $EventData.Message = $_.Message
                            $EventData | Select-Object Date, Computer, EventID, Process, Action, User, Reason, Message ; 
                        } ; 
                
                

                    $SetupEvts |  sort Date | ft -a $prpSU ; 
                    write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;

                    $sBnrS="`n#*------v `$patchevts : v------" ; 
                    write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($sBnrS)" ;
                    # AP patch installer evts
                    [int32[]]$ID = @(1033,1035,1036,1040,1042.2.0000,100001) ; 
                    [string[]]$provs = @('MsiInstaller','Microsoft-Windows-RestartManager') ; 
                    $cfltr = @{ LogName = "Application"; StartTime = $start; EndTime = $end ; ProviderName = $provs; id = $id};
                    write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):Get-WinEvent w`n$(($cfltr|out-string).trim())" ; 
                    $patchevts = Get-WinEvent -ComputerName $computer -FilterHashtable $cfltr  | 
                        ForEach-Object {
                            $EventData = New-Object PSObject | Select-Object Date, EventID, User, Action, Reason, ReasonCode, Comment, Computer, Message, Process
                            $EventData.Date = $_.TimeCreated
                            $EventData.User = $_.Properties[6].Value
                            $EventData.Process = $_.Properties[0].Value
                            $EventData.Action = $_.Properties[4].Value
                            $EventData.Reason = $_.Properties[2].Value
                            $EventData.ReasonCode = $_.Properties[3].Value
                            $EventData.Comment = $_.Properties[5].Value
                            $EventData.Computer = $Computer
                            $EventData.EventID = $_.id
                            $EventData.Message = $_.Message
                            $EventData | Select-Object Date, Computer, EventID, Process, Action, User, Reason, Message ; 
                        } ; 
                    #$patchevts |?{$_.id -match '(1035|1036)'} ; 
                    $prpsAp = 'Date','EventID','Process','Reason','Message' ; 

                    #write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):PatchEvts 1035|1036: w`n$(($patchevts |?{$_.Eventid -match '(1035|1036)'}  |  sort Date | ft -a $prpsAp  |out-string).trim())`n" ; 
                    write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):PatchEvts 1035|1036: w`n$(($patchevts | sort Date | ft -a $prpsAp  |out-string).trim())`n" ; 
                    write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;

                } else { 
                    $sBnrS="`n#*------v `$bootevts : v------" ; 
                    write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($sBnrS)" ;
                    $bootEvents = Get-WinEvent -ComputerName $computer -FilterHashtable @{logname = 'System'; id = 1074,6005,6006,6008}  |
                        ForEach-Object {
                            $EventData = New-Object PSObject | Select-Object Date, EventID, User, Action, Reason, ReasonCode, Comment, Computer, Message, Process
                            $EventData.Date = $_.TimeCreated
                            $EventData.User = $_.Properties[6].Value
                            $EventData.Process = $_.Properties[0].Value
                            $EventData.Action = $_.Properties[4].Value
                            $EventData.Reason = $_.Properties[2].Value
                            $EventData.ReasonCode = $_.Properties[3].Value
                            $EventData.Comment = $_.Properties[5].Value
                            $EventData.Computer = $Computer
                            $EventData.EventID = $_.id
                            $EventData.Message = $_.Message
                            $EventData | Select-Object Date, Computer, EventID, Process, Action, User, Reason, Message ; 
                        } ; 
                    #$bootEvents |?{$_.id -match '(1035|1036)'} ; 
                    write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):bootEvents`n$(($bootEvents | sort Date | ft -a $prpSU |out-string).trim())`n" ; 
                    write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;


                } ; 
                

            } # if-E
            write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($sBnr.replace('=v','=^').replace('v=','^='))`n" ;
        } #end Foreach Computer Loop
    } #end Process block
}

#*------^ Get-RestartInfo.ps1 ^------


#*------v get-Subnet.ps1 v------
function get-Subnet {
    <#
    .SYNOPSIS
    get-Subnet.ps1 - Returns subnet details for the local IP address, or a given network address and mask.
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-
    FileName    : 
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka/verb-XXX
    Tags        : Powershell
    AddedCredit : REFERENCE
    AddedWebsite:	URL
    AddedTwitter:	URL
    REVISIONS
    * 2:53 PM 11/2/2021 refactor/fix CBH
    * 12:33 PM 8/16/2021 renamed/added -Enumerate for prior -force, turned off autoexpansion (unless -enumerate), shifted to maxhosts calc to gen count, vs full expansion & count
    * 1:29 PM 8/12/2021 tweaked CBH, minor param inline help etc.
    * 1:29 PM 5/12/2021 Mark Wragg posted rev (corresponds to PSG v1.1.14)
    .DESCRIPTION
    get-Subnet.ps1 - Returns subnet details for the local IP address, or a given network address and mask.
    Use to get subnet details  for a given network address and mask, including network address, broadcast address, network class, address range, host addresses and host address count.
    .PARAMETER IP
    The network IP address or IP address with subnet mask via slash notation.
    .PARAMETER MaskBits
    The numerical representation of the subnet mask.
    .PARAMETER Enumerate
    Use to calc & return all host IP addresses regardless of the subnet size (skipped by default)).[-Eunumerate]
    .EXAMPLE
    Get-Subnet 10.1.2.3/24
    Returns the subnet details for the specified network and mask, specified as a single string to the -IP parameter.
    .EXAMPLE
    Get-Subnet 192.168.0.1 -MaskBits 23
    Returns the subnet details for the specified network and mask.
    .EXAMPLE
    Get-Subnet
    Returns the subnet details for the current local IP.
    .EXAMPLE
    '10.1.2.3/24','10.1.2.4/24' | Get-Subnet
    Returns the subnet details for two specified networks.    
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://github.com/markwragg/PowerShell-Subnet/tree/master/Subnet/Public
    #>
    ##Requires -Modules DnsClient
    [CmdletBinding()]
    PARAM (
        [parameter(ValueFromPipeline,HelpMessage="The network IP address or IP address with subnet mask via slash notation.[-IP 192.168.0.1]")]
        [string]$IP,
        [parameter(HelpMessage="The numerical representation of the subnet mask.[-MaskBits 23]")]
        [ValidateRange(0, 32)]
        [Alias('CIDR')]
        [int]$MaskBits,
        #[parameter(HelpMessage="Use to force the return of all host IP addresses regardless of the subnet size (skipped by default for subnets larger than /16).[-Force]")]
        #[switch]$Force
        [parameter(HelpMessage="Use to calc & return all host IP addresses regardless of the subnet size (skipped by default)).[-Eunumerate]")]
        [switch]$Enumerate
    )
    BEGIN {
        ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
        $Verbose = ($VerbosePreference -eq 'Continue') ; 
    } ;  # BEG-E
    PROCESS {

        if ($PSBoundParameters.ContainsKey('MaskBits')) { 
            $Mask = $MaskBits  ; 
        } ; 

        if (-not $IP) { 
            $LocalIP = (Get-NetIPAddress | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.PrefixOrigin -ne 'WellKnown' }) ; 
            $IP = $LocalIP.IPAddress ; 
            If ($Mask -notin 0..32) { $Mask = $LocalIP.PrefixLength } ; 
        } ; 

        if ($IP -match '/\d') { 
            $IPandMask = $IP -Split '/'  ; 
            $IP = $IPandMask[0] ; 
            $Mask = $IPandMask[1] ; 
        } ; 
        
        $Class = Get-NetworkClass -IP $IP ; 

        <# detecting ipv6 - core was written for ipv4...
        # ip4 CIDR range: 0 to 32
        # ip6 CIDR range: 0 to 128 - need to update to accomodate cidr ip6
        if($Address -like "*:*" -AND [int]$cidr[1] -ge 0 -AND [int]$cidr[1] -le 128){
            # CIDR ip6
            write-verbose "valid ipv6 CIDR subnet syntax" ;
            $report.Valid = $true ; 
        } elseif([int]$cidr[1] -ge 0 -and [int]$cidr[1] -le 32){}
        #>

        if($IP -like "*:*" -AND [int]$Mask -ge 0 -AND [int]$Mask -le 128){
                write-warning "ipv6 CIDR detected: unsupported to expand subnet specs with this function" ; 
                $false | write-output ; 
        }else{
        
            if ($Mask -notin 0..32) {
                $Mask = switch ($Class) {
                    'A' { 8 }
                    'B' { 16 }
                    'C' { 24 }
                    #'Single' { 32 } # just marking 32 indicates a single IP, not used in code below
                    default { 
                        throw "Subnet mask size was not specified and could not be inferred because the address is Class $Class." 
                    }
                } ; 
                Write-Warning "Subnet mask size was not specified. Using default subnet size for a Class $Class network of /$Mask." ; 
            } ; 

            $IPAddr = [ipaddress]::Parse($IP) ; 
            $MaskAddr = [ipaddress]::Parse((Convert-Int64toIP -int ([convert]::ToInt64(("1" * $Mask + "0" * (32 - $Mask)), 2)))) ; 

            # fast way to get a count, wo full expansion
            $maxHosts=[math]::Pow(2,(32-$Mask)) - 2 ; 

            $NetworkAddr = [ipaddress]($MaskAddr.address -band $IPAddr.address) ; 
            #$BroadcastAddr = [ipaddress](([ipaddress]::parse("255.255.255.255").address -bxor $MaskAddr.address -bor $NetworkAddr.address)) ; 
            # inacc, returning 255.255.255.255 for 170.92.0.0/16
            # Add-IntToIPv4Address -IPv4Address 10.10.0.252 -Integer 10
            $BroadcastAddr = [ipaddress](Add-IntToIPv4Address -IP $NetworkAddr.IPAddressToString  -Integer ($maxHosts+1)) ; 
            $Range = "$NetworkAddr ~ $BroadcastAddr" ; 
        
            $HostStartAddr = (Convert-IPtoInt64 -ip $NetworkAddr.ipaddresstostring) + 1 ; 
            $HostEndAddr = (Convert-IPtoInt64 -ip $broadcastaddr.ipaddresstostring) - 1 ; 
        

            #if ($Mask -ge 16 -or $Force) {
            if ($Enumerate) {
                Write-Progress "Calcualting host addresses for $NetworkAddr/$Mask.." ; 
                if ($Mask -ge 31) {
                    $HostAddresses = ,$NetworkAddr ; 
                    if ($Mask -eq 31) {
                        $HostAddresses += $BroadcastAddr ; 
                    } ; 

                    $HostAddressCount = $HostAddresses.Length ; 
                    $NetworkAddr = $null ; 
                    $BroadcastAddr = $null ; 
                } else {
                    $HostAddresses = for ($i = $HostStartAddr; $i -le $HostEndAddr; $i++) {
                        Convert-Int64toIP -int $i ; 
                    }
                    $HostAddressCount = ($HostEndAddr - $HostStartAddr) + 1 ; 
                }                     
            } ; 
            # more interested in the count than specific ips
            <#else {
                Write-Warning "Host address enumeration was not performed because it would take some time for a /$Mask subnet. `nUse -Force if you want it to occur." ; 
            } ; 
            #>

            $report = [ordered]@{
                IPAddress        = $IPAddr
                MaskBits         = $Mask
                NetworkAddress   = $NetworkAddr
                BroadcastAddress = $broadcastaddr
                SubnetMask       = $MaskAddr
                NetworkClass     = $Class
                Range            = $Range
            } ; 
            if($Enumerate){
                $report.add('HostAddresses',$HostAddresses) ;
                $report.add('HostAddressCount',$HostAddressCount );
            } else {
                $report.add('HostAddressCount',$maxHosts);
            } ; ;

            <#[pscustomobject]@{
                IPAddress        = $IPAddr
                MaskBits         = $Mask
                NetworkAddress   = $NetworkAddr
                BroadcastAddress = $broadcastaddr
                SubnetMask       = $MaskAddr
                NetworkClass     = $Class
                Range            = $Range
                HostAddresses    = $HostAddresses
                HostAddressCount = $HostAddressCount
            } ; 
            #>

            New-Object PSObject -Property $report | write-output ;    
        } ;

    } ; # PROC-E
    END {}
}

#*------^ get-Subnet.ps1 ^------


#*------v get-tsusers.ps1 v------
function get-tsUsers {
    <# 
    .SYNOPSIS
    get-tsUsers.ps1 - Simple easy-to-remember wrapper for quser remote termserve query tool. Takes the output from the quser program and parses this to PowerShell objects
    .NOTES
    Version     : 1.0.0.
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2021-07-13
    FileName    : get-tsUsers.ps1
    License     : (non-asserted)
    Copyright   : (non-asserted)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell
    AddedCredit : REFERENCE
    AddedWebsite: URL
    AddedCredit : Jaap Brasser
    AddedWebsite: http://www.jaapbrasser.com	
    AddedTwitter: URL
    REVISIONS   :
    * 1:27 PM 9/27/2021 converted to verb-Network function, ren'd get-tsUser -> get-tsUsers
    * 7:42 AM 11/11/2016 corrected script name typo in help example
    * 9:55 AM 10/24/2016 updated 
    * 8:12 AM 10/24/2016 minor tweaking, reworked pshelp 1tb formation etc
    * 9/23/2015 v1.2.1 jaap's posted version
    .DESCRIPTION
    get-tsUsers.ps1 - simple easy-to-remember wrapper for quser remote termserve query tool. 
    Actually, I just decided to save time and rename Jaap's prefab to my preferred name get-tsUsers.ps1.
    Necessary because Win2012R2 permanetly removed 99% of the TSC mgmt tools that we've RELIED ON for the last decade. 
    Yea, the typical admin wants to build a full blown citrix-mgmt equivalent like a termserve farm, just to figure output
    Who the *REDACTED* is logged into and hogging that rdp console you need. Pftftft!
    All this does is put the quser into a ps-compliant verb-noun format. 
    Note: quser.exe requires open port 455, jumpbox 7330 is *blocked*, so use RemPS to run it on the remote box directly:
    Invoke-Command -ComputerName 'REMOTECOMPUTER' -ScriptBlock {quser} ;
    Invoke-Command -ComputerName 'REMOTECOMPUTER' -ScriptBlock { logoff 2 } ;
    .PARAMETER ComputerName
    The string or array of string for which a query will be executed
    .INPUTS
    Accepts piped input.
    .OUTPUTS
    Returns user logon summaries to the pipeline
    .EXAMPLE
    PS> 'server01','server02' | get-tsusers
    Display the session information on server01 and server02, default output
    .EXAMPLE
    PS> get-tsusers SERVERNAME | sort logontime | format-table -auto ;  
    More useful session display in condensed table layout, with logontime sorted on actual dates (non-alphabetic).
    .EXAMPLE
    PS> get-tsusers SERVERNAME | select -expand username |%{  if($_ -match "^(\w*)s$"){ $X=$matches[1] ;get-recipient -id $x | select windowsema*,dist*};};
    Version that converts SID logons, to UID equiv (truncates trailing s), and retrieves matching mbx 
    .EXAMPLE
    PS> $tus = SERVERNAME,SERVERNAME2 | get-tsusers | ?{$_.username -eq 'LOGON'};
        $tus | ft -auto ;
    returns: 
    UserName ComputerName SessionName Id State IdleTime LogonTime         Error
    -------- ------------ ----------- -- ----- -------- ---------         -----
    LOGON    SERVERNAME               2  Disc  2+15:00  9/7/2021 12:03 PM
        # then demo the logoffs:
        $tus |%{"logoff $($_.id) /server:$($_.computername)"}
        # then log off the sessions remotely:
        returns: 
        logoff 2 /server:SERVERNAME
        # then exec the logoffs
        $tus |%{"Exec:logoff $($_.id) /server:$($_.computername):" ; logoff $($_.id) /server:$($_.computername) ;}
        # confirm cleared
        SERVERNAME,SERVERNAME2 | get-tsusers | ft -auto ;
    Demo use of ft -a for cleaner report, post-filtered Username, looped use of the logoff cmd to do targeted logoffs
    .EXAMPLE
    PS> Invoke-Command -ComputerName 'REMOTECOMPUTER' -ScriptBlock {quser} ;
        Invoke-Command -ComputerName 'REMOTECOMPUTER' -ScriptBlock { logoff 2 } ; 
    If port 455 is blocked, use RemPS to bypass the restruction:
    .LINK
    https://gallery.technet.microsoft.com/scriptcenter/Get-LoggedOnUser-Gathers-7cbe93ea
    #>
    [CmdletBinding()] 
    PARAM(
        [Parameter(Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [string[]]$ComputerName = 'localhost'  
    ) ; 
    BEGIN {
        $ErrorActionPreference = 'Stop' ; 
    } ;  # BEG-E
    PROCESS {
        # underlying cmdline: quser.exe /server xxxx
        foreach ($Computer in $ComputerName) {
            TRY {
                quser /server:$Computer 2>&1 | Select-Object -Skip 1 | ForEach-Object {
                    $CurrentLine = $_.Trim() -Replace '\s+',' ' -Split '\s' ; 
                    $HashProps = @{
                        UserName = $CurrentLine[0] ; 
                        ComputerName = $Computer ; 
                    } ; 

                    # If session is disconnected different fields will be selected
                    if ($CurrentLine[2] -eq 'Disc') {
                            $HashProps.SessionName = $null ; 
                            $HashProps.Id = $CurrentLine[1] ; 
                            $HashProps.State = $CurrentLine[2] ; 
                            $HashProps.IdleTime = $CurrentLine[3] ; 
                            $HashProps.LogonTime = $CurrentLine[4..6] -join ' ' ; 
                            $HashProps.LogonTime = $CurrentLine[4..($CurrentLine.GetUpperBound(0))] -join ' ' ; 
                    } else {
                            $HashProps.SessionName = $CurrentLine[1] ; 
                            $HashProps.Id = $CurrentLine[2] ; 
                            $HashProps.State = $CurrentLine[3] ; 
                            $HashProps.IdleTime = $CurrentLine[4] ; 
                            $HashProps.LogonTime = $CurrentLine[5..($CurrentLine.GetUpperBound(0))] -join ' ' ; 
                    } ; 

                    New-Object -TypeName PSCustomObject -Property $HashProps |
                    Select-Object -Property UserName,ComputerName,SessionName,Id,State,IdleTime,LogonTime,Error | write-output ; 
                } ; 
            } CATCH {
                New-Object -TypeName PSCustomObject -Property @{
                    ComputerName = $Computer ; 
                    Error = $_.Exception.Message
                } | Select-Object -Property UserName,ComputerName,SessionName,Id,State,IdleTime,LogonTime,Error | write-output ; 
            } ; 
        } ; 
    } ; # PROC-E  
}

#*------^ get-tsusers.ps1 ^------


#*------v get-whoami.ps1 v------
function get-whoami {
        <#
        .SYNOPSIS
        get-whoami.ps1 - assemble & return DOMAIN\LOGON string from local eVaris
        .NOTES
        Version     : 1.0.0
        Author      : Todd Kadrie
        Website     : http://www.toddomation.com
        Twitter     : @tostka / http://twitter.com/tostka
        CreatedDate : 2020-04-17
        FileName    : get-whoami.ps1
        License     : MIT License
        Copyright   : (c) 2020 Todd Kadrie
        Github      : https://github.com/tostka
        Tags        : Powershell,Internet,Download,File
        REVISIONS
        11:31 AM 4/17/2020 added CBH
        .DESCRIPTION
        get-whoami.ps1 - assemble & return DOMAIN\LOGON string from local eVaris
        .INPUTS
        None. Does not accepted piped input.
        .OUTPUTS
        System.String 
        .EXAMPLE
        $logon = get-whoami
        .LINK
        #>
        [CmdletBinding()]
        PARAM ()
        return (get-content env:\userdomain).ToLower() + "\" + (get-content env:\username).ToLower() ;
    }

#*------^ get-whoami.ps1 ^------


#*------v Invoke-BypassPaywall.ps1 v------
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
}

#*------^ Invoke-BypassPaywall.ps1 ^------


#*------v Invoke-SecurityDialog.ps1 v------
function Invoke-SecurityDialog {
    <#
    .SYNOPSIS
    Invoke-SecurityDialog.ps1 - Open Windows System Security dialog via powershell (for Password changes etc) - handy for nested RDP/TermServ sessions where normal Ctrl+Alt+Del/Ctrl+Alt+End(remote) triggers don't work (hotkey, remote triggers only outtermost RDP sec dlg). 
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2021-11-23
    FileName    : 
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell
    AddedCredit : 
    AddedWebsite: 
    AddedTwitter: 
    REVISIONS
    * 9:16 AM 11/23/2021 init
    .DESCRIPTION
    Invoke-SecurityDialog.ps1 - Open system Security dialog via powershell - handy for nested RDP/TermServ sessions where normal Ctrl+Alt+Del/Ctrl+Alt+End (remote) triggers don't work. 
    .INPUTS
    Accepts piped input
    .OUTPUTS
    None. Returns no objects or output (.NET types)
    .EXAMPLE
    PS> Invoke-SecurityDialog
    For the query of the corresponding TXT records in the DNS only the paramater name is needed
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://cloudbrothers.info/en/powershell-tip-resolve-spf/
    #>
    #Requires -Modules DnsClient
    [CmdletBinding()]
    PARAM () ; 
    write-host "Triggering local Windows Security Dialog (requires RAA)...`n(cmd.exe RAA, alt:`nexplorer.exe shell:::{2559a1f2-21d7-11d4-bdaf-00c04f60b9f0}`n)" ; 
    (New-Object -COM Shell.Application).WindowsSecurity() ;
}

#*------^ Invoke-SecurityDialog.ps1 ^------


#*------v Reconnect-PSR.ps1 v------
Function Reconnect-PSR {
    <#
    .SYNOPSIS
    Reconnect-PSR - Reconnect Remote Powershell connection
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2020-06-09
    FileName    : Reconnect-PSR.ps1
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka
    Tags        : Powershell,Remote
    REVISIONS
    * 8:56 AM 6/9/2020 added to verb-Network
    * 2:51 PM 12/21/2016 add support for Connect-PSR -silent ; port to Powershell remote
    * 1:26 PM 12/9/2016 split no-session and reopen code, to suppress notfound errors ; cleaned up, add pshelp; implented and debugged as part of verb-PSR set; ported to local EMSRemote
    .DESCRIPTION
    .EXAMPLE
    .\Reconnect-PSR.ps1
    .EXAMPLE
    .\Reconnect-PSR.ps1
    .LINK
    #>
    [CmdletBinding()]
    [Alias('rPSR')]
    Param() ;
    $verbose = ($VerbosePreference -eq "Continue") ; 
    if(!$PSRSess){Connect-PSR -silent }
    elseif($PSRSess.state -ne 'Opened' -OR $PSRSess.Availability -ne 'Available' ) { Disconnect-PSR ;Start-Sleep -S 3;Connect-PSR -silent ;} ;
}

#*------^ Reconnect-PSR.ps1 ^------


#*------v Resolve-DNSLegacy.ps1 v------
function Resolve-DNSLegacy.ps1{
    <#
    .SYNOPSIS
    Resolve-DNSLegacy.ps1 - 1LINEDESC
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2021-01-13
    FileName    : Resolve-DNSLegacy.ps1
    License     : (none specified)
    Copyright   : (none specified)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,DNS,Network
    AddedCredit :  i255d
    AddedWebsite:	https://community.idera.com/database-tools/powershell/ask_the_experts/f/powershell_for_windows-12/22127/powershell-wrapper-for-nslookup-with-error-handling-basically-nslookup-on-steroids
    REVISIONS
    * 3:02 PM 11/2/2021 refactor/fix cbh
    * 9:23 AM 1/13/2021 TSK:updated CBH, reformated & minor tweaks
    * 2015 orig posted copy
    .DESCRIPTION
    Get FQDN and IP for a single server, or a list of servers, specify the Ip of the DNS server otherwise it defaults to the 1st DNS Server on the PPP* nic, and then to the first non-PPP* nic.
    I tweaked this version to leverage my Get-NetIPConfigurationLegacy ipconfig /all wrapper fuct, to return the DNS servers on the PPP* (VPN in my case) nic, or the non-PPP* nic, by preference.
    Posted by i255d to Idera Forums (https://community.idera.com/database-tools/powershell/ask_the_experts/f/powershell_for_windows-12/22127/powershell-wrapper-for-nslookup-with-error-handling-basically-nslookup-on-steroids), tagged 'over 6 yrs ago' (in 2021 = ~2015) ; 
    Updated/tweaked by TSK 2021.
    .PARAMETER ComputerName
    Computername
    .PARAMETER DNSServerIP
    DNS Server IP Address
    .PARAMETER ErrorFile
    Path to output file for results
    .EXAMPLE
    PS> Get-Content C:\serverlist.txt | Resolve-DNSLegacy.ps1 | Export-CSV C:\ServerList.csv
    Process serverlist from pipelined txt file, and export to serverlist.
    .LINK
    https://github.com/tostka/verb-Network
    #>
    [CmdletBinding()]
    PARAM(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=0)]
        [alias("Computer")]
        [ValidateLength(3,35)]
        [string[]]$Computername,
        [Parameter(Position=1)]
        [string]$DNSServerIP,
        [Parameter(Position=2)]
        [string] $ErrorFile
    )
    BEGIN{
        # if not specified, move it to random temp file
        if(!$ErrorFile -OR (!(test-path $ErrorFile))){
            $ErrorFile = [System.IO.Path]::GetTempFileName().replace('.tmp','.txt') ;
        } ; 
        if(!$DNSServerIP){
            $nics = Get-NetIPConfigurationLegacy ; 
            if($DNSServerIP = ($nics | ?{$_.DNSServers -AND $_.AdapterName -like 'PPP*'}).DNSServers[0]){write-verbose "(Using PPP* Nic DNSServerIP:$($DNSServerIP)"}  ; 
        
            elseif($DNSServerIP = ($nics | ?{$_.DNSServers -AND $_.AdapterName -notlike 'PPP*'}).DNSServers[0]){
                write-verbose "(Using first non-PPP* Nic DNSServerIP:$($DNSServerIP)"
                if($DNSServerIP -is [system.array]){write-warning "Returned multiple DNS server IPs!"
            }} 
            else { throw "Get-NetIPConfigurationLegacy:No matchable DNS Server found"} ; 
        } ; 
        $server = ""
        $IP = ""
        $object = [pscustomobject]@{}
    }#end begin
    PROCESS{
        foreach($computer in $Computername){
            $Lookup = nslookup $computer $DNSServerIP 2> $ErrorFile
                $Lookup | Where{$_} | foreach{
                    if(($Error[1].Exception.Message -split ':')[1] -eq ' Non-existent domain'){
                        $object | Add-Member ComputeName $computer
                        $object | Add-Member IpAddress "None"
                        $object
                        $object = [pscustomobject]@{}
                        Write-Error "End" 2>> $ErrorFile
                    }elseif($_ -match "^Name:\s+(?<name>.+)"){
                            $server = $Matches.name
                    }elseif($_ -match "$DNSServerIP"){
                    }elseif($_ -match "^Address:\s+(?<ipaddress>.+)"){
                            $IP = $Matches.ipaddress
                    }#if
                }#foreach
            $Lookup = ''
            $object | Add-Member ComputeName $server
            $object | Add-Member IpAddress $ip
            if($object.ComputeName){$object| write-output }
            $server = ''
            $ip = ''
            $object = [pscustomobject]@{}
        } ; 
    } ; #end process
    END{} ; 
}

#*------^ Resolve-DNSLegacy.ps1 ^------


#*------v Resolve-SPFRecord.ps1 v------
function Resolve-SPFRecord {
    <#
    .SYNOPSIS
    resolve-SPFRecord.ps1 - query & parse/validate the current SPF DNS records, including all included services
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2020-
    FileName    : 
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell
    AddedCredit : Fabian Bader
    AddedWebsite: https://cloudbrothers.info/en/
    AddedTwitter: 
    REVISIONS
    * 3:46 PM 11/2/2021 flipped some echos to wv ;  CBH minor cleanup
    * 2:28 PM 8/16/2021 spliced in simple summarize of ipv4 CIDR subnets (range, # usable ips in range etc), leveraging combo of Mark Wragg get-subnet() and a few bits from Brian Farnsworth's Get-IPv4Subnet() (which pulls summaries wo fully enumeratinfg every ip - much faster)
    * 12:25 PM 8/13/2021Add ip4/6 syntax testing/simple validation (via 
    test-IpAddressCidrRange, sourced in verb-network, local deferral copy) ; 
    extended verbose echos ; add case for version spec & [~+-?]all (suppress spurious 
    warnings) ; expanded macro/explanation mechanism warnings (non-invalid: just script 
    doesn't support their expansion/validation). Added examples for grouping referrer and 
    dumping summaries per referrer. 
    * 1:29 PM 8/12/2021 updated format to OTB, added CBH, minor param inline help etc.
    * 1:29 PM 4/12/2021 Fabian Bader posted rev
    .DESCRIPTION
    resolve-SPFRecord.ps1 - query & parse/validate the current SPF DNS records, including all included services. 
    
    From [PowerShell Tip: Resolve SPF Records - Cloudbrothers - cloudbrothers.info/](https://cloudbrothers.info/en/powershell-tip-resolve-spf/):
    ## Supported SPF directives and functions: 
     - include
     - mx
     - a
     - ip4 und ip6
     - redirect
     - Warning for too many include entries
    ## Not supported: 
     - exp
     - Makros
     - Usage
     
    Optionally, the Server (DNS) parameter can be used. Defaults to cloudflare resolver: 1.1.1.1 (secondary is 1.0.0.1)
    documented here: [Introducing DNS Resolver, 1.1.1.1 (not a joke) - blog.cloudflare.com/](https://blog.cloudflare.com/dns-resolver-1-1-1-1/)
    
    Specify explicit DNS server to be queried. Useful, if you want to test the DNS changes directly on your own root name server shortly after the update, or if there are restrictions on which DNS server your client is allowed to query.
    .PARAMETER Name
    Domain Name[-Name some.tld]
    .PARAMETER Server
    DNS Server to use (defaults to Cloudflare public resolver 1.1.1.1)[-Server 1.0.0.1]
    .PARAMETER Referrer
    if called nested provide a referrer to build valid objects[-Referrer referrer]
    .INPUTS
    Accepts piped input
    .OUTPUTS
    None. Returns no objects or output (.NET types)
    System.Boolean
    [| get-member the output to see what .NET obj TypeName is returned, to use here]
    .EXAMPLE
    PS> Resolve-SPFRecord -Name domainname.tld
    For the query of the corresponding TXT records in the DNS only the paramater name is needed
    .EXAMPLE
    PS> Resolve-SPFRecord -Name domainname.tld | ft
    It is recommended to output the result with 'Format-Table' for better readability.
    .EXAMPLE
    PS> $spfs = Resolve-SPFRecord -name domain.com ; 
    # group referrers
    $spfs | group referrer | ft -auto count,name ;
    output: 
    Count Name                      
    ----- ----                      
        3                           
        10 domain.com                  
        9 spf.protection.outlook.com
    # output ip summary for a specific referrer
    $spfs|?{$_.Referrer  -eq 'spf.protection.outlook.com'} | ft -auto ipaddress,referrer ; 
    output: 
    IPAddress                Referrer                  
    ---------                --------                  
    51.4.72.0/24             spf.protection.outlook.com

    Broader example, group/profile returned referrers, dump summaries on referrers
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://cloudbrothers.info/en/powershell-tip-resolve-spf/
    #>
    #Requires -Modules DnsClient
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 1,HelpMessage="Domain Name[-Name some.tld]")]
        [string]$Name,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true,Position = 2,HelpMessage="DNS Server to use (defaults to Cloudflare public resolver 1.1.1.1)[-Server 1.0.0.1]")]
        [string]$Server = "1.1.1.1",
        [Parameter(Mandatory = $false,HelpMessage="If called nested provide a referrer to build valid objects[-Referrer referrer]")]
        [string]$Referrer
    ) ; 
    BEGIN {
        class SPFRecord {
            [string] $SPFSourceDomain
            [string] $IPAddress
            [string] $Referrer
            [string] $Qualifier
            [bool] $Include
            # Constructor: Creates a new SPFRecord object, with a specified IPAddress
            SPFRecord ([string] $IPAddress) {
                $this.IPAddress = $IPAddress
            }
            # Constructor: Creates a new SPFRecord object, with a specified IPAddress and DNSName
            SPFRecord ([string] $IPAddress, [String] $DNSName) {
                $this.IPAddress = $IPAddress
                $this.SPFSourceDomain = $DNSName
            }
            # Constructor: Creates a new SPFRecord object, with a specified IPAddress and DNSName and
            SPFRecord ([string] $IPAddress, [String] $DNSName, [String] $Qualifier) {
                $this.IPAddress = $IPAddress
                $this.SPFSourceDomain = $DNSName
                $this.Qualifier = $Qualifier
            }
        } ; 
        #*------v Function test-IpAddressCidrRange v------
        if(!(get-command  test-IpAddressCidrRange)){
            function test-IpAddressCidrRange{
                <#
                .SYNOPSIS
                test-IpAddressCidrRange.ps1 - evaluate an IP Address specification as either IPAddress|CidrRange|IPAddressRange
                .NOTES
                Version     : 1.0.0
                Author      : Todd Kadrie
                Website     : http://www.toddomation.com
                Twitter     : @tostka / http://twitter.com/tostka
                CreatedDate : 2020-
                FileName    : 
                License     : (none asserted)
                Copyright   : (none asserted)
                Github      : https://github.com/tostka/verb-Network
                Tags        : Powershell,Network,IPAddress
                AddedCredit : cyruslab (from public forum post, cited as 'https://powershell.org/forums/topic/detecting-if-ip-address-entered/', now gone)
                AddedWebsite: https://cyruslab.net/2018/04/26/powershellcheck-valid-ip-address-subnet-or-ip-address-range/
                AddedTwitter: 
                REVISIONS
                * 10:51 AM 8/13/2021 added to verb-network ; updated base code to work with ip6 CIDR notation ; fixed 
                bug in if/then comparisions: need to coerce subnet mask to integer, for 
                comparison (esp under ip6) ; converted to function updated format to OTB, added 
                CBH, minor param inline help etc. 
                * 4/26/2016 cyruslab posted ps code from earlier unattributed powershell.org forums post (non-function)
                .DESCRIPTION
                test-IpAddressCidrRange.ps1 - evaluate an IP Address specification as either IPAddress|CidrRange|IPAddressRange
                .PARAMETER Address
                IPAddress, CIDR notation, or IP range specification to be tested[-Address 192.168.0.1]
                .INPUTS
                Does not accept piped input
                .OUTPUTS
                System.SystemObject with Type (IPAddress|CIDRRange|IPAddressRange) and boolean Valid properties
                .EXAMPLE
                PS> $ret= test-IpAddressCidrRange -Address 192.168.1.1 ;
                if(($ret.type -eq 'IPAddress' -AND $ret.valid){'Valid IP'} ; 
                Test IP Address
                .EXAMPLE
                PS> $ret= test-IpAddressCidrRange -Address 91.198.224.29/32
                if(( $ret.type -eq 'CIDRRange' -AND $ret.valid){'Valid CIDR'} ; 
                Test CIDR notation block
                .EXAMPLE
                PS> $ret= test-IpAddressCidrRange -Address '192.168.0.1-192.168.0.200' ;
                if($ret.type -eq 'IPAddressRange' -AND $ret.valid){'Valid CIDR'} ; 
                Test IP Address range
                .LINK
                https://github.com/tostka/verb-Network
                .LINK
                https://cyruslab.net/2018/04/26/powershellcheck-valid-ip-address-subnet-or-ip-address-range/
                #>            
                [CmdletBinding()]
                PARAM(
                    [Parameter(HelpMessage="IPAddress, CIDR notation, or IP range specification to be tested[-Address 192.168.0.1]")]
                    $Address
                ) ;
                $isIPAddr = ($Address -as [IPaddress]) -as [Bool] ;
                $report=[ordered]@{
                    Type = $null ;
                    Valid = $false ;
                } ;
                write-verbose "specified Address:$($Address)" ;
                if($isIPAddr){
                    write-verbose "Valid ip address" ;
                    $report.type = 'IPAddress' ;
                    $report.Valid = $true ; 
                } elseif($Address -like "*/*" -or $Address -like "*-*"){
                    $cidr = $Address.split("/") ;
                    if($cidr){ 
                        $report.type = 'CIDRRange'
                    } ;
                    # ip4 CIDR range: 0 to 32
                    # ip6 CIDR range: 0 to 128 - need to update to accomodate cidr ip6
                    if($Address -like "*:*" -AND [int]$cidr[1] -ge 0 -AND [int]$cidr[1] -le 128){
                        # CIDR ip6
                        write-verbose "valid ipv6 CIDR subnet syntax" ;
                        $report.Valid = $true ; 
                    } elseif([int]$cidr[1] -ge 0 -and [int]$cidr[1] -le 32){
                        write-verbose "valid ipv4 CIDR subnet syntax" ;
                        $report.Valid = $true ; 
                    }elseif($Address -like "*-*"){
                        $report.type = 'IPAddressRange' ; 
                        $ip = $Address.split("-") ; 
                        $ip1 = $ip[0] -as [IPaddress] -as [Bool] ; 
                        $ip2 = $ip[1] -as [IPaddress] -as [Bool] ; 
                        if($ip -and $ip){
                            write-verbose "valid ip address range" ;
                            $report.Valid = $true ;
                        } else{
                            write-verbose "invalid range" ;
                            $report.Valid = $false ;
                        } ;
                    } else {
                        $report.type = 'INVALID' ;
                        $report.Valid = $false ;
                        write-warning "invalid subnet" ;
                    } ; 
                }else{
                    $report.type = 'INVALID' ;
                    $report.Valid = $false ;
                    write-warning "not valid address" ;
                } ;
                New-Object PSObject -Property $report | write-output ;   
            } ; 
        } ;
        #*------^ END Function test-IpAddressCidrRange ^------

        ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
        $Verbose = ($VerbosePreference -eq 'Continue') ; 
    } ; 
    PROCESS {
        # Keep track of number of DNS queries
        # DNS Lookup Limit = 10
        # https://tools.ietf.org/html/rfc7208#section-4.6.4
        # Query DNS Record
        write-verbose "(pulling TXT DNS records for $($Name) from server:$($Server))" ;
        $DNSRecords = Resolve-DnsName -Server $Server -Name $Name -Type TXT ; 
        # Check SPF record
        $SPFRecord = $DNSRecords | Where-Object { $_.Strings -match "^v=spf1" } ; 
        # Validate SPF record
        $SPFCount = ($SPFRecord | Measure-Object).Count ; 
        write-verbose "(returned $($SPFCount) spf records)" ; 
        if ( $SPFCount -eq 0) {
            # If there is no error show an error
            Write-Error "No SPF record found for `"$Name`""
        } elseif ( $SPFCount -ge 2 ) {
            # Multiple DNS Records are not allowed
            # https://tools.ietf.org/html/rfc7208#section-3.2
            Write-Error "There is more than one SPF for domain `"$Name`"" ; 
        } else {
            # Multiple Strings in a Single DNS Record
            # https://tools.ietf.org/html/rfc7208#section-3.3
            $SPFString = $SPFRecord.Strings -join '' ; 
            # Split the directives at the whitespace
            $SPFDirectives = $SPFString -split " " ; 

            # Check for a redirect
            if ( $SPFDirectives -match "redirect" ) {
                $RedirectRecord = $SPFDirectives -match "redirect" -replace "redirect=" ; 
                Write-Verbose "[REDIRECT]`t$RedirectRecord" ; 
                # Follow the include and resolve the include
                Resolve-SPFRecord -Name "$RedirectRecord" -Server $Server -Referrer $Name ; 
            } else {
                # Extract the qualifier
                $Qualifier = switch ( $SPFDirectives -match "^[+-?~]all$" -replace "all" ) {
                    "+" { "pass" }
                    "-" { "fail" }
                    "~" { "softfail" }
                    "?" { "neutral" }
                } ; 
                write-verbose "detected Qualifier:$($Qualifier)" ; 
                write-host -foregroundcolor green "Processing SPFDirectives:`n$(($SPFDirectives|out-string).trim())" ; 
                $ReturnValues = foreach ($SPFDirective in $SPFDirectives) {
                    switch -Regex ($SPFDirective) {
                        # 9:59 AM 8/13/2021 add case for version spec, otherwise it throws:WARNING: [v=spf1]	 Unknown directive
                        "v=spf\d" {
                            write-verbose "Spf Version: $($SPFDirective)" ;
                        } 
                        # 9:59 AM 8/13/2021 add a case for all mechanism, or throws: WARNING: [~all]	 Unknown directive
                        "[~+-?]all" {
                            switch ($Qualifier){
                                "pass" {write-verbose "all PASS mechanism: $($SPFDirective)"}
                                "fail" {write-verbose "all FAIL mechanism: $($SPFDirective)"}
                                "softfail" {write-verbose "all SOFTFAIL mechanism: $($SPFDirective)"}
                                "neutral" {write-verbose "all NEUTRAL mechanism: $($SPFDirective)"}
                            } ;
                        } 
                        "%[{%-_]" {
                            Write-Warning "[$_]`tMacro sytax detected:Macros validation/expansion is not supported by this function. For more information, see https://tools.ietf.org/html/rfc7208#section-7" ;  
                            Continue ; 
                        }
                        "^exp:.*$" {
                            Write-Warning "[$_]`texp: Explanation syntax detected:Explanation validation/expansion is not supported by this function. For more information, see https://tools.ietf.org/html/rfc7208#section-6.2" ; 
                            Continue ; 
                        }
                        '^include:.*$' {
                            # Follow the include and resolve the include
                            Write-Verbose "[include]`tSPF entry: $SPFDirective (recursing)" ; 
                            Resolve-SPFRecord -Name ( $SPFDirective -replace "^include:" ) -Server $Server -Referrer $Name ; 
                        }
                        '^ip[46]:.*$' {
                            Write-Verbose "[IP]`tSPF entry: $SPFDirective" ; 
                            $SPFObject = [SPFRecord]::New( ($SPFDirective -replace "^ip[46]:"), $Name, $Qualifier) ; 
                            if ( $PSBoundParameters.ContainsKey('Referrer') ) {
                                $SPFObject.Referrer = $Referrer ; 
                                $SPFObject.Include = $true ; 
                            } ; 

                            # validate ip spec (IPAddress|CIDRRange|IPAddressRange) and boolean Valid properties
                            
                            $ret= test-IpAddressCidrRange -Address $SPFDirective.replace('ip4:','').replace('ip6:','') ;
                            #$type = [regex]::match($ret.type ,'(IPAddress|CIDRRange)').captures[0].groups[0].value
                            if($ret.valid){
                                if($ret.type -match '(IPAddress|CIDRRange)'){
                                    write-verbose "(Validated ip4: entry format is:$($matches[0]))" 
                                    if($ret.type -eq 'CIDRRange'){
                                        $subnet = Get-Subnet -ip $SPFDirective.replace('ip4:','').replace('ip6:','') -verbose:$($verbose);
                                        if($subnet){
                                            if($subnet.MaskBits -eq 32){
                                                $smsg = "$($subnet.ipaddress)/$($subnet.MaskBits) is a single IP address (/32)" ;
                                            } elseif($subnet.HostAddressCount -eq 0){
                                                $smsg = "$($subnet.ipaddress)/$($subnet.MaskBits) is Class$($subnet.NetworkClass) spanning $($subnet.HostAddressCount+1) usable addresses on range:$($subnet.Range)" ;
                                            }  else { 
                                                $smsg = "$($subnet.ipaddress)/$($subnet.MaskBits) is Class$($subnet.NetworkClass) spanning $($subnet.HostAddressCount) usable addresses on range:$($subnet.Range)" ;
                                            } ; 
                                        } elseif($SPFDirective -like 'ip6:*') { 
                                            $smsg = "($($SPFDirective) is an ipv6 CIDR Range: This script does not support summarizing ipv6 Ranges)" ; 
                                        } else {
                                            $smsg = "WARNING: unrecognized CIDRRange specification" ; 
                                        } ; 
                                        write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):`n$($smsg)" ; 
                                    } ; 
                                } else {
                                    write-warning "invalid IP specification:$($ret.type) is unsupported format" ;
                                } ;       
                            } else { 
                                write-warning "invalid IP specification:$($SPFDirective.replace('ip4:',''))" ;
                            } ; 
                            
                            $SPFObject ; 
                        } 
                        '^a:.*$' {
                            Write-Verbose "[A]`tSPF entry: $SPFDirective"
                            $DNSRecords = Resolve-DnsName -Server $Server -Name $Name -Type A ; 
                            # Check SPF record
                            foreach ($IPAddress in ($DNSRecords.IPAddress) ) {
                                $SPFObject = [SPFRecord]::New( $IPAddress, ($SPFDirective -replace "^a:"), $Qualifier) ; 
                                if ( $PSBoundParameters.ContainsKey('Referrer') ) {
                                    $SPFObject.Referrer = $Referrer ; 
                                    $SPFObject.Include = $true ; 
                                }
                                $SPFObject ; 
                            }
                        }
                        '^mx:.*$' {
                            Write-Verbose "[MX]`tSPF entry: $SPFDirective" ; 
                            $DNSRecords = Resolve-DnsName -Server $Server -Name $Name -Type MX ; 
                            foreach ($MXRecords in ($DNSRecords.NameExchange) ) {
                                # Check SPF record
                                $DNSRecords = Resolve-DnsName -Server $Server -Name $MXRecords -Type A ; 
                                foreach ($IPAddress in ($DNSRecords.IPAddress) ) {
                                    $SPFObject = [SPFRecord]::New( $IPAddress, ($SPFDirective -replace "^mx:"), $Qualifier) ; 
                                    if ( $PSBoundParameters.ContainsKey('Referrer') ) {
                                        $SPFObject.Referrer = $Referrer ; 
                                        $SPFObject.Include = $true ; 
                                    } ; 
                                    $SPFObject ; 
                                } ; 
                            } ; 
                        }
                        Default {
                            Write-Warning "[$_]`t Unknown directive" ; 
                        }
                    } ; 
                } ; 

                $DNSQuerySum = $ReturnValues | Select-Object -Unique SPFSourceDomain | Measure-Object | Select-Object -ExpandProperty Count ; 
                if ( $DNSQuerySum -gt 6) {
                    Write-Warning "Watch your includes!`nThe maximum number of DNS queries is 10 and you have already $DNSQuerySum.`nCheck https://tools.ietf.org/html/rfc7208#section-4.6.4" ; 
                } ; 
                if ( $DNSQuerySum -gt 10) {
                    Write-Error "Too many DNS queries made ($DNSQuerySum).`nMust not exceed 10 DNS queries.`nCheck https://tools.ietf.org/html/rfc7208#section-4.6.4" ; 
                } ; 

                $ReturnValues ; 
            } ; 
        } ; 
    } ; 

    END {}
}

#*------^ Resolve-SPFRecord.ps1 ^------


#*------v Send-EmailNotif.ps1 v------
Function Send-EmailNotif {
    <#
    .SYNOPSIS
    Send-EmailNotif.ps1 - Mailer function (wraps send-mailmessage)
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website:	http://www.toddomation.com
    Twitter:	@tostka, http://twitter.com/tostka
    CreatedDate : 2014-08-21
    FileName    : 
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,Email,SMTP,Gmail
    AddedCredit : REFERENCE
    AddedWebsite:	URL
    AddedTwitter:	URL
    REVISIONS
    * 9:58 PM 11/7/2021 updated CBH with complete gmail example ; updated CBH with complete gmail example
    * 8:56 PM 11/5/2021 added $Credential & $useSSL param (to support gmail/a-smtp sends); added Param HelpMessage, added params to CBH
    * send-emailnotif.ps1: * 1:49 PM 11/23/2020 wrapped the email hash dump into a write-host cmd to get it streamed into the log at the point it's fired. 
    # 2:48 PM 10/13/2020 updated autodetect of htmltags to drive BodyAsHtml choice (in addition to explicit)
    # 1:12 PM 9/22/2020 pulled [string] type on $smtpAttachment (should be able to pass in an array of paths)
    # 12:51 PM 5/15/2020 fixed use of $global:smtpserver infra param for mybox/jumpboxes
    # 2:32 PM 5/14/2020 re-enabled & configured params - once it's in a mod, there's no picking up $script level varis (need explicits). Added -verbose support, added jumpbox alt mailing support
    # 1:14 PM 2/13/2019 Send-EmailNotif(): added $SmtpBody += "`$PassStatus triggers:: $($PassStatus)"
    # 11:04 AM 11/29/2018 added -ea 0 on the get-services, override abberant $mybox lacking new laptop
    # 1:09 PM 11/5/2018 reworked $email splat & attachment handling & validation, now works for multiple attachments, switched catch write-error's to write-hosts (was immed exiting)
    # 10:15 AM 11/5/2018 added test for MSExchangeADTopology service, before assuming running on an ex server
    #    also reworked $SMTPServer logic, to divert non-Mybox and non-EX (Lync) into vscan.
    # 9:50 PM 10/20/2017 just validating, this version has been working fine in prod
    # 10:35 AM 8/21/2014 always use a port; tested for $SMTPPort: if not spec'd defaulted to 25.
    # 10:17 AM 8/21/2014 added custom port spec for access to lynms650:8111 from my workstation
    .DESCRIPTION
    Send-EmailNotif.ps1 - Mailer function (wraps send-mailmessage)
    If using Gmail for mailings, pre-stock gmail cred file:
      To Setup a gmail app-password:
       - Google, logon, Security > 'Signing in to Google' pane:App Passwords > _Generate_:select app, Select device
       - reuse the app pw above in the credential prompt below, to store the apppassword as a credential in the current profile:
          get-credfile -PrefixTag gml -SignInAddress XXX@gmail.com -ServiceName Gmail -UserRole user
    .PARAMETER SMTPFrom
    Sender address
    .PARAMETER SmtpTo
    Recipient address
    .PARAMETER SMTPSubj
    Subject
    .PARAMETER server
    Server
    .PARAMETER SMTPPort
    Port number
    .PARAMETER useSSL
    Switch for SSL
    .PARAMETER SmtpBody
    Message Body
    .PARAMETER BodyAsHtml
    Switch for Body in Html format
    .PARAMETER SmtpAttachment
    array of attachement files
    .PARAMETER Credential
    Credential (PSCredential obj) [-credential XXXX]
    .EXAMPLE
    PS> # This normally gets triggered from Cleanup()
    # constants
    $smtpFrom = (($scriptBaseName.replace(".","-")) + "@toro.com") ;
    $smtpSubj= ("Daily Rpt: "+ (Split-Path $transcript -Leaf) + " " + [System.DateTime]::Now) ;
    #$smtpTo=$tormeta.NotificationDlUs2 ;
    #$smtpTo=$tormeta.NotificationDlUs ;
    # 1:02 PM 4/28/2017 hourly run, just send to me
    $smtpTo="dG9kZC5rYWRyaWVAdG9yby5jb20="| convertFrom-Base64String ; 
    # 12:09 PM 4/26/2017 need to email transcript before archiving it
    if($bdebug){ write-host -ForegroundColor Yellow "$((get-date).ToString('HH:mm:ss')):Mailing Report" };
    #Load as an attachment into the body text:
    #$body = (Get-Content "path-to-file\file.html" ) | converto-html ;
    #$SmtpBody += ("Pass Completed "+ [System.DateTime]::Now + "`nResults Attached: " +$transcript) ;
    $SmtpBody += "Pass Completed $([System.DateTime]::Now)`nResults Attached:($transcript)" ;
    if($PassStatus ){
        $SmtpBody += "`$PassStatus triggers:: $($PassStatus)" ;
    } ;
    $SmtpBody += ('-'*50) ;
    #$SmtpBody += (gc $outtransfile | ConvertTo-Html) ;
    # name $attachment for the actual $SmtpAttachment expected by Send-EmailNotif
    $SmtpAttachment=$transcript ;
    # 1:33 PM 4/28/2017 test for ERROR|CHANGE
    if($PassStatus ){
        $Email = @{
            smtpFrom = $SMTPFrom ;
            SMTPTo = $SMTPTo ;
            SMTPSubj = $SMTPSubj ;
            #SMTPServer = $SMTPServer ;
            SmtpBody = $SmtpBody ;
        } ;
        write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):Send-EmailNotif w`n$(($Email|out-string).trim())" ; 
        Send-EmailNotif @Email;
    } else {
        write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):No Email Report: `$Passstatus is $null ; " ;
    }  ;
    SMTP Send, using From, To, Subject & Body. 
    .EXAMPLE
    PS> $smtpToFailThru=convertFrom-Base64String -string "XXXXXXXXXXx"  ; 
    if(!$showdebug){
        if((Get-Variable  -name "$($TenOrg)Meta").value.NotificationAddr2){
            $smtpTo = (Get-Variable  -name "$($TenOrg)Meta").value.NotificationAddr2 ;
        #}elseif((Get-Variable  -name "$($TenOrg)Meta").value.NotificationAddr1){
        #   $smtpTo = (Get-Variable  -name "$($TenOrg)Meta").value.NotificationAddr1 ;
        } else {
            $smtpTo=$smtpToFailThru;
        } ;
    } else {
        # debug pass, variant to: NotificationAddr1    
        #if((Get-Variable  -name "$($TenOrg)Meta").value.NotificationDlUs){
        if((Get-Variable  -name "$($TenOrg)Meta").value.NotificationAddr1){
            $smtpTo = (Get-Variable  -name "$($TenOrg)Meta").value.NotificationAddr1 ;
        } else {
            $smtpTo=$smtpToFailThru ;
        } ;
    };
    if($tenOrg -eq 'HOM' ){
        $SMTPServer = "smtp.gmail.com" ; 
        $smtpFrom = $smtpTo ; # can only send via gmail from the auth address
    } else {
        $SMTPServer = $global:smtpserver ; 
        $smtpFromDom = (Get-Variable  -name "$($TenOrg)Meta").value.o365_OPDomain ; 
        $smtpFrom = (($CmdletName.replace(".","-")) + "@$( $smtpFromDom  )") ;
        $smtpFromDom = "gmail.com" ; 
    } ; 
    # -----------
    $smsg = "Mailing Report" ;
    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
    else{ write-verbose "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    # variant options:
    #$smtpSubj= "Proc Rpt:$($ScriptBaseName):$(get-date -format 'yyyyMMdd-HHmmtt')"   ;
    #Load as an attachment into the body text:
    #$body = (Get-Content "path-to-file\file.html" ) | converto-html ;
    #$SmtpBody += ("Pass Completed "+ [System.DateTime]::Now + "`nResults Attached: " +$transcript) ;
    # 4:07 PM 10/11/2018 giant transcript, no send
    #$SmtpBody += "Pass Completed $([System.DateTime]::Now)`nResults Attached:($transcript)" ;
    #$SmtpBody += "Pass Completed $([System.DateTime]::Now)`nTranscript:($transcript)" ;
    # group out the PassStatus_$($tenorg) strings into a report for eml body
    if($script:PassStatus){
        if($summarizeStatus){
            if(get-command -Name summarize-PassStatus -ea STOP){
                if($script:TargetTenants){
                    # loop the TargetTenants/TenOrgs and summarize each processed
                    #foreach($TenOrg in $TargetTenants){
                        $SmtpBody += "`n===Processing Summary: $($TenOrg):" ;
                        if((get-Variable -Name PassStatus_$($tenorg)).value){
                            if((get-Variable -Name PassStatus_$($tenorg)).value.split(';') |Where-Object{$_ -ne ''}){
                                $SmtpBody += (summarize-PassStatus -PassStatus (get-Variable -Name PassStatus_$($tenorg)).value -verbose:$($VerbosePreference -eq 'Continue') );
                            } ;
                        } else {
                            $SmtpBody += "(no processing of mailboxes in $($TenOrg), this pass)" ;
                        } ;
                        $SmtpBody += "`n" ;
                    #} ;
                } ;
                if($PassStatus){
                    if($PassStatus.split(';') |Where-Object{$_ -ne ''}){
                        $SmtpBody += (summarize-PassStatus -PassStatus $PassStatus -verbose:$($VerbosePreference -eq 'Continue') );
                    } ;
                } else {
                    $SmtpBody += "(no `$PassStatus updates, this pass)" ;
                } ;
            } else {
                $smsg = "Unable to gcm summarize-PassStatus!" ; ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN} #Error|Warn|Debug
                else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
                throw $smsg
            }  ;
        } else {
            # dump PassStatus right into the email
            $SmtpBody += "`n`$script:PassStatus: $($script:PassStatus):" ;
        } ;
        if($outRpt -AND ($ProcMov.count -OR  $ProcTV.count) ){
            $smtpBody += $outRpt ;
        } ;
        if($SmtpAttachment){
            $smtpBody +="(Logs Attached)"
        };
        $SmtpBody += "`n$('-'*50)" ;
        # Incl $transcript in body, where fewer than limit of processed items logged in PassStatus
        # If using $Transcripts, there're 3 TenOrg-lvl transcripts, as an array, not approp
        if( ($script:PassStatus.split(';') |?{$_ -ne ''}|measure).count -lt $TranscriptItemsLimit){
            # add full transcript if less than limit entries in array
            $SmtpBody += "`nTranscript:$(gc $transcript)`n" ;
        } else {
            # attach $trans
            #if(!$ArchPath ){ $ArchPath = get-ArchivePath } ;
            $ArchPath = 'c:\tmp\' ;
            # path static trans from archpath
            #$archedTrans = join-path -path $ArchPath -childpath (split-path $transcript -leaf) ;
            # OR: if attaching array of transcripts (further down) - summarize fullname into body
            if($Alltranscripts){
                $Alltranscripts |ForEach-Object{
                    $archedTrans = join-path -path $ArchPath -childpath (split-path $_ -leaf) ;
                    $smtpBody += "`nTranscript accessible at:`n$($archedTrans)`n" ;
                } ;
            } ;
        };
    }
    $SmtpBody += "Pass Completed $([System.DateTime]::Now)" + "`n" + $MailBody ;
    # raw text body rendered in OL loses all CrLfs - do rendered html/css <pre/pre> approach
    $styleCSS = "<style>BODY{font-family: Arial; font-size: 10pt;}" ;
    $styleCSS += "TABLE{border: 1px solid black; border-collapse: collapse;}" ;
    $styleCSS += "TH{border: 1px solid black; background: #dddddd; padding: 5px; }" ;
    $styleCSS += "TD{border: 1px solid black; padding: 5px; }" ;
    $styleCSS += "</style>" ;
    $html = @"
    <html>
    <head>
    $($styleCSS)
    <title>$title</title></head>
    <body>
    <pre>
    $($smtpBody)
    </pre>
    </body>
    </html>
    "@ ;
    $smtpBody = $html ;
    # Attachment options:
    # 1. attach raw pathed transcript
    #$SmtpAttachment=$transcript ;
    # 2. IfMail: Test for ERROR
    #if($script:passstatus.split(';') -contains 'ERROR'){
    # 3. IfMail $PassStatus non-blank
    if([string]::IsNullOrEmpty($script:PassStatus)){
        $smsg = "No Email Report: `$script:PassStatus isNullOrEmpty" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
    } else {
        $Email = @{
            smtpFrom = $SMTPFrom ;
            SMTPTo = $SMTPTo ;
            SMTPSubj = $SMTPSubj ;
            SMTPServer = $SMTPServer ;
            SmtpBody = $SmtpBody ;
            SmtpAttachment = $SmtpAttachment ;
            BodyAsHtml = $false ; # let the htmltag rgx in Send-EmailNotif flip on as needed
            verbose = $($VerbosePreference -eq "Continue") ;
        } ;
        # for gmail sends: add rqd params - note: GML requires apppasswords (non-user cred)
        $Email.add('Credential',$mailcred.value) ;
        $Email.add('useSSL',$true) ;
        $smsg = "Send-EmailNotif w`n$(($Email|out-string).trim())" ;
        if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Info } #Error|Warn|Debug
        else{ write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ;
        Send-EmailNotif @Email ;
    } ;
    Full blown gmail mailer BP
    .LINK
    https://github.com/tostka/verb-Network
    #>
    <# Underlying available send-mailmessage params: (set up param aliases)
    Send-MailMessage [-To] <String[]> [-Subject] <String> [[-Body] <String>] [[-SmtpServer] <String>] [-Attachments
    <String[]>] [-Bcc <String[]>] [-BodyAsHtml] [-Cc <String[]>] [-Credential <PSCredential>]
    [-DeliveryNotificationOption <DeliveryNotificationOptions>] [-Encoding <Encoding>] [-Port <Int32>] [-Priority
    <MailPriority>] [-UseSsl] -From <String> [<CommonParameters>]
    #>
    [CmdletBinding(DefaultParameterSetName='SMTP')]
    PARAM(
        [parameter(Mandatory=$true,HelpMessage="Sender address")]
        [alias("from","SenderAddress")]
        [string] $SMTPFrom,
        [parameter(Mandatory=$true,HelpMessage="Recipient address")]
        [alias("To","RecipientAddress")]
        [string] $SmtpTo,
        [parameter(Mandatory=$true,HelpMessage="Subject")]
        [alias("Subject")]
        [string] $SMTPSubj,
        [parameter(HelpMessage="Server")]
        [alias("server")]
        [string] $SMTPServer,
        [parameter(HelpMessage="Port number")]
        [alias("port")]
        [int] $SMTPPort,
        [parameter(ParameterSetName='Smtp',HelpMessage="Switch for SSL")]        
        [parameter(ParameterSetName='Gmail',Mandatory=$true,HelpMessage="Switch for SSL")]
        [int] $useSSL,
        [parameter(Mandatory=$true,HelpMessage="Message Body")]
        [alias("Body")]
        [string] $SmtpBody,
        [parameter(HelpMessage="Switch for Body in Html format")]
        [switch] $BodyAsHtml,
        [parameter(HelpMessage="array of attachement files")]
        [alias("attach","Attachments","attachment")]
        $SmtpAttachment,
        [parameter(ParameterSetName='Gmail',HelpMessage="Switch to trigger stock Gmail send options (req Cred & useSSL)")]
        [switch] $GmailSend,
        [parameter(ParameterSetName='Smtp',HelpMessage="Credential (PSCredential obj) [-credential XXXX]")]        
        [parameter(ParameterSetName='Gmail',Mandatory=$true,HelpMessage="Credential (PSCredential obj) [-credential XXXX]")]
        [System.Management.Automation.PSCredential]$Credential
    )
<# #-=-=-=MUTUALLY EXCLUSIVE PARAMS OPTIONS:-=-=-=-=-=
# designate a default paramset, up in cmdletbinding line
[CmdletBinding(DefaultParameterSetName='SETNAME')]
  # * set blank, if none of the sets are to be forced (eg optional mut-excl params)
  # * force exclusion by setting ParameterSetName to a diff value per exclusive param
# example:single $Computername param with *multiple* ParameterSetName's, and varying Mandatory status per set
    [Parameter(ParameterSetName='LocalOnly', Mandatory=$false)]
    $LocalAction,
    [Parameter(ParameterSetName='Credential', Mandatory=$true)]
    [Parameter(ParameterSetName='NonCredential', Mandatory=$false)]
    $ComputerName,
    # $Credential as tied exclusive parameter
    [Parameter(ParameterSetName='Credential', Mandatory=$false)]
    $Credential ;    
    # effect: 
    -computername is mandetory when credential is in use
    -when $localAction param (w localOnly set) is in use, neither $Computername or $Credential is permitted
    write-verbose -verbose:$verbose "ParameterSetName:$($PSCmdlet.ParameterSetName)"
    Can also steer processing around which ParameterSetName is in force:
    if ($PSCmdlet.ParameterSetName -eq 'LocalOnly') {
        return "some localonly stuff" ; 
    } ;     
#-=-=-=-=-=-=-=-=
#>
    $verbose = ($VerbosePreference -eq "Continue") ; 
    if ($PSCmdlet.ParameterSetName -eq 'gmail') {
        $useSSL = $true; 
    } ;     
    # before you email conv to str & add CrLf:
    $SmtpBody = $SmtpBody | out-string
    # just default the port if missing, and always use it
    if ($SMTPPort -eq $null) {
        $SMTPPort = 25;
    }	 # if-block end

    if ( ($myBox -contains $env:COMPUTERNAME) -OR ($AdminJumpBoxes -contains $env:COMPUTERNAME) ) {
        $SMTPServer = $global:SMTPServer ;
        $SMTPPort = $smtpserverport ; # [infra file]
        write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):Mailing:$($SMTPServer):$($SMTPPort)" ;
    }
    elseif ((Get-Service -Name MSExchangeADTopology -ea 0 ) -AND (get-exchangeserver $env:computername | Where-Object {$_.IsHubTransportServer})) {
        $SMTPServer = $env:computername ;
        write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):Mailing Locally:$($SMTPServer)" ;
    }
    elseif ((Get-Service -Name MSExchangeADTopology -ea 0 ) ) {
        # non Hub Ex server, draw from local site
        $htsrvs = (Get-ExchangeServer | Where-Object {  ($_.Site -eq (get-exchangeserver $env:computername ).Site) -AND ($_.IsHubTransportServer) } ) ;
        $SMTPServer = ($htsrvs | get-random).name ;
        write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):Mailing Random Hub:$($SMTPServer)" ;
    }
    else {
        # non-Ex servers, non-mybox: Lync etc, assume vscan access
        write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):Non-Exch server, assuming Vscan access" ;
        $SMTPServer = "vscan.toro.com" ;
    } ;

    # define/update variables into $Email splat for params
    $Email = @{
        From       = $SMTPFrom ;
        To         = $SMTPTo ;
        Subject    = $($SMTPSubj) ;
        SMTPServer = $SMTPServer ;
        Body       = $SmtpBody ;
        BodyAsHtml = $false ; 
        verbose = $verbose ; 
    } ;

    if($Credential){
        write-verbose "Adding specified credential" ; 
        $Email.add('Credential',$Credential) ; 
    } ; 
    
    if($useSSL){
        write-verbose "Adding specified credential" ; 
        $Email.add('useSSL',$useSSL) ; 
    } ; 
    
    [array]$validatedAttachments = $null ;
    if ($SmtpAttachment) {
        # attachment send
        if ($SmtpAttachment -isnot [system.array]) {
            if (test-path $SmtpAttachment) {$validatedAttachments += $SmtpAttachment }
            else {write-warning "$((get-date).ToString('HH:mm:ss')):UNABLE TO GCI ATTACHMENT:$($SmtpAttachment)" }
        }
        else {
            foreach ($attachment in $SmtpAttachment) {
                if (test-path $attachment) {$validatedAttachments += $attachment }
                else {write-warning "$((get-date).ToString('HH:mm:ss')):UNABLE TO GCI ATTACHMENT:$($attachment)" }  ;
            } ;
        } ;
    } ; 

    if ($host.version.major -ge 3) {$Email.add("Port", $($SMTPPort));}
    elseif ($SmtpPort -ne 25) {
        write-warning "$((get-date).ToString('HH:mm:ss')):Less than Psv3 detected: send-mailmessage does NOT support -Port, defaulting (to 25) ";
    } ;

    # trigger html if body has html tags in it
    if ($BodyAsHtml -OR ($SmtpBody -match "\<[^\>]*\>")) {$Email.BodyAsHtml = $True } ;

    # dumping to pipeline appears out of sync in console put it into a write- command to keep in sync
    write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):send-mailmessage w`n$(($email |out-string).trim())" ; 
    if ($validatedAttachments) {write-host -foregroundcolor green "$((get-date).ToString('HH:mm:ss')):`$validatedAttachments:$(($validatedAttachments|out-string).trim())" } ;
    $error.clear()
    TRY {
        if ($validatedAttachments) {
            # looks like on psv2?v3 attachment is an array, can be pipelined in too
            $validatedAttachments | send-mailmessage @email ;
        }
        else {
            send-mailmessage @email
        } ;
    }
    Catch {
        Write-Warning "$(get-date -format 'HH:mm:ss'): Failed processing $($_.Exception.ItemName). `nError Message: $($_.Exception.Message)`nError Details: $($_)" ;
    } ; 
    $error.clear() ;
}

#*------^ Send-EmailNotif.ps1 ^------


#*------v summarize-PassStatus.ps1 v------
function summarize-PassStatus {
    <#
    .SYNOPSIS
    summarize-PassStatus - Summarize $PassStatus string (semi-colon-delimited array) into a grouped formatted herestring report of the histogram of values. 
    .NOTES
    Version     : 1.0.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 20201012-0849AM
    FileName    : summarize-PassStatus
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka/
    REVISIONS
    * 8:49 AM 10/12/2020 init
    .DESCRIPTION
    summarize-PassStatus - Summarize $PassStatus string (semi-colon-delimited array) into a grouped formatted herestring report of the histogram of values. 
    .OUTPUTS
    System.String
    .EXAMPLE
    $SmtpBody += (summarize-PassStatus -PassStatus ';CHANGE;CHANGE;CHANGE;CHANGE;CHANGE;CHANGE;ERROR;ADD' )
    Returns a summary historgram of the specified semi-colon-delimited array of PassStatus values
    .EXAMPLE
    # group out the PassStatus_$($tenorg) strings into a report for eml body
    if($script:PassStatus){
        if($summarizeStatus){
            if($script:TargetTenants){
                # loop the TargetTenants/TenOrgs and summarize each processed
                foreach($TenOrg in $TargetTenants){
                    $SmtpBody += "`n===Processing Summary: $($TenOrg):" ; 
                    if((get-Variable -Name PassStatus_$($tenorg)).value){
                        if((get-Variable -Name PassStatus_$($tenorg)).value.split(';') |?{$_ -ne ''}){
                            $SmtpBody += (summarize-PassStatus -PassStatus (get-Variable -Name PassStatus_$($tenorg)).value -verbose:$($VerbosePreference -eq 'Continue') );
                        } ; 
                    } else {
                        $SmtpBody += "(no processing of mailboxes in $($TenOrg), this pass)" ; 
                    } ; 
                    $SmtpBody += "`n" ; 
                } ; 
            } ;
        } else { 
            # dump PassStatus right into the email
            $SmtpBody += "`n`$script:PassStatus: $($script:PassStatus):" ; 
        } ;
        if($SmtpAttachment){ 
            $smtpBody +="(Logs Attached)" 
        };
        $SmtpBody += "`n$('-'*50)" ;
    }
    .LINK
    https://github.com/tostka/verb-Network
    #>
    [CmdletBinding()] 
    Param(
        [Parameter(Position=0,Mandatory=$True,HelpMessage="Semi-colon-delimited string of PassStatus elements, to be summarized in a returned report[-PassStatus 'TEN1']")]
        [ValidateNotNullOrEmpty()]
        [string]$PassStatus
    ) ;
    BEGIN {$Verbose = ($VerbosePreference -eq 'Continue') } ;
    PROCESS {
        $Error.Clear() ;
        if($StatusElems = $PassStatus.split(';') |?{$_ -ne ''}){
        $Rpt = @"
    
`$PassStatus Triggers Summary::

$(($StatusElems | group | sort count -desc | ft -auto Count,Name|out-string).trim())
    
"@ ; 
        } else {
            $Rpt = @"
    
`$PassStatus Triggers Summary::

(no `$PassStatus elements passed)
    
"@ ; 
        } ; 
    } ;  # PROC-E
    END{
          $Rpt | write-output ; 
    } ;
}

#*------^ summarize-PassStatus.ps1 ^------


#*------v summarize-PassStatusHtml.ps1 v------
function summarize-PassStatusHtml {
    <#
    .SYNOPSIS
    summarize-PassStatusHtml - Summarize $PassStatus string (semi-colon-delimited array) into a grouped formatted HTML report of the histogram of values. 
    .NOTES
    Version     : 1.0.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 20201012-0849AM
    FileName    : summarize-PassStatusHtml
    License     : MIT License
    Copyright   : (c) 2020 Todd Kadrie
    Github      : https://github.com/tostka/
    REVISIONS
    * 8:49 AM 10/12/2020 init, half-implemented, untested, moved to another method instead
    .DESCRIPTION
    summarize-PassStatusHtml - Summarize $PassStatus string (semi-colon-delimited array) into a grouped formatted HTML (fragment) report of the histogram of values. 
    .OUTPUTS
    System.String
    .EXAMPLE
    $datatable = (summarize-PassStatusHtml -PassStatus ';CHANGE;CHANGE;CHANGE;CHANGE;CHANGE;CHANGE;ERROR;ADD' )
    $smtpBody = ConvertTo-HTML -Body "$datatable" -Title "" -PostContent "<p>(Creation Date: $((get-date -format 'yyyyMMdd-HHmmtt'))<p>" 
    Returns a summary historgram of the specified semi-colon-delimited array of PassStatus values
    .LINK
    https://github.com/tostka/
    #>
    
    [CmdletBinding()] 
    Param(
        [Parameter(Position=0,Mandatory=$True,HelpMessage="Semi-colon-delimited string of PassStatus elements, to be summarized in a returned report[-PassStatus 'TEN1']")]
        [ValidateNotNullOrEmpty()]
        [string]$PassStatus
    ) ;
    BEGIN {$Verbose = ($VerbosePreference -eq 'Continue') } ;
    PROCESS {
        $Error.Clear() ;
        if($StatusElems = $script:PassStatus.split(';') |?{$_ -ne ''}){

            $datatable = $StatusElems | group | sort count -desc  | ConvertTo-Html -Property count,Name -Fragment -PreContent "<h2>`$PassStatus Triggers Summary::</h2>" ; 
            # full html build in the return 
            #$Report = ConvertTo-HTML -Body "$datatable" -Title "`$PassStatus Triggers Summary::" -PostContent "<p>(Creation Date: $((get-date -format 'yyyyMMdd-HHmmtt'))<p>" 

            <#
            $Rpt = @"
    
`$PassStatus Triggers Summary::

$(($StatusElems | group | sort count -desc | ft -auto Count,Name|out-string).trim())
    
"@ ; 
#>
        } else {

            $datatable = "<h2>`$PassStatus Triggers Summary::</h2>(no `$PassStatus elements passed)<br>" ;

            <#
            $Rpt = @"
    
`$PassStatus Triggers Summary::

(no `$PassStatus elements passed)
    
"@ ; 
#>
        } ; 
    } ;  # PROC-E
    END{
          $datatable | write-output ; 
    } ;
}

#*------^ summarize-PassStatusHtml.ps1 ^------


#*------v test-IpAddressCidrRange.ps1 v------
function test-IpAddressCidrRange{
    <#
    .SYNOPSIS
    test-IpAddressCidrRange.ps1 - evaluate an IP Address specification as either IPAddress|CidrRange|IPAddressRange
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2020-
    FileName    : 
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,Network,IPAddress
    AddedCredit : cyruslab (from public forum post, cited as 'https://powershell.org/forums/topic/detecting-if-ip-address-entered/', now gone)
    AddedWebsite: https://cyruslab.net/2018/04/26/powershellcheck-valid-ip-address-subnet-or-ip-address-range/
    AddedTwitter: 
    REVISIONS
    * 10:51 AM 8/13/2021 added to verb-network ; updated base code to work with ip6 CIDR notation ; fixed 
    bug in if/then comparisions: need to coerce subnet mask to integer, for 
    comparison (esp under ip6) ; converted to function updated format to OTB, added 
    CBH, minor param inline help etc. 
    * 4/26/2016 cyruslab posted ps code from earlier unattributed powershell.org forums post (non-function)
    .DESCRIPTION
    test-IpAddressCidrRange.ps1 - evaluate an IP Address specification as either IPAddress|CidrRange|IPAddressRange
    .PARAMETER Address
    IPAddress, CIDR notation, or IP range specification to be tested[-Address 192.168.0.1]
    .INPUTS
    Does not accept piped input
    .OUTPUTS
    System.SystemObject with Type (IPAddress|CIDRRange|IPAddressRange) and boolean Valid properties
    .EXAMPLE
    PS> $ret= test-IpAddressCidrRange -Address 192.168.1.1 ;
    if(($ret.type -eq 'IPAddress' -AND $ret.valid){'Valid IP'} ; 
    Test IP Address
    .EXAMPLE
    PS> $ret= test-IpAddressCidrRange -Address 91.198.224.29/32
    if(( $ret.type -eq 'CIDRRange' -AND $ret.valid){'Valid CIDR'} ; 
    Test CIDR notation block
    .EXAMPLE
    PS> $ret= test-IpAddressCidrRange -Address '192.168.0.1-192.168.0.200' ;
    if($ret.type -eq 'IPAddressRange' -AND $ret.valid){'Valid CIDR'} ; 
    Test IP Address range
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://cyruslab.net/2018/04/26/powershellcheck-valid-ip-address-subnet-or-ip-address-range/
    #>            
    [CmdletBinding()]
    PARAM(
        [Parameter(HelpMessage="IPAddress, CIDR notation, or IP range specification to be tested[-Address 192.168.0.1]")]
        $Address
    ) ;
    $isIPAddr = ($Address -as [IPaddress]) -as [Bool] ;
    $report=[ordered]@{
        Type = $null ;
        Valid = $false ;
    } ;
    write-verbose "specified Address:$($Address)" ;
    if($isIPAddr){
        write-verbose "Valid ip address" ;
        $report.type = 'IPAddress' ;
        $report.Valid = $true ; 
    } elseif($Address -like "*/*" -or $Address -like "*-*"){
        $cidr = $Address.split("/") ;
        if($cidr){ 
            $report.type = 'CIDRRange'
        } ;
        # ip4 CIDR range: 0 to 32
        # ip6 CIDR range: 0 to 128 - need to update to accomodate cidr ip6
        if($Address -like "*:*" -AND [int]$cidr[1] -ge 0 -AND [int]$cidr[1] -le 128){
            # CIDR ip6
            write-verbose "valid ipv6 CIDR subnet syntax" ;
            $report.Valid = $true ; 
        } elseif([int]$cidr[1] -ge 0 -and [int]$cidr[1] -le 32){
            write-verbose "valid ipv4 CIDR subnet syntax" ;
            $report.Valid = $true ; 
        }elseif($Address -like "*-*"){
            $report.type = 'IPAddressRange' ; 
            $ip = $Address.split("-") ; 
            $ip1 = $ip[0] -as [IPaddress] -as [Bool] ; 
            $ip2 = $ip[1] -as [IPaddress] -as [Bool] ; 
            if($ip -and $ip){
                write-verbose "valid ip address range" ;
                $report.Valid = $true ;
            } else{
                write-verbose "invalid range" ;
                $report.Valid = $false ;
            } ;
        } else {
            $report.type = 'INVALID' ;
            $report.Valid = $false ;
            write-warning "invalid subnet" ;
        } ; 
    }else{
        $report.type = 'INVALID' ;
        $report.Valid = $false ;
        write-warning "not valid address" ;
    } ;
    New-Object PSObject -Property $report | write-output ;   
}

#*------^ test-IpAddressCidrRange.ps1 ^------


#*------v Test-Port.ps1 v------
function Test-Port {
    <#
    .SYNOPSIS
    Test-Port() - test the specified ip/fqdn port combo
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 2022-04-12
    FileName    : test-port.ps1
    License     : MIT License
    Copyright   : (c) 2022 Todd Kadrie
    Github      : https://github.com/tostka/verb-XXX
    Tags        : Powershell
    REVISIONS
    # 12:28 PM 4/12/2022 prior was .net dependant, not psCore compliant: make it defer to and use the NetTCPIP:Test-NetConnection -ComputerName -Port alt, or psv6+ test-connection -targetname -tcpport, only fallback to .net when on Win and no other option avail); moved port valid to param block, rem'd out eapref; added position to params; updated CBH
    # 10:42 AM 4/15/2015 fomt cleanup, added help
    # vers: 8:42 AM 7/24/2014 added proper fail=$false
    # vers: 10:25 AM 7/23/2014 disabled feedback, added a return
    .DESCRIPTION
    Test-Port() - test the specified ip/fqdn port combo
    Excplicitly does not have pipeline support, to make it broadest backward-compatibile, as this func name has been in use goine way back in my code.
    .PARAMETER  Server
    Server fqdn, name, ip to be connected to
    .PARAMETER  port
    Port number to be connected to
    .EXAMPLE
    PS> test-port -ComputerName hostname -Port 1234 -verbose
    Check hostname port 1234, with verbose output
    .LINK
    https://github.com/tostka/verb-network
    #>
    PARAM(
        [parameter(Position=0,Mandatory=$true)]
        [alias("s",'ComputerName','TargetName')]
        [string]$Server,
        [parameter(Position=1,Mandatory=$true)]
        [alias("p",'TcpPort')]
        [ValidatePattern("^(6553[0-5]|655[0-2]\d|65[0-4]\d\d|6[0-4]\d{3}|[1-5]\d{4}|[1-9]\d{0,3}|0)$")]
        [int32]$Port
    )
    # tree down an if than and only use .net/win-specific netsockets if nothing else avail
    if($host.version.major -ge 6 -AND (gcm test-connection)){
        write-verbose "(Psv6+:using PS native:test-connection -Targetname  $($server) -tcpport $($port)...)" ; 
        # has *ugly* output and down-state handling, so wrap & control the output
        TRY {$PortTest = test-connection -targetname $Server -tcpport $port -Count 1 -ErrorAction SilentlyContinue -ErrorVariable Err } CATCH { $PortTest = $Null } ;
        if($PortTest -ne $null ){
            write-verbose "Success" ; 
            return $true ; 
        } else {
            write-verbose "Failure" ; 
            return $False;
        } ; 
    } elseif (gcm Test-NetConnection){
        write-verbose "(Psv5:using NetTCPIP:Test-NetConnection -computername $($server) -port $($port)...)" ; 
        # (test-netconnection  -computername boojum -port 3389 -verbose).PingSucceeded
        if( (Test-NetConnection -computername $Server -port $port).TcpTestSucceeded ){
            write-verbose "Success" ; 
            return $true ; 
        } else {
            write-verbose "Failure" ; 
            return $False;
        } ; 
    } elseif([System.Environment]::OSVersion.Platform -eq 'Win32NT'){ 
        write-verbose "(Falling back to PsWin:Net.Sockets.TcpClient)" ; 
        $Socket = new-object Net.Sockets.TcpClient
        $Socket.Connect($Server, $Port)
        if ($Socket.Connected){
            $Socket.Close()
            write-verbose "Success" ; 
            return $True;
        } else {
            write-verbose "Failure" ; 
            return $False;
        } # if-block end
        $Socket = $null
    } else {
        throw "Unsupported OS/Missing depedancy module! (missing PSCore6+, NetTCPIP, .net.sockets.tcpClient)! Aborting!" ;
    } ; 
    #} # if-E port-range valid
}

#*------^ Test-Port.ps1 ^------


#*------v test-PrivateIP.ps1 v------
function test-PrivateIP {
<#
    .SYNOPSIS
    test-PrivateIP.ps1 - Use to determine if a given IP address is within the IPv4 private address space ranges.
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2021-08-16
    FileName    : test-PrivateIP.ps1
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,Network,IP,Subnet
    AddedCredit : Mark Wragg
    AddedWebsite: https://github.com/markwragg
    AddedTwitter: 
    REVISIONS
    * 1:29 PM 8/12/2021 tweaked CBH, minor param inline help etc.
    * 9/10/2019 Mark Wragg posted rev (corresponds to PSG v1.1.14)
    .DESCRIPTION
    Use to determine if a given IP address is within the IPv4 private address space ranges.
    Returns $true or $false for a given IP address string depending on whether or not is is within the private IP address ranges.
    .PARAMETER IP
    The IP address to test[-IP 192.168.0.1]
    .EXAMPLE
    Test-PrivateIP -IP 172.16.1.2
    Result
    ------
    True
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://github.com/markwragg/PowerShell-Subnet/blob/master/Subnet/Public/Test-PrivateIP.ps1
    #>
    ##Requires -Modules DnsClient
    [CmdletBinding()]
    PARAM (
        [parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="The IP address to test[-IP 192.168.0.1]")]
        [string]$IP
    )
    BEGIN {
        ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
        $Verbose = ($VerbosePreference -eq 'Continue') ; 
    } ;  # BEG-E
    PROCESS {
        if ($IP -Match '(^127\.)|(^192\.168\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)') {
            $true ; 
        } else {
            $false ; 
        } ; 
    } ;  # PROC-E
    END {}
}

#*------^ test-PrivateIP.ps1 ^------


#*------v Test-RDP.ps1 v------
function Test-RDP {
    <#
    .SYNOPSIS
    Test-RDP() - determine if powershell is running within an RDP session
    .NOTES
    Author: Todd Kadrie
    Website:	http://toddomation.com
    Twitter:	http://twitter.com/tostka
    REVISIONS   :
    # 9:48 AM 9/25/2020 fixed to explicitly check for an RDP & clientname evari: wasn't properly firing on work box, $env:sessionname is blank, not 'Console' 
    # 3:45 PM 4/17/2020 added cbh
    # 10:45 AM 7/23/2014
    .DESCRIPTION
    Test-RDP() - determine if powershell is running within an RDP session
    RDP sets 2 environment variables on remote connect:
    $env:sessionname: RDP-Tcp#[session#]
    $env:clientname: [connecting client computername]
    If both are set, you're in an RDP 
    Proviso: unless Explorer Folder Option "Launch folder windows in a separate process" is enabled, 
    applications launched from an additional Explorer window do not have these e-varis.
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    System.Boolean
    .EXAMPLE
    if(Test-RDP){write-host "Running in RDP"} ; 
    .LINK
    #>
    # win10 on workbox doesn't have $env:SESSIONNAME -eq 'Console', below is false positive
    #if ($env:SESSIONNAME -ne 'Console') { return $True; }; 
    # better test is test match rgx on RDP-Tcp# string & $env:clientname populated 
    if(($env:sessionname -match 'RDP-Tcp#\d*') -AND ($env:clientname)){ return $True} ;
}

#*------^ Test-RDP.ps1 ^------


#*------v Convert-Int64toIP.ps1 v------
function convert-Int64toIP {
    <#
    .SYNOPSIS
    Convert-Int64toIP.ps1 - Converts 64bit Integer representation back to IPv4 Address
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2021-08-16
    FileName    : Convert-Int64toIP.ps1
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,Network,IP,Subnet
    AddedCredit : Mark Wragg
    AddedWebsite: https://github.com/markwragg
    AddedTwitter: 
    REVISIONS
        * 1:29 PM 8/12/2021 added CBH, minor param inline help etc.
    * 4/14/2019 Mark Wragg posted rev (corresponds to PSG v1.1.14)
    .DESCRIPTION
    Convert-Int64toIP.ps1 - Converts 64bit Integer representation back to IPv4 Address
    .PARAMETER IP
    The IP address to convert[-IP 192.168.0.1]
    .OUTPUT
    System.String
    .EXAMPLE
    convert-Int64toIP -int 3232235521
    Result
    ------
    192.168.0.1
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://github.com/markwragg/PowerShell-Subnet/blob/master/Subnet/Private/Convert-Int64toIP.ps1
    #>
    ###Requires -Modules DnsClient
    [CmdletBinding()]
    PARAM (
        [parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="64-bit integer IP address  representation, to be converted back to IP[-int 3232235521]")]
        [int64]$int
    )
    BEGIN {
        ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
        $Verbose = ($VerbosePreference -eq 'Continue') ; 
    } ;  # BEG-E
    PROCESS {
        (([math]::truncate($int / 16777216)).tostring() + "." + ([math]::truncate(($int % 16777216) / 65536)).tostring() + "." + ([math]::truncate(($int % 65536) / 256)).tostring() + "." + ([math]::truncate($int % 256)).tostring() )
    } ;  # PROC-E
    END {} ;
}

#*------^ Convert-Int64toIP.ps1 ^------


#*------v convert-IPtoInt64.ps1 v------
function Convert-IPtoInt64 {
<#
    .SYNOPSIS
    Convert-IPtoInt64.ps1 - Converts IP Address into a 64bit Integer representation
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     : http://www.toddomation.com
    Twitter     : @tostka / http://twitter.com/tostka
    CreatedDate : 2021-08-16
    FileName    : Convert-IPtoInt64.ps1
    License     : (none asserted)
    Copyright   : (none asserted)
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,Network,IP,Subnet
    AddedCredit : Mark Wragg
    AddedWebsite: https://github.com/markwragg
    AddedTwitter: 
    REVISIONS
    * 1:29 PM 8/12/2021 added CBH, minor param inline help etc.
    * 4/14/2019 Mark Wragg posted rev (corresponds to PSG v1.1.14)
    .DESCRIPTION
    Convert-IPtoInt64.ps1 - Converts IP Address into a 64bit Integer representation
    .PARAMETER IP
    The IP address to convert[-IP 192.168.0.1]
    .OUTPUT
    System.Int64
    .EXAMPLE
    Convert-IPtoInt64 -IP 192.168.0.1
    Result
    ------
    3232235521
    .LINK
    https://github.com/tostka/verb-Network
    .LINK
    https://github.com/markwragg/PowerShell-Subnet/blob/master/Subnet/Private/Convert-IPtoInt64.ps1
    #>
    ###Requires -Modules DnsClient
    [CmdletBinding()]
    PARAM (
        [parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="The IP address to convert[-IP 192.168.0.1]")]
        [string]$IP
    )
    BEGIN {
        ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
        $Verbose = ($VerbosePreference -eq 'Continue') ; 
    } ;  # BEG-E
    PROCESS {
        $octets = $ip.split(".") ;
        [int64]([int64]$octets[0] * 16777216 + [int64]$octets[1] * 65536 + [int64]$octets[2] * 256 + [int64]$octets[3]) ; 
    } ;  # PROC-E
    END {} ;
}

#*------^ convert-IPtoInt64.ps1 ^------


#*======^ END FUNCTIONS ^======

Export-ModuleMember -Function Add-IntToIPv4Address,Connect-PSR,Disconnect-PSR,download-file,download-filecurl,download-fileNoSSLNoSSL,get-DNSServers,get-IPSettings,Get-NetIPConfigurationLegacy,get-NetworkClass,Get-RestartInfo,get-Subnet,get-tsUsers,get-whoami,Invoke-BypassPaywall,New-RandomFilename,Invoke-SecurityDialog,Reconnect-PSR,Resolve-DNSLegacy.ps1,Resolve-SPFRecord,SPFRecord,SPFRecord,SPFRecord,test-IpAddressCidrRange,Send-EmailNotif,summarize-PassStatus,summarize-PassStatusHtml,test-IpAddressCidrRange,Test-Port,test-PrivateIP,Test-RDP -Alias *




# SIG # Begin signature block
# MIIELgYJKoZIhvcNAQcCoIIEHzCCBBsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU/xh6IC8VnJt6r8MVCVbgbOIL
# aC2gggI4MIICNDCCAaGgAwIBAgIQWsnStFUuSIVNR8uhNSlE6TAJBgUrDgMCHQUA
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
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQmIWP/
# +IEbgETItf+azP0I3/JWUzANBgkqhkiG9w0BAQEFAASBgEcJQYLQiqZjxjZILjki
# FnjaSYsU1F0R6pd1BB3rSxzK22BXsB6vRd0oRCldw4GIZnm7pgjWRwPG4aYFBrDa
# qgbQ510zBvO9HeP3//3Lwoe09cI/abC8SrE3E0nEB23EL0RtdsQOamNtI8x3PKFK
# ovM1Gow5LOFeKcSuHYE4PSr7
# SIG # End signature block
