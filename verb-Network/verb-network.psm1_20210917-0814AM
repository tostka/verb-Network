# verb-network.psm1


<#
.SYNOPSIS
verb-Network - Generic network-related functions
.NOTES
Version     : 1.0.25.0
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
    * 3:00 PM 1/14/2021 updated CBH, minor revisions & tweaking
    .DESCRIPTION
    This script displays DNS servers list of each IP enabled network connection in local or remote computer (Note:only displays Nics with IPEnabled=TRUE, which ignores VPN tunnels)
    .Parameter ComputerName
    Computer Name(s) from which you want to query the DNS server details. If this
    parameter is not used, the the script gets the DNS servers from local computer network adapaters.
    .EXAMPLE.Example 1
        Get-DNSServers.ps1 -ComputerName MYTESTPC21
        Get the DNS servers information from a remote computer MYTESTPC21.
    .LINK
    https://github.com/tostka/verb-XXX
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
    Get-NetIPConfigurationLegacy.ps1 - Wrapper for ipconfig, as Legacy/alt version of PSv3+'s 'get-NetIPConfiguration' cmdlet
    (to my knowledge) by get-NetIPConfiguration.
    .NOTES
    Version     : 1.0.0
    Author      : Todd Kadrie
    Website     :	http://www.toddomation.com
    Twitter     :	@tostka / http://twitter.com/tostka
    CreatedDate : 20210114-1055AM
    FileName    : Get-NetIPConfigurationLegacy.ps1
    License     : MIT License
    Copyright   : (c) 2021 Todd Kadrie
    Github      : https://github.com/tostka/verb-Network
    Tags        : Powershell,Network,Ipconfig,Legacy
    AddedCredit : REFERENCE
    AddedWebsite:	URL
    AddedTwitter:	URL
    REVISIONS
    * 11:02 AM 1/14/2021 initial vers. Still needs to accomodate Wins Servers (aren't config'd on my box):
    Ethernet adapter nic:

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
    Wrapper for ipconfig, as either Legacy version of PSv3+'s 'get-NetIPConfiguration' cmdlet, 
    or as a means to parse and leverage properties *displayed* by ipconfig, that aren't surfaced 
    (to my knowledge) by get-NetIPConfiguration.
    Parses the propreties of each adapter output into an object. 
    My intent was to grab the PPP* adapter's DNSServers while on VPN. Couldn't find the properties 
    exposed in the stock cmdlet or WMI (probably there, didn't find *yet*), 
    so I wrote my own quick-n-ugly parser of ipconfig's /all output. :D 
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
                    $nic.Description = ($output[$i+1] -split -split ": ")[1].trim() ;
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
                    $nic.Description = ($output[$i+1] -split -split ": ")[1].trim() ;
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
    * 1:29 PM 8/12/2021 tweaked CBH, minor param inline help etc.
    * 9/10/2019 Mark Wragg posted rev (corresponds to PSG v1.1.14)
    .DESCRIPTION
    Use to determine the network class of a given IP address.
    Returns A, B, C, D or E depending on the numeric value of the first octet of a given IP address.
    .OUTPUT
    System.String
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

#*------v get-Subnet.ps1 v------
function get-Subnet {
    <#
    .SYNOPSIS
    get-Subnet.ps1 - Returns subnet details for the local IP address, or a given network address and mask.
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
    Tags        : Powershell,Network,IP,Subnet
    AddedCredit : Mark Wragg
    AddedWebsite: https://github.com/markwragg
    AddedTwitter: 
    REVISIONS
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
    Description
    -----------
    Returns the subnet details for the specified network and mask, specified as a single string to the -IP parameter.
    .EXAMPLE
    Get-Subnet 192.168.0.1 -MaskBits 23
    Description
    -----------
    Returns the subnet details for the specified network and mask.
    .EXAMPLE
    Get-Subnet
    Description
    -----------
    Returns the subnet details for the current local IP.
    .EXAMPLE
    '10.1.2.3/24','10.1.2.4/24' | Get-Subnet
    Description
    -----------
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
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=0)]
        [alias("Computer")]
        [ValidateLength(3,35)]
        [string[]]$Computername,
        [Parameter(Position=1)]
        [string]$DNSServerIP,
        [Parameter(Position=2)]
        [string] $ErrorFile
    )
    Begin{
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
    Process{
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
    End{} ; 
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
    
    from [PowerShell Tip: Resolve SPF Records - Cloudbrothers - cloudbrothers.info/](https://cloudbrothers.info/en/powershell-tip-resolve-spf/):
    Supported SPF directives and functions
     - include
     - mx
     - a
     - ip4 und ip6
     - redirect
     - Warning for too many include entries
    Not supported
     - exp
     - Makros
     - Usage
     
    For the query of the corresponding TXT records in the DNS only the paramater name is needed. The domain to be queried must be specified here, and the script does the rest.
    Resolve-SPFRecord -Name domainname.tld
    It is recommended to output the result with 'Format-Table' for better readability.
    Resolve-SPFRecord -Name domainname.tld | ft
    Alternative DNS server
    Optionally, the Server parameter can be used. Defaults to defaults to cloudflare resolver 1.1.1.1 (secondary is 1.0.0.1):
    [Introducing DNS Resolver, 1.1.1.1 (not a joke) - blog.cloudflare.com/](https://blog.cloudflare.com/dns-resolver-1-1-1-1/)
    With this you change the DNS server to be queried. This can be helpful, for example, if you want to test the DNS changes directly on your own root name server shortly after the update, or if there are restrictions on which DNS server your client is allowed to query.
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
    ...
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
                                    write-host -ForegroundColor gray "(Validated ip4: entry format is:$($matches[0]))" 
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
    Author: Todd Kadrie
    Website:	http://www.toddomation.com
    Twitter:	@tostka, http://twitter.com/tostka
    Website:	URL
    Twitter:	URL
    REVISIONS   :
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
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output.
    .EXAMPLE
        # This normally gets triggered from Cleanup()
        # constants
        $smtpFrom = (($scriptBaseName.replace(".","-")) + "@toro.com") ;
        $smtpSubj= ("Daily Rpt: "+ (Split-Path $transcript -Leaf) + " " + [System.DateTime]::Now) ;
        #$smtpTo="emailadmin@toro.com" ;
        #$smtpTo="LYNDLISMessagingReports@toro.com" ;
        # 1:02 PM 4/28/2017 hourly run, just send to me
        $smtpTo="todd.kadrie@toro.com" ;
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
    .LINK
    #>

    <# send-mailmessage params: (set up param aliases)
    Send-MailMessage [-To] <String[]> [-Subject] <String> [[-Body] <String>] [[-SmtpServer] <String>] [-Attachments
    <String[]>] [-Bcc <String[]>] [-BodyAsHtml] [-Cc <String[]>] [-Credential <PSCredential>]
    [-DeliveryNotificationOption <DeliveryNotificationOptions>] [-Encoding <Encoding>] [-Port <Int32>] [-Priority
    <MailPriority>] [-UseSsl] -From <String> [<CommonParameters>]
    #>
    [CmdletBinding()]
    PARAM(
        [parameter(Mandatory=$true)]
        [alias("from")]
        [string] $SMTPFrom,
        [parameter(Mandatory=$true)]
        [alias("To")]
        [string] $SmtpTo,
        [parameter(Mandatory=$true)]
        [alias("subj","Subject")]
        [string] $SMTPSubj,
        [parameter(Mandatory=$false)]
        [alias("server")]
        [string] $SMTPServer,
        [parameter(Mandatory=$false)]
        [alias("port")]
        [string] $SMTPPort,
        [parameter(Mandatory=$true)]
        [alias("Body")]
        [string] $SmtpBody,
        [parameter(Mandatory=$false)]
        [string] $BodyAsHtml,
        [parameter(Mandatory=$false)]
        [alias("attach","Attachments","attachment")]
        $SmtpAttachment
    )
    $verbose = ($VerbosePreference -eq "Continue") ; 
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
    Author: Todd Kadrie
    Website:	http://toddomation.com
    Twitter:	http://twitter.com/tostka

    REVISIONS   :
    # call: Test-Port $server $port
    # 10:42 AM 4/15/2015 fomt cleanup, added help
    # vers: 8:42 AM 7/24/2014 added proper fail=$false
    # vers: 10:25 AM 7/23/2014 disabled feedback, added a return
    .PARAMETER  Server
    Server fqdn, name, ip to be connected to
    .PARAMETER  port
    Port number to be connected to
    .INPUTS
    None. Does not accepted piped input.
    .OUTPUTS
    None. Returns no objects or output.
    .EXAMPLE
    .EXAMPLE
    .LINK
    *----------^ END Comment-based Help  ^---------- #>

    PARAM(
        [parameter(Mandatory=$true)]
        [alias("s")]
        [string]$Server,
        [parameter(Mandatory=$true)]
        [alias("p")]
        [int]$Port
    )

    # 10:46 AM 4/15/2015 validate port in supported range: 0 -65536
    if( $Port -notmatch "^(6553[0-5]|655[0-2]\d|65[0-4]\d\d|6[0-4]\d{3}|[1-5]\d{4}|[1-9]\d{0,3}|0)$" ) {
        throw "$($Port) is an INVALID port. ABORTING";
    } else {
        $ErrorActionPreference = "SilentlyContinue"
        $Socket = new-object Net.Sockets.TcpClient
        $Socket.Connect($Server, $Port)

        if ($Socket.Connected){
            #write-host "We have successfully connected to the server" -ForegroundColor Yellow -BackgroundColor Black
            $Socket.Close()
            # 9:54 AM 7/23/2014 added return true/false
            return $True;
        } else {
            #write-host "The port seems to be closed or you cannot connect to it" -ForegroundColor Red -BackgroundColor Black
            return $False;
        } # if-block end
        $Socket = $null
    } # if-E port-range valid
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

Export-ModuleMember -Function Add-IntToIPv4Address,Connect-PSR,Disconnect-PSR,download-file,download-filecurl,download-fileNoSSLNoSSL,get-DNSServers,get-IPSettings,Get-NetIPConfigurationLegacy,get-NetworkClass,get-Subnet,get-whoami,Reconnect-PSR,Resolve-DNSLegacy.ps1,Resolve-SPFRecord,SPFRecord,SPFRecord,SPFRecord,test-IpAddressCidrRange,Send-EmailNotif,summarize-PassStatus,summarize-PassStatusHtml,test-IpAddressCidrRange,Test-Port,test-PrivateIP,Test-RDP -Alias *


# SIG # Begin signature block
# MIIELgYJKoZIhvcNAQcCoIIEHzCCBBsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU/zjMQrRs2Gz3d2MKmhOm/oNp
# u9CgggI4MIICNDCCAaGgAwIBAgIQWsnStFUuSIVNR8uhNSlE6TAJBgUrDgMCHQUA
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
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBS4ClL7
# yNne0obPeoKh7Rm8qieDuTANBgkqhkiG9w0BAQEFAASBgKd14qYEHXvF2GtjiZhp
# vn2Ecps2jN/fUWhxAzS3Iu9PQmN1v/W9Cu8ZzK9jhFZc9Ld1XxWBsv+gaLduCQ1P
# 36JLgwlD/Y/5I9MI7fVuQApm18YHvZfFhj9Zqj0MBk8aidn1o4Zn2DwhhUQGyWAx
# XIhmocJ/yvFVh9+yK1DFY1Fk
# SIG # End signature block
