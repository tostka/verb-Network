#*----------v Function get-DNSServers() v----------
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
} ; 
#*------^ END Function get-DNSServers() ^------