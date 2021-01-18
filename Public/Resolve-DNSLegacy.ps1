<#
.SYNOPSIS
Resolve-DNSLegacy.ps1 - Get FQDN and IP for a list of servers.
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
* 9:23 AM 1/13/2021 TSK:updated CBH, reformated & minor tweaks
* 2015 orig posted copy
.DESCRIPTION
Get FQDN and IP for a single server, or a list of servers, specify the Ip of the DNS server otherwise it defaults to the 1st DNS Server on the PPP* nic, and then to the first non-PPP* nic.
I tweaked this version to leverage my Get-NetIPConfigurationLegacy ipconfig /all wrapper fuct, to return the DNS servers on the PPP* (VPN in my case) nic, or the non-PPP* nic, by preference.
Posted by i255d to Idera Forums (https://community.idera.com/database-tools/powershell/ask_the_experts/f/powershell_for_windows-12/22127/powershell-wrapper-for-nslookup-with-error-handling-basically-nslookup-on-steroids), tagged 'over 6 yrs ago' (in 2021 = ~2015) ; 
Updated/tweaked by TSK 2021.
.PARAMETER ComputerName
.PARAMETER DNSServerIP
.PARAMETER Whatif
.EXAMPLE
Get-Content C:\serverlist.txt | Resolve-DNSLegacy.ps1 | Export-CSV C:\ServerList.csv
.EXAMPLE
.\Resolve-DNSLegacy.ps1
.LINK
https://github.com/tostka/verb-XXX
#>
<#
.Synopsis
Get FQDN and IP for a list of servers.
.DESCRIPTION
Get FQDN and IP for a single server, or a list of servers, specify the Ip of the DNS server if you don't want 10.10.10.20.
.PARAMETER ComputerName
.PARAMETER DNSServerIP
.EXAMPLE
Get-Content C:\serverlist.txt | Resolve-DNSLegacy.ps1 | Export-CSV C:\ServerList.csv
.EXAMPLE
Another example of how to use this cmdlet
#>
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
}#end function