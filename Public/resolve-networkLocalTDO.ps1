# resolve-networkLocalTDO.ps1

#region RESOLVE_NETWORKLOCALTDO ; #*------v resolve-NetworkLocalTDO v------
if (-not(gi function:resolve-NetworkLocalTDO -ea 0)) {
    Function resolve-NetworkLocalTDO {
        <#
        .SYNOPSIS
        resolve-NetworkLocalTDO.ps1 - Retrieve local network settings - interface descriptors and resolved ip address PTR -> A Record FQDN, also returns Domain/Workgroup info
        .NOTES
        Version     : 0.0.1
        Author      : Todd Kadrie
        Website     : http://www.toddomation.com
        Twitter     : @tostka / http://twitter.com/tostka
        CreatedDate : 2025-04-28
        FileName    : resolve-NetworkLocalTDO.ps1
        License     : MIT License
        Copyright   : (c) 2025 Todd Kadrie
        Github      : https://github.com/tostka/verb-XXX
        Tags        : Powershell
        AddedCredit : REFERENCE
        AddedWebsite: URL
        AddedTwitter: URL
        REVISIONS
        * 11:20 AM 9/17/2025 removed write-my* calls: implemented support in vio\write-log() instead (avoids all this manual updating)
        * 10:45 AM 8/6/2025 added write-myOutput|Warning|Verbose support (for xopBuildLibrary/install-Exchange15.ps1 compat)
        * 4:07 PM 5/15/2025 added psv2-compat hash code; get-cim|wmiobject Win32_ComputerSystem wasn't returning a Domain or Workgroup property, unless |select -expand used, so tacked on 2 explicit queries for the properties.
        12:55 PM 5/13/2025 added get-CimInstance/get-WMIInstance fail through logic, added OS.Domain & .Workgroup properties to return
        .DESCRIPTION
        resolve-NetworkLocalTDO.ps1 - Retrieve local network settings - interface descriptors and resolved ip address PTR -> A Record FQDN, also returns Domain/Workgroup info
        .INPUTS
        None. Does not accepted piped input.(.NET types, can add description)
        .OUTPUTS
        System.PsCustomObject summary of useful Nic descriptors
        .EXAMPLE
        PS> $netsettings = resolve-NetworkLocalTDO ;
        Demo run
        .LINK
        https://github.com/tostka/verb-Network
        #>
        [CmdletBinding()]
        Param () ;
        BEGIN {
            $rgxIP4Addr = "(?:\d{1,3}\.){3}\d{1,3}" ;
            $rgxIP6Addr = "^((([0-9A-Fa-f]{1,4}:){1,6}:)|(([0-9A-Fa-f]{1,4}:){7}))([0-9A-Fa-f]{1,4})$" ;
            $rgxIP4AddrAuto = "169\.254\.\d{1,3}\.\d{1,3}" ;
            $prpNS = 'DNSHostName', 'ServiceName', @{N = "DNSServerSearchOrder"; E = { "$($_.DNSServerSearchOrder)" } },
            @{N = 'IPAddress'; E = { $_.IPAddress } }, @{N = 'DefaultIPGateway'; E = { $_.DefaultIPGateway } } ;
        } ;
        PROCESS {

            if ($host.version.major -ge 3) { $netsettings = [ordered]@{Dummy = $null ; } }
            else { $netsettings = @{Dummy = $null ; } } ;
            if ($netsettings.keys -contains 'dummy') { $netsettings.remove('Dummy') };
            #$fieldsBoolean = 'isLocalExchangeServer','IsEdgeTransport','isEx2019','isEx2016','isEx2010','isEx2007','isEx2003','isEx2000' | sort ; $fieldsBoolean | foreach-object { $netsettings.add($_,$false) } ;
            $fieldsnull = 'DNSHostName', 'ServiceName', 'DNSServerSearchOrder', 'IPAddress', 'DefaultIPGateway', 'Fqdn', 'Domain', 'Workgroup' | sort ; $fieldsnull | foreach-object { $netsettings.add($_, $null) } ;

            TRY {
                if (get-command get-ciminstance -ea 0) {
                    $OS = (Get-ciminstance -class Win32_OperatingSystem -ea STOP) ;
                    $netsettings.Domain = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Domain ;
                    $netsettings.Workgroup = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Workgroup ;
                    $nic = Get-ciminstance -class Win32_NetworkAdapterConfiguration -ComputerName localhost -ea STOP ;
                } else {
                    $OS = (Get-WmiObject -Class Win32_ComputerSystem -ea STOP)
                    $netsettings.Domain = Get-WmiObject -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Domain ;
                    $netsettings.Workgroup = Get-WmiObject -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Workgroup ;
                    $nic = Get-WMIObject Win32_NetworkAdapterConfiguration -Computername localhost -ea STOP ;
                } ;
                if ($nic = $nic | ? { $_.IPEnabled -match "True" } | Select -property $prpNS) {
                    $netsettings.DNSHostName = $nic.DNSHostName;
                    $netsettings.ServiceName = $nic.ServiceName;
                    $netsettings.DNSServerSearchOrder = $nic.DNSServerSearchOrder;
                    $netsettings.IPAddress = $nic.IPAddress;
                    $netsettings.DefaultIPGateway = $nic.DefaultIPGateway;
                    if ($netsettings.ipaddress | ? { $_ -MATCH $rgxIP4Addr -AND $_ -notmatch $rgxIP4AddrAuto } ) {
                        $netsettings.fqdn = (resolve-dnsname -name ($netsettings.ipaddress | ? { $_ -MATCH $rgxIP4Addr -AND $_ -notmatch $rgxIP4AddrAuto } ) -type ptr).namehost | select -first 1 ;
                    } ;
                } else {
                    $smsg = "No IPEnabled NIC found!" ; 
                    $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level Error} else{ write-ERROR "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                    throw $smsg ;
                }
                # 9:45 AM 5/13/2025 add workgroup collection, if non-domain-joined
                if ($env:Userdomain -eq $env:COMPUTERNAME) {
                    $smsg = "%USERDOMAIN% -EQ %COMPUTERNAME%: $($env:computername) => non-domain-connected, likely edge role Ex server!" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                }
                if ($netsettings.Workgroup) {
                    $smsg = "WorkgroupName:$($WorkgroupName)" ;
                    if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
                } ;
                [pscustomobject]$netsettings | write-output ;
            } CATCH {
                $ErrTrapd = $Error[0] ;
                $smsg = "`n$(($ErrTrapd | fl * -Force|out-string).trim())" ;
                if ($logging) { Write-Log -LogContent $smsg -Path $logfile -useHost -Level WARN -Indent} else{ write-WARNING "$((get-date).ToString('HH:mm:ss')):$($smsg)" } ; 
            } ;
        } ;
    } ; 
} ;
#endregion RESOLVE_NETWORKLOCALTDO ; #*------^ END resolve-NetworkLocalTDO ^------