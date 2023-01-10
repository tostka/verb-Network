# Test-IPAddressInRange.ps1

#*------v Function Test-IPAddressInRange v------
        function Test-IPAddressInRange {
            <#
            .SYNOPSIS
            Test-IPAddressInRange - Test an array of IP Addreses for presence in specified CIDR-notated subnet range. 
            .NOTES
            Version     : 0.0.5
            Author      : Nick James (omniomi)
            Website     : http://www.toddomation.com
            Twitter     : @tostka / http://twitter.com/tostka
            CreatedDate : 2022-11-03
            FileName    : Test-IPAddressInRange
            License     : (none asserted)
            Copyright   : (none asserted)
            Github      : https://github.com/tostka/verb-network
            Tags        : Powershell
            AddedCredit : Todd Kadrie
            AddedWebsite: http://www.toddomation.com
            AddedTwitter: @tostka / http://twitter.com/tostka
            REVISIONS
            * 11:57 AM 1/5/2023 TSK flipped $IPAddress type from [string] to [ipaddress]; Added CBH, and example; converted to Adv Func syntax; 
            added pipeline support on the IPAddress input ; simplfied compound stmts ; added to verb-Network.
            * Apr 17, 2018 Nick James (omniomi) posted github version from: https://github.com/omniomi/PSMailTools/blob/v0.2.0/src/Private/spf/IPInRange.ps1
            .DESCRIPTION
            .SYNOPSIS
            Test-IPAddressInRange - Test an array of IP Addreses for presence in specified CIDR-notated subnet range.
            .PARAMETER 

            .INPUTS
            None. Does not accepted piped input.(.NET types, can add description)
            .OUTPUTS
            System.Boolean
            .EXAMPLE
            PS> IPInRange 10.10.10.230 10.10.10.10/24 ; 
                True
            Feed it an IP and a CIDR address and it returns true or false.
            .EXAMPLE
            PS>  if((Test-IPAddressInRange -IPAddress 10.10.10.230,10.10.11.230 -Range 10.10.10.10/24 -verbose) -contains $false){
            PS>      write-warning 'FAIL!';
            PS>  } else { write-host "TRUE!"} ;
                WARNING: FAIL!
            Test an array of ips against the specified CIDR subnet, and warn if any fails (outside of the subnet).
            .EXAMPLE
            PS> @('10.10.10.230','10.10.11.230') | Test-IPAddressInRange -Range 10.10.10.10/24 -verbose ;
            Pipeline demo, fed with array of ip's.
            .LINK
            https://github.com/tostka/verb-network
            .LINK
            https://github.com/omniomi/PSMailTools/blob/v0.2.0/src/Private/spf/IPInRange.ps1
            #>
            # VALIDATORS: [ValidateNotNull()][ValidateNotNullOrEmpty()][ValidateLength(24,25)][ValidateLength(5)][ValidatePattern("some\sregex\sexpr")][ValidateSet("US","GB","AU")][ValidateScript({Test-Path $_ -PathType 'Container'})][ValidateScript({Test-Path $_})][ValidateRange(21,65)]#positiveInt:[ValidateRange(0,[int]::MaxValue)]#negativeInt:[ValidateRange([int]::MinValue,0)][ValidateCount(1,3)]
            [outputtype([System.Boolean])]
            [CmdletBinding()]
            PARAM(
                [parameter(Mandatory=$true, Position=0,ValueFromPipeline = $True,HelpMessage="Array of IP Addresses to be compared to specified Range[-IPAddress 192.168.1.1")]
                [validatescript({([System.Net.IPAddress]$_).AddressFamily -eq 'InterNetwork'})]
                [ipaddress[]]$IPAddress,
                [parameter(Mandatory,Position=1,HelpMessage="CIDR-notated subnet specification[-Range 10.10.10.10/24")]
                [validatescript({
                    $IP,$Bits  = $_ -split '/' 
                     (([System.Net.IPAddress]($IP)).AddressFamily -eq 'InterNetwork') 
                    if (-not($Bits)) {
                        throw 'Missing CIDR notiation.' 
                    } elseif (-not(0..32 -contains [int]$Bits)) {
                        throw 'Invalid CIDR notation. The valid bit range is 0 to 32.' ; 
                    } ; 
                })]
                [alias('CIDR')]
                [string]$Range
            ) ;
            BEGIN{
                #region CONSTANTS-AND-ENVIRO #*======v CONSTANTS-AND-ENVIRO v======
                # function self-name (equiv to script's: $MyInvocation.MyCommand.Path) ;
                ${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name ;
                #region BANNER ; #*------v BANNER v------
                $sBnr="#*======v $(${CmdletName}): v======" ;
                $smsg = $sBnr ;
                write-verbose "$($smsg)"  ;
                #endregion BANNER ; #*------^ END BANNER ^------
                $verbose = ($VerbosePreference -eq "Continue") ;
                $PSParameters = New-Object -TypeName PSObject -Property $PSBoundParameters ;
                write-verbose -message "`$PSBoundParameters:`n$(($PSBoundParameters|out-string).trim())" ;
                #endregion CONSTANTS-AND-ENVIRO ; #*------^ END CONSTANTS-AND-ENVIRO ^------       

                write-verbose "Split range into the address and the CIDR notation" ; 
                [String]$CIDRAddress,[int]$CIDRBits = $Range.Split('/') ; 

                if ($PSCmdlet.MyInvocation.ExpectingInput) {
                    write-verbose -message "Data received from pipeline input: '$($InputObject)'" ; 
                } else {
                    #write-verbose "Data received from parameter input: '$($InputObject)'" ; 
                    write-verbose -message "(non-pipeline - param - input)" ; 
                } ; 
            } ; 
            PROCESS{
                foreach($item in $IPAddress){
                    $sBnrS="`n#*------v PROCESSING : $($item.IPAddressToString) v------" ; 
                    write-verbose -message "$($sBnrS)" ;
            
                    write-verbose "Address from range and the search address are converted to Int32 and the full mask is calculated from the CIDR notation."
                    [int]$BaseAddress    = [System.BitConverter]::ToInt32((([System.Net.IPAddress]::Parse($CIDRAddress)).GetAddressBytes()), 0) ; 
                    [int]$Address        = [System.BitConverter]::ToInt32(([System.Net.IPAddress]::Parse($item).GetAddressBytes()), 0) ; 
                    [int]$Mask           = [System.Net.IPAddress]::HostToNetworkOrder(-1 -shl ( 32 - $CIDRBits)) ; 

                    write-verbose "Determine whether the address is in the range. (-band == bitwise-AND)"
                    if (($BaseAddress -band $Mask) -eq ($Address -band $Mask)) {
                        $true ; 
                    } else {
                        $false ; 
                    } ;  
                    write-verbose -message "$($sBnrS.replace('-v','-^').replace('v-','^-'))" ;

                } ;  # loop-E
            }  # PROC-E
            END{
                write-verbose -message "$($sBnr.replace('=v','=^').replace('v=','^='))" ;
            } ;
        } ; 
        #*------^ END Function Test-IPAddressInRange ^------