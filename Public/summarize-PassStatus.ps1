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
