#Requires -Version 3.0

<#  
    Author : Nitish Kumar
    Gets WSUS Inventory
    version 1.0 | 18/07/2023 Initial version    

    The script is kept as much modular as possible so that functions can be modified or added without altering the entire script
    It should be run as administrator and preferably Enterprise Administrator to get complete data. Its advised to run in demonstration environment to be sure first

    Disclaimer: This script is designed to only read data and should not cause any problems or change configurations but author do not claim to be responsible for any issues. Do due dilligence before running in the production environment

    LIST OF FUNCTIONS
    1. Write-Log                       # This function creates log entries for the major steps in the script.
    2. New-BaloonNotification          # This function creates a balloon notification to display on client computers.
    3. Get-WSUSReport                  # The main functions which generates the WSUS report
#>

<#
.SYNOPSIS
    Get-WSUSReport.ps1 - Gets report from given list of WSUS servers.

.DESCRIPTION
    This script generates WSUS report with details of available updates, pending updates etc

.NOTES    
    - Ensure that the required PowerShell modules and dependencies are installed.

.EXAMPLE
    Get-WSUSReport -wsusserver "DC2016" | Format-Table
#>

# This function creates log entries for the major steps in the script.
function Write-Log {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$logtext,
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$logpath
    )

    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    $LogMessage = "$Stamp : $logtext"
    
    $isWritten = $false

    do {
        try {
            Add-content $logpath -value $LogMessage -Force -ErrorAction SilentlyContinue
            $isWritten = $true
        }
        catch {
        }
    } until ( $isWritten )
}

# This function creates a balloon notification to display on client computers.
function New-BaloonNotification {
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)][String]$title,
        [Parameter(ValueFromPipeline = $true, mandatory = $true)][String]$message,        
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][ValidateSet('None', 'Info', 'Warning', 'Error')][String]$icon = "Info",
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][scriptblock]$Script
    )
    Add-Type -AssemblyName System.Windows.Forms

    if ($null -eq $script:balloonToolTip) { $script:balloonToolTip = New-Object System.Windows.Forms.NotifyIcon }

    $tip = New-Object System.Windows.Forms.NotifyIcon

    $path = Get-Process -id $pid | Select-Object -ExpandProperty Path    
    $tip.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path)
    $tip.BalloonTipIcon = $Icon
    $tip.BalloonTipText = $message
    $tip.BalloonTipTitle = $title    
    $tip.Visible = $true            
    
    try {
        register-objectevent $tip BalloonTipClicked BalloonClicked_event -Action { $script.Invoke() } | Out-Null
    }
    catch {}
    $tip.ShowBalloonTip(10000) # Even if we set it for 1000 milliseconds, it usually follows OS minimum 10 seconds
    Start-Sleep -seconds 1
    
    $tip.Dispose() # Important to dispose otherwise the icon stays in notifications till reboot
    Get-EventSubscriber -SourceIdentifier "BalloonClicked_event"  -ErrorAction SilentlyContinue | Unregister-Event # In case if the Event Subscription is not disposed
}

$scriptBlock1 = ${function:Write-log}
$scriptBlock2 = ${function:New-BaloonNotification}
    
$initScript = [scriptblock]::Create(@"
    function Write-log {$scriptBlock1}
    function New-BaloonNotification {$scriptBlock2}
"@)

function Get-WSUSReport {
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$wsusserver,        
        [Parameter(ValueFromPipeline = $true, mandatory = $false)]$logFile = "$env:userprofile\desktop\WSUSReport__$(get-date -Uformat "%Y%m%d-%H%M%S").txt"
    )

    $jobs = @()
    $WSUSSummary = @()
    $maxParallelJobs = 50    

    ForEach ($WS1 in $wsusserver) {
        while ((Get-Job -State Running | Where-Object { $_.Name -like "WSUSServer_*" }).Count -ge $maxParallelJobs) {
            Start-Sleep -Milliseconds 50  # Wait for 0.05 seconds before checking again
        }

        $scriptBlock = {
            param ($WS1, $report, $logFile, $maxParallelJobs)

            $infoObject = @()
            $WSUS = $null

            try {
                [void][reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration")
            }
            catch {        
                $message = "Local machine doesn't seem to have WSUS related modules. Can not continue."
                New-BaloonNotification -title "Error" -message $message -icon "Error"
                Write-Log -logtext $message -logpath $logfile
                Exit
            }

            try {
                Try {
                    # Try with port 8530 first
                    $WSUS = [Microsoft.UpdateServices.Administration.AdminProxy]::getUpdateServer($WS1, $false, 8530)
                }
                Catch {                
                    try {
                        # If port 8530 doesn't work then try with port 80
                        $WSUS = [Microsoft.UpdateServices.Administration.AdminProxy]::getUpdateServer($WS1, $false, 80)
                    }
                    catch {
                        $message = "Unable to connect to $($WS1) over port 8530 or 80. Need to update the code for any other ports. Can not continue."
                        New-BaloonNotification -title "Error" -message $message -icon "Error"
                        Write-Log -logtext $message -logpath $logfile
                        Continue
                    }
                }

                $ComputerScope = New-Object Microsoft.UpdateServices.Administration.ComputerTargetScope
                $UpdateScope = New-Object Microsoft.UpdateServices.Administration.UpdateScope
                $UpdateScope.ApprovedStates = [Microsoft.UpdateServices.Administration.ApprovedStates]::LatestRevisionApproved
                $updatescope.IncludedInstallationStates = [Microsoft.UpdateServices.Administration.UpdateInstallationStates]::All

                $ComputerTargetGroups = $WSUS.GetComputerTargetGroups() | Where-Object { $_.Name -eq 'All Computers' }
                $MemberOfGroup = $WSUS.getComputerTargetGroup($ComputerTargetGroups.Id).GetComputerTargets()
            
                $message = "Connected and Fetching the data from $($WS1) for all computers connecting to it..."
                New-BaloonNotification -title "Information" -message $message
                Write-Log -logtext $message -logpath $logfile
            
                # Data from all computers connected to given WSUS
                $Alldata = $WSUS.GetSummariesPerComputerTarget($updatescope, $computerscope)
            
                $message = "Data recieved from $WS1 for all computers connecting to it..."
                New-BaloonNotification -title "Information" -message $message
                Write-Log -logtext $message -logpath $logfile

                $Subjobs = @()

                if ($Alldata) {
                    Foreach ($Object in $Alldata) {
                        while ((Get-Job -State Running  | Where-Object { $_.Name -like "WSUSClient_*" }).Count -ge $maxParallelJobs) {
                            Start-Sleep -Milliseconds 50  # Wait for 0.05 seconds before checking again
                        }

                        $SubScript = {
                            param ($object, $MemberOfGroup, $WS, $report, $logFile)
                            $WSUSClientStatus = @()
                            
                            [void][reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration")
                            Try {
                                # Try with port 8530 first
                                $WSUS = [Microsoft.UpdateServices.Administration.AdminProxy]::getUpdateServer($WS, $false, 8530)
                            }
                            Catch {                
                                try {
                                    # If port 8530 doesn't work then try with port 80
                                    $WSUS = [Microsoft.UpdateServices.Administration.AdminProxy]::getUpdateServer($WS, $false, 80)
                                }
                                catch {                                    
                                    Continue
                                }
                            }

                            Try {
                                Foreach ($object1 in $MemberOfGroup) {                                    
                                    If ($object.computertargetid -match $object1.id) {
                                        $NeededUpdateReport = @()
                                        $NeededUpdateDateReport = @()

                                        $ComputerTargetToUpdate = $WSUS.GetComputerTargetByName($object1.FullDomainName)                                        
                                        $NeededUpdate = $ComputerTargetToUpdate.GetUpdateInstallationInfoPerUpdate() | Where-Object { ($_.UpdateApprovalAction -eq "install") -and (($_.UpdateInstallationState -eq "Downloaded") -or ($_.UpdateInstallationState -eq "Notinstalled") -or ($_.UpdateInstallationState -eq "Failed"))	}

                                        if ($null -ne $NeededUpdate) {
                                            foreach ($Update in $NeededUpdate) {
                                                $NeededUpdateReport += ($WSUS.GetUpdate([Guid]$Update.updateid)).KnowledgebaseArticles
                                                $NeededUpdateDateReport += ($WSUS.GetUpdate([Guid]$Update.updateid)).ArrivalDate.ToString("dd/MM/yyyy ")
                                            }
                                        }

                                        $WSUSClient = [PSCustomObject]@{
                                            ClientName                  = $Object1.FullDomainName
                                            NeededCount                 = $NeededUpdate.count
                                            LastSyncTime                = $object1.LastSyncTime                                    
                                            InstalledPendingRebootCount = $object.InstalledPendingRebootCount
                                            NotInstalledCount           = $object.NotInstalledCount
                                            DownloadedCount             = $object.DownloadedCount
                                            InstalledCount              = $object.InstalledCount
                                            FailedCount                 = $object.FailedCount
                                            NotApplicable               = $object.NotApplicableCount
                                            Needed                      = $NeededUpdateReport
                                            NeededDate                  = $NeededUpdateDateReport
                                            IPAddress                   = $object1.IPAddress
                                            OS                          = $object1.OSDescription                                    
                                        }
                                
                                        $WSUSClientStatus += $WSUSClient
                                    }
                                }
                            }
                            catch {                                
                                continue
                            }

                            $WSUSClientStatus = $WSUSClientStatus | Select-object ClientName, NeededCount, LastSyncTime, InstalledPendingRebootCount, NotInstalledCount, DownloadedCount, InstalledCount, FailedCount, @{Name = "Needed"; Expression = { $_.Needed -join "," } }, @{Name = "ArrivalDate"; Expression = { $_.NeededDate -join "," } }, NotApplicable, IPAddress, OS
                            
                            $WSUSClientStatus
                        }

                        $Subjobs += Start-Job -Name "WSUSClient_$($WS1)" -ScriptBlock $SubScript -ArgumentList $object, $MemberOfGroup, $WSUS.Name, $report, $logFile
                    }

                    $output = $SubJobs | Wait-Job | Receive-Job

                    foreach ($result in $output) {
                        $infoObject += $result
                    }
                }
                else {
                    $message = "No comtputers connected to $WS1"
                    New-BaloonNotification -title "Warning" -message $message -icon "Warning"
                    Write-Log -logtext $message -logpath $logfile
                }
            }
            catch {
                $message = "Error occured while collecting the data from WSUS server $($WS1): $_.Exception.Message."
                New-BaloonNotification -title "Error" -message $message -icon "Error"
                Write-Log -logtext $message -logpath $logfile                    
                continue
            }

            $infoObject  | Select-object ClientName, NeededCount, LastSyncTime, InstalledPendingRebootCount, NotInstalledCount, DownloadedCount, InstalledCount, FailedCount, Needed, ArrivalDate, NotApplicable, IPAddress, OS
        }

        $jobs += Start-Job -Name "WSUSServer_$($WS1)" -ScriptBlock $scriptBlock -ArgumentList $WS1, $report, $logFile, $maxParallelJobs -InitializationScript $initscript
    }

    $output1 = $Jobs | Wait-Job | Receive-Job

    foreach ($result in $output1) {
        $WSUSSummary += $result | Select-object ClientName, NeededCount, LastSyncTime, InstalledPendingRebootCount, NotInstalledCount, DownloadedCount, InstalledCount, FailedCount, Needed, ArrivalDate, NotApplicable, IPAddress, OS
    }

    return $WSUSSummary
}

Get-WSUSReport -wsusserver "DC2016" | Format-Table

# Remove if any residue jobs left
$null = Get-Job | Where-Object { $_.Name -like "WSUS*" } | Remove-Job -Force
