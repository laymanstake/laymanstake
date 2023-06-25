#Requires -Version 3.0

<#  
    Author : Nitish Kumar
    Performs Remote patching
    version 1.0 | 25/06/2023 Initial version    

    The script is kept as much modular as possible so that functions can be modified or added without altering the entire script   

    Disclaimer: This script is designed for illustration purposes only and the author do not claim to be responsible for any issues if caused by the script in production usages. Do due dilligence before running in the production environment
#>

<#
.SYNOPSIS
    Install-RemotePatch.ps1 - Performs windows patching on the remote server

.DESCRIPTION
    This script performs windows patching on the remote server

.NOTES
    - This script requires elevated privileges on the remote machine and also PS remoting being enabled is prerequisites.    

.EXAMPLE
    Running the script would ask you the name of the remote server to patch
#>

# Global Variables
$WorkDir = "c:\temp\RemoteUpdate" # This is hard-coded, script would break if any other path used
$logpath = "$env:USERPROFILE\desktop\RemoteUpdate_$(get-date -Uformat "%Y%m%d-%H%M%S").txt"
$Counter = 0

Function Write-Log {
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
            Add-content $logpath -value $LogMessage -ErrorAction SilentlyContinue
            $isWritten = $true
        }
        catch {
        }
    } until ( $isWritten )
}

Function New-BaloonNotification {
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
    Start-Sleep -s 1
    
    $tip.Dispose() # Important to dispose otherwise the icon stays in notifications till reboot
    Get-EventSubscriber -SourceIdentifier "BalloonClicked_event"  -ErrorAction SilentlyContinue | Unregister-Event # In case if the Event Subscription is not disposed
}

Function Start-ServiceCheck {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$ServerName,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)]$WorkDirectory = $WorkDir
    )
    # List of common services, which do not need to restarted if found stopped during service checks
    $Whitelist = ("Windows Installer", "Portable Device Enumerator Service", "Application Information", "Smart Card Device Enumeration Service", "Windows Modules Installer", "Windows Error Reporting Service", "Device Setup Manager", "CNG Key Isolation", "Microsoft Policy Platform Local Authority")

    # Ensure that work directory exists
    try {
        Invoke-Command -ComputerName $ServerName -scriptBlock { $null = New-Item $args[0] -ItemType Directory -ErrorAction SilentlyContinue } -ArgumentList $WorkDirectory
    }
    catch {
        $message = "Can not create folder on $($serverName), since PS remote not working. Quitting now."
        New-BaloonNotification -title "Error" -message $message
        Write-Log -logtext $message -logpath $logpath
        Exit
    }

    $WorkDirectory = $WorkDirectory -replace "^([a-z]):", "\\$serverName\`$1`$" # Covert the loca path given to UNC path    
    
    if (-NOT(Test-Path -Path $WorkDirectory)) {
        $message = "Can not check services on $($serverName), since [driveLetter]$ is not accessible. Quitting now."
        New-BaloonNotification -title "Error" -message $message
        Write-Log -logtext $message -logpath $logpath
        Exit
    }

    # Find the most recent service status report
    try {
        $ServiceStatusPath = "$WorkDirectory\$((Get-ChildItem -Path $WorkDirectory | Where-Object{$_.Name -like "$($ServerName)*.csv"} | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)} | Sort-Object LastWriteTime | Select-Object -Last 1).Name)"
    }
    catch {
        $message = "Something went wrong in finding services status on $($serverName): $($_.Exception.Message)"
        New-BaloonNotification -title "Error" -message $message
        Write-Log -logtext $message -logpath $logpath
    }
    
    if ($ServiceStatusPath -ne "$WorkDirectory\") {
        $ServiceStatus = Import-Csv -Path $ServiceStatusPath   
    
        # Service status baseline before the Patch process
        $BaseStatusPath = "$WorkDirectory\$($ServerName)_$((Get-Date -Format dd-MM-yyyy).ToString()).csv"         

        If ($ServiceStatusPath -ne $BaseStatusPath) {
            If ($ServiceStatus.count -ge 11) {            
                $message = "More than 10 Services seem to be in altered state on $($serverName), need manual attention. Quitting now.`n$($ServiceStatus)"
                New-BaloonNotification -title "Error" -message $message
                Write-Log -logtext $message -logpath $logpath
                #Exit
            }
            else {
                $message = "$($ServiceStatus.count) Services seem to be in altered state on $($serverName), Starting the services"
                New-BaloonNotification -title "Error" -message $message
                Write-Log -logtext $message -logpath $logpath
            }

            ForEach ($Service in $ServiceStatus) {
                If (($Service.Status -eq "Stopped") -AND !($Whitelist -contains $Service.DisplayName)) {
                    $message = "Starting $($Service.DisplayName) on $($ServerName)...."                
                    New-BaloonNotification -title "Warning" -message $message
                    Write-Log -logtext $message -logpath $logpath
                
                    try {
                        Get-Service -Name $Service.DisplayName -Computername $ServerName | Start-Service
                    }
                    catch {
                        $message = "Could not start $($Service.DisplayName) on $($ServerName)....`n"
                        Write-Output $message -Foregroundcolor RED
                        New-BaloonNotification -title "Error" -message $message
                        Write-Log -logtext $message -logpath $logpath
                    }
                }
            }
        }
    }
    else {
        $message = "First update pass on $($serverName)."
        New-BaloonNotification -title "Information" -message $message
        Write-Log -logtext $message -logpath $logpath
    }

    return $ServiceStatus
}

Function Start-Patch {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$ServerName,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)]$WorkDirectory = $WorkDir
    )

    # Ensure that work directory exists
    try {
        Invoke-Command -ComputerName $ServerName -scriptBlock { $null = New-Item $args[0] -ItemType Directory -ErrorAction SilentlyContinue } -ArgumentList $WorkDirectory
    }
    catch {
        $message = "Can not create folder on $($serverName), since PS remote not working. Quitting now."
        New-BaloonNotification -title "Error" -message $message
        Write-Log -logtext $message -logpath $logpath
        Exit
    }

    $WorkDirectory = $WorkDirectory -replace "^([a-z]):", "\\$serverName\`$1`$"    

    If (-Not(Test-Path -Path $WorkDirectory)) {
        $message = "$($WorkDirectory) not accessible, Either not shared or the user doesn't has admin permissions. Quitting now."
        New-BaloonNotification -title "Error" -message $message
        Write-Log -logtext $message -logpath $logpath
        Exit
    }

    $ExprStart1 = {
        $ScriptBlock1 = {
            #Variables to customize         
            $FileReportPath = "c:\temp\RemoteUpdate" # This is hard-coded, script would break if any other path used
            $AutoRestart = $true         
            $WorkDirectory = $FileReportPath
        
            # Create the directory if not already created
            $null = New-Item $WorkDirectory -ItemType Directory -ErrorAction SilentlyContinue
            $ServiceStatusPath = $FileReportPath + "\$($env:ComputerName)_$((Get-Date -Format dd-MM-yyyy).ToString()).csv" 
            $HTMLPath = $FileReportPath + "\$($env:ComputerName)_$((Get-Date -Format dd-MM-yyyy_HH-mm).ToString()).html" 
            $CSVPath = $FileReportPath + "\$($env:ComputerName)_$((Get-Date -Format dd-MM-yyyy_HH-mm).ToString()).csv" 

            # Check the services status and record either the baseline or changed services status
            if (-Not([System.IO.File]::Exists($ServiceStatusPath))) {
                Get-Service | Select-object DisplayName, servicename, starttype, status | export-csv -nti $ServiceStatusPath
            }
            Else {
                $Pre = import-csv -Path $ServiceStatusPath
                $Post = Get-Service | Select-object DisplayName, servicename, starttype, status
                Compare-object -ReferenceObject $Pre -DifferenceObject $Post -Property Status, displayname, name | Where-Object { $_.sideIndicator -eq "=>" } | export-csv -nti $CSVPath
            }

            #Testing if there are any pending reboots from earlier Windows Update sessions 
            if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
                "WindowsUpdate was run on $env:ComputerName, but there is a pending reboot already. Restarting machine first." | Out-File -FilePath $HTMLPath
                try {
                    Invoke-command -ComputerName $ServerName -ScriptBlock {
                        Set-Content "c:\temp\RemoteUpdate\RebootRequired.txt" -Value "Reboot Required" -Force
                        Exit
                    }
                }
                catch {
                    $message = "Failed to set reboot required flag on $($serverName)."
                    New-BaloonNotification -title "Error" -message $message
                    Write-Log -logtext $message -logpath $logpath    
                }
            }
            else {

                #Checking for available updates 
                $updateSession = new-object -com "Microsoft.Update.Session" 
                write-progress -Activity "Updating" -Status "Checking available updates" 
                $criteria = "IsInstalled=0 and Type='Software'"  
                $updates = $updateSession.CreateupdateSearcher().Search($criteria).Updates 
                $downloader = $updateSession.CreateUpdateDownloader()           
                $downloader.Updates = $Updates 

                #If no updates available, do nothing 
                if ($downloader.Updates.Count -eq "0") {                 
                    "WindowsUpdate was run on $env:ComputerName, but no new updates were found. Please try again later." | Out-File -FilePath $HTMLPath
                    Set-Content "c:\temp\RemoteUpdate\RebootRequired.txt" -Value "Reboot Not Required" -Force
                } 
                else { 
                    #If updates are available, download and install 
                    $resultcode = @{0 = "Not Started"; 1 = "In Progress"; 2 = "Succeeded"; 3 = "Succeeded With Errors"; 4 = "Failed" ; 5 = "Aborted" }

                    $Result = $downloader.Download()

                    if (($Result.Hresult -eq 0) -and (($result.resultCode -eq 2) -or ($result.resultCode -eq 3)) ) {
                        $updatesToInstall = New-object -com "Microsoft.Update.UpdateColl"
                        $Updates | Where-Object { $_.isdownloaded } | foreach-Object { $updatesToInstall.Add($_) | out-null
                        } 

                        $installer = $updateSession.CreateUpdateInstaller()
                        $installer.Updates = $updatesToInstall
                        $installationResult = $installer.Install()                

                        $Report = $installer.updates | Select-Object -property Title, EulaAccepted, @{Name = 'Result'; expression = { $ResultCode[$installationResult.GetUpdateResult($Global:Counter++).resultCode ] } }, @{Name = 'Reboot required'; expression = { $installationResult.GetUpdateResult($Global:Counter++).RebootRequired } } | ConvertTo-Html
                        $Report | Out-File -FilePath $HTMLPath

                        # Reboot if autorestart is enabled and one or more updates are requiring a reboot 
                        if ($autoRestart -and $installationResult.rebootRequired) { 
                            try {
                                Invoke-command -ComputerName $ServerName -ScriptBlock {
                                    Set-Content "c:\temp\RemoteUpdate\RebootRequired.txt" -Value "Reboot Required" -Force
                                    Exit
                                }
                            }
                            catch {
                                $message = "Failed to set reboot required flag on $($serverName)."
                                New-BaloonNotification -title "Error" -message $message
                                Write-Log -logtext $message -logpath $logpath    
                            }
                        }
                    } 
                }
            }
        }
        
        Set-Content -Path c:\temp\remoteupdate\InstallPatches.ps1 -Value $ScriptBlock1

        $taskAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File ""c:\temp\remoteupdate\InstallPatches.ps1"""
        $taskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date)
        $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -DontStopOnIdleEnd
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId "NT Authority\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $null = Register-ScheduledTask -TaskName "RemoteWindowsUpdate" -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Principal $taskPrincipal -Force
    }

    $ExprStart = [Scriptblock]::Create($ExprStart1)
    
    try {        
        Invoke-command -ComputerName $ServerName -ScriptBlock $ExprStart        
    }
    catch {        
        $message = "Unable to create schedule task on $($serverName): $($_.exception.message). Quitting now."
        New-BaloonNotification -title "Error" -message $message
        Write-Log -logtext $message -logpath $logpath
        Exit
    }

    # Launch the schedule task and wait till it gets completed
    $ExprStart1 = { Start-ScheduledTask -TaskName "RemoteWindowsUpdate" }
    $ExprStart = [Scriptblock]::Create($ExprStart1)

    try {        
        Invoke-command -ComputerName $ServerName -ScriptBlock $ExprStart        
    }
    catch {        
        $message = "Unable to run schedule task on $($serverName): $($_.exception.message). Quitting now."
        New-BaloonNotification -title "Error" -message $message
        Write-Log -logtext $message -logpath $logpath
        Exit
    }

    $message = "Patching is in progress on $($serverName)."
    New-BaloonNotification -title "Information" -message $message
    Write-Log -logtext $message -logpath $logpath

    $Initial = (Get-EventLog -ComputerName $serverName -LogName "System" -Source "Microsoft-Windows-WindowsUpdateClient" -After (Get-Date).AddDays(-1) -Newest 1 -ErrorAction SilentlyContinue).Message
    $count = 0
    $StartTime = Get-Date

    DO {
        $ExprStart1 = { Get-ScheduledTask -TaskName "RemoteWindowsUpdate" | Select-Object -ExpandProperty State }
        $ExprStart = [Scriptblock]::Create($ExprStart1)
        $State = Invoke-command -ComputerName $ServerName -ScriptBlock $ExprStart
        write-progress -activity "Patching started at $StartTime" -status (get-date)
        If ($Initial -ne (Get-EventLog -ComputerName $serverName -LogName "System" -Source "Microsoft-Windows-WindowsUpdateClient" -After (Get-Date).AddDays(-1) -Newest 1 -ErrorAction SilentlyContinue).Message) {
            $count++
            $Initial = (Get-EventLog -ComputerName $serverName -LogName "System" -Source "Microsoft-Windows-WindowsUpdateClient" -After (Get-Date).AddDays(-1) -Newest 1 -ErrorAction SilentlyContinue).Message
            [String]$count + ". " + $Initial
        }
    } Until ($State.Value -eq 'Ready')

    $RebootFlag = invoke-command -ComputerName $ServerName -ScriptBlock { Get-Content "c:\temp\RemoteUpdate\RebootRequired.txt" -ErrorAction SilentlyContinue }

    if ($RebootFlag -eq "Reboot Required") {
        $message = "Rebooting $($serverName)."
        New-BaloonNotification -title "Warning" -message $message
        Write-Log -logtext $message -logpath $logpath
        Restart-Computer -ComputerName $ServerName -Force -Wait -For PowerShell -Timeout 7200 -Delay 2
            
        Invoke-command -ComputerName $ServerName -ScriptBlock {
            $FileReportPath = "c:\temp\RemoteUpdate"
            $ServiceStatusPath = $FileReportPath + "\$($env:ComputerName)_$((Get-Date -Format dd-MM-yyyy).ToString()).csv" 
            $CSVPath = $FileReportPath + "\$($env:ComputerName)_$((Get-Date -Format dd-MM-yyyy_HH-mm).ToString()).csv" 

            $Pre = import-csv -Path $ServiceStatusPath
            $Post = Get-Service | Select-object DisplayName, servicename, starttype, status
            Compare-object -ReferenceObject $Pre -DifferenceObject $Post -Property Status, displayname, name | Where-Object { $_.sideIndicator -eq "=>" } | export-csv -nti $CSVPath
        }
    }
    else {
        $message = "Patching pass completed on $($serverName). Reboot not required."
        New-BaloonNotification -title "Information" -message $message
        Write-Log -logtext $message -logpath $logpath    
    }    
    
    $PendingUpdates = Get-Content -tail 3 "\\$($servername)\c$\Windows\SoftwareDistribution\ReportingEvents.log"
    
    if (($PendingUpdates -contains "detected 0 updates") -ne "") {
        While (($PendingUpdates -contains "detected 0 updates") -ne "") {        
            $PendingUpdates = Get-Content -tail 3 "\\$($servername)\c$\Windows\SoftwareDistribution\ReportingEvents.log"        
            Start-Patch -ServerName $ServerName
            $message = "Patches still pending, running another pass on $($serverName)."
            New-BaloonNotification -title "Information" -message $message
            Write-Log -logtext $message -logpath $logpath
            Start-Sleep 15
        } 
    }

    $ServiceStatus = Start-ServiceCheck -ServerName $ServerName

    $message = "Patching pass completed on $($serverName) at $((Get-Date).ToString())."    
    New-BaloonNotification -title "Information" -message $message
    Write-Log -logtext $message -logpath $logpath

    $Patches = Invoke-command -ComputerName $ServerName -ScriptBlock { Get-WmiObject -Class "win32_quickfixengineering" | Select-Object -Property "Description", "HotfixID", @{Name = "InstalledOn"; Expression = { ([DateTime]($_.InstalledOn)).ToLocalTime() } } | ? { $_.InstalledOn -ge (Get-Date).AddDays(-1) } }    

    $message = "Removing script file and schedule task from $($serverName)."
    New-BaloonNotification -title "Information" -message $message
    Write-Log -logtext $message -logpath $logpath
    try {
        Invoke-command -ComputerName $ServerName -ScriptBlock {
            $null = Remove-Item "c:\temp\RemoteUpdate\Installpatches.ps1" -Force -ErrorAction SilentlyContinue
            $null = Remove-Item "c:\temp\RemoteUpdate\RebootRequired.txt"  -Force -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName "RemoteWindowsUpdate" -Confirm:$false
        }
    }
    catch {
        $message = "Failed to remove script file and schedule task from $($serverName)."
        New-BaloonNotification -title "Error" -message $message
        Write-Log -logtext $message -logpath $logpath    
    }

    $Results = [PSCustomObject]@{
        Services = $ServiceStatus
        Patches  = $Patches        
    }

    Return $Results
}

Clear-Host
$RemoteComputer = Read-Host "Enter the Server name to patch and reboot: "
$Results = Start-Patch -ServerName $RemoteComputer

Write-Output "The services in Altered state `n" 
$Results.Services | Format-Table DisplayName, Status

Write-Output "The list of patches installed today `n" 
$Results.Patches | Format-Table PSComputerName, InstalledOn, HotfixID, Description
