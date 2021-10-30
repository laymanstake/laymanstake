# Author : Nitish Kumar
# Performs a cleanup of WSUS.
# Outputs the results to a text file.
# version 1.4
# 07 March 2017
# 1.2 Revised on 22 May 2017
# 1.3 Revised on 8 December 2017
# 1.4 Revised on 29 January 2018
# 1.5 Revised on 30 May 2018

Clear-Host
#PS version Checking
$PSV = $PSVersionTable.PSVersion.Major

[void][reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration")

if ($psv -lt 3) {
	Write-Information "This script will only work on PowerShell v3 and above."
	[void][System.Console]::ReadKey($TRUE)
	Exit
}

#Specify the input server list file bellow
$Servers = ("WSUS1","WSUS2","WSUS3")

$StartMS0 = (Get-date)

#Deleting old jobs, if any
Get-Job "WSUS*" | Stop-Job
Get-Job "WSUS*" | Remove-Job
$FailedServers = @()

$MAXJOB = "30"
$i = $null

$thisDir = "c:\WSUSTemp"
$logFile = "WSUSCleanupResults_$((Get-Date).ToString('MM-dd-yyyy_hh-mm-ss')).txt"
Start-Transcript -Path $thisDir\$logFile

foreach ($Server in $Servers) {
	$i++
	Write-Progress -Activity "Creating job for WSUS Clean-up .." -Status $Server -PercentComplete (100 * $i / ($Servers.count))
	#Adding Jobs
	Start-Job -Name "WSUS.$Server" -ScriptBlock {
		[void][reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration")
		try {
			$StartMS1 = (Get-date)
			Try { $WSUS = [Microsoft.UpdateServices.Administration.AdminProxy]::getUpdateServer($args[0], $false, 8530) }
			Catch { $WSUS = [Microsoft.UpdateServices.Administration.AdminProxy]::getUpdateServer($args[0], $false, 80) }
			$StartMS2 = (Get-date)

			write-output "$args[0] took $(($StartMS2 - $StartMS1).TotalSeconds) seconds in being connected"

			$cleanupScope = new-object Microsoft.UpdateServices.Administration.CleanupScope;

			$cleanupScope.CleanupObsoleteComputers = $true
			$cleanupScope.DeclineSupersededUpdates = $true
			$cleanupScope.DeclineExpiredUpdates = $true
			$cleanupScope.CleanupObsoleteUpdates = $true
			$cleanupScope.CleanupUnneededContentFiles = $true
			$cleanupScope.CompressUpdates = $true
			$cleanupManager = $WSUS.GetCleanupManager();
			$cleanupManager.PerformCleanup($cleanupScope);
			$LastSync = $WSUS.GetSubscription().LastSynchronizationTime

			$StartMS3 = (Get-date)
			write-output "$args[0] took $(($StartMS3 - $StartMS2).TotalSeconds) seconds in cleanup."
			write-output "Last Synchronization time for $args[0] with upstream is $LastSync"
		}
		catch [Exception] {
			Write-Information $_.Exception.GetType().FullName -foregroundcolor Red
			Write-Information $_.Exception.Message -foregroundcolor Red
			write-output "ERROR: Cleaning failed for $args[0]. Hope you ran the script in admin mode and have admin rights on $args[0]"
			continue;
		}

	} -ArgumentList $Server | Out-Null

	$getRunningJobsCount = (Get-Job "WSUS*" | Where-Object { $_.State -eq "Running" }).count
	while ($getRunningJobsCount -gt $MAXJOB) {
		Write-Progress -Activity "Reached maximum number of threads ($($MAXJOB))..." -Status "Wait till it gets reduced.." -PercentComplete (100 * $i / ($Servers.count))
		Start-Sleep 10
		$getRunningJobsCount = (Get-Job "WSUS*" | Where-Object { $_.State -eq "Running" }).count
	}
}

$t = 0
While (Get-Job "WSUS*" | Where-Object { $_.State -eq "Running" }) {
	$CurrentRunningJobs = (Get-Job "WSUS*" | Where-Object { $_.State -eq "Running" }).count
	Write-Progress -Activity "Jobs are running, please wait." -Status "$($CurrentRunningJobs) jobs running" -PercentComplete (100 * ($i - $CurrentRunningJobs) / $i)
	$t++
	Clear-Host
	$c = " "
	$JobStatus = "$c"
	Write-Information $JobStatus -foregroundcolor Yellow
	Start-Sleep 1
}

#Collecting the data from Jobs
$Result = @()
foreach ($Job in (Get-Job | Where-Object { $_.Name -like "WSUS.*" })) {
	$JobResult = $null
	$JobResult = Receive-Job $Job
	$Result += $JobResult
	Remove-Job $Job
}
$Result

$StartMS4 = (Get-date)

write-output "Today it took $(($StartMS4 - $StartMS0).TotalSeconds) seconds in cleanup."
$Sel = select-string -pattern "Error" -path $logFile

ForEach ($s in $Sel.line) {
	$FailedServers += $s.split(" ")[-1]
}
write-output "A total $($FailedServers.count) servers failed: `n$($FailedServers -join ",")"

Stop-Transcript

If ($Sel) {
	Get-Item $logFile | Rename-Item -NewName ("Failed-" + $logFile)
	notepad ("Failed-" + $logFile)
}
Else {
	Get-Item $logFile | Rename-Item -NewName ("Successfull-" + $logFile)
	notepad ("Sucessfull-" + $logFile)
}