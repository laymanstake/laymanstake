# Author : Nitish Kumar
# Performs an audit of WSUS
# Outputs the results to a text file.
# version 1.2
# 21 May 2017 / Test commit

[void][reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration")

$DomainName = "." + $env:USERDNSDOMAIN

# Create empty arrays to contain collected data.
$UpdateStatus = @()
$SummaryStatus = @()

# For WSUS servers catering servers
$WSUSServers = ("XYZ", "ABC", "WSUS1")

$a0 = ($WSUSServers | Measure-Object).count
$b0 = 0

$thisDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$logFile = "WSUSAuditReports_$((Get-Date).ToString('MM-dd-yyyy_hh-mm-ss')).txt"
Start-Transcript -Path $thisDir\$logFile


ForEach ($WS1 in $WSUSServers) {
	Write-Output "Working on $WS1 ..."	-foregroundcolor Green
	$b0 = $b0 + 1

	try {

		Try {
			$WSUS = [Microsoft.UpdateServices.Administration.AdminProxy]::getUpdateServer($WS1, $false, 8530)
		}
		Catch {
			$WSUS = [Microsoft.UpdateServices.Administration.AdminProxy]::getUpdateServer($WS1, $false, 80)
		}

		$ComputerScope = New-Object Microsoft.UpdateServices.Administration.ComputerTargetScope
		$UpdateScope = New-Object Microsoft.UpdateServices.Administration.UpdateScope
		$UpdateScope.ApprovedStates = [Microsoft.UpdateServices.Administration.ApprovedStates]::LatestRevisionApproved
		$updatescope.IncludedInstallationStates = [Microsoft.UpdateServices.Administration.UpdateInstallationStates]::All

		$ComputerTargetGroups = $WSUS.GetComputerTargetGroups() | Where-Object { $_.Name -eq 'All Computers' }
		$MemberOfGroup = $WSUS.getComputerTargetGroup($ComputerTargetGroups.Id).GetComputerTargets()	

		Write-Output "Connected and Fetching the data from $WS1 for all computers connecting to it..."
		$Alldata = $WSUS.GetSummariesPerComputerTarget($updatescope, $computerscope)
		$a = ($Alldata | Measure-Object).count
		$b = 0

		Write-Output "Data recieved from $WS1 for all computers connecting to it..."

		Foreach ($Object in $Alldata) {
			$b = $b + 1
			Write-Output "Getting data from number $b of all $a computers connecting to $WS1 ($b0 of $a0)..."	-foregroundcolor Yellow

			Try {
				Foreach ($object1 in $MemberOfGroup) {
					If ($object.computertargetid -match $object1.id) {

						$ComputerTargetToUpdate = $WSUS.GetComputerTargetByName($object1.FullDomainName)
						$NeededUpdate = $ComputerTargetToUpdate.GetUpdateInstallationInfoPerUpdate() | Where-Object { ($_.UpdateApprovalAction -eq "install") -and (($_.UpdateInstallationState -eq "Downloaded") -or ($_.UpdateInstallationState -eq "Notinstalled") -or ($_.UpdateInstallationState -eq "Failed"))	}

						$NeededUpdateReport = @()
						$NeededUpdateDateReport = @()

						if ($null -ne $NeededUpdate) {
							foreach ($Update in $NeededUpdate) {
								$NeededUpdateReport += ($WSUS.GetUpdate([Guid]$Update.updateid)).KnowledgebaseArticles
								$NeededUpdateDateReport += ($WSUS.GetUpdate([Guid]$Update.updateid)).ArrivalDate.ToString("dd/MM/yyyy ")
							}
						}

						$object1 | Select-Object -ExpandProperty FullDomainName
						$myObject1 = New-Object -TypeName PSObject
						$myObject1 | add-member -type Noteproperty -Name Server -Value (($object1 | Select-Object -ExpandProperty FullDomainName) -replace $DomainName, "")
						$myObject1 | add-member -type Noteproperty -Name NotInstalledCount -Value $object.NotInstalledCount
						$myObject1 | add-member -type Noteproperty -Name NotApplicable -Value $object.NotApplicableCount
						$myObject1 | add-member -type Noteproperty -Name DownloadedCount -Value $object.DownloadedCount
						$myObject1 | add-member -type Noteproperty -Name InstalledCount -Value $object.InstalledCount
						$myObject1 | add-member -type Noteproperty -Name InstalledPendingRebootCount -Value $object.InstalledPendingRebootCount
						$myObject1 | add-member -type Noteproperty -Name FailedCount -Value $object.FailedCount
						$myObject1 | add-member -type Noteproperty -Name NeededCount -Value ($NeededUpdate | Measure-Object).count
						$myObject1 | add-member -type Noteproperty -Name Needed -Value $NeededUpdateReport
						$myObject1 | add-member -type Noteproperty -Name LastSyncTime -Value $object1.LastSyncTime
						$myObject1 | add-member -type Noteproperty -Name IPAddress -Value $object1.IPAddress
						$myObject1 | add-member -type Noteproperty -Name OS -Value $object1.OSDescription
						$myObject1 | add-member -type Noteproperty -Name NeededDate -Value $NeededUpdateDateReport
						$SummaryStatus += $myObject1
					}
				}
			}
			catch {
				Write-Output $_.Exception.GetType().FullName -foregroundcolor Red
				Write-Output $_.Exception.Message -foregroundcolor Red
				continue;
			}
		}

		$SummaryStatus | select-object server, NeededCount, LastSyncTime, InstalledPendingRebootCount, NotInstalledCount, DownloadedCount, InstalledCount, FailedCount, @{Name = "KB Numbers"; Expression = { $_.Needed } }, @{Name = "Arrival Date"; Expression = { $_.NeededDate } }, NotApplicable, IPAddress, OS | export-csv -notype C:\UpdateDetails\ServersStatus_$($WS1).csv

		Write-Output "Connected with $WS1 and finding patches for last month schedule .."

		# Find patches from 1st day of (M-2) month to 2nd Monday of (M-1) month		
		$updatescope.FromArrivalDate = [datetime](get-date).Addmonths(-1)
		$updatescope.ToArrivalDate = [datetime](get-date)

		$file1 = "C:\UpdateDetails\Currentmonthupdates_" + $WS1 + ".csv"
		$WSUS.GetSummariesPerUpdate($updatescope, $computerscope) | select-object @{L = 'UpdateTitle'; E = { ($WSUS.GetUpdate([guid]$_.UpdateId)).Title } }, @{L = 'Arrival Date'; E = { ($WSUS.GetUpdate([guid]$_.UpdateId)).ArrivalDate } }, @{L = 'KB Article'; E = { ($WSUS.GetUpdate([guid]$_.UpdateId)).KnowledgebaseArticles } }, @{L = 'NeededCount'; E = { ($_.DownloadedCount + $_.NotInstalledCount) } }, DownloadedCount, NotApplicableCount, NotInstalledCount, InstalledCount, FailedCount | Export-csv -Notype $file1
		$UpdateStatus += $WSUS.GetSummariesPerUpdate($updatescope, $computerscope) | select-object @{L = 'UpdateTitle'; E = { ($WSUS.GetUpdate([guid]$_.UpdateId)).Title } }, @{L = 'Arrival Date'; E = { ($WSUS.GetUpdate([guid]$_.UpdateId)).ArrivalDate } }, @{L = 'KB Article'; E = { ($WSUS.GetUpdate([guid]$_.UpdateId)).KnowledgebaseArticles } }, @{L = 'NeededCount'; E = { ($_.DownloadedCount + $_.NotInstalledCount) } }, DownloadedCount, NotApplicableCount, NotInstalledCount, InstalledCount, FailedCount
	}
	catch [Exception] {
		Write-Output $_.Exception.GetType().FullName -foregroundcolor Red
		Write-Output $_.Exception.Message -foregroundcolor Red
		continue;
	}
	$UpdateStatus | export-csv -notype C:\UpdateDetails\AllUpdatesStatus.csv
}

Stop-Transcript
notepad $logFile