# To Check Active Directory Health
# Author: Nitish Kumar
# v1.0 | 20-08-2018

# Report path
$reportpath = "c:\temp\ADHealthReport_$(get-date -Uformat "%Y%m%d-%H%M%S").csv"

#Import Active Directory PowerShell Module
$Test = Get-Module -List ActiveDirectory
If ($Test) {
	import-module ActiveDirectory
}
Else {
	Write-Output "Run this from Domain Controller or a machine with RSAT Installed."
	Exit
}

# Collect the list of domain controllers
$DC = Get-ADDomainController -Filter *

$Report = @()
$b = 0

#foreach domain controller
foreach ($Dcserver in $dc.hostname) {
	$a = $dc.count
	$b++

	Write-Output "Working on $dcserver.hostname - $b / $a ..."
	if (Test-Connection -ComputerName $Dcserver -Count 4 -Quiet) {
		try {
			# Ping status
			$setping = "OK"

			# Netlogon Service Status
			$DcNetlogon = Get-Service -ComputerName $Dcserver -Name "Netlogon" -ErrorAction SilentlyContinue
			if ($DcNetlogon.Status -eq "Running") {
				$setnetlogon = "ok"
			}
			else {
				$setnetlogon = "$DcNetlogon.status"
			}

			#NTDS Service Status
			$dcntds = Get-Service -ComputerName $Dcserver -Name "NTDS" -ErrorAction SilentlyContinue
			if ($dcntds.Status -eq "running") {
				$setntds = "ok"
			}
			else {
				$setntds = "$dcntds.status"
			}

			#DNS Service Status
			$dcdns = Get-Service -ComputerName $Dcserver -Name "DNS" -ea SilentlyContinue
			if ($dcdns.Status -eq "running") {
				$setdcdns = "ok"
			}
			else {
				$setdcdns = "$dcdns.Status"
			}

			#Dcdiag netlogons "Checking now"
			$dcdiagnetlogon = dcdiag /test:netlogons /s:$dcserver
			if ($dcdiagnetlogon -match "passed test NetLogons")	{
				$setdcdiagnetlogon = "ok"
			}
			else {
				$setdcdiagnetlogon = $dcdiagnetlogon
			}

			#Dcdiag services check
			$dcdiagservices = dcdiag /test:services /s:$dcserver
			if ($dcdiagservices -match "passed test services") {
				$setdcdiagservices = "ok"
			}
			else {
				$setdcdiagservices = $dcdiagservices
			}

			#Dcdiag Replication Check
			$dcdiagreplications = dcdiag /test:Replications /s:$dcserver
			if ($dcdiagreplications -match "passed test Replications") {
				$setdcdiagreplications = "ok"
			}
			else {
				$setdcdiagreplications = $dcdiagreplications
			}

			#Dcdiag FSMOCheck Check
			$dcdiagFsmoCheck = dcdiag /test:FSMOCheck /s:$dcserver
			if ($dcdiagFsmoCheck -match "passed test FsmoCheck") {
				$setdcdiagFsmoCheck = "ok"
			}
			else {
				$setdcdiagFsmoCheck = $dcdiagFsmoCheck
			}

			#Dcdiag Advertising Check
			$dcdiagAdvertising = dcdiag /test:Advertising /s:$dcserver
			if ($dcdiagAdvertising -match "passed test Advertising") {
				$setdcdiagAdvertising = "ok"
			}
			else {
				$setdcdiagAdvertising = $dcdiagAdvertising
			}

			$tryok = "ok"
		}
		catch {
			Write-Output $_.Exception.Message
		}

		if ($tryok -eq "ok") {
			$csvObject = New-Object PSObject

			Add-Member -inputObject $csvObject -memberType NoteProperty -name "DCName" -value $dcserver
			Add-Member -inputObject $csvObject -memberType NoteProperty -name "Ping" -value $setping
			Add-Member -inputObject $csvObject -memberType NoteProperty -name "Netlogon" -value $setnetlogon
			Add-Member -inputObject $csvObject -memberType NoteProperty -name "NTDS" -value $setntds
			Add-Member -inputObject $csvObject -memberType NoteProperty -name "DNS" -value $setdcdns
			Add-Member -inputObject $csvObject -memberType NoteProperty -name "Dcdiag_netlogons" -value $setdcdiagnetlogon
			Add-Member -inputObject $csvObject -memberType NoteProperty -name "Dcdiag_Services" -value $setdcdiagservices
			Add-Member -inputObject $csvObject -memberType NoteProperty -name "Dcdiag_replications" -value $setdcdiagreplications
			Add-Member -inputObject $csvObject -memberType NoteProperty -name "Dcdiag_FSMOCheck" -value $setdcdiagFsmoCheck
			Add-Member -inputObject $csvObject -memberType NoteProperty -name "DCdiag_Advertising" -value $setdcdiagAdvertising

			#set DC status
			$setdcstatus = "ok"
		}
	}
	else {
		#if Server Down
		$csvObject = New-Object PSObject
		$setdcstatus = "$dcserver is down"

		Add-Member -inputObject $csvObject -memberType NoteProperty -name "DCName" -value $dcserver
		Add-Member -inputObject $csvObject -memberType NoteProperty -name "Ping" -value $setdcstatus
		Add-Member -inputObject $csvObject -memberType NoteProperty -name "Netlogon" -value $setdcstatus
		Add-Member -inputObject $csvObject -memberType NoteProperty -name "NTDS" -value $setdcstatus
		Add-Member -inputObject $csvObject -memberType NoteProperty -name "DNS" -value $setdcstatus
		Add-Member -inputObject $csvObject -memberType NoteProperty -name "Dcdiag_netlogons" -value $setdcstatus
		Add-Member -inputObject $csvObject -memberType NoteProperty -name "Dcdiag_Services" -value $setdcstatus
		Add-Member -inputObject $csvObject -memberType NoteProperty -name "Dcdiag_replications" -value $setdcstatus
		Add-Member -inputObject $csvObject -memberType NoteProperty -name "Dcdiag_FSMOCheck" -value $setdcstatus
		Add-Member -inputObject $csvObject -memberType NoteProperty -name "DCdiag_Advertising" -value $setdcstatus
	}
	$csvObject
	$Report += $csvObject
}

$Report  | export-csv -nti $reportpath

# set subject
if ($setping -like "ok" -and $setnetlogon -like "ok" -and $setntds -like "ok" -and `
	$setdcdns -like "ok" -and $setdcdiagnetlogon -like "ok" -and $setdcdiagservices -like "ok" -and `
		$setdcdiagreplications -like "ok" -and $setdcdiagFsmoCheck -like "ok" -and $setdcdiagAdvertising -like "ok" -and $setdcstatus -like "ok" ) {
	$Subject = "Domain Controller Daily Server Status :- All servers are 'ok' "
}
else {
	$Subject = "Domain Controller Daily Server Status :- ERROR "
}

$style = "BODY{font-family: Arial; font-size: 10pt;}"
$style = $style + "TABLE{border: 1px solid black; border-collapse: collapse;}"
$style = $style + "TH{border: 1px solid black; background: #dddddd; padding: 5px; }"
$style = $style + "TD{border: 1px solid black; padding: 5px; }"
$style = $style + ""

$smtpServer = "mail.abc.xyz"
$att = new-object Net.Mail.Attachment($reportpath)
$msg = new-object Net.Mail.MailMessage
$smtp = new-object Net.Mail.SmtpClient($smtpServer)
$msg.From = "AD-Health-Alert@abc.xyz"
$msg.To.Add("wintelengineers@abc.xyz")
$msg.Subject = $Subject
$body = "<b>Dear Team</b><br />"
$body += "Here is the Report of ADHealth Check <br /><br />"
$body += $Report | Select-Object DCName, Ping, Netlogon, NTDS, DNS, Dcdiag_netlogons, Dcdiag_Services, Dcdiag_replications, Dcdiag_FSMOCheck, DCdiag_Advertising | ConvertTo-Html -Head $style
$body += "<br /><b>Regards</b><br />"
$body += "IT Team <br />"
$msg.Body = $body
$msg.IsBodyHTML = $true
$msg.Attachments.Add($att)
$smtp.Send($msg)
$att.Dispose()

