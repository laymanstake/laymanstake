# Author : Nitish Kumar
# To Automate Sharepoint Mass Deletion Monitoring
# version 1.0 | 02/09/2021
# version 1.1 | 02/09/2021 | updated to exclude OneDrive sites and better output
# version 1.2 | 03/09/2021 | updated to imporving mail functionality and formatting output, also added option to add multiple recipients

# Connection to O365 tenant with a service account with Basic Authentication and no MFA

$Manual = 0

function ConnectO365 () {
	If ([System.IO.File]::Exists("C:\temp\myCred_${env:USERNAME}_${env:COMPUTERNAME}.xml")) {
		$UserCredential = Import-CliXml -Path "C:\temp\myCred_${env:USERNAME}_${env:COMPUTERNAME}.xml"
	}
 	Else {
		$Answer = Read-host "Want to create credentials file to re-use (Y/N)"
		If ($Answer.ToUpper() -eq "Y") {
			Get-Credential  -Message "Provide O365 admin credentials" | Export-CliXml -Path "C:\temp\myCred_$($env:USERNAME)_$($env:COMPUTERNAME).xml"
			Write-Output "`nCredentials file created."  -Foregroundcolor GREEN -Backgroundcolor White
			$UserCredential = Import-CliXml -Path "C:\temp\myCred_${env:USERNAME}_${env:COMPUTERNAME}.xml"
		}
		Else {
			Write-Output "`nThese credentials would not be saved for later run." -Foregroundcolor RED -Backgroundcolor YELLOW
			$UserCredential = Get-Credential
  		}
	}

	$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection
	Return $Session
}

# Mail configuration
$SMTPServer = "mx.abc.xyz"
$SenderAddress = "Sharepoint-CustomAlert@abc.xyz"
$RecipientAddressTo = @("Nitish.Kumar@abc.xyz") # For multiple recipients, use format like this @("Nitish.Kumar@abc.xyz","Sharepoint@cde.com")
$RecipientAddressCc = @("Sharepoint@cde.com")
$RecipientAddressBCC = @("nitish.1.kumar@cde.com")
$Subject = "Suspicious Sharepoint Activities"

# Stylesheet for Table formatting in mail body
$style = "<style>BODY{font-family: Arial; font-size: 10pt;}"
$style = $style + "TABLE{border: 1px solid black; border-collapse: collapse;}"
$style = $style + "TH{border: 1px solid black; background: #dddddd; padding: 5px; }"
$style = $style + "TD{border: 1px solid black; padding: 5px; }"
$style = $style + "</style>"

# Audit logs to be checked for how many minutes
$ScheduleFrequency = 30

# Threshold for alertinig
$Threshold = 100

# Connect to O365 for Audit log check
Try {
	$s = ConnectO365
	Import-PSSession $s
}
Catch {
	Send-MailMessage  -From $SenderAddress -To $RecipientAddressTo -Cc $RecipientAddressCc -Bcc $RecipientAddressBCC -Subject "Error: Sharepoint Mass Deletion Monitoring not working" -Body $_.Exception.Message -SmtpServer $SMTPServer -BodyAsHtml -UseSsl

	# For manual ad-hoc run
	Connect-ExchangeOnline
	$Manual = 1
}

Try {
	# Audit log query to find out potentially harmful operations
	$Data = Search-UnifiedAuditLog -StartDate (Get-Date).AddMinutes( - ($ScheduleFrequency)) -EndDate (Get-date) -RecordType SharePointFileOperation -Operations FileDeleted, FileMoved, FileRenamed, FolderDeleted, FolderRenamed, FolderMoved -ResultSize 5000 | Select-Object UserIds, Operations, @{l = "SharepointSite"; e = { ($_.AuditData | ConvertFrom-Json ).SiteUrl } }  | Where-Object { $_.SharepointSite -notlike "https://abc365-my.sharepoint.com/personal/*" } | Group-Object UserIds, SharepointSite, Operations | Where-Object { $_.Count -ge $Threshold } | Select-Object @{l = "User"; e = { ($_.Name -split ", ")[0] } }, @{l = "SharepointSiteName"; e = { ($_.Name -split ", ")[1] } } , @{l = "OperationType"; e = { ($_.Name -split ", ")[2] } }, Count
}
Catch {
	$ErrorMessage = $_.Exception.Message
	Write-Output $ErrorMessage -Foregroundcolor RED

	Send-MailMessage  -From $SenderAddress -To $RecipientAddressTo -Cc $RecipientAddressCc -Bcc $RecipientAddressBCC -Subject "Error: Sharepoint Mass Deletion Monitoring not working" -Body $_.Exception.Message -SmtpServer $SMTPServer -BodyAsHtml -UseSsl
}

# Log the sessions which completed with errors
If ($Data.count -gt 0) {
	$Message = "Below actions seem to be of concern, please validate ... "
	$Message += "`r`n"
	$body = "<b>Dear Team</b><br><br>"
	$body += $Message
	$body += "<br><br>"
	$body += $Data | ConvertTo-Html -Head $style | Out-String
	$body += "<br><br><b>Regards</b><br>"
	$body += "Monitoring Team <br>"

	#$RecipientAddressTo += $Data.User # Enable this one if you need to send emails to particular users as well

	Send-MailMessage  -From $SenderAddress -To $RecipientAddressTo -Cc $RecipientAddressCc -Bcc $RecipientAddressBCC -Subject $Subject -Body $Body -SmtpServer $SMTPServer -BodyAsHtml -UseSsl
}

If ($Manual -eq 0) {	Remove-PSSession $s } Else { Disconnect-ExchangeOnline -Confirm:$false -InformationAction Ignore -ErrorAction SilentlyContinue }