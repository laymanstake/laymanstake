# Author : Nitish Kumar
# Email Alert Function
# version 1.0 | 19/10/2022

# Function to send email
function EmailAlert () {
	[CmdletBinding()]
	param(
		[parameter(mandatory = $true)]$RecipientAddressTo,		
		[parameter(mandatory = $true)]$SenderAddress,
		[parameter(mandatory = $true)]$SMTPServer,		
		[parameter(mandatory = $true)]$Subject,
		[parameter(mandatory = $true)]$Body,
		[parameter(mandatory = $false)]$SMTPServerPort = "25",		
		[parameter(mandatory = $false)]$RecipientAddressCc,		
		[parameter(mandatory = $false)][bool]$IsBodyHtml = $false
	)

	if ($RecipientAddressCc) {
		try {
			$email = @{
				From       = $SenderAddress
				To         = $RecipientAddressTo
				Cc         = $RecipientAddressCc
				Subject    = $Subject
				Body       = $Body
				SmtpServer = $SMTPServer
				Port       = $SMTPServerPort				
				IsBodyHtml = $IsBodyHtml
			}		
			Send-MailMessage @email -UseSsl
		}
		Catch {
			Throw $_.exception.message 
		}
	}
	else {
		try {
			$email = @{
				From       = $SenderAddress
				To         = $RecipientAddressTo
				Subject    = $Subject
				Body       = $Body
				SmtpServer = $SMTPServer			
				Port       = $SMTPServerPort				
				IsBodyHtml = $IsBodyHtml
			}		
			Send-MailMessage @email  -UseSsl
		}
		Catch {
			Throw $_.exception.message 
		}
	}

}
