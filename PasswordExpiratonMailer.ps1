# Author : Nitish Kumar
# Advance Password Expiry Notification for users
# version 1.0
# 09/06/2021

Import-Module ActiveDirectory

$PasswordAge = 90
$Threshold = 15

$Users = Get-ADUser -filter { Enabled -eq $True -and PasswordNeverExpires -eq $False -and SamAccountName -notlike "*$*" -and SamAccountName -notlike "train*" } -pro * | Where-Object { $_.PasswordLastSet -le (Get-Date).AddDays($Threshold - $PasswordAge) -AND $_.PasswordLastset -ne $null } | Sort-Object PasswordLastSet | Select-Object DisplayName, SamAccountName , PasswordLastSet, Enabled, PasswordNeverExpires, @{l = "Mail"; e = { If ($_.SamAccountName -like "admin.*") { (Get-ADuser $_.ExtensionAttribute5 -pro Mail).Mail } Else { $_.Mail } } }

#$Users = Get-ADUser admin.nk1 -pro *| Where-Object { $_.PasswordLastSet -le (Get-Date).AddDays($Threshold - $PasswordAge) -AND $_.PasswordLastset -ne $null} | Sort-Object PasswordLastSet | Select-Object DisplayName, SamAccountName , PasswordLastSet, Enabled, PasswordNeverExpires, @{l="Mail";e={If($_.SamAccountName -like "admin.*"){(Get-ADuser $_.ExtensionAttribute5 -pro Mail).Mail} Else {$_.Mail} }}

ForEach ($User in $Users) {
  $SamAccountName = $User.SamAccountName
  $Mail = $User.mail
  $DisplayName = $User.DisplayName
  $ExpirationDate = ($User.PasswordLastSet).AddDays($PasswordAge)
  $Expirationdays = (New-Timespan -Start (Get-Date) -End $ExpirationDate).Days
  $ddisplay = if ($expdays -eq 1) { "day" } else { "days" }
  $mailto = $Mail
  $msg = @"
<b>Dear $DisplayName</b>, <br /> <br />
Your Corporate SSO password (The one you use to log into your workstation, also known as Active Directory) for <b>$SamAccountName</b> will expire in $Expirationdays $ddisplay (on $ExpirationDate).  This will disable your access to all SSO Services.<br /> <br />
==> PLEASE CHANGE YOUR PASSWORD NOW : To reset your password from your PC press simultaneously the key "Ctrl" + "Alt" + "Delete" and then select the option "Change a password...". Alternatively visit the self-service password reset website. <br /><br />

============================================================================================= <br />
The Password complexity rule reminder: <br />
Following our security rules the password has to meet a minimum of requirements : <br />
Password history:  8 new passwords must be used before an old password can be reused. <br />
Minimum password length: 8 characters. <br />
Complexity requirements: <br />
The password must contains characters from at least three of the following five categories: <br />
  - English upper case characters (A - Z) <br />
  - English lower case characters (a - z) <br />
  - Base 10 digits (0 - 9) <br />
  - Non-alphanumeric (For example: !, $, #, or %) <br />
  - Unicode characters <br />
The password does not contain three or more characters from the user's account name  <br />
=============================================================================================
"@
  If ($null -ne $Mail) {
    Send-MailMessage -To $mailto -From "corporate.support@abc.com" -Subject "Password Expiration Notice" -Body $msg -BodyAsHtml -SmtpServer "mx.abc.com"
  }
}