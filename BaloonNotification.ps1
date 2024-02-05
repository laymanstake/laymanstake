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
Get-EventSubscriber -SourceIdentifier "BalloonClicked_event" -ErrorAction SilentlyContinue | Unregister-Event # In case if the Event Subscription is not disposed
}

New-BaloonNotification -title "The Notification from Cororate IT: " -message "It's break time! Take a moment to stand up, stretch, and refresh"
