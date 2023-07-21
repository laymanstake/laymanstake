Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Windows.Forms.DataVisualization

function New-SplashFromImage {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)][String]$imageFilePath
    )

    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.Application]::EnableVisualStyles() # To enable system theme
    
    $img = [System.Drawing.Image]::Fromfile($imageFilePath)    
    
    $SScreen = New-Object system.Windows.Forms.Form
    $SScreen.Width = $img.Width
    $SScreen.Height = $img.Height
    $SScreen.TopMost = $true
    $SScreen.BackgroundImage = $img
    $SScreen.AllowTransparency = $true
    $SScreen.TransparencyKey = $SScreen.BackColor
    $SScreen.StartPosition = 1 # 0: Manual, 1: CenterScreen, 2: WindowsDefaultLocation, 3:WindowsDefaultBounds, 4:CenterParent
    $SScreen.FormBorderStyle = 0 # 0: None, 1: FixedSingle, 2:Fixed3D, 3:FixedDialog, 4:Sizable, 5:FixedToolWindow, 6:SizableToolWindow
    
    $SScreen.Show()    
    Start-Sleep -Seconds 5    
    $SScreen.Close()    
    $SScreen.Dispose()
} #New-SplashFromImage -imageFilePath "C:\temp\light.png"

function New-OkCancelBox {
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)][String]$title,
        [Parameter(ValueFromPipeline = $true, mandatory = $true)][String]$message,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][ValidateSet('Hand', 'Question', 'Exclamation', 'Asterisk', 'Stop', 'Error', 'Warning', 'Information')][String]$icon = "Information"
    )
    Add-Type -AssemblyName System.Windows.Forms

    $result = [System.Windows.Forms.MessageBox]::Show($message, $title, [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::$icon)
    return $result    
} #$Output = New-OkCancelBox -title "Info Button" -message "Sample Info" -icon Stop

function New-FileDialog {
    [cmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][ValidateScript({ if ( -Not($_ | Test-Path)) { throw "incorrect start Directory" } else { return $true } })][String]$startDirectory,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][String[]]$filter = "All Files (*.*)|*.*"
    )
    Add-Type -AssemblyName System.Windows.Forms

    $fileBrowser = New-Object System.Windows.Forms.OpenFileDialog 
    
    if ($startDirectory) {
        $fileBrowser.InitialDirectory = $startDirectory
    } 
    else {
        $fileBrowser.InitialDirectory = [Environment]::GetFolderPath('MyDocuments')
    }
    
    if ($filter -ne "All Files (*.*)|*.*") {
        $fileBrowser.Filter = ($filter | Where-Object { $_ -match "\*\..*" } | ForEach-Object { "$_ files |$_" }) -join "|"
    }
    else {
        $fileBrowser.Filter = "All Files (*.*)|*.*"
    }
    [void]$fileBrowser.ShowDialog()
    
    # Return the selected file name
    return $fileBrowser.FileName
} #New-FileDialog -startDirectory "c:\" -filter @("*.txt","*.csv")

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

    $path = Get-Process -Name powershell | Select-Object -ExpandProperty Path
    $tip.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path[0])
    $tip.BalloonTipIcon = $Icon
    $tip.BalloonTipText = $message
    $tip.BalloonTipTitle = $title    
    $tip.Visible = $true            
    
    register-objectevent $tip BalloonTipClicked BalloonClicked_event -Action { $script.Invoke() } | Out-Null
    $tip.ShowBalloonTip(50000) # Even if we set it for 1000 milliseconds, it usually follows OS minimum 10 seconds
    Start-Sleep -s 10
    
    $tip.Dispose() # Important to dispose otherwise the icon stays in notifications till reboot
    Get-EventSubscriber -SourceIdentifier "BalloonClicked_event"  -ErrorAction SilentlyContinue | Unregister-Event # In case if the Event Subscription is not disposed
} 

# You can pass a script that what to do when someone clicks on ballon notification
<# $script = {
    Start-Process https://nitishkumar.net
}
New-BaloonNotification -title "The Notification from Nitish Kumar : " -message "Just trying out cool stuff" -script $Script #>

# Function to get password expiration date for the given samAccountName
function Get-PasswordExpiry {
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][String]$samAcccountName = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split "\\")[1]
    )
    # Step 1 - Find the max password age as per domain policy
    $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() # Find current domain
    $domain = [ADSI]"LDAP://$currentDomain" # find current domain LDAP coordinates
    $maxPasswordAge = $domain.ConvertLargeIntegerToInt64($domain.maxPwdAge.Value) / (600000000 * 1440) # Max password age in days

    # Step 2 - Find when the password was last set for the user
    $searcher = New-Object DirectoryServices.DirectorySearcher # Create ADSI searcher
    [adsisearcher]$searcher.Filter = "(&(samaccountname=$samAccountName))" # Create search query
    $results = $searcher.FindOne() # Perform the search
    $passwordLastSet = [datetime]::FromFileTimeUtc($results.Properties.pwdlastset) # Find when the password was last set

    # Step 3 - Find when the password would be expired for the user
    $passwordExpirationDate = $passwordLastSet.AddDays($maxPasswordAge)

    Return $passwordExpirationDate
}

# Function to extract icon from the given file
function Get-Icon {
    [cmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true, HelpMessage = "Specify the path to the file", mandatory = $true)][ValidateScript({ if ( -Not($_ | Test-Path)) { throw "File doesn't exists" } else { return $true } })][String]$fileName,
        [Parameter(ValueFromPipeline = $true, HelpMessage = "Specify the icon file type, default is Png", mandatory = $false)][ValidateScript({ $_ -in (([System.Drawing.Imaging.ImageFormat] | get-member -Static -MemberType Properties)).Name })]$iconFormat = "Png",
        [Parameter(ValueFromPipeline = $true, HelpMessage = "Specify the folder to save the file", mandatory = $false)][ValidateScript({ if ( -Not($_ | Test-Path )) { throw "Folder doesn't exists" } else { return $true } })][string]$savePath = ".",
        [Parameter(ValueFromPipeline = $true, HelpMessage = "Specify the icon file name", mandatory = $false)][ValidateNotNullOrEmpty()][String]$iconFileName = "icon",
        [Parameter(ValueFromPipeline = $true, HelpMessage = "Specify the icon index in dll", mandatory = $false)][ValidateRange(-2, [int]::MaxValue)][int]$dllIconIndex = -2,
        [Parameter(ValueFromPipeline = $true, HelpMessage = "Specify the icon size in dll (small or large)", mandatory = $false)][ValidateSet('small', 'large')][string]$dllIconSize,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][switch]$asBase64
    )

    Add-Type -AssemblyName System.Drawing -ErrorAction Stop
        
    if ([System.IO.Path]::GetExtension($filename) -ne ".dll") {
        $icon = [System.Drawing.Icon]::ExtractAssociatedIcon($fileName)
        if ($asBase64) {
            $ms = New-Object System.IO.MemoryStream
            $icon.save($ms)
            $bytes = $ms.ToArray()
            $base64 = [convert]::ToBase64String($Bytes)
            $ms.Flush()
            $ms.Dispose()
            
            return $base64
        }
        else {
            $outPath = $savePath + "\" + $iconFileName + "." + $iconFormat
            $icon.ToBitmap().Save($outPath, $iconFormat)

            $finalPath = (get-item $outPath).FullName
            #Write-Output "The icon file has been saved to $finalPath"

            return $finalPath
        }
    }
    else {
        # ref https://github.com/ReneNyffenegger/about-powershell/blob/master/examples/WinAPI/Shell32/Extract/Shell32_Extract.ps1
        # using c# code to call function from shell32.dll
        add-type -typeDefinition '
        using System;
        using System.Runtime.InteropServices;
        public class Shell32_Extract {  
            [DllImport("Shell32.dll", EntryPoint = "ExtractIconExW", CharSet = CharSet.Unicode, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
            public static extern int ExtractIconEx(string lpszFile, int iconIndex, out IntPtr phiconLarge, out IntPtr phiconSmall, int nIcons );
        }
        ';

        $dllPath = $fileName

        [System.IntPtr] $phiconSmall = 0
        [System.IntPtr] $phiconLarge = 0

        if ($dllIconIndex -ge 0) {            
            Write-Host "Now about single icon"
            $dllIconIndex
            $nofIconsExtracted = [Shell32_Extract]::ExtractIconEx($dllPath, $dllIconIndex, [ref] $phiconLarge, [ref] $phiconSmall, 1)   
            if ($nofIconsExtracted -ne 2) { 
                write-error "iconsExtracted = $nofIconsExtracted" 
            }
            else {
                if ($dllIconSize -eq 'small') {
                    $bmpSmall = ([System.Drawing.Icon]::FromHandle($phiconSmall))
                    if ($asBase64) {
                        $ms = New-Object System.IO.MemoryStream
                        $bmpSmall.save($ms)
                        $bytes = $ms.ToArray()
                        $base64 = [convert]::ToBase64String($Bytes)
                        $ms.Flush()
                        $ms.Dispose()                        
                        return $base64
                    }
                    else {
                        $outPath = $savePath + "\" + $iconFileName + "." + $iconFormat
                        $bmpSmall.ToBitmap().Save($outPath, $iconFormat)            
                        $finalPath = (get-item $outPath).FullName            
                        return $finalPath
                    }
                }
                else {
                    $bmpLarge = ([System.Drawing.Icon]::FromHandle($phiconLarge))
                    if ($asBase64) {
                        $ms = New-Object System.IO.MemoryStream
                        $bmpLarge.save($ms)
                        $bytes = $ms.ToArray()
                        $base64 = [convert]::ToBase64String($Bytes)
                        $base64
                        $ms.Flush()
                        $ms.Dispose()                        
                        return $base64
                    }
                    else {
                        $outPath = $savePath + "\" + $iconFileName + "." + $iconFormat
                        $bmpLarge.ToBitmap().Save($outPath, $iconFormat)
                        $finalPath = (get-item $outPath).FullName
                        return $finalPath
                    }
                }
            }
        }
        else {                        
            $nofImages = [Shell32_Extract]::ExtractIconEx($dllPath, -1, [ref] $phiconLarge, [ref] $phiconSmall, 0)

            foreach ($iconIndex in 0 .. ($nofImages - 1)) {
                $nofIconsExtracted = [Shell32_Extract]::ExtractIconEx($dllPath, $iconIndex, [ref] $phiconLarge, [ref] $phiconSmall, 1)   
                if ($nofIconsExtracted -ne 2) { write-error "iconsExtracted = $nofIconsExtracted" }                

                $small = [System.Drawing.Icon]::FromHandle($phiconSmall)
                $large = [System.Drawing.Icon]::FromHandle($phiconLarge)

                $bmpSmall = $small.ToBitmap()
                $bmpLarge = $large.ToBitmap()                
                $iconIndex_0 = '{0,3:000}' -f $iconIndex            

                $bmpSmall.Save("$($savePath)\$($iconFileName)_small-$($iconIndex_0).$($iconFormat)", [System.Drawing.Imaging.ImageFormat]::$iconFormat)
                $bmpLarge.Save("$($savePath)\$($iconFileName)_large-$($iconIndex_0).$($iconFormat)", [System.Drawing.Imaging.ImageFormat]::$iconFormat)
            }
        }
    }
}

#Get-Icon -fileName "$env:SystemRoot\System32\imageres.dll" -iconFormat "jpeg" -iconFileName "supericon" -savePath "C:\temp" -dllIconIndex 191 -dllIconSize "small" # -asBase64

# Function to generate Windows 10 Toast notification
function New-ToastNotification {
    [cmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][String]$title = "Test Title",
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][String]$message = "Test Message",        
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][String]$Sender = "IT Team",
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][ValidateSet('long', 'short')][String]$duration = "long",
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][String]$logo = $null,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][String]$heroImage = $null,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][String]$extraImage = $null,        
        [Parameter(ValueFromPipeline = $true, mandatory = $false, ParameterSetName = "Actions",
            HelpMessage = "Need to provide content, argument, protocol and optionally imgeuri")][string[]]$action1 = ("Nitish Kumar's Blog", "http://nitishkumar.net", "protocol", "C:\temp\1616.png"),
        [Parameter(ValueFromPipelineByPropertyName = $true, mandatory = $false, ParameterSetName = "Actions",
            HelpMessage = "Need to provide content, argument, protocol and optionally imgeuri")][string[]]$action2,
        [Parameter(ValueFromPipelineByPropertyName = $true, mandatory = $false, ParameterSetName = "Actions",
            HelpMessage = "Need to provide content, argument, protocol and optionally imgeuri")][string[]]$action3
    )

    if ((Get-CimInstance win32_operatingSystem).version -lt 10) {
        # If OS less than Windows 10 then generate balloon notification instead
        New-BaloonNotification -title $title -message $message -icon Warning 
        return        
    }

    if ($PSEdition -eq "Core") {
        Write-Host "Script is running in PowerShell version $($PSVersionTable.PSVersion.Major).x so need to manually load libraries"
        Add-Type -Path "C:\temp\lib\Microsoft.Windows.SDK.NET.dll"
    }
    else {
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        [Windows.UI.Notifications.ToastNotification, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
    }

    $appId = ((Get-StartApps -Name "Windows Powershell") | Select-Object -First 1).AppId 

    #Enable push notifications for system and the notificaiton for the app
    $pushNotificationsEnabled = (get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" ).ToastEnabled
    if (!($pushNotificationsEnabled)) { 
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name ToastEnabled -Value 1 -Force 
        Get-Service -Name WpnUserService** | Restart-Service -Force
    }
    
    $appNotificationEnabled = (Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\$appId").Enabled
    if (!($appNotificationEnabled)) { 
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\$appId" -Name Enabled -Value 1 -Force 
        Get-Service -Name WpnUserService** | Restart-Service -Force
    }

    if ($action1) { $firstAction = "<action content=""$($action1[0])"" arguments=""$($action1[1])"" activationType=""$($action1[2])"" imageUri=""$($action1[3])"" />" }    
    if ($action2) { $secondAction = "<action content=""$($action2[0])"" arguments=""$($action2[1])"" activationType=""$($action2[2])"" imageUri=""$($action2[3])"" />" }    
    if ($action3) { $thirdAction = "<action content=""$($action3[0])"" arguments=""$($action3[1])"" activationType=""$($action3[2])"" imageUri=""$($action3[3])"" />" }
    
    if ($firstAction -OR $secondAction -OR $thirdAction) {
        $actionStart = '<actions>'
        $actionClose = '</actions>'
    }    

    [xml]$toastXml = '<?xml version="1.0" encoding="utf-8"?><toast><visual><binding template="ToastGeneric">' +
    '<text></text><text></text><text></text><image src="" /><image src="" /><image src="" /></binding></visual>' +
    $actionStart + $firstAction + $secondAction + $thirdAction + $actionClose +
    '</toast>'    
    
    # Below lines are to create Base64 string for logo in case you want to burn that in the script itself than supplying from outside
    <# $File = "C:\temp\logo1.png"
    $Image = [System.Drawing.Image]::FromFile($File)
    $MemoryStream = New-Object System.IO.MemoryStream
    $Image.Save($MemoryStream, $Image.RawFormat)
    [System.Byte[]]$Bytes = $MemoryStream.ToArray()
    $Base64Image = [System.Convert]::ToBase64String($Bytes)
    $Image.Dispose()
    $MemoryStream.Dispose() #>

    $Base64Image = "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"

    # Can use below code block in case if you got base64 value from any logo with above proecss, no need to unblock earlier code
    if ($logo.Length -le 1 -AND $Base64Image) {
        $logo = "$($env:TEMP)\logoImage.png"
        [byte[]]$Bytes = [convert]::FromBase64String($Base64Image)
        [System.IO.File]::WriteAllBytes($logo, $Bytes)
    }

    $toastXml.GetElementsByTagName("text")[0].AppendChild($toastXml.CreateTextNode($title)) | Out-Null
    $toastXml.GetElementsByTagName("text")[1].AppendChild($toastXml.CreateTextNode($message)) | Out-Null
    $toastXml.GetElementsByTagName("text")[2].SetAttribute("placement", "Attribution") | Out-Null
    $toastXml.GetElementsByTagName("text")[2].AppendChild($toastXml.CreateTextNode("Notifiaiton by " + $Sender)) | Out-Null
    
    if ($logo.Length -ge 1) {
        if ($logo -match "http*") { $wc = New-Object System.Net.WebClient; $logoLocal = "$($env:TEMP)\logoImage.png"; $wc.DownloadFile($logo, $logoLocal) } 
        else { $logoLocal = $logo }

        $toastXml.GetElementsByTagName("image")[0].SetAttribute("placement", "appLogoOverride") | Out-Null
        $toastXml.GetElementsByTagName("image")[0].SetAttribute("hint-crop", "circle") | Out-Null
        $toastXml.GetElementsByTagName("image")[0].SetAttribute("src", $logoLocal) | Out-Null
    }        
    if ($heroImage.Length -ge 1) {
        if ($heroImage -match "http*") { $wc = New-Object System.Net.WebClient; $heroLocal = "$($env:TEMP)\heroImage.png"; $wc.DownloadFile($heroImage, $heroLocal) } 
        else { $heroLocal = $heroImage }
        
        $toastXml.GetElementsByTagName("image")[1].SetAttribute("placement", "hero") | Out-Null
        $toastXml.GetElementsByTagName("image")[1].SetAttribute("src", $heroLocal) | Out-Null        
    }
    if ($extraImage.Length -ge 1) {
        if ($extraImage -match "http*") { $wc = New-Object System.Net.WebClient; $extraImageLocal = "$($env:TEMP)\extraImage.png"; $wc.DownloadFile($extraImage, $extraImageLocal) } 
        else { $extraImageLocal = $extraImage }

        $toastXml.GetElementsByTagName("image")[2].SetAttribute("src", $extraImageLocal) | Out-Null
    }
    $toastXml.toast.SetAttribute("duration", $duration)    

    $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
    $xml.LoadXml($toastXml.OuterXml)
    $toast = New-Object Windows.UI.Notifications.ToastNotification $xml
    
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($toast)    
}
#Invoke-Command -ComputerName 192.168.1.22 -ScriptBlock ${function:New-ToastNotification} -Credential (Get-Credential)
#New-ToastNotification -title "This is custom notification" -message "One liner custom message. Some extra long, super long message " -logo "C:\temp\extra.png" -extraImage "C:\temp\extra.png" -heroImage "C:\temp\hero.png" -action1 ("Nitish Kumar Blog","https://nitishkumar.net","protocol","C:\temp\1616.png") -action2 ("Ignore","dismiss","system","C:\temp\logo.png")  -action3 ("Ignore-test","dismiss","system")

# Funtion to create a save dialog
function New-SaveDialog {
    [cmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][ValidateScript({ if ( -Not($_ | Test-Path)) { throw "incorrect start Directory" } else { return $true } })][String]$startDirectory = [Environment]::GetFolderPath('MyDocuments'),
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][String]$filter = "*.png"
    )
    
    Add-Type -AssemblyName System.Windows.Forms
    $SaveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    
    if ($startDirectory) { $SaveFileDialog.InitialDirectory = $startDirectory } 
    else { $SaveFileDialog.InitialDirectory = [Environment]::GetFolderPath('MyDocuments') }    
    
    if ($filter -ne "*.png") {
        $SaveFileDialog.Filter = ($filter | Where-Object { $_ -match "\*\..*" } | ForEach-Object { "$_ files |$_" }) -join "|"
    }
    else {
        $SaveFileDialog.Filter = ($filter | Where-Object { $_ -match "\*\..*" } | ForEach-Object { "$_ files |$_" }) -join "|"
        #$SaveFileDialog.DefaultExt='png'
    }
    
    $show = $SaveFileDialog.ShowDialog()
    
    If ($show -eq 'OK') {  
        $file = [pscustomobject]@{  FileName = $SaveFileDialog.FileName; Extension = $SaveFileDialog.FileName -replace '.*\.(.*)', '$1' } 
    }
    
    Return $file
}

# Function to create Chart
function New-Chart {
    [cmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true, mandatory = $false)]$xAxis,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)]$yAxis,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)]$width = 700,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)]$height = 400,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)]$left = 10,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)]$top = 10,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)]$title = "",
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][ValidateScript({ $_ -in ([System.Drawing.Color] | Get-Member -Static -MemberType Properties).Name })]$chartColor = "Transparent",
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][ValidateScript({ $_ -in ([System.Windows.Forms.DataVisualization.Charting.SeriesChartType] | Get-Member -Static -MemberType Properties).Name })]$chartType,
        [Parameter(ValueFromPipeline = $true, ParameterSetName = "extra", mandatory = $true)][bool]$generateImage,
        [Parameter(ValueFromPipeline = $true, ParameterSetName = "extra", mandatory = $false)][string]$imgExt = "png",
        [Parameter(ValueFromPipeline = $true, ParameterSetName = "extra", mandatory = $false)][string]$saveImagePath = "$env:TEMP\image.png"
    )    
    
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Windows.Forms.DataVisualization

    $Chart = New-object System.Windows.Forms.DataVisualization.Charting.Chart
    $ChartArea = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea
    $Series = New-Object -TypeName System.Windows.Forms.DataVisualization.Charting.Series
    $ChartTypes = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]

    $Series.ChartType = $ChartTypes::$chartType
    $Chart.Series.Add($Series)
    $Chart.ChartAreas.Add($ChartArea)

    $Chart.Series['Series1'].Points.DataBindXY($xAxis, $yAxis)
    $Chart.Width = $width
    $Chart.Height = $height
    $Chart.Left = $left
    $Chart.Top = $top
    $Chart.BackColor = [System.Drawing.Color]::$chartColor
    $Chart.BorderColor = 'Black'
    $Chart.BorderDashStyle = 'Solid'    
    

    $ChartTitle = New-Object System.Windows.Forms.DataVisualization.Charting.Title
    $ChartTitle.Text = $title
    $Font = New-Object System.Drawing.Font @('Microsoft Sans Serif', '12', [System.Drawing.FontStyle]::Bold)
    $ChartTitle.Font = $Font
    $Chart.Titles.Add($ChartTitle)

    $Legend = New-Object System.Windows.Forms.DataVisualization.Charting.Legend
    $Legend.IsEquallySpacedItems = $True
    $Legend.BorderColor = 'Black'
    $Chart.Legends.Add($Legend)
    $chart.Series["Series1"].LegendText = "#VALX (#VALY)"
    $Chart.Series['Series1']['PieLineColor'] = 'Black'
    $Chart.Series['Series1']['PieLabelStyle'] = 'Outside'
    $Chart.Series['Series1'].Label = "#VALX (#VALY)"

    $ChartArea.Area3DStyle.Enable3D = $True
    $ChartArea.Area3DStyle.Inclination = 60
    
    if ($generateImage) {
        $Chart.SaveImage($saveImagePath, $imgExt)
    }
    
    Return $Chart
}

#$Processes = Get-Process | Sort-Object WS -Descending | Select-Object -First 10
#$s = New-Chart -xAxis $Processes.Name -yAxis $Processes.WS -chartType "Pie" -generateImage $true 

