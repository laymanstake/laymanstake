#Requires -RunAsAdministrator
#Requires -Version 3.0
#Requires -Modules BitsTransfer
# Author : Nitish Kumar
# Download and Install Prometheus, Grafana and Windows Exporter
# version 1.0 | 19/10/2022

Import-Module BitsTransfer

# Function to download excutables for Prometheus, Grafana, Windows_exporter and nssm
function Get-Executables {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true,mandatory=$false)]
        [ValidateSet('Prometheus','Grafana','Windows_exporter','nssm')]
        [String[]]$packages = @('Prometheus','Grafana','Windows_exporter','nssm'),
        [Parameter(ValueFromPipeline = $true,mandatory=$false)]$executableDownloadPath = "$env:userprofile\downloads\"
    )

    if (Test-Path -Path $executableDownloadPath"Executables") {
        #Clean up the old files in the path before downloading new ones
        $OldFiles = (get-Childitem $executableDownloadPath"Executables" ).FullName | Select-String -Pattern $packages 
        $OldFiles | ForEach-Object {Remove-Item $_.Line}
    } else {
        New-Item -Path $executableDownloadPath -Name "Executables" -ItemType "directory" | Out-Null
    }

    if ($packages -match 'Prometheus'){
        $url = Invoke-RestMethod -uri  https://api.github.com/repos/prometheus/prometheus/releases/latest | Select-Object -ExpandProperty assets | Where-Object{$_.Name.EndsWith("windows-amd64.zip")} | select -expand browser_download_url
        $file = Split-Path $url -Leaf
        Write-Host "Downloading $file ..."
        Start-BitsTransfer -Source $url -Destination $executableDownloadPath"Executables\"$file
    }
    
    if ($packages -match 'Grafana'){
        $grafanaVersion = (Split-Path (Invoke-RestMethod -uri  https://api.github.com/repos/grafana/grafana/releases/latest).html_url -Leaf ).Substring(1)
        $file = "grafana-" + $grafanaVersion + ".windows-amd64.zip"
        $url = "https://dl.grafana.com/oss/release/" + $file
        Write-Host "Downloading $file ..."
        Start-BitsTransfer -Source $url -Destination $executableDownloadPath"Executables\"$file
    }

    if ($packages -match 'Windows_exporter'){
        $url = Invoke-RestMethod -uri  https://api.github.com/repos/prometheus-community/windows_exporter/releases/latest | Select-Object -ExpandProperty assets | Where-Object{$_.Name.EndsWith("amd64.exe")} | select -expand browser_download_url
        $file = Split-Path $url -Leaf
        Write-Host "Downloading $file ..."
        Start-BitsTransfer -Source $url -Destination $executableDownloadPath"Executables\"$file
    }

    if ($packages -match 'nssm'){
        $file = Split-Path("https://nssm.cc/release/nssm-2.24.zip") -Leaf
        Write-Host "Downloading $file ..."
        Start-BitsTransfer -Source https://nssm.cc/release/nssm-2.24.zip -Destination $executableDownloadPath"Executables\"$file        
    }    
}

# Function to install services for Prometheus, Grafana, Windows_exporter and nssm
function New-Services {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true,mandatory=$false)]
        [ValidateSet('Prometheus','Grafana','Windows_exporter','nssm')]
        [String[]]$packages = @('nssm','Prometheus','Grafana','Windows_exporter'),
        [Parameter(ValueFromPipeline = $true,mandatory=$false)]$servicePath = "$env:programfiles\",
        [Parameter(ValueFromPipeline = $true,mandatory=$false)]$executableDownloadPath = "$env:userprofile\downloads\Executables"
    )

    ForEach($package in $packages){
        if (Test-Path -Path ($servicePath + $package)) {
            #Clean up the old files in the path before downloading new ones
            Write-host "Cleaning up $($servicePath + $package)"
            $OldFiles = (get-Childitem ($servicePath + $package) ).FullName | Select-String -Pattern $packages 
            $OldFiles | ForEach-Object {Remove-Item $_.Line -Recurse -Force}
        } else {
            New-Item -Path $servicePath -Name $package -ItemType "directory" | Out-Null
        }    

        # Install nssm which would help creating services for Prometheus and Grafana
        if ($package -match 'nssm'){
            # Create folder for nssm in Installation path or cleanup old files
            if (Test-Path -Path ($servicePath + $package)) {
                #Clean up the old files in the path before downloading new ones
                $OldFiles = (get-Childitem ($servicePath + $package) ).FullName | Select-String -Pattern $package
                $OldFiles | ForEach-Object {Remove-Item $_.Line -Recurse -Force}
            } else {
                New-Item -Path $servicePath -Name $package -ItemType "directory" | Out-Null
            }

            Write-Host "Setting up $package ..."

            # Extract nssm zip to Install path
            $filePath = (get-childitem $executableDownloadPath | Where-Object {$_.Name.StartsWith($package.ToLower())}).versioninfo.filename
            $shell = New-Object -ComObject Shell.Application
            $zipFile = $shell.NameSpace($filePath + "\" + ((get-childitem $executableDownloadPath | Where-Object {$_.Name.StartsWith($package)}).Name -replace ".zip"))
            $destinationFolder = $shell.NameSpace($servicePath + $package)

            $copyFlags = 0x00
            $copyFlags += 0x04 # Hide progress dialogs
            $copyFlags += 0x10 # Overwrite existing files

            $destinationFolder.CopyHere($zipFile.Items(), $copyFlags)

            # Add nssm to system path permanently
            if (!(where.exe nssm)){
                $oldpath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).path
                $newpath = $oldpath + ";" + $servicePath + $package + "\win64"
                Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $newPath
                
                # Refresh the path variable for current session 
                $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")                 
            }
        }

        # Install Prometheus as Service
        if ($package -match 'prometheus' -and (where.exe nssm)){
            # Extract Prometheus installer zip to Install path
            $filePath = (get-childitem $executableDownloadPath | Where-Object {$_.Name.StartsWith($package.ToLower())}).versioninfo.filename
            $shell = New-Object -ComObject Shell.Application
            $zipFile = $shell.NameSpace($filePath + "\" + ((get-childitem $executableDownloadPath | Where-Object {$_.Name.StartsWith($package.ToLower())}).Name -replace ".zip"))
            $destinationFolder = $shell.NameSpace($servicePath + $package)

            $copyFlags = 0x00
            $copyFlags += 0x04 # Hide progress dialogs
            $copyFlags += 0x10 # Overwrite existing files

            $destinationFolder.CopyHere($zipFile.Items(), $copyFlags)

            Write-Host "Setting up $package ..."
            $prometheusServiceName = 'prometheus-service'
            $prometheusInstallPath = $servicePath + "Prometheus"
            $prometheusServiceUsername = "NT SERVICE\$prometheusServiceName"
            Write-Host "Configuring the $prometheusServiceName service..."
            $prometheusInstallPath

            nssm install $prometheusServiceName "`"$prometheusInstallPath\prometheus.exe`""
            nssm set $prometheusServiceName Start SERVICE_AUTO_START
            nssm set $prometheusServiceName AppRotateFiles 1
            nssm set $prometheusServiceName AppRotateOnline 1
            nssm set $prometheusServiceName AppRotateSeconds 86400
            nssm set $prometheusServiceName AppRotateBytes 1048576
            nssm set $prometheusServiceName AppStdout "`"$prometheusInstallPath\logs\service-stdout.log`""
            nssm set $prometheusServiceName AppStderr "`"$prometheusInstallPath\logs\service-stderr.log`""
            nssm set $prometheusServiceName AppDirectory "`"$prometheusInstallPath`""
            
# Parameters are passed via a Here-String, so do not touch formatting if to use a path with space
            nssm set $prometheusServiceName AppParameters `
@"
--config.file=""$prometheusInstallPath\prometheus.yml"" --storage.tsdb.path=""$prometheusInstallPath\data"" --storage.tsdb.retention=168h --web.console.libraries=""$prometheusInstallPath\console_libraries"" --web.console.templates=""$prometheusInstallPath\consoles"" --web.listen-address=localhost:9090
"@

            $result = sc.exe sidtype $prometheusServiceName unrestricted
            if ($result -ne '[SC] ChangeServiceConfig2 SUCCESS') {
                throw "sc.exe sidtype failed with $result"
            }
            
            $result = sc.exe config $prometheusServiceName obj= $prometheusServiceUsername
            if ($result -ne '[SC] ChangeServiceConfig SUCCESS') {
                throw "sc.exe config failed with $result"
            }

            $result = sc.exe failure $prometheusServiceName reset= 0 actions= restart/1000
            if ($result -ne '[SC] ChangeServiceConfig2 SUCCESS') {
                throw "sc.exe failure failed with $result"
            }

            $acl = Get-Acl $prometheusInstallPath
            $user = New-Object System.Security.Principal.NTAccount($prometheusServiceUsername)
            $acl.SetOwner([System.Security.Principal.NTAccount] $user)
            $acl.SetAccessRuleProtection($True, $False)
            $ruleSystem = New-Object System.Security.AccessControl.FileSystemAccessRule('SYSTEM','FullControl','ObjectInherit, ContainerInherit','None','Allow')
            $ruleAdmins = New-Object System.Security.AccessControl.FileSystemAccessRule('Administrators','FullControl','ObjectInherit, ContainerInherit','None','Allow')
            $ruleService = New-Object System.Security.AccessControl.FileSystemAccessRule($user,'ReadAndExecute','ObjectInherit, ContainerInherit','None','Allow')
            $acl.AddAccessRule($ruleSystem)            
            $acl.AddAccessRule($ruleAdmins)
            $acl.AddAccessRule($ruleService)
            Set-Acl $prometheusInstallPath $acl | Out-Null            

            'data','logs' | ForEach-Object {
                mkdir $prometheusInstallPath\$_ | Out-Null
                $acl = Get-Acl $prometheusInstallPath\$_
                $acl.SetOwner([System.Security.Principal.NTAccount] $prometheusServiceUsername)
                $acl.SetAccessRuleProtection($True, $False)                
                $acl.AddAccessRule($ruleSystem)                
                $acl.AddAccessRule($ruleAdmins)
                $ruleService = New-Object System.Security.AccessControl.FileSystemAccessRule($user,'FullControl','ObjectInherit, ContainerInherit','None','Allow')
                $acl.AddAccessRule($ruleService)
                Set-Acl $prometheusInstallPath\$_ $acl | Out-Null
                
                Write-Host "Checking the prometheus configuration..."
                &$prometheusInstallPath\promtool.exe check config $prometheusInstallPath\prometheus.yml

                Write-Host "Starting the $prometheusServiceName service..."
                Start-Service $prometheusServiceName

                # Create Firewall rule for Prometheus Server
                New-NetFirewallRule -DisplayName 'Prometheus Server' -Profile @('Public','Private','Domain') -Direction Inbound -Action Allow -Protocol TCP -LocalPort 9090
            }
        }

        # Install Grafana as Service
        if ($package -match 'Grafana' -and (where.exe nssm)){
            $grafanaServiceName = 'grafana-server'
            $grafanaInstallPath = $servicePath + "Grafana"
            $grafanaServiceUsername = "NT SERVICE\$grafanaServiceName"

            # Extract Grafana installer zip to Install path
            $filePath = (get-childitem $executableDownloadPath | Where-Object {$_.Name.StartsWith($package.ToLower())}).versioninfo.filename
            $shell = New-Object -ComObject Shell.Application
            $rawPath = $filePath + "\" + ((get-childitem $executableDownloadPath | Where-Object {$_.Name.StartsWith($package.ToLower())}).Name -replace ".zip")
            $actualPath = $rawPath.Substring(0,$rawPath.Length-14)
            $zipFile = $shell.NameSpace($actualPath)
            $destinationFolder = $shell.NameSpace($servicePath + $package)            

            $copyFlags = 0x00
            $copyFlags += 0x04 # Hide progress dialogs
            $copyFlags += 0x10 # Overwrite existing files
            Write-Host "Setting up $package ..."
            Write-Host "Copying data for the $($grafanaServiceName) service, may take some time..."
            $destinationFolder.CopyHere($zipFile.Items(), $copyFlags)
            $confPath = $servicePath + $package
            Copy-Item $confPath\Conf\defaults.ini $confPath\Conf\custom.ini
            
            Write-Host "Configuring the $($grafanaServiceName) service..."            

            nssm install $grafanaServiceName "`"$grafanaInstallPath\bin\grafana-server.exe`""
            nssm set $grafanaServiceName Start SERVICE_AUTO_START
            nssm set $grafanaServiceName AppRotateFiles 1
            nssm set $grafanaServiceName AppRotateOnline 1
            nssm set $grafanaServiceName AppRotateSeconds 86400
            nssm set $grafanaServiceName AppRotateBytes 1048576
            nssm set $grafanaServiceName AppStdout "`"$grafanaInstallPath\logs\service-stdout.log`""
            nssm set $grafanaServiceName AppStderr "`"$grafanaInstallPath\logs\service-stderr.log`""
            nssm set $grafanaServiceName AppDirectory "`"$grafanaInstallPath\bin`""
            
            $result = sc.exe sidtype $grafanaServiceName unrestricted
            if ($result -ne '[SC] ChangeServiceConfig2 SUCCESS') {
                throw "sc.exe sidtype failed with $result"
            }
            
            $result = sc.exe config $grafanaServiceName obj= $grafanaServiceUsername
            if ($result -ne '[SC] ChangeServiceConfig SUCCESS') {
                throw "sc.exe config failed with $result"
            }

            $result = sc.exe failure $grafanaServiceName reset= 0 actions= restart/1000
            if ($result -ne '[SC] ChangeServiceConfig2 SUCCESS') {
                throw "sc.exe failure failed with $result"
            }

            $acl = Get-Acl $grafanaInstallPath
            $user = New-Object System.Security.Principal.NTAccount($grafanaServiceUsername)
            $acl.SetOwner([System.Security.Principal.NTAccount] $user)
            $acl.SetAccessRuleProtection($True, $False)
            $ruleSystem = New-Object System.Security.AccessControl.FileSystemAccessRule('SYSTEM','FullControl','ObjectInherit, ContainerInherit','None','Allow')
            $ruleAdmins = New-Object System.Security.AccessControl.FileSystemAccessRule('Administrators','FullControl','ObjectInherit, ContainerInherit','None','Allow')
            $ruleService = New-Object System.Security.AccessControl.FileSystemAccessRule($user,'ReadAndExecute','ObjectInherit, ContainerInherit','None','Allow')
            $acl.AddAccessRule($ruleSystem)            
            $acl.AddAccessRule($ruleAdmins)
            $acl.AddAccessRule($ruleService)
            Set-Acl $grafanaInstallPath $acl | Out-Null            

            'data','logs' | ForEach-Object {
                mkdir $grafanaInstallPath\$_ | Out-Null
                $acl = Get-Acl $grafanaInstallPath\$_
                $acl.SetOwner([System.Security.Principal.NTAccount] $grafanaServiceUsername)
                $acl.SetAccessRuleProtection($True, $False)                
                $acl.AddAccessRule($ruleSystem)                
                $acl.AddAccessRule($ruleAdmins)
                $ruleService = New-Object System.Security.AccessControl.FileSystemAccessRule($user,'FullControl','ObjectInherit, ContainerInherit','None','Allow')
                $acl.AddAccessRule($ruleService)
                Set-Acl $grafanaInstallPath\$_ $acl | Out-Null
                
                Write-Host "Starting the $grafanaServiceName service..."
                Start-Service $grafanaServiceName

                # Create Firewall rule for Grafana Server
                New-NetFirewallRule -DisplayName 'Grafana Server' -Profile @('Public','Private','Domain') -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3000
            }
        }
        
        # Install nssm which would help creating services for Prometheus and Grafana
        if ($package -match 'windows_exporter'){
            # Create folder for Windows Exporter in Installation path or cleanup old files
            if (Test-Path -Path ($servicePath + $package)) {
                #Clean up the old files in the path before downloading new ones
                $OldFiles = (get-Childitem ($servicePath + $package) ).FullName | Select-String -Pattern $package
                $OldFiles | ForEach-Object {Remove-Item $_.Line -Recurse -Force}
            } else {
                New-Item -Path $servicePath -Name $package -ItemType "directory" | Out-Null
            }

            Write-Host "Setting up $package ..."
            # Extract Windows Exporter installer zip to Install path
            $filePath = (get-childitem $executableDownloadPath | Where-Object {$_.Name.StartsWith($package.ToLower())}).versioninfo.filename
            $exePath = $servicePath + $package
            Copy-Item $filePath $exePath          
            $exeName = split-path $filePath -leaf
            $ServicePath = """$exePath\$exeName"" --log.format logger:eventlog?name=windows_exporter --collectors.enabled cpu,cs,net,service,process,tcp,logical_disk,os,system,textfile,thermalzone --collector.textfile.directory C:\custom_metrics\"

            $params = @{
                Name = "Windows_exporter"
                BinaryPathName = $ServicePath
                DisplayName = "Windows Exporter"
                StartupType = "Automatic"
                Description = "To run windows exporter service"
            }
            New-Service @params

            Write-Host "Starting the Windows Exporter service..."
            Start-Service Windows_exporter

            # Create Firewall rule for Windows Exporter
            New-NetFirewallRule -DisplayName 'Windows Exporter' -Profile @('Public','Private','Domain') -Direction Inbound -Action Allow -Protocol TCP -LocalPort 9182
        }
        
    }
}

Write-Host "Download all the latest executables ...."
Get-Executables

Write-Host "Setting up services ...."
New-Services