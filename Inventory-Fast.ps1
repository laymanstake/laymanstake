# Author : Nitish Kumar
# Inventory of all Servers 
# Outputs the results to a csv file.
# version 1.0
# 11/05/2023

$func = {
    function Inventory {
        [CmdletBinding()]
        Param(
            [Parameter(ValueFromPipeline = $true, mandatory = $true)]$hostname
        )

        $CPUInfo = Get-CimInstance Win32_Processor -ComputerName $hostname
        $PhysicalMemory = Get-CimInstance CIM_PhysicalMemory -ComputerName $hostname | Measure-Object -Property capacity -Sum | ForEach-Object { [Math]::Round(($_.sum / 1GB), 2) }
        $NetworkInfo = Get-CimInstance Win32_networkadapter -ComputerName $hostname | Where-Object { $null -ne $_.MACAddress -AND $_.PhysicalAdapter -eq $true }
        $DiskInfo = Get-CimInstance Win32_LogicalDisk -ComputerName $hostname
        $hostnameerialNumber = (Get-CimInstance Win32_BIOs -ComputerName $hostname).SerialNumber
        $MakeInfo = Get-CimInstance Win32_ComputerSystem -ComputerName $hostname
        $NICSpeed = (($NetworkInfo.Speed | ForEach-Object { ([Math]::Round(($_ / 1GB), 2)) }) -Join " Gbps,") + " Gbps"
        $DiskSizes = (($DiskInfo.size | ForEach-Object { ([Math]::Round(($_ / 1GB), 2)) }) -join " GB,") + " GB"
        $DiskFreeSizes = (($DiskInfo.FreeSpace | ForEach-Object { ([Math]::Round(($_ / 1GB), 2)) }) -join " GB,") + " GB"

        $infoObject = New-Object PSObject
        #The following add data to the infoObjects.
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "ServerName" -value $hostname
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "IP Address" -value (Resolve-DnsName $hostname | Where-Object { $_.type -eq "A" }).IPAddress[0]
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "SerialNumber" -value $hostnameerialNumber
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "Manufacturer" -value $MakeInfo.Manufacturer
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "Model" -value $MakeInfo.Model
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "OperatingSystem" -value (Get-CimInstance win32_operatingsystem -ComputerName $hostname).caption
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "Processor" -value ($CPUInfo.Name -join ",")
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "CPU Model" -value ($CPUInfo.Description -join ",")
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "CPU Manufacturer" -value ($CPUInfo.Manufacturer -join ",")
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "CPU PhysicalCores" -value ($CPUInfo.NumberOfCores -join ",")
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "CPU LogicalCores" -value ($CPUInfo.NumberOfLogicalProcessors -join ",")
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "OS_Name" -value $OSInfo.Caption
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "TotalPhysical_Memory_GB" -value $PhysicalMemory
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "NIC count" -value ($NetworkInfo | Measure-object).Count
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "NIC Name" -value ($NetworkInfo.NetConnectionID -join ",")
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "NIC Type" -value ($NetworkInfo.ProductName -join ",")
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "NIC Manufacturer" -value ($NetworkInfo.Manufacturer -join ",")
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "NIC MAC Address" -value ($NetworkInfo.MACAddress -join ",")
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "NIC Speed" -value $NICSpeed
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "Drives Count" -value ($DiskInfo | Measure-object).Count
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "Drives Letters" -value ($DiskInfo.DeviceID -join ",")
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "Drive Volume Names" -value ($DiskInfo.VolumeName -join ",")
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "Drive Sizes" -value $DiskSizes
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "Drive free space Sizes" -value $DiskFreeSizes            

        return $infoObject
    }
}

# All Servers which are part of certain group | Can be used any other condition
#$Servers = (Get-ADGroupMember CustomGroup).Name | get-adcomputer -properties * | select-object Name, IPv4Address, OperatingSystem

$Servers = ("XYZ", "ABC", "QWERTY")
$i = $Servers.count

ForEach ($hostname in $Servers) {
    
    $f1 = {
        Inventory $using:hostname
    }
    If (Test-Connection $hostname -Quiet -Ping) {
        Start-Job -Name "Inventory.$hostname" -InitializationScript $func -ScriptBlock $f1 | Out-Null
    }
    Else {
        Write-Host "$hostname not reachable"
    }
}


While (Get-Job "Inventory*" | Where-Object { $_.State -eq "Running" }) {    
    $CurrentRunningJobs = (Get-Job "Inventory*" | Where-Object { $_.State -eq "Running" }).count
    Write-Progress -Activity "Jobs are running, please wait." -Status "$($CurrentRunningJobs) jobs running" -PercentComplete (100 * ($i - $CurrentRunningJobs) / $i)    
    Start-Sleep 1
}

#Collecting the data from Jobs
$Result = @()
foreach ($Job in (Get-Job | Where-Object { $_.Name -like "Inventory.*" })) {
    $JobResult = $null
    $JobResult = Receive-Job $Job
    $Result += $JobResult
    Remove-Job $Job
}

Clear-Host

$Result | Export-csv -nti $env:userprofile\desktop\Inventory.csv

