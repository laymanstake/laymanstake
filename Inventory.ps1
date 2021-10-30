# Author : Nitish Kumar
# Inventory of all Servers 
# Outputs the results to a csv file.
# version 1.0
# 21 Feb 2019


# All Servers which are part of certain group | Can be used any other condition
$servers = (Get-ADGroupMember CustomGroup).Name | get-adcomputer -properties * | select-object Name, IPv4Address, OperatingSystem

#Run the commands for each server in the list
$infoColl = @()
$i = 0
Foreach ($s in $servers) {
	$i++
	Write-Progress -activity "Getting Server Details ($i / $($Servers.Count)):" -status "Percent Done: " -PercentComplete (($i / $Servers.Count) * 100) -CurrentOperation "Now processing $($s.Name)"

	try {
		$CPUInfo = Get-CimInstance Win32_Processor -ComputerName $s.Name
		$PhysicalMemory = Get-CimInstance CIM_PhysicalMemory -ComputerName $s.Name | Measure-Object -Property capacity -Sum | ForEach-Object { [Math]::Round(($_.sum / 1GB), 2) }
		$NetworkInfo = Get-CimInstance Win32_networkadapter -ComputerName $s.Name | Where-Object { $_.MACAddress -ne $null -AND $_.PhysicalAdapter -eq $true }
		$DiskInfo = Get-CimInstance Win32_LogicalDisk -ComputerName $s.Name
		$SerialNumber = (Get-CimInstance Win32_BIOs -ComputerName $s.Name).SerialNumber
		$MakeInfo = Get-CimInstance Win32_ComputerSystem -ComputerName $s.Name
		$NICSpeed = (($NetworkInfo.Speed | ForEach-Object { ([Math]::Round(($_ / 1GB), 2)) }) -Join " Gbps,") + " Gbps"
		$DiskSizes = (($DiskInfo.size | ForEach-Object { ([Math]::Round(($_ / 1GB), 2)) }) -join " GB,") + " GB"
		$DiskFreeSizes = (($DiskInfo.FreeSpace | ForEach-Object { ([Math]::Round(($_ / 1GB), 2)) }) -join " GB,") + " GB"

		$infoObject = New-Object PSObject
		#The following add data to the infoObjects.
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "ServerName" -value $s.Name
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "IP Address" -value $s.IPv4Address
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "SerialNumber" -value $SerialNumber
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "Manufacturer" -value $MakeInfo.Manufacturer
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "Model" -value $MakeInfo.Model
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "OperatingSystem" -value $s.OperatingSystem
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

		$infoObject #Output to the screen for a visual feedback.
		$infoColl += $infoObject
	}
	catch {
		Write-Output "Issue in data collection from $($s)"
		Continue
	}
}
$infoColl | Export-Csv -path .\Server_Inventory_$((Get-Date).ToString('MM-dd-yyyy')).csv -NoTypeInformation #Export the results in csv file.
