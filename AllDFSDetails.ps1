# Author : Nitish Kumar
# Performs an audit of Sita departmental file shares
# Outputs the results to a csv file.
# version 1.0
# 26 March 2018

$AllDFS = (Get-DFSNRoot | Where-Object { $_.State -eq 'Online' }).Path
$DFSInfo = @()

ForEach ($DFS in $AllDFS) {
	$DFS = $DFS + "\*"
	$DFSInfo += Get-DFSNFolder -path  $DFS | Get-DFSNFolderTarget | Select-object Path, Targetpath
}

Function GetShareDetails {
	[CmdletBinding()]
	Param (
		$Server,
		$ShareName,
		$FullPath
	)

	$array = @()
	$Share = Get-CIMInstance -class Win32_Share -Computername $Server | Where-object { $_.name -eq $ShareName }
	$BaseShare = "\\" + $Server + "\" + $ShareName
	$Postfix = $FullPath.Replace($BaseShare, "")

	Try { $ShareSec = Get-CIMInstance -Class Win32_LogicalShareSecuritySetting -ComputerName $Server  -filter "Name='$($Share.Name)'"  -ErrorAction silentlycontinue }
	Catch { Write-Output "Unable to get shares from $($Server)."}

	if ($shareSec) {
		$SD = $sharesec.GetSecurityDescriptor()
		$ShareInfo = $SD.Descriptor.DACL | ForEach-Object { $_ | Select-Object AccessMask, AceFlags, AceType, @{e = { $_.trustee.Name }; n = 'User' }, @{e = { $_.trustee.Domain }; n = 'Domain' }, @{e = { $_.trustee.SIDString }; n = 'SID' } }

		#Convert the current output into something more readable
		Switch ($ShareInfo.AceType) {
			0 { $AceType = "Allow" }
			1 { $AceType = "Deny" }
			2 { $AceType = "Audit" }
		}
		$ShareInfo | Add-Member NoteProperty AccessType $AceType

		#Convert the current output into something more readable
		Switch ($ShareInfo.AccessMask) {
			2032127 { $AccessMask = "FullControl" }
			1179785 { $AccessMask = "Read" }
			1180063 { $AccessMask = "Read, Write" }
			1179817 { $AccessMask = "ReadAndExecute" }
			-1610612736 { $AccessMask = "ReadAndExecuteExtended" }
			1245631 { $AccessMask = "ReadAndExecute, Modify, Write" }
			1180095 { $AccessMask = "ReadAndExecute, Write" }
			268435456 { $AccessMask = "FullControl (Sub Only)" }
			default { $AccessMask = $DACL.AccessMask }
		}
		$ShareInfo | Add-Member NoteProperty Access $AccessMask
	}
 else {
		Write-Warning "Specified share not exist or you may not have sufficient rights to access them!"
	}

	$SharePath = $Share.Path + $Postfix
	$Details = Get-Item $SharePath
	$Files = Get-ChildItem -Recurse $SharePath -ErrorAction SilentlyContinue | Where-Object { !$_.PSIsContainer }
	$SharePermissions = (Get-ACL -path $SharePath).Access | Select-object IdentityReference, FileSystemRights, AccessControlType
	$Size = [Math]::Round(($Files | Measure-Object Length -Sum -ErrorAction SilentlyContinue).Sum / 1MB, 2)
	$obj = New-Object PSObject
	$obj | Add-Member -MemberType NoteProperty -Name "ServerName" $env:Computername
	$obj | Add-Member -MemberType NoteProperty -Name "ShareName" $Share.Name
	$obj | Add-Member -MemberType NoteProperty -Name "Path" $SharePath
	$obj | Add-Member -MemberType NoteProperty -Name "PermittedOnShare" $($ShareInfo.User -join ',')
	$obj | Add-Member -MemberType NoteProperty -Name "SharePermissionType" $($ShareInfo.AccessType -join ',')
	$obj | Add-Member -MemberType NoteProperty -Name "SharePermissionLevel" $($ShareInfo.Access -join ',')
	$obj | Add-Member -MemberType NoteProperty -Name "Allowedusers" $($SharePermissions.IdentityReference -join ',')
	$obj | Add-Member -MemberType NoteProperty -Name "Accesstype" $($SharePermissions.FileSystemRights -join ',')
	$obj | Add-Member -MemberType NoteProperty -Name "SizeinMB" $Size
	$obj | Add-Member -MemberType NoteProperty -Name "Filescount" $Files.count
	$obj | Add-Member -MemberType NoteProperty -Name "DateModified" $Details.LastWritetime
	$obj | Add-Member -MemberType NoteProperty -Name "DateLastAccessed" $Details.LastAccesstime
	$array += $obj
	$array | select-object ServerName, ShareName, Path, PermittedOnShare, SharePermissionType, SharePermissionLevel, Allowedusers, AccessType, SizeinMB, Filescount, DateModified, DateLastAccessed
}

$Result = @()
$k = 0

ForEach ($DFSObject in $DFSInfo) {
	$k++
	$Server = [String]$DFSObject.TargetPath.Split("\")[2]
	$Sharename = [String]$DFSObject.TargetPath.Split("\")[3]
	$FullPath = [String]$DFSObject.TargetPath
	$Server
	$Sharename
	Write-Progress -activity "Getting File Shares Details ($k / $($DFSInfo.Count)):" -status "Percent Done: " -PercentComplete (($k / $DFSInfo.Count) * 100) -CurrentOperation "Now processing $($DFSObject.Path)"
	$temp = Invoke-Command -ComputerName $Server -ScriptBlock ${Function:GetShareDetails} -ArgumentList $Server, $ShareName, $FullPath -ErrorAction Continue
	$temp | Add-Member -MemberType NoteProperty "DFSShareName" -Value $DFSObject.Path
	#$temp |  select-object ServerName, DFSShareName, ShareName, Path, PermittedOnShare, SharePermissionType, SharePermissionLevel, Allowedusers, AccessType, SizeinMB, Filescount, DateModified, DateLastAccessed
	$Result += $temp
}
$Result | Select-object ServerName, DFSShareName, ShareName, Path, PermittedOnShare, SharePermissionType, SharePermissionLevel, Allowedusers, AccessType, SizeinMB, Filescount, DateModified, DateLastAccessed | export-csv -nti $env:userprofile\desktop\FileSharedata_$(get-date -Uformat "%Y%m%d-%H%M%S").csv

