# Check if current OS is Windows 10
$WindowsVer = Get-WmiObject -Query 'select * from Win32_OperatingSystem where Version like "10.0%" and ProductType = "1"' -ErrorAction SilentlyContinue

## Define new class name and date
$NewClassName = 'Win32_WinBLInfo_Local'
$Computername = $env:Computername
$Date = [string](Get-Date)
$Language = (Get-Culture).DisplayName

$class = Get-WmiObject -Class 'Win32_WinBLInfo_Local' -List -Namespace 'root\cimv2';
$classExists = $class -ne $null;

If (!($classExists)) {
	# Create new WMI class
	$newClass = New-Object System.Management.ManagementClass ("root\cimv2", [String]::Empty, $null)
	$newClass["__CLASS"] = $NewClassName

	# Create properties you want inventoried
	$newClass.Qualifiers.Add("Static", $true)
	$newClass.Properties.Add("Computername", [System.Management.CimType]::String, $false)
	$newClass.Properties.Add("Language", [System.Management.CimType]::String, $false)
	$newClass.Properties.Add("KeyProtectorId", [System.Management.CimType]::String, $false)
	$newClass.Properties.Add("RecoveryPassword", [System.Management.CimType]::String, $false)
	$newClass.Properties.Add("ScriptLastRan", [System.Management.CimType]::String, $false)
	$newClass.Properties["KeyProtectorId"].Qualifiers.Add("Key", $true)
	$newClass.Put() | Out-Null
}

# Collect the existing data to a variable
$CurrentData = (Get-WmiObject -Query 'select * from Win32_WinBLInfo_Local')

# Check current OS is Windows 10 to proceed 
if ($WindowsVer) {		
	
	# Identify all the Bitlocker volumes.
	$BitlockerVolumes = Get-BitLockerVolume

	# For each volume, get the RecoveryPassword and display it.
	$BitlockerVolumes |
	ForEach-Object {
		$MountPoint = $_.MountPoint			
		$ProtectionStatus = [string]($_.ProtectionStatus)	

		# Check if the current drive is Bitlocker Protected
		if ($ProtectionStatus -eq 'On') {
			#Get Recovery Key info & sync with AD     				
			$BLVs = Get-BitLockerVolume -MountPoint $MountPoint				

			ForEach ($BLV in $BLVs.KeyProtector) {
				if ($BLV.KeyProtectorType -eq "RecoveryPassword") {                    
					# Proceed for inserting only non-null values of RecoveryPassword
					if ($BLV.RecoveryPassword -ne "") {
						# Attempt to Sync Recovery Key to Corporate Active Directory				
						Write-Host "Backing up to AD" -ForegroundColor YELLOW
						Backup-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $BLV.KeyProtectorId
						
						# Attempt to Sync Recovery Key to Azure Active Directory
						Write-Host "Backing up to AAD" -ForegroundColor YELLOW
						BackupToAAD-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $BLV.KeyProtectorId
				
						if (!(($CurrentData.RecoveryPassword -contains $BLV.RecoveryPassword) -AND ($CurrentData.KeyProtectorId -contains $BLV.KeyProtectorId))) {
							# write-host "Inserting data ..." -ForegroundColor GREEN
							Set-WmiInstance -Namespace root\cimv2 -class $NewClassName -Arguments @{
								Computername     = $Computername;
								Language         = $Language;
								KeyProtectorId   = $BLV.KeyProtectorId;
								RecoveryPassword = $BLV.RecoveryPassword;            
								ScriptLastRan    = $Date;
							}		| Out-Null
						}
					}
				}
			}
		}
	}
}