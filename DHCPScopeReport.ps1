# To obtain DHCP Scopes related details from all domain servers
# Author: Nitish Kumar
# v1.0

import-module DHCPServer
#Get all Authorized DCs from AD configuration
$DHCPs = Get-DhcpServerInDC  #| ?{$_.DNSname -like "SINFPS0*" }

$filename = "$Env:userprofile\Desktop\DHCPScopes_DNS_$(get-date -Uformat "%Y%m%d-%H%M%S").csv"
$Report = @()

$Reservations = @()
$k = $null

Write-Output -foregroundcolor Green "`n`n`n`n`n`n`n`n`n"

foreach ($dhcp in $DHCPs) {
	$k++
	Write-Progress -activity "Getting DHCP scopes:" -status "Percent Done: " -PercentComplete (($k / $DHCPs.Count) * 100) -CurrentOperation "Now processing $($dhcp.DNSName)"
	$scopes = $null
	$scopes = (Get-DhcpServerv4Scope -ComputerName $dhcp.DNSName -ErrorAction:SilentlyContinue)
	$Res = $scopes | ForEach-Object { Get-DHCPServerv4Lease -ComputerName $dhcp.DNSName -ScopeID $_.ScopeID } | Select-Object ScopeId, IPAddress, HostName, Description, ClientID, AddressState

	Write-Output -foregroundcolor Green "Processing reservations on ""$($dhcp.DNSName)"""
	ForEach ($Temp in $Res ) {
		$Reservation = New-Object -TypeName PSObject -Property @{
			ServerName   = $dhcp.DNSName
			ScopeID      = $Temp.ScopeId
			IPAddress    = $Temp.IPAddress
			HostName     = $Temp.HostName
			Description  = $Temp.Description
			ClientID     = $Temp.ClientID
			AddressState = $Temp.AddressState
		} | select-object ServerName, ScopeID, IPAddress, HostName, Description, ClientID, AddressState
		$Reservations += $Reservation
	}

	If ($null -ne $scopes) {
		$GlobalDNSList = $null
		#getting global DNS settings, in case scopes are configured to inherit these settings
		$GlobalDNSList = (Get-DhcpServerv4OptionValue -OptionId 6 -ComputerName $dhcp.DNSName -ErrorAction:SilentlyContinue).Value
		Try { $Option015 = [String](Get-DhcpServerv4OptionValue -OptionId 015 -ComputerName $dhcp.DNSName -ErrorAction:SilentlyContinue).value }
		Catch { $Option015 = "" }

		$scopes | ForEach-Object {
			$row = "" | Select-Object Hostname, ScopeID, SubnetMask, Name, State, StartRange, EndRange, LeaseDuration, Description, DNS1, DNS2, DNS3, DNS4, DNS5, GDNS1, GDNS2, GDNS3, GDNS4, GDNS5, Router, DoGroupId, Option160, option015, Scopeoption015, Exclusions
			Try { $DoGroupId = [String](Get-DhcpServerv4OptionValue -OptionId 234 -ScopeID $_.ScopeId -ComputerName $dhcp.DNSName -ErrorAction:SilentlyContinue).value }
			Catch { $DoGroupId = "" }

			Try { $Option160 = [String](Get-DhcpServerv4OptionValue -OptionId 160 -ScopeID $_.ScopeId -ComputerName $dhcp.DNSName -ErrorAction:SilentlyContinue).value }
			Catch { $Option160 = "" }

			Try { $ScopeOption015 = [String](Get-DhcpServerv4OptionValue -OptionId 015 -ScopeID $_.ScopeId -ComputerName $dhcp.DNSName -ErrorAction:SilentlyContinue).value }
			Catch { $ScopeOption015 = "" }

			$router = @()
			Try { $router = (Get-DhcpServerv4OptionValue -ComputerName $dhcp.DNSName -OptionId 3 -ScopeID $_.ScopeId -ErrorAction:SilentlyContinue).Value }
			Catch { $router = ("") }

			$ScopeExclusions = @()
			Try { $ScopeExclusions = Get-DhcpServerv4ExclusionRange -ComputerName $dhcp.DNSName -ScopeID $_.ScopeId -ErrorAction:SilentlyContinue }
			Catch { $ScopeExclusions = ("") }

			$Exclusions = ""
			$z = 0
			If ($ScopeExclusions) {
				ForEach ($ScopeExclusion in $ScopeExclusions) {
					$z++
					Write-Output "Checking exclusion $($z) for $($_.ScopeId) ..." -Foregroundcolor GREEN
					$ExclusionValue = [String]$ScopeExclusion.StartRange + "-" + [String]$ScopeExclusion.EndRange
					if ($z -ge 2) {	$Exclusions = $Exclusions + "," + $ExclusionValue } else { $Exclusions = $ExclusionValue }
				}
			}

			$row.Router = $router[0]
			$row.Hostname = $dhcp.DNSName
			$row.ScopeID = $_.ScopeID
			$row.SubnetMask = $_.SubnetMask
			$row.Name = $_.Name
			$row.State = $_.State
			$row.StartRange = $_.StartRange
			$row.EndRange = $_.EndRange
			$row.LeaseDuration = $_.LeaseDuration
			$row.Description = $_.Description
			$row.DoGroupId = $DoGroupId
			$row.Option160 = $Option160
			$row.Option015 = $Option015
			$row.ScopeOption015 = $ScopeOption015
			$row.Exclusions = $Exclusions
			$ScopeDNSList = $null
			$ScopeDNSList = (Get-DhcpServerv4OptionValue -OptionId 6 -ScopeID $_.ScopeId -ComputerName $dhcp.DNSName -ErrorAction:SilentlyContinue).Value

			If (($ScopeDNSList -eq $null) -and ($GlobalDNSList -ne $null)) {
				$row.GDNS1 = $GlobalDNSList[0]
				$row.GDNS2 = $GlobalDNSList[1]
				$row.GDNS3 = $GlobalDNSList[2]
				$row.GDNS4 = $GlobalDNSList[3]
				$row.GDNS5 = $GlobalDNSList[4]
			}
			ElseIf (($ScopeDNSList -ne $null) -and ($GlobalDNSList -ne $null)) {
				$row.GDNS1 = $GlobalDNSList[0]
				$row.GDNS2 = $GlobalDNSList[1]
				$row.GDNS3 = $GlobalDNSList[2]
				$row.GDNS4 = $GlobalDNSList[3]
				$row.GDNS5 = $GlobalDNSList[4]
				$row.DNS1 = $ScopeDNSList[0]
				$row.DNS2 = $ScopeDNSList[1]
				$row.DNS3 = $ScopeDNSList[2]
				$row.DNS4 = $ScopeDNSList[3]
				$row.DNS5 = $ScopeDNSList[4]
			}
			Else {
				$row.DNS1 = $ScopeDNSList[0]
				$row.DNS2 = $ScopeDNSList[1]
				$row.DNS3 = $ScopeDNSList[2]
				$row.DNS4 = $ScopeDNSList[3]
				$row.DNS5 = $ScopeDNSList[4]
			}
			$row
			$Report += $row
		}
	}
	Else {
		Write-Output -foregroundcolor Yellow """$($dhcp.DNSName)"" is either running Windows 2003, or is somehow not responding to querries. Adding to report as blank"
		$row = "" | Select-Object Hostname, ScopeID, SubnetMask, Name, State, StartRange, EndRange, LeaseDuration, Description, DNS1, DNS2, DNS3, DNS4, DNS5, GDNS1, GDNS2, GDNS3, GDNS4, GDNS5, Router, DoGroupId, Option160, option015, Scopeoption015, Exclusions
		$row.Hostname = $dhcp.DNSName
		$Report += $row
	}
	Write-Output -foregroundcolor Green "Done Processing ""$($dhcp.DNSName)"""
}
$Report  | Export-csv -NoTypeInformation -UseCulture $filename
$Reservations | Export-Csv "$Env:userprofile\Desktop\DHCPLeasesReservations_$(get-date -Uformat "%Y%m%d-%H%M%S").csv" -NoTypeInformation