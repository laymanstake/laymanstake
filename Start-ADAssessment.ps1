#Requires -RunAsAdministrator
#Requires -Version 3.0
#Requires -Modules ActiveDirectory, GroupPolicy, DnsServer

<#  
    Author : Nitish Kumar
    Performs Active Directory Forest Assessment
    version 1.0 | 06/06/2023 Initial version
    version 1.1 | 15/06/2023 Covered most areas though error proofing and dependency over wsman still remains
    version 1.2 | 16/06/2023 Number of small fixes included wrong calulations on empty groups

    The script is kept as much modular as possible so that functions can be modified or added without altering the entire script
    It should be run as administrator and preferably Enterprise Administrator to get complete data. Its advised to run in demonstration environment to be sure first

    Disclaimer: This script is designed to only read data from the domain and should not cause any problems or change configurations but author do not claim to be responsible for any issues. Do due dilligence before running in the production environment
#>

<#
.SYNOPSIS
    Start-ADAssessment.ps1 - Perform Active Directory assessment and generate a report.

.DESCRIPTION
    This script performs an assessment of Active Directory (AD) environment and generates a report with information
    about domain controllers, replication status, DNS configuration, group policies, and more.

.NOTES
    - This script requires elevated privileges and should be run as an administrator.
    - Ensure that the required PowerShell modules and dependencies are installed (e.g., RSAT tools).

.EXAMPLE
    Running the script would present a menu and would pick current forest or domain accordingly.
    - Performs an assessment of the "example.com" domain and generates the report at the specified path.

#>

Import-Module ActiveDirectory
Import-Module GroupPolicy
Import-Module DnsServer

if (Get-Module -ListAvailable -Name DHCPServer) {    
    Import-Module DHCPServer
    $DHCPFlag = $true
}
else {
    $DHCPFlag = $false
}

# Output formating options
$logopath = "https://camo.githubusercontent.com/239d9de795c471d44ad89783ec7dc03a76f5c0d60d00e457c181b6e95c6950b6/68747470733a2f2f6e69746973686b756d61722e66696c65732e776f726470726573732e636f6d2f323032322f31302f63726f707065642d696d675f32303232303732335f3039343534372d72656d6f766562672d707265766965772e706e67"
$ReportPath1 = "$env:USERPROFILE\desktop\ADReport_$(get-date -Uformat "%Y%m%d-%H%M%S").html"
$CopyRightInfo = " @Copyright Niitsh Kumar <a href='https://github.com/laymanstake'>Visit nitishkumar.net</a>"
[bool]$forestcheck = $false

# CSS codes to format the report
$header = @"
<style>
    body { background-color: #b9d7f7; }
    h1 { font-family: Arial, Helvetica, sans-serif; color: #e68a00; font-size: 28px; }    
    h2 { font-family: Arial, Helvetica, sans-serif; color: #000099; font-size: 16px; }    
    table { font-size: 12px; border: 1px;  font-family: Arial, Helvetica, sans-serif; } 	
    td { padding: 4px; margin: 0px; border: 1; }	
    th { background: #395870; background: linear-gradient(#49708f, #293f50); color: #fff; font-size: 11px; text-transform: uppercase; padding: 10px 15px; vertical-align: middle; }
    tbody tr:nth-child(even) { background: #f0f0f2; }
    CreationDate { font-family: Arial, Helvetica, sans-serif; color: #ff3300; font-size: 12px; }
</style>
"@

If ($logopath) {
    $header = $header + "<img src=$logopath alt='Company logo' width='150' height='150' align='right'>"
}

# Number of functions to get the details of the environment
# Returns the details of AD trusts in the given domain
Function Get-ADTrustDetails {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][pscredential]$Credential
    )
    
    if ($Credential) {
        $trusts = Get-ADTrust -Filter * -Server $DomainName -Credential $Credential -Properties Created, Modified, ForestTransitive | Select-Object Name, Source, Target, Created, Modified, Direction, TrustType, Intraforest, ForestTransitive
    }
    else {
        $trusts = Get-ADTrust -Filter * -Server $DomainName -Properties Created, Modified, ForestTransitive | Select-Object Name, Source, Target, Created, Modified, Direction, TrustType, Intraforest, ForestTransitive
    }

    $TrustDetails = @()

    ForEach ($trust in $trusts) {
        $stale = $false        
        if ($trust.TrustType -eq "External" -and $trust.Direction -eq "Bidirectional") {
            try {
                if ($Credential) {
                    $null = Get-ADDomain -Identity $trust.Target -Server $trust.Target -Credential $Credential -ErrorAction Stop
                }
                else {
                    $null = Get-ADDomain -Identity $trust.Target -Server $trust.Target -ErrorAction Stop
                }
            }
            catch {
                $stale = $true
            }
        }        

        $TrustDetails += [PSCustomObject]@{
            TrustName        = $trust.Name
            CreationDate     = $trust.Created
            ModificationDate = $trust.Modified
            TrustSource      = $trust.Source
            TrustTarget      = $trust.Target
            TrustDirection   = $trust.Direction
            TrustType        = $trust.TrustType
            Intraforest      = $trust.Intraforest
            Foresttransitive = $trust.ForestTransitive
            Stale            = $stale
        }
    }
    Return $TrustDetails
}

Function Get-ADFSDetails {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][pscredential]$Credential
    )
    
    $adfsServers = @()
    $aadconnectServers = @()
    $ADFSServerDetails = @()
    $AADCServerDetails = @()

    $PDC = (Get-ADDomain -Identity $DomainName -Credential $Credential -Server $DomainName).PDCEmulator

    Get-ADComputer -Filter { OperatingSystem -like "*Server*" } -Server $PDC -Credential $Credential |
    ForEach-Object {
        $computer = $_.Name
        try {            
            $service = ((Get-Service -ComputerName $computer -Name adfssrv -ErrorAction SilentlyContinue).Name , (Get-Service -ComputerName $computer -Name adsync -ErrorAction SilentlyContinue).Name )
        }
        catch {
            
        }
        if ($service[0] -eq "adfssrv") {
            $adfsServers += $computer
        }
        if ($service[1] -eq "adsync" ) {
            $aadconnectServers += $computer
        }
    }

    foreach ($server in $adfsServers) {
        try {
            if (Test-WSMan -ComputerName $server -ErrorAction SilentlyContinue) {
                $ADFSproperties = invoke-command -ComputerName $server -ScriptBlock { import-module ADFS; Get-ADFSSyncProperties; (Get-ADFSProperties).Identifier } -Credential $Credential
            }
        }
        catch {
            Write-Output "PS remoting NOT supported on $server"
        }
        
        if (($ADFSproperties[0]).Role -eq "PrimaryComputer") {
            $isMaster = $true
        }
        else {
            $isMaster = $false
        }
        
        $serverInfo = [PSCustomObject]@{
            ServerName      = $server
            OperatingSystem = (Get-ADComputer $server -server $PDC -Credential $Credential -properties OperatingSystem).OperatingSystem
            IsMaster        = $isMaster
            ADFSName        = $ADFSproperties[1]
        }

        $ADFSServerDetails += $serverInfo
    }

    foreach ($server in $aadconnectServers) {        
        $InstallPath = ((([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $server)).OpenSubKey('SOFTWARE\Microsoft\Azure AD Connect')).GetValue('Wizardpath')) -replace "\\", "\\"
        $null = ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $server)).Close();
        
        if (Test-WSMan -ComputerName $server -ErrorAction SilentlyContinue) {
            $ADSyncVersion = (Get-CimInstance -ClassName Cim_DataFile -ComputerName $server -Filter "Name='$InstallPath'").Version
        }
        else {
            $ADSyncVersion = "Access denied"
        }

        $Info = [PSCustomObject]@{
            ServerName      = $server
            OperatingSystem = (Get-ADComputer $server -server $PDC -Credential $Credential -properties OperatingSystem).OperatingSystem            
            ADSyncVersion   = $ADSyncVersion
            IsActive        = (Get-Service -ComputerName $Server -Name ADSync -ErrorAction SilentlyContinue).Status -eq "Running"
        }

        $AADCServerDetails += $Info
    }
    
    return $AADCServerDetails, $ADFSServerDetails 
}

# Returns the details of the PKI servers
Function Get-PKIDetails {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$ForestName,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][pscredential]$Credential
    )

    $PKIDetails = New-Object psobject
    
    $PDC = (Get-ADDomain -Identity $ForestName -Credential $Credential -Server $ForestName).PDCEmulator    
    $PKI = Get-ADObject -Filter { objectClass -eq "pKIEnrollmentService" } -Server $PDC -Credential $Credential -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).ConfigurationNamingContext)"  -Properties DisplayName, DnsHostName | Select-Object DisplayName, DnsHostName, @{l = "OperatingSystem"; e = { (Get-ADComputer ($_.DNShostname -replace ".$ForestName") -Properties OperatingSystem -server $PDC -Credential $Credential).OperatingSystem } }, @{l = "IPv4Address"; e = { ([System.Net.Dns]::GetHostAddresses($_.DnsHostName) | Where-Object { $_.AddressFamily -eq "InterNetwork" }).IPAddressToString -join "`n" } }

    If ($PKI) {        
        $PKIDetails = $PKI
        try {
            if ( Test-WSMan -ComputerName $PKI.DnsHostName -ErrorAction SilentlyContinue) {
                $cert = invoke-command -ComputerName $PKI.DnsHostName -Credential $Credential -ScriptBlock { Get-ChildItem -Path cert:\LocalMachine\my | Where-Object { $_.issuer -eq $_.Subject } }
                Add-Member -inputObject $PKIDetails -memberType NoteProperty -name "SecureHashAlgo" -value $cert.SignatureAlgorithm.FriendlyName
            }
        }
        catch {
            Write-Out "WinRM access denied, can't obtain SHA information"
        }
    }    
    
    Return $PKIDetails
}

# Returns the details of the DNS servers in the given domain
Function Get-ADDNSDetails {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][pscredential]$Credential
    )

    $DNSServerDetails = @()
    $PDC = (Get-ADDomain -Identity $DomainName -Credential $Credential -Server $DomainName).PDCEmulator    
    
    $DNSServers = (Get-ADDomainController -Filter * -server $PDC -Credential $Credential) | Where-Object { (Get-WindowsFeature -ComputerName $_.name -Name DNS -Credential $Credential) } | Select-Object Name, IPv4Address

    ForEach ($DNSServer in $DNSServers) {
        $Scavenging = Get-DnsServerScavenging -ComputerName $DNSServer.Name
        $DNSServerDetails += [PSCustomObject]@{
            ServerName         = $DNSServer.Name
            IPAddress          = $DNSServer.IPv4Address
            OperatingSystem    = (Get-ADComputer $DNSServer.Name -Properties OperatingSystem -Server $PDC -Credential $Credential).OperatingSystem
            Forwarders         = (Get-DnsServerForwarder -ComputerName $DNSServer.Name).IPAddress -join "`n"
            ScanvengingState   = $Scavenging.ScavengingState
            ScavengingInterval = $Scavenging.ScavengingInterval
            NoRefreshInterval  = $Scavenging.NoRefreshInterval
            RefreshInterval    = $Scavenging.RefreshInterval
            LastScavengeTime   = $Scavenging.LastScavengeTime
        }        
    }

    return $DNSServerDetails
}

# Returns the details of the DNS zones in the given DNS Server
Function Get-ADDNSZoneDetails {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][pscredential]$Credential
    )

    $DNSServerZoneDetails = @()
    $PDC = (Get-ADDomain -Identity $DomainName -Credential $Credential -Server $DomainName).PDCEmulator    
    
    $DNSZones = Get-DnsServerZone -ComputerName $PDC | Where-Object { -Not $_.IsReverseLookupZone } | Select-Object DistinguishedName, ZoneName, ZoneType, IsReadOnly, DynamicUpdate, IsSigned, IsWINSEnabled, ReplicationScope, MasterServers, SecureSecondaries, SecondaryServers

    ForEach ($DNSZone in $DNSZones) {
        If ($DNSZone.DistinguishedName) {
            $Info = (Get-DnsServerZone -zoneName $DNSZone.ZoneName -ComputerName $PDC | Where-Object { -NOT $_.IsReverseLookupZone -AND $_.ZoneType -ne "Forwarder" }).Distinguishedname | ForEach-Object { Get-ADObject -Identity $_ -Server $PDC -Credential $Credential -Properties ProtectedFromAccidentalDeletion, Created }
        }
        Else {
            $Info = [PSCustomObject]@{
                ProtectedFromAccidentalDeletion = $false
                Created                         = ""
            }
        }
        $ZoneInfo = New-Object PSObject
        $ZoneInfo = $DNSZone
        Add-Member -inputObject $ZoneInfo -memberType NoteProperty -name DNSServer -value $PDC
        Add-Member -inputObject $ZoneInfo -memberType NoteProperty -name ProtectedFromDeletion -value $Info.ProtectedFromAccidentalDeletion
        Add-Member -inputObject $ZoneInfo -memberType NoteProperty -name Created -value $Info.Created
        $DNSServerZoneDetails += $ZoneInfo | Select-Object DNSServer, ZoneName, ProtectedFromDeletion, Created, ZoneType, IsReadOnly, DynamicUpdate, IsSigned, IsWINSEnabled, ReplicationScope, @{l = "MasterServers"; e = { $_.MasterServers -join "`n" } } , SecureSecondaries, @{l = "SecondaryServers"; e = { $_.SecondaryServers -join "`n" } } 
    }

    return $DNSServerZoneDetails
}

# Return the group members recusrively from the given domain only, would skip foreign ones
Function Get-ADGroupMemberRecursive {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName,
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$GroupName,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][pscredential]$Credential
    )
    
    $Domain = (Get-ADDomain -Identity $DomainName -Credential $Credential)
    $PDC = $Domain.PDCEmulator    
    $members = (Get-ADGroup -Identity $GroupName -Server $PDC -Credential $Credential -Properties Members).members

    $membersRecursive = @()
    foreach ($member in $members) {
        If ($member.Substring($member.IndexOf("DC=")) -eq $Domain.DistinguishedName) {
            if ((Get-ADObject -identity $member -server $PDC -Credential $Credential).Objectclass -eq "group" ) { 
                $membersRecursive += Get-ADGroupMemberRecursive -GroupName $member -DomainName $Domain.DNSRoot -Credential $Credential
            }
            else {
                $membersRecursive += Get-ADUser -identity $member -Server $PDC  -Credential $Credential | Select-Object Name
            }
        }
    }
    return $membersRecursive    
}

# Return the users with adminCount
Function Get-AdminCountDetails {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][pscredential]$Credential
    )
    
    $PDC = (Get-ADDomain -Identity $DomainName).PDCEmulator
    $protectedGroups = (Get-ADGroup -Filter * -Server $PDC -Credential $Credential -properties adminCount | Where-Object { $_.adminCount -eq 1 }).Name

    $ProtectedUsers = ($protectedGroups | ForEach-Object { Get-ADGroupMemberRecursive -GroupName $_ -DomainName $DomainName -Credential $Credential } | Sort-Object Name -Unique).Name
    $UserWithAdminCount = (Get-ADUser -Filter * -Server $PDC -Credential $Credential -Properties AdminCount | Where-Object { $_.adminCount -eq 1 }).Name
    $UndesiredAdminCount = (Compare-Object -ReferenceObject $UserWithAdminCount -DifferenceObject $ProtectedUsers | Where-Object { $_.SideIndicator -eq '<=' -AND $_.InputObject -ne "krbtgt" }).InputObject

    $AdminCountDetails = [PSCustomObject]@{
        DomainName          = $DomainName
        ProtectedUsersCount = $ProtectedUsers.Count
        UserWithAdminCount  = $UserWithAdminCount.Count - 1
        UndesiredAdminCount = $UndesiredAdminCount.Count
        UsersToClear        = $UndesiredAdminCount -join "`n"
    }

    return $AdminCountDetails
}

# Return the details of DHCP Servers
Function Get-ADDHCPDetails {  
    [CmdletBinding()]
    Param(    
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][pscredential]$Credential
    )

    $PDC = (Get-ADDomain -Current LocalComputer).PDCEmulator    
    $configPartition = (Get-ADforest).PartitionsContainer.Replace("CN=Partitions,", "")
    $AllDHCPServers = (Get-ADObject -SearchBase $configPartition -Filter "objectclass -eq 'dhcpclass' -AND Name -ne 'dhcproot'" -Server $PDC -Credential $Credential).Name
    $DHCPDetails = @()

    foreach ($dhcpserver in $AllDHCPServers) {
        $ErrorActionPreference = "SilentlyContinue"
        try {
            $Allscopes = @(Get-DhcpServerv4Scope -ComputerName $dhcpserver -ErrorAction:SilentlyContinue)
            $InactiveScopes = @($Allscopes | Where-Object { $_.State -eq 'Inactive' })
        
            $NoLeaseScopes = @()
            foreach ($Scope in $Allscopes) {
                $Leases = Get-DhcpServerv4Lease -ComputerName $dhcpserver -ScopeId $Scope.ScopeId
                if ($Leases.Count -eq 0) {
                    $NoLeaseScopes += $Scope.ScopeID
                }
            }

            try {
                $OS = (Get-WmiObject win32_operatingSystem -ComputerName $dhcpserver -Property Caption).Caption                
            }
            catch {
                $OS = "Access denied"
            }

            $DHCPDetails += [PSCustomObject]@{
                ServerName         = $dhcpserver
                IPAddress          = ([System.Net.Dns]::GetHostAddresses($dhcpserver) | Where-Object { $_.AddressFamily -eq "InterNetwork" }).IPAddressToString -join "`n"
                OperatingSystem    = $OS 
                ScopeCount         = $Allscopes.count
                InactiveScopeCount = $InactiveScopes.count
                ScopeWithNoLease   = $NoLeaseScopes -join "`n"
                NoLeaseScopeCount  = $NoLeaseScopes.count                
            }
        }
        catch {}
    }
    
    return $DHCPDetails
}

# Returns all DHCP servers inventory along with reservations details
Function Get-DHCPInventory {
    [CmdletBinding()]
    Param(    
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][pscredential]$Credential
    )
    
    # Get all Authorized DCs from AD configuration
    $DHCPs = Get-DhcpServerInDC    
    $Report = @()
    $Reservations = @()

    foreach ($dhcp in $DHCPs) {
        $scopes = $null
        $scopes = (Get-DhcpServerv4Scope -ComputerName $dhcp.DNSName -ErrorAction:SilentlyContinue)
        $Res = $scopes | ForEach-Object { Get-DHCPServerv4Lease -ComputerName $dhcp.DNSName -ScopeID $_.ScopeID } | Select-Object ScopeId, IPAddress, HostName, Description, ClientID, AddressState
    
        ForEach ($Temp in $Res ) {
            $Reservation = [PSCustomObject]@{
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
                        $ExclusionValue = [String]$ScopeExclusion.StartRange + "-" + [String]$ScopeExclusion.EndRange
                        if ($z -ge 2) {	$Exclusions = $Exclusions + "," + $ExclusionValue } else { $Exclusions = $ExclusionValue }
                    }
                }

                if ($router) {
                    $row.Router = $router[0]
                }
                else {
                    $row.Router = ""
                }                
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

                If (($null -eq $ScopeDNSList) -and ($null -ne $GlobalDNSList)) {
                    $row.GDNS1 = $GlobalDNSList[0]
                    $row.GDNS2 = $GlobalDNSList[1]
                    $row.GDNS3 = $GlobalDNSList[2]
                    $row.GDNS4 = $GlobalDNSList[3]
                    $row.GDNS5 = $GlobalDNSList[4]
                }
                ElseIf (($null -ne $ScopeDNSList) -and ($null -ne $GlobalDNSList)) {
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
            $row = "" | Select-Object Hostname, ScopeID, SubnetMask, Name, State, StartRange, EndRange, LeaseDuration, Description, DNS1, DNS2, DNS3, DNS4, DNS5, GDNS1, GDNS2, GDNS3, GDNS4, GDNS5, Router, DoGroupId, Option160, option015, Scopeoption015, Exclusions
            $row.Hostname = $dhcp.DNSName
            $Report += $row
        }        
    }
    
    $Details = [pscustomobject] @{
        Inventory   = $Report
        Reservation = $Reservations
    }
    
    Return $Details
}

# Returns the details of empty OUs in the given domain
Function Get-EmptyOUDetails {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][pscredential]$Credential
    )

    $PDC = (Get-ADDomain -Identity $DomainName -Credential $Credential -Server $DomainName).PDCEmulator

    $AllOUs = Get-ADOrganizationalUnit -Filter * -Server $PDC -Credential $Credential -Properties * 

    $EmptyOUs = ($AllOUs | Select-Object Name, CanonicalName, DistinguishedName, @{Name = 'ObjectCount'; Expression = { (Get-ADObject -Server $PDC -Credential $Credential -Filter { ObjectClass -eq 'user' -or ObjectClass -eq 'group' -or ObjectClass -eq 'computer' } -SearchBase $_.DistinguishedName).Count } } | Where-Object { $_.ObjectCount -eq 0 }).CanonicalName

    $EmptyOUDetails = [PSCustomObject]@{
        Domain       = $domainname
        AllOUs       = $AllOUs.count
        EmptyOUs     = $emptyOUs -join "`n"
        EmptyOUCount = $emptyOUs.count
    }
    
    return $EmptyOUDetails
}

# Returns the details of orphaned and lingering objects from given domain
Function Get-ADObjectsToClean {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][pscredential]$Credential
    )

    $ObjectsToClean = @()
    $Domain = Get-ADDomain -Identity $DomainName -Credential $Credential
    $PDC = $Domain.PDCEmulator
    $orphanedObj = Get-ADObject -Filter * -SearchBase "cn=LostAndFound,$($Domain.DistinguishedName)" -SearchScope OneLevel -Server $PDC -Credential $Credential
    $lingConfReplObj = Get-ADObject -LDAPFilter "(cn=*\0ACNF:*)" -SearchBase $Domain.DistinguishedName -SearchScope SubTree -Server $PDC -Credential $Credential

    $ObjectsToClean = [PSCustomObject]@{
        Domain               = $domainname        
        OrphanedObjects      = $orphanedObj.DistinguishedName -join "`n"
        OrphanedObjectCount  = $orphanedObj.Name.count
        LingeringObjects     = $lingConfReplObj.DistinguishedName -join "`n"
        LingeringObjectCount = $lingConfReplObj.Name.count
    }
    
    return $ObjectsToClean
}

# Returns the details of unlinked GPOs in the given domain
Function Get-ADGPOSummary {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][pscredential]$Credential
    )
    
    $AllGPOs = Get-GPO -All -Domain $DomainName
    $LinkedGPOs = @($AllGPOs | Where-Object { $_ | Get-GPOReport -ReportType XML -Domain $DomainName | Select-String -Pattern  "<LinksTo>" -SimpleMatch } | Select-Object DisplayName, CreationTime, ModificationTime )
    $UnlinkedGPOs = @($AllGPOs | Where-Object { $_ | Get-GPOReport -ReportType XML -Domain $DomainName | Select-String -NotMatch "<LinksTo>" } | Select-Object DisplayName, CreationTime, ModificationTime )
    $DeactivatedGPOs = @($AllGPOs | Where-Object { $_.GPOStatus -eq "AllSettingsDisabled" } | Select-Object DisplayName, CreationTime, ModificationTime )
    $LinkedButDeactivatedGPOs = @()

    If ($LinkedGPOs.count -ge 1 -AND $DeactivatedGPOs.Count -ge 1) {
        $LinkedButDeactivatedGPOs = (Compare-Object -ReferenceObject $DeactivatedGPOs -DifferenceObject $LinkedGPOs -IncludeEqual | Where-Object { $_.SideIndicator -eq '==' } | Select-Object InputObject).InputObject
    }

    $GPOsAtRootLevel = (Get-GPInheritance -Target (Get-ADDomain -Identity $DomainName -credential $Credential).DistinguishedName).Gpolinks.DisplayName -join "`n"

    $UnlinkedGPODetails = [PSCustomObject]@{
        Domain                      = $domainname
        AllGPOs                     = $AllGPOs.count
        GPOsAtRoot                  = $GPOsAtRootLevel
        Unlinked                    = @($UnlinkedGPOs).DisplayName -join "`n"
        UnlinkedCreationTime        = @($UnlinkedGPOs).CreationTime -join "`n"
        UnlinkedModificationTime    = @($UnlinkedGPOs).ModificationTime -join "`n"
        UnlinkedCount               = @($UnlinkedGPOs).count
        Deactivated                 = @($DeactivatedGPOs).DisplayName -join "`n"
        DeactivatedCreationTime     = @($DeactivatedGPOs).CreationTime -join "`n"
        DeactivatedModificationTime = @($DeactivatedGPOs).ModificationTime -join "`n"
        DeactivatedCount            = @($DeactivatedGPOs).count
        LinkedButDeactivated        = @($LinkedButDeactivatedGPOs).DisplayName -join "`n"
        LinkedButDeactivatedCount   = @($LinkedButDeactivatedGPOs).Count
    }
    
    return $UnlinkedGPODetails
}

# To return details of all GPOs and their WMI filter for the given domain
Function Get-GPOInventory {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName     
    )
    
    $GPOSummary = @()
    $PDC = (Get-ADDomain -Identity $DomainName).PDCEmulator    
    $GPOs = Get-GPO -All -Domain $DomainName
    
    $GPOs | ForEach-Object {
        [xml]$Report = $_ | Get-GPOReport -ReportType XML -Domain $DomainName

        $Permissions = Get-GPPermission -Name $Report.GPO.Name -All -DomainName $DomainName | Select-Object @{l = "Permission"; e = { "$($_.Trustee.Name), $($_.Trustee.SIDType), $($_.permission), Denied: $($_.Denied)" } }    
        $Links = $Report.GPO.LinksTo

        $wmifilterid = ($_.WmiFilter.Path -split '"')[1]    
        $wmiquery = ((Get-ADObject -Filter { objectClass -eq 'msWMI-Som' } -Server $PDC -Properties 'msWMI-Parm2' | where-object { $_.name -eq $wmifilterid })."msWMI-Parm2" -split "root\\CIMv2;")[1]    
        
        $GPOSummary += [pscustomobject]@{
            Domain           = $DomainName
            GPOName          = $Report.GPO.Name
            Creationtime     = $_.CreationTime
            ModificationTime = $_.ModificationTime
            Link             = $($Links.SOMPATH) -join "`n"
            ComputerSettings = $Report.GPO.Computer.Enabled
            UserSettings     = $Report.GPO.User.Enabled
            Permissions      = $Permissions.Permission -join "`n"
            WmiFilter        = $_.WmiFilter.Name
            WmiQuery         = $wmiquery
        
        }
    }

    return $GPOSummary
}

# Returns the details of Applied Password Policy in the given domain
Function Get-ADPasswordPolicy {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][pscredential]$Credential
    )

    $PDC = (Get-ADDomain -Identity $DomainName -Credential $Credential -Server $DomainName).PDCEmulator
    $PwdPolicy = Get-ADDefaultDomainPasswordPolicy -Server $PDC -Credential $Credential

    $DefaultPasswordPolicy = [PSCustomObject]@{
        DomainName           = $DomainName
        MinPwdAge            = [string]($PwdPolicy.MinPasswordAge.days) + " Day(s)"
        MaxPwdAge            = [string]($PwdPolicy.MaxPasswordAge.days) + " Day(s)"
        MinPwdLength         = $PwdPolicy.MinPasswordLength
        LockoutThreshold     = $PwdPolicy.LockoutThreshold
        LockoutDuration      = $PwdPolicy.LockoutDuration
        ComplexityEnabled    = $PwdPolicy.ComplexityEnabled
        ReversibleEncryption = $PwdPolicy.ReversibleEncryptionEnabled
        PasswordHistoryCount = $PwdPolicy.PasswordHistoryCount        
    }

    return $DefaultPasswordPolicy
}

# Returns the details of Fine grained Password Policy in the given domain
Function Get-FineGrainedPasswordPolicy {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][pscredential]$Credential
    )

    $FGPwdPolicyDetails = @()
    $PDC = (Get-ADDomain -Identity $DomainName -Credential $Credential -Server $DomainName).PDCEmulator
    $DomainFL = (Get-ADDomain -Identity $DomainName -Credential $Credential).DomainMode
    
    if ( $DomainFL -in ("Windows2008Domain", "Windows2008R2Domain", "Windows2012Domain", "Windows2012R2Domain", "Windows2016Domain")) {		
        $FGPwdPolicy = Get-ADFineGrainedPasswordPolicy -Filter * -Server $PDC -Credential $Credential

        ForEach ($FGPP in $FGPwdPolicy) {
            $Obj = $FGPP.AppliesTo | ForEach-Object { Get-ADObject $_ -Server $PDC -Credential $Credential | Select-Object DistinguishedName , Name, ObjectClass } 
            $Users = $Obj | Where-Object { $_.ObjectClass -eq "User" }
            $UserList = $Users | ForEach-Object { Get-ADUser -Identity $_.DistinguishedName -Server $PDC -Credential $Credential }
            $Groups = $Obj | Where-Object { $_.ObjectClass -eq "Group" }
            $GroupList = $Groups | ForEach-Object { Get-ADGroup -Identity $_.DistinguishedName -Server $PDC -Credential $Credential }
            
            $FGPwdPolicyDetails += [PSCustomObject]@{
                DomainName           = $DomainName
                PolicyName           = $FGPP.Name
                MinPwdAge            = [string]($FGPP.MinPasswordAge.days) + " Day(s)"
                MaxPwdAge            = [string]($FGPP.MaxPasswordAge.days) + " Day(s)"
                MinPwdLength         = $FGPP.MinPasswordLength
                LockoutThreshold     = $FGPP.LockoutThreshold
                LockoutDuration      = $FGPP.LockoutDuration
                ComplexityEnabled    = $FGPP.ComplexityEnabled
                ReversibleEncryption = $FGPP.ReversibleEncryptionEnabled
                PasswordHistoryCount = $FGPP.PasswordHistoryCount        
                AppliedonUsers       = $UserList.Name -join "`n"
                AppliedonGroups      = $GroupList.Name -join "`n"
            }
        }
    }

    return $FGPwdPolicyDetails
}

# Returns the details of the given domain
Function Get-ADDomainDetails {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][pscredential]$Credential
    )

    $DomainDetails = @()
    $UndesiredFeatures = ("ADFS-Federation", "DHCP", "Telnet-Client", "WDS", "Web-Server", "Web-Application-Proxy", "FS-DFS-Namespace", "FS-DFS-Replication")

    $dcs = Get-ADDomainController -Filter * -Server $DomainName -Credential $Credential

    $LowestOSversion = ($dcs.OperatingSystemVersion | Measure-Object -Minimum).Minimum
    switch ($LowestOSversion) {
        { $_ -like "6.0*" } { $possibleDFL += "Windows Server 2008" }
        { $_ -like "6.1*" } { $possibleDFL += "Windows Server 2008 R2" }
        { $_ -like "6.2*" } { $possibleDFL += "Windows Server 2012" }
        { $_ -like "6.3*" } { $possibleDFL += "Windows Server 2012 R2" }
        { $_ -like "10.0 (14*" } { $possibleDFL += "Windows Server 2016" }
        { $_ -like "10.0 (17*" } { $possibleDFL += "Windows Server 2019" }
        { $_ -like "10.0 (19*" -OR $_ -like "10.0 (2*" } { $possibleDFL += "Windows Server 2022" }
        default { $possibleDFL += "Windows Server 2003" }
    }
    
    $PDC = (Get-ADDomain -Identity $DomainName -Credential $Credential -Server $DomainName).PDCEmulator

    if ((Get-ADObject -Server $PDC -SearchBase (Get-ADDomainController -Identity $PDC -Server $PDC -Credential $Credential).ComputerObjectDN -Filter { name -like "SYSVOL*" } -Properties replPropertyMetaData).ReplPropertyMetadata.count -gt 0) {
        $sysvolStatus = "DFSR"
    }
    else {
        $sysvolStatus = "FSR"
    }

    # It needs WinRM being enabled on PDC 
    try {
        if (Test-WSMan -ComputerName $PDC -ErrorAction SilentlyContinue) {
            $FSR2DFSRStatus = invoke-command -ComputerName $PDC -ScriptBlock { ((dfsrmig.exe /GetGlobalState )[0].replace("'", "") -split ": ")[1] } -Credential $Credential
        }
    }
    catch {
        $FSR2DFSRStatus = "WinRM access denied on $PDC"
    }

    foreach ($dc in $dcs) {
        if ( Test-Connection -ComputerName $dc -Count 1 -ErrorAction SilentlyContinue ) { 
            try {
                $NLParamters = ((([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc)).OpenSubKey('SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\')).GetValueNames() | ForEach-Object { [PSCustomObject]@{ Parameter = $_; Value = ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc)).OpenSubKey('SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\').GetValue($_) } } | ForEach-Object { "$($_.parameter), $($_.value)" }) -join "`n"
            }
            catch { $NLParamters = "Reg not found" }
            try {
                $SSL2Client = ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc)).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client').GetValue('Enabled') -eq 1 -AND ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc)).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client').GetValue('DisabledByDefault') -eq 0
            }
            catch { $SSL2Client = "Reg not found" }
            try {
                $SSL2Server = ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc)).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server').GetValue('Enabled') -eq 1 -AND ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc)).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client').GetValue('DisabledByDefault') -eq 0
            }
            catch { $SSL2Server = "Reg not found" }
            try {
                $TLS10Client = ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc)).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client').GetValue('Enabled') -eq 1 -AND ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc)).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client').GetValue('DisabledByDefault') -eq 0
            }
            catch { $TLS10Client = "Reg not found" }
            try {
                $TLS10Server = ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc)).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server').GetValue('Enabled') -eq 1 -AND ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc)).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client').GetValue('DisabledByDefault') -eq 0
            }
            catch { $TLS10Server = "Reg not found" }
            try {
                $TLS11Client = ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc)).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client').GetValue('Enabled') -eq 1 -AND ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc)).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client').GetValue('DisabledByDefault') -eq 0
            }
            catch { $TLS11Client = "Reg not found" }
            try {
                $TLS11Client = ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc)).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server').GetValue('Enabled') -eq 1 -AND ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc)).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client').GetValue('DisabledByDefault') -eq 0
            }
            catch { $TLS11Client = "Reg not found" }
            try {
                $NTPServer = ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc)).OpenSubKey('SYSTEM\CurrentControlSet\Services\W32Time\Parameters').GetValue('NTPServer')
            }
            catch { $NTPServer = "Reg not found" }

            $results = ($NLParamters, $SSL2Client, $SSL2Server, $TLS10Client, $TLS10Server, $TLS11Client, $TLS11Client, $NTPServer)
            $null = ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc)).Close();

            $InstalledFeatures = (Get-WindowsFeature -ComputerName $dc -Credential $Credential | Where-Object Installed).Name

            if ($InstalledFeatures) {
                $UndesiredFeatures = Compare-Object -ReferenceObject $UndesiredFeatures -DifferenceObject $InstalledFeatures  -IncludeEqual | Where-Object { $_.SideIndicator -eq '==' } | Select-Object -ExpandProperty InputObject
            }

            $DomainDetails += [PSCustomObject]@{
                Domain                      = $domain
                DomainFunctionLevel         = (Get-ADDomain -Identity $DomainName -Credential $Credential).DomainMode
                PossibleDomainFunctionLevel = $possibleDFL
                DCName                      = $dc.Name
                Site                        = $dc.site
                OSVersion                   = $dc.OperatingSystem
                IPAddress                   = $dc.IPv4Address
                FSMORoles                   = (Get-ADDomainController -Identity $dc -Server $dc -Credential $Credential | Select-Object @{l = "FSMORoles"; e = { $_.OperationMasterRoles -join ", " } }).FSMORoles
                Sysvol                      = $sysvolStatus
                FSR2DFSR                    = $FSR2DFSRStatus
                LAPS                        = $null -ne (Get-ADObject -LDAPFilter "(name=ms-Mcs-AdmPwd)" -Server $PDC -Credential $Credential)
                NTPServer                   = ($Results[7] | Select-Object -Unique) -join "`n"
                ADWSStatus                  = (Get-Service ADWS -computername $dc.Name  -ErrorAction SilentlyContinue ).StartType
                SSL2Client                  = $Results[1]
                SSL2Server                  = $Results[2]
                TLS1Client                  = $Results[3]
                TLS1Server                  = $Results[4]
                TLS11Client                 = $Results[5]
                TLS11Server                 = $Results[6]
                Firewall                    = (Get-Service -name MpsSvc -ComputerName $dc).Status
                NetlogonParameter           = $Results[0]
                ReadOnly                    = $dc.IsReadOnly                
                UndesiredFeatures           = $UndesiredFeatures
            }
        }
    }

    return $DomainDetails    
}

# Returns the AD site details of the given domain
Function Get-ADSiteDetails {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][pscredential]$Credential
    )

    $SiteDetails = @()
    $PDC = (Get-ADDomain -Identity $DomainName -Credential $Credential -Server $DomainName).PDCEmulator
    $sites = Get-ADReplicationSite -Filter * -Server $PDC -Credential $Credential -Properties WhenCreated, WhenChanged, ProtectedFromAccidentalDeletion, Subnets    

    foreach ($site in $sites) {        
        $dcs = @(Get-ADDomainController -Filter { Site -eq $site.Name } -Server $PDC -Credential $Credential)
        if ($dcs.Count -eq 0) {
            $links = Get-ADReplicationSiteLink -Filter * -Server $PDC -Credential $Credential -Properties InterSiteTransportProtocol, replInterval, ProtectedFromAccidentalDeletion | Where-Object { $_.sitesIncluded -contains $site.DistinguishedName }
            foreach ($link in $links) {
                $SiteDetails += [pscustomobject]@{
                    DomainName                          = $DomainName
                    SiteName                            = $site.Name
                    SiteCreated                         = $Site.WhenCreated
                    SiteModified                        = $Site.WhenChanged
                    Subnets                             = ($site.subnets | Get-ADReplicationSubnet -Server $PDC  -Credential $Credential | Select-Object Name).Name -join "`n"
                    DCinSite                            = "No DCs in site"
                    SiteLink                            = $link.Name
                    SiteLinkType                        = $link.InterSiteTransportProtocol
                    SiteLinkCost                        = $link.Cost
                    ReplicationInterval                 = $link.replInterval
                    SiteProtectedFromAccidentalDeletion = $site.ProtectedFromAccidentalDeletion
                    LinkProtectedFromAccidentalDeletion = $link.ProtectedFromAccidentalDeletion                    
                }
            }            
        }
        else {
            foreach ($dc in $dcs) {
                $links = Get-ADReplicationSiteLink -Filter * -Server $PDC -Credential $Credential -Properties InterSiteTransportProtocol, replInterval, ProtectedFromAccidentalDeletion | Where-Object { $_.sitesIncluded -contains $site.DistinguishedName }
                foreach ($link in $links) {
                    $SiteDetails += [pscustomobject]@{
                        DomainName                          = $DomainName
                        SiteName                            = $site.Name
                        SiteCreated                         = $Site.WhenCreated
                        SiteModified                        = $Site.WhenChanged
                        Subnets                             = ($site.subnets | Get-ADReplicationSubnet -Server $PDC  -Credential $Credential | Select-Object Name).Name -join "`n"
                        DCinSite                            = $dc.Name
                        SiteLink                            = $link.Name
                        SiteLinkType                        = $link.InterSiteTransportProtocol
                        SiteLinkCost                        = $link.Cost
                        ReplicationInterval                 = $link.replInterval
                        SiteProtectedFromAccidentalDeletion = $site.ProtectedFromAccidentalDeletion
                        LinkProtectedFromAccidentalDeletion = $link.ProtectedFromAccidentalDeletion
                    }     
                }
            }            
        }
    }    

    $SiteDetails = $SiteDetails | Select-Object DomainName, SiteName, SiteCreated, SiteModified, Subnets, SiteProtectedFromAccidentalDeletion, DCinSite, SiteLink, SiteLinkType, SiteLinkCost, ReplicationInterval, LinkProtectedFromAccidentalDeletion | Sort-Object DomainName, SiteLink

    return $SiteDetails
}

# Returns the priviledged group details of the given domain
Function Get-PrivGroupDetails {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][pscredential]$Credential        
    )

    $PDC = (Get-ADDomain -Identity $DomainName -Credential $Credential -Server $DomainName).PDCEmulator
    $domainSID = (Get-ADDomain $DomainName -server $PDC -Credential $Credential).domainSID.Value
    $PrivGroupSIDs = @(@("Domain Admins", ($domainSID + "-512")), 
        @("Domain Guests", ($domainSID + "-514")), 
        @("Cert Publishers", ($domainSID + "-517")), 
        @("Group Policy Creator Owners", ($domainSID + "-520")),         
        @("Account Operators", "S-1-5-32-548"), 
        @("Server Operators", "S-1-5-32-549"), 
        @("Backup Operators", "S-1-5-32-551"), 
        @("Remote Desktop Users", "S-1-5-32-555"))

    $PrivGroups = @()

    ForEach ($groupSID in $PrivGroupSIDs ) {
        $PrivGroups += [PSCustomObject]@{
            DomainName        = $DomainName
            OriginalGroupName = $groupSID[0]
            GroupName         = (Get-ADGroup -Server $PDC -Identity $GroupSID[1] -Credential $Credential).Name
            MemberCount       = @(Get-ADGroupMember -Server $PDC -Credential $Credential -Identity $GroupSID[1] -Recursive ).count
            IsRenamed         = $groupSID[0] -ne (Get-ADGroup -Server $PDC -Credential $Credential -Identity $GroupSID[1]).Name
        }
    }

    return $PrivGroups
}

# Returns the group details of the given domain
Function Get-ADGroupDetails {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][pscredential]$Credential 
    )

    $GroupDetails = @()    
    $PDC = (Get-ADDomain -Identity $DomainName -Credential $Credential -Server $DomainName).PDCEmulator

    $AllGroups = Get-ADGroup -Filter { GroupCategory -eq "Security" } -Properties GroupScope -Server $PDC -Credential $Credential
    $EmptyGroups = $AllGroups |  Where-Object { -NOT( Get-ADGroupMember $_ ) }

    $GroupDetails += [PSCustomObject]@{
        DomainName      = $DomainName
        GroupType       = "Global"
        GroupCount      = ($AllGroups | Where-Object { $_.GroupScope -eq "Global" }).count
        EmptyGroups     = ($EmptyGroups | Where-Object { $_.GroupScope -eq "Global" }).Name -join "`n"
        EmptyGroupCount = ($EmptyGroups | Where-Object { $_.GroupScope -eq "Global" }).count
    }

    $GroupDetails += [PSCustomObject]@{
        DomainName      = $DomainName
        GroupType       = "DomainLocal"
        GroupCount      = ($AllGroups | Where-Object { $_.GroupScope -eq "DomainLocal" }).count
        EmptyGroups     = ($EmptyGroups | Where-Object { $_.GroupScope -eq "DomainLocal" }).Name -join "`n"
        EmptyGroupCount = ($EmptyGroups | Where-Object { $_.GroupScope -eq "DomainLocal" }).count
    }

    $GroupDetails += [PSCustomObject]@{
        DomainName      = $DomainName
        GroupType       = "Universal"
        GroupCount      = ($AllGroups | Where-Object { $_.GroupScope -eq "Universal" }).count
        EmptyGroups     = ($EmptyGroups | Where-Object { $_.GroupScope -eq "Universal" }).Name -join "`n"
        EmptyGroupCount = ($EmptyGroups | Where-Object { $_.GroupScope -eq "Universal" }).count
    }

    return $GroupDetails
}

# Returns user summary details of the given domain
Function Get-ADUserDetails {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][pscredential]$Credential 
    )

    $PDC = (Get-ADDomain -Identity $DomainName -Credential $Credential -Server $DomainName).PDCEmulator

    $AllUsers = Get-ADUser -Filter * -Server $PDC -Properties SamAccountName, Enabled, whenCreated, PasswordLastSet, PasswordExpired, PasswordNeverExpires, PasswordNotRequired, AccountExpirationDate, LastLogonTimestamp, LockedOut | Select-object SamAccountName, Enabled, whenCreated, PasswordLastSet, PasswordExpired, PasswordNeverExpires, PasswordNotRequired, AccountExpirationDate, @{l = "Lastlogon"; e = { [DateTime]::FromFileTime($_.LastLogonTimestamp) } }, LockedOut    

    $UserDetails = [PSCustomObject]@{
        DomainName           = $DomainName
        Users                = $AllUsers.count
        RecentlyCreated      = @($AllUsers | Where-Object { $_.whenCreated -ge (Get-Date).AddDays(-30) }).count
        ChangeOnNextLogon    = @($AllUsers | Where-Object { ($null -eq $_.PasswordLastSet) -and ($_.PasswordNotRequired -eq $false) }).count
        PasswordExpired      = @($AllUsers | Where-Object { $_.PasswordExpired -eq $true }).count
        Disabled             = @($AllUsers | Where-Object { $_.Enabled -eq $false }).count
        LockedOut            = @($AllUsers | Where-Object { $_.LockedOut -eq $true }).count        
        AccountExpired       = @($AllUsers | Where-Object { $_.AccountExpirationDate -lt (Get-Date) -AND $null -ne $_.AccountExpirationDate }).count
        Inactive             = @($AllUsers | Where-Object { $_.LastLogon -lt (Get-Date).AddDays(-30) -AND $null -ne $_.LastLogon }).count
        PasswordNeverExpires = @($AllUsers | Where-Object { $_.PasswordNeverExpires -eq $true }).count        
    }

    return $UserDetails
}

# Returns Builtin Admin/Guest details of the given domain
Function Get-BuiltInUserDetails {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][pscredential]$Credential 
    )

    $PDC = (Get-ADDomain -Identity $DomainName -Credential $Credential -Server $DomainName).PDCEmulator
    $domainSID = (Get-ADDomain $DomainName -server $PDC -Credential $Credential).domainSID.Value
    $BuiltInUserSIDs = @(@("Administrator", ($domainSID + "-500")), @("Guest", ($domainSID + "-501")), @("krbtgt", ($domainSID + "-502")))

    $BuiltInUsers = @()

    ForEach ($UserSID in $BuiltInUserSIDs ) {
        $User = Get-ADUser -Server $PDC -Credential $Credential -Identity $UserSID[1] -Properties SamAccountName, WhenCreated, LastLogonTimestamp, Enabled, LastBadPasswordAttempt, PasswordLastSet | select-Object SamAccountName, WhenCreated, @{l = "Lastlogon"; e = { [DateTime]::FromFileTime($_.LastLogonTimestamp) } }, Enabled, LastBadPasswordAttempt, PasswordLastSet
    
        $BuiltInUsers += [PSCustomObject]@{
            DomainName             = $DomainName
            OriginalUserName       = $UserSID[0]
            UserName               = $user.SamAccountName
            Enabled                = $user.Enabled
            WhenCreated            = $user.WhenCreated
            LastLogonDate          = $User.LastLogon
            PasswordLastSet        = $User.PasswordLastSet
            LastBadPasswordAttempt = $User.LastBadPasswordAttempt
            IsRenamed              = $UserSID[0] -ne $user.SamAccountName
        }
    }

    return $BuiltInUsers    
}

# Return the details of Orphaned Foreign Security Principals for the given domain, be cautious as domain connectivity issues can flag false positive
Function Get-OrphanedFSP {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][pscredential]$Credential 
    )

    $orphanedFSPs = @()
    $Domain = Get-ADDomain -Identity $DomainName -Credential $Credential
    $PDC = $Domain.PDCEmulator
    $AllFSPs = Get-ADObject -Filter { ObjectClass -eq 'ForeignSecurityPrincipal' } -Server $PDC -Credential $Credential
    
    <# NT AUTHORITY\INTERACTIVE, NT AUTHORITY\Authenticated Users, NT AUTHORITY\IUSR, NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS #>
    $KnownFSPs = (("CN=S-1-5-4,CN=ForeignSecurityPrincipals," + $Domain), ("CN=S-1-5-11,CN=ForeignSecurityPrincipals," + $Domain), ("CN=S-1-5-17,CN=ForeignSecurityPrincipals," + $Domain), ("CN=S-1-5-9,CN=ForeignSecurityPrincipals," + $Domain))
        

    foreach ($FSP in $AllFSPs) {
        Try
        { $null = (New-Object System.Security.Principal.SecurityIdentifier($FSP.objectSid)).Translate([System.Security.Principal.NTAccount]) }
        Catch {         
            If (-NOT($FSp.DistinguishedName -in $KnownFSPs)) {
                $OrphanedFSPs += $FSp.DistinguishedName
            }
        }
    }

    $OrphanedFSPDetails = [PSCustomObject]@{
        DomainName   = $DomainName
        OrphanedFSPs = $OrphanedFSPs -join "`n"
    }

    return $OrphanedFSPDetails
}

# Returns the Server OS sumamry of the given domain
Function Get-DomainServerDetails {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][pscredential]$Credential 
    )

    $DomainServerDetails = @()
    $Today = Get-Date
    $InactivePeriod = 90
    $PDC = (Get-ADDomain -Identity $DomainName -Credential $Credential -Server $DomainName).PDCEmulator
    
    $Servers = Get-ADComputer -Filter { OperatingSystem -Like "*Server*" } -Properties OperatingSystem, PasswordLastSet -Server $PDC -Credential $Credential
    $OSs = $Servers | Group-Object OperatingSystem | Select-Object Name, Count

    ForEach ($OS in $OSs) {
        $DomainServerDetails += [PSCustomObject]@{
            DomainName     = $DomainName
            OSName         = $OS.Name
            Count          = $OS.count
            StaleCount_90d = ($Servers | Where-Object { $_.OperatingSystem -eq $OS.Name -AND $_.PasswordLastSet -lt $Today.AddDays( - ($InactivePeriod)) }).Name.Count
        }        
    }
    return $DomainServerDetails
}

# Returns the Client OS sumamry of the given domain
Function Get-DomainClientDetails {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][pscredential]$Credential 
    )

    $DomainClientDetails = @()
    $Today = Get-Date
    $InactivePeriod = 90
    $PDC = (Get-ADDomain -Identity $DomainName -Credential $Credential -Server $DomainName).PDCEmulator

    $Workstations = Get-ADComputer -Filter { OperatingSystem -Notlike "*Server*" } -Properties OperatingSystem, PasswordLastSet -Server $PDC -Credential $Credential
    $OSs = $Workstations | Group-Object OperatingSystem | Select-Object Name, Count

    If ($OSs.count -gt 0) {
        ForEach ($OS in $OSs) {
            $DomainClientDetails += [PSCustomObject]@{
                DomainName     = $DomainName
                OSName         = $OS.Name
                Count          = $OS.count
                StaleCount_90d = ($Workstations | Where-Object { $_.OperatingSystem -eq $OS.Name -AND $_.PasswordLastSet -lt $Today.AddDays( - ($InactivePeriod)) }).Name.Count
            }
        }
    }

    return $DomainClientDetails
}

# returns value of select security settings for the given domain by checking all DCs
Function Start-SecurityCheck {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][pscredential]$Credential 
    )

    $SecuritySettings = @()
    $DCs = (Get-ADDomainController -Filter * -Server $DomainName -Credential $Credential).hostname

    ForEach ($DC in $DCs) {
        $results = (
            ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $DC)).OpenSubKey('System\CurrentControlSet\Control\Lsa').GetValue('LmCompatibilityLevel'),
            ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $DC)).OpenSubKey('System\CurrentControlSet\Control\Lsa').GetValue('NoLMHash'),
            ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $DC)).OpenSubKey('System\CurrentControlSet\Control\Lsa').GetValue('RestrictAnonymous'),
            ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $DC)).OpenSubKey('System\CurrentControlSet\Services\NTDS\Parameters').GetValue('LDAPServerIntegrity'),
            ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $DC)).OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').GetValue('InactivityTimeoutSecs')
        )
        $null = ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc)).Close()
        
        $NTLM = switch ($results[0]) {
            5 { "Send NTLMv2 response only. Refuse LM & NTLM" }
            4 { "Send NTLMv2 response only. Refuse LM" }
            3 { "Send NTLMv2 response only" }
            2 { "Send NTLM response only" }
            1 { "Send LM & NTLM - use NTLMv2 session security if negotiated" }
            0 { "Send LM & NTLM responses" }
            Default {
                switch ((Get-WmiObject -Class Win32_OperatingSystem -ComputerName $DC).Caption ) {
                    { $_ -like "*2022*" -OR $_ -like "*2019*" -OR $_ -like "*2016*" -OR $_ -like "*2012 R2*" } { "Send NTLMv2 response only. Refuse LM & NTLM" }
                    Default { "Not configured, OS default assumed" }
                }
            }
        }

        $LMHash = switch ($results[1]) {
            1 { "Enabled" }
            0 { "Disabled" }
            Default { "Not configured" }
        }

        $RestrictAnnon = switch ($results[2]) {
            0 { "Disabled" }
            1 { "Enabled" }
            Default { "Not configured" }
        }

        $LDAPIntegrity = switch ($results[3]) {
            0 { "Does not requires signing" }
            1 { "Requires signing" }
            Default { "Not configured" }
        }

        $InactivityTimeout = switch ( $results[4] ) {
            { $_ -le 900 -AND $_ -ne 0 -AND $_ -ne $null } { "900 or fewer second(s), but not 0: $($_)" }
            { $_ -eq 0 } { "0 second" }
            { $_ -gt 900 } { "More than 900 seconds: $($_) seconds" }
            Default { 
                switch ((Get-WmiObject -Class Win32_OperatingSystem -ComputerName $DC).Caption ) {
                    { $_ -like "*2022*" -OR $_ -like "*2019*" -OR $_ -like "*2016*" -OR $_ -like "*2012*" } { "OS default: 900 second" }
                    Default { "Unlimited" }
                }
            }
        }

        $settings = ($NTLM, $LMHash, $RestrictAnnon, $LDAPIntegrity, $InactivityTimeout)   

        if (Test-WSMan -ComputerName $DC -ErrorAction SilentlyContinue) {
            try {
                $settings += invoke-command -ComputerName $DC -Credential $Credential -ScriptBlock { 
                    $null = secedit.exe /export /areas USER_RIGHTS /cfg "$env:TEMP\secedit.cfg"
                    $seceditContent = Get-Content "$env:TEMP\secedit.cfg" 
            
                    $LocalLogonSIDs = ((($seceditContent | Select-String "SeInteractiveLogonRight") -split "=")[1] -replace "\*", "" -replace " ", "") -split ","
                    $LocalLogonUsers = $LocalLogonSIDs | Where-Object { $_ -ne "" } | ForEach-Object { 
                        $SID = New-Object System.Security.Principal.SecurityIdentifier($_)
                        $User = $SID.Translate([System.Security.Principal.NTAccount])
                        $User.Value
                    }
                    $LocalLogonUsers -join "`n"
            
                    $RemoteLogonSIDs = ((($seceditContent | Select-String "SeRemoteInteractiveLogonRight") -split "=")[1] -replace "\*", "" -replace " ", "") -split ","
                    $RemoteLogonUsers = $RemoteLogonSIDs | Where-Object { $_ -ne "" } | ForEach-Object { 
                        $SID = New-Object System.Security.Principal.SecurityIdentifier($_)
                        $User = $SID.Translate([System.Security.Principal.NTAccount])
                        $User.Value
                    }
                    $RemoteLogonUsers -join "`n"            

                    $DenyNetworkLogonSIDs = ((($seceditContent | Select-String "SeDenyNetworkLogonRight") -split "=")[1] -replace "\*", "" -replace " ", "") -split ","
                    $DenyNetworkLogonUsers = $DenyNetworkLogonSIDs | Where-Object { $_ -ne "" } | ForEach-Object { 
                        $SID = New-Object System.Security.Principal.SecurityIdentifier($_)
                        $User = $SID.Translate([System.Security.Principal.NTAccount])
                        $User.Value
                    }
                    $DenyNetworkLogonUsers -join "`n"            

                    $DenyServiceLogonSIDs = ((($seceditContent | Select-String "SeDenyServiceLogonRight") -split "=")[1] -replace "\*", "" -replace " ", "") -split ","
                    $DenyServiceLogonUsers = $DenyServiceLogonSIDs | Where-Object { $_ -ne "" } | ForEach-Object { 
                        $SID = New-Object System.Security.Principal.SecurityIdentifier($_)
                        $User = $SID.Translate([System.Security.Principal.NTAccount])
                        $User.Value
                    }
                    $DenyServiceLogonUsers -join "`n"

                    $DenyBatchLogonSIDs = ((($seceditContent | Select-String "SeDenyBatchLogonRight") -split "=")[1] -replace "\*", "" -replace " ", "") -split ","
                    $DenyBatchLogonUsers = $DenyBatchLogonSIDs | Where-Object { $_ -ne "" } | ForEach-Object {
                        $SID = New-Object System.Security.Principal.SecurityIdentifier($_)
                        $User = $SID.Translate([System.Security.Principal.NTAccount])
                        $User.Value
                    }
                    $DenyBatchLogonUsers -join "`n"

                    $null = Remove-Item "$env:TEMP\secedit.cfg"
                }
            }
            catch {
                $settings += ("Access denied", "Access denied", "Access denied", "Access denied", "Access denied")
            }
        }
        else {
            $settings += ("Access denied", "Access denied", "Access denied", "Access denied", "Access denied")
        }

        $SecuritySettings += [PSCustomObject]@{
            DomainName                                                                      = $DomainName
            DCName                                                                          = $DC
            "Network security: LAN Manager authentication level"                            = $settings[0]
            "Network security: Do not store LAN Manager hash value on next password change" = $settings[1]
            "Network access: Allow anonymous SID/Name translation"                          = $settings[2]
            "Domain controller: LDAP server signing requirements"                           = $settings[3]
            "Interactive logon: Machine inactivity limit"                                   = $settings[4]
            "Allow logon locally on domain controllers"                                     = $settings[5]
            "Allow logon through Terminal Services on domain controllers"                   = $settings[6]
            "Deny access to this computer from the network"                                 = $settings[7]
            "Deny log on as a service"                                                      = $settings[8]
            "Deny log on as a batch job"                                                    = $settings[9]
        }
    }

    return $SecuritySettings
}

# Returns the unused scripts from Netlogon share of the given domain
function Get-UnusedNetlogonScripts {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]$DomainName,
        [Parameter(ValueFromPipeline = $true, Mandatory = $false)][pscredential]$Credential
    )

    $unusedScripts = @()
    $referencedScripts = @()
    $PDC = (Get-ADDomain -Identity $DomainName -Credential $Credential -Server $DomainName).PDCEmulator
    $netlogonPath = "\\$DomainName\netlogon"
    $scriptFiles = Get-ChildItem -Path $netlogonPath -File -Recurse | Select-Object -ExpandProperty FullName
    $scriptFiles = $scriptfiles -replace $DomainName, $DomainName.Split(".")[0] | Where-Object { $_ -ne $null } | Sort-Object -Unique
    $referencedScripts = (Get-ADuser -filter * -Server $PDC -Properties ScriptPath | Where-Object { $_.ScriptPath } | Sort-Object ScriptPath -Unique).ScriptPath
    

    if ($scriptFiles) {
        $gpos = Get-GPO -All -Domain $DomainName -Server $PDC

        foreach ($gpo in $gpos) {
            $gpoReport = Get-GPOReport -Name $gpo.DisplayName -ReportType Xml -Domain $DomainName -Server $PDC            
            
            $gpoXml = [xml]$gpoReport

            $computerScripts = $gpoXml.GPO.Computer.ExtensionData.Extension.Script | Select-Object -ExpandProperty Command
            $userScripts = $gpoXml.GPO.User.ExtensionData.Extension.Script | Select-Object -ExpandProperty Command

            $referencedScripts += $computerScripts, $userScripts
        }
        
        $referencedScripts = $referencedScripts -replace $DomainName, $DomainName.Split(".")[0] | Where-Object { $_ -ne $null } | Sort-Object -Unique

        if ($null -ne $referencedScripts ) {
            $unused = Compare-Object -ReferenceObject $scriptFiles -DifferenceObject $referencedScripts | Where-Object { $_.SideIndicator -eq '<=' } | Select-Object -ExpandProperty InputObject
        }
        else {
            $unused = $scriptFiles
        }
    }

    $unused = $unused | Where-Object { $_ -ne $null } | Sort-Object -Unique

    $unusedScripts = [PSCustomObject]@{
        DomainName    = $DomainName
        UnusedScripts = $unused -join "`n"        
    }

    return $unusedScripts
}

function Get-PotentialSvcAccount {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]$DomainName,
        [Parameter(ValueFromPipeline = $true, Mandatory = $false)][pscredential]$Credential
    )


}

# Returns the permissions on SYSVOL and NETLOGON shares of the given domain
function Get-SysvolNetlogonPermissions {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]$DomainName,
        [Parameter(ValueFromPipeline = $true, Mandatory = $false)][pscredential]$Credential
    )

    $SYSVOLPermsummary = @()
    $NETLOGONPermsummary = @()
    $SysvolNetlogonPermissions = @()
    
    $SYSVOLACLs = Get-ACL "\\$DomainName\SYSVOL"
    $NETLOGONACLs = Get-ACL "\\$DomainName\NETLOGON"

    ForEach ($SYSVOLACL in $SYSVOLACLs.Access) {
        Switch ([long]$SYSVOLACL.FileSystemRights) {
            2032127 { $AccessMask = "FullControl" }
            1179785 { $AccessMask = "Read" }
            1180063 { $AccessMask = "Read, Write" }
            1179817 { $AccessMask = "ReadAndExecute" }
            { -1610612736 } { $AccessMask = "ReadAndExecuteExtended" }                        
            1245631 { $AccessMask = "ReadAndExecute, Modify, Write" }
            1180095 { $AccessMask = "ReadAndExecute, Write" }
            268435456 { $AccessMask = "FullControl (Sub Only)" }
            { $_ -notmatch '^[0-9]+$' -AND -NOT($_ -in ("-536084480")) } { $AccessMask = $SYSVOLACL.FileSystemRights }
            default { $AccessMask = "SpecialPermissions" }
        }
        $IdentityReference = $SYSVOLACL.Identityreference.Value
        $AccessType = $AccessMask        
        $AccessControlType = $SYSVOLACL.AccessControlType       

        $SYSVOLPermsummary += ("$IdentityReference, $AccessType, $AccessControlType")        
    }

    ForEach ($NETLOGONACL in $NETLOGONACLs.Access) {        
        Switch ([long]$NETLOGONACL.FileSystemRights) {
            2032127 { $AccessMask = "FullControl" }
            1179785 { $AccessMask = "Read" }
            1180063 { $AccessMask = "Read, Write" }
            1179817 { $AccessMask = "ReadAndExecute" }
            { -1610612736 } { $AccessMask = "ReadAndExecuteExtended" }            
            1245631 { $AccessMask = "ReadAndExecute, Modify, Write" }
            1180095 { $AccessMask = "ReadAndExecute, Write" }
            268435456 { $AccessMask = "FullControl (Sub Only)" }
            { $_ -notmatch '^[0-9]+$' -AND -NOT($_ -in ("-536084480")) } { $AccessMask = $SYSVOLACL.FileSystemRights }
            default { $AccessMask = "SpecialPermissions" }
        }

        $IdentityReference = $NETLOGONACL.Identityreference.Value
        $AccessType = $AccessMask        
        $AccessControlType = $NETLOGONACL.AccessControlType       

        $NETLOGONPermsummary += ("$IdentityReference, $AccessType, $AccessControlType")
    }

    $SysvolNetlogonPermissions += [pscustomobject] @{
        DomainName       = $DomainName
        ShareName        = "SYSVOL"
        Sharepermissions = $SYSVOLPermsummary -join "`n" 
        IsInherited      = -NOT($SYSVOLACLs.AreAccessRulesProtected)
    }

    $SysvolNetlogonPermissions += [pscustomobject] @{
        DomainName       = $DomainName
        ShareName        = "NETLOGON"
        Sharepermissions = $NETLOGONPermsummary -join "`n" 
        IsInherited      = -NOT($NETLOGONACLs.AreAccessRulesProtected)
    }

    return $SysvolNetlogonPermissions
}

# Returns the inventory of the given list of computers
Function Get-SystemInfo {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]$DomainName,
        [Parameter(ValueFromPipeline = $true, Mandatory = $false)][pscredential]$Credential,
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]$Servers
    )

    $PDC = (Get-ADDomain -Identity $DomainName -Credential $Credential -Server $DomainName).PDCEmulator

    $servers = $servers | ForEach-Object { Get-ADComputer -Identity $_ -Server $PDC -properties Name, IPv4Address, OperatingSystem } | select-object Name, IPv4Address, OperatingSystem

    #Run the commands for each server in the list
    $infoObject = @()
    
    Foreach ($s in $servers) {   
        $ErrorActionPreference = "Continue" 
        try {
            $CPUInfo = Get-CimInstance Win32_Processor -ComputerName $s.Name
            $PhysicalMemory = Get-CimInstance CIM_PhysicalMemory -ComputerName $s.Name | Measure-Object -Property capacity -Sum | ForEach-Object { [Math]::Round(($_.sum / 1GB), 2) }
            $NetworkInfo = Get-CimInstance Win32_networkadapter -ComputerName $s.Name | Where-Object { $_.MACAddress -AND $_.PhysicalAdapter -eq $true }
            $DiskInfo = Get-CimInstance Win32_LogicalDisk -ComputerName $s.Name
            $SerialNumber = (Get-CimInstance Win32_BIOs -ComputerName $s.Name).SerialNumber
            $MakeInfo = Get-CimInstance Win32_ComputerSystem -ComputerName $s.Name
            $NICSpeed = (($NetworkInfo.Speed | ForEach-Object { ([Math]::Round(($_ / 1GB), 2)) }) -Join " Gbps,") + " Gbps"
            $DiskSizes = (($DiskInfo.size | ForEach-Object { ([Math]::Round(($_ / 1GB), 2)) }) -join " GB,") + " GB"
            $DiskFreeSizes = (($DiskInfo.FreeSpace | ForEach-Object { ([Math]::Round(($_ / 1GB), 2)) }) -join " GB,") + " GB"

            $infoObject += [PSCustomObject]@{
                Name            = $s.Name
                IPAddress       = $s.IPV4Address
                SerialNumber    = $SerialNumber
                Manufacturer    = $MakeInfo.Manufacturer
                Model           = $MakeInfo.Model
                OperatingSystem = $s.OperatingSystem
                Processor       = ($CPUInfo.Name -join ",")
                PhysicalCores   = ($CPUInfo.NumberOfCores -join ",")
                Logicalcores    = ($CPUInfo.NumberOfLogicalProcessors -join ",")
                PhysicalMemory  = $PhysicalMemory
                NIC_Count       = ($NetworkInfo | Measure-object).Count
                NIC_Name        = ($NetworkInfo.NetConnectionID -join ",")
                NIC_MAC         = ($NetworkInfo.MACAddress -join ",")
                NIC_Speed       = $NICSpeed
                DriveLetter     = ($DiskInfo.DeviceID -join ",")                
                DriveSize       = $DiskSizes
                DriveFreeSpace  = $DiskFreeSizes
            }
        }
        catch {
            Write-Output "Issue in data collection from $($s)"
            Continue
        }
    }

    Return $infoObject
}

# Function to send email
function New-Email () {
    [CmdletBinding()]
    param(
        [parameter(mandatory = $true)]$RecipientAddressTo,		
        [parameter(mandatory = $true)]$SenderAddress,
        [parameter(mandatory = $true)]$SMTPServer,		
        [parameter(mandatory = $true)]$Subject,
        [parameter(mandatory = $true)]$Body,
        [parameter(mandatory = $false)]$SMTPServerPort = "25",		
        [parameter(mandatory = $false)]$RecipientAddressCc,
        [parameter(mandatory = $false)][pscredential]$credential

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
            }		
            Send-MailMessage @email -UseSsl -BodyAsHtml -Credential $credential
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
            }		
            
            Send-MailMessage @email -UseSsl -BodyAsHtml -Credential $credential
        }
        Catch {
            Throw $_.exception.message 
        }
    }

}

# For showing up baloon notification
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
    
    register-objectevent $tip BalloonTipClicked BalloonClicked_event -Action { $script.Invoke() } | Out-Null
    $tip.ShowBalloonTip(50000) # Even if we set it for 1000 milliseconds, it usually follows OS minimum 10 seconds
    Start-Sleep -s 10
    
    $tip.Dispose() # Important to dispose otherwise the icon stays in notifications till reboot
    Get-EventSubscriber -SourceIdentifier "BalloonClicked_event"  -ErrorAction SilentlyContinue | Unregister-Event # In case if the Event Subscription is not disposed
}

# Returns AD health information in a tabular format for the given domain by running dcdiag against each domain controller in the given domain
function Test-ADHealth {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][pscredential]$Credential
    )    

    $Report = @()
    $dcs = Get-ADDomainController -Filter * -Server $DomainName -Credential $Credential

    #foreach domain controller
    foreach ($Dcserver in $dcs.hostname) {        
        if (Test-Connection -ComputerName $Dcserver -Count 4 -Quiet) {
            try {                
                $setping = "OK"

                # Netlogon Service Status
                $DcNetlogon = Get-Service -ComputerName $Dcserver -Name "Netlogon" -ErrorAction SilentlyContinue
                if ($DcNetlogon.Status -eq "Running") {
                    $setnetlogon = "ok"
                }
                else {
                    $setnetlogon = "$DcNetlogon.status"
                }

                #NTDS Service Status
                $dcntds = Get-Service -ComputerName $Dcserver -Name "NTDS" -ErrorAction SilentlyContinue
                if ($dcntds.Status -eq "running") {
                    $setntds = "ok"
                }
                else {
                    $setntds = "$dcntds.status"
                }

                #DNS Service Status
                $dcdns = Get-Service -ComputerName $Dcserver -Name "DNS" -ea SilentlyContinue
                if ($dcdns.Status -eq "running") {
                    $setdcdns = "ok"
                }
                else {
                    $setdcdns = "$dcdns.Status"
                }

                #Dcdiag netlogons "Checking now"
                $dcdiagnetlogon = dcdiag /test:netlogons /s:$dcserver
                if ($dcdiagnetlogon -match "passed test NetLogons")	{
                    $setdcdiagnetlogon = "ok"
                }
                else {
                    $setdcdiagnetlogon = (($dcdiagnetlogon | select-string "Error", "warning" | ForEach-Object { $_.line.trim() }) -join "`n") + "`n`nRun dcdiag /test:netlogons /s:$dcserver"
                }

                #Dcdiag services check
                $dcdiagservices = dcdiag /test:services /s:$dcserver
                if ($dcdiagservices -match "passed test services") {
                    $setdcdiagservices = "ok"
                }
                else {
                    $setdcdiagservices = (($dcdiagservices  | select-string "Error", "warning" | ForEach-Object { $_.line.trim() }) -join "`n") + "`n`nRun dcdiag /test:services /s:$dcserver"
                }

                #Dcdiag Replication Check
                $dcdiagreplications = dcdiag /test:Replications /s:$dcserver
                if ($dcdiagreplications -match "passed test Replications") {
                    $setdcdiagreplications = "ok"
                }
                else {
                    $setdcdiagreplications = (($dcdiagreplications  | select-string "Error", "warning" | ForEach-Object { $_.line.trim() }) -join "`n") + "`n`nRun dcdiag /test:Replications /s:$dcserver"
                }

                #Dcdiag FSMOCheck Check
                $dcdiagFsmoCheck = dcdiag /test:FSMOCheck /s:$dcserver
                if ($dcdiagFsmoCheck -match "passed test FsmoCheck") {
                    $setdcdiagFsmoCheck = "ok"
                }
                else {
                    $setdcdiagFsmoCheck = (($dcdiagFsmoCheck | select-string "Error", "warning" | ForEach-Object { $_.line.trim() }) -join "`n") + "`n`nRun dcdiag /test:FSMOCheck /s:$dcserver"
                }

                #Dcdiag Advertising Check
                $dcdiagAdvertising = dcdiag /test:Advertising /s:$dcserver
                if ($dcdiagAdvertising -match "passed test Advertising") {
                    $setdcdiagAdvertising = "ok"
                }
                else {
                    $setdcdiagAdvertising = (($dcdiagAdvertising | select-string "Error", "warning" | ForEach-Object { $_.line.trim() }) -join "`n") + "`n`nRun dcdiag /test:Advertising /s:$dcserver" 
                }

                $tryok = "ok"
            }
            catch {
                Write-Output $_.Exception.Message
            }

            if ($tryok -eq "ok") {
                $Report += [PSCustomObject]@{
                    DCName              = $Dcserver
                    Ping                = $setping
                    Netlogon            = $setnetlogon
                    NTDS                = $setntds
                    DNS                 = $setdcdns
                    DCDIAG_Netlogons    = $setdcdiagnetlogon
                    DCDIAG_Services     = $setdcdiagservices
                    DCDIAG_Replications = $setdcdiagreplications
                    DCDIAG_FSMOCheck    = $setdcdiagFsmoCheck
                    DCDIAG_Advertising  = $setdcdiagAdvertising
                }
                #set DC status
                $setdcstatus = "ok"
            }
        }
        else {
            $setdcstatus = "DC is down"

            $Report += [PSCustomObject]@{
                DCName              = $Dcserver
                Ping                = $setdcstatus
                Netlogon            = $setdcstatus
                NTDS                = $setdcstatus
                DNS                 = $setdcstatus
                DCDIAG_Netlogons    = $setdcstatus
                DCDIAG_Services     = $setdcstatus
                DCDIAG_Replications = $setdcstatus
                DCDIAG_FSMOCheck    = $setdcstatus
                DCDIAG_Advertising  = $setdcstatus
            }            
        }
    }

    Return $Report 
}

# The main function to perform assessment of AD Forest and produce results as html file
Function Get-ADForestDetails {
    [CmdletBinding()]
    Param(        
        [Parameter(ValueFromPipeline = $true, mandatory = $false)]$Logo = $logopath,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)]$ReportPath = $ReportPath1,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)]$CSSHeader = $header,
        [Parameter(ValueFromPipeline = $true, mandatory = $true)][pscredential]$Credential,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)]$ChildDomain
    )    

    # Collecting information about current Forest configuration
    $ForestInfo = Get-ADForest -Current LocalComputer -Credential $Credential
    $forest = $ForestInfo.RootDomain
    $allDomains = $ForestInfo.Domains
    $ForestGC = $ForestInfo.GlobalCatalogs    
    $forestFL = $ForestInfo.ForestMode
    $FSMODomainNaming = $ForestInfo.DomainNamingMaster
    $FSMOSchema = $ForestInfo.SchemaMaster
    $forestDomainSID = (Get-ADDomain $forest -Server $forest -Credential $Credential).domainSID.Value    

    $SchemaPartition = $ForestInfo.PartitionsContainer.Replace("CN=Partitions", "CN=Schema")
    $SchemaVersion = Get-ADObject -Server $forest -Identity $SchemaPartition -Credential $Credential -Properties * | Select-Object objectVersion

    <#     $forestDN = $ForestInfo.PartitionsContainer.Replace("CN=Partitions,CN=Configuration,", "") #>
    $configPartition = $ForestInfo.PartitionsContainer.Replace("CN=Partitions,", "")

    # Check if AD Recycle Bin support is enabled
    if ( $forestFL -in ("Windows2008R2Forest", "Windows2012Forest", "Windows2012R2Forest", "Windows2016Forest")) {
        $ADR = (Get-ADOptionalFeature 'Recycle Bin Feature' -Server $forest -Credential $Credential).EnabledScopes.count
        if ( $ADR.Count -ne 0 ) {		
            $ADRSupport = "Enabled"		
        }		
        else {		
            $ADRSupport = "Disabled"		
        }
    }

    switch ($SchemaVersion.objectVersion) {
        13 { $ForestSchemaVersion = "Windows 2000 Server" }
        30 { $ForestSchemaVersion = "Windows Server 2003" }
        31 { $ForestSchemaVersion = "Windows Server 2003 R2" }
        44 { $ForestSchemaVersion = "Windows Server 2008" }
        47 { $ForestSchemaVersion = "Windows Server 2008 R2" }
        51 { $ForestSchemaVersion = "Windows Server 8 Developers Preview" }
        52 { $ForestSchemaVersion = "Windows Server 8 Beta" }
        56 { $ForestSchemaVersion = "Windows Server 2012" }
        69 { $ForestSchemaVersion = "Windows Server 2012 R2" }
        87 { $ForestSchemaVersion = "Windows Server 2016" }
        88 { $ForestSchemaVersion = "Windows Server 2019/2022" }
        default { $ForestSchemaVersion = "unknown forest schema version: ($SchemaVersion.objectVersion)" }
    }

    switch ($forestFL) {
        Windows2000Forest { $ForestFunctionalLevel = "Windows 2000" }
        Windows2003Forest { $ForestFunctionalLevel = "Windows Server 2003" }
        Windows2008Forest { $ForestFunctionalLevel = "Windows Server 2008" }
        Windows2008R2Forest { $ForestFunctionalLevel = "Windows Server 2008 R2" }
        Windows2012Forest { $ForestFunctionalLevel = "Windows Server 2012" }
        Windows2012R2Forest { $ForestFunctionalLevel = "Windows Server 2012 R2" }
        Windows2016Forest { $ForestFunctionalLevel = "Windows Server 2016" }
        default { $ForestFunctionalLevel = "Unknown Forest Functional Level: $forestFL" }
    }

    $tombstoneLifetime = (Get-ADobject -Server $forest -Identity "cn=Directory Service,cn=Windows NT,cn=Services,$configPartition" -Credential $Credential -Properties tombstoneLifetime).tombstoneLifetime

    if ($null -eq $tombstoneLifetime) {
        $tombstoneLifetime = 60
    }    

    $ForestDetails = [PSCustomObject]@{
        ForestName            = $forest
        ForestFunctionalLevel = $ForestFunctionalLevel
        ForestSchemaVersion   = $ForestSchemaVersion
        DomainNamingMaster    = $FSMODomainNaming
        SchemaMaster          = $FSMOSchema
        GlobalCatalogs        = $ForestGC.count
        DomainCount           = $allDomains.count
        RecycleBinSupport     = $ADRSupport
        TombstoneLifeTime     = $tombstoneLifetime
    }

    $ForestSummary = ($ForestDetails | ConvertTo-Html -As List -Property ForestName, ForestFunctionLevel, ForestSchemaVersion, DomainNamingMaster, SchemaMaster, GlobalCatalogs, DomainCount, RecycleBinSupport, TombstoneLifetime -Fragment -PreContent "<h2>Forest Summary: $forest</h2>")

    $entGroupID = $forestDomainSID + "-519"
    $enterpriseAdminsNo = @(Get-ADGroup -Server $forest -Identity $entGroupID -Credential $Credential | Get-ADGroupMember -Recursive).count

    $schemaGroupID = $forestDomainSID + "-518"
    $schmaAdminsNo = @(Get-ADGroup -Server $forest -Identity $schemaGroupID -Credential $Credential | Get-ADGroupMember -Recursive).count

    $ForestPrivGroups = [PSCustomObject]@{
        ForestName             = $forest
        EnterpriseAdminGroup   = (Get-ADGroup -Server $forest -Identity $entGroupID -Credential $Credential).Name
        EntAdminMemberCount    = $enterpriseAdminsNo
        SchemaAdminGroup       = (Get-ADGroup -Server $forest -Identity $schemaGroupID -Credential $Credential).Name
        SchemaAdminMemberCount = $schmaAdminsNo
    }

    $ForestPrivGroupsSummary = ($ForestPrivGroups | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Forest-wide Priviledged groups Summary</h2>") -replace "`n", "<br>"
    
    # PKI details to be picked from schema only if the script is being run from the forest level
    if ($forestcheck) {
        $PKIDetails = Get-PKIDetails -ForestName $forest -Credential $Credential
    }

    # Setting up variables, which would collect the information from all the domains
    $TrustDetails = @()
    $DomainDetails = @()    
    $SiteDetails = @()
    $privGroupDetails = @()
    $UserDetails = @()
    $BuiltInUserDetails = @()
    $GroupDetails = @()
    $UndesiredAdminCount = @()
    $PasswordPolicyDetails = @()
    $FGPwdPolicyDetails = @()
    $ObjectsToClean = @()
    $OrphanedFSPDetails = @()
    $ServerOSDetails = @()
    $ClientOSDetails = @()    
    $ADFSDetails = @()    
    $ADSyncDetails = @()
    $DNSServerDetails = @()
    $DNSZoneDetails = @()
    $EmptyOUDetails = @()
    $GPOSummaryDetails = @()
    $GPODetails = @()
    $SecuritySettings = @()
    $unusedScripts = @()
    $SysvolNetlogonPermissions = @()
    $DCInventory = @()
    $ADHealth = @()

    if (!($forestcheck)) {
        $allDomains = $ChildDomain
    }

    New-BaloonNotification -title "Information" -message "Summary details about forest: $forest done."

    # This section collects information from all domains
    ForEach ($domain in $allDomains) {
        New-BaloonNotification -title Information -message "Working over domain: $Domain related details."
        $TrustDetails += Get-ADTrustDetails -DomainName $domain -credential $Credential
        $DomainDetails += Get-ADDomainDetails -DomainName $domain -credential $Credential
        New-BaloonNotification -title "Information" -message "Working over domain: $Domain Health checks"
        $ADHealth += Test-ADHealth -DomainName $domain -Credential $Credential
        New-BaloonNotification -title "Information" -message "The domain: $Domain Health checks done"
        New-BaloonNotification -title Information -message "Working over domain: $Domain DC inventory related details."
        $DCInventory += Get-SystemInfo -DomainName $domain -Credential $Credential -server ($DomainDetails | Where-Object { $_.Domain -eq $domain }).DCName
        New-BaloonNotification -title Information -message "The domain: $Domain DC inventory related details collected."
        $SiteDetails += Get-ADSiteDetails -DomainName $domain -credential $Credential
        $privGroupDetails += Get-PrivGroupDetails -DomainName $domain -credential $Credential
        New-BaloonNotification -title Information -message "Working over domain: $Domain user summary related details."
        $UserDetails += Get-ADUserDetails -DomainName $domain -credential $Credential
        $BuiltInUserDetails += Get-BuiltInUserDetails -DomainName $domain -credential $Credential
        New-BaloonNotification -title Information -message "Working over domain: $Domain Group summary related details."
        $GroupDetails += Get-ADGroupDetails -DomainName $domain -credential $Credential
        $UndesiredAdminCount += Get-AdminCountDetails -DomainName $domain -credential $Credential
        $PasswordPolicyDetails += Get-ADPasswordPolicy -DomainName $domain -credential $Credential
        $FGPwdPolicyDetails += Get-FineGrainedPasswordPolicy -DomainName $domain -credential $Credential
        New-BaloonNotification -title Information -message "Working over domain: $Domain orpahed/lingering objects related details."
        $ObjectsToClean += Get-ADObjectsToClean -DomainName $domain -credential $Credential
        $OrphanedFSPDetails += Get-OrphanedFSP -DomainName $domain -credential $Credential
        $ServerOSDetails += Get-DomainServerDetails -DomainName $domain -credential $Credential
        $ClientOSDetails += Get-DomainClientDetails -DomainName $domain -credential $Credential
        New-BaloonNotification -title "Caution" -message "Looking for ADFS/ ADSync server in domain: $Domain. It might take long time" -icon Warning
        $ADSyncDetail, $ADFSDetail = Get-ADFSDetails -DomainName $domain -credential $Credential
        $ADFSDetail = $ADFSDetail | Sort-Object * -Unique
        $ADFSDetails += $ADFSDetail
        $ADSyncDetail = $ADSyncDetail | Sort-Object * -Unique
        $ADSyncDetails += $ADSyncDetail
        New-BaloonNotification -title "Information" -message "Lookup for ADFS/ ADSync server in domain: $Domain done."
        $DNSServerDetails += Get-ADDNSDetails -DomainName $domain -credential $Credential
        $DNSZoneDetails += Get-ADDNSZoneDetails -DomainName $domain -credential $Credential
        New-BaloonNotification -title "Information" -message "Looking for empty OUs in domain: $Domain ."
        $EmptyOUDetails += Get-EmptyOUDetails -DomainName $domain -credential $Credential
        $GPOSummaryDetails += Get-ADGPOSummary -DomainName $domain -credential $Credential
        New-BaloonNotification -title "Information" -message "Working over domain: $Domain GPO related details."
        $GPODetails += Get-GPOInventory -DomainName $domain
        $SysvolNetlogonPermissions += Get-SysvolNetlogonPermissions -DomainName $domain -Credential $Credential 
        New-BaloonNotification -title "Information" -message "Working over domain: $Domain security setting."
        $SecuritySettings += Start-SecurityCheck -DomainName $domain -Credential $Credential
        $unusedScripts += Get-UnusedNetlogonScripts -DomainName $domain -Credential $Credential        
    }    

    # This scetion prepares HTML report
    If ($TrustDetails) {
        $TrustSummary = ($TrustDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>AD Trust Summary</h2>")
    }    
    
    If ($DHCPFlag) {
        New-BaloonNotification -title "Caution" -message "Looking for all DHCP servesr in forest: $forest and their scope details. It might take long time" -icon Warning
        $DHCPDetails = Get-ADDHCPDetails -Credential $Credential
        $DHCPInventory = Get-DHCPInventory
        $DHCPSummary = ($DHCPDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>DHCP Server Summary</h2>") -replace "`n", "<br>"
        $DHCPInventorySummary = ($DHCPInventory.Inventory | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>DHCP Server Inventory</h2>") -replace "`n", "<br>" -replace '<td>Inactive</td>', '<td bgcolor="red">Inactive</td>'
        $DHCPResInventory = ($DHCPInventory.reservation | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>DHCP Server Reservation Inventory</h2>") -replace "`n", "<br>"

        New-BaloonNotification -title "Information" -message "DHCP Server information in forest: $forest collected"
    }
    
    #If ($PKIDetails) {
    $PKISummary = ($PKIDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Certificate servers Summary</h2>") -replace '<td>SHA1RSA</td>', '<td bgcolor="red">SHA1RSA</td>'
    #}
    
    #If ($ADSyncDetails) {
    $ADSyncSummary = ($ADSyncDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>ADSync servers Summary</h2>") -replace '<td>Access denied</td>', '<td bgcolor="red">Access denied</td>'
    #}
    
    #If ($ADFSDetails) {
    $ADFSSummary = ($ADFSDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>ADFS servers Summary</h2>") -replace '<td>Access denied</td>', '<td bgcolor="red">Access denied</td>'
    #}    
    
    If ($ClientOSDetails) {        
        $ClientOSSummary = $ClientOSDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Client OS Summary</h2>"
    }
    If ($FGPwdPolicyDetails) {
        $FGPwdPolicySummary = ($FGPwdPolicyDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Fine Grained Password Policy Summary</h2>") -replace "`n", "<br>"
    }
    If ($UndesiredAdminCount) {
        $UndesiredAdminCountSummary = ($UndesiredAdminCount | ConvertTo-Html -As Table  -Fragment -PreContent "<h2> Undesired AdminCount atribute user Summary</h2>") -replace "`n", "<br>"
    }
    If ($ObjectsToClean) {
        $ObjectsToCleanSummary = ($ObjectsToClean | ConvertTo-Html -As Table  -Fragment -PreContent "<h2> Orphaned and Lingering objects Summary</h2>") -replace "`n", "<br>"
    }

    If ($OrphanedFSPDetails) {
        $OrphanedFSPSummary = ($OrphanedFSPDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2> Orphaned foreign security principals Summary</h2>") -replace "`n", "<br>"
    }
    If ($unusedScripts) {
        $unusedScriptsSummary = ($unusedScripts | ConvertTo-Html -As Table  -Fragment -PreContent "<h2> Unused Netlogon Scripts summary </h2>") -replace "`n", "<br>"
    }

    $DomainSummary = ($DomainDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Domains Summary</h2>") -replace '<td>Reg not found</td>', '<td bgcolor="red">Reg not found</td>'
    $DomainHealthSumamry = ($ADHealth | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Domain Controller health Summary</h2>") -replace "`n", "<br>" -replace '<td>DC Down</td>', '<td bgcolor="red">DC Down</td>'
    $DNSSummary = ($DNSServerDetails  | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>DNS Servers Summary</h2>") -replace "`n", "<br>"
    $DNSZoneSummary = ($DNSZoneDetails  | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>DNS Zones Summary</h2>") -replace "`n", "<br>"
    $SitesSummary = ($SiteDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>AD Sites Summary</h2>" ) -replace "`n", "<br>" -replace '<td>No DC in Site</td>', '<td bgcolor="red">No DC in Site</td>'
    $BuiltInUserSummary = $BuiltInUserDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>BuiltInUsers Summary</h2>"
    $UserSummary = $UserDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Users Summary</h2>"    
    $GroupSummary = ($GroupDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Groups Summary</h2>") -replace "`n", "<br>"
    $PrivGroupSummary = ($privGroupDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Priviledged groups Summary</h2>") -replace '<td>True</td>', '<td bgcolor="red">True</td>'
    $PwdPolicySummary = $PasswordPolicyDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Password Policy Summary</h2>"
    $ServerOSSummary = $ServerOSDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Server OS Summary</h2>"
    $EmptyOUSummary = ($EmptyOUDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Empty OU Summary</h2>") -replace "`n", "<br>"
    $GPOSummary = ($GPOSummaryDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Unlinked GPO Summary</h2>") -replace "`n", "<br>"
    $GPOInventory = ($GPODetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Unlinked GPO Summary</h2>") -replace "`n", "<br>"
    $SysvolNetlogonPermSummary = ($SysvolNetlogonPermissions | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Sysvol and Netlogon Permissions Summary</h2>") -replace "`n", "<br>"
    $SecuritySummary = ($SecuritySettings | ConvertTo-Html -As List  -Fragment -PreContent "<h2>Domains Security Settings Summary</h2>") -replace "`n", "<br>" -replace '<td>Access denied</td>', '<td bgcolor="red">Access denied</td>'
    $DCSummary = ($DCInventory | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Sysvol and Netlogon Permissions Summary</h2>") -replace "`n", "<br>"

    New-BaloonNotification -title "Information" -message "Forest $forest details collected now, preparing html report"

    $ReportRaw = ConvertTo-HTML -Body "$ForestSummary $ForestPrivGroupsSummary $TrustSummary $PKISummary $ADSyncSummary $ADFSSummary $DHCPSummary $DomainSummary $DomainHealthSumamry $DNSSummary $DNSZoneSummary $SitesSummary $PrivGroupSummary $UserSummary $BuiltInUserSummary $GroupSummary $UndesiredAdminCountSummary $PwdPolicySummary $FGPwdPolicySummary $ObjectsToCleanSummary $OrphanedFSPSummary $unusedScriptsSummary $ServerOSSummary $ClientOSSummary $EmptyOUSummary $GPOSummary $GPOInventory $SysvolNetlogonPermSummary $SecuritySummary $DHCPInventorySummary $DHCPResInventory $DCSummary" -Head $header -Title "Report on AD Forest: $forest" -PostContent "<p id='CreationDate'>Creation Date: $(Get-Date) $CopyRightInfo </p>"
    $ReportRaw | Out-File $ReportPath
}

# Menu
Clear-Host 
Write-Output "Menu:" 
"Option 1: Run script over entire forest" 
"Option 2: Run script over single domain" 
"Option 3: Press any other key to Quit`n"

$choice = Read-Host "Enter your choice: "

switch ($choice) {
    '1' {
        Write-Output "Type Forest Enterprise Admin credentials:"
        $forestcheck = $true
        Get-ADForestDetails -Credential (Get-Credential)        
    }   
    '2' {
        $Response = Read-host "Type the domain name or just press ENTER to select current domain :"
        if ($Response) {
            $DomainName = $response -replace " ", ""
        }
        else {
            $DomainName = (Get-ADDomain -Current LocalComputer).DNSRoot
        }
        Write-Output "Type Domain Admin credentials for $DomainName :"
        [pscredential]$DomainCred = (Get-Credential)
        $forestcheck = $false
        Get-ADForestDetails -Credential $DomainCred -ChildDomain $DomainName
    }
    default {
        Write-Output "Incorrect reponse, script terminated"
        Start-Sleep 2
        exit
    }
}

<# $MailCredential = Get-Credential -Message "Enter the password for the email account: " -UserName "contactfor_nitish@hotmail.com"

$body = Get-Content $ReportPath1 -Raw
New-Email -RecipientAddressTo "nitish@nitishkumar.net" -SenderAddress "contactfor_nitish@hotmail.com" -SMTPServer "smtp.office365.com" -SMTPServerPort 587 -Subject "AD Assessment Report $(get-date -Uformat "%Y%m%d-%H%M%S")" -Body $body -credential $MailCredential #>