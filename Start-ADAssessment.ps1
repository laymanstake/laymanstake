#Requires -RunAsAdministrator
#Requires -Version 3.0
#Requires -Modules ActiveDirectory, DHCPServer, GroupPolicy, DnsServer

<#  
    Author : Nitish Kumar
    Performs Active Directory Forest Assessment
    version 1.0 | 06/06/2023 Initial version
    The script is kept as much modular as possible so that functions can be modified or added without altering the entire script 
#>

Import-Module ActiveDirectory
Import-Module DHCPServer
Import-Module GroupPolicy
Import-Module DnsServer

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
        $service = Invoke-Command -ComputerName $computer -ScriptBlock { (Get-Service -Name "adfssrv" -ErrorAction SilentlyContinue).Name ; (Get-Service -Name "adsync" -ErrorAction SilentlyContinue).Name }  -Credential $Credential
        if ($service[0] -eq "adfssrv") {
            $adfsServers += $computer
        }
        if ($service[1] -eq "adsync" ) {
            $aadconnectServers += $computer
        }
    }

    foreach ($server in $adfsServers) {        
        $ADFSproperties = invoke-command -ComputerName $server -ScriptBlock { import-module ADFS; Get-ADFSSyncProperties; (Get-ADFSProperties).Identifier } -Credential $Credential
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
        $ADSyncVersion = invoke-command -ComputerName $server -Credential $Credential -ScriptBlock { (Get-Item (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Azure AD Connect").WizardPath).VersionInfo.FileVersion; (Get-Service -Name ADSYnc).Status -eq "Running" }        
        
        $Info = [PSCustomObject]@{
            ServerName      = $server
            OperatingSystem = (Get-ADComputer $server -server $PDC -Credential $Credential -properties OperatingSystem).OperatingSystem            
            ADSyncVersion   = $ADSyncVersion[0]
            IsActive        = $ADSyncVersion[1]
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
        $cert = invoke-command -ComputerName $PKI.DnsHostName -Credential $Credential -ScriptBlock { Get-ChildItem -Path cert:\LocalMachine\my | Where-Object { $_.issuer -eq $_.Subject } }    
        $PKIDetails = $PKI
        Add-Member -inputObject $PKIDetails -memberType NoteProperty -name "SecureHashAlgo" -value $cert.SignatureAlgorithm.FriendlyName
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
    
    $configPartition = (Get-ADforest).PartitionsContainer.Replace("CN=Partitions,", "")
    $AllDHCPServers = (Get-ADObject -SearchBase $configPartition -Filter "objectclass -eq 'dhcpclass' -AND Name -ne 'dhcproot'" -Credential $Credential).Name
    $DHCPDetails = @()

    foreach ($dhcpserver in $AllDHCPServers) {
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

            $DHCPDetails += [PSCustomObject]@{
                ServerName         = $dhcpserver
                IPAddress          = ([System.Net.Dns]::GetHostAddresses($dhcpserver) | Where-Object { $_.AddressFamily -eq "InterNetwork" }).IPAddressToString -join "`n"
                OperatingSystem    = (Get-CimInstance win32_operatingSystem -ComputerName $dhcpserver -Property Caption).Caption
                ScopeCount         = $Allscopes.count
                InactiveScopeCount = $InactiveScopes.count
                ScopeWithNoLease   = $NoLeaseScopes -join "`n"
                NoLeaseScopeCount  = $NoLeaseScopes.count
                IsVirtual          = ((Get-CimInstance Win32_ComputerSystem -ComputerName $dhcpserver).model).Contains("Virtual")
            }
        }
        catch {}
    }
    
    return $DHCPDetails
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
Function Get-ADGPODetails {
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

    $UndesiredFeatures = ("ADFS-Federation", "DHCP", "Telnet-Client", "WDS", "Web-Server", "Web-Application-Proxy")

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
        $FSR2DFSRStatus = invoke-command -ComputerName $PDC -ScriptBlock { ((dfsrmig.exe /GetGlobalState )[0].replace("'", "") -split ": ")[1] } -Credential $Credential
    }
    catch {
        $FSR2DFSRStatus = "WinRM access denied on PDC"
    }

    foreach ($dc in $dcs) {
        if ( Test-Connection -ComputerName $dc -Count 1 -ErrorAction SilentlyContinue ) { 
            $Results = invoke-command -ComputerName $dc -ScriptBlock { 
                (Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol), 
                (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\'), 
                ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name Enabled -ErrorAction SilentlyContinue).Enabled -eq 1 -and (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name DisabledByDefault -ErrorAction SilentlyContinue).DisabledByDefault -eq 0),
                ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name Enabled -ErrorAction SilentlyContinue).Enabled -eq 1 -and (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name DisabledByDefault -ErrorAction SilentlyContinue).DisabledByDefault -eq 0),
                ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name Enabled -ErrorAction SilentlyContinue).Enabled -eq 1 -and (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name DisabledByDefault -ErrorAction SilentlyContinue).DisabledByDefault -eq 0),
                ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name Enabled -ErrorAction SilentlyContinue).Enabled -eq 1 -and (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name DisabledByDefault -ErrorAction SilentlyContinue).DisabledByDefault -eq 0),
                ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name Enabled -ErrorAction SilentlyContinue).Enabled -eq 1 -and (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name DisabledByDefault -ErrorAction SilentlyContinue).DisabledByDefault -eq 0),
                ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name Enabled -ErrorAction SilentlyContinue).Enabled -eq 1 -and (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name DisabledByDefault -ErrorAction SilentlyContinue).DisabledByDefault -eq 0),
                (w32tm /query /source)
            }  -Credential $Credential

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
                NTPServer                   = ($Results[8] | Select-Object -Unique) -join "`n"
                ADWSStatus                  = (Get-Service ADWS -computername $dc.Name  -ErrorAction SilentlyContinue ).StartType
                SMB1Status                  = ($Results[0]).EnableSMB1Protocol
                SSL2Client                  = $Results[2]
                SSL2Server                  = $Results[3]
                TLS1Client                  = $Results[4]
                TLS1Server                  = $Results[5]
                TLS11Client                 = $Results[6]
                TLS11Server                 = $Results[7]
                Firewall                    = (Get-Service -name MpsSvc -ComputerName $dc).Status
                NetlogonParameter           = ($Results[1]).vulnerablechannelallowlist
                ReadOnly                    = $dc.IsReadOnly
                IsVirtual                   = ((Get-CimInstance Win32_ComputerSystem -ComputerName $dc).model).Contains("Virtual")
                UndesiredFeatures           = Compare-Object -ReferenceObject $UndesiredFeatures -DifferenceObject  (Get-WindowsFeature -ComputerName $dc  -Credential $Credential | Where-Object Installed).Name -IncludeEqual | Where-Object { $_.SideIndicator -eq '==' } | Select-Object -ExpandProperty InputObject
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

    $AllGroups = Get-ADGroup -Filter { GroupCategory -eq "Security" } -Properties GroupScope, Members -Server $PDC -Credential $Credential
    $GroupScopes = $AllGroups | Group-Object GroupScope

    ForEach ($GroupScope in $GroupScopes) {
        $EmptyGroups = ($GroupScope.Group | Where-Object { Get-ADGroup $_.DistinguishedName -Properties Members -Server $PDC | Where-Object { -not $_.members } })

        $GroupDetails += [PSCustomObject]@{
            DomainName      = $DomainName
            GroupType       = $GroupScope.Name
            GroupCount      = $GroupScope.Count
            EmptyGroups     = $EmptyGroups.Name -join "`n"
            EmptyGroupCount = $EmptyGroups.count
        }
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

    $AllUsers = Get-ADUser -Filter * -Server $PDC -Credential $Credential -Properties SamAccountName, Enabled, whenCreated, PasswordLastSet, PasswordExpired, PasswordNeverExpires, PasswordNotRequired, AccountExpirationDate, LastLogonDate, LockedOut

    $UserDetails = [PSCustomObject]@{
        DomainName           = $DomainName
        Users                = $AllUsers.count
        RecentlyCreated      = @($AllUsers | Where-Object { $_.whenCreated -ge (Get-Date).AddDays(-30) }).count
        ChangeOnNextLogon    = @($AllUsers | Where-Object { ($null -eq $_.PasswordLastSet) -and ($_.PasswordNotRequired -eq $false) }).count
        PasswordExpired      = @($AllUsers | Where-Object { $_.PasswordExpired -eq $true }).count
        Disabled             = @($AllUsers | Where-Object { $_.Enabled -eq $false }).count
        LockedOut            = @($AllUsers | Where-Object { $_.LockedOut -eq $true }).count        
        AccountExpired       = @($AllUsers | Where-Object { $_.AccountExpirationDate -lt (Get-Date) -AND $null -ne $_.AccountExpirationDate }).count
        Inactive             = @($AllUsers | Where-Object { $_.LastLogonDate -lt (Get-Date).AddDays(-30) -AND $null -ne $_.LastLogonDate }).count
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
        $User = Get-ADUser -Server $PDC -Credential $Credential -Identity $UserSID[1] -Properties SamAccountName, WhenCreated, LastLogonDate, Enabled, LastBadPasswordAttempt, PasswordLastSet
    
        $BuiltInUsers += [PSCustomObject]@{
            DomainName             = $DomainName
            OriginalUserName       = $UserSID[0]
            UserName               = $user.SamAccountName
            Enabled                = $user.Enabled
            WhenCreated            = $user.WhenCreated
            LastLogonDate          = $User.LastLogonDate
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

Function Start-SecurityCheck {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][pscredential]$Credential 
    )

    $SecuritySettings = @()
    $DCs = (Get-ADDomainController -Filter * -Server $DomainName -Credential $Credential).hostname

    ForEach ($DC in $DCs) {
        $settings = invoke-command -ComputerName $DC -Credential $Credential -ScriptBlock { 
            switch ((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue | Select-Object LmCompatibilityLevel).LmCompatibilityLevel) {
                5 { "Send NTLMv2 response only. Refuse LM & NTLM" }
                4 { "Send NTLMv2 response only. Refuse LM" }
                3 { "Send NTLMv2 response only" }
                2 { "Send NTLM response only" }
                1 { "Send LM & NTLM - use NTLMv2 session security if negotiated" }
                0 { "Send LM & NTLM responses" }
                Default {
                    switch ((Get-WmiObject -Class Win32_OperatingSystem).Caption ) {
                        { $_ -like "*2022*" -OR $_ -like "*2019*" -OR $_ -like "*2016*" -OR $_ -like "*2012 R2*" } { "Send NTLMv2 response only. Refuse LM & NTLM" }
                        Default { "Not configured, OS default assumed" }
                    }
                }
            }

            switch (Get-ItemPropertyValue -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "NoLMHash") {
                1 { "Enabled" }
                0 { "Disabled" }
                Default { "Not configured" }
            }

            switch (Get-ItemPropertyValue -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous") {
                0 { "Disabled" }
                1 { "Enabled" }
                Default { "Not configured" }
            }

            switch (Get-ItemPropertyValue -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity") {
                0 { "Does not requires signing" }
                1 { "Requires signing" }
                Default { "Not configured" }
            }

            switch ( (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -ErrorAction SilentlyContinue).InactivityTimeoutSecs ) {
                { $_ -le 900 -AND $_ -ne 0 } { "900 or fewer second(s), but not 0: $($_)" }
                { $_ -eq 0 } { "0 second" }
                { $_ -gt 900 } { "More than 900 seconds: $($_)" }
                Default { "Policy not configured" }
            }
            
        }

        $SecuritySettings += [PSCustomObject]@{
            DomainName                                                                      = $DomainName
            DCName                                                                          = $DC
            "Network security: LAN Manager authentication level"                            = $settings[0]
            "Network security: Do not store LAN Manager hash value on next password change" = $settings[1]
            "Network access: Allow anonymous SID/Name translation"                          = $settings[2]
            "Domain controller: LDAP server signing requirements"                           = $settings[3]
            "Interactive logon: Machine inactivity limit"                                   = $settings[4]
        }
    }

    return $SecuritySettings
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
    if ($forestcheck) {
        $PKIDetails = Get-PKIDetails -ForestName $forest -Credential $Credential
    }

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
    $GPODetails = @()
    $SecuritySettings = @()

    if (!($forestcheck)) {
        $allDomains = $ChildDomain
    }

    ForEach ($domain in $allDomains) {        
        $TrustDetails += Get-ADTrustDetails -DomainName $domain -credential $Credential
        $DomainDetails += Get-ADDomainDetails -DomainName $domain -credential $Credential
        $SiteDetails += Get-ADSiteDetails -DomainName $domain -credential $Credential
        $privGroupDetails += Get-PrivGroupDetails -DomainName $domain -credential $Credential
        $UserDetails += Get-ADUserDetails -DomainName $domain -credential $Credential
        $BuiltInUserDetails += Get-BuiltInUserDetails -DomainName $domain -credential $Credential
        $GroupDetails += Get-ADGroupDetails -DomainName $domain -credential $Credential
        $UndesiredAdminCount += Get-AdminCountDetails -DomainName $domain -credential $Credential
        $PasswordPolicyDetails += Get-ADPasswordPolicy -DomainName $domain -credential $Credential
        $FGPwdPolicyDetails += Get-FineGrainedPasswordPolicy -DomainName $domain -credential $Credential
        $ObjectsToClean += Get-ADObjectsToClean -DomainName $domain -credential $Credential
        $OrphanedFSPDetails += Get-OrphanedFSP -DomainName $domain -credential $Credential
        $ServerOSDetails += Get-DomainServerDetails -DomainName $domain -credential $Credential
        $ClientOSDetails += Get-DomainClientDetails -DomainName $domain -credential $Credential
        $ADSyncDetail, $ADFSDetail = Get-ADFSDetails -DomainName $domain -credential $Credential
        $ADFSDetail = $ADFSDetail | Sort-Object * -Unique
        $ADFSDetails += $ADFSDetail
        $ADSyncDetail = $ADSyncDetail | Sort-Object * -Unique
        $ADSyncDetails += $ADSyncDetail        
        $DNSServerDetails += Get-ADDNSDetails -DomainName $domain -credential $Credential
        $DNSZoneDetails += Get-ADDNSZoneDetails -DomainName $domain -credential $Credential
        $EmptyOUDetails += Get-EmptyOUDetails -DomainName $domain -credential $Credential
        $GPODetails += Get-ADGPODetails -DomainName $domain -credential $Credential
        $SecuritySettings += Start-SecurityCheck -DomainName $domain -Credential $Credential
    }

    If ($TrustDetails) {
        $TrustSummary = ($TrustDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>AD Trust Summary</h2>")
    }
    $DHCPDetails = Get-ADDHCPDetails -Credential $Credential
    If ($DHCPDetails) {
        $DHCPSummary = ($DHCPDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>DHCP Server Summary</h2>") -replace "`n", "<br>"
    }
    If ($PKIDetails) {
        $PKISummary = ($PKIDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Certificate servers Summary</h2>") -replace '<td>SHA1RSA</td>', '<td bgcolor="red">SHA1RSA</td>'
    }
    If ($ADSyncDetails) {
        $ADSyncSummary = $ADSyncDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>ADSync servers Summary</h2>"        
    }
    If ($ADFSDetails) {
        $ADFSSummary = $ADFSDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>ADFS servers Summary</h2>"            
    }    
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

    $DomainSummary = $DomainDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Domains Summary</h2>"
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
    $GPOSummary = ($GPODetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Unlinked GPO Summary</h2>") -replace "`n", "<br>"
    $SecuritySummary = $SecuritySettings | ConvertTo-Html -As List  -Fragment -PreContent "<h2>Domains Summary</h2>"

    $ReportRaw = ConvertTo-HTML -Body "$ForestSummary $ForestPrivGroupsSummary $TrustSummary $PKISummary $ADSyncSummary $ADFSSummary $DHCPSummary $DomainSummary $DNSSummary $DNSZoneSummary $SitesSummary $PrivGroupSummary $UserSummary $BuiltInUserSummary $GroupSummary $UndesiredAdminCountSummary $PwdPolicySummary $FGPwdPolicySummary $ObjectsToCleanSummary $OrphanedFSPSummary $ServerOSSummary $ClientOSSummary $EmptyOUSummary $GPOSummary $SecuritySummary" -Head $header -Title "Report on AD Forest: $forest" -PostContent "<p id='CreationDate'>Creation Date: $(Get-Date) $CopyRightInfo </p>"
    $ReportRaw | Out-File $ReportPath    
}

Clear-Host 
Write-Output "Menu:`n" +
"Option 1: Run script over entire forest`n" +
"Option 2: Run script over single domain`n" +
"Option 3: Press any other key to Quit"

$choice = Read-Host "Enter your choice: "

switch ($choice) {
    '1' {
        Write-Output "Carefully type Forest Enterprise Admin credentials:"
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
        Write-Output "Carefully type Domain Admin credentials for $DomainName :"
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