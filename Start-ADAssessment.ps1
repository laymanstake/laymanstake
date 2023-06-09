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

# Numbe of functions to get the details of the environment
# Returns the details of AD trusts in the given domain
Function Get-ADTrustDetails {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName
    )
    
    $trusts = Get-ADTrust -Filter * -Server $DomainName -Properties Created, Modified, ForestTransitive | Select-Object Name, Source, Target, Created, Modified, Direction, TrustType, Intraforest, ForestTransitive

    $TrustDetails = @()

    ForEach ($trust in $trusts) {
        $stale = $false        
        if ($trust.TrustType -eq "External" -and $trust.Direction -eq "Bidirectional") {
            try {
                $null = Get-ADDomain -Identity $trust.Target -Server $trust.Target -ErrorAction Stop
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
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName
    )

    #$PDC = (Get-ADDomain -Identity $DomainName).PDCEmulator
}

# Returns the details of the PKI servers
Function Get-PKIDetails {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName
    )

    $PDC = (Get-ADDomain -Identity $DomainName).PDCEmulator    
    $PKI = Get-ADObject -Filter { objectClass -eq "pKIEnrollmentService" } -Server $PDC -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).ConfigurationNamingContext)"  -Properties DisplayName, DnsHostName | Select-Object DisplayName, DnsHostName, @{l = "OperatingSystem"; e = { (Get-ADComputer $_.DnsHostName -Properties OperatingSystem).OperatingSystem } }, @{l = "IPv4Address"; e = { ([System.Net.Dns]::GetHostAddresses($_.DnsHostName) | Where-Object { $_.AddressFamily -eq "InterNetwork" }).IPAddressToString -join "`n" } }

    Return $PKI
}

# Returns the details of the DNS servers in the given domain
Function Get-ADDNSDetails {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName
    )

    $DNSServerDetails = @()
    $PDC = (Get-ADDomain -Identity $DomainName).PDCEmulator    
    
    $DNSServers = (Get-ADDomainController -Filter * -server $PDC) | Where-Object { (Get-WindowsFeature -ComputerName $_.name -Name DNS ) } | Select-Object Name, IPv4Address

    ForEach ($DNSServer in $DNSServers) {
        $Scavenging = Get-DnsServerScavenging -ComputerName $DNSServer.Name 
        $DNSServerDetails += [PSCustomObject]@{
            ServerName         = $DNSServer.Name
            IPAddress          = $DNSServer.IPv4Address
            OperatingSystem    = (Get-ADComputer $DNSServer.Name -Properties OperatingSystem -Server $PDC).OperatingSystem
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
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName
    )

    $DNSServerZoneDetails = @()
    $PDC = (Get-ADDomain -Identity $DomainName).PDCEmulator    
    
    $DNSZones = Get-DnsServerZone -ComputerName $PDC | Where-Object { -Not $_.IsReverseLookupZone } | Select-Object DistinguishedName, ZoneName, ZoneType, IsReadOnly, DynamicUpdate, IsSigned, IsWINSEnabled, ReplicationScope, MasterServers, SecureSecondaries, SecondaryServers

    ForEach ($DNSZone in $DNSZones) {
        If ($DNSZone.DistinguishedName) {
            $Info = (Get-DnsServerZone -zoneName $DNSZone.ZoneName -ComputerName $PDC | Where-Object { -NOT $_.IsReverseLookupZone -AND $_.ZoneType -ne "Forwarder" }).Distinguishedname | ForEach-Object { Get-ADOBject -Identity $_ -Server $PDC -Properties ProtectedFromAccidentalDeletion, Created }
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
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$GroupName
    )
    
    $Domain = (Get-ADDomain -Identity $DomainName)
    $PDC = $Domain.PDCEmulator    
    $members = (Get-ADGroup -Identity $GroupName -Server $PDC -Properties Members).members

    $membersRecursive = @()
    foreach ($member in $members) {
        If ($member.Substring($member.IndexOf("DC=")) -eq $Domain.DistinguishedName) {
            if ((Get-ADObject -identity $member -server $PDC).Objectclass -eq "group" ) { 
                $membersRecursive += Get-ADGroupMemberRecursive -GroupName $member -DomainName $Domain.DNSRoot
            }
            else {
                $membersRecursive += Get-ADUser -identity $member -Server $PDC | Select-Object Name
            }
        }
    }
    return $membersRecursive    
}

# Return the users with adminCount
Function Get-AdminCountDetails {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName
    )
    
    $PDC = (Get-ADDomain -Identity $DomainName).PDCEmulator
    $protectedGroups = (Get-ADGroup -Filter * -Server $PDC -properties adminCount | Where-Object { $_.adminCount -eq 1 }).Name

    $ProtectedUsers = ($protectedGroups | ForEach-Object { Get-ADGroupMemberRecursive -GroupName $_ -DomainName $DomainName } | Sort-Object Name -Unique).Name
    $UserWithAdminCount = (Get-ADUser -Filter * -Server $PDC -Properties AdminCount | Where-Object { $_.adminCount -eq 1 }).Name
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
    
    $configPartition = (Get-ADforest).PartitionsContainer.Replace("CN=Partitions,", "")
    $AllDHCPServers = (Get-ADObject -SearchBase $configPartition -Filter "objectclass -eq 'dhcpclass' -AND Name -ne 'dhcproot'").Name
    $DHCPDetails = @()

    foreach ($dhcpserver in $AllDHCPServers) {
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
    
    return $DHCPDetails
}

# Returns the details of empty OUs in the given domain
Function Get-EmptyOUDetails {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName
    )

    $PDC = (Get-ADDomain -Identity $DomainName).PDCEmulator

    $AllOUs = Get-ADOrganizationalUnit -Filter * -Server $PDC -Properties * 

    $EmptyOUs = ($AllOUs | Select-Object Name, CanonicalName, DistinguishedName, @{Name = 'ObjectCount'; Expression = { (Get-ADObject -Server $PDC -Filter { ObjectClass -eq 'user' -or ObjectClass -eq 'group' -or ObjectClass -eq 'computer' } -SearchBase $_.DistinguishedName).Count } } | Where-Object { $_.ObjectCount -eq 0 }).CanonicalName

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
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName
    )

    $ObjectsToClean = @()
    $Domain = Get-ADDomain -Identity $DomainName
    $PDC = $Domain.PDCEmulator
    $orphanedObj = Get-ADObject -Filter * -SearchBase "cn=LostAndFound,$($Domain.DistinguishedName)" -SearchScope OneLevel -Server $PDC    
    $lingConfReplObj = Get-ADObject -LDAPFilter "(cn=*\0ACNF:*)" -SearchBase $Domain.DistinguishedName -SearchScope SubTree -Server $PDC

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
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName
    )
    
    $AllGPOs = Get-GPO -All -Domain $DomainName
    $LinkedGPOs = @($AllGPOs | Where-Object { $_ | Get-GPOReport -ReportType XML -Domain $DomainName | Select-String -Pattern  "<LinksTo>" -SimpleMatch } | Select-Object DisplayName, CreationTime, ModificationTime )
    $UnlinkedGPOs = @($AllGPOs | Where-Object { $_ | Get-GPOReport -ReportType XML -Domain $DomainName | Select-String -NotMatch "<LinksTo>" } | Select-Object DisplayName, CreationTime, ModificationTime )
    $DeactivatedGPOs = @($AllGPOs | Where-Object { $_.GPOStatus -eq "AllSettingsDisabled" } | Select-Object DisplayName, CreationTime, ModificationTime )
    $LinkedButDeactivatedGPOs = @()

    If ($LinkedGPOs.count -ge 1 -AND $DeactivatedGPOs.Count -ge 1) {
        $LinkedButDeactivatedGPOs = (Compare-Object -ReferenceObject $DeactivatedGPOs -DifferenceObject $LinkedGPOs -IncludeEqual | Where-Object { $_.SideIndicator -eq '==' } | Select-Object InputObject).InputObject
    }

    $UnlinkedGPODetails = [PSCustomObject]@{
        Domain                      = $domainname
        AllGPOs                     = $AllGPOs.count
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
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName
    )

    $PDC = (Get-ADDomain -Identity $DomainName).PDCEmulator
    $PwdPolicy = Get-ADDefaultDomainPasswordPolicy -Server $PDC

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
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName
    )

    $FGPwdPolicyDetails = @()
    $PDC = (Get-ADDomain -Identity $DomainName).PDCEmulator
    $DomainFL = (Get-ADDomain -Identity $DomainName).DomainMode
    
    if ( $DomainFL -in ("Windows2008Domain", "Windows2008R2Domain", "Windows2012Domain", "Windows2012R2Domain", "Windows2016Domain")) {		
        $FGPwdPolicy = Get-ADFineGrainedPasswordPolicy -Filter * -Server $PDC

        ForEach ($FGPP in $FGPwdPolicy) {
            $Obj = $FGPP.AppliesTo | ForEach-Object { Get-ADObject $_ -Server $PDC | Select-Object DistinguishedName , Name, ObjectClass } 
            $Users = $Obj | Where-Object { $_.ObjectClass -eq "User" }
            $UserList = $Users | ForEach-Object { Get-ADUser -Identity $_.DistinguishedName -Server $PDC }
            $Groups = $Obj | Where-Object { $_.ObjectClass -eq "Group" }
            $GroupList = $Groups | ForEach-Object { Get-ADGroup -Identity $_.DistinguishedName -Server $PDC }
            
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
        [Parameter(ValueFromPipeline = $true, mandatory = $false)]$Logo,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)]$ReportPath,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)]$CSSHeader = $header
    )

    $UndesiredFeatures = ("ADFS-Federation", "DHCP", "Telnet-Client", "WDS", "Web-Server", "Web-Application-Proxy")

    $dcs = Get-ADDomainController -Filter * -Server $DomainName
    
    $PDC = (Get-ADDomain -Identity $DomainName).PDCEmulator

    if ((Get-ADObject -Server $PDC -SearchBase (Get-ADDomainController -Identity $PDC -Server $PDC).ComputerObjectDN -Filter { name -like "SYSVOL*" } -Properties replPropertyMetaData).ReplPropertyMetadata.count -gt 0) {
        $sysvolStatus = "DFSR"
    }
    else {
        $sysvolStatus = "FSR"
    }

    # It needs WinRM being enabled on PDC 
    try {
        $FSR2DFSRStatus = invoke-command -ComputerName $PDC -ScriptBlock { ((dfsrmig.exe /GetGlobalState )[0].replace("'", "") -split ": ")[1] }
    }
    catch {
        $FSR2DFSRStatus = "WinRM access denied on PDC"
    }

    foreach ($dc in $dcs) {
        if ( Test-Connection -ComputerName $dc -Count 1 -ErrorAction SilentlyContinue ) { 
            $Results = invoke-command -ComputerName $dc -ScriptBlock { (Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol), (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\') }

            $DomainDetails += [PSCustomObject]@{
                Domain              = $domain
                DomainFunctionLevel = (Get-ADDomain -Identity $DomainName).DomainMode
                DCName              = $dc.Name
                Site                = $dc.site
                OSVersion           = $dc.OperatingSystem
                IPAddress           = $dc.IPv4Address
                FSMORoles           = (Get-ADDomainController -Identity $dc -Server $dc | Select-Object @{l = "FSMORoles"; e = { $_.OperationMasterRoles -join ", " } }).FSMORoles
                SysvolType          = $sysvolStatus
                FSR2DFSRStatus      = $FSR2DFSRStatus
                SMB1Status          = ($Results[0]).EnableSMB1Protocol
                Firewall            = (Get-Service -name MpsSvc -ComputerName $dc).Status
                NetlogonParameter   = ($Results[1]).vulnerablechannelallowlist
                ReadOnly            = $dc.IsReadOnly
                IsVirtual           = ((Get-CimInstance Win32_ComputerSystem -ComputerName $dc).model).Contains("Virtual")
                UndesiredFeatures   = Compare-Object -ReferenceObject $UndesiredFeatures -DifferenceObject  (Get-WindowsFeature -ComputerName $dc | Where-Object Installed).Name -IncludeEqual | Where-Object { $_.SideIndicator -eq '==' } | Select-Object -ExpandProperty InputObject
            }
        }
    }

    return $DomainDetails    
}

# Returns the AD site details of the given domain
Function Get-ADSiteDetails {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName
    )

    $PDC = (Get-ADDomain -Identity $DomainName).PDCEmulator

    $sites = Get-ADReplicationSite -Filter * -Server $PDC -Properties WhenCreated, WhenChanged, ProtectedFromAccidentalDeletion, Subnets
    $SiteDetails = @()

    foreach ($site in $sites) {
        $dcs = @(Get-ADDomainController -Filter { Site -eq $site.Name } -Server $PDC)
        if ($dcs.Count -eq 0) {
            $SiteDetails += New-Object PSObject -Property @{
                DomainName                          = $DomainName
                SiteName                            = $site.Name
                SiteCreated                         = $Site.WhenCreated
                SiteModified                        = $Site.WhenChanged
                Subnets                             = ($site.subnets | Get-ADReplicationSubnet -Server $PDC | Select-Object Name).Name -join "`n"
                DCinSite                            = "No DC in Site"
                SiteLink                            = $link.Name
                SiteLinkType                        = $link.InterSiteTransportProtocol
                SiteLinkCost                        = $link.Cost
                ReplicationInterval                 = $link.replInterval
                SiteProtectedFromAccidentalDeletion = $site.ProtectedFromAccidentalDeletion
                LinkProtectedFromAccidentalDeletion = $link.ProtectedFromAccidentalDeletion
            }
        }
        else {
            foreach ($dc in $dcs) {
                $links = Get-ADReplicationSiteLink -Filter * -Server $PDC -Properties InterSiteTransportProtocol, replInterval, ProtectedFromAccidentalDeletion | Where-Object { $_.sitesIncluded -contains $site.DistinguishedName }
                foreach ($link in $links) {
                    $SiteDetails += New-Object PSObject -Property @{
                        DomainName                          = $DomainName
                        SiteName                            = $site.Name
                        SiteCreated                         = $Site.WhenCreated
                        SiteModified                        = $Site.WhenChanged
                        Subnets                             = ($site.subnets | Get-ADReplicationSubnet -Server $PDC | Select-Object Name).Name -join "`n"
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

    $SiteDetails = $SiteDetails | Select-Object DomainName, SiteName, SiteCreated, SiteModified, Subnets, SiteProtectedFromAccidentalDeletion, DCinSite, SiteLink, SiteLinkType, SiteLinkCost, ReplicationInterval, LinkProtectedFromAccidentalDeletion

    return $SiteDetails
}

# Returns the priviledged group details of the given domain
Function Get-PrivGroupDetails {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName
    )

    $PDC = (Get-ADDomain -Identity $DomainName).PDCEmulator
    $domainSID = (Get-ADDomain $DomainName -server $PDC).domainSID.Value
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
            GroupName         = (Get-ADGroup -Server $PDC -Identity $GroupSID[1]).Name
            MemberCount       = @(Get-ADGroupMember -Server $PDC -Identity $GroupSID[1] -Recursive ).count
            IsRenamed         = $groupSID[0] -ne (Get-ADGroup -Server $PDC -Identity $GroupSID[1]).Name
        }
    }

    return $PrivGroups
}

# Returns the group details of the given domain
Function Get-ADGroupDetails {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName
    )

    $GroupDetails = @()
    $PDC = (Get-ADDomain -Identity $DomainName).PDCEmulator

    $AllGroups = Get-ADGroup -Filter { GroupCategory -eq "Security" } -Properties GroupScope, Members -Server $PDC
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
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName
    )

    $PDC = (Get-ADDomain -Identity $DomainName).PDCEmulator

    $AllUsers = Get-ADUser -Filter * -Server $PDC -Properties SamAccountName, Enabled, whenCreated, PasswordLastSet, PasswordExpired, PasswordNeverExpires, PasswordNotRequired, AccountExpirationDate, LastLogonDate, LockedOut

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
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName
    )

    $PDC = (Get-ADDomain -Identity $DomainName).PDCEmulator
    $domainSID = (Get-ADDomain $DomainName -server $PDC).domainSID.Value
    $BuiltInUserSIDs = @(@("Administrator", ($domainSID + "-500")), @("Guest", ($domainSID + "-501")))

    $BuiltInUsers = @()

    ForEach ($UserSID in $BuiltInUserSIDs ) {
        $User = Get-ADUser -Server $PDC -Identity $UserSID[1] -Properties SamAccountName, WhenCreated, LastLogonDate, Enabled, LastBadPasswordAttempt, PasswordLastSet
    
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

# Returns the Server OS sumamry of the given domain
Function Get-DomainServerDetails {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName
    )

    $DomainServerDetails = @()
    $Today = Get-Date
    $InactivePeriod = 90
    $PDC = (Get-ADDomain -Identity $DomainName).PDCEmulator
    
    $Servers = Get-ADComputer -Filter { OperatingSystem -Like "*Server*" } -Properties OperatingSystem, PasswordLastSet -Server $PDC 
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
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName
    )

    $DomainClientDetails = @()
    $Today = Get-Date
    $InactivePeriod = 90
    $PDC = (Get-ADDomain -Identity $DomainName).PDCEmulator

    $Workstations = Get-ADComputer -Filter { OperatingSystem -Notlike "*Server*" } -Properties OperatingSystem, PasswordLastSet -Server $PDC 
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

# The main function to perform assessment of AD Forest and produce results as html file
Function Get-ADForestDetails {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $false)]$ForestName = (Get-ADForest).RootDomain,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)]$Logo = $logopath,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)]$ReportPath = $ReportPath1,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)]$CSSHeader = $header
    )    

    if ( $ForestName.Length -gt 0 ) {	
        # Collecting information about specified Forest configuration
        $ForestInfo = Get-ADForest -Identity $ForestName	
    }        
    else {
        # Collecting information about current Forest configuration
        $ForestInfo = Get-ADForest
    }

    $forest = $ForestInfo.RootDomain
    $allDomains = $ForestInfo.Domains
    $ForestGC = $ForestInfo.GlobalCatalogs    
    $forestFL = $ForestInfo.ForestMode
    $FSMODomainNaming = $ForestInfo.DomainNamingMaster
    $FSMOSchema = $ForestInfo.SchemaMaster
    $forestDomainSID = (Get-ADDomain $ForestName).domainSID.Value    

    $SchemaPartition = $ForestInfo.PartitionsContainer.Replace("CN=Partitions", "CN=Schema")
    $SchemaVersion = Get-ADObject -Server $forest -Identity $SchemaPartition -Properties * | Select-Object objectVersion

    <#     $forestDN = $ForestInfo.PartitionsContainer.Replace("CN=Partitions,CN=Configuration,", "") #>
    $configPartition = $ForestInfo.PartitionsContainer.Replace("CN=Partitions,", "")

    # Check if AD Recycle Bin support is enabled
    if ( $forestFL -in ("Windows2008R2Forest", "Windows2012Forest", "Windows2012R2Forest", "Windows2016Forest")) {
        $ADR = (Get-ADOptionalFeature 'Recycle Bin Feature').EnabledScopes.count
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
        default { Write-Host -ForegroundColor red "unknown forest schema version - "$SchemaVersion.objectVersion }
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

    $tombstoneLifetime = (Get-ADobject -Server $forest -Identity "cn=Directory Service,cn=Windows NT,cn=Services,$configPartition" -Properties tombstoneLifetime).tombstoneLifetime

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
    $enterpriseAdminsNo = @(Get-ADGroup -Server $forest -Identity $entGroupID | Get-ADGroupMember -Recursive).count

    $schemaGroupID = $forestDomainSID + "-518"
    $schmaAdminsNo = @(Get-ADGroup -Server $forest -Identity $schemaGroupID | Get-ADGroupMember -Recursive).count

    $ForestPrivGroups = [PSCustomObject]@{
        ForestName             = $forest
        EnterpriseAdminGroup   = (Get-ADGroup -Server $forest -Identity $entGroupID).Name
        EntAdminMemberCount    = $enterpriseAdminsNo
        SchemaAdminGroup       = (Get-ADGroup -Server $forest -Identity $schemaGroupID).Name
        SchemaAdminMemberCount = $schmaAdminsNo
    }

    $ForestPrivGroupsSummary = ($ForestPrivGroups | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Forest-wide Priviledged groups Summary</h2>") -replace "`n", "<br>"

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
    $ServerOSDetails = @()
    $ClientOSDetails = @()
    $PKIDetails = @()
    $DNSServerDetails = @()
    $DNSZoneDetails = @()
    $EmptyOUDetails = @()
    $GPODetails = @()

    ForEach ($domain in $allDomains) {        
        $TrustDetails += Get-ADTrustDetails -DomainName $domain        
        $DomainDetails += Get-ADDomainDetails -DomainName $domain
        $SiteDetails += Get-ADSiteDetails -DomainName $domain
        $privGroupDetails += Get-PrivGroupDetails -DomainName $domain        
        $UserDetails += Get-ADUserDetails -DomainName $domain
        $BuiltInUserDetails += Get-BuiltInUserDetails -DomainName $domain
        $GroupDetails += Get-ADGroupDetails -DomainName $domain
        $UndesiredAdminCount += Get-AdminCountDetails -DomainName $domain
        $PasswordPolicyDetails += Get-ADPasswordPolicy -DomainName $domain        
        $FGPwdPolicyDetails += Get-FineGrainedPasswordPolicy -DomainName $domain
        $ObjectsToClean += Get-ADObjectsToClean -DomainName $domain
        $ServerOSDetails += Get-DomainServerDetails -DomainName $domain
        $ClientOSDetails += Get-DomainClientDetails -DomainName $domain
        $PKIDetails += Get-PKIDetails -DomainName $domain
        $DNSServerDetails += Get-ADDNSDetails -DomainName $domain
        $DNSZoneDetails += Get-ADDNSZoneDetails -DomainName $domain
        $EmptyOUDetails += Get-EmptyOUDetails -DomainName $domain
        $GPODetails += Get-ADGPODetails -DomainName $domain        
    }


    If ($TrustDetails) {
        $TrustSummary = ($TrustDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>AD Trust Summary</h2>")
    }
    If (Get-ADDHCPDetails) {
        $DHCPSummary = (Get-ADDHCPDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>DHCP Server Summary</h2>") -replace "`n", "<br>"
    }
    If ($PKIDetails) {
        $PKISummary = $PKIDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Certificate servers Summary</h2>"
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

    $ReportRaw = ConvertTo-HTML -Body "$ForestSummary $ForestPrivGroupsSummary $TrustSummary $PKISummary $DHCPSummary $DomainSummary $DNSSummary $DNSZoneSummary $SitesSummary $PrivGroupSummary $UserSummary $BuiltInUserSummary $GroupSummary $UndesiredAdminCountSummary $PwdPolicySummary $FGPwdPolicySummary $ObjectsToCleanSummary $ServerOSSummary $ClientOSSummary $EmptyOUSummary $GPOSummary" -Head $header -Title "Report on AD Forest: $forest" -PostContent "<p id='CreationDate'>Creation Date: $(Get-Date) $CopyRightInfo </p>"
    $ReportRaw | Out-File $ReportPath    
}

Get-ADForestDetails