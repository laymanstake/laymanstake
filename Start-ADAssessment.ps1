Try { Import-Module -Name ActiveDirectory -Force -Erroraction stop }
Catch { Write-Output "ActiveDirectory Module is not installed" }

Try { Import-Module -Name DHCPServer -Force -Erroraction stop }
Catch { Write-Output "DHCPServer Module is not installed" }

Import-Module ActiveDirectory
Import-Module DHCPServer

# Output formating options
$logopath = "https://camo.githubusercontent.com/239d9de795c471d44ad89783ec7dc03a76f5c0d60d00e457c181b6e95c6950b6/68747470733a2f2f6e69746973686b756d61722e66696c65732e776f726470726573732e636f6d2f323032322f31302f63726f707065642d696d675f32303232303732335f3039343534372d72656d6f766562672d707265766965772e706e67"
$ReportPath1 = "$env:USERPROFILE\desktop\ADReport_$(get-date -Uformat "%Y%m%d-%H%M%S").html"
$CopyRightInfo = " @Copyright Niitsh Kumar <a href='https://github.com/laymanstake'>Visit nitishkumar.net</a>"

#CSS codes to format the report
$header = @"
<style>
    body { background-color: #b9d7f7; }
    h1 { font-family: Arial, Helvetica, sans-serif; color: #e68a00; font-size: 28px; }    
    h2 { font-family: Arial, Helvetica, sans-serif; color: #000099; font-size: 16px; }    
    table { font-size: 12px; border: 0px;  font-family: Arial, Helvetica, sans-serif; } 	
    td { padding: 4px; margin: 0px; border: 0; }	
    th { background: #395870; background: linear-gradient(#49708f, #293f50); color: #fff; font-size: 11px; text-transform: uppercase; padding: 10px 15px; vertical-align: middle; }
    tbody tr:nth-child(even) { background: #f0f0f2; }
    CreationDate { font-family: Arial, Helvetica, sans-serif; color: #ff3300; font-size: 12px; }
</style>
<img src="$logopath" alt="Company logo" width="150" height="150" align="right">
"@


# Numbe of functions to get the details of the environment

# Returns the details of AD trusts in the given domain
Function Get-ADTrustDetails {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName
    )
    
    $trusts = Get-ADTrust -Filter * -Server $DomainName | Select-Object Source, Target, Direction, TrustType, Intraforest

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
            TrustSource    = $trust.Source
            TrustTarget    = $trust.Target
            TrustDirection = $trust.Direction
            TrustType      = $trust.TrustType
            Intraforest    = $trust.Intraforest
            Stale          = $stale
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

Function Get-ADDNSDetails {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName
    )

    # $PDC = (Get-ADDomain -Identity $DomainName).PDCEmulator
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

# Returns the details of unlinked GPOs in the given domain
Function Get-ADGPODetails {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $true)]$DomainName
    )
    
    $AllGPOs = Get-GPO -All -Domain $DomainName
    $UnlinkedGPOs = $AllGPOs | Where-Object { $_ | Get-GPOReport -ReportType XML -Domain $DomainName | Select-String -NotMatch "<LinksTo>" } | Select-Object DisplayName, CreationTime, ModificationTime 

    $UnlinkedGPODetails = [PSCustomObject]@{
        Domain                      = $domainname
        AllGPOs                     = $AllGPOs.count
        UnlinkedGPOs                = $UnlinkedGPOs.DisplayName -join "`n"
        UnlinkedGPOCreationTime     = $UnlinkedGPOs.CreationTime -join "`n"
        UnlinkedGPOModificationTime = $UnlinkedGPOs.ModificationTime -join "`n"
        UnlinkedGPOCount            = $UnlinkedGPOs.count
    }
    
    return $UnlinkedGPODetails
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
                Domain            = $domain
                DCName            = $dc.Name
                Site              = $dc.site
                OSVersion         = $dc.OperatingSystem
                IPAddress         = $dc.IPv4Address
                FSMORoles         = (Get-ADDomainController -Identity $dc -Server $dc | Select-Object @{l = "FSMORoles"; e = { $_.OperationMasterRoles -join ", " } }).FSMORoles
                SysvolType        = $sysvolStatus
                FSR2DFSRStatus    = $FSR2DFSRStatus
                SMB1Status        = ($Results[0]).EnableSMB1Protocol
                Firewall          = (Get-Service -name MpsSvc -ComputerName $dc).Status
                NetlogonParameter = ($Results[1]).vulnerablechannelallowlist
                ReadOnly          = $dc.IsReadOnly
                UndesiredFeatures = Compare-Object -ReferenceObject $UndesiredFeatures -DifferenceObject  (Get-WindowsFeature -ComputerName $dc | Where-Object Installed).Name -IncludeEqual | Where-Object { $_.SideIndicator -eq '==' } | Select-Object -ExpandProperty InputObject
            }
        }
    }
    
    return $DomainDetails    
}

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
        @("Administrators", "S-1-5-32-544"), 
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
            MemberCount       = @(Get-ADGroup -Server $PDC -Identity $GroupSID[1] | Get-ADGroupMember -Recursive).count
            IsRenamed         = $groupSID[0] -ne (Get-ADGroup -Server $PDC -Identity $GroupSID[1]).Name
        }
    }
    
    return $PrivGroups
}

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
    $privGroupDetails = @()
    $EmptyOUDetails = @()
    $PKIDetails = @()
    $GPODetails = @()
    $UserDetails = @()

    ForEach ($domain in $allDomains) {        
        $TrustDetails += Get-ADTrustDetails -DomainName $domain        
        $DomainDetails += Get-ADDomainDetails -DomainName $domain
        $privGroupDetails += Get-PrivGroupDetails -DomainName $domain        
        $UserDetails += Get-ADUserDetails -DomainName $domain
        $PKIDetails += Get-PKIDetails -DomainName $domain
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
    $DomainSummary = $DomainDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Domains Summary</h2>"    
    $UserSummary = $UserDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Users Summary</h2>"    
    $PrivGroupSummary = ($privGroupDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Priviledged groups Summary</h2>") -replace '<td>True</td>', '<td bgcolor="red">True</td>'
    $EmptyOUSummary = ($EmptyOUDetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Empty OU Summary</h2>") -replace "`n", "<br>"
    $GPOSummary = ($GPODetails | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Unlinked GPO Summary</h2>") -replace "`n", "<br>"

    $ReportRaw = ConvertTo-HTML -Body "$ForestSummary $ForestPrivGroupsSummary $TrustSummary $PKISummary $DHCPSummary $DomainSummary $PrivGroupSummary $UserSummary $EmptyOUSummary $GPOSummary" -Head $header -Title "Report on AD Forest: $forest" -PostContent "<p id='CreationDate'>Creation Date: $(Get-Date) $CopyRightInfo </p>"
    $ReportRaw | Out-File $ReportPath    
}

Get-ADForestDetails