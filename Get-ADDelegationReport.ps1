# Initialize an empty array to store delegated permissions on OUs
$global:delegatedPermissionsOnOUs = @()

# Define a function to check permissions on an OU and its sub-OUs
function Get-OUPermissions {
    param (
        [string]$ouDN
    )

    # Get the security descriptor of the OU
    $ou = Get-ADOrganizationalUnit -Filter { DistinguishedName -eq $ouDN }
    

    if ($ou) {
        $ouSecurity = Get-Acl -Path "AD:\$ouDN"

        # Loop through each ACE in the OU's ACL
        foreach ($ace in $ouSecurity.Access) {
            # Check if the ACE is explicitly set (not inherited) and represents delegated permissions
            if ($ace.IsInherited -eq $false) {
                # Create an object to store information about the delegated permission on the OU
                $permissionInfo = [PSCustomObject]@{
                    "OU"                    = $ou.DistinguishedName
                    "IdentityReference"     = $ace.IdentityReference
                    "ActiveDirectoryRights" = $ace.ActiveDirectoryRights
                    "AccessControlType"     = $ace.AccessControlType
                    "IsInherited"           = $Ace.IsInherited
                }
                $global:delegatedPermissionsOnOUs += $permissionInfo
            }
        }

        # Get child OUs and check their permissions
        $childOUs = Get-ADOrganizationalUnit -SearchBase $ouDN -Filter * -SearchScope OneLevel
        foreach ($childOU in $childOUs) {
            Get-OUPermissions -ouDN $childOU.DistinguishedName
        }
    }
    else {
        # Get child OUs and check their permissions
        $childOUs = Get-ADOrganizationalUnit -SearchBase $ouDN -Filter * -SearchScope OneLevel
        foreach ($childOU in $childOUs) {
            Get-OUPermissions -ouDN $childOU.DistinguishedName
        }
    }
}



# Specify the domain DN (e.g., "DC=domain,DC=com")
$domainDN = "DC=ADLAB, DC=Local"

# Check permissions at the domain root
$domainRoot = Get-ADDomain -Identity $domainDN
$domainRootSecurity = Get-Acl -Path "AD:\$domainDN"

# Loop through each ACE in the domain's ACL
foreach ($ace in $domainRootSecurity.Access) {
    # Check if the ACE is explicitly set (not inherited) and represents delegated permissions
    if ($ace.IsInherited -eq $false) {
        # Create an object to store information about the delegated permission at the domain root
        $permissionInfo = [PSCustomObject]@{
            "OU"                    = "Domain Root"
            "IdentityReference"     = $ace.IdentityReference
            "ActiveDirectoryRights" = $ace.ActiveDirectoryRights
            "AccessControlType"     = $ace.AccessControlType
            "IsInherited"           = $Ace.IsInherited
        }
        $global:delegatedPermissionsOnOUs += $permissionInfo
    }
}


# Check permissions on OUs within the domain
Get-OUPermissions -ouDN $domainDN


# Display the explicitly set delegated permissions on OUs, including the domain root
$global:delegatedPermissionsOnOUs | export-csv -nti c:\temp\delegation.csv
