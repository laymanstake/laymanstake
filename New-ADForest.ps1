Install-windowsfeature -name AD-Domain-Services -IncludeManagementTools

Function New-ADLabForest {
    [cmdletBinding()]
    param
    (
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][string]$localAdminpass = 'Local@adminp@$$',
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][string]$domainName = 'ADLAB.local',
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][string]$domainNetbiosName = 'ADLAB',
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][string]$safeModePass = '$@feM0d3p@$$',
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][ValidateSet(2, 3, 4, 5, 6, 7, 'Win2003', 'Win2008', 'Win2008R2', 'Win2012', 'Win2012R2', 'WinThreshold')][string]$DomainMode = 6,
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][ValidateSet(2, 3, 4, 5, 6, 7, 'Win2003', 'Win2008', 'Win2008R2', 'Win2012', 'Win2012R2', 'WinThreshold')][string]$ForestMode = 6
    )

    Write-Output 'Resetting the Administrator account password and settings...'

    Set-LocalUser `
        -Name Administrator `
        -AccountNeverExpires `
        -Password (ConvertTo-SecureString "$localAdminpass" -AsPlainText -Force) `
        -PasswordNeverExpires:$true `
        -UserMayChangePassword:$true

    Write-Output '[+] Installing Forest AD'

    Install-ADDSForest `
        -DatabasePath 'C:\Windows\NTDS' `
        -DomainMode "$DomainMode" `
        -DomainName "$domainName" `
        -DomainNetbiosName "$domainNetbiosName" `
        -ForestMode "$ForestMode" `
        -InstallDns `
        -LogPath 'C:\Windows\NTDS' `
        -SysvolPath 'C:\Windows\SYSVOL' `
        -SafeModeAdministratorPassword (ConvertTo-SecureString "$safeModePass" -AsPlainText -Force) `
        -Force
}

New-ADLabForest

# Create OUs

$fqdn = Get-ADDomain
$fulldomain = $fqdn.DNSRoot
$domain = $fulldomain.split(".")
$Dom = $domain[0]
$Ext = $domain[1]

$Sites = ("Lyon", "New-York", "London")
$Services = ("Production", "Marketing", "IT", "Direction", "Helpdesk")
$FirstOU = "Sites"

New-ADOrganizationalUnit -Name $FirstOU -Description $FirstOU  -Path "DC=$Dom,DC=$EXT" -ProtectedFromAccidentalDeletion $false


foreach ($S in $Sites) {
    New-ADOrganizationalUnit -Name $S -Description "$S"  -Path "OU=$FirstOU,DC=$Dom,DC=$EXT" -ProtectedFromAccidentalDeletion $false

    foreach ($Serv in $Services) {
        New-ADOrganizationalUnit -Name $Serv -Description "$S $Serv"  -Path "OU=$S,OU=$FirstOU,DC=$Dom,DC=$EXT" -ProtectedFromAccidentalDeletion $false
    }

}

function FindSamAccountName {
    param (		
        [String]$FirstName,
        [String]$LastName		
    )
	
    # Deciding SamAccountName basis the first name and last name
    $FirstSamAccountName = $FirstName + "." + $LastName
	
    # Check if the user already exists
    $Exists = Get-ADuser -f { SamAccountName -eq $FirstSamAccountName }
	
    If (!($Exists)) {
        If ($FirstSamAccountName.length -ge 21) {
            Return $FirstSamAccountName.Substring(0, 20)
        }
        Else {
            Return $FirstSamAccountName
        }
    }
    Else {			
        $Numeric = $LastName.substring($LastName.length - 1 ) -replace '^[a-z]'
        If ($Numeric -ne "") {			
            $LastName = $LastName + "1"
            Return FindSamAccountName -FirstName $FirstName -LastName $LastName
        }
        Else {
            $Numeric = $Numeric + 1
            $LastName = $LastName + $Numeric
            Return FindSamAccountName -FirstName $FirstName -LastName $LastName
        }
    }	
}

function Get-RandomCharacters($length, $characters) { 
    $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length } 
    $private:ofs = "" 
    return [String]$characters[$random]
}

$FirstNames = ("Nitish", "Abhishek", "Deepak", "Manish", "Devashish", "Ayush", "Pankaj", "Sandeep", "Saurbh")
$lastNames = ("Kumar", "Mishra", "Singh", "Pandey", "Srivastava", "Dubey", "Sharma", "Gupta", "Sahu")
$OUs = Get-ADOrganizationalUnit -Filter * | Where-Object { $_.Name -ne "Domain Controllers" -AND $_.Name -ne "Sites" } | Select-Object Name, DistinguishedName

ForEach ($i in 1..200) {
    $GivenName = Get-Random -InputObject $FirstNames
    $SurName = Get-Random -InputObject $lastNames
    $DisplayName = "$GivenName $SurName"
    $SamaccountName = FindSamAccountName -FirstName $GivenName -LastName $SurName
    $UPN = $SamaccountName + "@" + (Get-ADDomain).DNSRoot
    $OU = Get-Random -InputObject $OUs.DistinguishedName
    $Department = (Get-ADOrganizationalUnit $OU).Name

    $password = Get-RandomCharacters -length 5 -characters 'abcdefghiklmnoprstuvwxyz'
    $password += Get-RandomCharacters -length 1 -characters 'ABCDEFGHKLMNOPRSTUVWXYZ'
    $password += Get-RandomCharacters -length 1 -characters '1234567890'
    $password += Get-RandomCharacters -length 1 -characters '!$%&?@*+-'
    
    New-ADuser -SamAccountName $SamAccountName  -Path $OU -DisplayName  $DisplayName -Name $SamAccountName.Replace(".", " ") -UserPrincipalName $UPN -Department $Department -GivenName $GivenName -SurName $SurName -Confirm:$false
    Set-ADAccountPassword -Identity $SamAccountName -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $password -Force)	
    Enable-ADAccount -Identity $SamAccountName	
    Set-ADUser -Identity $SamAccountName -ChangePasswordAtLogon $true

    Write-Output "The user account $SamAccountName created `n"

}
