function Show-Menu {
    param (
        [string]$Title = 'My Menu'
    )
    Clear-Host
    Write-Output "================ $Title ================"

    Write-Output "1: Press '1' for automatically selecting current primary DNS of this machine."
    Write-Output "2: Press '2' for automatically selecting current logon server."
    Write-Output "3: Press '3' for manually typing DNS Server Name to work upon."
    Write-Output "Q: Press 'Q' to quit."
}

Show-Menu -Title "Choice for DNS Server"
$selection = Read-Host "Which DNS Server, you want to have inventory from "
switch ($selection) {
    '1' {
        $CurerntSystemIP = (Resolve-DnsName $Env:Computername | Where-Object { $_.Type -eq "A" }).IPAddress
        $DNSServer = (Resolve-DNSName (Get-CimInstance -class win32_Networkadapterconfiguration | Where-Object { $_.IPAddress -like $CurerntSystemIP }).DNSServerSearchOrder[0]).NameHost
    }
    '2' {
        $DNSServer = $env:logonserver.split("\")[2]
    }
    '3' {
        $DNSServer = Read-Host "Provide the DNS Name "
    }
    'Q' {
        Exit
    }
}


Write-Output "Collecting DNS Inventory from $($DNSServer) ..." -foregroundcolor GREEN

$Summary = @()
$Zones = @(Get-DnsServerZone -ComputerName $DNSServer)
ForEach ($Zone in $Zones) {
    $Temp = $Zone | Get-DnsServerResourceRecord -ComputerName $DNSServer | Select-Object HostName, RecordType, TimeStamp, TimetoLive, @{Name = 'PTR Record'; Expression = { $_.RecordData.PtrDomainName } }, @{Name = 'IPv4Address'; Expression = { $_.RecordData.IPv4Address } }, @{Name = 'IPv6Address'; Expression = { $_.RecordData.IPv6Address } }, @{Name = 'CNAME Record'; Expression = { $_.RecordData.HostNameAlias } }, @{Name = 'TXT Record'; Expression = { $_.RecordData.DescriptiveText } }, @{Name = 'NS Record'; Expression = { $_.RecordData.NameServer } }, @{Name = 'MX Record'; Expression = { $_.RecordData.MailExchange } }, @{Name = 'SRV Record'; Expression = { $_.RecordData.DomainName + "|" + $_.RecordData.Port + "|" + $_.RecordData.Priority + "|" + $_.RecordData.Weight } } | export-csv -Notype "$env:userprofile\desktop\$DNSServer_$($Zone.ZoneName).csv"
    $Summary += $Temp
}







