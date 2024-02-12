$DCs =  (Get-ADDomainController -filter *).Name #("XXX","ABC")
$Userlogon = @()
$users = get-content c:\temp\users1.txt

foreach ($DC in $DCs){
        Write-Host "Getting Report from $DC"
        ForEach($user in $users){
            $userlogontemp = Get-ADUser -filter {mail -eq $user} -Properties EmployeeID, mail, lastlogon, lastlogontimestamp -Server $DC #| Sort-Object -Property SamAccountName

            $Info = [PSCustomObject]@{
                    SamAccountName = $userlogontemp.SamAccountName
                    mail = $userlogontemp.mail
                    EmployeeID = $userlogontemp.EmployeeID
                    lastlogontimestamp = $userlogontemp.lastlogontimestamp
                    Lastlogon = $userlogontemp.Lastlogon
                    FinalLogon = ($userlogontemp.lastlogontimestamp, $userlogontemp.Lastlogon)| Measure-Object -Maximum | Select-Object -ExpandProperty Maximum
                    DCName = $DC
                }
            $Userlogon += $Info
        }
}

$LatestList = $Userlogon | Group-Object -Property SamAccountName | % {$_.group | Sort-Object -Property FinalLogon | select -Last 1} | Select-Object SamAccountName, mail, EmployeeID, @{l = "Lastlogon"; e = { [DateTime]::FromFileTime($_.LastLogon).tostring('dd/MM/yyyy_hh:mm:ss tt') } }, @{l = "LastlogonDate"; e = { [DateTime]::FromFileTime($_.LastLogontimestamp).tostring('dd/MM/yyyy_hh:mm:ss tt') } },@{l = "FinalLogon"; e = { [DateTime]::FromFileTime($_.FinalLogon).tostring('dd/MM/yyyy_hh:mm:ss tt') } }, DCName
$LatestList | export-csv -nti c:\temp\userloginreport02.csv
