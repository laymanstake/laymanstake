$DCs =  (Get-ADDomainController -filter *).Name #("XXX","ABC")

$Userlogon = @()

$users = get-content c:\temp\users01.txt

foreach ($DC in $DCs){    
        ForEach($user in $users){
            $userlogontemp = Get-ADUser $user -Properties lastlogon, lastlogondate -Server $DC | Sort-Object -Property SamAccountName

            $Info = [PSCustomObject]@{
                    SamAccountName = $userlogontemp.SamAccountName
                    LastlogonDate = $userlogontemp.LastlogonDate
                    Lastlogon = $userlogontemp.Lastlogon
                    DCName = $DC
                }
            $Userlogon += $Info
        }
    
}

$LatestList = $Userlogon | Group-Object -Property SamAccountName | % {$_.group | Sort-Object -Property lastlogon | select -Last 1} | Select-Object SamAccountName, @{l = "Lastlogon"; e = { [DateTime]::FromFileTime($_.LastLogon) } }, lastlogonDate, DCName
$LatestList | export-csv -nti c:\temp\userloginreport01.csv
