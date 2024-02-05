#requires -version 5

# Author : Nitish Kumar
# This script parses Windows Auditing logs to file share access logs
# version 1.0
# 05/02/2024

enum AccessType {
    ReadData_ListDirectory = 4416
    WriteData_AddFile = 4417
    AppendData_AddSubdirectory_CreatePipeInstance = 4418
    ReadEA = 4419
    WriteEA = 4420
    Execute_Traverse = 4421
    DeleteChild = 4422
    ReadAttributes = 4423
    WriteAttributes = 4424
    DELETE = 1537
    READ_CONTROL = 1538
    WRITE_DAC = 1539
    WRITE_OWNER = 1540
    SYNCHRONIZE = 1541
    ACCESS_SYS_SEC = 1542
}

$events = Get-WinEvent -FilterHashtable @{

    LogName   = 'Security'
    Id        = 4663, 5140
    StartTime = (Get-Date).AddMinutes(-475)
}


$Allevents = $events.Foreach({
        [xml]$event = $_.ToXml()

        $dataHt = @{}
        $event.Event.EventData.Data | ForEach-Object { $dataHt[$_.Name] = $_.'#text' }

        $ats = foreach ($stringMatch in ($dataHt['AccessList'] | Select-String -Pattern '\%\%(?<id>\d{4})' -AllMatches)) {
            foreach ($group in $stringMatch.Matches.Groups | Where-Object { $_.Name -eq 'id' }) {
                [AccessType]$group.Value
            }
        }

        [pscustomobject]@{
            Time       = $_.TimeCreated
            EventId    = $_.Id
            LogonID    = $dataHt['SubjectLogonId']
            Path       = "$($dataHt['ObjectName'])".trim('\??\')
            Share      = $dataHt['ShareName']
            User       = $dataHt['SubjectUserName']
            UserDomain = $dataHt['SubjectDomainName']
            IpAddress  = $dataHt['IpAddress']
            AccessType = $ats -join ', '
        }    
    })

$Allevents 