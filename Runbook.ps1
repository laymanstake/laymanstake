param (
    [parameter (mandatory=$false)][Object]$webhookData,
    [parameter (mandatory=$false)][string]$Subject,
    [parameter (mandatory=$false)][string]$MailHeader,
    [parameter (mandatory=$false)][string]$mailbody,
    [parameter (mandatory=$false)][string]$recipients = "xxxxxxxxxxx"
)      
    

if($Webhookdata -ne $null){
    $essentials = $Webhookdata.RequestBody | ConvertFrom-JSON

    $AlertRule = $essentials.data.essentials.alertRule
    $severity = $essentials.data.essentials.severity
    $signalType = $essentials.data.essentials.signalType
    $firedDateTime = $essentials.data.essentials.firedDateTime
    $conditionType = $essentials.data.alertContext.conditionType
    $condition = $essentials.data.alertContext.condition.allOf[0].searchQuery
    $threshold = $essentials.data.alertContext.condition.AllOf[0].threshold
    $Count = $essentials.data.alertContext.condition.AllOf[0].metricValue
    $results = $essentials.data.alertContext.condition.AllOf[0].linkToFilteredSearchResultsUI

    $WebhookName = $Webhookdata.WebhookName
    $WebhookBody = ConvertFrom-JSON -InputObject $WebhookData.RequestBody
    $Subject = "$AlertRule - $severity - $signalType - $firedDateTime"
    $MailHeader = @"
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
    $mailbody = "Alert rule named $AlertRule fired since below $conditionType condition met $count times while threshold is $threshold <br><br> $condition <br><br> <a href=$results>Link to query results</a>  <br><br><b>Regards<br></b>IT Team"    
}

$MYcredetial = "GA"
$cred = Get-AutomationPSCredential -Name $MYcredetial

$clientID = $cred.UserName
$clientSecret = $Cred.GetNetworkCredential().Password

$tenantID = "xxxxxxxxxxxxxxxxxxxx"
$mailSender = "xxxxxxxxxxxxxxx"

$mailRecipient = $recipients

#Connect to Graph API
$tokenBody = @{
    Grant_Type = "client_credentials"
    Scope = "https://graph.microsoft.com/.default"
    Client_Id = $clientID
    Client_Secret = $clientSecret
}

$tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantID/oauth2/v2.0/token" -Method POST -Body $tokenBody
$headers = @{
    "Authorization" = "Bearer $($tokenResponse.access_token)"
    "Content-type" = "application/json"
}

#Send email
$URLsend = "https://graph.microsoft.com/v1.0/users/$mailSender/sendMail"
$BodyJsonsend = @"
{
    "message": {
        "subject": "$Subject",
        "body": {
            "contentType": "HTML",
            "content": "$mailbody"
        },
        "toRecipients": [
            {
                "emailAddress": {
                    "address": "$recipients"
                }
            }
        ]
    },
    "saveToSentItems": "false"
}
"@

Invoke-RestMethod -Method POST -Uri $URLsend -Headers $headers -Body $BodyJsonsend
