# Read JSON input from the user
$JsonInput = Read-Host
$InputData = $JsonInput | ConvertFrom-Json 
$InputData = $InputData | ConvertFrom-Json
$ErrorActionPreference = "SilentlyContinue"

# Extract necessary commands and data from JSON
$operation = $InputData.command
$localIP = (Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object {
    $_.DHCPEnabled -ne $null -and $_.DefaultIPGateway -ne $null
}).IPAddress | Select-Object -First 1
$targetIP = $InputData.parameters.alert.data.misp.value

# Define path for the log file
$logPath = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

# Add or remove Destination IP from Windows Firewall based on command
switch ($operation) {
    'add' {
        if ($targetIP -notmatch '127.0.0.1|0.0.0.0' -And $targetIP -ne $localIP) {
            New-NetFirewallRule -DisplayName "Активное реагирование Wazuh - $targetIP" -Direction Outbound -LocalPort Any -Protocol Any -Action Block -RemoteAddress $targetIP
            $message = @{ IP = $targetIP; Action = "Added to blocklist" } | ConvertTo-Json -Compress
            Out-File -InputObject $message -FilePath $logPath -Append -Width 2000 -Encoding ascii
            Write-Output "$targetIP added to blocklist via Windows Firewall"
        }
    }
    'delete' {
        if ($targetIP -notmatch '127.0.0.1|0.0.0.0' -And $targetIP -ne $localIP) {
            Remove-NetFirewallRule -DisplayName "Активное реагирование Wazuh - $targetIP"
            $message = @{ IP = $targetIP; Action = "Removed from blocklist" } | ConvertTo-Json -Compress
            Out-File -InputObject $message -FilePath $logPath -Append -Width 2000 -Encoding ascii
            Write-Output "$targetIP removed from blocklist via Windows Firewall"
        }
    }
}
