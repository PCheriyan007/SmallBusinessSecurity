<#
.SYNOPSIS
    Immediately stops the Windows Defender scan in progress on this endpoint and emails
    RECIPIENT EMAIL that it was stopped.

.DESCRIPTION
    Deploy through Action1 (runs as SYSTEM). The script:
      1. Finds the scan in progress (Quick or Full) from Defender's own scan events
      2. Tells the scan runner not to send a results email (this script reports instead)
      3. Cancels the scan with MpCmdRun.exe -Cancel and waits for Defender to confirm
      4. Emails "[Endpoint] has stopped the Windows Defender scan", with how long it ran
         and anything detected before it was stopped

    If no scan is running, it reports that in Action1 and sends no email.
    Works while the endpoint is isolated: the email briefly opens SMTP to Gmail, then closes it.
#>

$ErrorActionPreference = 'Stop'
$ScanDir    = Join-Path $env:ProgramData 'DefenderScan'
$StopMarker = Join-Path $ScanDir 'stop-requested.txt'

function Say { param([string]$Message) Write-Host ('{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $Message) }

function Get-MpCmdRun {
    $platform = Get-ChildItem (Join-Path $env:ProgramData 'Microsoft\Windows Defender\Platform') -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path (Join-Path $_.FullName 'MpCmdRun.exe') } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($platform) { return (Join-Path $platform.FullName 'MpCmdRun.exe') }
    Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
}

# ===================== EMAIL CONFIG (same as Defender alert script) =====================
$Mail = @{
    To            = 'RECIPIENT EMAIL'
    From          = 'SENDER EMAIL'                              # must match Username (or a verified alias of it)
    Username      = 'SENDER EMAIL'
    RelayServer   = 'smtp-relay.gmail.com'                      # tried FIRST: IP-allowlisted Workspace relay, no login
    SmtpServer    = 'smtp.gmail.com'                            # FALLBACK: authenticated Gmail SMTP with App Password
    UseRelayFirst = $true
    Port          = 587
    # DPAPI-encrypted App Password: from the Defender alert script, or stored by the scan scripts
    CredFiles     = @(
        (Join-Path $env:ProgramData 'DefenderAlert\smtp.cred'),
        (Join-Path $env:ProgramData 'DefenderScan\smtp.cred')
    )
}
$ProvidedPassword = if ($SmtpAppPassword) { [string]$SmtpAppPassword } elseif ($env:SmtpAppPassword) { $env:SmtpAppPassword } else { '' }
$ProvidedPassword = $ProvidedPassword -replace '\s', ''
$RuleGroup        = 'Endpoint Isolation'                   # must match the isolation script
$IsolationState   = Join-Path $env:ProgramData 'Isolation\isolation-state.json'
$MailRuleName     = 'ISOLATION - TEMP notification email'
# =========================================================================================

function Get-MailCredential {
    if ($ProvidedPassword) { return New-Object System.Net.NetworkCredential($Mail.Username, $ProvidedPassword) }
    foreach ($f in $Mail.CredFiles) {
        if (Test-Path $f) {
            $secure = (Get-Content -Path $f -Raw).Trim() | ConvertTo-SecureString
            return New-Object System.Net.NetworkCredential($Mail.Username, $secure)
        }
    }
    throw 'No SMTP credential found (no stored smtp.cred and no SmtpAppPassword parameter).'
}

function Send-Mail {
    param([string]$Subject, [string]$Html, [bool]$High)
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $send = {
        param($Server, $Credential)
        $msg = New-Object System.Net.Mail.MailMessage($Mail.From, $Mail.To, $Subject, $Html)
        $msg.IsBodyHtml = $true
        if ($High) { $msg.Priority = [System.Net.Mail.MailPriority]::High }
        $smtp = New-Object System.Net.Mail.SmtpClient($Server, $Mail.Port)
        $smtp.EnableSsl = $true
        $smtp.Timeout   = 20000
        if ($Credential) { $smtp.Credentials = $Credential }
        try { $smtp.Send($msg) } finally { $msg.Dispose(); $smtp.Dispose() }
    }
    if ($Mail.UseRelayFirst -and $Mail.RelayServer) {
        try { & $send $Mail.RelayServer $null; Say "Email sent via relay ($($Mail.RelayServer))."; return }
        catch {
            $err = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
            Say "Relay failed ($err). Trying authenticated SMTP."
        }
    }
    & $send $Mail.SmtpServer (Get-MailCredential)
    Say "Email sent via authenticated SMTP ($($Mail.SmtpServer))."
}

function Test-Isolated {
    (Test-Path $IsolationState) -or [bool](Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue)
}

# If the endpoint is isolated, briefly allows outbound SMTP to Gmail only for the send
function Open-MailChannel {
    $ips = foreach ($h in $Mail.RelayServer, $Mail.SmtpServer) {
        try { [System.Net.Dns]::GetHostAddresses($h) | ForEach-Object { $_.IPAddressToString } } catch { }
    }
    $ips = @($ips | Select-Object -Unique)
    if ($ips.Count -eq 0) { throw 'Could not resolve Gmail SMTP servers.' }
    New-NetFirewallRule -Group $RuleGroup -DisplayName $MailRuleName -Direction Outbound -Action Allow `
        -Profile Any -Protocol TCP -RemoteAddress $ips -RemotePort $Mail.Port | Out-Null
}

function Close-MailChannel {
    Get-NetFirewallRule -DisplayName $MailRuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
}

function Send-Notice {
    param([string]$Subject, [string]$Headline, [string]$Color, [System.Collections.IDictionary]$Details,
          [string]$ExtraHtml, [switch]$HighPriority)
    $isolated = Test-Isolated
    try {
        if ($isolated) { Open-MailChannel }
        $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
        $cs  = Get-CimInstance Win32_ComputerSystem
        $ips = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' }).IPAddress -join ', '

        $rows = [ordered]@{
            'Computer'       = $env:COMPUTERNAME
            'Domain'         = $cs.Domain
            'Logged-on user' = if ($cs.UserName) { $cs.UserName } else { '(none)' }
            'IP address(es)' = $ips
            'Network status' = if ($isolated) { 'ISOLATED (Action1 only)' } else { 'Normal' }
        }
        if ($Details) { foreach ($k in $Details.Keys) { $rows[$k] = $Details[$k] } }
        $tr = foreach ($k in $rows.Keys) { "<tr><td><b>$(& $enc $k)</b></td><td>$(& $enc $rows[$k])</td></tr>" }

        $html = @"
<html><body style="font-family:Segoe UI,Arial,sans-serif;font-size:13px">
<h2 style="color:$Color">$(& $enc $Headline)</h2>
<table style="border-collapse:collapse" cellpadding="4">
$($tr -join "`n")
</table>
$ExtraHtml
<p style="color:#666">Sent by the Action1-deployed Defender scan scripts.</p>
</body></html>
"@
        Send-Mail -Subject $Subject -Html $html -High ([bool]$HighPriority)
    } catch {
        Say "WARNING: Could not send notification email ($($_.Exception.Message))."
    } finally {
        if ($isolated) { Close-MailChannel }
    }
}
# ===================== DEFENDER HELPERS =====================
$LogName = 'Microsoft-Windows-Windows Defender/Operational'

function Get-EventData {
    param($Evt)
    $d = @{}
    foreach ($n in ([xml]$Evt.ToXml()).Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
    $d
}

# Returns the scan currently in progress (from Defender's scan start/end events), or $null
function Get-ActiveScan {
    param([int]$MaxHours = 24)
    $startEvt = Get-WinEvent -FilterHashtable @{ LogName = $LogName; Id = 1000; StartTime = (Get-Date).AddHours(-$MaxHours) } `
        -MaxEvents 1 -ErrorAction SilentlyContinue
    if (-not $startEvt) { return $null }
    $sd = Get-EventData $startEvt
    $ended = Get-WinEvent -FilterHashtable @{ LogName = $LogName; Id = 1001, 1002, 1005; StartTime = $startEvt.TimeCreated } `
        -ErrorAction SilentlyContinue | Where-Object { $_.RecordId -gt $startEvt.RecordId -and (Get-EventData $_)['Scan ID'] -eq $sd['Scan ID'] }
    if ($ended) { return $null }
    [pscustomobject]@{ ScanId = $sd['Scan ID']; Type = $sd['Scan Parameters']; Started = $startEvt.TimeCreated; RecordId = $startEvt.RecordId }
}

# Finds how a given scan ended: 1001 completed, 1002 stopped before completion, 1005 failed
function Get-ScanEnd {
    param([string]$ScanId, [datetime]$Since)
    Get-WinEvent -FilterHashtable @{ LogName = $LogName; Id = 1001, 1002, 1005; StartTime = $Since } -ErrorAction SilentlyContinue |
        Where-Object { -not $ScanId -or (Get-EventData $_)['Scan ID'] -eq $ScanId } | Select-Object -Last 1
}

function Format-Duration {
    param([timespan]$T)
    '{0}h {1}m {2}s' -f [int][math]::Floor($T.TotalHours), $T.Minutes, $T.Seconds
}

# Detections since a point in time, as an HTML table (plus a count)
function Get-DetectionReport {
    param([datetime]$Since)
    $sev = @{ 0 = 'Unknown'; 1 = 'Low'; 2 = 'Moderate'; 4 = 'High'; 5 = 'Severe' }
    $threats = @{}
    Get-MpThreat -ErrorAction SilentlyContinue | ForEach-Object { $threats[[string]$_.ThreatID] = $_ }
    $dets = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -ge $Since })
    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $rows = foreach ($d in $dets) {
        $t = $threats[[string]$d.ThreatID]
        $name = if ($t) { $t.ThreatName } else { "ThreatID $($d.ThreatID)" }
        $severity = if ($t) { $sev[[int]$t.SeverityID] } else { 'Unknown' }
        "<tr><td>$(& $enc $d.InitialDetectionTime)</td><td><b>$(& $enc $name)</b></td><td>$(& $enc $severity)</td>" +
        "<td>$(if ($d.ActionSuccess) { 'Yes' } else { '<b style=''color:#b00020''>No</b>' })</td>" +
        "<td style='word-break:break-all'>$(& $enc (($d.Resources | ForEach-Object { $_ -replace '^\w+:_', '' }) -join '; '))</td></tr>"
    }
    $html = if ($dets.Count -gt 0) {
@"
<h3>Detections</h3>
<table border="1" style="border-collapse:collapse" cellpadding="5">
<tr style="background:#eee"><th>Detected</th><th>Threat</th><th>Severity</th><th>Remediated</th><th>Resources</th></tr>
$($rows -join "`n")
</table>
"@
    } else { '<p>No threats were detected.</p>' }
    [pscustomobject]@{
        Count  = $dets.Count
        Active = @(Get-MpThreat -ErrorAction SilentlyContinue | Where-Object { $_.IsActive }).Count
        Html   = $html
    }
}

# ---------------------------------------------------------------------------
try {
    $scan = Get-ActiveScan
    if (-not $scan) {
        Say 'No Windows Defender scan is in progress. Nothing to stop.'
        exit 0
    }
    $scanName = switch -Wildcard ($scan.Type) { '*Full*' { 'Full Disk Scan' } '*Quick*' { 'Quick Scan' } default { "$($scan.Type)" } }
    Say "Found $scanName in progress (started $($scan.Started), Scan ID $($scan.ScanId))."

    # Tell the runner (if any) that this stop was intentional, so it skips its results email
    New-Item -ItemType Directory -Path $ScanDir -Force | Out-Null
    Set-Content -Path $StopMarker -Value (Get-Date).ToString('o')

    $mpcmd = Get-MpCmdRun
    & $mpcmd -Cancel | Out-Null
    Say "Cancel requested via $mpcmd."

    # Wait for Defender to confirm the scan ended
    $endEvt = $null
    for ($i = 0; $i -lt 30 -and -not $endEvt; $i++) {
        Start-Sleep -Seconds 2
        $endEvt = Get-ScanEnd -ScanId $scan.ScanId -Since $scan.Started.AddSeconds(-5)
    }

    if (-not $endEvt) {
        Remove-Item $StopMarker -Force -ErrorAction SilentlyContinue   # let the runner report normally
        throw 'Defender did not confirm the scan stopped within 60 seconds. It may still be running.'
    }

    $stoppedAt = $endEvt.TimeCreated
    $report    = Get-DetectionReport -Since $scan.Started.AddSeconds(-5)

    if ($endEvt.Id -eq 1001) {
        Say 'The scan finished on its own before the cancel took effect.'
        $how  = 'Scan had already completed before the stop request took effect'
        $note = 'The scan completed, so the whole scope was checked.'
    } else {
        Say "Scan stopped at $stoppedAt."
        $how  = 'Stopped by DefenderStopScan.ps1 via Action1'
        $note = 'The scan did not finish, so parts of the system were not checked.'
    }

    Send-Notice -Subject "[Scan Stopped] $env:COMPUTERNAME has stopped the Windows Defender scan" `
        -Headline "$env:COMPUTERNAME has stopped the Windows Defender $scanName" -Color '#b36b00' `
        -ExtraHtml $report.Html -HighPriority:($report.Count -gt 0) `
        -Details ([ordered]@{
            'Scan type'                = $scanName
            'Started'                  = $scan.Started.ToString('yyyy-MM-dd HH:mm:ss')
            'Stopped'                  = $stoppedAt.ToString('yyyy-MM-dd HH:mm:ss')
            'Ran for'                  = Format-Duration ($stoppedAt - $scan.Started)
            'How'                      = $how
            'Threats detected so far'  = $report.Count
            'Active threats on device' = $report.Active
            'Note'                     = $note
        })
    exit 0
} catch {
    Say "ERROR: $($_.Exception.Message)"
    exit 1
}
