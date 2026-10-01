<#
.SYNOPSIS
    Immediately starts a Windows Defender Full Disk Scan on this endpoint and emails RECIPIENT EMAIL
    when it starts and again with the results when it finishes.

.DESCRIPTION
    Deploy through Action1 (runs as SYSTEM). Nothing is scheduled: the scan starts right away.

    Because a scan can outlast the Action1 run (a Full Disk Scan can take hours), the script writes a
    small runner to C:\ProgramData\DefenderScan and launches it as its own background process.
    The runner:
      1. Optionally updates Defender definitions (skipped if the endpoint is isolated)
      2. Starts the scan and emails "[Endpoint] has started a Windows Defender Full Disk Scan"
      3. Waits for the scan to finish, then emails the outcome, duration, and any detections
         (unless the scan was stopped with DefenderStopScan.ps1, which sends its own email)

    Works while the endpoint is isolated: each email briefly opens SMTP to Gmail, then closes it.
    Uses the DPAPI-encrypted App Password stored by the Defender alert script. Optionally, an Action1
    parameter named SmtpAppPassword can supply it.

    Runner log: C:\ProgramData\DefenderScan\ScanRunner.log
#>

# ========================= CONFIG =========================
$ScanType              = 'Full'   # 'Quick' or 'Full'
$UpdateSignaturesFirst = $true        # update definitions before scanning (skipped automatically if isolated)
# ==========================================================

$ErrorActionPreference = 'Stop'
$ScanDir    = Join-Path $env:ProgramData 'DefenderScan'
$RunnerPath = Join-Path $ScanDir 'ScanRunner.ps1'
$StopMarker = Join-Path $ScanDir 'stop-requested.txt'
$PidFile    = Join-Path $ScanDir 'runner.pid'
$RunnerLog  = Join-Path $ScanDir 'ScanRunner.log'
$scanName   = if ($ScanType -eq 'Full') { 'Full Disk Scan' } else { 'Quick Scan' }

function Say { param([string]$Message) Write-Host ('{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $Message) }

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

# ===================== SCAN RUNNER (written to disk and launched) =====================
$RunnerCode = @'
# Defender scan runner. Written and launched by DefenderQuickScan.ps1 / DefenderFullScan.ps1.
# Runs in its own process so long scans aren't cut off when the Action1 script finishes.
$ScanType = if ($args.Count -gt 0) { [string]$args[0] } else { 'Quick' }
$UpdateSignaturesFirst = ($args -contains '-UpdateSignatures')
$ErrorActionPreference = 'Stop'

$ScanDir    = Join-Path $env:ProgramData 'DefenderScan'
$StopMarker = Join-Path $ScanDir 'stop-requested.txt'
$PidFile    = Join-Path $ScanDir 'runner.pid'
$RunnerLog  = Join-Path $ScanDir 'ScanRunner.log'

function Say {
    param([string]$Message)
    $line = '{0:yyyy-MM-dd HH:mm:ss} [{1}] {2}' -f (Get-Date), $ScanType, $Message
    try { Add-Content -Path $RunnerLog -Value $line } catch { }
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

# ============================== RUN ==============================
$scanName = if ($ScanType -eq 'Full') { 'Full Disk Scan' } else { 'Quick Scan' }
Set-Content -Path $PidFile -Value $PID

try {
    # Optional definitions update (skipped while isolated: Microsoft's update servers are blocked)
    $sigNote = 'Not updated before scan'
    if ($UpdateSignaturesFirst) {
        if (Test-Isolated) { $sigNote = 'Not updated (endpoint is isolated)' }
        else {
            try { Update-MpSignature -ErrorAction Stop; $sigNote = 'Updated just before scan' }
            catch { $sigNote = "Update failed: $($_.Exception.Message)" }
        }
    }
    $status = Get-MpComputerStatus
    $sigInfo = "$($status.AntivirusSignatureVersion) (last updated $($status.AntivirusSignatureLastUpdated))"

    $start = Get-Date
    Say "Starting $scanName."
    $job = Start-MpScan -ScanType "${ScanType}Scan" -AsJob

    # Confirm Defender actually started it
    $scan = $null
    for ($i = 0; $i -lt 60 -and -not $scan; $i++) {
        Start-Sleep -Seconds 2
        $scan = Get-ActiveScan -MaxHours 1
        if (-not $scan -and $job.State -in 'Completed', 'Failed') {
            $evt = Get-WinEvent -FilterHashtable @{ LogName = $LogName; Id = 1000; StartTime = $start.AddSeconds(-5) } -MaxEvents 1 -ErrorAction SilentlyContinue
            if ($evt) { $d = Get-EventData $evt; $scan = [pscustomobject]@{ ScanId = $d['Scan ID']; Type = $d['Scan Parameters']; Started = $evt.TimeCreated } }
            break
        }
    }

    if (-not $scan) {
        $reason = if ($job.State -eq 'Failed') { ($job.ChildJobs[0].JobStateInfo.Reason.Message) } else { 'Defender did not report a scan start within 2 minutes.' }
        throw "Scan did not start. $reason"
    }
    Say "Scan started (Scan ID $($scan.ScanId))."

    Send-Notice -Subject "[Scan Started] $env:COMPUTERNAME has started a Windows Defender $scanName" `
        -Headline "$env:COMPUTERNAME has started a Windows Defender $scanName" -Color '#1a5fb4' `
        -Details ([ordered]@{
            'Scan type'          = $scanName
            'Started'            = $scan.Started.ToString('yyyy-MM-dd HH:mm:ss')
            'Definitions'        = $sigInfo
            'Definitions update' = $sigNote
            'Next'               = 'Results will be emailed when the scan finishes. To stop it, run DefenderStopScan.ps1.'
        })

    Wait-Job $job | Out-Null
    Receive-Job $job -ErrorAction SilentlyContinue | Out-Null
    Start-Sleep -Seconds 5   # let Defender finish writing its events
    $finished = Get-Date

    if ((Test-Path $StopMarker) -and (Get-Item $StopMarker).LastWriteTime -ge $start) {
        Say 'Scan was stopped by DefenderStopScan.ps1, which sends its own email. Skipping results email.'
        return
    }

    $endEvt  = Get-ScanEnd -ScanId $scan.ScanId -Since $scan.Started.AddSeconds(-5)
    $outcome = switch ($endEvt.Id) {
        1001    { 'Completed' }
        1002    { 'Stopped before completion' }
        1005    { 'Failed' }
        default { if ($job.State -eq 'Failed') { 'Failed' } else { 'Finished (outcome not reported by Defender)' } }
    }
    if ($endEvt) { $finished = $endEvt.TimeCreated }
    $failReason = if ($endEvt.Id -eq 1005) { (Get-EventData $endEvt)['Error Description'] } else { $null }

    $report = Get-DetectionReport -Since $scan.Started.AddSeconds(-5)
    Say "Outcome: $outcome. Detections: $($report.Count)."

    $details = [ordered]@{
        'Scan type'              = $scanName
        'Outcome'                = $outcome
        'Started'                = $scan.Started.ToString('yyyy-MM-dd HH:mm:ss')
        'Finished'               = $finished.ToString('yyyy-MM-dd HH:mm:ss')
        'Duration'               = Format-Duration ($finished - $scan.Started)
        'Threats detected'       = $report.Count
        'Active threats on device' = $report.Active
        'Definitions'            = $sigInfo
    }
    if ($failReason) { $details['Error'] = $failReason }

    if ($outcome -eq 'Completed') {
        if ($report.Count -gt 0) {
            $subject = "[Scan Complete] $env:COMPUTERNAME $scanName found $($report.Count) threat(s)"; $color = '#b00020'; $high = $true
        } else {
            $subject = "[Scan Complete] $env:COMPUTERNAME $scanName finished, no threats found"; $color = '#1b7f3b'; $high = $false
        }
        $headline = "Windows Defender $scanName finished on $env:COMPUTERNAME"
    } elseif ($outcome -eq 'Failed') {
        $subject = "[Scan Failed] $env:COMPUTERNAME Windows Defender $scanName failed"; $color = '#b36b00'; $high = $true
        $headline = "Windows Defender $scanName failed on $env:COMPUTERNAME"
    } else {
        $subject = "[Scan Stopped] $env:COMPUTERNAME Windows Defender $scanName did not finish"; $color = '#b36b00'; $high = $true
        $headline = "Windows Defender $scanName on $env:COMPUTERNAME ended before completion"
        $details['Note'] = 'Stopped outside the Stop script (e.g. by a user, a reboot, or Defender itself).'
    }

    Send-Notice -Subject $subject -Headline $headline -Color $color -Details $details -ExtraHtml $report.Html -HighPriority:$high
} catch {
    Say "ERROR: $($_.Exception.Message)"
    Send-Notice -Subject "[Scan Failed] $env:COMPUTERNAME Windows Defender $scanName could not run" `
        -Headline "Windows Defender $scanName could not run on $env:COMPUTERNAME" -Color '#b36b00' -HighPriority `
        -Details ([ordered]@{ 'Scan type' = $scanName; 'Error' = $_.Exception.Message })
} finally {
    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
}

'@

# ---------------------------------------------------------------------------
try {
    # Pre-checks
    $status = Get-MpComputerStatus
    if (-not $status.AMServiceEnabled -or -not $status.AntivirusEnabled) {
        throw 'Windows Defender Antivirus is not enabled on this endpoint.'
    }

    $active = Get-ActiveScan
    if ($active) {
        Say "A Defender scan is already running ($($active.Type), started $($active.Started)). Not starting another."
        Say 'Stop it first with DefenderStopScan.ps1 if you want to start a different scan.'
        exit 1
    }
    if ((Test-Path $PidFile) -and (Get-Process -Id ([int](Get-Content $PidFile -Raw).Trim()) -ErrorAction SilentlyContinue)) {
        Say 'A scan runner is already active on this endpoint. Not starting another.'
        exit 1
    }

    # Prepare the working folder (SYSTEM + Administrators only)
    New-Item -ItemType Directory -Path $ScanDir -Force | Out-Null
    & icacls.exe $ScanDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    Remove-Item $StopMarker -Force -ErrorAction SilentlyContinue

    # If an App Password was passed as an Action1 parameter, store it encrypted for the runner
    if ($ProvidedPassword) {
        $ProvidedPassword | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString |
            Set-Content -Path (Join-Path $ScanDir 'smtp.cred') -Encoding ASCII
    }

    Set-Content -Path $RunnerPath -Value $RunnerCode -Encoding UTF8

    # Launch the runner as an independent process (not a child of the Action1 script)
    $argList = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$RunnerPath`" $ScanType"
    if ($UpdateSignaturesFirst) { $argList += ' -UpdateSignatures' }
    $launched = Get-Date
    $result = Invoke-CimMethod -ClassName Win32_Process -MethodName Create `
        -Arguments @{ CommandLine = "powershell.exe $argList" }
    if ($result.ReturnValue -ne 0) { throw "Could not launch the scan runner (Win32_Process.Create returned $($result.ReturnValue))." }
    Say "Scan runner launched (PID $($result.ProcessId))."

    # Wait for Defender to confirm the scan started (definitions update can take a few minutes)
    $started = $null
    for ($i = 0; $i -lt 90 -and -not $started; $i++) {
        Start-Sleep -Seconds 2
        $s = Get-ActiveScan -MaxHours 1
        if ($s -and $s.Started -ge $launched.AddSeconds(-5)) { $started = $s }
        elseif (-not (Get-Process -Id $result.ProcessId -ErrorAction SilentlyContinue)) { break }
    }

    if ($started) {
        Say "Windows Defender $scanName started at $($started.Started) (Scan ID $($started.ScanId))."
        Say "Start and results emails are sent by the runner. Log: $RunnerLog"
        exit 0
    }
    Say "WARNING: Scan start not confirmed yet. Check $RunnerLog on the endpoint."
    if (Test-Path $RunnerLog) { Get-Content $RunnerLog -Tail 5 | ForEach-Object { Say "  runner: $_" } }
    exit 2
} catch {
    Say "ERROR: $($_.Exception.Message)"
    exit 1
}
