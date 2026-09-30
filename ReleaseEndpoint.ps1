<#
.SYNOPSIS
    Releases an endpoint isolated by Blvd-Isolate-Endpoint.ps1 and restores normal network access.

.DESCRIPTION
    Deploy through Action1 (runs as SYSTEM). The script:
      1. Removes the isolation allow rules
      2. Restores each firewall profile's previous settings (enabled state, default inbound/outbound action)
      3. Re-enables exactly the firewall rules that were enabled before isolation
      4. Deletes the saved state and verifies internet access is back
      5. Emails it-admin@blvdautoinc.com that the endpoint has been reconnected
         (or that the release failed)

    Email uses the same settings and the DPAPI-encrypted App Password stored by the
    Defender alert script (C:\ProgramData\BlvdDefenderAlert\smtp.cred). Optionally, an Action1
    parameter named SmtpAppPassword can supply it instead.

    If the state file is missing (e.g. deleted), it falls back to Windows defaults
    (firewall on, block inbound, allow outbound). Rules disabled during isolation stay
    disabled in that case, because the script can't know which were on; review them afterwards.
#>

$ErrorActionPreference = 'Stop'

# ========================= CONFIG =========================
$StateDir       = Join-Path $env:ProgramData 'BlvdIsolation'
$StateFile      = Join-Path $StateDir 'isolation-state.json'
$RuleGroup      = 'BLVD Endpoint Isolation'
$InternetTestIP = '1.1.1.1'
# ==========================================================

function Say { param([string]$Message) Write-Host ('{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $Message) }

function Test-Tcp {
    param([string]$IP, [int]$Port, [int]$TimeoutMs = 4000)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($IP, $Port, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs)) { $client.EndConnect($iar); return $true }
        return $false
    } catch { return $false } finally { $client.Close() }
}

# ===================== EMAIL CONFIG (same as Defender alert script) =====================
$Mail = @{
    To            = 'it-admin@blvdautoinc.com'
    From          = 'pcheriyan@blvdautoinc.com'                 # must match Username (or a verified alias of it)
    Username      = 'pcheriyan@blvdautoinc.com'
    RelayServer   = 'smtp-relay.gmail.com'                      # tried FIRST: IP-allowlisted Workspace relay, no login
    SmtpServer    = 'smtp.gmail.com'                            # FALLBACK: authenticated Gmail SMTP with App Password
    UseRelayFirst = $true
    Port          = 587
    # Reuses the DPAPI-encrypted App Password stored by the Defender alert script on this endpoint
    CredFile      = Join-Path $env:ProgramData 'BlvdDefenderAlert\smtp.cred'
}
# Optional: an Action1 parameter named SmtpAppPassword overrides the stored credential
$ProvidedPassword = if ($SmtpAppPassword) { [string]$SmtpAppPassword } elseif ($env:SmtpAppPassword) { $env:SmtpAppPassword } else { '' }
$ProvidedPassword = $ProvidedPassword -replace '\s', ''
$MailRuleName     = 'ISOLATION - TEMP notification email'
# =========================================================================================

function Get-MailCredential {
    if ($ProvidedPassword) { return New-Object System.Net.NetworkCredential($Mail.Username, $ProvidedPassword) }
    if (Test-Path $Mail.CredFile) {
        $secure = (Get-Content -Path $Mail.CredFile -Raw).Trim() | ConvertTo-SecureString
        return New-Object System.Net.NetworkCredential($Mail.Username, $secure)
    }
    throw "No SMTP credential found ($($Mail.CredFile) missing and no SmtpAppPassword parameter)."
}

function Send-Mail {
    param([string]$Subject, [string]$Html)
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $send = {
        param($Server, $Credential)
        $msg = New-Object System.Net.Mail.MailMessage($Mail.From, $Mail.To, $Subject, $Html)
        $msg.IsBodyHtml = $true
        $msg.Priority   = [System.Net.Mail.MailPriority]::High
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

# Briefly allows outbound SMTP to Gmail's current addresses while the endpoint is isolated
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
    param([string]$Subject, [string]$Headline, [string]$Color, [System.Collections.IDictionary]$Details, [switch]$ThroughIsolation)
    try {
        if ($ThroughIsolation) { Open-MailChannel }
        $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
        $cs  = Get-CimInstance Win32_ComputerSystem
        $ips = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' }).IPAddress -join ', '

        $rows = [ordered]@{
            'Computer'       = $env:COMPUTERNAME
            'Domain'         = $cs.Domain
            'Logged-on user' = if ($cs.UserName) { $cs.UserName } else { '(none)' }
            'IP address(es)' = $ips
            'Time'           = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
        }
        if ($Details) { foreach ($k in $Details.Keys) { $rows[$k] = $Details[$k] } }
        $tr = foreach ($k in $rows.Keys) { "<tr><td><b>$(& $enc $k)</b></td><td>$(& $enc $rows[$k])</td></tr>" }

        $html = @"
<html><body style="font-family:Segoe UI,Arial,sans-serif;font-size:13px">
<h2 style="color:$Color">$(& $enc $Headline)</h2>
<table style="border-collapse:collapse" cellpadding="4">
$($tr -join "`n")
</table>
<p style="color:#666">Sent by the Action1-deployed endpoint isolation script.</p>
</body></html>
"@
        Send-Mail -Subject $Subject -Html $html
    } catch {
        Say "WARNING: Could not send notification email ($($_.Exception.Message))."
    } finally {
        if ($ThroughIsolation) { Close-MailChannel }
    }
}

function Send-ReleaseFailure {
    param([string]$Reason)
    Send-Notice -ThroughIsolation -Subject "[Release FAILED] $env:COMPUTERNAME may still be isolated" `
        -Headline "Reconnecting $env:COMPUTERNAME to the network failed" -Color '#b36b00' `
        -Details ([ordered]@{ 'Reason' = $Reason; 'Current status' = 'May still be isolated. Check the Action1 run output.' })
}

try {
    $isolationRules = @(Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue)

    if (Test-Path $StateFile) {
        $state = Get-Content $StateFile -Raw | ConvertFrom-Json
        Say "Found isolation state from $($state.IsolatedAt)."

        # Restore profiles first (allow outbound again), then rules, then remove isolation rules
        foreach ($p in $state.Profiles) {
            Set-NetFirewallProfile -Name $p.Name -Enabled $p.Enabled `
                -DefaultInboundAction $p.DefaultInboundAction -DefaultOutboundAction $p.DefaultOutboundAction
        }
        Say "Restored $(@($state.Profiles).Count) firewall profile(s)."

        $rules = @($state.EnabledRules)
        if ($rules.Count -gt 0) {
            $missing = @()
            foreach ($name in $rules) {
                try { Enable-NetFirewallRule -Name $name -ErrorAction Stop } catch { $missing += $name }
            }
            Say "Re-enabled $($rules.Count - $missing.Count) of $($rules.Count) rule(s)."
            if ($missing.Count -gt 0) { Say "NOTE: $($missing.Count) rule(s) no longer exist and were skipped." }
        }
    } elseif ($isolationRules.Count -gt 0) {
        Say 'WARNING: State file missing. Falling back to Windows default firewall behavior.'
        Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True `
            -DefaultInboundAction Block -DefaultOutboundAction Allow
        Say 'Profiles set to: firewall on, block inbound, allow outbound.'
        Say 'Previously enabled rules are unknown. Rules remain disabled; review them or reset with: netsh advfirewall reset'
    } else {
        Say 'Endpoint does not appear to be isolated (no state file, no isolation rules). Nothing to do.'
        exit 0
    }

    if ($isolationRules.Count -gt 0) {
        $isolationRules | Remove-NetFirewallRule
        Say "Removed $($isolationRules.Count) isolation rule(s)."
    }

    if (Test-Path $StateDir) { Remove-Item $StateDir -Recurse -Force }
} catch {
    Say "ERROR during release: $($_.Exception.Message)"
    Send-ReleaseFailure "Error during release: $($_.Exception.Message)"
    exit 1
}

# Verify
Start-Sleep -Seconds 3
if (Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue) {
    Say 'ERROR: Isolation rules still present.'
    Send-ReleaseFailure 'Isolation firewall rules are still present after release.'
    exit 1
}

$internetOk = Test-Tcp -IP $InternetTestIP -Port 443
if ($internetOk) {
    Say "Internet access confirmed (${InternetTestIP}:443 reachable)."
    $internetStatus = 'Restored (confirmed)'
} else {
    Say "WARNING: ${InternetTestIP}:443 still unreachable. Firewall is restored, but check other network controls."
    $internetStatus = 'WARNING: still unreachable. Firewall is restored, but check other network controls'
}

Send-Notice -Subject "[Reconnected] $env:COMPUTERNAME has been reconnected to the network" `
    -Headline "$env:COMPUTERNAME has been reconnected to the network" -Color '#1b7f3b' `
    -Details ([ordered]@{
        'Status'           = 'Released: previous firewall configuration restored'
        'General internet' = $internetStatus
    })

if (-not $internetOk) { exit 2 }
Say 'ENDPOINT RELEASED. Normal network access restored.'
exit 0
