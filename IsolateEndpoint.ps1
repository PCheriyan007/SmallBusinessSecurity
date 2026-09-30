<#
.SYNOPSIS
    Isolates a Windows endpoint from the network (EDR-style containment) while keeping
    Action1 North America connectivity so the device can still be managed remotely.

.DESCRIPTION
    Deploy through Action1 (runs as SYSTEM). The script:
      1. Checks the endpoint can reach Action1 BEFORE making changes
      2. Records every enabled local firewall rule and the firewall profile settings
         to C:\ProgramData\Isolation\isolation-state.json (used by the release script)
      3. Disables all local firewall rules and sets every profile to block inbound AND outbound
      4. Adds allow rules only for:
           - Action1 servers and North America Remote Desktop relays (TCP 443 / 22543)
           - DNS to the endpoint's configured DNS servers (so the agent can resolve Action1)
           - DHCP and IPv6 neighbor discovery (so the endpoint keeps its IP address)
      5. Verifies Action1 is still reachable. If it isn't, it rolls everything back automatically.
      6. Verifies general internet access is blocked
      7. Emails RECIPIENT EMAIL that the endpoint has been isolated (a temporary
         rule opens SMTP to Gmail only for the send, then is removed). If isolation fails
         and is rolled back, a failure email is sent instead.

    Email uses the same settings and the DPAPI-encrypted App Password stored by the
    Defender alert script (C:\ProgramData\SERVICENAME\smtp.cred). Optionally, an Action1
    parameter named SmtpAppPassword can supply it instead.

    Isolation persists across reboots until ReleaseEndpoint.ps1 is run.

    Action1 IPs source (verify before use, Action1 may change them):
    https://www.action1.com/documentation/firewall-configuration/region-north-america/
#>

$ErrorActionPreference = 'Stop'

# ========================= CONFIG =========================
$StateDir  = Join-Path $env:ProgramData 'Isolation'
$StateFile = Join-Path $StateDir 'isolation-state.json'
$RuleGroup = 'Endpoint Isolation'

# Action1 servers: server.action1.com and server.na-2.action1.com
$Action1ServerIPs = @(
    '54.210.188.13', '54.227.102.112', '3.210.54.212', '3.213.90.174',
    '44.232.42.159', '44.241.5.109', '52.41.75.35', '54.244.151.59'
)
# Action1 Remote Desktop relay servers, North America
$Action1RelayIPs = @(
    '34.203.184.16', '44.212.254.73', '52.200.246.160', '52.205.66.134', '100.24.103.37',
    '3.229.22.34', '3.88.244.142', '54.144.130.130', '44.244.87.228', '52.32.48.50',
    '52.41.51.36', '54.186.213.1', '54.244.2.21'
)
# Resolved at run time; any IPs not in the lists above are added automatically
$Action1Hostnames = @('server.action1.com', 'server.na-2.action1.com')
$Action1Ports     = @('443', '22543')
$InternetTestIP   = '1.1.1.1'   # used only to confirm general internet access is blocked
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
    To            = 'RECIPIENT EMAIL'
    From          = 'SENDER EMAIL'                 # must match Username (or a verified alias of it)
    Username      = 'SENDER EMAIL'
    RelayServer   = 'smtp-relay.gmail.com'                      # tried FIRST: IP-allowlisted Workspace relay, no login
    SmtpServer    = 'smtp.gmail.com'                            # FALLBACK: authenticated Gmail SMTP with App Password
    UseRelayFirst = $true
    Port          = 587
    # Reuses the DPAPI-encrypted App Password stored by the Defender alert script on this endpoint
    CredFile      = Join-Path $env:ProgramData 'SERVICENAME\smtp.cred'
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

function Test-Action1Reachable {
    foreach ($ip in $Action1ServerIPs) {
        if (Test-Tcp -IP $ip -Port 443) { return $ip }
    }
    return $null
}

function Restore-FromState {
    Say 'Rolling back isolation...'
    $state = Get-Content $StateFile -Raw | ConvertFrom-Json
    Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    foreach ($p in $state.Profiles) {
        Set-NetFirewallProfile -Name $p.Name -Enabled $p.Enabled `
            -DefaultInboundAction $p.DefaultInboundAction -DefaultOutboundAction $p.DefaultOutboundAction
    }
    if ($state.EnabledRules.Count -gt 0) {
        Enable-NetFirewallRule -Name $state.EnabledRules -ErrorAction SilentlyContinue
    }
    Remove-Item $StateFile -Force
    Say 'Rollback complete. Endpoint is NOT isolated.'
}

function Stop-WithRollback {
    param([string]$Reason)
    Say "ERROR: $Reason"
    try { Restore-FromState } catch { Say "ERROR during rollback: $($_.Exception.Message)" }
    Send-Notice -Subject "[Isolation FAILED] $env:COMPUTERNAME was NOT isolated" `
        -Headline "Isolation of $env:COMPUTERNAME failed and was rolled back" -Color '#b36b00' `
        -Details ([ordered]@{ 'Reason' = $Reason; 'Current status' = 'NOT isolated (normal network access restored)' })
    exit 1
}

# ---------------------------------------------------------------------------
if (Test-Path $StateFile) {
    Say "Endpoint is already isolated (state file exists: $StateFile). Nothing to do."
    exit 0
}

# 1. Pre-flight: resolve Action1 hostnames and confirm connectivity before changing anything
foreach ($h in $Action1Hostnames) {
    try {
        $resolved = (Resolve-DnsName -Name $h -Type A -ErrorAction Stop | Where-Object { $_.Type -eq 'A' }).IPAddress
        foreach ($ip in $resolved) {
            if ($ip -notin $Action1ServerIPs) {
                Say "Adding $ip (resolved from $h, not in the documented list)."
                $Action1ServerIPs += $ip
            }
        }
    } catch { Say "WARNING: Could not resolve $h ($($_.Exception.Message))." }
}

if (-not (Test-Action1Reachable)) {
    Say 'ERROR: No Action1 server is reachable on TCP 443 right now. Aborting without changes.'
    Send-Notice -Subject "[Isolation FAILED] $env:COMPUTERNAME was NOT isolated" `
        -Headline "Isolation of $env:COMPUTERNAME was aborted" -Color '#b36b00' `
        -Details ([ordered]@{
            'Reason'         = 'No Action1 server was reachable before isolating, so no changes were made (isolating would have cut off remote access).'
            'Current status' = 'NOT isolated (no changes made)'
        })
    exit 1
}

$dnsServers = @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
    ForEach-Object { $_.ServerAddresses } | Where-Object { $_ } | Select-Object -Unique)
if ($dnsServers.Count -eq 0) { Say 'WARNING: No DNS servers found; the agent may be unable to resolve Action1.' }

# Warn about Group Policy firewall rules, which this script can't disable locally
$gpoAllow = @(Get-NetFirewallRule -PolicyStore RSOP -ErrorAction SilentlyContinue |
    Where-Object { $_.Enabled -eq 'True' -and $_.Action -eq 'Allow' })
if ($gpoAllow.Count -gt 0) {
    Say "WARNING: $($gpoAllow.Count) allow rule(s) come from Group Policy and will stay active during isolation."
}

# 2. Record current state
New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
& icacls.exe $StateDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null

$enabledRules = @(Get-NetFirewallRule -PolicyStore PersistentStore |
    Where-Object { $_.Enabled -eq 'True' } | Select-Object -ExpandProperty Name)
$profiles = @(Get-NetFirewallProfile -PolicyStore PersistentStore | ForEach-Object {
    [pscustomobject]@{
        Name                  = [string]$_.Name
        Enabled               = [string]$_.Enabled
        DefaultInboundAction  = [string]$_.DefaultInboundAction
        DefaultOutboundAction = [string]$_.DefaultOutboundAction
    }
})

[pscustomobject]@{
    IsolatedAt   = (Get-Date).ToString('o')
    Computer     = $env:COMPUTERNAME
    Profiles     = $profiles
    EnabledRules = $enabledRules
    AllowedIPs   = $Action1ServerIPs + $Action1RelayIPs
    DnsServers   = $dnsServers
} | ConvertTo-Json -Depth 4 | Set-Content -Path $StateFile -Encoding UTF8
Say "Saved state: $($enabledRules.Count) enabled rule(s) and $($profiles.Count) profile(s)."

# 3-4. Isolate
try {
    # Allow rules first, so there's no window where Action1 is blocked
    $common = @{ Group = $RuleGroup; Enabled = 'True'; Profile = 'Any'; Action = 'Allow' }

    New-NetFirewallRule @common -DisplayName 'ISOLATION - Action1 servers' -Direction Outbound `
        -Protocol TCP -RemoteAddress $Action1ServerIPs -RemotePort $Action1Ports | Out-Null
    New-NetFirewallRule @common -DisplayName 'ISOLATION - Action1 Remote Desktop relays (NA)' -Direction Outbound `
        -Protocol TCP -RemoteAddress $Action1RelayIPs -RemotePort $Action1Ports | Out-Null

    if ($dnsServers.Count -gt 0) {
        New-NetFirewallRule @common -DisplayName 'ISOLATION - DNS (UDP)' -Direction Outbound `
            -Protocol UDP -RemoteAddress $dnsServers -RemotePort 53 | Out-Null
        New-NetFirewallRule @common -DisplayName 'ISOLATION - DNS (TCP)' -Direction Outbound `
            -Protocol TCP -RemoteAddress $dnsServers -RemotePort 53 | Out-Null
    }

    New-NetFirewallRule @common -DisplayName 'ISOLATION - DHCP out' -Direction Outbound `
        -Protocol UDP -LocalPort 68 -RemotePort 67 | Out-Null
    New-NetFirewallRule @common -DisplayName 'ISOLATION - DHCP in' -Direction Inbound `
        -Protocol UDP -LocalPort 68 -RemotePort 67 | Out-Null
    New-NetFirewallRule @common -DisplayName 'ISOLATION - DHCPv6 out' -Direction Outbound `
        -Protocol UDP -LocalPort 546 -RemotePort 547 | Out-Null
    New-NetFirewallRule @common -DisplayName 'ISOLATION - DHCPv6 in' -Direction Inbound `
        -Protocol UDP -LocalPort 546 -RemotePort 547 | Out-Null

    foreach ($dir in 'Inbound', 'Outbound') {
        New-NetFirewallRule @common -DisplayName "ISOLATION - IPv6 neighbor discovery ($dir)" -Direction $dir `
            -Protocol ICMPv6 -IcmpType 133, 134, 135, 136 | Out-Null
    }

    # Disable every other local rule, then block by default on all profiles
    if ($enabledRules.Count -gt 0) { Disable-NetFirewallRule -Name $enabledRules }
    Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True `
        -DefaultInboundAction Block -DefaultOutboundAction Block
    Say 'Isolation rules applied.'
} catch {
    Stop-WithRollback "Error while applying isolation: $($_.Exception.Message)"
}

# 5. Confirm the effective (merged) policy is actually blocking, and Action1 still works
Start-Sleep -Seconds 3
$notBlocking = @(Get-NetFirewallProfile -PolicyStore ActiveStore |
    Where-Object { -not $_.Enabled -or $_.DefaultOutboundAction -ne 'Block' })
if ($notBlocking.Count -gt 0) {
    Stop-WithRollback "Group Policy is overriding the firewall on profile(s): $($notBlocking.Name -join ', ')."
}

$reached = Test-Action1Reachable
if (-not $reached) {
    Stop-WithRollback 'Action1 was unreachable after isolation, so it was rolled back to keep remote access.'
}
Say "Action1 still reachable (${reached}:443)."

# 6. Confirm general internet access is blocked
$internetBlocked = -not (Test-Tcp -IP $InternetTestIP -Port 443)
if ($internetBlocked) {
    Say "Confirmed general internet access is blocked (${InternetTestIP}:443 unreachable)."
    $internetStatus = 'Blocked (confirmed)'
} else {
    Say "WARNING: ${InternetTestIP}:443 is still reachable. Something is bypassing isolation (check Group Policy rules)."
    $internetStatus = 'WARNING: still reachable. Something is bypassing isolation (check Group Policy rules)'
}

# 7. Notify IT
Send-Notice -ThroughIsolation `
    -Subject "[Isolated] $env:COMPUTERNAME has been isolated from the network" `
    -Headline "$env:COMPUTERNAME has been isolated from the network" -Color '#b00020' `
    -Details ([ordered]@{
        'Status'               = 'Isolated: only Action1 management traffic is allowed'
        'Action1 connectivity' = "Confirmed (${reached}:443)"
        'General internet'     = $internetStatus
        'To reconnect'         = 'Run ReleaseEndpoint.ps1 from Action1'
    })

if (-not $internetBlocked) { exit 2 }
Say "ENDPOINT ISOLATED. Run ReleaseEndpoint.ps1 to restore normal network access."
exit 0
