<#
.SYNOPSIS
    Emails RECIPIENT EMAIL when Microsoft Defender logs a detection (Event 1116)
    or takes action on a threat (Event 1117).

.DESCRIPTION
    Deploy through Action1 (runs as SYSTEM). On each Action1 run the script:
      1. Installs/updates itself to C:\ProgramData\SERVICENAME (locked to SYSTEM + Administrators)
      2. Registers a local scheduled task that fires within ~30 seconds of any 1116/1117 event,
         plus an hourly sweep as a safety net (e.g. if the machine was offline when email failed)
      3. Runs an immediate check

    State is tracked by event RecordId, so each detection is emailed once. The state file is only
    updated after the email is sent successfully, so failed sends are retried on the next run.

.NOTES
    The SMTP App Password is NOT stored in this script. Supply it as an Action1 script
    parameter named SmtpAppPassword (type String), set on the Automation. On each Action1 run
    the script encrypts it with DPAPI (SYSTEM account) into C:\ProgramData\SERVICENAME\smtp.cred.
    The local scheduled task runs this script with -Notify and reads the encrypted file.

    Uninstall: run with -Uninstall, or in Action1 run:
      Unregister-ScheduledTask 'SERVICE NAME' -Confirm:$false; Remove-Item "$env:ProgramData\SERVICENAME" -Recurse -Force
#>

# Switches are read from $args (no param block) so Action1's injected parameter variables can't break parsing
$Notify    = $args -contains '-Notify'
$Uninstall = $args -contains '-Uninstall'

# Password comes from the Action1 parameter (PowerShell variable or environment variable); blank on scheduled-task runs
$ProvidedPassword = if ($SmtpAppPassword) { [string]$SmtpAppPassword } elseif ($env:SmtpAppPassword) { $env:SmtpAppPassword } else { '' }
$ProvidedPassword = $ProvidedPassword -replace '\s', ''   # Google shows App Passwords with spaces

# ========================= CONFIG =========================
$Config = @{
    To                    = 'RECIPIENT EMAIL'                   # placeholder value for destination email value
    From                  = 'SENDER EMAIL'                      # must match Username (or a verified alias of it)
    RelayServer           = 'smtp-relay.gmail.com'              # tried FIRST: IP-allowlisted Workspace relay, no login
    SmtpServer            = 'smtp.gmail.com'                    # FALLBACK: authenticated Gmail SMTP with App Password
    UseRelayFirst         = $true                               # set $false to skip the relay and always log in
    Port                  = 587                                 # must be 587 (STARTTLS); .NET SmtpClient can't do 465
    UseSsl                = $true
    Username              = 'SENDER EMAIL'         # the Workspace user the alerts send from
    Password              = $ProvidedPassword                   # from Action1 parameter SmtpAppPassword; never hard-code it here
    FirstRunLookbackHours = 24                                  # how far back to look on first install
}
# ==========================================================

$ErrorActionPreference = 'Stop'
$InstallDir = Join-Path $env:ProgramData 'SERVICENAME'
$ScriptPath = Join-Path $InstallDir 'DefenderAlert.ps1'
$StateFile  = Join-Path $InstallDir 'lastRecordId.txt'
$LogFile    = Join-Path $InstallDir 'DefenderAlert.log'
$CredFile   = Join-Path $InstallDir 'smtp.cred'
$TaskName   = 'SERVICE NAME'
$LogName    = 'Microsoft-Windows-Windows Defender/Operational'

function Write-Log {
    param([string]$Message)
    $line = '{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $Message
    Write-Host $line
    try {
        if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }
        if ((Test-Path $LogFile) -and (Get-Item $LogFile).Length -gt 1MB) {
            Move-Item $LogFile "$LogFile.old" -Force
        }
        Add-Content -Path $LogFile -Value $line
    } catch { }
}

function Install-Self {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

    # Lock the folder down first so everything written below inherits SYSTEM + Administrators only
    & icacls.exe $InstallDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null

    # Copy this script into place, scrubbing the password in case Action1 injected it into the script text
    $selfText = if ($PSCommandPath -and (Test-Path $PSCommandPath)) { Get-Content -Path $PSCommandPath -Raw } else { $script:SelfText }
    if ($Config.Password) { $selfText = $selfText.Replace($Config.Password, '') }
    if ($SmtpAppPassword) { $selfText = $selfText.Replace([string]$SmtpAppPassword, '') }
    Set-Content -Path $ScriptPath -Value $selfText -Encoding UTF8

    # Store the password encrypted with DPAPI under the SYSTEM account (only SYSTEM on this PC can decrypt it)
    if ($Config.Password) {
        $Config.Password | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString |
            Set-Content -Path $CredFile -Encoding ASCII
    } elseif (-not (Test-Path $CredFile)) {
        Write-Log 'WARNING: No SmtpAppPassword parameter provided and no stored credential. Only the relay path will work.'
    }

    $start = (Get-Date).ToString('s')
    $taskXml = @"
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Emails IT when Microsoft Defender logs Event 1116/1117. Deployed via Action1.</Description>
  </RegistrationInfo>
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="$LogName"&gt;&lt;Select Path="$LogName"&gt;*[System[(EventID=1116 or EventID=1117)]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
      <Delay>PT30S</Delay>
    </EventTrigger>
    <TimeTrigger>
      <Enabled>true</Enabled>
      <StartBoundary>$start</StartBoundary>
      <Repetition>
        <Interval>PT1H</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>Queue</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "$ScriptPath" -Notify</Arguments>
    </Exec>
  </Actions>
</Task>
"@
    Register-ScheduledTask -TaskName $TaskName -Xml $taskXml -Force | Out-Null
    Write-Log "Installed/updated script at $ScriptPath and registered task '$TaskName'."
}

function Uninstall-Self {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Removed task '$TaskName' and $InstallDir."
}

function Get-NewDefenderEvents {
    [long]$lastId = 0
    if (Test-Path $StateFile) {
        [long]::TryParse((Get-Content $StateFile -Raw).Trim(), [ref]$lastId) | Out-Null
    }

    # If the log was cleared, RecordIds restart; reset our marker
    try {
        $newest = Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction Stop
        if ($newest.RecordId -lt $lastId) { Write-Log 'Log appears to have been cleared; resetting marker.'; $lastId = 0 }
    } catch { }

    $startTime = if ($lastId -gt 0) { (Get-Date).AddDays(-7) } else { (Get-Date).AddHours(-$Config.FirstRunLookbackHours) }

    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = $LogName; Id = 1116, 1117; StartTime = $startTime } -ErrorAction Stop
    } catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return @() }
        throw
    }

    return @($events | Where-Object { $_.RecordId -gt $lastId } | Sort-Object RecordId)
}

function ConvertFrom-DefenderEvent {
    param($Event)
    $xml  = [xml]$Event.ToXml()
    $data = @{}
    foreach ($node in $xml.Event.EventData.Data) { $data[$node.Name] = $node.'#text' }

    [pscustomobject]@{
        Time        = $Event.TimeCreated
        EventId     = $Event.Id
        Type        = if ($Event.Id -eq 1116) { 'Detected' } else { 'Action taken' }
        Threat      = $data['Threat Name']
        Severity    = $data['Severity Name']
        Category    = $data['Category Name']
        Path        = ($data['Path'] -replace '(^|;)\w+:_', '$1')
        Process     = $data['Process Name']
        User        = $data['Detection User']
        Action      = $data['Action Name']
        DetectionId = $data['Detection ID']
        RecordId    = $Event.RecordId
    }
}

function Get-SmtpCredential {
    if (-not $Config.Username) { return $null }
    if ($Config.Password) {
        return New-Object System.Net.NetworkCredential($Config.Username, $Config.Password)
    }
    if (Test-Path $CredFile) {
        $secure = (Get-Content -Path $CredFile -Raw).Trim() | ConvertTo-SecureString
        return New-Object System.Net.NetworkCredential($Config.Username, $secure)
    }
    throw "No SMTP password found. Re-run the script from Action1 to store the credential."
}

function Send-Via {
    param([string]$Server, $Credential, [string]$Subject, [string]$HtmlBody, [bool]$HighPriority)
    $msg = New-Object System.Net.Mail.MailMessage($Config.From, $Config.To, $Subject, $HtmlBody)
    $msg.IsBodyHtml = $true
    if ($HighPriority) { $msg.Priority = [System.Net.Mail.MailPriority]::High }
    $smtp = New-Object System.Net.Mail.SmtpClient($Server, $Config.Port)
    $smtp.EnableSsl = $Config.UseSsl
    $smtp.Timeout   = 20000   # 20s, so a failed relay attempt falls back quickly
    if ($Credential) { $smtp.Credentials = $Credential }
    try { $smtp.Send($msg) } finally { $msg.Dispose(); $smtp.Dispose() }
}

function Send-Alert {
    param([string]$Subject, [string]$HtmlBody, [bool]$HighPriority)
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    if ($Config.UseRelayFirst -and $Config.RelayServer) {
        try {
            Send-Via -Server $Config.RelayServer -Credential $null -Subject $Subject -HtmlBody $HtmlBody -HighPriority $HighPriority
            Write-Log "Sent via IP-allowlisted relay ($($Config.RelayServer))."
            return
        } catch {
            $err = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
            Write-Log "Relay failed ($err). Falling back to authenticated SMTP."
        }
    }

    Send-Via -Server $Config.SmtpServer -Credential (Get-SmtpCredential) -Subject $Subject -HtmlBody $HtmlBody -HighPriority $HighPriority
    Write-Log "Sent via authenticated SMTP ($($Config.SmtpServer))."
}

function Invoke-Check {
    $events = Get-NewDefenderEvents
    if ($events.Count -eq 0) { Write-Log 'No new Defender detections.'; return }

    $rows = @($events | ForEach-Object { ConvertFrom-DefenderEvent $_ })
    $enc  = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }

    # Endpoint context
    $cs       = Get-CimInstance Win32_ComputerSystem
    $os       = Get-CimInstance Win32_OperatingSystem
    $ips      = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                 Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' }).IPAddress -join ', '
    $loggedOn = if ($cs.UserName) { $cs.UserName } else { '(none)' }

    $tableRows = foreach ($r in $rows) {
        "<tr><td>$(& $enc $r.Time)</td><td>$($r.EventId) - $(& $enc $r.Type)</td><td><b>$(& $enc $r.Threat)</b></td>" +
        "<td>$(& $enc $r.Severity)</td><td>$(& $enc $r.Category)</td><td>$(& $enc $r.Action)</td>" +
        "<td style='word-break:break-all'>$(& $enc $r.Path)</td><td>$(& $enc $r.Process)</td><td>$(& $enc $r.User)</td></tr>"
    }

    $html = @"
<html><body style="font-family:Segoe UI,Arial,sans-serif;font-size:13px">
<h2 style="color:#b00020">Microsoft Defender alert on $(& $enc $env:COMPUTERNAME)</h2>
<table style="border-collapse:collapse" cellpadding="4">
<tr><td><b>Computer</b></td><td>$(& $enc $env:COMPUTERNAME)</td></tr>
<tr><td><b>Domain</b></td><td>$(& $enc $cs.Domain)</td></tr>
<tr><td><b>Logged-on user</b></td><td>$(& $enc $loggedOn)</td></tr>
<tr><td><b>IP address(es)</b></td><td>$(& $enc $ips)</td></tr>
<tr><td><b>OS</b></td><td>$(& $enc $os.Caption) ($(& $enc $os.Version))</td></tr>
</table><br/>
<table border="1" style="border-collapse:collapse" cellpadding="5">
<tr style="background:#eee"><th>Time</th><th>Event</th><th>Threat</th><th>Severity</th><th>Category</th><th>Action</th><th>Path</th><th>Process</th><th>Detection user</th></tr>
$($tableRows -join "`n")
</table>
<p style="color:#666">Sent by the Action1-deployed Defender alert script.</p>
</body></html>
"@

    $threats = ($rows.Threat | Where-Object { $_ } | Select-Object -Unique) -join ', '
    if ($threats.Length -gt 120) { $threats = $threats.Substring(0, 117) + '...' }
    $subject = "[Defender] $($env:COMPUTERNAME): $threats"
    $high    = [bool]($rows | Where-Object { $_.Severity -in 'High', 'Severe' })

    Send-Alert -Subject $subject -HtmlBody $html -HighPriority $high

    $maxId = ($events | Measure-Object -Property RecordId -Maximum).Maximum
    Set-Content -Path $StateFile -Value $maxId
    Write-Log "Emailed $($rows.Count) event(s) to $($Config.To): $threats"
}

# ========================= MAIN =========================
$script:SelfText = $MyInvocation.MyCommand.ScriptBlock.ToString()

try {
    if ($Uninstall) { Uninstall-Self; exit 0 }
    if (-not $Notify) { Install-Self }
    Invoke-Check
    exit 0
} catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    exit 1
}
