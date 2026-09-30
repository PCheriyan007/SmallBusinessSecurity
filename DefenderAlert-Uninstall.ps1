<#
.SYNOPSIS
    Removes everything installed by the Defender alert script (DefenderAlert.ps1).

.DESCRIPTION
    Deploy through Action1 (runs as SYSTEM). Reverses all changes the alert script makes:
      1. Stops and deletes the scheduled task (by name, plus any task that points at the install folder)
      2. Deletes the install folder and its contents:
           DefenderAlert.ps1, smtp.cred (encrypted password), lastRecordId.txt,
           DefenderAlert.log, DefenderAlert.log.old
         (the folder's locked-down permissions are removed with it)
      3. Verifies both are gone and exits 0 on success, 1 if anything remains

    The alert script makes no other changes (no registry keys, services, or system settings).

    IMPORTANT: Disable or delete the Action1 Automation that runs DefenderAlert.ps1 first,
    or its next scheduled run will reinstall everything.
#>

# ========================= CONFIG =========================
# Must match the values used in DefenderAlert.ps1
$InstallFolderName = 'SERVICENAME'     # $InstallDir folder name under C:\ProgramData
$TaskName          = 'SERVICE NAME'    # $TaskName
# ==========================================================

$ErrorActionPreference = 'Continue'
$InstallDir = Join-Path $env:ProgramData $InstallFolderName
$problems   = @()

function Say { param([string]$Message) Write-Host ('{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $Message) }

# --- 1. Scheduled task(s) ---------------------------------------------------
$tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.TaskName -eq $TaskName -or
    ($_.Actions | Where-Object { $_.Arguments -like "*$InstallDir*" })
})

if ($tasks.Count -eq 0) {
    Say "No scheduled task found (name '$TaskName' or pointing at $InstallDir)."
}

foreach ($t in $tasks) {
    try {
        if ($t.State -eq 'Running') {
            Stop-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop
            Say "Stopped running task '$($t.TaskPath)$($t.TaskName)'."
        }
        Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction Stop
        Say "Deleted scheduled task '$($t.TaskPath)$($t.TaskName)'."
    } catch {
        $problems += "Could not delete task '$($t.TaskName)': $($_.Exception.Message)"
    }
}

# Give any in-flight alert run a moment to exit so its files aren't locked
Start-Sleep -Seconds 3

# --- 2. Install folder --------------------------------------------------------
if (Test-Path $InstallDir) {
    for ($attempt = 1; $attempt -le 3 -and (Test-Path $InstallDir); $attempt++) {
        try {
            Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction Stop
        } catch {
            if ($attempt -eq 2) {
                # Permissions may have been altered; take ownership and reset them, then retry
                & takeown.exe /F $InstallDir /R /A /D Y | Out-Null
                & icacls.exe $InstallDir /reset /T /C /Q | Out-Null
            }
            Start-Sleep -Seconds 5
        }
    }
    if (Test-Path $InstallDir) {
        $problems += "Could not delete $InstallDir"
    } else {
        Say "Deleted $InstallDir (script, encrypted credential, state file, and logs)."
    }
} else {
    Say "Install folder $InstallDir not found."
}

# --- 3. Verify ----------------------------------------------------------------
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    $problems += "Scheduled task '$TaskName' still exists."
}
if (Test-Path $InstallDir) {
    $problems += "$InstallDir still exists."
}

if ($problems.Count -gt 0) {
    $problems | ForEach-Object { Say "ERROR: $_" }
    exit 1
}

Say 'Uninstall complete. No Defender alert components remain on this endpoint.'
exit 0
