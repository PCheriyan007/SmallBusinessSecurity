<#
.SYNOPSIS
    Configures Google Chrome Cloud Management Enrollment Token and resets stale device tokens remotely.
#>

# --- CONFIGURATION ---
$EnrollmentToken = "TOKEN" # Using placeholder value TOKEN in place of actual Google Workspace token.

Write-Host "Starting Chrome Cloud Management enrollment process..."

# 1. Set CloudManagementEnrollmentToken Registry Key
$ChromePolicyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"

if (!(Test-Path $ChromePolicyPath)) {
    Write-Host "Creating registry key: $ChromePolicyPath"
    New-Item -Path $ChromePolicyPath -Force | Out-Null
}

Set-ItemProperty -Path $ChromePolicyPath -Name "CloudManagementEnrollmentToken" -Value $EnrollmentToken -Type String -Force
Write-Host "SUCCESS: CloudManagementEnrollmentToken set to $EnrollmentToken"

# 2. Check and Delete Existing DMTokens if present in 64-bit or 32-bit locations
$Path64 = "HKLM:\SOFTWARE\Google\Chrome\Enrollment"
$Path32 = "HKLM:\SOFTWARE\WOW6432Node\Google\Enrollment"

function Clear-DMToken {
    param ([string]$BasePath)

    if (Test-Path $BasePath) {
        # Search direct key and subkeys for 'dmtoken' or 'DMToken'
        $Keys = Get-ChildItem -Path $BasePath -Recurse -ErrorAction SilentlyContinue
        $AllPaths = @($BasePath) + ($Keys | Select-Object -ExpandProperty PSPath)

        foreach ($Path in $AllPaths) {
            $Props = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
            if ($Props.dmtoken -or $Props.DMToken) {
                Write-Host "Found DMToken at $Path. Removing..."
                Remove-ItemProperty -Path $Path -Name "dmtoken" -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path $Path -Name "DMToken" -ErrorAction SilentlyContinue
            }
        }
    }
}

Write-Host "Checking for existing device tokens..."
Clear-DMToken -BasePath $Path64
Clear-DMToken -BasePath $Path32

# 3. Terminate Running Chrome Instances
$ChromeProcesses = Get-Process -Name "chrome" -ErrorAction SilentlyContinue

if ($ChromeProcesses) {
    Write-Host "Closing active Google Chrome instances..."
    Stop-Process -Name "chrome" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Write-Host "Chrome processes stopped. Policy will take effect when users open Chrome."
} else {
    Write-Host "Chrome was not running. Token will take effect on next launch."
}
