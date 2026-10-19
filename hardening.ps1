# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danang Galuh Tegar Prasetyo
#
# Entry script of https://github.com/danang-id/server-hardening
#
# It shows what machine it is on (operating system, kernel, processor) and
# whether the tool supports it. On a machine that is not supported it says why
# and stops, without downloading the tool. On a supported machine it downloads
# the matching binary from the latest release, checks it against the checksum
# list of that release, explains why administrator access is needed, waits for
# Enter, and starts the tool.
#
#   powershell -c "irm https://raw.githubusercontent.com/danang-id/server-hardening/refs/heads/main/hardening.ps1 | iex"
#
# What is supported is not written here. The release carries a file, SUPPORTED,
# with one line per system: the system ID, the version and the processors, for
# example "debian 13 amd64 arm64". This script reads the lines with the ID
# "windows", whose version is the year of the Windows Server release, for
# example "windows 2025 amd64". The release has no such line, so the script
# reports that Windows is not supported.
#
# $env:HARDENING_RELEASE_URL replaces the download location (mirrors, tests).
#
# The checksum comes from the same release as the binary. It catches a broken
# or cut-off download. It does not protect you from a release that was
# tampered with.

$ErrorActionPreference = 'Stop'

function Stop-Here([string]$Message) {
    [Console]::Error.WriteLine("error: $Message")
    exit 1
}

if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
    Stop-Here 'This script is for Windows Server. On Linux use hardening.sh.'
}

# ---- the machine ----

$os = Get-CimInstance -ClassName Win32_OperatingSystem
$caption = ($os.Caption -replace '^Microsoft\s+', '').Trim()
$kernel = "Windows NT $($os.Version)"

# The processor the way the release names its files, and the way people say it.
# A 32-bit PowerShell on a 64-bit Windows reports the real processor in
# PROCESSOR_ARCHITEW6432.
$cpu = $env:PROCESSOR_ARCHITEW6432
if (-not $cpu) { $cpu = $env:PROCESSOR_ARCHITECTURE }
switch ($cpu) {
    'AMD64' { $arch = 'amd64'; $archName = 'x86-64' }
    'ARM64' { $arch = 'arm64'; $archName = 'ARM64' }
    'X86'   { $arch = '386';   $archName = 'x86 (32-bit)' }
    'ARM'   { $arch = 'arm';   $archName = 'ARM (32-bit)' }
    default { $arch = "$cpu".ToLower(); $archName = "$cpu" }
}

# ProductType 1 is a workstation. The tool hardens servers, so Windows 10 and
# 11 are not supported, whatever the list says.
$isServer = ($os.ProductType -ne 1)
if ($isServer) {
    $osName = 'Windows Server'
    $osVersion = $os.Version
    if ($caption -match 'Windows Server (\d{4})') { $osVersion = $Matches[1] }
} else {
    $osName = 'Windows'
    $osVersion = $os.Version
}

# ---- the screen ----

function Write-Row([string]$Label, [string]$Text, [string]$Color) {
    Write-Host ('  ' + $Label.PadRight(16)) -NoNewline -ForegroundColor DarkGray
    if ($Color) { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text }
}

# Show-Panel prints what is known about the machine and the verdict. $Reasons
# holds one phrase per reason, and is empty when the machine is supported.
function Show-Panel([string[]]$Reasons) {
    Write-Host ''
    Write-Host '  Interactive Server Hardening'
    Write-Host '  github.com/danang-id/server-hardening' -ForegroundColor DarkGray
    Write-Host ''
    Write-Row 'OS' $caption ''
    Write-Row 'Kernel' $kernel ''
    Write-Row 'Architecture' $arch ''
    if ($Reasons.Count -eq 0) {
        Write-Row 'Support status' 'SUPPORTED' 'Green'
    } else {
        Write-Row 'Support status' 'NOT SUPPORTED' 'Red'
        $label = 'Reason'
        foreach ($r in $Reasons) {
            if ($Reasons.Count -gt 1) { $r = "- $r" }
            Write-Row $label $r ''
            $label = ''
        }
    }
    Write-Host ''
}

# A workstation needs no list to be refused, and nothing needs downloading.
if (-not $isServer) {
    Show-Panel @("$osName is not supported operating system")
    exit 1
}

$base = $env:HARDENING_RELEASE_URL
if (-not $base) { $base = 'https://github.com/danang-id/server-hardening/releases/latest/download' }
$asset = "hardening-windows-$arch.exe"

$work = Join-Path ([IO.Path]::GetTempPath()) ("hardening." + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $exe = Join-Path $work $asset
    $sums = Join-Path $work 'SHA256SUMS'
    $listed = Join-Path $work 'SUPPORTED'

    # Test-Download checks a downloaded file against the checksum list.
    function Test-Download([string]$Path, [string]$Name) {
        $want = $null
        foreach ($line in Get-Content $sums) {
            $parts = $line -split '\s+', 2
            if ($parts.Count -eq 2 -and $parts[1].TrimStart('*') -eq $Name) { $want = $parts[0].ToLower(); break }
        }
        if (-not $want) { Stop-Here "The checksum list has no entry for $Name." }
        $got = (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLower()
        if ($got -ne $want) { Stop-Here "Checksum mismatch for $Name (expected $want, got $got). Nothing was run." }
    }

    # ---- is this machine supported? ----

    # The two small files come quietly. Only the binary gets a progress bar.
    $ProgressPreference = 'SilentlyContinue'
    try {
        Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile $sums
    } catch {
        Stop-Here "Cannot download the checksum list $base/SHA256SUMS. ($($_.Exception.Message))"
    }
    try {
        Invoke-WebRequest -UseBasicParsing -Uri "$base/SUPPORTED" -OutFile $listed
    } catch {
        Stop-Here "Cannot download the list of supported systems $base/SUPPORTED. ($($_.Exception.Message))"
    }
    $ProgressPreference = 'Continue'
    Test-Download $listed 'SUPPORTED'

    # The checks go in order: the operating system, then its version, then the
    # processor. An operating system that is not supported ends them.
    $osKnown = $false; $verKnown = $false; $archOk = $false; $archAny = $false
    foreach ($line in Get-Content $listed) {
        $f = $line.Trim() -split '\s+'
        if ($f.Count -lt 2 -or $f[0].StartsWith('#')) { continue }
        $archs = @($f | Select-Object -Skip 2)
        if ($archs -contains $arch) { $archAny = $true }
        if ($f[0] -eq 'windows') {
            $osKnown = $true
            if ($f[1] -eq $osVersion) {
                $verKnown = $true
                if ($archs -contains $arch) { $archOk = $true }
            }
        }
    }
    $reasons = @()
    if (-not $osKnown) {
        $reasons += "$osName is not supported operating system"
    } elseif (-not $verKnown) {
        $reasons += "$osName $osVersion is not supported operating system version"
        if (-not $archAny) { $reasons += "$archName is not supported processor architecture" }
    } elseif (-not $archOk) {
        $reasons += "$archName is not supported processor architecture"
    }

    Show-Panel $reasons
    if ($reasons.Count -gt 0) { exit 1 }

    # ---- downloading ----

    Write-Host "Downloading $asset"
    try {
        Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile $exe
    } catch {
        Stop-Here "Cannot download $base/$asset. ($($_.Exception.Message))"
    }
    Test-Download $exe $asset
    Write-Host 'Checksum verified.'

    # ---- administrator access ----

    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $admin) {
        Write-Host ''
        Write-Host 'The tool changes system settings, so it needs administrator access.'
        Write-Host 'Windows will ask you to allow it after you press Enter, and the tool opens in a new window.'
    }

    Write-Host ''
    Write-Host 'Press Enter to start, or Ctrl+C to cancel. ' -NoNewline
    [void][Console]::ReadLine()

    # The start screen is the one above, so the tool skips its own.
    $toolArgs = @('--skip-welcome') + $args
    if ($admin) {
        & $exe @toolArgs
        $code = $LASTEXITCODE
    } else {
        $p = Start-Process -FilePath $exe -ArgumentList $toolArgs -Verb RunAs -Wait -PassThru
        $code = $p.ExitCode
    }
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
# Leave the session alone when it went well: the script may run inside `iex`.
if ($code -ne 0) { exit $code }
