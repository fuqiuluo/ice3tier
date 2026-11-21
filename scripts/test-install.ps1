<#
Runs deploy/install.ps1 for real on a throwaway Windows machine (CI): installs the node from DIR as a system service,
joins it to a controller started here on loopback with `i3t join`, checks that it comes online, that `i3t run` points at
the service, that the service comes back after its process is killed, installs over it, then uninstalls and checks
nothing is left. Needs administrator rights and changes the machine: do not run it on yours.

Usage: scripts\test-install.ps1 <dir with i3t.exe, wintun.dll, i3t-controller.exe and i3tctl.exe>
#>
param([Parameter(Mandatory = $true)][string]$Dir)

$ErrorActionPreference = 'Stop'
$dir = (Resolve-Path -LiteralPath $Dir).Path
$repo = Split-Path -Parent $PSScriptRoot
$installer = Join-Path $repo 'deploy\install.ps1'
$work = Join-Path ([IO.Path]::GetTempPath()) ('i3t-test-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
$installed = Join-Path $env:ProgramFiles 'ice3tier'
$state = Join-Path $env:ProgramData 'i3t'
$controller = $null

function Step([string]$text) {
    Write-Host "`n=== $text"
}

function Fail([string]$text) {
    throw "FAIL: $text"
}

# i3tctl with JSON output, parsed.
function Ctl {
    $out = & (Join-Path $dir 'i3tctl.exe') --json @args
    if ($LASTEXITCODE -ne 0) { Fail "i3tctl $args failed" }
    $text = ($out | Out-String).Trim()
    if (-not $text) { return $null }
    return ($text | ConvertFrom-Json)
}

function Test-ServiceRunning {
    $service = Get-Service -Name i3t -ErrorAction SilentlyContinue
    return ($null -ne $service) -and ($service.Status -eq 'Running')
}

function Test-AllOnline {
    $nodes = @(Ctl node list)
    return ($nodes.Count -gt 0) -and (@($nodes | Where-Object { -not $_.online }).Count -eq 0)
}

function Wait-Online {
    for ($i = 0; $i -lt 60; $i++) {
        if ((Test-ServiceRunning) -and (Test-AllOnline)) { return }
        Start-Sleep -Seconds 1
    }
    Fail 'the node did not come online within 60 s'
}

# Runs i3t with its two output streams merged into text. cmd does the merging: Windows PowerShell turns a program's
# standard error into error records when it is redirected, and those stop the script.
function Invoke-I3t([string]$arguments) {
    $out = & cmd.exe /c "i3t $arguments 2>&1"
    return [pscustomobject]@{ Code = $LASTEXITCODE; Text = ($out | Out-String) }
}

try {
    Step 'controller on loopback'
    $controller = Start-Process -FilePath (Join-Path $dir 'i3t-controller.exe') -PassThru -NoNewWindow `
        -ArgumentList '--data-dir', (Join-Path $work 'ctl'), '--public-addr', '127.0.0.1:20331', '--listen', '127.0.0.1:20331' `
        -RedirectStandardOutput (Join-Path $work 'ctl.out') -RedirectStandardError (Join-Path $work 'ctl.err')
    $adminToken = $null
    for ($i = 0; ($i -lt 60) -and (-not $adminToken); $i++) {
        Start-Sleep -Seconds 1
        $line = Get-Content -LiteralPath (Join-Path $work 'ctl.out') -ErrorAction SilentlyContinue | Where-Object { $_ -match '^    \S+$' } | Select-Object -First 1
        if ($line) { $adminToken = $line.Trim() }
    }
    if (-not $adminToken) { Fail 'the controller printed no admin token' }
    $env:I3T_ADMIN_TOKEN = $adminToken
    $env:I3T_ADMIN_URL = 'http://127.0.0.1:20332'
    Ctl network create ci | Out-Null
    $token = (Ctl token create --expires 30m).token

    Step 'install without a token'
    & $installer -From $dir
    $service = Get-Service -Name i3t
    if ($service.StartType -ne 'Automatic') { Fail "the service does not start at boot: $($service.StartType)" }
    if ($service.Status -ne 'Stopped') { Fail 'the service runs before joining' }
    if (-not (Get-Command i3t -ErrorAction SilentlyContinue)) { Fail 'i3t is not on the PATH of this session' }
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    if (@($machinePath -split ';') -notcontains $installed) { Fail 'the install directory is not on the machine PATH' }

    Step 'the state directory is closed to ordinary users'
    $access = (& icacls.exe $state | Out-String)
    if ($access -match 'BUILTIN\\Users|Authenticated Users|Everyone') { Fail "ordinary users can reach ${state}:`n$access" }

    Step 'starting the service before joining stops it cleanly'
    Start-Service -Name i3t -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5
    if (Test-ServiceRunning) { Fail 'the service keeps running without having joined' }

    Step 'i3t run points at the service'
    $run = Invoke-I3t 'run'
    if ($run.Code -eq 0) { Fail 'i3t run started a node' }
    if ($run.Text -notmatch 'Start-Service i3t') { Fail "i3t run: unexpected answer: $($run.Text)" }

    Step 'i3t join joins and starts the service'
    $probe = Join-Path $work 'stdin-hex.ps1'
    Set-Content -LiteralPath $probe -Value '$stdin = [Console]::OpenStandardInput(); $bytes = New-Object byte[] 64; $read = $stdin.Read($bytes, 0, 64); Write-Output ("read=" + $read + " " + [BitConverter]::ToString($bytes, 0, $read))'
    $head = $token.Substring(0, 8)
    Write-Host ('diag: piped to powershell.exe: ' + ($head | & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $probe))
    Write-Host ('diag: piped to findstr: ' + ($head | & findstr.exe /N .))
    Write-Host ('diag: i3t on the PATH: ' + (Get-Command i3t).Source)
    Write-Host ('diag: echo through cmd: ' + (& cmd.exe /c "echo $head| findstr /N ."))
    $token | & i3t join --can-relay
    if ($LASTEXITCODE -ne 0) { Fail 'i3t join failed' }
    Wait-Online
    & i3t status
    if ($LASTEXITCODE -ne 0) { Fail 'i3t status failed' }
    $node = Get-CimInstance Win32_Service -Filter "Name='i3t'"
    if ($node.StartName -ne 'LocalSystem') { Fail "the service runs as $($node.StartName)" }

    Step 'the service comes back after its process is killed'
    $killed = $node.ProcessId
    Stop-Process -Id $killed -Force
    $revived = 0
    for ($i = 0; ($i -lt 30) -and (($revived -eq 0) -or ($revived -eq $killed)); $i++) {
        Start-Sleep -Seconds 1
        $revived = (Get-CimInstance Win32_Service -Filter "Name='i3t'").ProcessId
    }
    if (($revived -eq 0) -or ($revived -eq $killed)) { Fail 'the service did not come back within 30 s' }
    Wait-Online

    Step 'install over the joined node'
    & $installer -From $dir
    Wait-Online

    Step 'uninstall and purge, piped the way the one-line command does it'
    $env:I3T_UNINSTALL = '1'
    $env:I3T_PURGE = '1'
    Get-Content -LiteralPath $installer -Raw | Invoke-Expression
    Remove-Item Env:I3T_UNINSTALL, Env:I3T_PURGE
    foreach ($path in $installed, $state) {
        if (Test-Path -LiteralPath $path) { Fail "$path is still there" }
    }
    if (Get-Service -Name i3t -ErrorAction SilentlyContinue) { Fail 'the service is still registered' }
    if (Get-Process -Name i3t -ErrorAction SilentlyContinue) { Fail 'an i3t process is still running' }
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    if (@($machinePath -split ';') -contains $installed) { Fail 'the install directory is still on the machine PATH' }

    Step 'ok'
} catch {
    Write-Host "`n--- failed; the node says:"
    Get-Content -LiteralPath (Join-Path $state 'i3t.log') -Tail 80 -Encoding UTF8 -ErrorAction SilentlyContinue
    Write-Host '--- the controller says:'
    Get-Content -LiteralPath (Join-Path $work 'ctl.err') -Tail 40 -Encoding UTF8 -ErrorAction SilentlyContinue
    throw
} finally {
    if ($controller -and (-not $controller.HasExited)) { Stop-Process -Id $controller.Id -Force -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
