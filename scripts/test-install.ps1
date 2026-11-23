<#
Runs deploy/install.ps1 for real on a throwaway Windows machine (CI): installs the node from DIR as a system service,
joins it to a controller started here on loopback with `i3t join`, checks that it comes online, that `i3t run` points at
the service, that the service comes back after its process is killed, installs over it, then uninstalls and checks
nothing is left. Needs administrator rights and changes the machine: do not run it on yours.

The controller needs a PostgreSQL: start the test one first (scripts/test-postgres.sh start) and put what it prints
into the environment.

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
$fileServer = $null
$certThumbprint = $null

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

function Wait-Vnet {
    $last = $null
    for ($i = 0; $i -lt 45; $i++) {
        try {
            $nodes = @(Ctl node list)
            if ($nodes.Count -gt 0) {
                $detail = Ctl node show $nodes[0].id
                $last = $detail.vnet
                if (($null -ne $last) -and ($last.state -eq 'installed') -and ($last.firewall.accept.state -eq 'on')) {
                    $ruleName = "ice3tier-$($last.device)"
                    $rule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
                    if ($null -ne $rule) {
                        Write-Host "vnet ok: device=$($last.device) mtu=$($last.mtu) firewall=$($last.firewall.accept.state)"
                        return
                    }
                }
            }
        } catch {
            # Wait for the service and controller state to settle.
        }
        Start-Sleep -Seconds 1
    }
    $summary = if ($null -ne $last) { $last | ConvertTo-Json -Compress } else { 'null' }
    Fail "virtual adapter and Windows Firewall rule did not become ready within 45 s (last vnet: $summary)"
}

function Get-FreeLoopbackPort {
    $listener = New-Object System.Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try {
        return $listener.LocalEndpoint.Port
    } finally {
        $listener.Stop()
    }
}

# Runs i3t with its two output streams merged into text. cmd does the merging: Windows PowerShell turns a program's
# standard error into error records when it is redirected, and those stop the script.
function Invoke-I3t([string]$arguments) {
    $out = & cmd.exe /c "i3t $arguments 2>&1"
    return [pscustomobject]@{ Code = $LASTEXITCODE; Text = ($out | Out-String) }
}

try {
    Step 'controller on loopback'
    # A new empty database on the test PostgreSQL, so that running this twice against one server works.
    $server = $env:I3T_TEST_DATABASE_URL
    if (-not $server) { Fail 'I3T_TEST_DATABASE_URL is not set: start the test PostgreSQL first (scripts/test-postgres.sh start)' }
    $psql = if ($env:PGBIN) { Join-Path $env:PGBIN 'psql.exe' } else { 'psql' }
    $database = "install_test_$PID"
    & $psql $server -q -v ON_ERROR_STOP=1 -c "CREATE DATABASE $database"
    if ($LASTEXITCODE -ne 0) { Fail "could not create the database $database" }
    $env:I3T_DATABASE_URL = $server.Substring(0, $server.LastIndexOf('/') + 1) + $database
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
    $env:I3T_FROM = $dir
    & $installer
    if ($env:I3T_FROM) { Fail 'the installer left its settings in the environment' }
    $service = Get-Service -Name i3t
    if ($service.StartType -ne 'Automatic') { Fail "the service does not start at boot: $($service.StartType)" }
    if ($service.Status -ne 'Stopped') { Fail 'the service runs before joining' }
    if (-not (Get-Command i3t -ErrorAction SilentlyContinue)) { Fail 'i3t is not on the PATH of this session' }
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    if (@($machinePath -split ';') -notcontains $installed) { Fail 'the install directory is not on the machine PATH' }

    Step 'the state directory is closed to ordinary users and owned by Administrators or SYSTEM'
    $access = (& icacls.exe $state | Out-String)
    if ($access -match 'BUILTIN\\Users|Authenticated Users|Everyone') { Fail "ordinary users can reach ${state}:`n$access" }
    $ownerSid = (Get-Acl -LiteralPath $state).GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($ownerSid -notin 'S-1-5-18', 'S-1-5-32-544') { Fail "unexpected owner SID on ${state}: $ownerSid" }

    Step 'starting the service before joining stops it cleanly'
    Start-Service -Name i3t -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5
    if (Test-ServiceRunning) { Fail 'the service keeps running without having joined' }

    Step 'i3t run points at the service'
    $run = Invoke-I3t 'run'
    if ($run.Code -eq 0) { Fail 'i3t run started a node' }
    if ($run.Text -notmatch 'Start-Service i3t') { Fail "i3t run: unexpected answer: $($run.Text)" }

    Step 'i3t join joins and starts the service'
    # Piped the way a user does it. Windows PowerShell puts a byte order mark in front when the console code page is UTF-8.
    $token | & i3t join --can-relay
    if ($LASTEXITCODE -ne 0) { Fail 'i3t join failed' }
    Wait-Online
    Wait-Vnet
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
    Wait-Vnet

    Step 'install over the joined node, piped the way the one-line command does it'
    $env:I3T_FROM = $dir
    Get-Content -LiteralPath $installer -Raw | Invoke-Expression
    Wait-Online
    Wait-Vnet

    Step 'uninstall without purge keeps state, and reinstall from zip archive brings the node back'
    $env:I3T_UNINSTALL = '1'
    Get-Content -LiteralPath $installer -Raw | Invoke-Expression
    if (Test-Path -LiteralPath $installed) { Fail "$installed is still there after uninstall" }
    if (Get-Service -Name i3t -ErrorAction SilentlyContinue) { Fail 'the service is still registered after uninstall' }
    if (-not (Test-Path -LiteralPath (Join-Path $state 'controller.json'))) { Fail 'enrollment state was deleted without I3T_PURGE' }
    $leftRules = @(Get-NetFirewallRule -Group 'ice3tier' -ErrorAction SilentlyContinue)
    if ($leftRules.Count -gt 0) { Fail "firewall rules left after uninstall: $($leftRules.Name -join ', ')" }

    $releaseRoot = Join-Path $work 'releases'
    $relVersion = '0.9.9'
    $verDir = Join-Path $releaseRoot "download\v$relVersion"
    $latestDir = Join-Path $releaseRoot 'latest\download'
    New-Item -ItemType Directory -Path $verDir -Force | Out-Null
    New-Item -ItemType Directory -Path $latestDir -Force | Out-Null

    $zipPath = Join-Path $verDir 'i3t-windows-x86_64.zip'
    $zipFiles = @((Join-Path $dir 'i3t.exe'), (Join-Path $dir 'wintun.dll'))
    $licensePath = Join-Path $dir 'wintun-LICENSE.txt'
    if (Test-Path -LiteralPath $licensePath) { $zipFiles += $licensePath }
    Compress-Archive -Path $zipFiles -DestinationPath $zipPath -Force
    Copy-Item -LiteralPath (Join-Path $dir 'i3t.exe') -Destination (Join-Path $verDir 'i3t-windows-x86_64.exe')

    $releaseTool = Join-Path $dir 'i3t-release.exe'
    if (-not (Test-Path -LiteralPath $releaseTool)) { Fail "i3t-release.exe not found in $dir" }
    $relKey = Join-Path $work 'release.key'
    $relPub = (& $releaseTool keygen --out $relKey | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or (-not $relPub)) { Fail 'i3t-release keygen failed' }
    & $releaseTool manifest --version $relVersion --dir $verDir --key $relKey --min-controller 0.1.0 | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail 'i3t-release manifest failed' }
    Copy-Item -LiteralPath (Join-Path $verDir 'manifest.json') -Destination (Join-Path $latestDir 'manifest.json')
    Copy-Item -LiteralPath (Join-Path $verDir 'manifest.json.sig') -Destination (Join-Path $latestDir 'manifest.json.sig')

    $openssl = Get-Command openssl -ErrorAction SilentlyContinue
    $opensslExe = if ($openssl) { $openssl.Source } else { 'C:\Program Files\Git\usr\bin\openssl.exe' }
    if (-not (Test-Path -LiteralPath $opensslExe)) { Fail "openssl not found at $opensslExe" }
    $opensslCnf = Join-Path $work 'openssl.cnf'
    @'
[req]
distinguished_name = dn
x509_extensions = v3_req
prompt = no
[dn]
CN = 127.0.0.1
[v3_req]
subjectAltName = IP:127.0.0.1
basicConstraints = CA:TRUE
keyUsage = critical, digitalSignature, keyEncipherment, keyCertSign
extendedKeyUsage = serverAuth
'@ | Set-Content -LiteralPath $opensslCnf -Encoding Ascii
    $certPem = Join-Path $work 'server.crt'
    $keyPem = Join-Path $work 'server.key'
    $opensslProc = Start-Process -FilePath $opensslExe -PassThru -Wait -NoNewWindow `
        -ArgumentList 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', $keyPem, '-out', $certPem, '-days', '1', '-config', $opensslCnf `
        -RedirectStandardOutput (Join-Path $work 'openssl.out') -RedirectStandardError (Join-Path $work 'openssl.err')
    if ($opensslProc.ExitCode -ne 0) {
        $opensslErr = Get-Content -LiteralPath (Join-Path $work 'openssl.err') -Raw -ErrorAction SilentlyContinue
        Fail "openssl self-signed cert generation failed (exit $($opensslProc.ExitCode)): $opensslErr"
    }
    $importedCert = Import-Certificate -FilePath $certPem -CertStoreLocation 'Cert:\LocalMachine\Root'
    $certThumbprint = $importedCert.Thumbprint

    $httpsPort = Get-FreeLoopbackPort
    $python = (Get-Command python -ErrorAction Stop).Source
    $serverScript = Join-Path $work 'https_server.py'
    @'
import http.server, ssl, sys
port, directory, cert, key = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=directory, **kw)
    def do_GET(self):
        if self.path.startswith("/redirect-http/"):
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/manifest.json")
            self.end_headers()
            return
        super().do_GET()
    def log_message(self, *a):
        pass
httpd = http.server.HTTPServer(("127.0.0.1", port), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(certfile=cert, keyfile=key)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
'@ | Set-Content -LiteralPath $serverScript -Encoding Ascii
    $fileServer = Start-Process -FilePath $python -PassThru -NoNewWindow `
        -ArgumentList '-I', $serverScript, $httpsPort, $releaseRoot, $certPem, $keyPem `
        -RedirectStandardOutput (Join-Path $work 'http.out') -RedirectStandardError (Join-Path $work 'http.err')
    $httpsReady = $false
    for ($i = 0; $i -lt 30; $i++) {
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $client.Connect('127.0.0.1', $httpsPort)
            $client.Close()
            $httpsReady = $true
            break
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }
    if (-not $httpsReady) { Fail 'local release HTTPS server did not start' }

    function Assert-InstallRejected([string]$Reason, [scriptblock]$Setup) {
        $failed = $false
        try {
            & $Setup
            Get-Content -LiteralPath $installer -Raw | Invoke-Expression
        } catch {
            $failed = $true
            Write-Host "  rejected as expected ($Reason): $($_.Exception.Message)"
        }
        if (-not $failed) { Fail "installer should have rejected: $Reason" }
    }

    Step 'verify HTTPS enforcement, redirect downgrade refusal, signature/hash checks, and ZIP hardening'
    Assert-InstallRejected 'plain http://' {
        $env:I3T_RELEASE_BASE = "http://127.0.0.1:$httpsPort"
        $env:I3T_RELEASE_KEY = $relPub
    }
    Assert-InstallRejected 'HTTPS -> HTTP redirect' {
        $env:I3T_RELEASE_BASE = "https://127.0.0.1:$httpsPort/redirect-http"
        $env:I3T_RELEASE_KEY = $relPub
    }
    Assert-InstallRejected 'untrusted signing key' {
        $env:I3T_RELEASE_BASE = "https://127.0.0.1:$httpsPort"
    }

    # Tampered ZIP (same byte length, flipped byte) must fail SHA-256 verification
    $goodZip = Join-Path $work 'good.zip'
    Copy-Item -LiteralPath $zipPath -Destination $goodZip
    $tamperedBytes = [IO.File]::ReadAllBytes($zipPath)
    $tamperedBytes[$tamperedBytes.Length - 1] = $tamperedBytes[$tamperedBytes.Length - 1] -bxor 0x01
    [IO.File]::WriteAllBytes($zipPath, $tamperedBytes)
    Assert-InstallRejected 'tampered ZIP SHA-256 mismatch' {
        $env:I3T_RELEASE_BASE = "https://127.0.0.1:$httpsPort"
        $env:I3T_RELEASE_KEY = $relPub
    }
    Copy-Item -LiteralPath $goodZip -Destination $zipPath -Force

    # Malicious signed ZIP with Zip Slip entry and unexpected extra binary must both be rejected
    foreach ($case in @(
        @{ Name = 'Zip Slip traversal'; Entry = '..\evil.dll'; Ver = '0.9.7' },
        @{ Name = 'unexpected extra executable'; Entry = 'extra.exe'; Ver = '0.9.8' }
    )) {
        $badDir = Join-Path $releaseRoot "download\v$($case.Ver)"
        New-Item -ItemType Directory -Path $badDir -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $dir 'i3t.exe') -Destination (Join-Path $badDir 'i3t-windows-x86_64.exe')
        $badZip = Join-Path $badDir 'i3t-windows-x86_64.zip'
        & $python -I -c "import sys, zipfile; z=zipfile.ZipFile(sys.argv[1],'w'); z.write(sys.argv[2],'i3t.exe'); z.write(sys.argv[3],'wintun.dll'); z.writestr(sys.argv[4], b'evil'); z.close()" $badZip (Join-Path $dir 'i3t.exe') (Join-Path $dir 'wintun.dll') $case.Entry
        if ($LASTEXITCODE -ne 0) { Fail "failed to build malicious zip for $($case.Name)" }
        & $releaseTool manifest --version $case.Ver --dir $badDir --key $relKey --min-controller 0.1.0 | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail "failed to sign malicious zip test case $($case.Name)" }
        Assert-InstallRejected $case.Name {
            $env:I3T_RELEASE_BASE = "https://127.0.0.1:$httpsPort"
            $env:I3T_RELEASE_KEY = $relPub
            $env:I3T_VERSION = "v$($case.Ver)"
        }
        if (Test-Path -LiteralPath (Join-Path $installed 'extra.exe')) { Fail 'unexpected extra.exe was copied into ProgramFiles' }
    }

    Step 'reinstall from verified signed HTTPS release'
    $env:I3T_RELEASE_BASE = "https://127.0.0.1:$httpsPort"
    $env:I3T_RELEASE_KEY = $relPub
    Get-Content -LiteralPath $installer -Raw | Invoke-Expression
    Wait-Online
    Wait-Vnet

    Step 'uninstall and purge, piped too'
    $env:I3T_UNINSTALL = '1'
    $env:I3T_PURGE = '1'
    Get-Content -LiteralPath $installer -Raw | Invoke-Expression
    foreach ($path in $installed, $state) {
        if (Test-Path -LiteralPath $path) { Fail "$path is still there" }
    }
    if (Get-Service -Name i3t -ErrorAction SilentlyContinue) { Fail 'the service is still registered' }
    if (Get-Process -Name i3t -ErrorAction SilentlyContinue) { Fail 'an i3t process is still running' }
    $leftRules = @(Get-NetFirewallRule -Group 'ice3tier' -ErrorAction SilentlyContinue)
    if ($leftRules.Count -gt 0) { Fail "firewall rules left after purge: $($leftRules.Name -join ', ')" }
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    if (@($machinePath -split ';') -contains $installed) { Fail 'the install directory is still on the machine PATH' }

    Step 'verify pre-created NTFS Junction and untrusted-owner %ProgramData%\i3t are rejected'
    $decoy = Join-Path $work 'decoy'
    New-Item -ItemType Directory -Path $decoy | Out-Null
    $decoyFile = Join-Path $decoy 'keep.txt'
    Set-Content -LiteralPath $decoyFile -Value 'do-not-touch'
    & cmd.exe /c "mklink /J `"$state`" `"$decoy`"" | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail 'failed to create NTFS junction for test' }
    try {
        Assert-InstallRejected 'NTFS junction at %ProgramData%\i3t (install)' {
            $env:I3T_FROM = $dir
        }
        Assert-InstallRejected 'NTFS junction at %ProgramData%\i3t (purge)' {
            $env:I3T_UNINSTALL = '1'
            $env:I3T_PURGE = '1'
        }
        if (-not (Test-Path -LiteralPath $decoyFile)) { Fail 'decoy file inside junction target was deleted!' }
    } finally {
        if (Test-Path -LiteralPath $state) { & cmd.exe /c "rmdir `"$state`"" | Out-Null }
    }

    New-Item -ItemType Directory -Path $state | Out-Null
    try {
        & icacls.exe $state /setowner '*S-1-5-32-545' | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail 'failed to set untrusted owner on test state directory' }
        Assert-InstallRejected 'untrusted-owner %ProgramData%\i3t (install)' {
            $env:I3T_FROM = $dir
        }
        if (Test-Path -LiteralPath (Join-Path $state 'node.key')) { Fail 'node.key was written into untrusted directory' }
        Assert-InstallRejected 'untrusted-owner %ProgramData%\i3t (purge)' {
            $env:I3T_UNINSTALL = '1'
            $env:I3T_PURGE = '1'
        }
    } finally {
        if (Test-Path -LiteralPath $state) {
            & icacls.exe $state /setowner '*S-1-5-32-544' | Out-Null
            Remove-Item -LiteralPath $state -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Step 'ok'
} catch {
    Write-Host "`n--- failed; the node says:"
    Get-Content -LiteralPath (Join-Path $state 'i3t.log') -Tail 80 -Encoding UTF8 -ErrorAction SilentlyContinue
    Write-Host '--- the controller says:'
    Get-Content -LiteralPath (Join-Path $work 'ctl.err') -Tail 40 -Encoding UTF8 -ErrorAction SilentlyContinue
    throw
} finally {
    if ($fileServer -and (-not $fileServer.HasExited)) { Stop-Process -Id $fileServer.Id -Force -ErrorAction SilentlyContinue }
    if ($controller -and (-not $controller.HasExited)) { Stop-Process -Id $controller.Id -Force -ErrorAction SilentlyContinue }
    if ($certThumbprint) { Remove-Item -LiteralPath "Cert:\LocalMachine\Root\$certThumbprint" -Force -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
