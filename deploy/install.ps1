<#
One-line installer for the ice3tier node on Windows (x86_64). Run it in a PowerShell opened with "Run as administrator".

Install the node as a system service (it runs in the background and starts at boot):
  irm https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.ps1 | iex

Install, join and start in one command:
  $env:I3T_TOKEN = '<TOKEN>'; irm https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.ps1 | iex

Settings are environment variables, set before the command. They apply to one run: the script clears them.
  I3T_TOKEN          Enrollment token; joins the network and starts the service
  I3T_CAN_RELAY=1    Declare relay capability when joining
  I3T_CAN_EXIT=1     Declare exit capability when joining
  I3T_VERSION        Install a specific release tag (e.g. v0.1.34) instead of the latest
  I3T_RELEASE_BASE   Release base URL (default: GitHub Releases)
  I3T_FROM           Take i3t.exe and wintun.dll from a local directory instead of downloading
  I3T_UNINSTALL=1    Remove the service and the program
  I3T_PURGE=1        With I3T_UNINSTALL, also delete the node's key and settings

What it installs:
  %ProgramFiles%\ice3tier   i3t.exe and wintun.dll (the virtual adapter's driver), added to the machine PATH
  %ProgramData%\i3t         the node's key and settings, readable by SYSTEM and Administrators only; the log is i3t.log
  service "i3t"             starts at boot, restarts when it fails; `i3t join` starts it
#>

# Everything runs in a child scope: piped into iex, this script shares the caller's session and must not leave its
# variables, functions or preferences behind. That is also why the settings are not parameters: iex would create them
# in the caller's scope. Failures are thrown, never `exit`: that would close the caller's window.
& {
    $ErrorActionPreference = 'Stop'
    # Windows PowerShell 5.1 draws a progress bar that slows downloads to a crawl.
    $ProgressPreference = 'SilentlyContinue'

    $service = 'i3t'
    $asset = 'i3t-windows-x86_64.zip'
    # A 32-bit PowerShell on 64-bit Windows sees "Program Files (x86)" as ProgramFiles.
    $programFiles = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
    $dir = Join-Path $programFiles 'ice3tier'
    $exe = Join-Path $dir 'i3t.exe'
    $state = Join-Path $env:ProgramData 'i3t'

    $token = $env:I3T_TOKEN
    $relay = $env:I3T_CAN_RELAY -eq '1'
    $canExit = $env:I3T_CAN_EXIT -eq '1'
    $version = $env:I3T_VERSION
    $releaseBase = $env:I3T_RELEASE_BASE
    $from = $env:I3T_FROM
    $removing = $env:I3T_UNINSTALL -eq '1'
    $purging = $env:I3T_PURGE -eq '1'
    # One run only: left set, I3T_UNINSTALL would turn the next install in this window into an uninstall.
    foreach ($name in 'I3T_TOKEN', 'I3T_CAN_RELAY', 'I3T_CAN_EXIT', 'I3T_VERSION', 'I3T_RELEASE_BASE', 'I3T_FROM', 'I3T_UNINSTALL', 'I3T_PURGE') {
        Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
    }

    function Say([string]$text) {
        Write-Host "==> $text"
    }

    # Puts the install directory on the machine PATH, or takes it off. The value is read and written as it is stored
    # (entries such as %SystemRoot%\system32 stay unexpanded), which [Environment]::SetEnvironmentVariable would not do.
    function Set-MachinePath([bool]$present) {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Environment', $true)
        try {
            $current = [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $entries = @($current -split ';' | Where-Object { $_ -and ($_.TrimEnd('\') -ne $dir) })
            if ($present) { $entries += $dir }
            $wanted = $entries -join ';'
            if ($wanted -eq $current.TrimEnd(';')) { return }
            $key.SetValue('Path', $wanted, [Microsoft.Win32.RegistryValueKind]::ExpandString)
        } finally {
            $key.Close()
        }
        # Programs that are already running (Explorer, and so every terminal opened from now on) only reread the
        # environment when told to; setting any machine variable sends that notice.
        [Environment]::SetEnvironmentVariable('I3T_PATH_CHANGED', '1', 'Machine')
        [Environment]::SetEnvironmentVariable('I3T_PATH_CHANGED', $null, 'Machine')
    }

    # Runs an action on files that a process which has just stopped may still hold open for a moment.
    function Invoke-Released([scriptblock]$action) {
        for ($attempt = 1; ; $attempt++) {
            try {
                & $action
                return
            } catch {
                if ($attempt -ge 20) { throw }
                Start-Sleep -Milliseconds 500
            }
        }
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator rights are required: open PowerShell with "Run as administrator" and run this again.'
    }

    if ($removing) {
        if (Test-Path -LiteralPath $exe) {
            Say "Removing the $service service"
            & $exe service uninstall
            if ($LASTEXITCODE -ne 0) { throw 'i3t service uninstall failed' }
            # Firewall rules a node that was killed may have left behind. Nothing to do is fine too.
            & $exe network cleanup | Out-Null
        } elseif (Get-Service -Name $service -ErrorAction SilentlyContinue) {
            # The program is gone but its service is still registered.
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            & sc.exe delete $service | Out-Null
        }
        Set-MachinePath $false
        if (Test-Path -LiteralPath $dir) {
            Say "Removing $dir"
            Invoke-Released { Remove-Item -LiteralPath $dir -Recurse -Force }
        }
        if ($purging -and (Test-Path -LiteralPath $state)) {
            Say "Removing $state"
            Remove-Item -LiteralPath $state -Recurse -Force
        }
        Say 'Uninstalled'
        return
    }
    if ($purging) {
        throw 'I3T_PURGE can only be used with I3T_UNINSTALL'
    }

    if (($env:PROCESSOR_ARCHITECTURE -ne 'AMD64') -and ($env:PROCESSOR_ARCHITEW6432 -ne 'AMD64')) {
        throw "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE (only x86_64 is supported)"
    }

    $work = Join-Path ([IO.Path]::GetTempPath()) ('i3t-install-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null
    try {
        if ($from) {
            foreach ($name in 'i3t.exe', 'wintun.dll') {
                $source = Join-Path $from $name
                if (-not (Test-Path -LiteralPath $source)) { throw "$name not found in $from" }
                Copy-Item -LiteralPath $source -Destination $work
            }
            $license = Join-Path $from 'wintun-LICENSE.txt'
            if (Test-Path -LiteralPath $license) { Copy-Item -LiteralPath $license -Destination $work }
        } else {
            if (-not $releaseBase) { $releaseBase = 'https://github.com/fuqiuluo/ice3tier/releases' }
            $url = if ($version) { "$releaseBase/download/$version/$asset" } else { "$releaseBase/latest/download/$asset" }
            Say "Downloading $url"
            # Windows PowerShell 5.1 does not offer TLS 1.2 by default on older systems.
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            $zip = Join-Path $work $asset
            Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
            Expand-Archive -LiteralPath $zip -DestinationPath $work
            Remove-Item -LiteralPath $zip
            foreach ($name in 'i3t.exe', 'wintun.dll') {
                if (-not (Test-Path -LiteralPath (Join-Path $work $name))) { throw "$name is missing from $asset" }
            }
        }

        $registered = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($registered -and ($registered.Status -ne 'Stopped')) {
            Say "Stopping the $service service"
            Stop-Service -Name $service -Force
        }

        Say "Installing i3t to $dir"
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        foreach ($file in Get-ChildItem -LiteralPath $work -File) {
            Invoke-Released { Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $dir $file.Name) -Force }
        }

        if (-not (Test-Path -LiteralPath $state)) {
            New-Item -ItemType Directory -Path $state | Out-Null
            # The node's private key lives here: SYSTEM and Administrators only, whatever the language of the system.
            & icacls.exe $state /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Could not restrict access to $state" }
        }

        Say "Registering the $service service (starts at boot)"
        & $exe service install
        if ($LASTEXITCODE -ne 0) { throw 'i3t service install failed' }

        Set-MachinePath $true
        # This window too, so that `i3t` works in it right away.
        if (@($env:Path -split ';') -notcontains $dir) { $env:Path = $env:Path.TrimEnd(';') + ';' + $dir }

        if ($token) {
            Say 'Joining the network'
            $arguments = @('join')
            if ($relay) { $arguments += '--can-relay' }
            if ($canExit) { $arguments += '--can-exit' }
            # `i3t join` starts the service once the node has joined.
            $token | & $exe @arguments
            if ($LASTEXITCODE -ne 0) { throw 'i3t join failed' }
            Say 'i3t is running (check with: i3t status)'
        } elseif (Test-Path -LiteralPath (Join-Path $state 'controller.json')) {
            Say "This node has already joined; starting the $service service"
            Start-Service -Name $service
            Say 'i3t upgraded and running (check with: i3t status)'
        } else {
            Say 'Installation complete!'
            Write-Host ''
            Write-Host 'Next step (joins and starts the service):'
            Write-Host '  echo <enrollment-token> | i3t join   # add --can-relay or --can-exit if needed'
        }
    } finally {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}
