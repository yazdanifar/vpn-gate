# Smoke test of build/VPN-Gate.msi on a disposable Windows machine (CI runner, admin): install, service, files, ACL,
# IPC over the named pipe, crash restart, uninstall. Do NOT run on a machine you care about (it installs and removes the service).
param([string]$Msi = 'build/VPN-Gate.msi')
$ErrorActionPreference = 'Stop'
$Msi = (Resolve-Path $Msi).Path
$prog = "$env:ProgramFiles\VPN Gate"
$data = "$env:ProgramData\VPNGate"
function Check($ok, $what) { if (-not $ok) { throw "FAILED: $what" } else { Write-Host "ok: $what" } }
function WaitFor($what, [scriptblock]$cond, $seconds = 60) {
  $end = (Get-Date).AddSeconds($seconds)
  while ((Get-Date) -lt $end) { if (& $cond) { Write-Host "ok: $what"; return }; Start-Sleep -Seconds 1 }
  throw "FAILED (timeout): $what"
}
function ServiceState { (Get-Service VPNGate -ErrorAction SilentlyContinue).Status }
function StatusReply {
  $c = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'VPNGate', [System.IO.Pipes.PipeDirection]::InOut)
  try {
    $c.Connect(5000)
    $w = New-Object System.IO.StreamWriter($c); $w.AutoFlush = $true
    $r = New-Object System.IO.StreamReader($c)
    $w.WriteLine('{"cmd":"status"}')
    $task = $r.ReadLineAsync()
    if (-not $task.Wait(5000)) { return $null }
    return $task.Result
  } finally { $c.Dispose() }
}

# 1. install
$p = Start-Process msiexec -ArgumentList '/i', "`"$Msi`"", '/qn', '/l*v', 'install.log' -Wait -PassThru
Check ($p.ExitCode -eq 0) "msiexec install exit code $($p.ExitCode)"

# 2. service
WaitFor 'service VPNGate is Running' { (ServiceState) -eq 'Running' }
$cfg = (sc.exe qc VPNGate | Out-String)
Check ($cfg -match 'AUTO_START' -and $cfg -match '--service') 'service is auto-start with --service'
$fail = (sc.exe qfailure VPNGate | Out-String)
Check (([regex]::Matches($fail, 'RESTART')).Count -ge 3) 'service restarts on failure (x3)'

# 3. files
foreach ($f in 'vpngate-daemon.exe', 'wintun.dll', 'VPNGate.dat', 'VPNGate.exe') {
  Check (Test-Path "$prog\$f") "installed $f"
}
Check (Test-Path "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\VPN Gate.lnk") 'Start menu shortcut'

# 4. state folder ACL: only SYSTEM and Administrators
$acl = (icacls.exe $data | Out-String)
Write-Host $acl
Check ($acl -match 'NT AUTHORITY\\SYSTEM' -and $acl -match 'BUILTIN\\Administrators') 'data dir grants SYSTEM and Administrators'
Check ($acl -notmatch 'BUILTIN\\Users' -and $acl -notmatch 'Everyone' -and $acl -notmatch 'Authenticated Users') 'data dir grants nobody else'

# 5. IPC: the daemon answers a status request over the named pipe
$reply = StatusReply
Write-Host "status reply: $reply"
Check ($reply -match '"state"\s*:\s*"disconnected"' -and $reply -match '"ipcVersion"\s*:\s*9') 'pipe answers status (disconnected, ipcVersion 9)'

# 6. crash recovery: kill the service process, SCM must restart it and the pipe must answer again
$pid1 = (Get-CimInstance Win32_Service -Filter "Name='VPNGate'").ProcessId
Stop-Process -Id $pid1 -Force
WaitFor 'service restarted with a new process' {
  $s = Get-CimInstance Win32_Service -Filter "Name='VPNGate'"
  $s.State -eq 'Running' -and $s.ProcessId -ne 0 -and $s.ProcessId -ne $pid1
} 90
WaitFor 'pipe answers again after the restart' { try { (StatusReply) -match '"state"' } catch { $false } } 30

# 7. uninstall
$p = Start-Process msiexec -ArgumentList '/x', "`"$Msi`"", '/qn', '/l*v', 'uninstall.log' -Wait -PassThru
Check ($p.ExitCode -eq 0) "msiexec uninstall exit code $($p.ExitCode)"
Check ($null -eq (ServiceState)) 'service removed'
Check (-not (Test-Path $prog)) 'program folder removed'
Check (-not (Test-Path $data)) 'data folder removed'
Check (-not (Test-Path "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\VPN Gate.lnk")) 'Start menu shortcut removed'
Check ($null -eq (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq 'VPN Gate' })) 'no Programs and Features entry left'
Check (@(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'VPNGate*' -or $_.InterfaceDescription -like '*Wintun*' }).Count -eq 0) 'no VPNGate/Wintun adapter left'
Check ($null -eq (Get-Process -Name 'vpngate-daemon', 'VPNGate' -ErrorAction SilentlyContinue)) 'no VPN Gate process left'
Write-Host 'MSI smoke test passed'
