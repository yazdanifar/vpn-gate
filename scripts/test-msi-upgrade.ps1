# Upgrade test on a disposable Windows machine (CI runner, admin): install an older MSI, install a newer one over it, check the
# service, data and version carried over, a downgrade is refused, and uninstall leaves nothing.
param([string]$Old = 'build/VPN-Gate.msi', [string]$New = 'build/VPN-Gate-next.msi', [string]$NewVersion = '99.0.0')
$ErrorActionPreference = 'Stop'
$Old = (Resolve-Path $Old).Path; $New = (Resolve-Path $New).Path
$prog = "$env:ProgramFiles\VPN Gate"
$data = "$env:ProgramData\VPNGate"
function Check($ok, $what) { if (-not $ok) { throw "FAILED: $what" } else { Write-Host "ok: $what" } }
function WaitFor($what, [scriptblock]$cond, $seconds = 60) {
  $end = (Get-Date).AddSeconds($seconds)
  while ((Get-Date) -lt $end) { if (& $cond) { Write-Host "ok: $what"; return }; Start-Sleep -Seconds 1 }
  throw "FAILED (timeout): $what"
}
function Msi($args_, $log) { (Start-Process msiexec -ArgumentList ($args_ + @('/qn', '/l*v', $log)) -Wait -PassThru).ExitCode }
function Installed {
  Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -eq 'VPN Gate' }
}
function ServicePid { (Get-CimInstance Win32_Service -Filter "Name='VPNGate'").ProcessId }
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

Check ((Msi @('/i', "`"$Old`"") 'upgrade-install-old.log') -eq 0) 'old version installs'
$oldVersion = (Installed).DisplayVersion
WaitFor 'old service running' { (Get-Service VPNGate -ErrorAction SilentlyContinue).Status -eq 'Running' }
$pid1 = ServicePid
Set-Content "$data\marker.txt" 'state that must survive an upgrade'

# The app is running while the upgrade replaces its files (what a user with the window open does). Installer exit
# 3010 means "done, restart needed to replace files in use"; anything else but 0 is a failure.
$app = Start-Process "$prog\VPNGate.exe" -PassThru
Start-Sleep -Seconds 8
$appRunning = -not $app.HasExited
Write-Host "app running before the upgrade: $appRunning"
$code = Msi @('/i', "`"$New`"") 'upgrade-install-new.log'
Check ($code -eq 0 -or $code -eq 3010) "newer version installs over it with the app open (exit code $code)"
Get-Process -Name 'VPNGate' -ErrorAction SilentlyContinue | Stop-Process -Force
Check (@(Installed).Count -eq 1) 'exactly one VPN Gate is installed'
Check ((Installed).DisplayVersion -eq $NewVersion) "installed version went $oldVersion -> $((Installed).DisplayVersion)"
WaitFor 'service running after the upgrade, as a new process' {
  $s = Get-CimInstance Win32_Service -Filter "Name='VPNGate'"
  $s.State -eq 'Running' -and $s.ProcessId -ne 0 -and $s.ProcessId -ne $pid1
}
Check (Test-Path "$data\marker.txt") 'data folder survived the upgrade'
Check ((StatusReply) -match '"ipcVersion"\s*:\s*9') 'pipe answers after the upgrade'
$acl = (icacls.exe $data | Out-String)
Check ($acl -match 'SYSTEM' -and $acl -match 'Administrators' -and $acl -notmatch 'BUILTIN\\Users') 'data folder ACL still locked'
Check ((Test-Path "$prog\VPNGate.exe") -and (Test-Path "$prog\vpngate-daemon.exe")) 'program files present'

Check ((Msi @('/i', "`"$Old`"") 'upgrade-downgrade.log') -ne 0) 'installing the older version over the newer one is refused'
Check ((Installed).DisplayVersion -eq $NewVersion) 'still on the newer version'

Check ((Msi @('/x', "`"$New`"") 'upgrade-uninstall.log') -eq 0) 'uninstall'
Check ($null -eq (Get-Service VPNGate -ErrorAction SilentlyContinue)) 'service removed'
Check (-not (Test-Path $prog)) 'program folder removed'
Check (-not (Test-Path $data)) 'data folder removed'
Write-Host 'MSI upgrade test passed'
