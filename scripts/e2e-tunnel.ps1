# End-to-end tunnel test for Windows. Needs Administrator (Wintun adapter, routes, DNS), wintun.dll next to the daemon and
# network. Run from an elevated prompt:  scripts/e2e-tunnel.ps1 -Server <relay-ip> [-Port <n>] [-Daemon <path>]
# Port of scripts/e2e-tunnel.sh. Checks that traffic really goes through the VPN and that a hard kill + restart leave the
# routes and DNS exactly as they were. (A console process cannot be sent Ctrl-C from a script without also interrupting
# the script, so the graceful stop is covered by the tunnel_windows test instead.)
param(
    [Parameter(Mandatory)][string]$Server,
    [int]$Port = 0,
    [string]$Daemon = 'target/release/vpngate-daemon.exe'
)
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'run as Administrator'; exit 2
}
if (-not (Test-Path $Daemon)) { cargo build --release -p vpngate-daemon | Out-Null }
$Daemon = (Resolve-Path $Daemon).Path
if (-not (Test-Path (Join-Path (Split-Path $Daemon) 'wintun.dll'))) { scripts/get-wintun.ps1 -Dest (Split-Path $Daemon) | Out-Null }

$script:fails = 0
$log = Join-Path $env:TEMP 'vpngate-e2e.log'
$err = Join-Path $env:TEMP 'vpngate-e2e.err'
function Ok($m)  { Write-Host "  ok   $m" }
function Bad($m) { Write-Host "  FAIL $m"; $script:fails++ }
function PubIp($family) {
    $o = & curl.exe "-$family" -s -m 10 https://api64.ipify.org 2>$null
    if ($LASTEXITCODE -eq 0 -and $o) { $o.Trim() } else { '?' }
}
# Every route and DNS server list outside the tunnel adapter, without multicast, broadcast and link-local noise.
function Snap {
    $r = Get-NetRoute | Where-Object { $_.InterfaceAlias -ne 'VPNGate' -and $_.DestinationPrefix -notlike '224.*' `
            -and $_.DestinationPrefix -notlike 'ff*' -and $_.DestinationPrefix -notlike 'fe80*' -and $_.DestinationPrefix -ne '255.255.255.255/32' } |
        ForEach-Object { "route $($_.DestinationPrefix) $($_.NextHop) $($_.InterfaceAlias) $($_.RouteMetric)" }
    $d = Get-DnsClientServerAddress | Where-Object { $_.InterfaceAlias -ne 'VPNGate' } |
        ForEach-Object { "dns $($_.InterfaceAlias) $($_.AddressFamily) $($_.ServerAddresses -join ',')" }
    @($r) + @($d) | Sort-Object
}
function WaitFor($pattern) {
    for ($i = 0; $i -lt 60; $i++) {
        if ((Test-Path $log) -and (Select-String -Path $log -Pattern $pattern -Quiet)) { return $true }
        Start-Sleep -Milliseconds 500
    }
    $false
}

$baseIp = PubIp 4
$before = Snap
Write-Host "baseline public IPv4: $baseIp"

Write-Host '== connect, then hard-kill the daemon'
$daemonArgs = @('--connect', $Server)
if ($Port) { $daemonArgs += @('--port', "$Port") }
$p = Start-Process -FilePath $Daemon -ArgumentList $daemonArgs -RedirectStandardOutput $log -RedirectStandardError $err -PassThru -WindowStyle Hidden
try {
    if (-not (WaitFor '\[connected\]')) {
        Bad 'never connected'; Get-Content $log, $err -ErrorAction SilentlyContinue
    } else {
        Ok ('connected: ' + (Select-String -Path $log -Pattern '\[connected\]' | Select-Object -First 1).Line)
        Start-Sleep -Seconds 2
        $via = PubIp 4
        if ($via -eq $Server -or ($via -ne $baseIp -and $via -ne '?')) { Ok "public IPv4 through the tunnel: $via" } else { Bad "public IPv4 unchanged ($via)" }
        $routes = (Get-NetRoute -AddressFamily IPv4).DestinationPrefix
        if (($routes -contains '0.0.0.0/1') -and ($routes -contains '128.0.0.0/1')) { Ok '0.0.0.0/1 and 128.0.0.0/1 routes present' } else { Bad 'default-capture routes missing' }
        $v6 = PubIp 6
        if ($v6 -like '*:*') { Bad "IPv6 reachable while connected (leak): $v6" } else { Ok 'IPv6 blocked' }
        $vpnDns = [regex]::Match((Get-Content $log -Raw), 'gateway ([0-9.]+)').Groups[1].Value
        $adapterDns = (Get-DnsClientServerAddress -InterfaceAlias 'VPNGate' -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
        if ($vpnDns -and ($adapterDns -contains $vpnDns)) { Ok "VPN resolver ($vpnDns) set on the tunnel adapter" } else { Bad "tunnel adapter DNS is '$adapterDns', expected '$vpnDns'" }
        try { Resolve-DnsName example.com -Type A -DnsOnly -ErrorAction Stop | Out-Null; Ok 'DNS resolves through the tunnel' } catch { Bad 'DNS lookup failed' }
    }
} finally {
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    $p.WaitForExit(10000) | Out-Null
}

# Stale state from the hard kill must be cleaned by the next start (the console form of the daemon does the same as the service).
Write-Host '  (daemon killed hard; the next start must clean up)'
$d = Start-Process -FilePath $Daemon -ArgumentList '--daemon' -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $env:TEMP 'vpngate-e2e-daemon.log') -RedirectStandardError (Join-Path $env:TEMP 'vpngate-e2e-daemon.err')
Start-Sleep -Seconds 3
Stop-Process -Id $d.Id -Force -ErrorAction SilentlyContinue
$d.WaitForExit(10000) | Out-Null
Start-Sleep -Seconds 1

$after = Snap
$diff = Compare-Object $before $after
if (-not $diff) { Ok 'routes and DNS restored exactly' } else { Bad 'routing/DNS differ after the kill:'; $diff | Select-Object -First 20 | ForEach-Object { Write-Host "      $($_.SideIndicator) $($_.InputObject)" } }
if (Get-NetAdapter -Name 'VPNGate' -ErrorAction SilentlyContinue) { Bad 'tunnel adapter left behind' } else { Ok 'tunnel adapter removed' }
$back = PubIp 4
if ($back -eq $baseIp) { Ok "public IPv4 back to $baseIp" } else { Bad "public IPv4 did not return to baseline ($back)" }
Write-Host ''
if ($script:fails -eq 0) { Write-Host 'E2E PASSED' } else { Write-Host "E2E FAILED ($($script:fails))" }
exit ([int]($script:fails -gt 0))
