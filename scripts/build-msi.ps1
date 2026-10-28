# Builds build/VPN-Gate.msi: the Rust service, wintun.dll, the self-contained WinUI app and the WiX v4 package.
# Needs: Rust (rust-toolchain.toml), .NET 8 SDK, and the WiX CLI (`dotnet tool install --global wix --version 4.0.5`).
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

$version = (Get-Content VERSION -Raw).Trim()
$wintunVersion = '0.14.1'
$wintunSha256 = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
$out = 'build/windows'
Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $out | Out-Null

Write-Host '1/4 service'
cargo build --release --locked -p vpngate-daemon
if ($LASTEXITCODE) { throw 'cargo build failed' }

Write-Host '2/4 wintun.dll (pinned version, SHA-256 checked)'
$zip = "$out/wintun.zip"
Invoke-WebRequest "https://www.wintun.net/builds/wintun-$wintunVersion.zip" -OutFile $zip
$actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
if ($actual -ne $wintunSha256) { throw "wintun-$wintunVersion.zip has SHA-256 $actual, expected $wintunSha256" }
Expand-Archive $zip "$out/wintun"

Write-Host '3/4 app'
dotnet publish apps/windows/VPNGate.App --configuration Release -p:Platform=x64 --runtime win-x64 --output "$out/app"
if ($LASTEXITCODE) { throw 'dotnet publish failed' }

Write-Host '4/4 msi'
# Harvest the app publish output into a WiX fragment (one component per file, subfolders as directories).
$appDir = (Resolve-Path "$out/app").Path
$sb = New-Object System.Text.StringBuilder
$null = $sb.AppendLine('<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs"><Fragment>')
$dirs = Get-ChildItem $appDir -Recurse -Directory | Sort-Object FullName
$dirId = @{ $appDir = 'INSTALLFOLDER' }
$n = 0
foreach ($d in $dirs) { $n++; $dirId[$d.FullName] = "AppDir$n" }
# Directory declarations
$null = $sb.AppendLine('<DirectoryRef Id="INSTALLFOLDER">')
function Add-Dirs($parent) {
  foreach ($d in ($dirs | Where-Object { $_.Parent.FullName -eq $parent })) {
    $null = $sb.AppendLine("<Directory Id=`"$($dirId[$d.FullName])`" Name=`"$($d.Name)`">")
    Add-Dirs $d.FullName
    $null = $sb.AppendLine('</Directory>')
  }
}
Add-Dirs $appDir
$null = $sb.AppendLine('</DirectoryRef></Fragment><Fragment><ComponentGroup Id="AppFiles">')
$i = 0
foreach ($f in Get-ChildItem $appDir -Recurse -File) {
  $i++
  $dir = $dirId[$f.DirectoryName]
  $src = [System.Security.SecurityElement]::Escape($f.FullName)
  $nm = [System.Security.SecurityElement]::Escape($f.Name)
  $null = $sb.AppendLine("<Component Id=`"AppC$i`" Directory=`"$dir`" Bitness=`"always64`"><File Source=`"$src`" Name=`"$nm`" KeyPath=`"yes`" /></Component>")
}
$null = $sb.AppendLine('</ComponentGroup></Fragment></Wix>')
$fragment = "$out/app-files.wxs"
Set-Content $fragment $sb.ToString() -Encoding utf8
wix extension add --global WixToolset.Util.wixext/4.0.5
wix build -arch x64 -ext WixToolset.Util.wixext `
  -d "Version=$version" `
  -d "DaemonExe=target/release/vpngate-daemon.exe" `
  -d "WintunDll=$out/wintun/wintun/bin/amd64/wintun.dll" `
  -d "DatFile=assets/VPNGate.dat" `
  -d "IconFile=apps/windows/VPNGate.App/Assets/AppIcon.ico" `
  -o build/VPN-Gate.msi packaging/windows/VPNGate.wxs $fragment
if ($LASTEXITCODE) { throw 'wix build failed' }
Write-Host "build/VPN-Gate.msi ($version)"
