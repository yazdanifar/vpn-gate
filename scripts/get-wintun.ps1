# Downloads wintun.dll (pinned version, SHA-256 checked) and copies the amd64 DLL to -Dest (a directory). Prints the DLL path.
param([Parameter(Mandatory)][string]$Dest)
$ErrorActionPreference = 'Stop'
$version = '0.14.1'
$sha256 = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) "wintun-$([guid]::NewGuid())"
New-Item -ItemType Directory -Force $tmp, $Dest | Out-Null
$zip = "$tmp/wintun.zip"
Invoke-WebRequest "https://www.wintun.net/builds/wintun-$version.zip" -OutFile $zip
$actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
if ($actual -ne $sha256) { throw "wintun-$version.zip has SHA-256 $actual, expected $sha256" }
Expand-Archive $zip "$tmp/x"
Copy-Item "$tmp/x/wintun/bin/amd64/wintun.dll" $Dest -Force
Remove-Item $tmp -Recurse -Force
(Join-Path (Resolve-Path $Dest).Path 'wintun.dll')
