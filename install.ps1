# Installs the cfs CLI from a GitHub release (Windows).
#   irm https://raw.githubusercontent.com/JuniYadi/cf-secret-remote/main/install.ps1 | iex
#   & ([scriptblock]::Create((irm .../install.ps1))) -Version v0.0.1
# Env: CFS_INSTALL_DIR (default %LOCALAPPDATA%\cfs\bin).
param([string]$Version = $(if ($env:CFS_VERSION) { $env:CFS_VERSION } else { "latest" }))
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$repo = "JuniYadi/cf-secret-remote"
$dir = if ($env:CFS_INSTALL_DIR) { $env:CFS_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "cfs\bin" }

# Only the x64 build is published; Windows on ARM runs it through emulation.
if (-not [Environment]::Is64BitOperatingSystem) { throw "cfs needs a 64-bit Windows." }
$asset = "cfs-windows-x64.exe"
$base = if ($Version -eq "latest") { "https://github.com/$repo/releases/latest/download" } else { "https://github.com/$repo/releases/download/$Version" }

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("cfs-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  Write-Host "Downloading $asset ($Version)..."
  Invoke-WebRequest "$base/$asset" -OutFile (Join-Path $tmp $asset)
  Invoke-WebRequest "$base/SHA256SUMS" -OutFile (Join-Path $tmp "SHA256SUMS")

  $line = Get-Content (Join-Path $tmp "SHA256SUMS") | Where-Object { $_ -match "\s\*?$([regex]::Escape($asset))$" } | Select-Object -First 1
  if (-not $line) { throw "SHA256SUMS has no entry for $asset. Nothing was installed." }
  $want = ($line -split "\s+")[0].ToLower()
  $got = (Get-FileHash (Join-Path $tmp $asset) -Algorithm SHA256).Hash.ToLower()
  if ($got -ne $want) { throw "Checksum mismatch for $asset. Nothing was installed." }

  New-Item -ItemType Directory -Path $dir -Force | Out-Null
  Move-Item (Join-Path $tmp $asset) (Join-Path $dir "cfs.exe") -Force
} finally {
  Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not (($userPath -split ";") -contains $dir)) {
  [Environment]::SetEnvironmentVariable("Path", "$userPath;$dir", "User")
  Write-Host "Added $dir to your PATH. Open a new terminal to use it."
}
Write-Host "Installed cfs to $dir\cfs.exe"
Write-Host "Next: cfs login --host https://your-vault.example.com"
