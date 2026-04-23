# PowerShell script to compile WiX installer with proper UI extension support
# This script is an alternative to cargo-wix when the extension is not being linked properly

param(
    [string]$BinDir = "target\x86_64-pc-windows-msvc\release",
    [string]$MinifilterDir = $env:MINIFILTER_PKG_DIR,
    [string]$TrayAppBinDir = "..\tray-app\src-tauri\target\x86_64-pc-windows-msvc\release"
)

# Get version from Cargo.toml (first match only)
$versionMatch = Get-Content "Cargo.toml" | Select-String 'version = "([^"]+)"' | Select-Object -First 1
$version = if ($versionMatch) { $versionMatch.Matches.Groups[1].Value } else { "0.0.0" }
Write-Host "Building Keysas USB Firewall Installer v$version"

# Find WiX Toolset
$wixPaths = @(
    "C:\Program Files (x86)\WiX Toolset v3.14\bin",
    "C:\Program Files (x86)\WiX Toolset v3.11\bin",
    "C:\Program Files\WiX Toolset v3.14\bin",
    "C:\Program Files\WiX Toolset v3.11\bin"
)

$wixBin = $null
foreach ($path in $wixPaths) {
    if (Test-Path $path) {
        $wixBin = $path
        Write-Host "Found WiX Toolset at: $wixBin"
        break
    }
}

if (-not $wixBin) {
    Write-Error "WiX Toolset v3 not found. Please install it from https://wixtoolset.org/"
    exit 1
}

$candle = Join-Path $wixBin "candle.exe"
$light = Join-Path $wixBin "light.exe"

# Create output directory (absolute path)
$outDir = Join-Path $PWD "target\wix"
if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}
Write-Host "Output directory: $outDir"

# Compile WiX source
Write-Host "Compiling WiX source..."
# Build argument list with -o as separate argument
$candleArgs = @(
    "-dVersion=$version",
    "-dBinDir=$BinDir",
    "-dMinifilterDir=$MinifilterDir",
    "-dTrayAppBinDir=$TrayAppBinDir",
    "-o", $outDir,
    "wix\main.wxs",
    "wix\ui.wxs"
)
Write-Host "Candle args: $candleArgs"
& $candle @($candleArgs)

if ($LASTEXITCODE -ne 0) {
    Write-Error "Candle compilation failed"
    exit 1
}

# Link with UI extension
Write-Host "Linking MSI with UI extension..."
Write-Host "Looking for .wxo files in: $outDir"

# Check if directory exists and list all contents
if (Test-Path $outDir) {
    Write-Host "Directory exists. Contents:"
    Get-ChildItem -Path "$outDir" | ForEach-Object { Write-Host "  - $($_.Name) (type: $($_.Extension))" }
} else {
    Write-Host "Directory does NOT exist!"
}

$wixObjFiles = @(Get-ChildItem -Path "$outDir" -Filter "*.wxo" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
Write-Host "Found $($wixObjFiles.Count) .wxo file(s)"
if ($wixObjFiles.Count -eq 0) {
    Write-Error "No .wxo object files found in $outDir"
    exit 1
}
$msiOutput = Join-Path $outDir "keysas-firewall-$version-x64.msi"
$lightArgs = @("-ext", "WixUIExtension", "-out$msiOutput") + @($wixObjFiles)
& $light @($lightArgs)

if ($LASTEXITCODE -ne 0) {
    Write-Error "Light linking failed"
    exit 1
}

Write-Host "MSI built successfully: $msiOutput"
