# WiX Installer Build Fix

## Problem
The `cargo-wix` tool was not passing the `-ext WixUIExtension` flag to the WiX linker (`light.exe`), causing unresolved references to `Dialog:ExitDlg`.

## Solution Options

### Option 1: Use the PowerShell Build Script (Recommended for CI)
Replace `cargo wix` with the custom build script in GitHub Actions:

```powershell
.\build-msi.ps1 -BinDir "target\x86_64-pc-windows-msvc\release" -MinifilterDir "$env:MINIFILTER_PKG_DIR" -TrayAppBinDir "..\tray-app\src-tauri\target\x86_64-pc-windows-msvc\release"
```

### Option 2: Manually with WiX Tools
Compile with WiX Toolset directly:

```powershell
# Compile
"C:\Program Files (x86)\WiX Toolset v3.14\bin\candle.exe" `
  -d "Version=0.1.0" `
  -d "BinDir=target\x86_64-pc-windows-msvc\release" `
  -d "MinifilterDir=..." `
  -o "target\wix\" `
  "wix\main.wxs" "wix\ui.wxs"

# Link with extension
"C:\Program Files (x86)\WiX Toolset v3.14\bin\light.exe" `
  -ext WixUIExtension `
  -out "target\wix\keysas-firewall-0.1.0-x64.msi" `
  "target\wix\*.wxo"
```

### Option 3: Update GitHub Actions Workflow
Modify `.github/workflows/keysas-firewall.yml` to use the build script:

```yaml
- name: Package MSI (custom WiX build)
  shell: pwsh
  working-directory: keysas-firewall/daemon
  run: |
    $minifilterDir = $env:MINIFILTER_PKG_DIR
    if (-not $minifilterDir) { throw "MINIFILTER_PKG_DIR not set" }
    .\build-msi.ps1 `
      -BinDir "target\x86_64-pc-windows-msvc\release" `
      -MinifilterDir "$minifilterDir" `
      -TrayAppBinDir "..\tray-app\src-tauri\target\x86_64-pc-windows-msvc\release"
```

## Files Changed
1. **Cargo.toml** - Added UI namespace to track extension usage
2. **wix/main.wxs** - Added UI namespace `xmlns:ui='http://schemas.microsoft.com/wix/2006/ui'`
3. **wix/ui.wxs** - Created fragment file (optional, for clarity)
4. **build-msi.ps1** - New custom build script with proper extension linking
5. **build.rs** - Added informational build script

## Why This Happens
`cargo-wix` v0.3 does not automatically pass `-ext WixUIExtension` to `light.exe` when required. The WiX linker needs this flag to resolve dialog definitions from the WixUIExtension library. Using a custom build script or modifying the workflow ensures this flag is passed correctly.
