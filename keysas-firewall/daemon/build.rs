// Custom build script to ensure WiX compilation with proper extension support
use std::env;
use std::path::PathBuf;

fn main() {
    // Note: This script primarily validates the WiX Toolset installation.
    // Actual MSI compilation is handled by cargo-wix or the build-msi.ps1 script.
    // 
    // If you encounter "Unresolved reference to symbol 'Dialog:ExitDlg'" errors,
    // use the build-msi.ps1 script instead of cargo-wix:
    //   .\build-msi.ps1 -BinDir "target\x86_64-pc-windows-msvc\release" ...

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let wix_dir = PathBuf::from(&manifest_dir).join("wix");
    let main_wxs = wix_dir.join("main.wxs");

    // Only check MSI on Windows
    #[cfg(target_os = "windows")]
    {
        if main_wxs.exists() {
            println!("cargo:warning=WiX source found. MSI can be built with:");
            println!("cargo:warning=  Option A: cargo wix (may fail if WixUIExtension not linked)");
            println!("cargo:warning=  Option B: .\\build-msi.ps1 (recommended - explicit extension linking)");
            
            // Try to find the WiX toolset installation
            let wix_paths = vec![
                "C:\\Program Files (x86)\\WiX Toolset v3.14\\bin",
                "C:\\Program Files (x86)\\WiX Toolset v3.11\\bin",
                "C:\\Program Files\\WiX Toolset v3.14\\bin",
                "C:\\Program Files\\WiX Toolset v3.11\\bin",
            ];
            
            let mut wix_found = false;
            for wix_path in &wix_paths {
                if PathBuf::from(wix_path).exists() {
                    println!("cargo:warning=✓ Found WiX Toolset at: {}", wix_path);
                    wix_found = true;
                    break;
                }
            }
            
            if !wix_found {
                println!("cargo:warning=✗ WiX Toolset v3 not found in standard locations");
                println!("cargo:warning=  Install from: https://wixtoolset.org/");
                println!("cargo:warning=  or check PATH");
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        if main_wxs.exists() {
            println!("cargo:warning=WiX source found (MSI compilation only works on Windows)");
            println!("cargo:warning=Use wixl for cross-compilation: wixl wix/main.wxs");
        }
    }
}
