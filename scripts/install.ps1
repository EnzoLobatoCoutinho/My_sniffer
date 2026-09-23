# Build and install my_sniffer on Windows.
#
# Usage: .\scripts\install.ps1 [-Prefix <path>]
#   -Prefix  install destination (default: $Env:ProgramFiles\my_sniffer)

param(
    [string]$Prefix = "$Env:ProgramFiles\my_sniffer"
)

$ErrorActionPreference = "Stop"

Write-Host "==> Checking for the Npcap driver"
$npcapService = Get-Service -Name npcap -ErrorAction SilentlyContinue
if (-not $npcapService) {
    Write-Warning "Npcap driver not detected. Install it from https://npcap.com/#download before running my_sniffer (the SDK alone is not enough at runtime)."
}

Write-Host "==> Detecting Conan profile"
conan profile detect --force | Out-Null

Write-Host "==> Installing dependencies (Conan)"
conan install . --output-folder=build --build=missing

Write-Host "==> Configuring (CMake)"
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release `
    -DCMAKE_TOOLCHAIN_FILE="$PWD/build/conan_toolchain.cmake"

Write-Host "==> Building"
cmake --build build --config Release

Write-Host "==> Installing to $Prefix"
cmake --install build --config Release --prefix "$Prefix"

Write-Host "==> Done. Run from an Administrator terminal: $Prefix\bin\my_sniffer.exe <interface>"
