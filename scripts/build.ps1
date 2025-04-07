# DSM Project Build Script for Windows
# Usage: .\scripts\build.ps1 [target] [-Release] [-Verbose]

param(
    [Parameter(Position=0)]
    [ValidateSet("all", "dsm", "storage-node", "ethereum-bridge", "sdk")]
    [string]$Target = "all",
    
    [Parameter()]
    [switch]$Release,
    
    [Parameter()]
    [switch]$Verbose
)

# Set build type and directory
$BuildType = if ($Release) { "release" } else { "debug" }
$BuildDir = if ($Release) { "release" } else { "debug" }

# Set cargo flags
$CargoFlags = if ($Release) { "--release" } else { "" }
if ($Verbose) {
    $CargoFlags = "$CargoFlags --verbose"
}

# Display build configuration
Write-Host "Building DSM Project:" -ForegroundColor Cyan
Write-Host "  Target:     $Target"
Write-Host "  Build type: $BuildType"
Write-Host ""

# Check for required dependencies
Write-Host "Checking dependencies..." -ForegroundColor Cyan

# Check for Rust toolchain
if (-not (Get-Command "cargo" -ErrorAction SilentlyContinue)) {
    Write-Host "Error: Rust toolchain not found. Please install Rust from https://rustup.rs/" -ForegroundColor Red
    exit 1
}

# Check for LLVM and Clang
if (-not (Get-Command "clang" -ErrorAction SilentlyContinue)) {
    Write-Host "Warning: Clang not found. Some components may fail to build." -ForegroundColor Yellow
    Write-Host "  Please install LLVM and Clang from https://releases.llvm.org/download.html"
    $continue = Read-Host "Do you want to continue without Clang? (y/n)"
    if ($continue -ne "y") {
        exit 1
    }
}

# Create .env file if it doesn't exist
if (-not (Test-Path ".env")) {
    Write-Host "Creating default .env file from template..." -ForegroundColor Yellow
    Copy-Item ".env.template" ".env"
}

# Build function
function Build-Component {
    param(
        [string]$ComponentName,
        [string]$Path
    )
    
    Write-Host "Building $ComponentName..." -ForegroundColor Cyan
    
    # Check if component directory exists
    if (-not (Test-Path $Path)) {
        Write-Host "Error: Directory $Path not found!" -ForegroundColor Red
        exit 1
    }
    
    # Build the component
    $currentLocation = Get-Location
    Set-Location $Path
    
    try {
        $output = Invoke-Expression "cargo build $CargoFlags"
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ $ComponentName built successfully" -ForegroundColor Green
        } else {
            Write-Host "❌ Failed to build $ComponentName" -ForegroundColor Red
            Write-Host $output
            exit 1
        }
    }
    finally {
        Set-Location $currentLocation
    }
}

# Windows-specific dependency checks
Write-Host "Checking Windows-specific dependencies..." -ForegroundColor Cyan

# Check for RocksDB (which can be tricky on Windows)
Write-Host "Note: RocksDB may require manual setup on Windows." -ForegroundColor Yellow
Write-Host "  See https://github.com/facebook/rocksdb/wiki/Building-on-Windows for instructions."
Write-Host "  If build fails, you may need to set ROCKSDB_LIB_DIR environment variable."
Write-Host ""

# Build based on target
switch ($Target) {
    "all" {
        Build-Component "dsm" "dsm"
        Build-Component "dsm-storage-node" "dsm-storage-node"
        Build-Component "dsm-ethereum-bridge" "dsm-ethereum-bridge"
        Build-Component "dsm-sdk" "dsm-sdk"
        Write-Host ""
        Write-Host "✅ All components built successfully!" -ForegroundColor Green
        Write-Host "Binaries are available in the target\$BuildDir directory of each component."
    }
    "dsm" {
        Build-Component "dsm" "dsm"
    }
    "storage-node" {
        Build-Component "dsm-storage-node" "dsm-storage-node"
    }
    "ethereum-bridge" {
        Build-Component "dsm-ethereum-bridge" "dsm-ethereum-bridge"
    }
    "sdk" {
        Build-Component "dsm-sdk" "dsm-sdk"
    }
}

Write-Host ""
Write-Host "Build complete. Use .\scripts\run.ps1 to start the components." -ForegroundColor Cyan
