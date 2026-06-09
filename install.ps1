# sshx Automatic Installation Script for Windows
# PowerShell script to install sshx on Windows

param(
    [string]$Version = "latest",
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\sshx"
)

$ErrorActionPreference = "Stop"

# Configuration
$Repo = "talkincode/sshx"
$BinaryName = "sshx.exe"

# Functions
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Type = "Info"
    )

    switch ($Type) {
        "Success" { Write-Host "✓ $Message" -ForegroundColor Green }
        "Error"   { Write-Host "✗ $Message" -ForegroundColor Red }
        "Warning" { Write-Host "⚠ $Message" -ForegroundColor Yellow }
        "Info"    { Write-Host "ℹ $Message" -ForegroundColor Blue }
        default   { Write-Host $Message }
    }
}

function Get-LatestVersion {
    Write-ColorOutput "Fetching latest version..." "Info"

    try {
        $response = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
        return $response.tag_name
    }
    catch {
        Write-ColorOutput "Failed to fetch latest version: $_" "Error"
        exit 1
    }
}

function Get-Platform {
    $arch = $env:PROCESSOR_ARCHITECTURE

    switch ($arch) {
        "AMD64" { return "windows-amd64" }
        "ARM64" { return "windows-arm64" }
        default {
            Write-ColorOutput "Unsupported architecture: $arch" "Error"
            exit 1
        }
    }
}

function Install-Sshx {
    $platform = Get-Platform
    $targetVersion = $Version

    if ($targetVersion -eq "latest") {
        $targetVersion = Get-LatestVersion
    }

    Write-ColorOutput "Platform: $platform" "Info"
    Write-ColorOutput "Version: $targetVersion" "Info"

    # Construct download URL
    $filename = "sshx-$platform.zip"
    $downloadUrl = "https://github.com/$Repo/releases/download/$targetVersion/$filename"

    Write-ColorOutput "Downloading from: $downloadUrl" "Info"

    # Create temporary directory
    $tmpDir = Join-Path $env:TEMP ([System.IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Path $tmpDir | Out-Null

    $zipFile = Join-Path $tmpDir $filename

    try {
        # Download
        Invoke-WebRequest -Uri $downloadUrl -OutFile $zipFile -UseBasicParsing
        Write-ColorOutput "Downloaded successfully" "Success"

        # Extract
        Write-ColorOutput "Extracting..." "Info"
        Expand-Archive -Path $zipFile -DestinationPath $tmpDir -Force

        # Create installation directory if it doesn't exist
        if (-not (Test-Path $InstallDir)) {
            New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        }

        # Move binary
        Write-ColorOutput "Installing to $InstallDir..." "Info"
        $sourceBinary = Join-Path $tmpDir $BinaryName
        $destBinary = Join-Path $InstallDir $BinaryName

        if (Test-Path $destBinary) {
            Remove-Item $destBinary -Force
        }

        Move-Item $sourceBinary $destBinary -Force

        Write-ColorOutput "Installation complete!" "Success"
    }
    catch {
        Write-ColorOutput "Installation failed: $_" "Error"
        exit 1
    }
    finally {
        # Cleanup
        Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Add-ToPath {
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")

    if ($currentPath -notlike "*$InstallDir*") {
        Write-ColorOutput "Adding $InstallDir to PATH..." "Info"

        $newPath = "$currentPath;$InstallDir"
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")

        # Update current session
        $env:Path = "$env:Path;$InstallDir"

        Write-ColorOutput "Added to PATH successfully" "Success"
        Write-ColorOutput "Please restart your terminal for PATH changes to take effect" "Warning"
    }
    else {
        Write-ColorOutput "$InstallDir is already in PATH" "Info"
    }
}

function Test-Installation {
    $binaryPath = Join-Path $InstallDir $BinaryName

    if (Test-Path $binaryPath) {
        Write-ColorOutput "$BinaryName installed successfully" "Success"
        Write-ColorOutput "Location: $binaryPath" "Info"

        # Try to get version
        try {
            $versionOutput = & $binaryPath --version 2>&1
            Write-ColorOutput "Version: $versionOutput" "Info"
        }
        catch {
            # Ignore version check errors
        }

        return $true
    }
    else {
        Write-ColorOutput "Installation verification failed" "Error"
        return $false
    }
}

function Show-QuickStart {
    Write-Host ""
    Write-ColorOutput "Quick Start:" "Info"
    Write-Host "  # Execute remote command"
    Write-Host "  sshx -h=192.168.1.100 -u=Administrator 'systeminfo'"
    Write-Host ""
    Write-Host "  # Save password (optional)"
    Write-Host "  sshx --set-password host=192.168.1.100 user=Administrator"
    Write-Host ""
    Write-Host "  # Start MCP server"
    Write-Host "  sshx mcp-stdio"
    Write-Host ""
    Write-ColorOutput "Documentation: https://github.com/$Repo" "Info"
}

# Main
function Main {
    Write-Host ""
    Write-Host "╔════════════════════════════════════════╗"
    Write-Host "║   sshx Automatic Installer            ║"
    Write-Host "║   SSH & SFTP Tool with MCP Support     ║"
    Write-Host "╚════════════════════════════════════════╝"
    Write-Host ""

    # Check for existing installation
    $existingBinary = Join-Path $InstallDir $BinaryName
    if (Test-Path $existingBinary) {
        Write-ColorOutput "$BinaryName is already installed at: $existingBinary" "Warning"
        $response = Read-Host "Do you want to overwrite it? [y/N]"
        if ($response -notmatch "^[Yy]$") {
            Write-ColorOutput "Installation cancelled" "Info"
            exit 0
        }
    }

    Install-Sshx
    Add-ToPath

    if (Test-Installation) {
        Show-QuickStart
    }
    else {
        exit 1
    }
}

# Run
Main
