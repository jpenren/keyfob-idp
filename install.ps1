# keyfob installation script for Windows (PowerShell)
# Usage:
#   irm https://jpenren.github.io/keyfob-idp/install.ps1 | iex
# or:
#   irm https://raw.githubusercontent.com/jpenren/keyfob-idp/main/install.ps1 | iex

$ErrorActionPreference = 'Stop'

$Repo = "jpenren/keyfob-idp"
$App = "keyfob"
$Asset = "keyfob-windows-x86_64.zip"

function Write-Info($msg) {
    Write-Host "==> " -ForegroundColor Cyan -NoNewline
    Write-Host $msg
}

function Write-Success($msg) {
    Write-Host "`u{2713} " -ForegroundColor Green -NoNewline
    Write-Host $msg
}

function Write-Warn($msg) {
    Write-Host "! " -ForegroundColor Yellow -NoNewline
    Write-Host $msg
}

# 1. Architecture Check
if (-not [Environment]::Is64BitOperatingSystem) {
    Write-Error "keyfob requires a 64-bit operating system."
    exit 1
}

# 2. Determine target version & URLs
if ($env:KEYFOB_VERSION) {
    $Version = $env:KEYFOB_VERSION
    if (-not $Version.StartsWith("v")) {
        $Version = "v$Version"
    }
    $DownloadUrl = "https://github.com/$Repo/releases/download/$Version/$Asset"
    $ChecksumUrl = "https://github.com/$Repo/releases/download/$Version/SHA256SUMS"
} else {
    $DownloadUrl = "https://github.com/$Repo/releases/latest/download/$Asset"
    $ChecksumUrl = "https://github.com/$Repo/releases/latest/download/SHA256SUMS"
}

# 3. Determine Installation Directory
if ($env:KEYFOB_INSTALL_DIR) {
    $InstallDir = $env:KEYFOB_INSTALL_DIR
} else {
    $InstallDir = Join-Path $HOME ".local\bin"
}

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

Write-Info "Installing $App into $InstallDir..."

# 4. Create temporary directory
$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

try {
    $ZipPath = Join-Path $TempDir $Asset
    $ChecksumPath = Join-Path $TempDir "SHA256SUMS"

    Write-Info "Downloading $Asset..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $ZipPath -UseBasicParsing

    # Download checksums
    try {
        Invoke-WebRequest -Uri $ChecksumUrl -OutFile $ChecksumPath -UseBasicParsing -ErrorAction SilentlyContinue
    } catch {
        # Optional checksum file download failure
    }

    # Verify checksum if present
    if (Test-Path $ChecksumPath) {
        $ChecksumContent = Get-Content $ChecksumPath
        $Match = $ChecksumContent | Where-Object { $_ -match $Asset }
        if ($Match) {
            $ExpectedHash = ($Match -split '\s+')[0].Trim().ToUpper()
            $ActualHash = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash.ToUpper()

            Write-Info "Verifying SHA256 checksum..."
            if ($ExpectedHash -ne $ActualHash) {
                Write-Error "Checksum mismatch! Expected: $ExpectedHash, got: $ActualHash"
                exit 1
            }
            Write-Success "Checksum verified ($ActualHash)"
        }
    }

    # 5. Extract archive
    Write-Info "Extracting archive..."
    $ExtractDir = Join-Path $TempDir "extracted"
    Expand-Archive -Path $ZipPath -DestinationPath $ExtractDir -Force

    $ExeFile = Get-ChildItem -Path $ExtractDir -Filter "$App.exe" -Recurse | Select-Object -First 1
    if (-not $ExeFile) {
        Write-Error "Could not find $App.exe inside the extracted archive."
        exit 1
    }

    $DestFile = Join-Path $InstallDir "$App.exe"
    Copy-Item -Path $ExeFile.FullName -Destination $DestFile -Force
    Write-Success "Installed $App.exe to $DestFile"

    # 6. Check and update PATH
    $UserPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)
    $PathParts = $UserPath -split ';' | ForEach-Object { $_.TrimEnd('\') }

    if ($PathParts -notcontains $InstallDir.TrimEnd('\')) {
        Write-Info "Adding $InstallDir to User PATH..."
        $NewPath = "$UserPath;$InstallDir"
        [Environment]::SetEnvironmentVariable("Path", $NewPath, [EnvironmentVariableTarget]::User)
        $env:PATH = "$env:PATH;$InstallDir"
        Write-Success "Added to User PATH. You may need to restart your terminal for it to take effect in other windows."
    }

    Write-Host ""
    Write-Host "Keyfob has been installed successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Get started:"
    Write-Host "  keyfob.exe init       # generate a default keyfob.yaml"
    Write-Host "  keyfob.exe run        # start the in-memory OIDC provider"
    Write-Host ""
}
finally {
    # Clean up temp directory
    if (Test-Path $TempDir) {
        Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
