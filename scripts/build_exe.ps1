param(
    [switch]$Install
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$PythonExe = Join-Path $RepoRoot ".venv\Scripts\python.exe"
$PyInstallerExe = Join-Path $RepoRoot ".venv\Scripts\pyinstaller.exe"

if (-not (Test-Path $PythonExe)) {
    throw "Virtual environment not found at $PythonExe"
}
if (-not (Test-Path $PyInstallerExe)) {
    throw "PyInstaller not found at $PyInstallerExe"
}

$BuildRoot = Join-Path $env:TEMP "ScreenShieldBuild"
$DistPath = Join-Path $BuildRoot "dist"
$WorkPath = Join-Path $BuildRoot "work"
$SpecPath = Join-Path $BuildRoot "spec"
$IconPath = Join-Path $BuildRoot "screenshield.ico"

New-Item -ItemType Directory -Force -Path $BuildRoot, $DistPath, $WorkPath, $SpecPath | Out-Null

# Generate multi-resolution icon into %TEMP%\ScreenShieldBuild
& $PythonExe -c "from pathlib import Path; from screenshield.assets import ensure_icon_file; ensure_icon_file(Path(r'$IconPath'))"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$EntryScript = Join-Path $RepoRoot "screenshield\__main__.py"
$WebSrc = Join-Path $RepoRoot "screenshield\web"

$PyArgs = @(
    "--noconfirm",
    "--clean",
    "--windowed",
    "--noconsole",
    "--onedir",
    "--name", "ScreenShield",
    "--distpath", $DistPath,
    "--workpath", $WorkPath,
    "--specpath", $SpecPath,
    "--icon", $IconPath,
    "--add-data", "$WebSrc;screenshield/web",
    "--hidden-import", "uvicorn.logging",
    "--hidden-import", "uvicorn.loops.auto",
    "--hidden-import", "uvicorn.protocols.http.auto",
    "--hidden-import", "uvicorn.lifespan.on",
    "--hidden-import", "clr_loader",
    "--hidden-import", "pythonnet",
    "--collect-submodules", "webview",
    $EntryScript
)

Push-Location $RepoRoot
try {
    & $PyInstallerExe @PyArgs
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    Pop-Location
}

$BuiltDir = Join-Path $DistPath "ScreenShield"
$BuiltExe = Join-Path $BuiltDir "ScreenShield.exe"
if (-not (Test-Path $BuiltExe)) {
    throw "Expected executable not found at $BuiltExe"
}
Write-Host "Build completed: $BuiltExe"

if ($Install) {
    Get-Process -Name "ScreenShield" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 300

    $InstallDir = Join-Path $env:LOCALAPPDATA "ScreenShield\app"
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item -Path (Join-Path $BuiltDir "*") -Destination $InstallDir -Recurse -Force

    $InstalledExe = Join-Path $InstallDir "ScreenShield.exe"
    $WshShell = New-Object -ComObject WScript.Shell

    $DesktopLnk = Join-Path ([Environment]::GetFolderPath("Desktop")) "ScreenShield.lnk"
    $StartMenuDir = Join-Path ([Environment]::GetFolderPath("StartMenu")) "Programs"
    $StartMenuLnk = Join-Path $StartMenuDir "ScreenShield.lnk"

    foreach ($LnkPath in @($DesktopLnk, $StartMenuLnk)) {
        $Shortcut = $WshShell.CreateShortcut($LnkPath)
        $Shortcut.TargetPath = $InstalledExe
        $Shortcut.WorkingDirectory = $InstallDir
        $Shortcut.IconLocation = "$InstalledExe,0"
        $Shortcut.Description = "ScreenShield Live Privacy Shield"
        $Shortcut.Save()
    }
    Write-Host "Installed to: $InstallDir"
}
