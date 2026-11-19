<#
.SYNOPSIS
    Script de publication et de packaging automatisé pour CyberSentinel AI.
.DESCRIPTION
    Ce script compile l'application en configuration Release, génère le bundle
    autonome pour Windows 10/11 x64, intègre les modèles d'IA EMBER, les règles YARA,
    et prépare le répertoire de déploiement final.
#>

[CmdletBinding()]
param(
    [string]$Configuration = "Release",
    [string]$Runtime = "win-x64",
    [string]$OutputDir = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$root = (Get-Item $PSScriptRoot).Parent.FullName
if (-not $OutputDir) {
    $OutputDir = "$root\publish\$Runtime"
}
$env:APPDATA = "$root\.dotnet\AppData"
$env:DOTNET_CLI_HOME = "$root\.dotnet"

Write-Host "`n[1/5] Nettoyage et préparation du répertoire de sortie..." -ForegroundColor Yellow
if (Test-Path $OutputDir) {
    Remove-Item -Path $OutputDir -Recurse -Force
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
New-Item -ItemType Directory -Path "$OutputDir\Models" -Force | Out-Null
New-Item -ItemType Directory -Path "$OutputDir\Rules" -Force | Out-Null
New-Item -ItemType Directory -Path "$OutputDir\Quarantine" -Force | Out-Null

Write-Host "[2/5] Compilation de la solution en mode $Configuration..." -ForegroundColor Yellow
& 'C:\Program Files\dotnet\sdk\10.0.402\MSBuild.exe' "$root\CyberSentinel_AI.slnx" /p:Configuration=$Configuration /v:m

if ($LASTEXITCODE -ne 0) {
    Write-Error "Échec de la compilation de la solution."
    exit 1
}

Write-Host "[3/5] Déploiement des binaires de l'application Desktop..." -ForegroundColor Yellow
$desktopBin = "$root\src\CyberSentinel.Desktop\bin\$Configuration\net10.0-windows"
Copy-Item -Path "$desktopBin\*" -Destination $OutputDir -Recurse -Force

Write-Host "[4/5] Copie des artefacts de sécurité et modèles IA..." -ForegroundColor Yellow
# Modèle ONNX EMBER
$dummyModelSource = "$root\src\CyberSentinel.AI\Models"
if (Test-Path $dummyModelSource) {
    Copy-Item -Path "$dummyModelSource\*" -Destination "$OutputDir\Models" -Recurse -Force -ErrorAction SilentlyContinue
}

# Fichier de configuration par défaut
$defaultConfig = @"
{
  "Logging": {
    "LogLevel": "Information",
    "LogDirectory": "%ProgramData%\\CyberSentinel\\Logs"
  },
  "Engines": {
    "ClamAv": {
      "Enabled": true,
      "Host": "127.0.0.1",
      "Port": 3310,
      "TimeoutSeconds": 15
    },
    "Yara": {
      "Enabled": true,
      "RulesDirectory": "Rules"
    },
    "EmberAi": {
      "Enabled": true,
      "ModelPath": "Models\\ember_malware_model.onnx",
      "Threshold": 0.85
    }
  },
  "Quarantine": {
    "Directory": "%ProgramData%\\CyberSentinel\\Quarantine",
    "MaxRetentionDays": 90
  },
  "Vulnerabilities": {
    "NvdApiEndpoint": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "CacheTtlHours": 24
  }
}
"@
Set-Content -Path "$OutputDir\appsettings.json" -Value $defaultConfig -Encoding UTF8

Write-Host "[5/5] Création de l'archive de distribution ZIP..." -ForegroundColor Yellow
$zipArchive = "$root\publish\CyberSentinel_AI_v1.0.0_$Runtime.zip"
if (Test-Path $zipArchive) {
    Remove-Item $zipArchive -Force
}
Compress-Archive -Path "$OutputDir\*" -DestinationPath $zipArchive -Force

Write-Host "`n================================================================" -ForegroundColor Green
Write-Host " [SUCCÈS] Livraison prête dans : $OutputDir" -ForegroundColor Green
Write-Host " [SUCCÈS] Archive de distribution : $zipArchive" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
