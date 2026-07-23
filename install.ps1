$ErrorActionPreference = "Stop"
$Model = if ($env:DATASNIPER_MODEL) { $env:DATASNIPER_MODEL } else { "qwen3-vl:4b-instruct-q4_K_M" }

if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) {
    Write-Host "Preparing DataSniper's private local intelligence..."
    winget install --id Ollama.Ollama --exact --silent --accept-package-agreements --accept-source-agreements
    $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
}
if (-not (Get-Process ollama -ErrorAction SilentlyContinue)) {
    Start-Process -WindowStyle Hidden ollama -ArgumentList "serve"
    Start-Sleep -Seconds 3
}
$Installed = ollama list 2>$null | Select-String -SimpleMatch ($Model.Split(":")[0])
if (-not $Installed) {
    ollama pull $Model
}
ollama show $Model | Out-Null

if (-not (Test-Path ".venv")) { py -3.11 -m venv .venv }
& .venv\Scripts\python.exe -m pip install --disable-pip-version-check -r requirements.txt
& .venv\Scripts\python.exe -m playwright install chromium
Write-Host "DataSniper is ready. The local intelligence service stays on this computer."

