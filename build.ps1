<#
.SYNOPSIS
  Compila PS5 Permission Broker para PS5 FW 5.50 desde Windows 11 usando WSL2.
.DESCRIPTION
  Ejecuta la toolchain Prospero dentro de WSL. Detecta el SDK PS5_PAYLOAD_SDK,
  prepara libhijacker si hace falta, compila, valida el encabezado ELF x86-64 y
  copia el resultado a .\dist\permission_broker.elf.
.EXAMPLE
  .\build.ps1
.EXAMPLE
  .\build.ps1 -SdkPath "D:\PS5\ps5-payload-sdk" -Clean
.EXAMPLE
  .\build.ps1 -Distro Ubuntu-24.04 -Jobs 8
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$SdkPath = "",

    [Parameter()]
    [string]$Distro = "",

    [Parameter()]
    [ValidateRange(0, 128)]
    [int]$Jobs = 0,

    [Parameter()]
    [switch]$Clean,

    [Parameter()]
    [switch]$SkipDependencySetup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host "[ OK ] $Message" -ForegroundColor Green
}

function Write-Fail {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Invoke-Wsl {
    param([Parameter(Mandatory)][string[]]$Arguments)
    if ([string]::IsNullOrWhiteSpace($Distro)) {
        & $script:WslExe @Arguments
    }
    else {
        & $script:WslExe --distribution $Distro @Arguments
    }
    if ($LASTEXITCODE -ne 0) {
        throw "WSL devolvió el código $LASTEXITCODE al ejecutar: $($Arguments -join ' ')"
    }
}

try {
    $projectRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
    $makefile = Join-Path $projectRoot 'Makefile'
    $mainSource = Join-Path $projectRoot 'source\main.cpp'

    if (-not (Test-Path -LiteralPath $makefile -PathType Leaf) -or
        -not (Test-Path -LiteralPath $mainSource -PathType Leaf)) {
        throw "No encuentro Makefile y source\main.cpp. Coloca build.ps1 en la raíz de PS5-Permission-Broker_FW550 y vuelve a ejecutarlo."
    }

    $wslCommand = Get-Command 'wsl.exe' -ErrorAction SilentlyContinue
    if (-not $wslCommand) {
        throw 'No encuentro wsl.exe. Instala/activa WSL 2 desde Windows 11 y configura una distribución Linux.'
    }
    $script:WslExe = $wslCommand.Source

    Write-Info 'Comprobando WSL...'
    $null = & $script:WslExe --status 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw 'WSL no responde correctamente. Ejecuta «wsl --status» y comprueba que tienes una distribución instalada.'
    }

    if (-not [string]::IsNullOrWhiteSpace($Distro)) {
        $distros = @(& $script:WslExe --list --quiet 2>$null) |
            ForEach-Object { ("$_" -replace "`0", '').Trim() } |
            Where-Object { $_ }
        if ($distros -notcontains $Distro) {
            throw "La distribución WSL '$Distro' no está instalada. Disponibles: $($distros -join ', ')"
        }
    }

    $wslProject = (Invoke-Wsl -Arguments @('--exec', 'wslpath', '-a', $projectRoot) | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($wslProject)) {
        throw 'No se pudo convertir la ruta del proyecto a formato WSL.'
    }

    # Prioridad: parámetro -SdkPath, variable Windows PS5_PAYLOAD_SDK y autodetección Linux.
    $sdkInput = $SdkPath
    if ([string]::IsNullOrWhiteSpace($sdkInput) -and
        -not [string]::IsNullOrWhiteSpace($env:PS5_PAYLOAD_SDK)) {
        $sdkInput = $env:PS5_PAYLOAD_SDK
    }

    $wslSdk = ''
    if (-not [string]::IsNullOrWhiteSpace($sdkInput)) {
        if ($sdkInput.StartsWith('/')) {
            $wslSdk = $sdkInput
        }
        else {
            $wslSdk = (Invoke-Wsl -Arguments @('--exec', 'wslpath', '-a', $sdkInput) | Out-String).Trim()
        }
    }

    $bashScript = @'
set -Eeuo pipefail
PROJECT_DIR="$(printf '%s' "${PROJECT_B64:?}" | base64 -d)"
SDK_OVERRIDE="$(printf '%s' "${SDK_B64:-}" | base64 -d)"
REQUESTED_JOBS="${JOBS:-0}"
DO_CLEAN="${DO_CLEAN:-0}"
DO_PREPARE="${DO_PREPARE:-1}"

fail() { printf '\n[ERROR] %s\n' "$*" >&2; exit 1; }
info() { printf '\n[INFO] %s\n' "$*"; }
ok()   { printf '[ OK ] %s\n' "$*"; }

[[ -d "$PROJECT_DIR" ]] || fail "No existe el directorio del proyecto: $PROJECT_DIR"
cd "$PROJECT_DIR"
[[ -f Makefile && -f source/main.cpp ]] || fail "La ruta no contiene el proyecto PS5 Permission Broker."

command -v bash >/dev/null 2>&1 || fail "bash no está disponible en WSL."
command -v make >/dev/null 2>&1 || fail "Falta make. Instala build-essential en tu distribución WSL."
command -v git >/dev/null 2>&1 || fail "Falta git. Instala git en tu distribución WSL."

SDK_ROOT="$SDK_OVERRIDE"
if [[ -z "$SDK_ROOT" && -n "${PS5_PAYLOAD_SDK:-}" ]]; then
  SDK_ROOT="$PS5_PAYLOAD_SDK"
fi

if [[ -z "$SDK_ROOT" ]]; then
  # Ruta de SDK utilizada previamente en este entorno y ubicaciones habituales.
  candidates=(
    "$HOME/.cache/ps5-native-builds/TALLERDECOLADAPS-OpenGL-UI/.deps/native/ps5-payload-sdk"
    "$HOME/ps5-payload-sdk"
    "/opt/ps5-payload-sdk"
    "/opt/ps5-sdk"
  )
  for candidate in "${candidates[@]}"; do
    if [[ -f "$candidate/toolchain/prospero.mk" ]]; then
      SDK_ROOT="$candidate"
      break
    fi
  done
fi

if [[ -z "$SDK_ROOT" ]]; then
  mapfile -t discovered < <(
    if [[ -d "$HOME/.cache/ps5-native-builds" ]]; then
      find "$HOME/.cache/ps5-native-builds" -maxdepth 7 -type f -path '*/toolchain/prospero.mk' -print 2>/dev/null |
        sed 's#/toolchain/prospero.mk$##' | sort -u
    fi
  )
  if [[ ${#discovered[@]} -eq 1 ]]; then
    SDK_ROOT="${discovered[0]}"
  elif [[ ${#discovered[@]} -gt 1 ]]; then
    printf '[ERROR] Se han encontrado varios SDK. Ejecuta build.ps1 -SdkPath con la ruta exacta:\n' >&2
    printf '  %s\n' "${discovered[@]}" >&2
    exit 1
  fi
fi

[[ -n "$SDK_ROOT" ]] || fail "No encuentro PS5 Payload SDK. Usa -SdkPath o define PS5_PAYLOAD_SDK en Windows/WSL."
[[ -f "$SDK_ROOT/toolchain/prospero.mk" ]] || fail "No existe $SDK_ROOT/toolchain/prospero.mk. La ruta indicada no parece ser la raíz del PS5 Payload SDK."
export PS5_PAYLOAD_SDK="$SDK_ROOT"
ok "PS5_PAYLOAD_SDK=$PS5_PAYLOAD_SDK"

if [[ "$DO_PREPARE" == "1" ]]; then
  [[ -f scripts/prepare-deps.sh ]] || fail "No existe scripts/prepare-deps.sh."
  info "Preparando libhijacker (la primera ejecución necesita Internet y GitHub)..."
  # Invocar con bash evita depender del bit ejecutable de /mnt/c o /mnt/d.
  bash scripts/prepare-deps.sh
fi

[[ -f extern/libhijacker/libhijacker.a ]] || fail "Falta extern/libhijacker/libhijacker.a. Ejecuta sin -SkipDependencySetup."
[[ -d "$PS5_PAYLOAD_SDK/toolchain" ]] || fail "No encuentro toolchain/ dentro del SDK."

JOBS="$REQUESTED_JOBS"
if [[ ! "$JOBS" =~ ^[0-9]+$ || "$JOBS" -lt 1 ]]; then
  JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 4)"
fi

mkdir -p dist
STAMP="$(date +%Y%m%d-%H%M%S)"
LOG="dist/build-$STAMP.log"

if [[ "$DO_CLEAN" == "1" ]]; then
  info "Limpiando objetos anteriores..."
  make clean
fi

info "Compilando Permission Broker con $JOBS trabajos..."
set +e
make -j"$JOBS" 2>&1 | tee "$LOG"
BUILD_STATUS=${PIPESTATUS[0]}
set -e
if [[ "$BUILD_STATUS" -ne 0 ]]; then
  fail "La compilación ha fallado (make=$BUILD_STATUS). Consulta $LOG."
fi

ELF="permission_broker.elf"
[[ -s "$ELF" ]] || fail "make terminó sin errores, pero no se generó $ELF."

info "Validando cabecera ELF..."
python3 - "$ELF" <<'PY'
import struct, sys
path = sys.argv[1]
with open(path, 'rb') as f:
    h = f.read(64)
if len(h) < 64 or h[:4] != b'\x7fELF':
    raise SystemExit('ERROR: el archivo no tiene una cabecera ELF válida')
if h[4] != 2:
    raise SystemExit(f'ERROR: se esperaba ELF de 64 bits (EI_CLASS=2); recibido {h[4]}')
if h[5] == 1:
    endian = '<'
elif h[5] == 2:
    endian = '>'
else:
    raise SystemExit(f'ERROR: endian ELF desconocido: {h[5]}')
e_type, machine = struct.unpack(endian + 'HH', h[16:20])
if machine != 62:
    raise SystemExit(f'ERROR: arquitectura ELF inesperada (e_machine={machine}); PS5 requiere x86-64 (62)')
if e_type not in (2, 3):
    raise SystemExit(f'ERROR: tipo ELF inesperado (e_type={e_type})')
print(f'ELF válido: 64-bit, x86-64, e_type={e_type}')
PY

cp -f "$ELF" dist/permission_broker.elf
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum dist/permission_broker.elf | tee dist/permission_broker.elf.sha256
fi

ok "Compilación completada."
printf 'ELF: %s/dist/permission_broker.elf\n' "$PROJECT_DIR/dist"
printf 'Log: %s/%s\n' "$PROJECT_DIR" "$LOG"
printf 'SDK: %s\n' "$PS5_PAYLOAD_SDK"
'@

    $scriptBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($bashScript))
    $projectBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($wslProject))
    $sdkBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($wslSdk))
    $cleanValue = if ($Clean) { '1' } else { '0' }
    $prepareValue = if ($SkipDependencySetup) { '0' } else { '1' }

    # Todos los valores variables se pasan codificados en Base64 para evitar
    # problemas de escape en rutas Windows/WSL con espacios o apóstrofos.
    $linuxCommand = "PROJECT_B64='$projectBase64' SDK_B64='$sdkBase64' JOBS='$Jobs' DO_CLEAN='$cleanValue' DO_PREPARE='$prepareValue'; export PROJECT_B64 SDK_B64 JOBS DO_CLEAN DO_PREPARE; printf '%s' '$scriptBase64' | base64 -d | bash -s"

    Write-Host ''
    Write-Info 'Proyecto:'
    Write-Host "  $projectRoot"
    if ($Distro) { Write-Info "Distribución WSL: $Distro" }
    else { Write-Info 'Distribución WSL: predeterminada' }
    if ($Clean) { Write-Info 'Se limpiarán los objetos anteriores.' }
    if ($SkipDependencySetup) { Write-Info 'Se omite la descarga/preparación de libhijacker.' }
    else { Write-Info 'Se comprobará/preparará libhijacker.' }
    Write-Host ''

    if ([string]::IsNullOrWhiteSpace($Distro)) {
        & $script:WslExe --exec bash -lc $linuxCommand
    }
    else {
        & $script:WslExe --distribution $Distro --exec bash -lc $linuxCommand
    }

    $buildExit = $LASTEXITCODE
    if ($buildExit -ne 0) {
        throw "La compilación dentro de WSL ha fallado con código $buildExit. Revisa el log que haya creado el script dentro de dist\."
    }

    $expectedElf = Join-Path $projectRoot 'dist\permission_broker.elf'
    if (-not (Test-Path -LiteralPath $expectedElf -PathType Leaf)) {
        throw "WSL terminó correctamente, pero no encuentro el ELF esperado: $expectedElf"
    }

    $item = Get-Item -LiteralPath $expectedElf
    if ($item.Length -lt 4096) {
        throw "El ELF generado parece demasiado pequeño ($($item.Length) bytes). No lo consideres válido."
    }

    Write-Host ''
    Write-Ok "ELF generado: $expectedElf"
    Write-Ok ("Tamaño: {0:N0} bytes" -f $item.Length)
    Write-Host 'No se ha enviado ni instalado nada en la PS5.' -ForegroundColor Yellow
}
catch {
    Write-Fail $_.Exception.Message
    exit 1
}
