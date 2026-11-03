# PS5 Permission Broker — FW 5.50 baseline

Payload residente para centralizar el protocolo de elevación de aplicaciones que ya utilizan los PRX compatibles con etaHEN/OnionHEN.

## Qué hace

- Un único proceso consume los marcadores `etahen_jailbreak` y `onionhen_jailbreak` en `/mnt/sandbox/<TITLE_ID>_<slot>/download0/`.
- Comprueba que el PID exista y que el Title ID real del proceso coincida con el nombre del sandbox.
- Solo concede la elevación a Title IDs presentes en `/data/permission-broker/allowlist.txt` o en el `/data/whitelist.txt` heredado de OnionHEN/PS5SX2.
- Usa `libhijacker` (`Hijacker::jailbreak(true)`) para la elevación compatible.
- Comprueba el `authid` resultante (`0x4801000000000013`). Si ya está aplicado, responde internamente `ALREADY_GRANTED`, no vuelve a escribir credenciales y elimina el marcador como acuse compatible con los PRX antiguos.
- Utiliza `fcntl(F_SETLK)` para impedir que arranquen dos instancias del propio Broker (equivalente a `flock`, que no exportan los stubs del SDK).
- **Se identifica solo al arrancar**: el loader de kstuff/etaHEN arranca los payloads con el nombre genérico `payload.elf`; el Broker reescribe el nombre de proceso gestionado por el kernel a `perm-broker` (vía `KProc::setName` de libhijacker) y escribe su PID en `/data/permission-broker/broker.pid`, así aparece reconocible en las herramientas de procesos (PS5-Xplorer, depuración de etaHEN, etc.).
- Verifica el TID del proceso con el `titleId()` nativo del kernel (fork de etaHEN), con respaldo al análisis de la ruta del SELF si el label viene vacío.
- **Gana la carrera de marcadores por diseño**: reclama cada marcador con un `rename()` atómico a un nombre privado `.pb_claim_*` en el mismo directorio; los consumidores competidores (Lapy, etaHEN) solo vigilan los nombres canónicos y quedan ciegos desde el instante del claim.
- **Despertar reactivo**: vigila cada `download0` con `kqueue(EVFILT_VNODE)`; si el kernel no entrega eventos, degrada automáticamente a sondeo puro de 2 ms (nunca es peor que sondear).
- **Auditoría de derrotas**: cada ~5 s recorre `allproc` y registra en `broker.log` cualquier proceso elevado con `authid` de app-jailbreak cuyo TID no esté en la allowlist (huella de un consumidor competidor que ganó alguna carrera).
- Reintenta hasta 10 segundos si el proceso aún no está listo (el claim retenido es invisible para competidores durante los reintentos); registra el resultado en `/data/permission-broker/<slot>.status` y en `broker.log`. Los claims huérfanos de un crash se recuperan en el siguiente arranque.
- **Huella acotada / auto-limpieza**: el bucle de 2 ms no asigna memoria (solo syscalls); los objetos transitorios de libhijacker (`KProc` ~3,2 KB, `KUcred`, `Hijacker`) se liberan al salir de scope vía `UniquePtr`; el `ProcessMemoryAllocator` no reserva memoria nueva en el proceso elevado (talla huecos de secciones ya existentes). Los watches kqueue están limitados a 32. En `/data`, todo se sobreescribe o se borra: claims procesados/STALE, `<slot>.status`, `broker.pid`; y `broker.log` rota a `broker.log.1` al superar 256 KB. Al morir el proceso, el kernel libera toda la RAM/fds/locks automáticamente (el lock de instancia se libera solo al salir).

## Límite importante

Este payload **no intercepta globalmente** `kernel_set_ucred_*`, no parchea funciones de kernel y no puede impedir que un ELF arbitrario modifique credenciales directamente. No existe una respuesta `NULL` universal para procesos independientes. El mecanismo correcto es que los payloads compatibles usen el marcador compartido o se adapten para llamar a una API del Broker.

Por eso, para tener una sola autoridad real hay que desactivar los consumidores duplicados conocidos. En tu KLOG del 02-11-2026 se ven:

1. Un watcher integrado en el helper de PS5SX2 que se identifica como `onionHEN jb` (PID 86).
2. `Lapy JB Daemon v1.2`, que también vigila `etahen_jailbreak`.
3. Un segundo arranque del helper que sale porque otra instancia ya posee su lock.

El Broker sustituye esos dos watchers; no debe cargarse junto a ambos.

## Preparación de dependencias

Requisitos:

- PS5 Payload SDK de John Törnblom (`PS5_PAYLOAD_SDK`).
- Kstuff activo y tablas de símbolos del SDK compatibles con el FW en ejecución.
- `git`, `make` y toolchain Prospero.

En WSL/Linux:

```bash
export PS5_PAYLOAD_SDK="$HOME/.cache/ps5-native-builds/TALLERDECOLADAPS-OpenGL-UI/.deps/native/ps5-payload-sdk"
./scripts/prepare-deps.sh
make clean
make -j"$(nproc)"
```

El script obtiene `libhijacker` desde el repositorio de Lapy JB Daemon v1.2. `offsets_v940.cpp` usa los símbolos de kernel resueltos en runtime por el SDK; no son offsets fijos de FW 9.40.

Salida esperada: `permission_broker.elf`.

## Compatibilidad con lanzadores (MihawkOS)

MihawkOS hace un «payload check» antes de arrancar y solo admite su conjunto oficial de payloads: cualquier payload residente identificado por nombre (como `perm-broker`) bloquea el arranque. Opciones:

- **Mantener △ 5 segundos** en el check: continúa con el broker residente (3 MiB; el broker seguirá siendo la autoridad de los marcadores y dejará sin trabajo al demonio Lapy interno de MihawkOS).
- **Crear `/data/permission-broker/no-rename`** (v0.4.1+): el broker no se renombra, aparece como un «payload» sin nombre y el check de MihawkOS no lo bloquea.
- **Arrancar sin broker** para sesiones de MihawkOS: su propio demonio Lapy consume los marcadores (sin allowlist). Quitar `permission_broker.elf` del autoload y reiniciar.

Nota: v0.4.0+ dejó kqueue y la auditoría desactivados por defecto tras un crash de ShellCore en FW 5.50 (causa raíz: ráfagas de eventos VNODE aceleraban el bucle y adelantaban la auditoría a offsets de kernel no verificados); con el build actual la consola es estable en hardware.

## Compilación real (WSL2, 03-11-2026)

Este proyecto **se ha compilado con éxito** en una distro WSL2 Ubuntu 24.04 usando el PS5 Payload SDK existente en `E:\TALLERDECOLADAPS-OpenGL-UI\.deps\native\ps5-payload-sdk` (el SDK no incluye el LLVM real: los wrappers resuelven el `clang-18`/`lld-18` del sistema, instalado vía apt).

Ruta rápida: `scripts/wsl-build.sh` monta `E:` en `/mnt/e`, sincroniza fuentes, compila, valida la cabecera ELF y copia el resultado a `dist\`:

```
wsl -d PS5-Ubuntu-24.04 -- bash /mnt/e/PS5-Permission-Broker_FW550/scripts/wsl-build.sh
```

Dependencia `libhijacker`: se usó el **fork de etaHEN** (`github.com/etaHEN/etaHEN`), que publica `libhijacker.a` precompilado y las cabeceras en `Source Code/include` — es el mismo linaje que usa Lapy JB Daemon (incluye `notify.hpp`/`Platform.hpp` y enlaza con `-lSceNotification`). El `.a` y las cabeceras quedaron vendored en `extern/libhijacker/`.

Adaptaciones aplicadas al compilar contra ese fork:

- `main.cpp`: `flock()` no existe en los stubs del SDK → bloqueo de instancia única con `fcntl(F_SETLK)` (equivalente, se libera al morir el proceso).
- `main.cpp`: verificación de TID vía `KProc::getSelfInfo()->path` (ruta del SELF bajo `/mnt/sandbox/<TID>_<slot>/`); el fork no expone `titleId()`.
- `offsets_v940.cpp`: reescrito como **resolución multi-firmware** con dos vías: (1) símbolos `KERNEL_ADDRESS_*` que kstuff resuelve en runtime (declarados débiles), y (2) tabla pública de respaldo por FW (etaHEN consolidada 1.00→10.60, cruzada con kstuff 3.00→4.51 y libhijacker vanilla para `rootvnode`), seleccionada con `sysctl kern.sdk_version`. Los offsets críticos para el Broker son `allproc` y `root_vnode`; `security/qa/utoken` se exponen por compatibilidad de API.

Resultado: `dist/permission_broker.elf` (PIE x86-64, ~550 KB) con su `.sha256`. No se ha probado en hardware.

## Instalación y migración

1. Compila el ELF y copia el proyecto de runtime a `/data/homebrew/permission-broker/`.
2. Copia `config/allowlist.txt` a `/data/permission-broker/allowlist.txt`.
3. Añade `permission_broker.elf` a tu autoload **después de Kstuff**.
4. Elimina de `/data/autoload.txt` la entrada de `lapy_jb_daemon.elf` (o desactiva su autoload). No basta con añadir el Broker al lado: ambos competirían por el mismo marcador.
5. Aplica `integration/disable-ps5sx2-embedded-jb-watcher.patch` al código fuente de PS5SX2 y recompila su helper, manteniendo el hilo de discos. No cargues la versión antigua junto al Broker.
6. Si tienes etaHEN u OnionHEN cargado como consumidor independiente de esos marcadores, desactiva esa función antes de usar el Broker.
7. Reinicia la consola para descargar los watchers antiguos y carga la cadena nueva.

No se mata ningún proceso automáticamente ni se parchean credenciales de payloads ajenos en caliente.

## Allowlist

El archivo inicial incluye `PPSA99203` y `PPSA99303`, que aparecen en el código/helper de PS5SX2 revisado. El Broker también lee `/data/whitelist.txt` para conservar las autorizaciones que ya tenías. Añade otros Title IDs solo cuando sepas qué homebrew los utiliza:

```text
PPSA99203
PPSA99303
PPSA12345
```

No uses comodines. Un título no incluido obtiene `DENIED_NOT_ALLOWLISTED` y su marcador se consume para no dejar la aplicación bloqueada esperando.

## Resultados

- `GRANTED`: elevación aplicada y verificada.
- `ALREADY_GRANTED`: el `authid` ya era el esperado; no se repite la escritura.
- `DENIED_NOT_ALLOWLISTED`: título fuera de la lista.
- `DENIED_PID_TID_MISMATCH`: el PID del marcador no pertenece al TID del sandbox.
- `STALE_OR_NOT_READY`: el proceso no apareció tras 10 segundos.
- `FAILED_VERIFY`: no se pudo verificar el `authid` tras la operación.

En el protocolo antiguo el acuse es la eliminación del archivo marcador. Los estados completos quedan en `/data/permission-broker/<slot>.status`.

## Qué no centraliza todavía

El helper PS5SX2 también configura su **propio** `authid` de servicio (`0x4800000000010003`) y capacidades para acceder a la unidad óptica. Eso es distinto de la elevación genérica de aplicaciones y no lo modifica este primer Broker. Tampoco arbitra montajes `/data`, LVD, MD, fakelib, ventilación ni hooks de Kstuff. Para centralizar esas operaciones haría falta una API adicional y adaptar cada payload propietario; no es seguro interceptarlas con un `NULL` ficticio.

## Diagnóstico esperado

Después de migrar, el KLOG debería mostrar una sola línea de arranque `[perm-broker] exclusive authority acquired`, peticiones `GRANTED` / `ALREADY_GRANTED`, y **no** debería volver a mostrar el arranque de `[lapy_jb] Lapy JB Daemon` ni `onionHEN-style jb watcher started` desde el helper de PS5SX2.
