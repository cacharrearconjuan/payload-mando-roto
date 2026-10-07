# LeftStickKiller

Payload para **PS5 jailbreakeada** (firmware 11.60, cargador ELF de
ps5-payload-dev en el puerto **9021**, **sin etaHEN**) para neutralizar el
**stick izquierdo** roto de un DualSense concreto: cuando pulsas
**L1 + R1 + R3** en ese mando, su stick izquierdo queda fijado en el centro
(0x80) y deja de irse solo hacia la izquierda. Los otros mandos conectados
siguen funcionando con normalidad.

No es persistente: vive en segundo plano y **desaparece al apagar o reiniciar**.

## Cómo funciona (PASO 2 — hook residente)

`scePadReadState` es, en todos los procesos de 11.60, un *thunk* corto:

```asm
31 d2            xor edx, edx        ; contador = 0
e9 89 eb ff ff   jmp  impl_real      ; salta a la implementación real
```

El payload:

1. **Enumera procesos** (`KERN_PROC_ALL`) y localiza el del juego (tiene
   `libScePad.sprx` y no es del sistema). Es **residente**: revisa cada pocos
   segundos, así engancha el juego aunque lo abras después.
2. Se engancha brevemente con **ptrace** (reutiliza `pt.c`/`pt.h` de
   [ps5-payload-dev/elfldr](https://github.com/ps5-payload-dev/elfldr)),
   reserva una página y, vía `kernel_mprotect`, la vuelve **RWX**.
3. Escribe en esa página un **trampolín** (shellcode) que:
   - llama a la implementación real de `scePadReadState`,
   - si en esa lectura el mando tiene pulsado **L1+R1+R3** (`0xC04`), **marca
     ese mando** por su *handle*,
   - en toda lectura del mando marcado, fija `leftStick.x` y `leftStick.y` en
     `0x80` (centro).
4. Reescribe el *rel32* del `jmp` del thunk para que apunte al trampolín. El
   `xor edx,edx` original se conserva (y el trampolín lo repite, así que es
   autosuficiente).

Es **autónomo por mando**: solo afecta al que pulsó la combinación. Mientras el
hook esté puesto, el stick marcado queda centrado dentro del juego.

> Enganchar con ptrace **detiene el proceso del juego una fracción de
> segundo** mientras se aplica el hook; es normal y se reanuda solo.

### Historial

- **PASO 1 / 1b** (sonda de solo lectura): localizó `scePadReadState` en los
  procesos y volcó sus bytes. Confirmó que en 11.60 el acceso de kernel, la
  resolución de símbolos y el `copyout`/`copyin` entre procesos funcionan, y
  que el thunk es idéntico en todos. (Queda en el historial de git.)
- **PASO 2** (esto): el hook real descrito arriba.

## Conseguir el `.elf`

> El `.elf` de confianza es el **artefacto de GitHub Actions**, no el binario
> que pueda haber commiteado en el repo (ese puede quedar desfasado).

Cada push compila el payload. Entra en la pestaña **Actions**, abre la
compilación más reciente, espera el tic verde y descarga el artefacto
`LeftStickKiller` (un zip con `LeftStickKiller.elf`). También se publica en la
Release `latest`.

Compilarlo tú mismo:

```console
wget https://github.com/ps5-payload-dev/sdk/releases/latest/download/ps5-payload-sdk.zip
sudo unzip -d /opt ps5-payload-sdk.zip
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
make
```

## Cargar y usar

1. Carga el payload con el cargador ELF en el puerto 9021:

   ```console
   nc -q0 <IP_de_tu_PS5> 9021 < LeftStickKiller.elf
   ```

2. Aparece *"Activo. Abre el juego..."*. Abre el juego (o déjalo ya abierto).
3. Cuando el hook se aplica, aparece *"Hook aplicado en N proceso(s)"*.
4. **Dentro del juego**, en el mando roto, pulsa **L1 + R1 + R3**. A partir de
   ese momento su stick izquierdo queda centrado.

Si algo va raro, el payload deja un informe en **`/data/LeftStickKiller.log`**
(recupéralo, por ejemplo, con un payload FTP como
[ftpsrv](https://github.com/ps5-payload-dev/ftpsrv)).

### Límites / notas

- Si `scePadReadState` no es el thunk esperado en tu firmware, el payload
  **no toca nada** en ese proceso y lo anota en el log.
- El trampolín usa un `jmp rel32`; si la página reservada cayera a más de 2 GiB
  del thunk, el hook **aborta en vez de arriesgar** (queda anotado).
- La marca de "mando centrado" dura mientras el proceso del juego vive. Al
  cerrar el juego o reiniciar, desaparece todo.

## Licencia

GPLv3+. Parte del ecosistema
[ps5-payload-dev](https://github.com/ps5-payload-dev). `pt.c`/`pt.h` son de
John Törnblom (elfldr), GPLv3+.
