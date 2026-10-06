# LeftStickKiller

Payload para **PS5 jailbreakeada** que detecta un mando concreto mediante la
combinación **L1 + R1 + R3** y neutraliza su **stick izquierdo** (lo fija en el
centro). Pensado para un DualSense cuyo joystick izquierdo está roto a nivel de
placa y genera movimiento fantasma (*drift*).

- Al cargarlo muestra un aviso en pantalla.
- Al pulsar **L1 + R1 + R3** en el mando roto, muestra *"stick izquierdo
  DESACTIVADO"* y lo neutraliza. Vuelve a pulsar la combinación para reactivarlo.
- Vive en segundo plano y **desaparece al apagar o reiniciar** la consola. No
  toca el almacenamiento, no es persistente.

## ⚠️ Lee esto antes: qué hace y qué no

Un payload lee el estado del mando con `libScePad`. Este payload:

- ✅ **Sí** detecta la combinación L1 + R1 + R3 en cualquier mando conectado.
- ✅ **Sí** muestra el aviso en pantalla en ese momento.
- ✅ **Sí** vive en segundo plano y muere al reiniciar.
- ✅ **Sí** neutraliza el stick izquierdo **en su propia lectura** del mando.

Lo que un payload suelto **no** hace por sí solo: cada juego abre su propio
acceso al mando y lo lee directamente. Que este payload ponga el stick al
centro en *su* copia **no cambia** lo que ve el juego. Para que el juego ignore
el stick hay que, además, **enganchar (hook)** la función de lectura del mando
*dentro del proceso del juego*. Eso depende del firmware y hay que probarlo en
la consola; no se puede escribir a ciegas con garantías sin arriesgar cuelgues
en los juegos.

Por eso este repositorio entrega la base **sólida y verificable** (detección +
aviso + residente), y documenta el camino para el efecto dentro de los juegos.
Si quieres que desarrolle el *hook*, dime tu **firmware** y si usas **etaHEN**
o solo el cargador de ELF, y lo iteramos probándolo en tu consola.

### Alternativas ya probadas por la comunidad

- **etaHEN** y su sistema de plugins: el sitio natural para un *hook* de mando.
- **Ghostcontrol / Ghostpad** (StonedModder): crean un DualSense virtual.
- **PuckbridgePS5**: remapeo con zonas muertas, orientado al Steam Controller.

## Requisitos

- Una PS5 jailbreakeada con un **cargador de ELF escuchando en el puerto 9021**
  (por ejemplo [ps5-payload-elfldr](https://github.com/ps5-payload-dev/elfldr)).
- Para compilar: el [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk).

## Conseguir el `.elf`

Tienes tres opciones:

1. **Descargarlo de las *Releases* / artefactos de GitHub Actions.** Cada push
   a este repositorio compila `LeftStickKiller.elf` automáticamente (ver abajo).
2. **El `.elf` incluido** en la raíz del repositorio (`LeftStickKiller.elf`).
3. **Compilarlo tú mismo:**

   ```console
   wget https://github.com/ps5-payload-dev/sdk/releases/latest/download/ps5-payload-sdk.zip
   sudo unzip -d /opt ps5-payload-sdk.zip
   export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
   make
   ```

## Cargarlo en la PS5

Con el cargador de ELF escuchando en el puerto 9021:

```console
# Por red, desde tu PC (sustituye la IP por la de tu PS5):
nc -q0 192.168.1.50 9021 < LeftStickKiller.elf
```

También puedes usar un gestor de payloads (etaHEN Toolbox, PS5 Payload Loader,
etc.) y seleccionar `LeftStickKiller.elf`.

## Uso

1. Carga el payload. Aparece el aviso *"LeftStickKiller activo"*.
2. En el mando con el stick roto, pulsa **L1 + R1 + R3** a la vez.
3. Aparece *"Mando identificado: stick izquierdo DESACTIVADO"*.
4. Para reactivarlo, vuelve a pulsar la misma combinación.
5. Al apagar o reiniciar la consola, el payload desaparece.

## Licencia

GPLv3+. Parte del ecosistema [ps5-payload-dev](https://github.com/ps5-payload-dev).
