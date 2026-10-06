# LeftStickKiller

Payload para **PS5 jailbreakeada** (firmware 11.60, cargador ELF por Y2JB o
Webkit Autoloader, **sin etaHEN**) para neutralizar el **stick izquierdo** roto
de un DualSense concreto: cuando pulsas **L1 + R1 + R3** en ese mando, su stick
izquierdo se fija en el centro (0x80) y deja de irse solo hacia la izquierda.
Los otros mandos conectados siguen funcionando con normalidad.

No es persistente: vive en segundo plano y **desaparece al apagar o reiniciar**.

## Estado: desarrollo por pasos

Para que el stick quede centrado **dentro de los juegos** hay que enganchar
(*hook*) la funcion `scePadReadState` en el proceso del juego. Un *hook* mal
hecho cuelga el juego, y depende de como sea esa funcion en tu firmware
exacto. Por eso se hace en pasos, probando en la consola.

### PASO 1b - Sonda (lo que hay ahora, SOLO LECTURA, no cuelga nada)

`main.c` actual. No modifica nada:

1. Lista **todos** los procesos (para localizar el del juego, se llame como se
   llame).
2. En los que tienen `libScePad`, localiza `scePadReadState` y vuelca 64 bytes
   de esa funcion (para medir el relleno y elegir la tecnica de hook mas
   segura).
3. Escribe un informe en **`/data/LeftStickKiller.log`** y muestra avisos.

Resultado conocido del PASO 1: el acceso de kernel, la resolucion de simbolos y
la lectura de memoria de otros procesos **funcionan** en 11.60, y
`scePadReadState` es un *thunk* corto (`xor edx,edx; jmp impl_real`).

### PASO 2 - Hook real (siguiente version)

Con los datos del paso 1: inyectar en el proceso del juego un *hook* de
`scePadReadState` que detecta L1 + R1 + R3 (marca ese mando) y fuerza su stick
izquierdo al centro. Autonomo por mando: solo afecta al mando marcado.

## Conseguir el `.elf`

> El `.elf` de confianza es el **artefacto de GitHub Actions**, no el binario
> que pueda haber commiteado en el repo (ese puede quedar desfasado).

Cada push compila el payload. Entra en la pestana **Actions**, abre la
compilacion mas reciente, espera el tic verde y descarga el artefacto
`LeftStickKiller` (un zip con `LeftStickKiller.elf`).

Tambien puedes compilarlo tu mismo:

```console
wget https://github.com/ps5-payload-dev/sdk/releases/latest/download/ps5-payload-sdk.zip
sudo unzip -d /opt ps5-payload-sdk.zip
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
make
```

## Cargar y usar (PASO 1b)

1. Carga el payload con el cargador ELF en el puerto 9021:

   ```console
   nc -q0 <IP_de_tu_PS5> 9021 < LeftStickKiller.elf
   ```

2. Aparece *"Sondeando. ABRE EL JUEGO..."*. Abre el juego que quieres usar y
   espera ~1 minuto.
3. Aparece *"Sonda OK: N proceso(s)"*.
4. Recupera **`/data/LeftStickKiller.log`** (por ejemplo con un payload FTP como
   [ftpsrv](https://github.com/ps5-payload-dev/ftpsrv)) y pasa su contenido.

## Licencia

GPLv3+. Parte del ecosistema [ps5-payload-dev](https://github.com/ps5-payload-dev).
