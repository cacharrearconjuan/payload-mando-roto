# LeftStickKiller

Payload para PS5 que soluciona la deriva (drift) del stick analógico izquierdo de un mando DualSense roto a nivel de hardware/placa.

## ¿Qué hace?

Este payload engancha las funciones `scePadReadState` y `scePadRead` del sistema. Deja pasar la lectura real del mando, pero si detecta que has pulsado **L1 + R1 + R3**, fija los valores del **stick izquierdo en el centro (0x80, 0x80)** para ese mando específico. 

- Solo afecta al mando con el que pulsaste la combinación. El resto de mandos, y el stick derecho, funcionan con normalidad.
- **Funciona tanto dentro de los juegos como en el menú de la consola (SceShellCore / SceShellUI)**.

## ¿Cómo funciona internamente?

A diferencia de las primeras versiones, este payload **NO utiliza `ptrace`** (lo cual causaba cuelgues en el firmware 11.60). En su lugar, utiliza una técnica de *hooking* mediante **code caves**:
1. Busca una racha de bytes `0xCC` (espacio muerto seguro) dentro de `libScePad.sprx`.
2. Escribe un *stub* (código ensamblador) que llama a la función real, comprueba si se ha pulsado L1+R1+R3, y si es así, modifica los bytes de salida.
3. Parchea el inicio de `scePadReadState` y `scePadRead` con un salto relativo (`E9`) hacia nuestro *stub*.

Esto es seguro, no congela el sistema y se replica correctamente en todos los procesos que compartan la librería.

## Instalación

### ⚠️ IMPORTANTE: No uses el `.elf` que está suelto en este repositorio.
El archivo `.elf` que ves en la raíz del código es una **sonda de diagnóstico antigua (PASO 1)**. No es el payload funcional.

Para obtener el payload real:
1. Ve a la pestaña **Releases** de este repositorio (a la derecha).
2. Descarga el archivo `LeftStickKiller-v1.0.X.elf` de la sección **Assets** de la última release.

### Cómo cargarlo en la PS5
1. Envía el ELF a tu PS5.
2. **Recomendado:** Cárgalo desde el botón "Cargar ELF" de la interfaz de **Payload Manager**. Esto te permitirá verlo en la lista de procesos y cerrarlo (matarlo) cuando quieras, igual que el resto de payloads.
3. Alternativa: Por red con `nc -q0 <IP_PS5> 9021 < LeftStickKiller-v1.0.X.elf` (nota: si lo haces así, no aparecerá como proceso independiente en Payload Manager).

## Uso

1. Enciende la PS5 y carga el payload.
2. Abre un juego o quédate en el menú de la consola.
3. Pulsa **L1 + R1 + R3** en el mando roto. Verás una notificación de confirmación.
4. A partir de ese momento, el stick izquierdo de ese mando se quedará fijo en el centro (ignorará la deriva física).

## Log de diagnóstico

El payload escribe un registro en `/data/LeftStickKiller.log`. Puedes acceder a él por FTP para ver qué está pasando. Si algo falla, busca líneas como `"HOOK OK"` o `"sin code cave"`.

## Compilación (para desarrolladores)

Requiere el [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk).

```bash
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
make
