# LeftStickKiller

Payload para PS5 que soluciona la deriva (drift) del stick analógico izquierdo de un mando DualSense roto a nivel de hardware/placa.

## ¿Qué hace?

Este payload engancha las funciones `scePadReadState` y `scePadRead` del sistema. Deja pasar la lectura real del mando, pero si detecta que has pulsado **L1 + R1 + R3**, fija los valores del **stick izquierdo en el centro (0x80, 0x80)** para ese mando específico.

- Solo afecta al mando con el que pulsaste la combinación. El resto de mandos, y el stick derecho, siguen funcionando con normalidad.
- Está diseñado para funcionar tanto dentro de los juegos como en el menú de la consola (SceShellCore / SceShellUI).

> **Estado:** en pruebas. Pensado para firmware 11.60 con el cargador ELF de ps5-payload-dev. Si te falla, abre una incidencia y adjunta el log (ver más abajo).

## ¿Cómo funciona internamente?

A diferencia de las primeras versiones, este payload **no utiliza `ptrace`**, que causaba cuelgues en el firmware 11.60. En su lugar, usa *hooking* mediante **code caves**:

1. Busca una racha de bytes de relleno `0xCC` en `libScePad.sprx`.
2. Escribe ahí un *stub* que llama a la función real, comprueba si se ha pulsado L1+R1+R3 y, si es así, centra el stick izquierdo de ese mando.
3. Parchea el inicio de `scePadReadState` y `scePadRead` con un salto relativo (`E9`) hacia el *stub*.

Si no encuentra un hueco válido, no toca nada en ese proceso y lo anota en el log.

## Instalación

### ⚠️ IMPORTANTE: no uses el `.elf` que está suelto en este repositorio

El archivo `.elf` de la raíz del código es una **sonda de diagnóstico antigua (PASO 1)**. No es el payload funcional.

Para obtener el payload real:

1. Ve a la pestaña **Releases** de este repositorio (a la derecha).
2. Descarga `LeftStickKiller-v1.0.X.elf` de la sección **Assets** de la última release.

### Cómo cargarlo en la PS5

- **Recomendado:** desde el botón «Cargar ELF» de **Payload Manager**. Así lo verás en su lista de procesos y podrás cerrarlo cuando quieras.
- **Alternativa:** por red, con el cargador ELF escuchando en el puerto 9021:

  ```console
  nc -q0 <IP_PS5> 9021 < LeftStickKiller-v1.0.X.elf
  ```

Al cargarlo verás la notificación *«Activo v1.0.X. Pulsa L1+R1+R3 en el menu o en el juego.»*, y cada vez que se engancha a un proceso nuevo, *«Hook aplicado en N proceso(s). Listo.»*

## Uso

1. Enciende la PS5 y carga el payload.
2. Abre un juego o quédate en el menú de la consola.
3. Pulsa **L1 + R1 + R3** en el mando roto. No aparece ninguna notificación: el cambio es inmediato.
4. A partir de ese momento, el stick izquierdo de ese mando queda fijo en el centro e ignora la deriva física.

No es persistente: al cerrar el payload, apagar o reiniciar la consola, todo vuelve a la normalidad.

## Log de diagnóstico

El payload escribe un registro en `/data/LeftStickKiller.log`. Puedes recuperarlo por FTP (por ejemplo, con [ftpsrv](https://github.com/ps5-payload-dev/ftpsrv)). Líneas útiles:

- `HOOK OK`: el enganche se aplicó en ese proceso.
- `ya enganchado`: ese proceso ya estaba enganchado.
- `sin code cave`: no encontró hueco y no tocó nada.
- `cave … no es ejecutable, descartado`: el hueco encontrado no era válido y no tocó nada.
- `fallos tras 3 intentos, lo dejo`: dejó de intentarlo en ese proceso.

## Compilación (para desarrolladores)

Requiere el [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk).

```console
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
make
```

Cada push a la rama de trabajo compila el payload en GitHub Actions y publica una Release con el `.elf` versionado.

## Licencia

GPLv3+. Parte del ecosistema [ps5-payload-dev](https://github.com/ps5-payload-dev). `pt.c` y `pt.h` son de John Törnblom ([elfldr](https://github.com/ps5-payload-dev/elfldr)), GPLv3+; se conservan en el repositorio, aunque la versión actual ya no los compila.
