/* LeftStickKiller - PASO 2 (Opcion A): hook de scePadReadState SIN ptrace
 *
 * Objetivo (accesibilidad / reparacion): un DualSense concreto tiene el
 * stick izquierdo roto a nivel de placa y deriva hacia la izquierda. Este
 * payload inyecta en el proceso del juego un hook de scePadReadState que
 * deja pasar la lectura real del mando y, acto seguido, fija el stick
 * izquierdo en el centro (X=0x80, Y=0x80), anulando la deriva.
 *
 * SIMPLIFICACION: centra el stick izquierdo en TODAS las lecturas mientras
 * el payload este cargado. Como se usa un mando a la vez y el payload no es
 * persistente, no hace falta logica por-mando ni combinacion de botones:
 *   cargalo SOLO cuando uses el mando roto; desaparece al reiniciar.
 *
 * Tecnica (SIN ptrace, sin etaHEN, firmware 11.60):
 *   - Enumera procesos (KERN_PROC_PROC), localiza el del juego (tiene
 *     libScePad y no es del sistema).
 *   - Resuelve scePadReadState (kernel_dynlib_handle + kernel_dynlib_dlsym).
 *     Es un thunk corto:
 *         31 d2            xor edx, edx
 *         e9 <rel32>       jmp impl_real      ; impl_real = thunk + 7 + rel32
 *   - Busca un "code cave" (racha de 0xCC) DENTRO del rango ejecutable de
 *     libScePad, escaneando con kernel_proc_copyout.
 *   - Escribe el stub en ese hueco:
 *         kernel_mprotect(RWX) -> kernel_proc_copyin(stub) -> kernel_mprotect(RX)
 *   - Repunta el jmp del thunk (reescribe su rel32 en thunk+3) para que
 *     salte al stub. El stub llama a impl_real (direccion ABSOLUTA) y luego
 *     centra el stick izquierdo.
 *
 * No usa ptrace: ni pt_attach, ni pt_mmap. Todo via el R/W de kernel del SDK,
 * que el reconocimiento (PASO 1) ya verifico que funciona sobre el proceso
 * del juego en 11.60 (handle/dlsym, copyin/copyout, mprotect).
 *
 * Licencia: GPLv3+. Ecosistema ps5-payload-dev.
 */

#include <ps5/kernel.h>

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/sysctl.h>
#include <sys/mman.h>

#define LOG_PATH "/data/LeftStickKiller.log"

/* En ScePadData: leftStick.x en +4, leftStick.y en +5 (el stub los fija). */

/* ---- Aviso en pantalla (libSceNotification) ---------------------- */

#define SCE_NOTIFICATION_LOCAL_USER_ID_SYSTEM 0xFE
int sceNotificationSend(int userId, bool isLogged, const char *payload);

static void
notify(const char *message) {
  char payload[1024];
  snprintf(payload, sizeof(payload),
           "{\"rawData\":{\"viewTemplateType\":\"InteractiveToastTemplateB\","
           "\"channelType\":\"Downloads\",\"useCaseId\":\"IDC\","
           "\"toastOverwriteType\":\"No\",\"isImmediate\":true,\"priority\":100,"
           "\"viewData\":{\"message\":{\"body\":\"%s\"},"
           "\"subMessage\":{\"body\":\"LeftStickKiller\"}},"
           "\"platformViews\":{\"previewDisabled\":{\"viewData\":{"
           "\"icon\":{\"type\":\"Predefined\",\"parameters\":{\"icon\":\"download\"}},"
           "\"message\":{\"body\":\"%s\"}}}}},"
           "\"localNotificationId\":\"772311902\"}",
           message, message);
  sceNotificationSend(SCE_NOTIFICATION_LOCAL_USER_ID_SYSTEM, true, payload);
}

/* ---- Log a fichero ----------------------------------------------- */

static void
logline(const char *line) {
  int fd = open(LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0777);
  if (fd >= 0) {
    write(fd, line, strlen(line));
    write(fd, "\n", 1);
    close(fd);
  }
}

/* ---- Procesos ya enganchados (no repetir) ------------------------ */

static pid_t hooked[256];
static int hooked_n = 0;

static bool
already_hooked(pid_t pid) {
  for (int i = 0; i < hooked_n; i++) {
    if (hooked[i] == pid) {
      return true;
    }
  }
  return false;
}

static void
mark_hooked(pid_t pid) {
  if (hooked_n < (int)(sizeof(hooked) / sizeof(hooked[0]))) {
    hooked[hooked_n++] = pid;
  }
}

static bool
is_system_proc(const char *name) {
  return !strcmp(name, "SceShellUI")    || !strcmp(name, "SceShellCore") ||
         !strcmp(name, "SceRedisServer")|| !strcmp(name, "SceSysCore.elf") ||
         !strcmp(name, "SceSysCore")    || !strcmp(name, "SceGnmCompositor") ||
         !strcmp(name, "SceRemotePlay") || !strcmp(name, "SceJSCd");
}

/* ---- Construccion del stub (shellcode x86-64) -------------------- */
/*
 * Entrada (via el jmp del thunk; este ya ejecuto xor edx,edx):
 *   rdi = handle, rsi = *ScePadData, edx = 0
 *
 * Esquema (26 bytes). Preserva rsi en rbx (callee-saved) para no perder el
 * puntero a ScePadData si impl_real lo pisa; preserva rax (valor de retorno).
 *
 *   push rbx                 ; 53
 *   mov  rbx, rsi            ; 48 89 F3
 *   mov  rax, impl_real      ; 48 B8 <imm64>   (direccion ABSOLUTA)
 *   call rax                 ; FF D0           (llama a la lectura real)
 *   mov  byte [rbx+4], 0x80  ; C6 43 04 80     (leftStick.x = centro)
 *   mov  byte [rbx+5], 0x80  ; C6 43 05 80     (leftStick.y = centro)
 *   pop  rbx                 ; 5B
 *   ret                      ; C3
 *
 * Alineacion de pila: se entra con rsp%16==8 (tras el call del juego al thunk).
 * push rbx -> rsp%16==0, por lo que 'call rax' deja a impl_real con rsp%16==8,
 * correcto para la ABI SysV.
 */

static size_t
build_shellcode(uint8_t *sc, intptr_t impl_real) {
  static const uint8_t tpl[] = {
    0x53,                             /* push rbx                */
    0x48, 0x89, 0xF3,                 /* mov  rbx, rsi           */
    0x48, 0xB8, 0,0,0,0,0,0,0,0,       /* mov  rax, impl_real @6  */
    0xFF, 0xD0,                       /* call rax                */
    0xC6, 0x43, 0x04, 0x80,           /* mov byte [rbx+4], 0x80  */
    0xC6, 0x43, 0x05, 0x80,           /* mov byte [rbx+5], 0x80  */
    0x5B,                             /* pop  rbx                */
    0xC3,                             /* ret                     */
  };
  memcpy(sc, tpl, sizeof(tpl));
  memcpy(sc + 6, &impl_real, 8);
  return sizeof(tpl);
}

/* ---- Busqueda de code cave (racha de 0xCC ejecutable) ------------ */
/*
 * Escanea hacia delante con kernel_proc_copyout buscando 'need' bytes 0xCC
 * consecutivos. Empieza en 'start' (alineado a pagina) y para cuando copyout
 * falla (fin del mapeo) o al llegar al tope. Devuelve la direccion del hueco
 * o 0 si no hay ninguno suficientemente grande.
 */
static intptr_t
find_code_cave(pid_t pid, intptr_t start, size_t need) {
  uint8_t chunk[0x1000];
  intptr_t run_start = 0;
  size_t run_len = 0;
  intptr_t addr = start & ~((intptr_t)0xFFF);
  intptr_t limit = addr + 0x600000; /* tope de escaneo: 6 MiB */

  for (; addr < limit; addr += (intptr_t)sizeof(chunk)) {
    if (kernel_proc_copyout(pid, addr, chunk, sizeof(chunk)) != 0) {
      break; /* fin del mapeo ejecutable del modulo */
    }
    for (size_t i = 0; i < sizeof(chunk); i++) {
      if (chunk[i] == 0xCC) {
        if (run_len == 0) {
          run_start = addr + (intptr_t)i;
        }
        run_len++;
        if (run_len >= need) {
          return run_start;
        }
      } else {
        run_len = 0;
      }
    }
  }
  return 0;
}

/* ---- Hook en un proceso ------------------------------------------ */

/* Devuelve:
 *    1  = hook aplicado (marcar el pid, no reintentar)
 *    0  = aun no tiene libScePad/simbolo (NO marcar; reintentar luego)
 *   -1  = tiene libScePad pero algo salio mal (marcar; no reintentar)
 */
static int
hook_pad(pid_t pid, const char *name) {
  uint32_t handle = 0;
  if (kernel_dynlib_handle(pid, "libScePad.sprx", &handle) != 0 || !handle) {
    return 0; /* todavia no ha cargado libScePad; probar de nuevo luego */
  }
  intptr_t thunk = kernel_dynlib_dlsym(pid, handle, "scePadReadState");
  if (!thunk) {
    return 0; /* libScePad presente pero el simbolo aun no; reintentar */
  }

  /* Verificar que es el thunk esperado: 31 d2 e9 <rel32> */
  uint8_t head[7];
  if (kernel_proc_copyout(pid, thunk, head, sizeof(head)) != 0) {
    logline("  (no pude leer el thunk)");
    return -1;
  }
  if (head[0] != 0x31 || head[1] != 0xD2 || head[2] != 0xE9) {
    char e[128];
    snprintf(e, sizeof(e),
             "  pid=%d: thunk inesperado (%02x %02x %02x) -> NO toco nada",
             (int)pid, head[0], head[1], head[2]);
    logline(e);
    return -1;
  }
  int32_t rel;
  memcpy(&rel, &head[3], 4);
  intptr_t impl_real = thunk + 7 + rel; /* destino del jmp original */

  /* Construir el stub (su tamano define el cave que necesitamos). */
  uint8_t sc[64];
  size_t sclen = build_shellcode(sc, impl_real);

  /* Base del modulo para escanear su .text; si no hay, desde impl_real. */
  intptr_t mapbase = kernel_dynlib_mapbase_addr(pid, handle);
  intptr_t scan_from = (mapbase > 0) ? mapbase : impl_real;

  char m[192];
  snprintf(m, sizeof(m),
           "  pid=%d (%s): thunk=0x%lx impl=0x%lx mapbase=0x%lx need=%u",
           (int)pid, name, (unsigned long)thunk, (unsigned long)impl_real,
           (unsigned long)mapbase, (unsigned)sclen);
  logline(m);

  intptr_t cave = find_code_cave(pid, scan_from, sclen);
  if (!cave) {
    logline("  NO hay code cave suficiente en libScePad -> aborto (no arriesgo)");
    return -1;
  }
  char c[96];
  snprintf(c, sizeof(c), "  code cave encontrado en 0x%lx (%u bytes)",
           (unsigned long)cave, (unsigned)sclen);
  logline(c);

  /* Escribir el stub en el cave: RWX -> copyin -> RX. */
  if (kernel_mprotect(pid, cave, sclen,
                      PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
    logline("  kernel_mprotect(cave RWX) fallo");
    return -1;
  }
  if (kernel_proc_copyin(pid, sc, cave, sclen) != 0) {
    logline("  kernel_proc_copyin(stub) fallo");
    kernel_mprotect(pid, cave, sclen, PROT_READ | PROT_EXEC);
    return -1;
  }
  kernel_mprotect(pid, cave, sclen, PROT_READ | PROT_EXEC);
  logline("  stub escrito en el cave");

  /* Repuntar el jmp del thunk hacia el cave (rel32 en thunk+3). */
  int64_t disp = (int64_t)cave - (int64_t)(thunk + 7);
  if (disp < INT32_MIN || disp > INT32_MAX) {
    logline("  cave fuera de rango rel32 -> aborto (no arriesgo)");
    return -1;
  }
  int32_t newrel = (int32_t)disp;

  int oldprot = kernel_get_vmem_protection(pid, thunk, 8);
  if (oldprot < 0) {
    oldprot = PROT_READ | PROT_EXEC;
  }
  if (kernel_mprotect(pid, thunk, 8,
                      PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
    logline("  kernel_mprotect(thunk RWX) fallo");
    return -1;
  }
  if (kernel_proc_copyin(pid, &newrel, thunk + 3, 4) != 0) {
    logline("  no pude escribir el parche del thunk");
    kernel_mprotect(pid, thunk, 8, oldprot);
    return -1;
  }
  kernel_mprotect(pid, thunk, 8, oldprot);

  char ok[192];
  snprintf(ok, sizeof(ok),
           "  pid=%d (%s): HOOK OK. thunk=0x%lx impl=0x%lx cave=0x%lx",
           (int)pid, name, (unsigned long)thunk,
           (unsigned long)impl_real, (unsigned long)cave);
  logline(ok);
  return 1;
}

/* ---- Barrido de procesos ----------------------------------------- */

#define KINFO_PID_OFF    72
#define KINFO_NAME_OFF   447

static int
scan_and_hook(void) {
  int mib[4] = {1, 14, 8, 0}; /* CTL_KERN, KERN_PROC, KERN_PROC_PROC */
  size_t buf_size = 0;
  int new_hooks = 0;

  if (sysctl(mib, 4, 0, &buf_size, 0, 0) != 0) {
    return 0;
  }
  uint8_t *buf = malloc(buf_size);
  if (!buf) {
    return 0;
  }
  if (sysctl(mib, 4, buf, &buf_size, 0, 0) != 0) {
    free(buf);
    return 0;
  }

  for (uint8_t *ptr = buf; ptr < buf + buf_size;) {
    int ki_structsize = *(int *)ptr;
    if (ki_structsize <= 0) {
      break;
    }
    pid_t pid = *(pid_t *)&ptr[KINFO_PID_OFF];
    char *name = (char *)&ptr[KINFO_NAME_OFF];
    ptr += ki_structsize;

    if (pid <= 0 || already_hooked(pid) || is_system_proc(name)) {
      continue;
    }
    int r = hook_pad(pid, name);
    if (r == 1) {
      mark_hooked(pid);  /* enganchado: no repetir */
      new_hooks++;
    } else if (r < 0) {
      mark_hooked(pid);  /* libScePad presente pero fallo/raro: no reintentar */
    }
    /* r == 0: aun sin libScePad; se deja sin marcar para reintentar luego */
  }

  free(buf);
  return new_hooks;
}

int
main(void) {
  logline("=== LeftStickKiller PASO 2 (Opcion A: sin ptrace, code cave) ===");
  notify("Activo. Abre el juego con el mando roto; el stick izq. ira al centro.");

  /* Daemon residente: vigila nuevos procesos y los engancha al vuelo. */
  for (;;) {
    int n = scan_and_hook();
    if (n > 0) {
      char msg[128];
      snprintf(msg, sizeof(msg),
               "Hook aplicado en %d proceso(s). Stick izquierdo centrado.", n);
      notify(msg);
    }
    sleep(3);
  }

  return 0; /* no se alcanza */
}
