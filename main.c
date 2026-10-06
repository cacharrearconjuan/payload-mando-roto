/* LeftStickKiller - PASO 2: hook residente de scePadReadState
 *
 * Objetivo (accesibilidad / reparacion): un DualSense concreto tiene el
 * stick izquierdo roto a nivel de placa y deriva hacia la izquierda. Este
 * payload inyecta en el proceso del juego un hook de scePadReadState que:
 *
 *   1. Deja pasar la lectura real del mando.
 *   2. Si en esa lectura ese mando tiene pulsado L1 + R1 + R3, MARCA ese
 *      mando (por su "handle").
 *   3. En todas las lecturas del mando marcado, fija el stick izquierdo en
 *      el centro (X=0x80, Y=0x80), anulando la deriva.
 *
 * Es autonomo por mando: solo afecta al que pulso la combinacion. Los demas
 * mandos siguen funcionando con normalidad.
 *
 * No es persistente: vive en segundo plano y desaparece al reiniciar.
 *
 * Tecnica (sin etaHEN, firmware 11.60):
 *   - Enumera procesos (KERN_PROC_ALL), localiza el del juego (tiene
 *     libScePad y no es del sistema).
 *   - Con ptrace (pt.c de ps5-payload-dev/elfldr) se engancha brevemente,
 *     reserva una pagina RWX via kernel_mprotect y escribe un pequeno
 *     trampolin en shellcode.
 *   - Reescribe el salto del thunk de scePadReadState
 *     (xor edx,edx ; jmp impl)  para que apunte al trampolin. El trampolin
 *     llama a la implementacion real, inspecciona los datos y, si procede,
 *     centra el stick izquierdo.
 *
 * Datos del reconocimiento (PASO 1): acceso de kernel OK, resolucion de
 * simbolos y copyout de otros procesos OK en 11.60, y scePadReadState es un
 * thunk corto identico en todos los procesos:
 *     31 d2            xor edx, edx
 *     e9 89 eb ff ff   jmp impl_real
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

#include "pt.h"

#define LOG_PATH "/data/LeftStickKiller.log"

/* Mascaras de botones de ScePad */
#define SCE_PAD_BUTTON_R3 0x00000004u
#define SCE_PAD_BUTTON_L1 0x00000400u
#define SCE_PAD_BUTTON_R1 0x00000800u
#define COMBO (SCE_PAD_BUTTON_L1 | SCE_PAD_BUTTON_R1 | SCE_PAD_BUTTON_R3) /* 0xC04 */

/* Pagina de 16 KiB (PS5) */
#define PS5_PAGE 0x4000

/* En ScePadData: buttons en +0, leftStick.x en +4, leftStick.y en +5. */
#define OFF_LEFT_X 4
#define OFF_LEFT_Y 5

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

/* ---- Construccion del trampolin (shellcode x86-64) --------------- */
/*
 * Entrada (ABI SysV, igual que scePadReadState):
 *   rdi = handle, rsi = *ScePadData, (edx = contador, lo ponemos a 0)
 *
 * Esquema:
 *   xor edx,edx                 ; contador = 0 (auto-suficiente)
 *   push rbp ; mov rbp,rsp
 *   push rdi ; push rsi         ; guardar args (impl los puede pisar)
 *   mov rax, impl_real ; call rax
 *   mov rsi,[rbp-16] ; mov rdi,[rbp-8]
 *   mov r9, rax                 ; preservar valor de retorno
 *   mov ecx,[rsi] ; and ecx,0xC04 ; cmp ecx,0xC04
 *   jne .nocombo
 *     mov r10, &marked ; mov [r10], edi   ; marcar este handle
 *   .nocombo:
 *   mov r10, &marked ; mov eax,[r10] ; cmp eax,edi
 *   jne .fin
 *     mov byte[rsi+4],0x80 ; mov byte[rsi+5],0x80  ; centrar stick izq.
 *   .fin:
 *   mov rax,r9 ; mov rsp,rbp ; pop rbp ; ret
 *
 * marked vive en la misma pagina RWX (offset 0); el codigo en +0x40.
 */

#define CODE_OFF   0x40          /* trampolin dentro de la pagina */
#define MARKED_OFF 0x00          /* int32: handle marcado, -1 = ninguno */

static size_t
build_shellcode(uint8_t *sc, intptr_t page, intptr_t impl_real) {
  static const uint8_t tpl[] = {
    0x31, 0xD2,                                     /* xor edx,edx         */
    0x55,                                           /* push rbp            */
    0x48, 0x89, 0xE5,                               /* mov rbp,rsp         */
    0x57,                                           /* push rdi            */
    0x56,                                           /* push rsi            */
    0x48, 0xB8, 0,0,0,0,0,0,0,0,                     /* mov rax, impl  @10  */
    0xFF, 0xD0,                                     /* call rax            */
    0x48, 0x8B, 0x75, 0xF0,                         /* mov rsi,[rbp-16]    */
    0x48, 0x8B, 0x7D, 0xF8,                         /* mov rdi,[rbp-8]     */
    0x49, 0x89, 0xC1,                               /* mov r9,rax          */
    0x8B, 0x0E,                                     /* mov ecx,[rsi]       */
    0x81, 0xE1, 0x04, 0x0C, 0x00, 0x00,             /* and ecx,0xC04       */
    0x81, 0xF9, 0x04, 0x0C, 0x00, 0x00,             /* cmp ecx,0xC04       */
    0x75, 0x0D,                                     /* jne .nocombo (+13)  */
    0x49, 0xBA, 0,0,0,0,0,0,0,0,                     /* mov r10,&marked @49 */
    0x41, 0x89, 0x3A,                               /* mov [r10],edi       */
    0x49, 0xBA, 0,0,0,0,0,0,0,0,                     /* mov r10,&marked @62 */
    0x41, 0x8B, 0x02,                               /* mov eax,[r10]       */
    0x39, 0xF8,                                     /* cmp eax,edi         */
    0x75, 0x08,                                     /* jne .fin (+8)       */
    0xC6, 0x46, 0x04, 0x80,                         /* mov byte[rsi+4],80h */
    0xC6, 0x46, 0x05, 0x80,                         /* mov byte[rsi+5],80h */
    0x4C, 0x89, 0xC8,                               /* mov rax,r9          */
    0x48, 0x89, 0xEC,                               /* mov rsp,rbp         */
    0x5D,                                           /* pop rbp             */
    0xC3,                                           /* ret                 */
  };
  intptr_t marked = page + MARKED_OFF;
  memcpy(sc, tpl, sizeof(tpl));
  memcpy(sc + 10, &impl_real, 8);
  memcpy(sc + 49, &marked, 8);
  memcpy(sc + 62, &marked, 8);
  return sizeof(tpl);
}

/* ---- Hook en un proceso ------------------------------------------ */

/* Devuelve:
 *    1  = hook aplicado (marcar el pid, no reintentar)
 *    0  = aun no tiene libScePad (NO marcar; reintentar en el proximo barrido)
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

  /* Enganchar el proceso */
  if (pt_attach(pid) != 0) {
    logline("  pt_attach fallo");
    return -1;
  }

  int rc = -1;
  do {
    /* Reservar pagina para datos + trampolin */
    intptr_t page = pt_mmap(pid, 0, PS5_PAGE, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == -1) {
      logline("  pt_mmap fallo");
      break;
    }

    /* marked = -1 (ningun mando marcado todavia) */
    pt_setint(pid, page + MARKED_OFF, (int)0xFFFFFFFF);

    /* Escribir el trampolin */
    uint8_t sc[160];
    size_t sclen = build_shellcode(sc, page, impl_real);
    if (pt_copyin(pid, sc, page + CODE_OFF, sclen) != 0) {
      logline("  pt_copyin(shellcode) fallo");
      pt_munmap(pid, page, PS5_PAGE);
      break;
    }

    /* Hacer la pagina ejecutable (y escribible para 'marked') via kernel */
    if (kernel_mprotect(pid, page, PS5_PAGE,
                        PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
      logline("  kernel_mprotect(RWX) fallo");
      pt_munmap(pid, page, PS5_PAGE);
      break;
    }

    intptr_t tramp = page + CODE_OFF;

    /* Redirigir el jmp del thunk al trampolin. Reutilizamos el hueco del
     * jmp rel32 existente: solo reescribimos el rel32 en thunk+3. */
    int64_t disp = (int64_t)tramp - (int64_t)(thunk + 7);
    if (disp < INT32_MIN || disp > INT32_MAX) {
      logline("  trampolin fuera de rango rel32 -> aborto (no arriesgo)");
      pt_munmap(pid, page, PS5_PAGE);
      break;
    }
    int32_t newrel = (int32_t)disp;

    /* Hacer escribible el texto de libScePad, parchear y restaurar. */
    int oldprot = kernel_get_vmem_protection(pid, thunk, 8);
    if (oldprot < 0) {
      oldprot = PROT_READ | PROT_EXEC;
    }
    if (kernel_mprotect(pid, thunk, 8,
                        PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
      logline("  kernel_mprotect(thunk RWX) fallo");
      pt_munmap(pid, page, PS5_PAGE);
      break;
    }
    if (kernel_proc_copyin(pid, &newrel, thunk + 3, 4) != 0) {
      logline("  no pude escribir el parche del thunk");
      kernel_mprotect(pid, thunk, 8, oldprot);
      pt_munmap(pid, page, PS5_PAGE);
      break;
    }
    kernel_mprotect(pid, thunk, 8, oldprot);

    char ok[192];
    snprintf(ok, sizeof(ok),
             "  pid=%d (%s): HOOK OK. thunk=0x%lx impl=0x%lx tramp=0x%lx",
             (int)pid, name, (unsigned long)thunk,
             (unsigned long)impl_real, (unsigned long)tramp);
    logline(ok);
    rc = 1;
  } while (0);

  pt_detach(pid, 0);
  return rc;
}

/* ---- Barrido de procesos ----------------------------------------- */

#define KINFO_PID_OFF    72
#define KINFO_NAME_OFF   447

static int
scan_and_hook(void) {
  int mib[3] = {1, 14, 0}; /* CTL_KERN, KERN_PROC, KERN_PROC_ALL */
  size_t buf_size = 0;
  int new_hooks = 0;

  if (sysctl(mib, 3, 0, &buf_size, 0, 0) != 0) {
    return 0;
  }
  uint8_t *buf = malloc(buf_size);
  if (!buf) {
    return 0;
  }
  if (sysctl(mib, 3, buf, &buf_size, 0, 0) != 0) {
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
  logline("=== LeftStickKiller PASO 2 (hook residente) ===");
  notify("Activo. Abre el juego; en el, pulsa L1+R1+R3 en el mando roto.");

  /* Daemon residente: vigila nuevos procesos y los engancha al vuelo. */
  for (;;) {
    int n = scan_and_hook();
    if (n > 0) {
      char msg[128];
      snprintf(msg, sizeof(msg),
               "Hook aplicado en %d proceso(s). L1+R1+R3 centra el stick.",
               n);
      notify(msg);
    }
    sleep(3);
  }

  return 0; /* no se alcanza */
}
