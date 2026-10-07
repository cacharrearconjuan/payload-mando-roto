/* LeftStickKiller - PASO 2 (Opcion A, v2): hook de lectura del mando SIN ptrace
 *
 * Objetivo (accesibilidad): un DualSense tiene el stick izquierdo roto a nivel
 * de placa y deriva a la izquierda. Este payload engancha las funciones de
 * lectura del mando en el proceso del juego, deja pasar la lectura real y luego
 * fija el stick izquierdo en el centro (X=0x80, Y=0x80) en CADA lectura mientras
 * el payload este cargado. Sin combo: cargalo solo cuando uses el mando roto.
 *
 * Por que v2: el hook de scePadReadState se aplicaba bien pero no tenia efecto
 * y el juego no se colgaba. Eso indica que el juego no lee por scePadReadState
 * sino por scePadRead (lectura con buffer que devuelve un ARRAY de ScePadData).
 * Ambas saltan al mismo lector interno, asi que hay que hookear las dos.
 *
 * Tecnica (SIN ptrace, firmware 11.60): resuelve cada funcion con
 * kernel_dynlib_dlsym, detecta la forma de su thunk, escribe un stub en un
 * code cave (racha de 0xCC) de libScePad via kernel_mprotect + kernel_proc_copyin,
 * y repunta el thunk hacia el stub (reescribiendo su rel32, o el puntero GOT si
 * es un salto indirecto). El stub llama a la implementacion real (direccion
 * ABSOLUTA) y centra el stick.
 *
 * Datos verificados del layout de ScePadData: leftStick.x=+4, leftStick.y=+5,
 * tamano de registro = 120 bytes (0x78). scePadRead(handle, data[], count)
 * devuelve en eax el numero de registros leidos.
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
#define PAD_STRIDE 0x78 /* sizeof(ScePadData) = 120 */

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

/* ---- Stubs (shellcode x86-64) ------------------------------------ */
/*
 * build_single (26 B) para scePadReadState(handle, data):
 *   push rbx ; mov rbx,rsi ; mov rax,impl ; call rax ;
 *   mov byte[rbx+4],0x80 ; mov byte[rbx+5],0x80 ; pop rbx ; ret
 * Se entra con rsp%16==8; push rbx -> %16==0, por lo que call deja impl con
 * %16==8 (ABI SysV). rsi = *ScePadData. rax (retorno) se conserva.
 */
static size_t
build_single(uint8_t *sc, intptr_t impl_real) {
  static const uint8_t tpl[] = {
    0x53,                         /* push rbx                */
    0x48, 0x89, 0xF3,             /* mov  rbx, rsi           */
    0x48, 0xB8, 0,0,0,0,0,0,0,0,   /* mov  rax, impl   @6     */
    0xFF, 0xD0,                   /* call rax                */
    0xC6, 0x43, 0x04, 0x80,       /* mov byte [rbx+4], 0x80  */
    0xC6, 0x43, 0x05, 0x80,       /* mov byte [rbx+5], 0x80  */
    0x5B,                         /* pop  rbx                */
    0xC3,                         /* ret                     */
  };
  memcpy(sc, tpl, sizeof(tpl));
  memcpy(sc + 6, &impl_real, 8);
  return sizeof(tpl);
}

/*
 * build_array (50 B) para scePadRead(handle, data[], count):
 *   push rbx ; mov rbx,rsi ; mov rax,impl ; call rax ; push rax ;
 *   cmp eax,64 ; jle ok ; mov eax,64 ;
 * ok/loop: test eax,eax ; jle done ;
 *   mov byte[rbx+4],0x80 ; mov byte[rbx+5],0x80 ; add rbx,0x78 ; dec eax ; jmp loop
 * done: pop rax ; pop rbx ; ret
 * eax tras call = numero de registros; se recorren todos (tope 64), stride 0x78.
 * El valor de retorno real se guarda en pila y se restaura al final.
 */
static size_t
build_array(uint8_t *sc, intptr_t impl_real) {
  static const uint8_t tpl[] = {
    0x53,                         /* push rbx                */
    0x48, 0x89, 0xF3,             /* mov  rbx, rsi           */
    0x48, 0xB8, 0,0,0,0,0,0,0,0,   /* mov  rax, impl   @6     */
    0xFF, 0xD0,                   /* call rax                */
    0x50,                         /* push rax (retorno)      */
    0x83, 0xF8, 0x40,             /* cmp eax, 64             */
    0x7E, 0x05,                   /* jle ok                  */
    0xB8, 0x40, 0x00, 0x00, 0x00, /* mov eax, 64             */
    0x85, 0xC0,                   /* ok/loop: test eax,eax   */
    0x7E, 0x10,                   /* jle done                */
    0xC6, 0x43, 0x04, 0x80,       /* mov byte [rbx+4], 0x80  */
    0xC6, 0x43, 0x05, 0x80,       /* mov byte [rbx+5], 0x80  */
    0x48, 0x83, 0xC3, 0x78,       /* add rbx, 0x78           */
    0xFF, 0xC8,                   /* dec eax                 */
    0xEB, 0xEC,                   /* jmp loop                */
    0x58,                         /* done: pop rax           */
    0x5B,                         /* pop rbx                 */
    0xC3,                         /* ret                     */
  };
  memcpy(sc, tpl, sizeof(tpl));
  memcpy(sc + 6, &impl_real, 8);
  return sizeof(tpl);
}

/* ---- Busqueda de code cave (racha de 0xCC) ----------------------- */
static intptr_t
find_code_cave(pid_t pid, intptr_t start, size_t need) {
  uint8_t chunk[0x1000];
  intptr_t run_start = 0;
  size_t run_len = 0;
  intptr_t addr = start & ~((intptr_t)0xFFF);
  intptr_t limit = addr + 0x600000; /* tope de escaneo: 6 MiB */

  for (; addr < limit; addr += (intptr_t)sizeof(chunk)) {
    if (kernel_proc_copyout(pid, addr, chunk, sizeof(chunk)) != 0) {
      break; /* fin del mapeo */
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

/* ---- Diagnostico: volcar direccion y primeros 16 bytes ----------- */
static void
probe_sym(pid_t pid, uint32_t handle, const char *sym) {
  intptr_t a = kernel_dynlib_dlsym(pid, handle, sym);
  if (!a) {
    char l[96];
    snprintf(l, sizeof(l), "  %s: no exportado", sym);
    logline(l);
    return;
  }
  uint8_t b[16];
  if (kernel_proc_copyout(pid, a, b, sizeof(b)) != 0) {
    char l[96];
    snprintf(l, sizeof(l), "  %s @0x%lx: no pude leer", sym, (unsigned long)a);
    logline(l);
    return;
  }
  char hx[16 * 3 + 1];
  for (int i = 0; i < 16; i++) {
    snprintf(hx + i * 3, 4, "%02x ", b[i]);
  }
  char l[160];
  snprintf(l, sizeof(l), "  %s @0x%lx: %s", sym, (unsigned long)a, hx);
  logline(l);
}

/* ---- Hook de una funcion ----------------------------------------- */
/* Devuelve 1 si la hookea, 0 si no esta exportada, -1 si esta pero fallo. */
static int
hook_func(pid_t pid, uint32_t handle, intptr_t mapbase,
          const char *sym, bool is_array) {
  intptr_t addr = kernel_dynlib_dlsym(pid, handle, sym);
  if (!addr) {
    char l[96];
    snprintf(l, sizeof(l), "  %s: no exportado", sym);
    logline(l);
    return 0;
  }

  uint8_t h[16];
  if (kernel_proc_copyout(pid, addr, h, sizeof(h)) != 0) {
    char l[96];
    snprintf(l, sizeof(l), "  %s @0x%lx: no pude leer", sym, (unsigned long)addr);
    logline(l);
    return -1;
  }
  char hx[16 * 3 + 1];
  for (int i = 0; i < 16; i++) {
    snprintf(hx + i * 3, 4, "%02x ", h[i]);
  }
  {
    char l[160];
    snprintf(l, sizeof(l), "  %s @0x%lx: %s", sym, (unsigned long)addr, hx);
    logline(l);
  }

  /* Detectar la forma del thunk y resolver impl_real. */
  intptr_t impl = 0, slot = 0;
  int kind = 0, rel_off = 0, instr_end = 0;
  if (h[0] == 0x31 && h[1] == 0xD2 && h[2] == 0xE9) {
    int32_t r; memcpy(&r, &h[3], 4); impl = addr + 7 + r;
    kind = 1; rel_off = 3; instr_end = 7;
  } else if (h[0] == 0xE9) {
    int32_t r; memcpy(&r, &h[1], 4); impl = addr + 5 + r;
    kind = 1; rel_off = 1; instr_end = 5;
  } else if (h[0] == 0xFF && h[1] == 0x25) {
    int32_t r; memcpy(&r, &h[2], 4); slot = addr + 6 + r; kind = 2;
    if (kernel_proc_copyout(pid, slot, &impl, 8) != 0) {
      char l[96];
      snprintf(l, sizeof(l), "  %s: no pude leer el slot GOT", sym);
      logline(l);
      return -1;
    }
  } else {
    char l[128];
    snprintf(l, sizeof(l),
             "  %s: forma no manejable (no es thunk) -> solo dump", sym);
    logline(l);
    return -1;
  }

  uint8_t sc[64];
  size_t sclen = is_array ? build_array(sc, impl) : build_single(sc, impl);

  intptr_t cave = find_code_cave(pid, mapbase > 0 ? mapbase : impl, sclen);
  if (!cave) {
    char l[96];
    snprintf(l, sizeof(l), "  %s: sin code cave de %u bytes", sym,
             (unsigned)sclen);
    logline(l);
    return -1;
  }

  if (kernel_mprotect(pid, cave, sclen,
                      PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
    char l[96];
    snprintf(l, sizeof(l), "  %s: mprotect(cave RWX) fallo", sym);
    logline(l);
    return -1;
  }
  if (kernel_proc_copyin(pid, sc, cave, sclen) != 0) {
    char l[96];
    snprintf(l, sizeof(l), "  %s: copyin(stub) fallo", sym);
    logline(l);
    kernel_mprotect(pid, cave, sclen, PROT_READ | PROT_EXEC);
    return -1;
  }
  kernel_mprotect(pid, cave, sclen, PROT_READ | PROT_EXEC);

  if (kind == 1) {
    int64_t disp = (int64_t)cave - (int64_t)(addr + instr_end);
    if (disp < INT32_MIN || disp > INT32_MAX) {
      char l[96];
      snprintf(l, sizeof(l), "  %s: cave fuera de rango rel32", sym);
      logline(l);
      return -1;
    }
    int32_t nr = (int32_t)disp;
    int op = kernel_get_vmem_protection(pid, addr, 8);
    if (op < 0) op = PROT_READ | PROT_EXEC;
    if (kernel_mprotect(pid, addr, 8,
                        PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
      char l[96];
      snprintf(l, sizeof(l), "  %s: mprotect(thunk) fallo", sym);
      logline(l);
      return -1;
    }
    if (kernel_proc_copyin(pid, &nr, addr + rel_off, 4) != 0) {
      char l[96];
      snprintf(l, sizeof(l), "  %s: copyin(rel32) fallo", sym);
      logline(l);
      kernel_mprotect(pid, addr, 8, op);
      return -1;
    }
    kernel_mprotect(pid, addr, 8, op);
  } else {
    int op = kernel_get_vmem_protection(pid, slot, 8);
    if (op < 0) op = PROT_READ | PROT_WRITE;
    if (kernel_mprotect(pid, slot, 8, PROT_READ | PROT_WRITE) != 0) {
      char l[96];
      snprintf(l, sizeof(l), "  %s: mprotect(slot) fallo", sym);
      logline(l);
      return -1;
    }
    if (kernel_proc_copyin(pid, &cave, slot, 8) != 0) {
      char l[96];
      snprintf(l, sizeof(l), "  %s: copyin(slot) fallo", sym);
      logline(l);
      kernel_mprotect(pid, slot, 8, op);
      return -1;
    }
    kernel_mprotect(pid, slot, 8, op);
  }

  {
    char l[192];
    snprintf(l, sizeof(l), "  %s: HOOK OK (%s) impl=0x%lx cave=0x%lx",
             sym, is_array ? "array" : "single",
             (unsigned long)impl, (unsigned long)cave);
    logline(l);
  }
  return 1;
}

/* ---- Hook en un proceso ------------------------------------------ */
/* 1 = algo hookeado (marcar), 0 = sin libScePad aun (reintentar). */
static int
hook_pad(pid_t pid, const char *name) {
  uint32_t handle = 0;
  if (kernel_dynlib_handle(pid, "libScePad.sprx", &handle) != 0 || !handle) {
    return 0;
  }
  intptr_t mapbase = kernel_dynlib_mapbase_addr(pid, handle);
  char m[160];
  snprintf(m, sizeof(m), "  pid=%d (%s): libScePad handle=%u mapbase=0x%lx",
           (int)pid, name, (unsigned)handle, (unsigned long)mapbase);
  logline(m);

  int any = 0;
  if (hook_func(pid, handle, mapbase, "scePadReadState", false) == 1) any = 1;
  if (hook_func(pid, handle, mapbase, "scePadRead", true) == 1) any = 1;
  probe_sym(pid, handle, "scePadReadStateExt");
  probe_sym(pid, handle, "scePadReadStateV2");
  return any ? 1 : 0;
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
      mark_hooked(pid);
      new_hooks++;
    }
    /* r == 0: aun sin libScePad; se reintenta en el proximo barrido */
  }

  free(buf);
  return new_hooks;
}

int
main(void) {
  logline("=== LeftStickKiller PASO 2 v2 (scePadReadState + scePadRead) ===");
  notify("Activo. Abre el juego con el mando roto; el stick izq. se centra solo.");

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
