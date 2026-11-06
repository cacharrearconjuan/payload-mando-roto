/* LeftStickKiller - v1.0.0: hook sin ptrace + soporte menú y juego
 *
 * Objetivo (accesibilidad): un DualSense con el stick izquierdo roto a nivel de
 * placa (deriva). Este payload engancha scePadReadState/scePadRead en el proceso
 * del juego Y en el menú de la consola, deja pasar la lectura real y fija el
 * stick izquierdo en el centro (0x80,0x80) SOLO para el mando (handle) que haya
 * pulsado L1+R1+R3.
 *
 * CAMBIOS v1.0.0 respecto a v12:
 *   1. SceShellCore se ha ELIMINADO de is_system_proc. En PS5 el menú lee el
 *      pad a través de SceShellCore; vetarlo impedía enganchar el menú. Ahora
 *      se escanea y, si tiene libScePad.sprx, se le aplica el mismo hook.
 *   2. Log de diagnóstico: cada proceso cuyo nombre contenga "SceShell" se
 *      registra como "Candidato menu: ..." en /data/LeftStickKiller.log.
 *   3. Mensaje de notify actualizado para mencionar menú y juego.
 *
 * POR QUÉ SE QUITÓ PTRACE (v12):
 *   El log de v11 demostró que el cuelgue estaba en pt_mmap: reservaba memoria
 *   por ptrace haciendo single-step, y en 11.60 ese single-step no retornaba de
 *   forma fiable. v12 en adelante coloca el stub en un "code cave" (racha de
 *   0xCC entre funciones) y salta a él con mov rax,imm64;jmp rax. Todo con
 *   kernel_proc_copyin: estable, no puede colgar ni crashear el proceso.
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

#define LSK_VERSION "1.0.0"
#define LOG_PATH    "/data/LeftStickKiller.log"
#define PAD_STRIDE  0x78 /* sizeof(ScePadData) = 120 */

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

/* ---- Estado por proceso (idempotencia) -------------------------- */
#define MAX_TRIES 3

typedef struct {
  pid_t pid;
  int tries;
  bool done;
} pstate_t;

static pstate_t procs[256];
static int procs_n = 0;

static pstate_t *
pstate_find(pid_t pid) {
  for (int i = 0; i < procs_n; i++) {
    if (procs[i].pid == pid) {
      return &procs[i];
    }
  }
  return 0;
}

static pstate_t *
pstate_get(pid_t pid) {
  pstate_t *st = pstate_find(pid);
  if (st) {
    return st;
  }
  if (procs_n < (int)(sizeof(procs) / sizeof(procs[0]))) {
    procs[procs_n].pid = pid;
    procs[procs_n].tries = 0;
    procs[procs_n].done = false;
    return &procs[procs_n++];
  }
  return 0;
}

/* Lista negra de procesos que NO queremos enganchar.
 *
 * v1.0.0: SceShellCore ya NO está en esta lista. En PS5 el menú de la consola
 * lee el pad a través de SceShellCore; si lo vetábamos, L1+R1+R3 no hacía nada
 * fuera del juego. Ahora se escanea como cualquier otro proceso. SceShellUI
 * nunca estuvo aquí, así que también se escanea.
 *
 * Si el log muestra "SceShellCore: sin code cave", el payload fallará LIMPIO
 * (no congela el menú). En ese caso habría que ampliar find_cave_any con más
 * librerías, pero es un caso poco probable. */
static bool
is_system_proc(const char *name) {
  return !strcmp(name, "SceRedisServer")|| !strcmp(name, "SceSysCore.elf") ||
         !strcmp(name, "SceSysCore")    || !strcmp(name, "SceGnmCompositor") ||
         !strcmp(name, "SceRemotePlay") || !strcmp(name, "SceJSCd");
}

/* ---- Thunks: prologo + jmp --------------------------------------- */

#define MAX_PRO 12

typedef struct {
  int kind;
  uint8_t pro[MAX_PRO];
  int pro_len;
  int rel_off;
  int instr_end;
  intptr_t slot;
  intptr_t target;
} thunk_t;

static bool
pro_dest_ok(int reg) {
  return reg == 0 || reg == 1 || reg == 2 || reg == 6 || reg == 7 ||
         (reg >= 8 && reg <= 11);
}

static int
pro_insn_len(const uint8_t *p, int avail) {
  int i = 0;
  uint8_t rex = 0;
  if (avail >= 1 && (p[0] & 0xF0) == 0x40) {
    rex = p[0];
    i = 1;
  }
  if (i >= avail) return 0;
  uint8_t op = p[i];

  if ((op == 0x31 || op == 0x29 || op == 0x33 || op == 0x2B) &&
      i + 1 < avail && (p[i + 1] & 0xC0) == 0xC0) {
    uint8_t m = p[i + 1];
    int dest = (op == 0x31 || op == 0x29)
                 ? ((m & 7) | ((rex & 1) << 3))
                 : (((m >> 3) & 7) | (((rex >> 2) & 1) << 3));
    return pro_dest_ok(dest) ? i + 2 : 0;
  }
  if (op >= 0xB8 && op <= 0xBF) {
    int dest = (op & 7) | ((rex & 1) << 3);
    int n = i + 1 + ((rex & 8) ? 8 : 4);
    return (n <= avail && pro_dest_ok(dest)) ? n : 0;
  }
  return 0;
}

static bool
parse_thunk(pid_t pid, intptr_t addr, const uint8_t *h, thunk_t *t) {
  memset(t, 0, sizeof(*t));
  int i = 0;
  while (i < MAX_PRO) {
    if (h[i] == 0xE9) {
      int32_t r;
      memcpy(&r, &h[i + 1], 4);
      t->kind = 1;
      t->rel_off = i + 1;
      t->instr_end = i + 5;
      t->target = addr + i + 5 + r;
      break;
    }
    if (h[i] == 0xFF && h[i + 1] == 0x25) {
      int32_t r;
      memcpy(&r, &h[i + 2], 4);
      t->kind = 2;
      t->slot = addr + i + 6 + r;
      if (kernel_proc_copyout(pid, t->slot, &t->target, 8) != 0) return false;
      break;
    }
    int n = pro_insn_len(h + i, MAX_PRO - i);
    if (!n) return false;
    i += n;
  }
  if (!t->kind) return false;
  t->pro_len = i;
  memcpy(t->pro, h, i);
  return true;
}

/* ---- Stubs (shellcode x86-64) ------------------------------------ */
static const uint8_t endbr64_pre[] = {
  0xF3, 0x0F, 0x1E, 0xFA,       /* endbr64                 */
};

static const uint8_t stub_hdr[] = {
  0x53,                         /* push rbx                */
  0x41, 0x54,                   /* push r12                */
  0x41, 0x55,                   /* push r13                */
  0x48, 0x89, 0xF3,             /* mov  rbx, rsi           */
  0x49, 0x89, 0xFC,             /* mov  r12, rdi           */
  0x48, 0xB8,                   /* mov  rax, imm64 (impl)  */
};

static const uint8_t stub_single_tail[] = {
  0xFF, 0xD0,                               /* call rax                */
  0x8B, 0x0B,                               /* mov ecx, dword [rbx]    */
  0x81, 0xE1, 0x04, 0x0C, 0x00, 0x00,       /* and ecx, 0xC04          */
  0x81, 0xF9, 0x04, 0x0C, 0x00, 0x00,       /* cmp ecx, 0xC04          */
  0x75, 0x07,                               /* jne skip_lock (+7)      */
  0x44, 0x89, 0x25, 0x17, 0x00, 0x00, 0x00, /* mov dword [rip+0x17], r12d */
  0x44, 0x3B, 0x25, 0x10, 0x00, 0x00, 0x00, /* cmp r12d, dword [rip+0x10] */
  0x75, 0x08,                               /* jne done (+8)           */
  0xC6, 0x43, 0x04, 0x80,                   /* mov byte [rbx+4], 0x80  */
  0xC6, 0x43, 0x05, 0x80,                   /* mov byte [rbx+5], 0x80  */
  0x41, 0x5D,                               /* pop r13                 */
  0x41, 0x5C,                               /* pop r12                 */
  0x5B,                                     /* pop rbx                 */
  0xC3,                                     /* ret                     */
  0xFF, 0xFF, 0xFF, 0xFF                    /* locked_handle inicial   */
};

static const uint8_t stub_array_tail[] = {
  0xFF, 0xD0,                               /* call rax                */
  0x50,                                     /* push rax                */
  0x83, 0xF8, 0x40,                         /* cmp eax, 64             */
  0x7E, 0x05,                               /* jle +5                  */
  0xB8, 0x40, 0x00, 0x00, 0x00,             /* mov eax, 64             */
  0x85, 0xC0,                               /* test eax, eax           */
  0x7E, 0x30,                               /* jle +0x30 (done_loop)   */
  0x8B, 0x0B,                               /* mov ecx, dword [rbx]    */
  0x81, 0xE1, 0x04, 0x0C, 0x00, 0x00,       /* and ecx, 0xC04          */
  0x81, 0xF9, 0x04, 0x0C, 0x00, 0x00,       /* cmp ecx, 0xC04          */
  0x75, 0x07,                               /* jne skip_lock (+7)      */
  0x44, 0x89, 0x25, 0x20, 0x00, 0x00, 0x00, /* mov dword [rip+0x20], r12d */
  0x44, 0x3B, 0x25, 0x19, 0x00, 0x00, 0x00, /* cmp r12d, dword [rip+0x19] */
  0x75, 0x08,                               /* jne next_iter (+8)      */
  0xC6, 0x43, 0x04, 0x80,                   /* mov byte [rbx+4], 0x80  */
  0xC6, 0x43, 0x05, 0x80,                   /* mov byte [rbx+5], 0x80  */
  0x48, 0x83, 0xC3, 0x78,                   /* add rbx, 0x78           */
  0xFF, 0xC8,                               /* dec eax                 */
  0x75, 0xD0,                               /* jnz -0x30 (loop_start)  */
  0x58,                                     /* pop rax                 */
  0x41, 0x5D,                               /* pop r13                 */
  0x41, 0x5C,                               /* pop r12                 */
  0x5B,                                     /* pop rbx                 */
  0xC3,                                     /* ret                     */
  0xFF, 0xFF, 0xFF, 0xFF                    /* locked_handle inicial   */
};

#define STUB_MAX (sizeof(endbr64_pre) + MAX_PRO + sizeof(stub_hdr) + 8 + \
                  sizeof(stub_array_tail))

static size_t
build_stub(uint8_t *sc, const thunk_t *t, intptr_t impl, bool is_array) {
  size_t n = 0;
  memcpy(sc + n, endbr64_pre, sizeof(endbr64_pre));
  n += sizeof(endbr64_pre);
  memcpy(sc + n, t->pro, t->pro_len);
  n += t->pro_len;
  memcpy(sc + n, stub_hdr, sizeof(stub_hdr));
  n += sizeof(stub_hdr);
  memcpy(sc + n, &impl, 8);
  n += 8;
  if (is_array) {
    memcpy(sc + n, stub_array_tail, sizeof(stub_array_tail));
    n += sizeof(stub_array_tail);
  } else {
    memcpy(sc + n, stub_single_tail, sizeof(stub_single_tail));
    n += sizeof(stub_single_tail);
  }
  return n;
}

/* Un thunk ya enganchado empieza por nuestro parche: 48 B8 <cave> FF E0 */
static bool
is_hooked_thunk(const uint8_t *h, intptr_t *cave_out) {
  if (h[0] == 0x48 && h[1] == 0xB8 && h[10] == 0xFF && h[11] == 0xE0) {
    memcpy(cave_out, h + 2, 8);
    return true;
  }
  return false;
}

/* ---- Busqueda de code cave (racha de 0xCC) SIN limite rel32 ------ */
static intptr_t
find_code_cave(pid_t pid, intptr_t start, size_t need) {
  uint8_t chunk[0x1000];
  intptr_t run_start = 0;
  size_t run_len = 0;
  intptr_t addr = start & ~((intptr_t)0xFFF);
  intptr_t limit = addr + 0x1000000; /* escanea 16 MiB del modulo */

  for (; addr < limit; addr += (intptr_t)sizeof(chunk)) {
    if (kernel_proc_copyout(pid, addr, chunk, sizeof(chunk)) != 0) {
      run_len = 0;
      continue;
    }
    for (size_t i = 0; i < sizeof(chunk); i++) {
      if (chunk[i] == 0xCC) {
        if (run_len == 0) run_start = addr + (intptr_t)i;
        run_len++;
        if (run_len >= need) return run_start;
      } else {
        run_len = 0;
      }
    }
  }
  return 0;
}

static intptr_t
find_cave_any(pid_t pid, intptr_t mapbase, size_t need) {
  static const char *libs[] = {
    "libScePad.sprx", "libc.sprx", "libSceLibcInternal.sprx",
    "libkernel.sprx", "libkernel_web.sprx", "libkernel_sys.sprx",
    "libSceSysmodule.sprx", "libSceGnmDriver.sprx",
  };
  intptr_t cave = 0;
  if (mapbase > 0) cave = find_code_cave(pid, mapbase, need);
  for (size_t i = 0; !cave && i < sizeof(libs) / sizeof(libs[0]); i++) {
    uint32_t h = 0;
    if (kernel_dynlib_handle(pid, libs[i], &h) != 0 || !h) continue;
    intptr_t base = kernel_dynlib_mapbase_addr(pid, h);
    if (base > 0) cave = find_code_cave(pid, base, need);
  }
  return cave;
}

/* ---- Diagnostico ------------------------------------------------- */
static void
log_bytes(const char *sym, intptr_t a, const uint8_t *b) {
  char hx[16 * 3 + 1];
  for (int i = 0; i < 16; i++) snprintf(hx + i * 3, 4, "%02x ", b[i]);
  char l[160];
  snprintf(l, sizeof(l), "  %s @0x%lx: %s", sym, (unsigned long)a, hx);
  logline(l);
}

static void
probe_sym(pid_t pid, uint32_t handle, const char *sym) {
  intptr_t a = kernel_dynlib_dlsym(pid, handle, sym);
  if (!a) return;
  uint8_t b[16];
  if (kernel_proc_copyout(pid, a, b, sizeof(b)) == 0) log_bytes(sym, a, b);
}

/* ---- Hook de una funcion (SIN ptrace) ---------------------------- */
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

  uint8_t h[MAX_PRO + 8];
  if (kernel_proc_copyout(pid, addr, h, sizeof(h)) != 0) {
    char l[96];
    snprintf(l, sizeof(l), "  %s @0x%lx: no pude leer", sym, (unsigned long)addr);
    logline(l);
    return -1;
  }
  log_bytes(sym, addr, h);

  intptr_t hooked_cave = 0;
  if (is_hooked_thunk(h, &hooked_cave)) {
    char l[128];
    snprintf(l, sizeof(l), "  %s: ya enganchado (cave=0x%lx)",
             sym, (unsigned long)hooked_cave);
    logline(l);
    return 2;
  }

  thunk_t t;
  if (!parse_thunk(pid, addr, h, &t)) {
    char l[128];
    snprintf(l, sizeof(l),
             "  %s: forma no manejable (no es prologo+jmp) -> solo dump", sym);
    logline(l);
    return -1;
  }
  intptr_t impl = t.target;

  uint8_t sc[STUB_MAX];
  size_t sclen = build_stub(sc, &t, impl, is_array);

  logline("  paso1: buscando code cave (sin ptrace)");
  intptr_t cave = find_cave_any(pid, mapbase, sclen);
  if (!cave) {
    char l[96];
    snprintf(l, sizeof(l), "  %s: sin code cave de %u bytes", sym, (unsigned)sclen);
    logline(l);
    return -1;
  }
  {
    char l[96];
    snprintf(l, sizeof(l), "  paso2: cave encontrado en 0x%lx", (unsigned long)cave);
    logline(l);
  }

  int cp = kernel_get_vmem_protection(pid, cave, sclen);
  if (cp < 0) cp = PROT_READ | PROT_EXEC;
  if (kernel_mprotect(pid, cave, sclen, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
    char l[96];
    snprintf(l, sizeof(l), "  %s: mprotect(cave RWX) fallo", sym);
    logline(l);
    return -1;
  }
  if (kernel_proc_copyin(pid, sc, cave, sclen) != 0) {
    char l[96];
    snprintf(l, sizeof(l), "  %s: copyin(stub) fallo", sym);
    logline(l);
    kernel_mprotect(pid, cave, sclen, cp);
    return -1;
  }
  kernel_mprotect(pid, cave, sclen, PROT_READ | PROT_WRITE | PROT_EXEC);
  logline("  paso3: stub escrito en el cave");

  uint8_t patch[12];
  patch[0] = 0x48;
  patch[1] = 0xB8;
  memcpy(patch + 2, &cave, 8);
  patch[10] = 0xFF;
  patch[11] = 0xE0;

  int op = kernel_get_vmem_protection(pid, addr, sizeof(patch));
  if (op < 0) op = PROT_READ | PROT_EXEC;
  if (kernel_mprotect(pid, addr, sizeof(patch),
                      PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
    char l[96];
    snprintf(l, sizeof(l), "  %s: mprotect(thunk) fallo", sym);
    logline(l);
    return -1;
  }
  if (kernel_proc_copyin(pid, patch, addr, sizeof(patch)) != 0) {
    char l[96];
    snprintf(l, sizeof(l), "  %s: copyin(parche thunk) fallo", sym);
    logline(l);
    kernel_mprotect(pid, addr, sizeof(patch), op);
    return -1;
  }
  kernel_mprotect(pid, addr, sizeof(patch), op);

  char l[192];
  snprintf(l, sizeof(l),
           "  %s: HOOK OK (%s) prologo=%dB impl=0x%lx cave=0x%lx len=%u",
           sym, is_array ? "array" : "single", t.pro_len,
           (unsigned long)impl, (unsigned long)cave, (unsigned)sclen);
  logline(l);
  return 1;
}

/* ---- Hook en un proceso (SIN ptrace) ----------------------------- */
static int
hook_pad(pid_t pid, const char *name, bool *failed) {
  uint32_t handle = 0;
  *failed = false;
  if (kernel_dynlib_handle(pid, "libScePad.sprx", &handle) != 0 || !handle) {
    return -1;
  }
  intptr_t mapbase = kernel_dynlib_mapbase_addr(pid, handle);

  char m[160];
  snprintf(m, sizeof(m), "  pid=%d (%s): libScePad handle=%u mapbase=0x%lx",
           (int)pid, name, (unsigned)handle, (unsigned long)mapbase);
  logline(m);

  static const struct {
    const char *sym;
    bool is_array;
  } targets[] = {
    {"scePadReadState", false},
    {"scePadRead", true},
  };

  int fresh = 0;
  for (size_t i = 0; i < sizeof(targets) / sizeof(targets[0]); i++) {
    int r = hook_func(pid, handle, mapbase, targets[i].sym, targets[i].is_array);
    if (r == 1) fresh++;
    else if (r == -1) *failed = true;
  }
  probe_sym(pid, handle, "scePadReadStateExt");
  probe_sym(pid, handle, "scePadReadStateV2");
  return fresh;
}

/* ---- Barrido de procesos ----------------------------------------- */
#define KINFO_PID_OFF    72
#define KINFO_NAME_OFF   447

static int
scan_and_hook(void) {
  int mib[4] = {1, 14, 8, 0};
  size_t buf_size = 0;
  int new_hooks = 0;

  if (sysctl(mib, 4, 0, &buf_size, 0, 0) != 0) return 0;
  uint8_t *buf = malloc(buf_size);
  if (!buf) return 0;
  if (sysctl(mib, 4, buf, &buf_size, 0, 0) != 0) {
    free(buf);
    return 0;
  }

  for (uint8_t *ptr = buf; ptr < buf + buf_size;) {
    int ki_structsize = *(int *)ptr;
    if (ki_structsize <= 0) break;
    pid_t pid = *(pid_t *)&ptr[KINFO_PID_OFF];
    char *name = (char *)&ptr[KINFO_NAME_OFF];
    ptr += ki_structsize;

    if (pid <= 0 || is_system_proc(name)) continue;

    /* Diagnostico: registrar cualquier proceso SceShell* que aparezca. */
    if (strstr(name, "SceShell") != NULL) {
      char l[160];
      snprintf(l, sizeof(l), "Candidato menu: %s (pid=%d)", name, (int)pid);
      logline(l);
    }

    pstate_t *st = pstate_find(pid);
    if (st && st->done) continue;

    bool failed = false;
    int r = hook_pad(pid, name, &failed);
    if (r < 0) continue;

    if (!st && !(st = pstate_get(pid))) continue;

    if (r > 0) new_hooks++;

    if (!failed) {
      st->done = true;
    } else if (++st->tries >= MAX_TRIES) {
      st->done = true;
      char l[96];
      snprintf(l, sizeof(l), "  pid=%d: fallos tras %d intentos, lo dejo",
               (int)pid, st->tries);
      logline(l);
    }
  }

  free(buf);
  return new_hooks;
}

int
main(void) {
  logline("=== LeftStickKiller v" LSK_VERSION " (menu + juego) ===");
  notify("Activo v" LSK_VERSION ". Pulsa L1+R1+R3 en el menú o en el juego.");

  for (;;) {
    int n = scan_and_hook();
    if (n > 0) {
      char msg[128];
      snprintf(msg, sizeof(msg),
               "Hook aplicado en %d proceso(s). Listo para bloquear stick.", n);
      notify(msg);
    }
    sleep(3);
  }

  return 0;
}
