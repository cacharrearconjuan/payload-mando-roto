/* LeftStickKiller - PASO 2 (Opcion A, v4): hook de lectura del mando SIN ptrace
 *
 * Objetivo (accesibilidad): un DualSense tiene el stick izquierdo roto a nivel
 * de placa y deriva a la izquierda. Este payload engancha las funciones de
 * lectura del mando en el proceso del juego y menú, deja pasar la lectura real
 * y luego fija el stick izquierdo en el centro (X=0x80, Y=0x80) SOLO para el
 * mando (handle) que haya pulsado la combinación L1+R1+R3.
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

/* Se elimina SceShellUI de esta lista para poder enganchar el menú del sistema */
static bool
is_system_proc(const char *name) {
  return !strcmp(name, "SceShellCore") ||
         !strcmp(name, "SceRedisServer")|| !strcmp(name, "SceSysCore.elf") ||
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
/*
 * Se guardan rbx (array), r12 (handle) y r13 (alineación) para preservar la ABI
 * al llamar a la implementación real. El handle sobrevive la llamada en r12.
 */
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
  0x81, 0x3B, 0x04, 0x0C, 0x00, 0x00,       /* cmp dword [rbx], 0xC04  */
  0x75, 0x07,                               /* jne +7                  */
  0x44, 0x89, 0x25, 0x17, 0x00, 0x00, 0x00, /* mov dword [rip+0x17], r12d */
  0x44, 0x3B, 0x25, 0x10, 0x00, 0x00, 0x00, /* cmp r12d, dword [rip+0x10] */
  0x75, 0x08,                               /* jne +8                  */
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
  0x7E, 0x28,                               /* jle +0x28               */
  /* loop_start: */
  0x81, 0x3B, 0x04, 0x0C, 0x00, 0x00,       /* cmp dword [rbx], 0xC04  */
  0x75, 0x07,                               /* jne +7                  */
  0x44, 0x89, 0x25, 0x20, 0x00, 0x00, 0x00, /* mov dword [rip+0x20], r12d */
  0x44, 0x3B, 0x25, 0x19, 0x00, 0x00, 0x00, /* cmp r12d, dword [rip+0x19] */
  0x75, 0x08,                               /* jne +8                  */
  0xC6, 0x43, 0x04, 0x80,                   /* mov byte [rbx+4], 0x80  */
  0xC6, 0x43, 0x05, 0x80,                   /* mov byte [rbx+5], 0x80  */
  0x48, 0x83, 0xC3, 0x78,                   /* add rbx, 0x78           */
  0xFF, 0xC8,                               /* dec eax                 */
  0x75, 0xD8,                               /* jnz -0x28 (loop_start)  */
  /* done_loop: */
  0x58,                                     /* pop rax                 */
  0x41, 0x5D,                               /* pop r13                 */
  0x41, 0x5C,                               /* pop r12                 */
  0x5B,                                     /* pop rbx                 */
  0xC3,                                     /* ret                     */
  0xFF, 0xFF, 0xFF, 0xFF                    /* locked_handle inicial   */
};

#define STUB_MAX (MAX_PRO + sizeof(stub_hdr) + 8 + sizeof(stub_array_tail))

static size_t
build_stub(uint8_t *sc, const thunk_t *t, intptr_t impl, bool is_array) {
  size_t n = 0;
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

static bool
is_our_stub(pid_t pid, const thunk_t *t, intptr_t *real_impl) {
  uint8_t b[MAX_PRO + sizeof(stub_hdr) + 8];
  size_t n = t->pro_len + sizeof(stub_hdr) + 8;
  if (kernel_proc_copyout(pid, t->target, b, n) != 0) return false;
  if (memcmp(b, t->pro, t->pro_len) != 0 ||
      memcmp(b + t->pro_len, stub_hdr, sizeof(stub_hdr)) != 0) {
    return false;
  }
  memcpy(real_impl, b + t->pro_len + sizeof(stub_hdr), 8);
  return true;
}

/* ---- Busqueda de code cave (racha de 0xCC) ----------------------- */
static bool
in_rel32(intptr_t a, intptr_t near) {
  int64_t d = (int64_t)a - (int64_t)near;
  return d > -0x7FFF0000LL && d < 0x7FFF0000LL;
}

static intptr_t
find_code_cave(pid_t pid, intptr_t start, size_t need,
               intptr_t near, bool need_rel32) {
  uint8_t chunk[0x1000];
  intptr_t run_start = 0;
  size_t run_len = 0;
  intptr_t addr = start & ~((intptr_t)0xFFF);
  intptr_t limit = addr + 0x600000;

  if (need_rel32 && !in_rel32(addr, near)) return 0;
  for (; addr < limit; addr += (intptr_t)sizeof(chunk)) {
    if (kernel_proc_copyout(pid, addr, chunk, sizeof(chunk)) != 0) break;
    for (size_t i = 0; i < sizeof(chunk); i++) {
      if (chunk[i] == 0xCC) {
        if (run_len == 0) run_start = addr + (intptr_t)i;
        run_len++;
        if (run_len >= need &&
            (!need_rel32 || in_rel32(run_start + (intptr_t)need, near))) {
          return run_start;
        }
      } else {
        run_len = 0;
      }
    }
  }
  return 0;
}

static intptr_t
find_cave_any(pid_t pid, intptr_t mapbase, size_t need,
              intptr_t near, bool need_rel32) {
  static const char *libs[] = {
    "libkernel.sprx", "libkernel_web.sprx", "libkernel_sys.sprx",
    "libSceLibcInternal.sprx", "libc.sprx",
  };
  intptr_t cave = 0;
  if (mapbase > 0) cave = find_code_cave(pid, mapbase, need, near, need_rel32);
  for (size_t i = 0; !cave && i < sizeof(libs) / sizeof(libs[0]); i++) {
    uint32_t h = 0;
    if (kernel_dynlib_handle(pid, libs[i], &h) != 0 || !h) continue;
    intptr_t base = kernel_dynlib_mapbase_addr(pid, h);
    if (base > 0) cave = find_code_cave(pid, base, need, near, need_rel32);
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

/* ---- Hook de una funcion ----------------------------------------- */
static int
hook_func(pid_t pid, uint32_t handle, intptr_t mapbase,
          const char *sym, bool is_array) {
  intptr_t addr = kernel_dynlib_dlsym(pid, handle, sym);
  if (!addr) return 0;

  uint8_t h[MAX_PRO + 8];
  if (kernel_proc_copyout(pid, addr, h, sizeof(h)) != 0) return -1;

  thunk_t t;
  if (!parse_thunk(pid, addr, h, &t)) return -1;

  intptr_t impl = 0;
  if (is_our_stub(pid, &t, &impl)) return 2;
  impl = t.target;

  uint8_t sc[STUB_MAX];
  size_t sclen = build_stub(sc, &t, impl, is_array);

  intptr_t cave = find_cave_any(pid, mapbase, sclen, addr, t.kind == 1);
  if (!cave) return -1;

  if (kernel_mprotect(pid, cave, sclen, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
    return -1;
  
  if (kernel_proc_copyin(pid, sc, cave, sclen) != 0) {
    kernel_mprotect(pid, cave, sclen, PROT_READ | PROT_EXEC);
    return -1;
  }
  
  /* NOTA: Se deja PROT_WRITE intencionalmente para que el stub pueda escribir en locked_handle */
  kernel_mprotect(pid, cave, sclen, PROT_READ | PROT_WRITE | PROT_EXEC);

  if (t.kind == 1) {
    int64_t disp = (int64_t)cave - (int64_t)(addr + t.instr_end);
    if (disp < INT32_MIN || disp > INT32_MAX) return -1;
    int32_t nr = (int32_t)disp;
    size_t plen = (size_t)t.instr_end;
    int op = kernel_get_vmem_protection(pid, addr, plen);
    if (op < 0) op = PROT_READ | PROT_EXEC;
    if (kernel_mprotect(pid, addr, plen, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) return -1;
    if (kernel_proc_copyin(pid, &nr, addr + t.rel_off, 4) != 0) {
      kernel_mprotect(pid, addr, plen, op);
      return -1;
    }
    kernel_mprotect(pid, addr, plen, op);
  } else {
    int op = kernel_get_vmem_protection(pid, t.slot, 8);
    if (op < 0) op = PROT_READ | PROT_WRITE;
    if (kernel_mprotect(pid, t.slot, 8, PROT_READ | PROT_WRITE) != 0) return -1;
    if (kernel_proc_copyin(pid, &cave, t.slot, 8) != 0) {
      kernel_mprotect(pid, t.slot, 8, op);
      return -1;
    }
    kernel_mprotect(pid, t.slot, 8, op);
  }
  return 1;
}

/* ---- Hook en un proceso ------------------------------------------ */
static int
hook_pad(pid_t pid, const char *name, bool *failed) {
  uint32_t handle = 0;
  *failed = false;
  if (kernel_dynlib_handle(pid, "libScePad.sprx", &handle) != 0 || !handle) {
    return -1;
  }
  intptr_t mapbase = kernel_dynlib_mapbase_addr(pid, handle);

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
    }
  }

  free(buf);
  return new_hooks;
}

int
main(void) {
  logline("=== LeftStickKiller PASO 2 v4 (Filtro por Handle y soporte SceShellUI) ===");
  notify("Activo. Ya funciona en juego y menú (L1+R1+R3 para centrar el mando roto).");

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
