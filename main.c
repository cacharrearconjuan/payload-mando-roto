/* LeftStickKiller - PASO 2 (Opcion A, v3): hook de lectura del mando SIN ptrace
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
 * v3: los thunks son "prologo ; jmp impl" con prologos distintos
 * (scePadReadState = 31 d2, scePadRead = 31 c9 que conserva edx=count,
 * scePadReadStateExt = ba 01 00 00 00). Se decodifica el prologo, se localiza
 * el E9 y el prologo capturado se reproduce tal cual en el stub. Cada stub
 * va en su propio code cave, y si el thunk ya apunta a un stub nuestro se
 * trata como enganchado (no se reintenta ni se duplica).
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

/* ---- Estado por proceso (idempotencia) -------------------------- */
/* done = no volver a tocar este pid; tries = intentos con fallo parcial. */

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

/* Solo se crea entrada para procesos que ya tienen libScePad. */
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

static bool
is_system_proc(const char *name) {
  return !strcmp(name, "SceShellUI")    || !strcmp(name, "SceShellCore") ||
         !strcmp(name, "SceRedisServer")|| !strcmp(name, "SceSysCore.elf") ||
         !strcmp(name, "SceSysCore")    || !strcmp(name, "SceGnmCompositor") ||
         !strcmp(name, "SceRemotePlay") || !strcmp(name, "SceJSCd");
}

/* ---- Thunks: prologo + jmp --------------------------------------- */
/*
 * Formas reales vistas en libScePad (todas "prologo ; jmp impl"):
 *   scePadReadState    : 31 d2          e9 rel32   (xor edx,edx)
 *   scePadRead         : 31 c9          e9 rel32   (xor ecx,ecx; edx=count intacto)
 *   scePadReadStateExt : ba 01 00 00 00 e9 rel32   (mov edx,1)
 * Se decodifica el prologo instruccion a instruccion (solo formas seguras)
 * hasta encontrar el E9 (o FF 25 = jmp [rip+rel32]). El prologo capturado se
 * reproduce TAL CUAL al inicio del stub, nunca se hardcodea.
 */

#define MAX_PRO 12

typedef struct {
  int kind;              /* 1 = jmp rel32, 2 = jmp [rip+rel32] (GOT) */
  uint8_t pro[MAX_PRO];  /* bytes del prologo previos al salto       */
  int pro_len;
  int rel_off;           /* kind 1: offset del rel32 dentro del thunk */
  int instr_end;         /* kind 1: offset del final del jmp          */
  intptr_t slot;         /* kind 2: direccion del puntero GOT         */
  intptr_t target;       /* destino actual del salto                  */
} thunk_t;

/* Registro destino permitido: solo volatiles que no usa el stub
 * (rax, rcx, rdx, rsi, rdi, r8-r11). Nunca rbx/rsp/rbp/r12-r15. */
static bool
pro_dest_ok(int reg) {
  return reg == 0 || reg == 1 || reg == 2 || reg == 6 || reg == 7 ||
         (reg >= 8 && reg <= 11);
}

/* Longitud de una instruccion de prologo admitida, o 0 si no se admite. */
static int
pro_insn_len(const uint8_t *p, int avail) {
  int i = 0;
  uint8_t rex = 0;
  if (avail >= 1 && (p[0] & 0xF0) == 0x40) {
    rex = p[0];
    i = 1;
  }
  if (i >= avail) {
    return 0;
  }
  uint8_t op = p[i];

  /* xor/sub registro-registro: 31/29 (dest = r/m), 33/2B (dest = reg) */
  if ((op == 0x31 || op == 0x29 || op == 0x33 || op == 0x2B) &&
      i + 1 < avail && (p[i + 1] & 0xC0) == 0xC0) {
    uint8_t m = p[i + 1];
    int dest = (op == 0x31 || op == 0x29)
                 ? ((m & 7) | ((rex & 1) << 3))
                 : (((m >> 3) & 7) | (((rex >> 2) & 1) << 3));
    return pro_dest_ok(dest) ? i + 2 : 0;
  }
  /* mov r32, imm32 (B8+r); con REX.W es mov r64, imm64 */
  if (op >= 0xB8 && op <= 0xBF) {
    int dest = (op & 7) | ((rex & 1) << 3);
    int n = i + 1 + ((rex & 8) ? 8 : 4);
    return (n <= avail && pro_dest_ok(dest)) ? n : 0;
  }
  return 0;
}

/* h debe tener al menos MAX_PRO + 6 bytes. */
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
      if (kernel_proc_copyout(pid, t->slot, &t->target, 8) != 0) {
        return false;
      }
      break;
    }
    int n = pro_insn_len(h + i, MAX_PRO - i);
    if (!n) {
      return false;
    }
    i += n;
  }
  if (!t->kind) {
    return false;
  }
  t->pro_len = i;
  memcpy(t->pro, h, i);
  return true;
}

/* ---- Stubs (shellcode x86-64) ------------------------------------ */
/*
 * Ambos stubs empiezan por el PROLOGO capturado del thunk (p.ej. 31 d2 o
 * 31 c9), y despues la cabecera comun:
 *   push rbx ; mov rbx,rsi ; mov rax,impl ; call rax
 * Se entra con rsp%16==8; push rbx -> %16==0, asi que call deja impl con
 * %16==8 (ABI SysV). rsi = *ScePadData. rax (retorno) se conserva.
 *
 * Nota: al repuntar un thunk "prologo ; jmp", el prologo del thunk ya se
 * ejecuta antes de saltar al stub; repetirlo es idempotente (mismo valor) y
 * hace el stub autocontenido (vale tambien para el caso GOT).
 */
static const uint8_t stub_hdr[] = {
  0x53,                         /* push rbx                */
  0x48, 0x89, 0xF3,             /* mov  rbx, rsi           */
  0x48, 0xB8,                   /* mov  rax, imm64 (impl)  */
};

/* single (26 B + prologo) para scePadReadState(handle, data). */
static const uint8_t stub_single_tail[] = {
  0xFF, 0xD0,                   /* call rax                */
  0xC6, 0x43, 0x04, 0x80,       /* mov byte [rbx+4], 0x80  */
  0xC6, 0x43, 0x05, 0x80,       /* mov byte [rbx+5], 0x80  */
  0x5B,                         /* pop  rbx                */
  0xC3,                         /* ret                     */
};

/*
 * array (50 B + prologo) para scePadRead(handle, data[], count):
 *   call rax ; push rax ; cmp eax,64 ; jle ok ; mov eax,64 ;
 * ok/loop: test eax,eax ; jle done ;
 *   mov byte[rbx+4],0x80 ; mov byte[rbx+5],0x80 ; add rbx,0x78 ; dec eax ; jmp loop
 * done: pop rax ; pop rbx ; ret
 * eax tras call = numero de registros; se recorren todos (tope 64), stride 0x78.
 */
static const uint8_t stub_array_tail[] = {
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

/* Si 'target' ya es uno de nuestros stubs (mismo prologo + cabecera),
 * devuelve true y la impl real que llama. */
static bool
is_our_stub(pid_t pid, const thunk_t *t, intptr_t *real_impl) {
  uint8_t b[MAX_PRO + sizeof(stub_hdr) + 8];
  size_t n = t->pro_len + sizeof(stub_hdr) + 8;
  if (kernel_proc_copyout(pid, t->target, b, n) != 0) {
    return false;
  }
  if (memcmp(b, t->pro, t->pro_len) != 0 ||
      memcmp(b + t->pro_len, stub_hdr, sizeof(stub_hdr)) != 0) {
    return false;
  }
  memcpy(real_impl, b + t->pro_len + sizeof(stub_hdr), 8);
  return true;
}

/* ---- Busqueda de code cave (racha de 0xCC) ----------------------- */
/* Cada stub tiene su propio cave: una vez escrito ya no es 0xCC, asi que
 * la siguiente busqueda nunca lo reutiliza. Si need_rel32, el cave debe
 * quedar a menos de +-2 GiB de 'near' (para repuntar un jmp rel32). */
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
  intptr_t limit = addr + 0x600000; /* tope de escaneo: 6 MiB */

  if (need_rel32 && !in_rel32(addr, near)) {
    return 0;
  }
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

/* Primero en libScePad; si no hay sitio, en otras librerias del proceso. */
static intptr_t
find_cave_any(pid_t pid, intptr_t mapbase, size_t need,
              intptr_t near, bool need_rel32) {
  static const char *libs[] = {
    "libkernel.sprx", "libkernel_web.sprx", "libkernel_sys.sprx",
    "libSceLibcInternal.sprx", "libc.sprx",
  };
  intptr_t cave = 0;
  if (mapbase > 0) {
    cave = find_code_cave(pid, mapbase, need, near, need_rel32);
  }
  for (size_t i = 0; !cave && i < sizeof(libs) / sizeof(libs[0]); i++) {
    uint32_t h = 0;
    if (kernel_dynlib_handle(pid, libs[i], &h) != 0 || !h) {
      continue;
    }
    intptr_t base = kernel_dynlib_mapbase_addr(pid, h);
    if (base > 0) {
      cave = find_code_cave(pid, base, need, near, need_rel32);
    }
  }
  return cave;
}

/* ---- Diagnostico: volcar direccion y primeros 16 bytes ----------- */
static void
log_bytes(const char *sym, intptr_t a, const uint8_t *b) {
  char hx[16 * 3 + 1];
  for (int i = 0; i < 16; i++) {
    snprintf(hx + i * 3, 4, "%02x ", b[i]);
  }
  char l[160];
  snprintf(l, sizeof(l), "  %s @0x%lx: %s", sym, (unsigned long)a, hx);
  logline(l);
}

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
  log_bytes(sym, a, b);
}

/* ---- Hook de una funcion ----------------------------------------- */
/* Devuelve 2 si ya estaba enganchada, 1 si la engancha ahora,
 * 0 si no esta exportada, -1 si esta pero fallo. */
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

  thunk_t t;
  if (!parse_thunk(pid, addr, h, &t)) {
    char l[128];
    snprintf(l, sizeof(l),
             "  %s: forma no manejable (no es prologo+jmp) -> solo dump", sym);
    logline(l);
    return -1;
  }

  /* Idempotencia: el thunk ya apunta a un stub nuestro. */
  intptr_t impl = 0;
  if (is_our_stub(pid, &t, &impl)) {
    char l[192];
    snprintf(l, sizeof(l), "  %s: ya enganchado (stub=0x%lx impl=0x%lx)",
             sym, (unsigned long)t.target, (unsigned long)impl);
    logline(l);
    return 2;
  }
  impl = t.target;

  uint8_t sc[STUB_MAX];
  size_t sclen = build_stub(sc, &t, impl, is_array);

  intptr_t cave = find_cave_any(pid, mapbase, sclen, addr, t.kind == 1);
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

  if (t.kind == 1) {
    int64_t disp = (int64_t)cave - (int64_t)(addr + t.instr_end);
    if (disp < INT32_MIN || disp > INT32_MAX) {
      char l[96];
      snprintf(l, sizeof(l), "  %s: cave fuera de rango rel32", sym);
      logline(l);
      return -1;
    }
    int32_t nr = (int32_t)disp;
    size_t plen = (size_t)t.instr_end;
    int op = kernel_get_vmem_protection(pid, addr, plen);
    if (op < 0) op = PROT_READ | PROT_EXEC;
    if (kernel_mprotect(pid, addr, plen,
                        PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
      char l[96];
      snprintf(l, sizeof(l), "  %s: mprotect(thunk) fallo", sym);
      logline(l);
      return -1;
    }
    if (kernel_proc_copyin(pid, &nr, addr + t.rel_off, 4) != 0) {
      char l[96];
      snprintf(l, sizeof(l), "  %s: copyin(rel32) fallo", sym);
      logline(l);
      kernel_mprotect(pid, addr, plen, op);
      return -1;
    }
    kernel_mprotect(pid, addr, plen, op);
  } else {
    int op = kernel_get_vmem_protection(pid, t.slot, 8);
    if (op < 0) op = PROT_READ | PROT_WRITE;
    if (kernel_mprotect(pid, t.slot, 8, PROT_READ | PROT_WRITE) != 0) {
      char l[96];
      snprintf(l, sizeof(l), "  %s: mprotect(slot) fallo", sym);
      logline(l);
      return -1;
    }
    if (kernel_proc_copyin(pid, &cave, t.slot, 8) != 0) {
      char l[96];
      snprintf(l, sizeof(l), "  %s: copyin(slot) fallo", sym);
      logline(l);
      kernel_mprotect(pid, t.slot, 8, op);
      return -1;
    }
    kernel_mprotect(pid, t.slot, 8, op);
  }

  {
    char l[192];
    snprintf(l, sizeof(l),
             "  %s: HOOK OK (%s) prologo=%dB impl=0x%lx cave=0x%lx len=%u",
             sym, is_array ? "array" : "single", t.pro_len,
             (unsigned long)impl, (unsigned long)cave, (unsigned)sclen);
    logline(l);
  }
  return 1;
}

/* ---- Hook en un proceso ------------------------------------------ */
/* -1 = sin libScePad aun (reintentar sin contar).
 * Si no, devuelve cuantas funciones se engancharon AHORA y pone *failed
 * a true si alguna exportada no se pudo enganchar. */
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
    int r = hook_func(pid, handle, mapbase, targets[i].sym,
                      targets[i].is_array);
    if (r == 1) {
      fresh++;
    } else if (r == -1) {
      *failed = true;
    }
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

    if (pid <= 0 || is_system_proc(name)) {
      continue;
    }
    pstate_t *st = pstate_find(pid);
    if (st && st->done) {
      continue;
    }
    bool failed = false;
    int r = hook_pad(pid, name, &failed);
    if (r < 0) {
      continue; /* aun sin libScePad; se reintenta en el proximo barrido */
    }
    if (!st && !(st = pstate_get(pid))) {
      continue; /* tabla llena: el hook es idempotente, no pasa nada */
    }
    if (r > 0) {
      new_hooks++;
    }
    if (!failed) {
      st->done = true; /* todo enganchado (o ya lo estaba): no reintentar */
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
  logline("=== LeftStickKiller PASO 2 v3 (prologo generico: scePadReadState + scePadRead) ===");
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
