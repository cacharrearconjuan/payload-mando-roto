/* LeftStickKiller - PASO 2 (v8): hook de lectura del mando con pagina propia
 *
 * Objetivo (accesibilidad): un DualSense tiene el stick izquierdo roto a nivel
 * de placa y deriva a la izquierda. Este payload engancha las funciones de
 * lectura del mando en el proceso del juego y del menu, deja pasar la lectura
 * real y luego fija el stick izquierdo en el centro (X=0x80, Y=0x80) SOLO para
 * el mando (handle) que haya pulsado la combinacion L1+R1+R3.
 *
 * NOVEDAD v8 (CRITICA - arregla crashes y conflictos con otros payloads):
 *   El texto de libScePad.sprx es una pagina FISICA compartida por todos los
 *   procesos. La v7 parcheaba el thunk con kernel_proc_copyin, que escribe en
 *   esa pagina compartida saltandose el copy-on-write: el salto absoluto a la
 *   pagina del stub (que solo existe en UN proceso) aparecia en el thunk de
 *   TODOS los procesos. Los demas saltaban a una direccion no mapeada en su
 *   espacio -> crash / conflictos. v8 escribe el parche del thunk con pt_copyin
 *   (ptrace -> proc_rwmem), que provoca copy-on-write y deja el parche PRIVADO
 *   de cada proceso: cada uno apunta a su propia pagina. (El stub, en memoria
 *   anonima privada, se sigue escribiendo con write_mem, que no comparte nada.)
 *
 * NOVEDADES v7 (respecto a v6, que ya enganchaba el juego):
 *   1) El menu del sistema (SceShellUI) fallaba al escribir el stub en la
 *      pagina reservada ("copyin(stub) fallo"): la pagina anonima recien
 *      mapeada no estaba residente y kernel_proc_copyin no la forzaba. Ahora
 *      cada escritura usa write_mem(): intenta kernel_proc_copyin y, si falla,
 *      cae a pt_copyin (ptrace), que corre en el contexto del proceso y si
 *      fuerza el fallo de pagina. Asi se engancha tambien el menu.
 *   2) Ya no hace falta repetir el combo en cada juego/proceso: en cuanto el
 *      daemon detecta que algun stub ha quedado bloqueado (combo pulsado),
 *      guarda ese handle y PRE-ARMA todos los demas stubs (presentes y
 *      futuros) con el mismo handle. Pulsas L1+R1+R3 una vez y vale para todo.
 *
 * v6 ya habia resuelto el problema de fondo: en 11.60 no hay un "code cave"
 * suficientemente grande cerca del thunk, asi que se reserva una pagina propia
 * con pt_mmap y se parchea el thunk con un salto absoluto (mov rax; jmp rax).
 *
 * Licencia: GPLv3+. Ecosistema ps5-payload-dev. pt.c/pt.h son de John Tornblom.
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
#define PAD_STRIDE 0x78 /* sizeof(ScePadData) = 120 */
#define STUB_PAGE_SZ 0x4000 /* 16 KiB: tamano de pagina de PS5, de sobra */
#define NO_HANDLE 0xFFFFFFFFu /* valor "sin bloquear" en locked_handle */

#ifndef MAP_ANONYMOUS
#ifdef MAP_ANON
#define MAP_ANONYMOUS MAP_ANON
#else
#define MAP_ANONYMOUS 0x1000
#endif
#endif

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

/* ---- Escritura robusta en otro proceso --------------------------- */
/* Intenta la via de kernel y, si falla, la de ptrace (fuerza fallo de
 * pagina en el contexto del proceso, necesario para el menu). El proceso
 * debe estar attacheado con ptrace para que pt_copyin funcione.
 * OJO: solo para memoria PRIVADA del proceso (p.ej. la pagina anonima del
 * stub). Para el thunk, que esta en texto COMPARTIDO, NO uses write_mem:
 * usa pt_copyin directamente para forzar copy-on-write (ver hook_func). */
static int
write_mem(pid_t pid, const void *src, intptr_t dst, size_t len) {
  if (kernel_proc_copyin(pid, src, dst, len) == 0) return 0;
  if (pt_copyin(pid, src, dst, len) == 0) return 0;
  return -1;
}

/* ---- Estado por proceso (idempotencia + propagacion) ------------- */
#define MAX_TRIES 3

typedef struct {
  pid_t pid;
  int tries;
  bool done;
  intptr_t slot[2]; /* direccion de locked_handle: [0]=single [1]=array */
} pstate_t;

static pstate_t procs[256];
static int procs_n = 0;

/* Estado global de "armado": una vez pulsado el combo en cualquier proceso,
 * recordamos el handle para pre-armar el resto. */
static bool g_armed = false;
static uint32_t g_handle = NO_HANDLE;

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
    memset(&procs[procs_n], 0, sizeof(procs[0]));
    procs[procs_n].pid = pid;
    return &procs[procs_n++];
  }
  return 0;
}

/* SceShellUI NO esta en la lista, para poder enganchar el menu del sistema. */
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
 * Layout del stub en la pagina reservada:
 *   [endbr64] [prologo original] [stub_hdr] [impl:imm64] [tail]
 *
 * endbr64 va delante porque al stub saltamos con un salto INDIRECTO
 * (jmp rax); si el firmware fuerza CET/IBT, el destino de un salto indirecto
 * debe empezar por endbr64. Si no lo fuerza, endbr64 es un NOP: inofensivo.
 *
 * Se guardan rbx (array de datos) y r12 (handle) para que sobrevivan a la
 * llamada a la implementacion real; r13 es un tercer push solo para dejar la
 * pila alineada a 16 antes del call. (buttons AND 0xC04) == 0xC04 detecta el
 * combo L1+R1+R3 aunque haya otros botones pulsados.
 *
 * Los desplazamientos rip-relativos del tail (0x17/0x10 y 0x20/0x19) son
 * internos al propio tail, asi que no cambian al anteponer endbr64/prologo.
 */
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
  /* skip_lock: */
  0x44, 0x3B, 0x25, 0x10, 0x00, 0x00, 0x00, /* cmp r12d, dword [rip+0x10] */
  0x75, 0x08,                               /* jne done (+8)           */
  0xC6, 0x43, 0x04, 0x80,                   /* mov byte [rbx+4], 0x80  */
  0xC6, 0x43, 0x05, 0x80,                   /* mov byte [rbx+5], 0x80  */
  /* done: */
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
  /* loop_start: */
  0x8B, 0x0B,                               /* mov ecx, dword [rbx]    */
  0x81, 0xE1, 0x04, 0x0C, 0x00, 0x00,       /* and ecx, 0xC04          */
  0x81, 0xF9, 0x04, 0x0C, 0x00, 0x00,       /* cmp ecx, 0xC04          */
  0x75, 0x07,                               /* jne skip_lock (+7)      */
  0x44, 0x89, 0x25, 0x20, 0x00, 0x00, 0x00, /* mov dword [rip+0x20], r12d */
  /* skip_lock: */
  0x44, 0x3B, 0x25, 0x19, 0x00, 0x00, 0x00, /* cmp r12d, dword [rip+0x19] */
  0x75, 0x08,                               /* jne next_iter (+8)      */
  0xC6, 0x43, 0x04, 0x80,                   /* mov byte [rbx+4], 0x80  */
  0xC6, 0x43, 0x05, 0x80,                   /* mov byte [rbx+5], 0x80  */
  /* next_iter: */
  0x48, 0x83, 0xC3, 0x78,                   /* add rbx, 0x78           */
  0xFF, 0xC8,                               /* dec eax                 */
  0x75, 0xD0,                               /* jnz -0x30 (loop_start)  */
  /* done_loop: */
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

/* Un thunk ya enganchado empieza por nuestro parche: 48 B8 <page> FF E0 */
static bool
is_hooked_thunk(const uint8_t *h, intptr_t *page_out) {
  if (h[0] == 0x48 && h[1] == 0xB8 && h[10] == 0xFF && h[11] == 0xE0) {
    memcpy(page_out, h + 2, 8);
    return true;
  }
  return false;
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

/* ---- Hook de una funcion (proceso YA attacheado con ptrace) ------ */
/* En exito (return 1) deja en *slot_out la direccion de locked_handle. */
static int
hook_func(pid_t pid, uint32_t handle, const char *sym, bool is_array,
          intptr_t *slot_out) {
  if (slot_out) *slot_out = 0;
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

  intptr_t hooked_page = 0;
  if (is_hooked_thunk(h, &hooked_page)) {
    char l[128];
    snprintf(l, sizeof(l), "  %s: ya enganchado (pagina=0x%lx)",
             sym, (unsigned long)hooked_page);
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

  /* Reserva una pagina propia en el proceso (via ptrace) y hazla RWX. */
  intptr_t page = pt_mmap(pid, 0, STUB_PAGE_SZ, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (page == -1 || page < 0x1000) {
    char l[96];
    snprintf(l, sizeof(l), "  %s: pt_mmap fallo (errno=%d)", sym, pt_errno(pid));
    logline(l);
    return -1;
  }
  if (kernel_mprotect(pid, page, STUB_PAGE_SZ,
                      PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
    char l[96];
    snprintf(l, sizeof(l), "  %s: mprotect(pagina RWX) fallo (pagina=0x%lx)",
             sym, (unsigned long)page);
    logline(l);
    pt_munmap(pid, page, STUB_PAGE_SZ);
    return -1;
  }
  if (write_mem(pid, sc, page, sclen) != 0) {
    char l[96];
    snprintf(l, sizeof(l), "  %s: copyin(stub) fallo (pagina=0x%lx)",
             sym, (unsigned long)page);
    logline(l);
    pt_munmap(pid, page, STUB_PAGE_SZ);
    return -1;
  }

  /* Parchea el thunk con un salto absoluto a la pagina:
   *   48 B8 <page:8>   mov rax, page
   *   FF E0            jmp rax
   * Son 12 bytes y entran de sobra en los 16 del thunk. */
  uint8_t patch[12];
  patch[0] = 0x48;
  patch[1] = 0xB8;
  memcpy(patch + 2, &page, 8);
  patch[10] = 0xFF;
  patch[11] = 0xE0;

  int op = kernel_get_vmem_protection(pid, addr, sizeof(patch));
  if (op < 0) op = PROT_READ | PROT_EXEC;
  if (kernel_mprotect(pid, addr, sizeof(patch),
                      PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
    char l[96];
    snprintf(l, sizeof(l), "  %s: mprotect(thunk) fallo", sym);
    logline(l);
    pt_munmap(pid, page, STUB_PAGE_SZ);
    return -1;
  }
  /* IMPORTANTE: el thunk esta en el TEXTO de libScePad, que es una pagina
   * FISICA compartida por todos los procesos. Hay que escribir el parche con
   * pt_copyin (ptrace): pasa por proc_rwmem, que provoca copy-on-write y deja
   * el parche PRIVADO de este proceso. Con kernel_proc_copyin la escritura iria
   * a la pagina compartida y contaminaria a los demas procesos (saltarian a una
   * pagina que no existe en su espacio -> crash y conflictos con otros payloads).
   * Por eso aqui NO se usa write_mem (que probaria antes la via de kernel). */
  if (pt_copyin(pid, patch, addr, sizeof(patch)) != 0) {
    char l[96];
    snprintf(l, sizeof(l), "  %s: pt_copyin(parche thunk) fallo", sym);
    logline(l);
    kernel_mprotect(pid, addr, sizeof(patch), op);
    pt_munmap(pid, page, STUB_PAGE_SZ);
    return -1;
  }
  kernel_mprotect(pid, addr, sizeof(patch), op);

  if (slot_out) *slot_out = page + (intptr_t)sclen - 4;

  char l[192];
  snprintf(l, sizeof(l),
           "  %s: HOOK OK (%s) prologo=%dB impl=0x%lx pagina=0x%lx len=%u",
           sym, is_array ? "array" : "single", t.pro_len,
           (unsigned long)impl, (unsigned long)page, (unsigned)sclen);
  logline(l);
  return 1;
}

/* ---- Hook en un proceso ------------------------------------------ */
static int
hook_pad(pid_t pid, const char *name, bool *failed, intptr_t slots_out[2]) {
  uint32_t handle = 0;
  *failed = false;
  slots_out[0] = 0;
  slots_out[1] = 0;
  if (kernel_dynlib_handle(pid, "libScePad.sprx", &handle) != 0 || !handle) {
    return -1;
  }
  intptr_t mapbase = kernel_dynlib_mapbase_addr(pid, handle);

  char m[160];
  snprintf(m, sizeof(m), "  pid=%d (%s): libScePad handle=%u mapbase=0x%lx",
           (int)pid, name, (unsigned)handle, (unsigned long)mapbase);
  logline(m);

  if (pt_attach(pid) != 0) {
    char l[96];
    snprintf(l, sizeof(l), "  pid=%d: pt_attach fallo", (int)pid);
    logline(l);
    *failed = true;
    return 0;
  }

  static const struct {
    const char *sym;
    bool is_array;
  } targets[] = {
    {"scePadReadState", false},
    {"scePadRead", true},
  };

  int fresh = 0;
  for (size_t i = 0; i < sizeof(targets) / sizeof(targets[0]); i++) {
    int r = hook_func(pid, handle, targets[i].sym, targets[i].is_array,
                      &slots_out[i]);
    if (r == 1) fresh++;
    else if (r == -1) *failed = true;
  }
  probe_sym(pid, handle, "scePadReadStateExt");
  probe_sym(pid, handle, "scePadReadStateV2");

  pt_detach(pid, 0);
  return fresh;
}

/* ---- Propagacion del "armado" entre procesos --------------------- */
/* Lee los locked_handle de todos los stubs. Si alguno esta bloqueado (combo
 * pulsado), guarda ese handle como global y lo escribe en el resto de stubs
 * que aun no esten bloqueados, para no tener que repetir el combo en cada
 * juego/proceso. Escribe en la pagina anonima PRIVADA del stub (no en texto
 * compartido), asi que kernel_proc_copyin aqui es seguro y best-effort. */
static void
propagate_arm(void) {
  /* 1) Detectar un combo ya pulsado en cualquier stub. */
  for (int i = 0; i < procs_n && !g_armed; i++) {
    for (int k = 0; k < 2; k++) {
      intptr_t s = procs[i].slot[k];
      if (!s) continue;
      uint32_t v = NO_HANDLE;
      if (kernel_proc_copyout(procs[i].pid, s, &v, 4) == 0 && v != NO_HANDLE) {
        g_handle = v;
        g_armed = true;
        char l[112];
        snprintf(l, sizeof(l),
                 "  ARMADO global: handle=%u (pre-armo el resto de procesos)",
                 (unsigned)v);
        logline(l);
        break;
      }
    }
  }

  /* 2) Si estamos armados, pre-armar los stubs que sigan sin bloquear. */
  if (!g_armed) return;
  for (int i = 0; i < procs_n; i++) {
    for (int k = 0; k < 2; k++) {
      intptr_t s = procs[i].slot[k];
      if (!s) continue;
      uint32_t v = NO_HANDLE;
      if (kernel_proc_copyout(procs[i].pid, s, &v, 4) == 0 && v == NO_HANDLE) {
        kernel_proc_copyin(procs[i].pid, &g_handle, s, 4); /* best-effort */
      }
    }
  }
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
    intptr_t slots_out[2] = {0, 0};
    int r = hook_pad(pid, name, &failed, slots_out);
    if (r < 0) continue;

    if (!st && !(st = pstate_get(pid))) continue;

    if (slots_out[0]) st->slot[0] = slots_out[0];
    if (slots_out[1]) st->slot[1] = slots_out[1];

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
  logline("=== LeftStickKiller PASO 2 v8 (parche privado por proceso) ===");
  notify("Activo (v8). Pulsa L1+R1+R3 UNA vez en el mando roto; vale para juego y menu.");

  for (;;) {
    int n = scan_and_hook();
    propagate_arm();
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
