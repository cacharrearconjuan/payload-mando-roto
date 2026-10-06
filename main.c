/* LeftStickKiller - PASO 1b: sonda ampliada (solo lectura, segura)
 *
 * Mejora respecto a la anterior:
 *   - Lista TODOS los procesos (para localizar el del juego, se llame como
 *     se llame), no solo los que ya tienen libScePad.
 *   - En los que tienen libScePad, vuelca 64 bytes de scePadReadState para
 *     medir el relleno (int3 / 0xCC) y decidir la tecnica de hook mas segura.
 *   - Evita repetir lineas: solo registra cada proceso una vez (por pid).
 *
 * Sigue siendo de SOLO LECTURA: no escribe en memoria de otros procesos, no
 * puede colgar juegos. Informe en /data/LeftStickKiller.log + avisos.
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

#define LOG_PATH "/data/LeftStickKiller.log"
#define DUMP_LEN 64

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

/* ---- Enumeracion de procesos (sysctl KERN_PROC) ------------------ */

#define KINFO_PID_OFF    72
#define KINFO_NAME_OFF   447

static bool
is_system_proc(const char *name) {
  return !strcmp(name, "SceShellUI")    || !strcmp(name, "SceShellCore") ||
         !strcmp(name, "SceRedisServer")|| !strcmp(name, "SceSysCore.elf") ||
         !strcmp(name, "SceSysCore")    || !strcmp(name, "SceGnmCompositor") ||
         !strcmp(name, "SceRemotePlay") || !strcmp(name, "SceJSCd");
}

/* Si el proceso tiene libScePad, vuelca DUMP_LEN bytes de scePadReadState. */
static void
dump_pad(pid_t pid, const char *name) {
  uint32_t handle = 0;
  if (kernel_dynlib_handle(pid, "libScePad.sprx", &handle) != 0 || handle == 0) {
    return;
  }
  intptr_t addr = kernel_dynlib_dlsym(pid, handle, "scePadReadState");
  if (!addr) {
    return;
  }
  uint8_t bytes[DUMP_LEN];
  memset(bytes, 0, sizeof(bytes));
  if (kernel_proc_copyout(pid, addr, bytes, sizeof(bytes)) != 0) {
    char e[160];
    snprintf(e, sizeof(e), "    scePadReadState=0x%lx (NO pude leer bytes)",
             (unsigned long)addr);
    logline(e);
    return;
  }
  char hex[DUMP_LEN * 3 + 1];
  for (int i = 0; i < DUMP_LEN; i++) {
    snprintf(hex + i * 3, 4, "%02x ", bytes[i]);
  }
  char line[DUMP_LEN * 3 + 128];
  snprintf(line, sizeof(line),
           "    scePadReadState=0x%lx bytes=%s", (unsigned long)addr, hex);
  logline(line);
}

static pid_t seen[512];
static int seen_n = 0;

static bool
already_seen(pid_t pid) {
  for (int i = 0; i < seen_n; i++) {
    if (seen[i] == pid) {
      return true;
    }
  }
  if (seen_n < (int)(sizeof(seen) / sizeof(seen[0]))) {
    seen[seen_n++] = pid;
  }
  return false;
}

/* Lista todos los procesos nuevos; vuelca pad si procede. */
static void
scan(void) {
  int mib[4] = {1, 14, 0, 0}; /* CTL_KERN, KERN_PROC, KERN_PROC_ALL */
  size_t buf_size = 0;

  if (sysctl(mib, 3, 0, &buf_size, 0, 0) != 0) {
    return;
  }
  uint8_t *buf = malloc(buf_size);
  if (!buf) {
    return;
  }
  if (sysctl(mib, 3, buf, &buf_size, 0, 0) != 0) {
    free(buf);
    return;
  }

  for (uint8_t *ptr = buf; ptr < buf + buf_size;) {
    int ki_structsize = *(int *)ptr;
    if (ki_structsize <= 0) {
      break;
    }
    pid_t pid = *(pid_t *)&ptr[KINFO_PID_OFF];
    char *name = (char *)&ptr[KINFO_NAME_OFF];
    ptr += ki_structsize;

    if (pid <= 0 || already_seen(pid)) {
      continue;
    }

    char line[160];
    snprintf(line, sizeof(line), "pid=%d name=%s %s", (int)pid, name,
             is_system_proc(name) ? "[sistema]" : "[<-- posible JUEGO]");
    logline(line);
    dump_pad(pid, name);
  }

  free(buf);
}

int
main(void) {
  logline("=== LeftStickKiller PASO 1b (sonda ampliada) ===");
  notify("Sondeando. ABRE EL JUEGO que quieres usar y espera ~1 min.");

  /* ~2 min: tiempo para abrir el juego y que aparezca su proceso. */
  for (int i = 0; i < 60; i++) {
    scan();
    sleep(2);
  }

  char msg[128];
  snprintf(msg, sizeof(msg), "Sonda OK: %d proceso(s). Pasame el .log",
           seen_n);
  notify(msg);
  logline("RESULTADO: fin del sondeo. Enviame /data/LeftStickKiller.log");
  return 0;
}
