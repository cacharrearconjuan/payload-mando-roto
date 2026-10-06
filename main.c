/* LeftStickKiller - PASO 1: sonda segura (no modifica nada)
 *
 * Objetivo final: cuando pulses L1 + R1 + R3 en el mando con el stick
 * izquierdo roto, forzar ese stick al centro (0x80) DENTRO de los juegos,
 * sin etaHEN, con un payload suelto. No persistente: desaparece al reiniciar.
 *
 * Para escribir un hook de scePadReadState que NO cuelgue el juego en tu
 * firmware (11.60) hace falta saber como es esa funcion por dentro en TU
 * consola. Este paso 1 es de solo lectura y seguro:
 *
 *   1. Enumera los procesos que tienen cargada libScePad (el juego en primer
 *      plano y la interfaz del sistema).
 *   2. En cada uno localiza la direccion de scePadReadState.
 *   3. Lee los primeros 16 bytes de esa funcion (el "prologo").
 *   4. Escribe un informe en /data/LeftStickKiller.log y muestra un aviso.
 *
 * Con el contenido de ese log te escribo el PASO 2: el hook real que centra
 * el stick izquierdo del mando marcado con la combinacion.
 *
 * No hace NINGUNA escritura en memoria de otros procesos. No puede colgar
 * juegos. Licencia: GPLv3+. Ecosistema ps5-payload-dev.
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
           "\"localNotificationId\":\"772311901\"}",
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
/* Offsets del kinfo_proc usados por el ecosistema ps5-payload-dev.   */

#define KINFO_PID_OFF    72
#define KINFO_NAME_OFF   447

/* Procesos del sistema que NO son el juego (solo para marcarlos en el log). */
static bool
is_system_proc(const char *name) {
  return !strcmp(name, "SceShellUI")    || !strcmp(name, "SceShellCore") ||
         !strcmp(name, "SceRedisServer")|| !strcmp(name, "SceSysCore")   ||
         !strcmp(name, "SceGnmCompositor");
}

/* Lee los primeros 16 bytes de scePadReadState en el proceso pid y los
 * registra. Devuelve true si lo consiguio. Solo lectura. */
static bool
probe_process(pid_t pid, const char *name) {
  uint32_t handle = 0;
  if (kernel_dynlib_handle(pid, "libScePad.sprx", &handle) != 0 || handle == 0) {
    return false; /* este proceso no usa libScePad */
  }

  intptr_t addr = kernel_dynlib_dlsym(pid, handle, "scePadReadState");
  if (!addr) {
    return false;
  }

  uint8_t bytes[16];
  memset(bytes, 0, sizeof(bytes));
  if (kernel_proc_copyout(pid, addr, bytes, sizeof(bytes)) != 0) {
    return false;
  }

  char hex[64];
  for (int i = 0; i < 16; i++) {
    snprintf(hex + i * 3, 4, "%02x ", bytes[i]);
  }

  char line[256];
  snprintf(line, sizeof(line), "pid=%d name=%s %s scePadReadState=0x%lx proI=%s",
           (int)pid, name, is_system_proc(name) ? "[sistema]" : "[JUEGO?]",
           (unsigned long)addr, hex);
  logline(line);
  return true;
}

/* Recorre todos los procesos y sonda los que tengan libScePad.
 * Devuelve cuantos proceso se pudieron sondar. */
static int
probe_all(void) {
  int mib[4] = {1, 14, 8, 0}; /* CTL_KERN, KERN_PROC, KERN_PROC_PROC */
  size_t buf_size = 0;
  int found = 0;

  if (sysctl(mib, 4, 0, &buf_size, 0, 0) != 0) {
    return -1;
  }
  uint8_t *buf = malloc(buf_size);
  if (!buf) {
    return -1;
  }
  if (sysctl(mib, 4, buf, &buf_size, 0, 0) != 0) {
    free(buf);
    return -1;
  }

  for (uint8_t *ptr = buf; ptr < buf + buf_size;) {
    int ki_structsize = *(int *)ptr;
    if (ki_structsize <= 0) {
      break;
    }
    pid_t pid = *(pid_t *)&ptr[KINFO_PID_OFF];
    char *name = (char *)&ptr[KINFO_NAME_OFF];
    ptr += ki_structsize;

    if (pid > 0 && probe_process(pid, name)) {
      found++;
    }
  }

  free(buf);
  return found;
}

int
main(void) {
  char msg[160];

  logline("=== LeftStickKiller PASO 1 (sonda) ===");
  notify("LeftStickKiller: sondeando. Abre un JUEGO y espera unos segundos.");

  /* Reintenta durante ~60 s para dar tiempo a abrir un juego. */
  int best = 0;
  for (int i = 0; i < 30; i++) {
    int n = probe_all();
    if (n > best) {
      best = n;
    }
    sleep(2);
  }

  if (best <= 0) {
    notify("No pude leer ningun proceso. Dime: no funciono el sondeo.");
    logline("RESULTADO: 0 procesos sondeados (sin acceso de kernel?).");
  } else {
    snprintf(msg, sizeof(msg),
             "Sonda OK: %d proceso(s). Pasame /data/LeftStickKiller.log",
             best);
    notify(msg);
    logline("RESULTADO: sondeo completado. Enviame este fichero.");
  }

  return 0;
}
