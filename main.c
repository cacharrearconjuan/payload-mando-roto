/* LeftStickKiller - Payload para PS5 jailbreakeada
 *
 * Detecta el mando que pulsa la combinacion L1 + R1 + R3 y "mata" su stick
 * izquierdo (lo deja fijo en el centro, 0x80/0x80) para que un stick roto a
 * nivel de placa deje de generar movimiento fantasma (drift).
 *
 * - Muestra un aviso (toast) en pantalla cuando se activa/desactiva.
 * - Es residente: se queda en segundo plano hasta que apagas o reinicias la
 *   consola. No es persistente, no toca el almacenamiento: al reiniciar
 *   desaparece solo.
 *
 * IMPORTANTE (lee el README): este payload LEE los mandos con libScePad y
 * neutraliza el stick en SU PROPIA lectura. Para que el stick quede anulado
 * DENTRO de los juegos hace falta, ademas, enganchar (hook) la funcion de
 * lectura del mando en el proceso del juego. Eso depende del firmware y hay
 * que probarlo en la consola. Aqui tienes la base funcional y verificable:
 * la deteccion de la combinacion y el aviso en pantalla.
 *
 * Licencia: GPLv3+. Parte del ecosistema ps5-payload-dev.
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* API de libScePad (declarada a mano: Sony no publica cabeceras)      */
/* ------------------------------------------------------------------ */

/* Mascaras de botones (Orbis/Prospero, valores estables en PS4/PS5). */
#define SCE_PAD_BUTTON_L3        0x00000002
#define SCE_PAD_BUTTON_R3        0x00000004
#define SCE_PAD_BUTTON_OPTIONS   0x00000008
#define SCE_PAD_BUTTON_UP        0x00000010
#define SCE_PAD_BUTTON_RIGHT     0x00000020
#define SCE_PAD_BUTTON_DOWN      0x00000040
#define SCE_PAD_BUTTON_LEFT      0x00000080
#define SCE_PAD_BUTTON_L2        0x00000100
#define SCE_PAD_BUTTON_R2        0x00000200
#define SCE_PAD_BUTTON_L1        0x00000400
#define SCE_PAD_BUTTON_R1        0x00000800
#define SCE_PAD_BUTTON_TRIANGLE  0x00001000
#define SCE_PAD_BUTTON_CIRCLE    0x00002000
#define SCE_PAD_BUTTON_CROSS     0x00004000
#define SCE_PAD_BUTTON_SQUARE    0x00008000

/* Combinacion que identifica el mando roto: L1 + R1 + R3. */
#define COMBO (SCE_PAD_BUTTON_L1 | SCE_PAD_BUTTON_R1 | SCE_PAD_BUTTON_R3)

/* Valor central de un eje analogico (sin movimiento). */
#define STICK_CENTER 0x80

#define SCE_PAD_PORT_TYPE_STANDARD 0

typedef struct {
  uint8_t x;
  uint8_t y;
} ScePadAnalogStick;

typedef struct {
  uint8_t l2;
  uint8_t r2;
} ScePadAnalogButtons;

/* Estructura devuelta por scePadReadState. Solo nos importan los primeros
 * campos (buttons, leftStick); el resto lo cubrimos con relleno de sobra
 * para que scePadReadState nunca escriba fuera de nuestro buffer. */
typedef struct {
  uint32_t buttons;              /* 0x00 */
  ScePadAnalogStick leftStick;   /* 0x04 */
  ScePadAnalogStick rightStick;  /* 0x06 */
  ScePadAnalogButtons analogButtons; /* 0x08 */
  uint16_t padding;              /* 0x0A */
  float orientation[4];          /* 0x0C */
  float acceleration[3];         /* 0x1C */
  float angularVelocity[3];      /* 0x28 */
  uint8_t touchData[48];         /* 0x34 */
  uint8_t connected;             /* conexion */
  uint64_t timestamp;
  uint8_t extensionUnitData[16];
  uint8_t connectedCount;
  uint8_t reserve[2];
  uint8_t deviceUniqueDataLen;
  uint8_t deviceUniqueData[12];
  uint8_t _tail[128];            /* margen de seguridad */
} ScePadData;

int scePadInit(void);
int scePadOpen(int userID, int type, int index, void *param);
int scePadClose(int handle);
int scePadReadState(int handle, ScePadData *data);

/* ------------------------------------------------------------------ */
/* API de libSceUserService                                            */
/* ------------------------------------------------------------------ */

#define SCE_USER_SERVICE_MAX_LOGIN_USERS 4

typedef struct {
  int32_t userId[SCE_USER_SERVICE_MAX_LOGIN_USERS];
} SceUserServiceLoginUserIdList;

int sceUserServiceInitialize(void *params);
int sceUserServiceGetLoginUserIdList(SceUserServiceLoginUserIdList *list);

/* ------------------------------------------------------------------ */
/* API de libSceNotification (aviso en pantalla)                       */
/* ------------------------------------------------------------------ */

#define SCE_NOTIFICATION_LOCAL_USER_ID_SYSTEM 0xFE

int sceNotificationSend(int userId, bool isLogged, const char *payload);

/* Muestra un toast con el texto indicado. */
static void
notify(const char *message) {
  char payload[1024];
  snprintf(payload, sizeof(payload),
           "{"
           "\"rawData\":{"
           "\"viewTemplateType\":\"InteractiveToastTemplateB\","
           "\"channelType\":\"Downloads\","
           "\"useCaseId\":\"IDC\","
           "\"toastOverwriteType\":\"No\","
           "\"isImmediate\":true,"
           "\"priority\":100,"
           "\"viewData\":{"
           "\"message\":{\"body\":\"%s\"},"
           "\"subMessage\":{\"body\":\"LeftStickKiller\"}"
           "},"
           "\"platformViews\":{"
           "\"previewDisabled\":{\"viewData\":{"
           "\"icon\":{\"type\":\"Predefined\",\"parameters\":{\"icon\":\"download\"}},"
           "\"message\":{\"body\":\"%s\"}"
           "}}}"
           "},"
           "\"localNotificationId\":\"772311900\""
           "}",
           message, message);
  sceNotificationSend(SCE_NOTIFICATION_LOCAL_USER_ID_SYSTEM, true, payload);
}

/* ------------------------------------------------------------------ */
/* Estado por mando abierto                                            */
/* ------------------------------------------------------------------ */

typedef struct {
  int32_t userId;   /* usuario dueno del mando */
  int handle;       /* handle de scePadOpen */
  bool combo_prev;  /* la combinacion estaba pulsada en la vuelta anterior */
  bool killed;      /* stick izquierdo desactivado para este mando */
} PadSlot;

static PadSlot pads[SCE_USER_SERVICE_MAX_LOGIN_USERS];
static int pad_count = 0;

/* Abre los mandos de todos los usuarios con sesion iniciada que todavia no
 * tengamos abiertos (permite enchufar mandos despues de lanzar el payload). */
static void
refresh_pads(void) {
  SceUserServiceLoginUserIdList list;

  memset(&list, 0, sizeof(list));
  if (sceUserServiceGetLoginUserIdList(&list) != 0) {
    return;
  }

  for (int i = 0; i < SCE_USER_SERVICE_MAX_LOGIN_USERS; i++) {
    int32_t uid = list.userId[i];
    if (uid <= 0) {
      continue;
    }

    /* ya abierto? */
    bool known = false;
    for (int j = 0; j < pad_count; j++) {
      if (pads[j].userId == uid) {
        known = true;
        break;
      }
    }
    if (known) {
      continue;
    }

    int h = scePadOpen(uid, SCE_PAD_PORT_TYPE_STANDARD, 0, NULL);
    if (h >= 0 && pad_count < SCE_USER_SERVICE_MAX_LOGIN_USERS) {
      pads[pad_count].userId = uid;
      pads[pad_count].handle = h;
      pads[pad_count].combo_prev = false;
      pads[pad_count].killed = false;
      pad_count++;
    }
  }
}

int
main(void) {
  ScePadData data;
  int ticks = 0;

  sceUserServiceInitialize(NULL);
  scePadInit();

  refresh_pads();
  notify("LeftStickKiller activo. Pulsa L1 + R1 + R3 en el mando roto.");

  for (;;) {
    /* Cada ~2 s buscamos mandos nuevos. */
    if (++ticks >= 200) {
      ticks = 0;
      refresh_pads();
    }

    for (int i = 0; i < pad_count; i++) {
      memset(&data, 0, sizeof(data));
      if (scePadReadState(pads[i].handle, &data) != 0) {
        continue;
      }

      bool combo_now = (data.buttons & COMBO) == COMBO;

      /* Flanco de subida: justo al pulsar la combinacion, conmutamos. */
      if (combo_now && !pads[i].combo_prev) {
        pads[i].killed = !pads[i].killed;
        if (pads[i].killed) {
          notify("Mando identificado: stick izquierdo DESACTIVADO.");
        } else {
          notify("Stick izquierdo reactivado.");
        }
      }
      pads[i].combo_prev = combo_now;

      /* Mientras este "matado", forzamos el stick izquierdo al centro. */
      if (pads[i].killed) {
        data.leftStick.x = STICK_CENTER;
        data.leftStick.y = STICK_CENTER;
      }
    }

    usleep(10000); /* ~100 Hz */
  }

  return 0;
}
