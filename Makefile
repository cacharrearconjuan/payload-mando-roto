# LeftStickKiller - Makefile para el ps5-payload-sdk
#
# Uso:
#   export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
#   make
#
# Enviar a la consola (con el cargador ELF escuchando en el puerto 9021):
#   export PS5_HOST=<IP_de_tu_PS5>
#   export PS5_PORT=9021
#   make test

PS5_HOST ?= ps5
PS5_PORT ?= 9021

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK no esta definido. Haz: export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk)
endif

ELF := LeftStickKiller.elf

CFLAGS := -Wall -O2 -lScePad -lSceUserService -lSceNotification

all: $(ELF)

$(ELF): main.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(ELF)

test: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^
