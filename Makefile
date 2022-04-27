#PROD=no
CC = musl-gcc
CFLAGS = -Wall -I mbedtls/include/ -Os -s -static  -Lmbedtls/library/ -Wl,--start-group -lmbedcrypto -lmbedtls -lmbedx509 -Wl,--end-group 
CFLAGS_MBEDTLS="-s -Os"
BIN=cb
.PHONY: mbedtls

all:mbedtls cb

mbedtls:
	cp -f mbedtls_config.h  mbedtls/include/mbedtls/mbedtls_config.h
	CC=$(CC) CFLAGS=$(CFLAGS_MBEDTLS) make -C mbedtls no_test
cb:
	$(CC) cb.c $(CFLAGS)  -o $(BIN)

clean:
	rm -f $(BIN)
	make -C mbedtls clean
