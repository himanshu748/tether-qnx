# Build with the QNX SDP toolchain: source qnxsdp-env.sh, then `make`.
CC ?= qcc
CFLAGS ?= -Vgcc_ntox86_64 -Wall -Wextra -O1

all: telemetryd

telemetryd: telemetryd.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f telemetryd
