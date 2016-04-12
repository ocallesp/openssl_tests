
CC		= gcc
CFLAGS 	= -ggdb -O0
LDFLAGS	= -lssl -lcrypto

all: swupd_sign swupd_verify

swupd_sign: swupd_sign.c
	$(CC) $< -o $@ $(LDFLAGS)

swupd_verify: swupd_verify.c
	$(CC) $< -o $@ $(LDFLAGS)

clean: 
	-$(RM) swupd_sign swupd_verify *.sign*

