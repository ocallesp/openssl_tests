
CC		= gcc
CFLAGS 	= -ggdb -O0
LDFLAGS	= -lssl -lcrypto

all: swupd_sign swupd_verify

swupd_sign: swupd_sign.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

swupd_verify: swupd_verify.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean: 
	-$(RM) swupd_sign swupd_verify *.sign*

