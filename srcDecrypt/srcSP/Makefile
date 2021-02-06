
CC= gcc
CFLAGS=-Wall

Obj = Decrypt.o
LDFLAGS = -lcrypt

all: release

debug: CFLAGS +=-D_DEBUG -g
debug: PasswordDecrypterSP

release: CFLAGS += -O3
release: PasswordDecrypterSP

PasswordDecrypterSP: $(Obj)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(Obj) PasswordDecrypterSP
