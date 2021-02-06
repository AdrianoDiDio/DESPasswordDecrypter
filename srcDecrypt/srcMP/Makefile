
CC= gcc
CFLAGS=-Wall

Obj = Decrypt.o
LDFLAGS = -lcrypt -pthread

all: release

debug: CFLAGS +=-D_DEBUG -g
debug: PasswordDecrypterMP

release: CFLAGS += -O3
release: PasswordDecrypterMP

PasswordDecrypterMP: $(Obj)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(Obj) PasswordDecrypterMP
