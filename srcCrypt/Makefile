
CC= gcc
CFLAGS=-Wall

Obj = Crypt.o
LDFLAGS = -lcrypt

all: release

debug: CFLAGS +=-D_DEBUG -g
debug: Crypt

release: CFLAGS += -O3
release: Crypt

Crypt: $(Obj)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(Obj) Crypt
