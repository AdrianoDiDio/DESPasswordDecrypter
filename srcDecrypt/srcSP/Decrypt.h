#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <crypt.h>
#include <sys/time.h>

#ifdef __GNUC__
#define Attribute(x) __attribute__(x)
#else
#define Attribute(x)
#endif

typedef struct DecypherSettings_s {
    int MaxLength;
    char Salt[3];
    char *EncryptedPassword;
    char *Charset;
    char *DecryptedPassword;
    int CharsetSize;
} DecypherSettings_t;

void    DPrintf(char *Fmt, ...) Attribute((format(printf,1,2)));
