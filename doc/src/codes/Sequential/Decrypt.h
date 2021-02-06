typedef struct DecypherSettings_s {
    int MaxLength;
    char Salt[3];
    char *EncryptedPassword;
    char *Charset;
    char *DecryptedPassword;
    int CharsetSize;
} DecypherSettings_t;
