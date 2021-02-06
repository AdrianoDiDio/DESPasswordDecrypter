#include "Decrypt.h"

char DefaultCharset[] = "abcdefghilmnopqrstuvzABCDEFGHILMNOPQRSTUVZ0123456789./";

char *StringCopy(const char *From)
{
    char *Dest;

    Dest = malloc(strlen(From) + 1);

    if ( !Dest ) {
        return NULL;
    }

    strcpy(Dest, From);

    return Dest;
}

int ComparePassword(DecypherSettings_t *DecypherSettings,char *PasswordAttempt)
{
    char *HashedPasswordAttempt;
    HashedPasswordAttempt = crypt(PasswordAttempt,DecypherSettings->Salt);
    return strcmp(HashedPasswordAttempt,DecypherSettings->EncryptedPassword) == 0;
}

int GuessPasswordByLength(DecypherSettings_t *DecypherSettings,int PasswordLength)
{
    int *PositionIndex;
    char *CurrentCombination;
    int Place;
    int Found;
    int i;
    
    PositionIndex = (int*) malloc(PasswordLength * sizeof(int));
    CurrentCombination = (char*) malloc(PasswordLength * sizeof(char) + 1);
    
    for( i = 0; i < PasswordLength; i++ ) {
        CurrentCombination[i] = DecypherSettings->Charset[0];
        PositionIndex[i] = 0;
    }
    CurrentCombination[i] = '\0';
    Found = -1;
    while(1) {
        if( ComparePassword(DecypherSettings,CurrentCombination) ) {
            DecypherSettings->DecryptedPassword = StringCopy(CurrentCombination);
            Found = 1;
            break;
        }
        Place = PasswordLength - 1;
        while( Place >= 0 ) {
            PositionIndex[Place]++;
            if( PositionIndex[Place] == DecypherSettings->CharsetSize ) {
                PositionIndex[Place] = 0;
                CurrentCombination[Place] = DecypherSettings->Charset[0];
                Place--;
            } else {
                CurrentCombination[Place] = DecypherSettings->Charset[PositionIndex[Place]];
                break;
            }
        }
        if( Place < 0 ) {
            break;
        }
    }
    free(CurrentCombination);
    free(PositionIndex);
    return Found;
}

void Decrypt(DecypherSettings_t *DecypherSettings)
{
    int Start;
    int End;
    int Found;

    Start = Sys_Milliseconds();
    Found = 0;
    for( int i = 1; i <= DecypherSettings->MaxLength; i++ ) {
        if( GuessPasswordByLength(DecypherSettings,i) != -1 ) {
            Found = 1;
            break;
        }
    }
    End = Sys_Milliseconds();
    if( Found ) {
        printf("Password %s took %i msec to be cracked\n",DecypherSettings->EncryptedPassword,End-Start);
    } else {
        printf("Password not found...try increasing the max length.\n");
    }
}

DecypherSettings_t* DecypherSettingsInit(char *Key,int MaxLength,char *Charset)
{
    DecypherSettings_t *Out;
    if( strlen(Key) <= 2 ) {
        printf("DecypherSettingsInit:Invalid Key.\n");
        return NULL;
    }
    Out = malloc(sizeof(DecypherSettings_t));
    Out->MaxLength = MaxLength;
    Out->Salt[0] = Key[0];
    Out->Salt[1] = Key[1];
    Out->Salt[2] = '\0';
    Out->EncryptedPassword = StringCopy(Key);
    if( Charset != NULL ) {
        Out->Charset = StringCopy(Charset);
    } else {
        Out->Charset = StringCopy(DefaultCharset);
    }
    Out->CharsetSize = strlen(Out->Charset);
    return Out;
}

int main(int argc,char** argv)
{
    DecypherSettings_t *DecypherSettings;
    
    if( argc < 3 ) {
        printf("Usage:%s <EncryptedPassword> <MaxLength> <Optional Charset>\n",argv[0]);
        return -1;
    }
    assert(strlen(argv[1]) > 2);
    DPrintf("Running Decrypt on %s, Max Length is %s\n",argv[1],argv[2]);
    DecypherSettings = DecypherSettingsInit(argv[1],atoi(argv[2]),argv[3]);
    Decrypt(DecypherSettings);
    DecypherSettingsCleanUp(DecypherSettings);
}
