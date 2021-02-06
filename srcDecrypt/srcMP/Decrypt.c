#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <pthread.h>
#define __USE_GNU
#include <crypt.h>

typedef enum {
    DECRYPTER_JOB_STATUS_NOT_COMPLETED = 0,
    DECRYPTER_JOB_STATUS_FOUND = 1,
    DECRYPTER_JOB_STATUS_REACHED_MAX_COMBINATION = 2
} DecrypterJobStatus;

typedef struct DecipherSettings_s {
    int MaxLength;
    char Salt[3];
    char *EncryptedPassword;
    char *Charset;
    char *DecryptedPassword;
    int CharsetSize;
    int CharsetIncrement;
} DecipherSettings_t;

typedef struct PoolWork_s {
    int CurrentLength;
    int CurrentPositionValue;
    int TargetPositionValue;
    int CharsetIterator;
} PoolWork_t;

typedef struct PoolJob_s {
//     int StartChar;
//     int TargetChar;
//     int Length;
    PoolWork_t GlobalWorkStatus;
    pthread_t *ThreadPool;
    DecipherSettings_t Settings;
    pthread_mutex_t JobStatusMutex;
    pthread_cond_t JobStatusCondition;
    int JobStatus;
    int ThreadPoolSize;
    char *DecryptedPassword;
} PoolJob_t;

int StartSeconds;

int Sys_Milliseconds()
{
    struct timeval tp;
    int CTime;

    gettimeofday(&tp, NULL);

    if ( !StartSeconds ){
        StartSeconds = tp.tv_sec;
        return tp.tv_usec/1000;
    }

    CTime = (tp.tv_sec - StartSeconds)*1000 + tp.tv_usec / 1000;

    return CTime;
}

char *StringCopy(const char *From)
{
    char *Dest;
    Dest = (char *) malloc(strlen(From) + 1);
    if ( !Dest ) {
        return NULL;
    }
    strcpy(Dest, From);
    return Dest;
}

int ComparePassword(DecipherSettings_t *DecipherSettings, char *PasswordAttempt, struct crypt_data *CryptReentrantData)
{
    char *HashedPasswordAttempt;
    HashedPasswordAttempt = crypt_r(PasswordAttempt, DecipherSettings->Salt, CryptReentrantData);

    return strcmp(DecipherSettings->EncryptedPassword, HashedPasswordAttempt) == 0;
//     return strcmp("foooB",PasswordAttempt) == 0;
}

int WorkerHasReachedMaxCombination(int *PositionIndexArray,int *TargetPositionIndexArray,int PositionIndexSize)
{
    int NumMaxCount;
    int i;

    NumMaxCount = 0;

    for( i = 0; i < PositionIndexSize; i++ ) {
        if( PositionIndexArray[i] == TargetPositionIndexArray[i] ) {
            NumMaxCount++;
        }
    }
    return NumMaxCount == i;
}

void *PoolGetAvailableJob(PoolJob_t *Pool)
{
    PoolWork_t *Work;
    int RealCharsetSize;
    
    pthread_mutex_lock(&Pool->JobStatusMutex);
    RealCharsetSize = Pool->Settings.CharsetSize - 1;
    if( Pool->GlobalWorkStatus.TargetPositionValue >= RealCharsetSize ) {
        Pool->GlobalWorkStatus.CharsetIterator = 0;
        Pool->GlobalWorkStatus.CurrentLength++;
    }
    if( Pool->GlobalWorkStatus.CurrentLength > Pool->Settings.MaxLength ) {
        //We have produced all the possible combinations...
        pthread_mutex_unlock(&Pool->JobStatusMutex);
        return NULL;
    }
    Pool->GlobalWorkStatus.CurrentPositionValue = Pool->GlobalWorkStatus.CharsetIterator * 
        Pool->Settings.CharsetIncrement;
    Pool->GlobalWorkStatus.TargetPositionValue = ((Pool->GlobalWorkStatus.CharsetIterator + 1) 
        * Pool->Settings.CharsetIncrement) - 1;
    //Clamp it if we have gone out of bounds...
    if( Pool->GlobalWorkStatus.TargetPositionValue > RealCharsetSize ) {
        Pool->GlobalWorkStatus.TargetPositionValue = RealCharsetSize;
    }
    Work = (PoolWork_t *) malloc(sizeof(PoolWork_t));
    Work->CurrentPositionValue = Pool->GlobalWorkStatus.CurrentPositionValue;
    Work->TargetPositionValue = Pool->GlobalWorkStatus.TargetPositionValue;
    Work->CurrentLength = Pool->GlobalWorkStatus.CurrentLength;
    Pool->GlobalWorkStatus.CharsetIterator++;
    pthread_mutex_unlock(&Pool->JobStatusMutex);
    return Work;
}
void WorkerQuit(PoolJob_t *Pool,DecrypterJobStatus Reason,char *DecryptedPassword)
{
    pthread_mutex_lock(&Pool->JobStatusMutex);
    Pool->JobStatus = Reason;
    if( DecryptedPassword != NULL ) {
        Pool->DecryptedPassword = DecryptedPassword;
    }
    pthread_cond_broadcast(&Pool->JobStatusCondition);
    pthread_mutex_unlock(&Pool->JobStatusMutex);
    pthread_exit(NULL);
}

void *DoWork(void *Arg)
{
    PoolJob_t  *Pool;
    PoolWork_t *Work;
    int *StartPositionIndex;
    int *TargetPositionIndex;
    char *CurrentCombination;
    char *DecryptedPassword;
    int Place;
    int i;
    pid_t tid = syscall(__NR_gettid);  
    
    struct crypt_data data;
    
    data.initialized = 0;
    
    Pool = (PoolJob_t *) Arg;
    
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    
//     printf("Worker %i Has started\n",tid);
    while( 1 ) {
        Work = (PoolWork_t *) PoolGetAvailableJob(Pool);
        if( Work == NULL ) {
            WorkerQuit(Pool,DECRYPTER_JOB_STATUS_REACHED_MAX_COMBINATION,NULL);
        }
        StartPositionIndex = (int *) malloc(Work->CurrentLength * sizeof(int));
        TargetPositionIndex = (int *) malloc(Work->CurrentLength * sizeof(int));
        CurrentCombination = (char *) malloc(Work->CurrentLength + 1);
        StartPositionIndex[0] = Work->CurrentPositionValue;
        TargetPositionIndex[0] = Work->TargetPositionValue;
        for( i = 0; i < Work->CurrentLength; i++ ) {
            if( i != 0 ) {
                StartPositionIndex[i] = 0;
                TargetPositionIndex[i] = Pool->Settings.CharsetSize - 1;
            }
            CurrentCombination[i] = Pool->Settings.Charset[StartPositionIndex[i]];
        }

        CurrentCombination[i] = '\0';

        while( 1 ) {
            if( WorkerHasReachedMaxCombination(StartPositionIndex,TargetPositionIndex,Work->CurrentLength) ) {
                break;
            }
            if( ComparePassword(&Pool->Settings, CurrentCombination, &data) ) {
                DecryptedPassword = (char *) malloc(strlen(CurrentCombination) + 1);
                strcpy(DecryptedPassword, CurrentCombination);
                WorkerQuit(Pool,DECRYPTER_JOB_STATUS_FOUND,DecryptedPassword);
            }
            Place = Work->CurrentLength - 1;
            while( Place >= 0 ) {
                StartPositionIndex[Place]++;
    //                WorkerLoad
                if( StartPositionIndex[Place] == Pool->Settings.CharsetSize ) {
                    StartPositionIndex[Place] = 0;
                    CurrentCombination[Place] = Pool->Settings.Charset[0];
                    Place--;
                } else {
                    CurrentCombination[Place] = Pool->Settings.Charset[StartPositionIndex[Place]];
                    break;
                }
            }
            if( Place < 0 ) {
                break;
            }
        }
        free(CurrentCombination);
        free(StartPositionIndex);
        free(TargetPositionIndex);
        free(Work);
    }
}
void *MasterWork(void *Arg)
{
    PoolJob_t  *Pool;
    int i;
    int JobStatus;
    pid_t tid = syscall(__NR_gettid);  

    Pool = (PoolJob_t *) Arg;    
    

    pthread_mutex_lock(&Pool->JobStatusMutex);

    while (Pool->JobStatus == DECRYPTER_JOB_STATUS_NOT_COMPLETED )
        pthread_cond_wait(&Pool->JobStatusCondition, &Pool->JobStatusMutex);

    JobStatus = Pool->JobStatus;
    pthread_mutex_unlock(&Pool->JobStatusMutex);

    if( JobStatus == 1) {
        for (i = 0; i < Pool->ThreadPoolSize ; i++) {
            pthread_cancel(Pool->ThreadPool[i]);
        }
    }
    for(i = 0; i < Pool->ThreadPoolSize; i++ ) {
        pthread_join(Pool->ThreadPool[i],NULL);
    }
    pthread_exit(NULL);

}
int main(int argc,char** argv)
{
    pthread_t Master;
    PoolJob_t PoolJob;
    int i;
    int Start;
    int End;
    DecipherSettings_t StaticDecipherSettings;
    PoolWork_t StaticGlobalWorkStatus;
    
    if( argc < 3 ) {
        printf("Usage:%s <EncryptedPassword> <MaxLength> <Optional Number of Worker Threads> <Optional Charset>\n",argv[0]);
        return -1;
    }
    
    StaticDecipherSettings.EncryptedPassword = StringCopy(argv[1]);
    StaticDecipherSettings.Salt[0] = argv[1][0];
    StaticDecipherSettings.Salt[1] = argv[1][1];
    StaticDecipherSettings.Salt[2] = '\0';
    if( argc > 3 && argv[4] != NULL ) {
        StaticDecipherSettings.Charset = StringCopy(argv[4]);
    } else {
        StaticDecipherSettings.Charset = StringCopy("abcdefghilmnopqrstuvzABCDEFGHILMNOPQRSTUVZ0123456789./");
    }
    StaticDecipherSettings.CharsetSize = strlen(StaticDecipherSettings.Charset);
    StaticDecipherSettings.MaxLength = atoi(argv[2]);
    StaticDecipherSettings.CharsetIncrement = 2;
    printf("Init with charset size:%i\n", StaticDecipherSettings.CharsetSize);
    PoolJob.Settings = StaticDecipherSettings;
    StaticGlobalWorkStatus.CurrentLength = 1;
    StaticGlobalWorkStatus.CurrentPositionValue = 0;
    StaticGlobalWorkStatus.TargetPositionValue = 0;
    StaticGlobalWorkStatus.CharsetIterator = 0;
    PoolJob.GlobalWorkStatus = StaticGlobalWorkStatus;
        
    pthread_mutex_init(&PoolJob.JobStatusMutex,NULL);
    pthread_cond_init(&PoolJob.JobStatusCondition,NULL);
    PoolJob.JobStatus = DECRYPTER_JOB_STATUS_NOT_COMPLETED;
    PoolJob.DecryptedPassword = NULL;
    
    if( argc > 3 && argv[3] != NULL ) {
        PoolJob.ThreadPoolSize = atoi(argv[3]);
    } else {
        PoolJob.ThreadPoolSize = 4;
    }
    
    Start = Sys_Milliseconds();
    pthread_create(&Master,NULL,MasterWork,(void*) &PoolJob);

    PoolJob.ThreadPool = (pthread_t *) malloc(PoolJob.ThreadPoolSize * sizeof(pthread_t));
    
    for(i = 0; i < PoolJob.ThreadPoolSize; i++ ) {
        pthread_create(&PoolJob.ThreadPool[i],NULL,DoWork,(void*) &PoolJob);
    }
        
    pthread_join(Master,NULL);
    
    End = Sys_Milliseconds();
    if( PoolJob.DecryptedPassword != NULL ) {
        printf("Decrypted Password is %s Time:%i ms\n",PoolJob.DecryptedPassword,End-Start);
        free(PoolJob.DecryptedPassword);
    } else {
        printf("Password couldn't be decrypted.\n");
    }
    
    free(StaticDecipherSettings.EncryptedPassword);
    free(StaticDecipherSettings.Charset);
    free(PoolJob.ThreadPool);
    
    pthread_mutex_destroy(&PoolJob.JobStatusMutex);
    pthread_cond_destroy(&PoolJob.JobStatusCondition);
    pthread_exit(NULL);
    
    return 0;
}
