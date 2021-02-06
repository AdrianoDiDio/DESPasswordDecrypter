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
    PoolWork_t GlobalWorkStatus;
    pthread_t *ThreadPool;
    DecipherSettings_t Settings;
    pthread_mutex_t JobStatusMutex;
    pthread_cond_t JobStatusCondition;
    int JobStatus;
    int ThreadPoolSize;
    char *DecryptedPassword;
} PoolJob_t;

int ComparePassword(DecipherSettings_t *DecipherSettings, char *PasswordAttempt, struct crypt_data *CryptReentrantData)
{
    char *HashedPasswordAttempt;
    HashedPasswordAttempt = crypt_r(PasswordAttempt, DecipherSettings->Salt, CryptReentrantData);
    return strcmp(DecipherSettings->EncryptedPassword, HashedPasswordAttempt) == 0;
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
        pthread_mutex_unlock(&Pool->JobStatusMutex);
        return NULL;
    }
    Pool->GlobalWorkStatus.CurrentPositionValue = Pool->GlobalWorkStatus.CharsetIterator * 
        Pool->Settings.CharsetIncrement;
    Pool->GlobalWorkStatus.TargetPositionValue = ((Pool->GlobalWorkStatus.CharsetIterator + 1) 
        * Pool->Settings.CharsetIncrement);
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
    struct crypt_data data;
    
    data.initialized = 0;
    
    Pool = (PoolJob_t *) Arg;
    
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    
    while( 1 ) {
        Work = (PoolWork_t *) PoolGetAvailableJob(Pool);
        if( Work == NULL ) {
            WorkerQuit(Pool,DECRYPTER_JOB_STATUS_
                REACHED_MAX_COMBINATION,NULL);
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

    Pool = (PoolJob_t *) Arg;    
    
    pthread_mutex_lock(&Pool->JobStatusMutex);

    while (Pool->JobStatus == DECRYPTER_JOB_STATUS_NOT_COMPLETED )
        pthread_cond_wait(&Pool->JobStatusCondition, &Pool->JobStatusMutex);

    JobStatus = Pool->JobStatus;
    pthread_mutex_unlock(&Pool->JobStatusMutex);

    if( JobStatus == DECRYPTER_JOB_STATUS_FOUND) {
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
    int PoolSize;
    int i;
    DecipherSettings_t StaticDecipherSettings;
    PoolWork_t StaticGlobalWorkStatus;
    
    if( argc < 3 ) {
        printf("Usage:%s <EncryptedPassword> <MaxLength> <Optional Charset>\n",argv[0]);
        return -1;
    }

    
    StaticDecipherSettings.EncryptedPassword = StringCopy(argv[1]);
    StaticDecipherSettings.Salt[0] = argv[1][0];
    StaticDecipherSettings.Salt[1] = argv[1][1];
    StaticDecipherSettings.Salt[2] = '\0';
    if( argv[3] != NULL ) {
        StaticDecipherSettings.Charset = StringCopy(argv[3]);
    } else {
        StaticDecipherSettings.Charset = StringCopy("abcdefghilmnopqrstuvzABCDEFGHILMNOP \
            QRSTUVZ0123456789./");
    }
    StaticDecipherSettings.CharsetSize = strlen(StaticDecipherSettings.Charset);
    StaticDecipherSettings.MaxLength = atoi(argv[2]);
    StaticDecipherSettings.CharsetIncrement = 2;

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
    PoolJob.ThreadPoolSize = 4;
    PoolJob.ThreadPool = (pthread_t *) malloc(PoolJob.ThreadPoolSize * sizeof(pthread_t));
    
    pthread_create(&Master,NULL,MasterWork,(void*) &PoolJob);
    for(i = 0; i < PoolJob.ThreadPoolSize; i++ ) {
        pthread_create(&PoolJob.ThreadPool[i],NULL,DoWork,(void*) &PoolJob);
    }
        
    pthread_join(Master,NULL);
    if( PoolJob.DecryptedPassword != NULL ) {
        printf("Decrypted Password is %s\n",PoolJob.DecryptedPassword);
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
