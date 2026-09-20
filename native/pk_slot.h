/*
 * packcore native core - key slots: opaque native-only AES key storage with
 * process-wide locking. Included exactly once by packcore.c.
 */
#pragma once

typedef struct {
    int used;
    uint8_t key[KEY_LEN];
} key_slot;

static key_slot g_slots[KEY_SLOTS];

/* Portable slot lock: CRITICAL_SECTION on Windows, pthread mutex on POSIX. */
#ifdef _WIN32
static CRITICAL_SECTION g_lock;
static INIT_ONCE g_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK lock_once(PINIT_ONCE once, PVOID param, PVOID *ctx) {
    (void) once; (void) param; (void) ctx;
    InitializeCriticalSection(&g_lock);
    return TRUE;
}
#define PK_LOCK()   do { InitOnceExecuteOnce(&g_once, lock_once, NULL, NULL); \
                         EnterCriticalSection(&g_lock); } while (0)
#define PK_UNLOCK() LeaveCriticalSection(&g_lock)
#else
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
#define PK_LOCK()   pthread_mutex_lock(&g_lock)
#define PK_UNLOCK() pthread_mutex_unlock(&g_lock)
#endif

static jbyteArray to_jbytes(JNIEnv *env, const uint8_t *p, jsize len) {
    jbyteArray arr = (*env)->NewByteArray(env, len);
    if (arr && len > 0) (*env)->SetByteArrayRegion(env, arr, 0, len, (const jbyte *) p);
    return arr;
}
