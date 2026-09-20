/*
 * packcore native core - JNI entry points for fabricpacker.N0:
 *   n0(data)                    -> SHA-256 digest
 *   n2(material, salt, info)    -> derive AES key natively, return slot handle
 *   n1(handle, nonce, aad, in, off, len) -> AES-256-GCM decrypt, or NULL
 *   n3(handle)                  -> destroy slot key
 *   n4()                        -> core version
 * Included exactly once by packcore.c.
 */
#pragma once

JNIEXPORT jbyteArray JNICALL Java_fabricpacker_N0_n0(JNIEnv *env, jclass cls, jbyteArray data) {
    jsize len = data ? (*env)->GetArrayLength(env, data) : 0;
    uint8_t *buf = NULL;
    uint8_t digest[32];
    jbyteArray out;
    (void) cls;
    if (len > 0) {
        buf = (uint8_t *) malloc((size_t) len);
        if (!buf) return NULL;
        (*env)->GetByteArrayRegion(env, data, 0, len, (jbyte *) buf);
    }
    sha256(buf, (size_t) len, digest);
    out = to_jbytes(env, digest, 32);
    secure_wipe(digest, 32);
    if (buf) { secure_wipe(buf, (size_t) len); free(buf); }
    return out;
}

/* Derives the real AES key natively and keeps it in a slot. Returns handle (0 = failure). */
JNIEXPORT jlong JNICALL Java_fabricpacker_N0_n2(JNIEnv *env, jclass cls,
        jbyteArray material, jbyteArray salt, jbyteArray info) {
    uint8_t m[KEY_LEN], s[SALT_LEN], info_buf[MAX_INFO], mask[KEY_LEN], key[KEY_LEN];
    jsize mlen = material ? (*env)->GetArrayLength(env, material) : 0;
    jsize slen = salt ? (*env)->GetArrayLength(env, salt) : 0;
    jsize ilen = info ? (*env)->GetArrayLength(env, info) : 0;
    jlong handle = 0;
    int i, slot = -1;
    (void) cls;
    if (mlen != KEY_LEN || slen != SALT_LEN || ilen < 1 || ilen > MAX_INFO) return 0;
    (*env)->GetByteArrayRegion(env, material, 0, mlen, (jbyte *) m);
    (*env)->GetByteArrayRegion(env, salt, 0, slen, (jbyte *) s);
    (*env)->GetByteArrayRegion(env, info, 0, ilen, (jbyte *) info_buf);
    hkdf_mask(s, info_buf, (size_t) ilen, mask);
    for (i = 0; i < KEY_LEN; i++) key[i] = (uint8_t)(m[i] ^ mask[i]);
    secure_wipe(mask, KEY_LEN);
    secure_wipe(m, KEY_LEN);
    secure_wipe(s, SALT_LEN);
    secure_wipe(info_buf, (size_t) ilen);
    PK_LOCK();
    for (i = 0; i < KEY_SLOTS; i++) {
        if (!g_slots[i].used) {
            g_slots[i].used = 1;
            memcpy(g_slots[i].key, key, KEY_LEN);
            slot = i;
            break;
        }
    }
    PK_UNLOCK();
    secure_wipe(key, KEY_LEN);
    if (slot >= 0) handle = (jlong) slot + 1;
    return handle;
}

/* Decrypts one GCM blob with the slot key. Returns plaintext or NULL on rejection. */
JNIEXPORT jbyteArray JNICALL Java_fabricpacker_N0_n1(JNIEnv *env, jclass cls, jlong handle,
        jbyteArray nonce, jbyteArray aad, jbyteArray in, jint inOff, jint inLen) {
    uint8_t key[KEY_LEN], n[NONCE_LEN];
    uint8_t *aadbuf = NULL, *inbuf = NULL, *outbuf = NULL;
    size_t outn = 0;
    jsize nlen = nonce ? (*env)->GetArrayLength(env, nonce) : 0;
    jsize alen = aad ? (*env)->GetArrayLength(env, aad) : 0;
    jsize total = in ? (*env)->GetArrayLength(env, in) : 0;
    jbyteArray result = NULL;
    int slot;
    (void) cls;
    if (handle < 1 || handle > KEY_SLOTS) return NULL;
    if (nlen != NONCE_LEN || inLen < TAG_LEN || inOff < 0
            || (size_t) inOff + (size_t) inLen > (size_t) total) return NULL;
    slot = (int) handle - 1;
    PK_LOCK();
    if (!g_slots[slot].used) { PK_UNLOCK(); return NULL; }
    memcpy(key, g_slots[slot].key, KEY_LEN);
    PK_UNLOCK();
    (*env)->GetByteArrayRegion(env, nonce, 0, NONCE_LEN, (jbyte *) n);
    if (alen > 0) {
        aadbuf = (uint8_t *) malloc((size_t) alen);
        if (!aadbuf) goto fail;
        (*env)->GetByteArrayRegion(env, aad, 0, alen, (jbyte *) aadbuf);
    }
    inbuf = (uint8_t *) malloc((size_t) inLen);
    if (!inbuf) goto fail;
    (*env)->GetByteArrayRegion(env, in, inOff, inLen, (jbyte *) inbuf);
    outbuf = (uint8_t *) malloc((size_t) inLen - TAG_LEN);
    if (!outbuf) goto fail;
    if (gcm_decrypt(key, n, aadbuf, (size_t) alen, inbuf, (size_t) inLen, outbuf, &outn) != 0) goto fail;
    result = to_jbytes(env, outbuf, (jsize) outn);
fail:
    if (aadbuf) { secure_wipe(aadbuf, (size_t) alen); free(aadbuf); }
    if (inbuf) { secure_wipe(inbuf, (size_t) inLen); free(inbuf); }
    if (outbuf) { secure_wipe(outbuf, (size_t) inLen - TAG_LEN); free(outbuf); }
    secure_wipe(key, KEY_LEN);
    secure_wipe(n, NONCE_LEN);
    return result;
}

/* Destroys the slot key (called from the loader's close()). */
JNIEXPORT void JNICALL Java_fabricpacker_N0_n3(JNIEnv *env, jclass cls, jlong handle) {
    int slot;
    (void) env; (void) cls;
    if (handle < 1 || handle > KEY_SLOTS) return;
    slot = (int) handle - 1;
    PK_LOCK();
    if (g_slots[slot].used) {
        g_slots[slot].used = 0;
        secure_wipe(g_slots[slot].key, KEY_LEN);
    }
    PK_UNLOCK();
}

/* Core version, used by the loader as a sanity check. */
JNIEXPORT jint JNICALL Java_fabricpacker_N0_n4(JNIEnv *env, jclass cls) {
    (void) env; (void) cls;
    return 20260920;
}

/*
 * Native debugger probe. Returns a bitmask (0 = clean). Windows uses the PEB /
 * debug APIs, Linux reads /proc/self/status TracerPid, macOS uses sysctl P_TRACED.
 * Native detection is much harder to patch out than a Java-side check.
 */
#ifdef _WIN32
JNIEXPORT jint JNICALL Java_fabricpacker_N0_n5(JNIEnv *env, jclass cls) {
    jint flags = 0;
    BOOL remote = FALSE;
    (void) env; (void) cls;
    if (IsDebuggerPresent()) flags |= 1;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote) flags |= 2;
#if defined(_M_X64)
    {
        /* PEB->NtGlobalFlag at offset 0xBC; heap debug flags set under a debugger. */
        unsigned char *peb = (unsigned char *) __readgsqword(0x60);
        unsigned int ntGlobalFlag = *(unsigned int *) (peb + 0xBC);
        if (ntGlobalFlag & 0x70) flags |= 4;
    }
#endif
    return flags;
}
#elif defined(__linux__)
JNIEXPORT jint JNICALL Java_fabricpacker_N0_n5(JNIEnv *env, jclass cls) {
    FILE *f;
    char line[256];
    int flags = 0;
    (void) env; (void) cls;
    f = fopen("/proc/self/status", "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                if (atoi(line + 10) != 0) flags = 1;
                break;
            }
        }
        fclose(f);
    }
    return flags;
}
#elif defined(__APPLE__)
JNIEXPORT jint JNICALL Java_fabricpacker_N0_n5(JNIEnv *env, jclass cls) {
    struct kinfo_proc info;
    size_t size = sizeof(info);
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    (void) env; (void) cls;
    memset(&info, 0, sizeof(info));
    if (sysctl(mib, 4, &info, &size, NULL, 0) == 0 && (info.kp_proc.p_flag & P_TRACED)) return 1;
    return 0;
}
#else
JNIEXPORT jint JNICALL Java_fabricpacker_N0_n5(JNIEnv *env, jclass cls) {
    (void) env; (void) cls; return 0;
}
#endif

#ifdef _WIN32
/* Distinctive window-title fragments of GUI reverse-engineering / dump tools.
 * Kept specific on purpose so common apps (e.g. "Nvidia") never match. */
static const char *const PK_WINDOW_NEEDLES[] = {
    "jbytemod", "recaf", "bytecode viewer", "bytecode-viewer", "threadtear",
    "ghidra", "x64dbg", "x32dbg", "dnspy", "cheat engine", "jd-gui",
    "task manager", "task-manager"
};

typedef struct { int hit; } pk_wt_ctx;

static BOOL CALLBACK pk_wt_enum(HWND hwnd, LPARAM lparam) {
    pk_wt_ctx *ctx = (pk_wt_ctx *) lparam;
    char title[256];
    int len, i, k;
    if (!IsWindowVisible(hwnd)) return TRUE;
    len = GetWindowTextA(hwnd, title, (int) sizeof(title));
    if (len <= 0) return TRUE;
    for (i = 0; i < len; i++) {
        if (title[i] >= 'A' && title[i] <= 'Z') title[i] = (char) (title[i] + 32);
    }
    for (k = 0; k < (int) (sizeof(PK_WINDOW_NEEDLES) / sizeof(PK_WINDOW_NEEDLES[0])); k++) {
        if (strstr(title, PK_WINDOW_NEEDLES[k])) { ctx->hit = 1; return FALSE; }
    }
    return TRUE;
}

/* Scans visible top-level window titles for RE/dump-tool GUIs. 1 = found. */
JNIEXPORT jint JNICALL Java_fabricpacker_N0_n6(JNIEnv *env, jclass cls) {
    pk_wt_ctx ctx;
    ctx.hit = 0;
    (void) env; (void) cls;
    EnumWindows(pk_wt_enum, (LPARAM) &ctx);
    return ctx.hit;
}
#else
/* No portable top-level window enumeration; the process scan covers tools here. */
JNIEXPORT jint JNICALL Java_fabricpacker_N0_n6(JNIEnv *env, jclass cls) {
    (void) env; (void) cls; return 0;
}
#endif

/* Process base names (no extension) of debuggers / dumpers / inspectors. */
static const char *const PK_PROC_NEEDLES[] = {
    "ida", "ida64", "ida32", "x64dbg", "x32dbg", "ollydbg", "windbg", "binaryninja",
    "dnspy", "ilspy", "dotpeek", "jd-gui", "recaf", "de4dot", "scylla", "megadumper",
    "extremedumper", "cheatengine", "frida", "frida-server", "radare2", "cutter",
    "processhacker", "systeminformer", "procmon", "procexp", "wireshark", "fiddler",
    "hxd", "pe-bear", "pestudio", "ghidra", "jbytemod", "threadtear", "taskmgr"
};
static const char *const PK_MODULE_NEEDLES[] = { "frida" };

static void pk_lower_noext(const char *in, char *out, size_t cap) {
    size_t i = 0, n;
    while (in[i] && i + 1 < cap) {
        char c = in[i];
        out[i] = (c >= 'A' && c <= 'Z') ? (char) (c + 32) : c;
        i++;
    }
    out[i] = 0;
    n = strlen(out);
    if (n > 4 && strcmp(out + n - 4, ".exe") == 0) out[n - 4] = 0;
}

static int pk_name_match(const char *base) {
    int k;
    for (k = 0; k < (int) (sizeof(PK_PROC_NEEDLES) / sizeof(PK_PROC_NEEDLES[0])); k++) {
        const char *needle = PK_PROC_NEEDLES[k];
        size_t ln = strlen(needle);
        if (strcmp(base, needle) == 0) return 1;
        if (strncmp(base, needle, ln) == 0 && (base[ln] == '-' || base[ln] == '_')) return 1;
    }
    return 0;
}

#ifdef _WIN32
static int pk_scan_processes(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    int hit = 0;
    if (snap == INVALID_HANDLE_VALUE) return 0;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            char base[280];
            pk_lower_noext(pe.szExeFile, base, sizeof(base));
            if (pk_name_match(base)) { hit = 1; break; }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return hit;
}

static int pk_scan_modules(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    MODULEENTRY32 me;
    int hit = 0, k;
    if (snap == INVALID_HANDLE_VALUE) return 0;
    me.dwSize = sizeof(me);
    if (Module32First(snap, &me)) {
        do {
            char base[280];
            pk_lower_noext(me.szModule, base, sizeof(base));
            for (k = 0; k < (int) (sizeof(PK_MODULE_NEEDLES) / sizeof(PK_MODULE_NEEDLES[0])); k++) {
                if (strstr(base, PK_MODULE_NEEDLES[k])) { hit = 1; break; }
            }
        } while (!hit && Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return hit;
}

static int pk_scan_debugregs(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te;
    DWORD pid = GetCurrentProcessId();
    int hit = 0;
    if (snap == INVALID_HANDLE_VALUE) return 0;
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            {
                HANDLE th = OpenThread(THREAD_GET_CONTEXT, FALSE, te.th32ThreadID);
                if (th) {
                    CONTEXT ctx;
                    memset(&ctx, 0, sizeof(ctx));
                    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                    if (GetThreadContext(th, &ctx)) {
                        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3 || (ctx.Dr7 & 0xFF)) hit = 1;
                    }
                    CloseHandle(th);
                }
            }
        } while (!hit && Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return hit;
}

#elif defined(__linux__)
static int pk_scan_processes(void) {
    DIR *d = opendir("/proc");
    struct dirent *e;
    int hit = 0;
    if (!d) return 0;
    while (!hit && (e = readdir(d)) != NULL) {
        const char *p = e->d_name;
        int isnum = (*p != 0);
        for (; *p; p++) if (!isdigit((unsigned char) *p)) { isnum = 0; break; }
        if (isnum) {
            char path[300], comm[280], base[280];
            FILE *f;
            snprintf(path, sizeof(path), "/proc/%s/comm", e->d_name);
            f = fopen(path, "r");
            if (f) {
                if (fgets(comm, sizeof(comm), f)) {
                    size_t l = strlen(comm);
                    while (l && (comm[l - 1] == '\n' || comm[l - 1] == '\r')) comm[--l] = 0;
                    pk_lower_noext(comm, base, sizeof(base));
                    if (pk_name_match(base)) hit = 1;
                }
                fclose(f);
            }
        }
    }
    closedir(d);
    return hit;
}

static int pk_scan_modules(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    int hit = 0, k;
    if (!f) return 0;
    while (!hit && fgets(line, sizeof(line), f)) {
        for (k = 0; k < (int) (sizeof(PK_MODULE_NEEDLES) / sizeof(PK_MODULE_NEEDLES[0])); k++) {
            if (strstr(line, PK_MODULE_NEEDLES[k])) { hit = 1; break; }
        }
    }
    fclose(f);
    return hit;
}

#elif defined(__APPLE__)
static int pk_scan_processes(void) {
    pid_t pids[8192];
    int n, i, hit = 0;
    n = proc_listpids(PROC_ALL_PIDS, 0, pids, (int) sizeof(pids));
    if (n <= 0) return 0;
    n = n / (int) sizeof(pid_t);
    for (i = 0; i < n && !hit; i++) {
        char name[256], base[280];
        if (pids[i] == 0) continue;
        if (proc_name(pids[i], name, sizeof(name)) > 0) {
            pk_lower_noext(name, base, sizeof(base));
            if (pk_name_match(base)) hit = 1;
        }
    }
    return hit;
}
static int pk_scan_modules(void) { return 0; }

#else
static int pk_scan_processes(void) { return 0; }
static int pk_scan_modules(void) { return 0; }
#endif

/* Deep native tamper scan: 1 = bad process, 2 = injected module, 3 = hardware
 * breakpoint, 0 = clean. Heavier than n5/n6, so the loader runs it less often. */
JNIEXPORT jint JNICALL Java_fabricpacker_N0_n7(JNIEnv *env, jclass cls) {
    (void) env; (void) cls;
    if (pk_scan_processes()) return 1;
    if (pk_scan_modules()) return 2;
#ifdef _WIN32
    if (pk_scan_debugregs()) return 3;
#endif
    return 0;
}
