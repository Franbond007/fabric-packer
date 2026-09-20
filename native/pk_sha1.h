/*
 * packcore native crypto core - part 1/4: base includes, constants,
 * baked key-mask material, secure wiping and SHA-256 compression (FIPS 180-4).
 * Included exactly once by packcore.c.
 */
#pragma once
#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#else
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/types.h>
#ifdef __APPLE__
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <libproc.h>
#endif
#endif

#define KEY_LEN   32
#define SALT_LEN  32
#define NONCE_LEN 12
#define TAG_LEN   16
#define KEY_SLOTS 16
#define MAX_INFO  64

/*
 * Baked per-binary contribution to the key mask. A packed mod's AES key is
 * (Java-visible material) XOR (native mask), where the mask is
 * HKDF-SHA256(ikm, salt = per-build salt, info = per-build info).
 *
 * The IKM is not stored as a clean 32-byte constant: it is split into two
 * random-looking halves (ikm = PK_K0 XOR PK_K1) and only reassembled into a
 * short-lived local buffer inside hkdf_mask, so a plain array is never visible
 * in the binary's data section. Rotate both halves (and FabricPacker.BAKED_IKM,
 * which must equal PK_K0 XOR PK_K1) whenever the core is rebuilt for a release.
 */
static const uint8_t PK_K0[KEY_LEN] = {
    0xcb,0x8a,0xb5,0xac,0x4a,0x0f,0xf4,0x1c,0xe3,0x9b,0xd4,0xe0,0x61,0x94,0x2f,0x25,
    0xb3,0xf9,0x4e,0xb0,0xd4,0xe5,0xf0,0x64,0xf8,0x1e,0x42,0xcf,0x27,0xa6,0xf8,0xc6
};
static const uint8_t PK_K1[KEY_LEN] = {
    0xd3,0x10,0xd3,0x28,0x38,0x28,0xbc,0xb2,0x2d,0xe5,0x83,0xcd,0x77,0x6f,0x54,0x07,
    0xfb,0xb4,0x11,0xb8,0x1f,0xfc,0x3b,0xc0,0xf9,0x2a,0xc5,0xa4,0x0b,0x79,0x73,0x69
};

static void secure_wipe(void *p, size_t n) {
    if (p == NULL || n == 0) return;
    {
        volatile uint8_t *v = (volatile uint8_t *) p;
        while (n--) { *v++ = 0; }
    }
}

typedef struct {
    uint32_t h[8];
    uint64_t bits;
    uint8_t  buf[64];
    size_t   blen;
} sha256_ctx;

static const uint32_t SHA256_K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

static const uint32_t SHA256_IV[8] = {
    0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
    0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
};

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) | ((uint32_t) p[2] << 8) | (uint32_t) p[3];
}

static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t) v;
}

static void put_be64(uint8_t *p, uint64_t v) {
    int i;
    for (i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}

static uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_compress(sha256_ctx *c, const uint8_t *p) {
    uint32_t w[64];
    uint32_t a, b, cc, d, e, f, g, hh;
    int i;
    for (i = 0; i < 16; i++) w[i] = be32(p + 4 * i);
    for (i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr32(w[i-2], 17) ^ rotr32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3];
    e = c->h[4]; f = c->h[5]; g = c->h[6]; hh = c->h[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = hh + S1 + ch + SHA256_K[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + maj;
        hh = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
    c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += hh;
}
