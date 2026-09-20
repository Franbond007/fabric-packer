/*
 * packcore native crypto core - part 2/4: SHA-256 streaming API,
 * HMAC-SHA256 (RFC 2104) and the per-build key-mask HKDF (RFC 5869).
 * Included exactly once by packcore.c after pk_sha1.h.
 */
#pragma once

static void sha256_init(sha256_ctx *c) {
    int i;
    for (i = 0; i < 8; i++) c->h[i] = SHA256_IV[i];
    c->bits = 0;
    c->blen = 0;
}

static void sha256_update(sha256_ctx *c, const uint8_t *p, size_t n) {
    c->bits += (uint64_t) n * 8;
    while (n > 0) {
        size_t take = 64 - c->blen;
        if (take > n) take = n;
        memcpy(c->buf + c->blen, p, take);
        c->blen += take;
        p += take;
        n -= take;
        if (c->blen == 64) { sha256_compress(c, c->buf); c->blen = 0; }
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32]) {
    uint8_t pad[72];
    size_t padlen = 0;
    uint64_t bits = c->bits;
    int i;
    pad[padlen++] = 0x80;
    while ((c->blen + padlen) % 64 != 56) pad[padlen++] = 0x00;
    put_be64(pad + padlen, bits);
    padlen += 8;
    sha256_update(c, pad, padlen);
    for (i = 0; i < 8; i++) put_be32(out + 4 * i, c->h[i]);
    secure_wipe(c, sizeof(*c));
}

static void sha256(const uint8_t *p, size_t n, uint8_t out[32]) {
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, p, n);
    sha256_final(&c, out);
}

static void hmac_sha256_2(const uint8_t *key, size_t klen,
                          const uint8_t *d1, size_t n1,
                          const uint8_t *d2, size_t n2, uint8_t out[32]) {
    uint8_t k0[64], ipad[64], opad[64], inner[32];
    sha256_ctx c;
    size_t i;
    memset(k0, 0, sizeof(k0));
    if (klen > 64) sha256(key, klen, k0);
    else memcpy(k0, key, klen);
    for (i = 0; i < 64; i++) {
        ipad[i] = (uint8_t)(k0[i] ^ 0x36);
        opad[i] = (uint8_t)(k0[i] ^ 0x5c);
    }
    sha256_init(&c);
    sha256_update(&c, ipad, 64);
    if (n1) sha256_update(&c, d1, n1);
    if (n2) sha256_update(&c, d2, n2);
    sha256_final(&c, inner);
    sha256_init(&c);
    sha256_update(&c, opad, 64);
    sha256_update(&c, inner, 32);
    sha256_final(&c, out);
    secure_wipe(k0, sizeof(k0));
    secure_wipe(ipad, sizeof(ipad));
    secure_wipe(opad, sizeof(opad));
    secure_wipe(inner, sizeof(inner));
}

/* mask = HKDF-SHA256(ikm = PK_K0 ^ PK_K1, salt = per-build salt, info = per-build info) */
static void hkdf_mask(const uint8_t salt[SALT_LEN], const uint8_t *info, size_t ilen,
                      uint8_t out[KEY_LEN]) {
    uint8_t prk[32];
    uint8_t ikm[KEY_LEN];
    uint8_t counter = 0x01;
    int i;
    for (i = 0; i < KEY_LEN; i++) ikm[i] = (uint8_t) (PK_K0[i] ^ PK_K1[i]);
    hmac_sha256_2(salt, SALT_LEN, ikm, KEY_LEN, NULL, 0, prk);
    secure_wipe(ikm, sizeof(ikm));
    hmac_sha256_2(prk, 32, info, ilen, &counter, 1, out);
    secure_wipe(prk, sizeof(prk));
}
