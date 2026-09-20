/*
 * packcore native crypto core - part 4/4: AES-256-GCM decryption with
 * 128-bit tag verification (NIST SP 800-38D).
 * Included exactly once by packcore.c.
 */
#pragma once

static void gf_shift_right(uint8_t v[16]) {
    int i;
    for (i = 15; i >= 1; i--) v[i] = (uint8_t)((v[i] >> 1) | ((v[i-1] & 1) << 7));
    v[0] >>= 1;
}

/* y = y * H in GF(2^128), GCM bit order. */
static void gf_mult_h(const uint8_t H[16], uint8_t y[16]) {
    uint8_t z[16], v[16];
    int i, k;
    memcpy(v, H, 16);
    memset(z, 0, 16);
    for (i = 0; i < 128; i++) {
        int lsb;
        if (y[i >> 3] & (0x80 >> (i & 7))) for (k = 0; k < 16; k++) z[k] ^= v[k];
        lsb = v[15] & 1;
        gf_shift_right(v);
        if (lsb) v[0] ^= 0xE1;
    }
    memcpy(y, z, 16);
    secure_wipe(z, 16);
    secure_wipe(v, 16);
}

static void ghash_blocks(const uint8_t H[16], uint8_t y[16], const uint8_t *data, size_t len) {
    uint8_t block[16];
    int k;
    while (len >= 16) {
        for (k = 0; k < 16; k++) y[k] ^= data[k];
        gf_mult_h(H, y);
        data += 16;
        len -= 16;
    }
    if (len) {
        memset(block, 0, 16);
        memcpy(block, data, len);
        for (k = 0; k < 16; k++) y[k] ^= block[k];
        gf_mult_h(H, y);
        secure_wipe(block, 16);
    }
}

static void gcm_inc32(uint8_t cb[16]) {
    int i;
    for (i = 15; i >= 12; i--) {
        cb[i]++;
        if (cb[i]) break;
    }
}

/*
 * Decryption only: in = ciphertext || tag(16). out receives clen bytes.
 * Returns 0 on success, -1 when the tag does not verify or input is malformed.
 */
static int gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                       const uint8_t *aad, size_t alen,
                       const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen) {
    uint32_t rk[60];
    uint8_t H[16], j0[16], ek[16], y[16], tag[16], cb[16], lb[16];
    size_t clen, i, base;
    int diff = 0, k;
    if (inlen < TAG_LEN) return -1;
    clen = inlen - TAG_LEN;
    aes256_expand(key, rk);
    memset(H, 0, 16);
    aes256_ecb(rk, H, H);
    memcpy(j0, nonce, 12);
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    aes256_ecb(rk, j0, ek);
    memset(y, 0, 16);
    ghash_blocks(H, y, aad, alen);
    ghash_blocks(H, y, in, clen);
    put_be64(lb, (uint64_t) alen * 8);
    put_be64(lb + 8, (uint64_t) clen * 8);
    for (k = 0; k < 16; k++) y[k] ^= lb[k];
    gf_mult_h(H, y);
    for (i = 0; i < 16; i++) tag[i] = (uint8_t)(y[i] ^ ek[i]);
    for (i = 0; i < 16; i++) diff |= tag[i] ^ in[clen + i];
    secure_wipe(tag, 16);
    secure_wipe(y, 16);
    secure_wipe(ek, 16);
    secure_wipe(H, 16);
    secure_wipe(lb, 16);
    if (diff != 0) { secure_wipe(rk, sizeof(rk)); return -1; }
    memcpy(cb, j0, 16);
    for (base = 0; base + 16 <= clen; base += 16) {
        uint8_t st[16];
        gcm_inc32(cb);
        aes256_ecb(rk, cb, st);
        for (k = 0; k < 16; k++) out[base + k] = (uint8_t)(in[base + k] ^ st[k]);
        secure_wipe(st, 16);
    }
    if (base < clen) {
        uint8_t st[16];
        gcm_inc32(cb);
        aes256_ecb(rk, cb, st);
        for (k = 0; k < (int)(clen - base); k++) out[base + k] = (uint8_t)(in[base + k] ^ st[k]);
        secure_wipe(st, 16);
    }
    secure_wipe(cb, 16);
    secure_wipe(j0, 16);
    secure_wipe(rk, sizeof(rk));
    if (outlen) *outlen = clen;
    return 0;
}
