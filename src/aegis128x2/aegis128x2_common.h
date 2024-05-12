#define RATE 64

static void
aegis128x2_init(const uint8_t *key, const uint8_t *nonce, aes_block_t *const state)
{
    static CRYPTO_ALIGN(AES_BLOCK_LENGTH) const uint8_t c0_[AES_BLOCK_LENGTH] = {
        0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37,
        0x59, 0x90, 0xe9, 0x79, 0x62, 0x00, 0x01, 0x01, 0x02, 0x03, 0x05,
        0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62,
    };
    static CRYPTO_ALIGN(AES_BLOCK_LENGTH) const uint8_t c1_[AES_BLOCK_LENGTH] = {
        0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31,
        0x42, 0x73, 0xb5, 0x28, 0xdd, 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2,
        0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd,
    };

    const aes_block_t c0 = AES_BLOCK_LOAD(c0_);
    const aes_block_t c1 = AES_BLOCK_LOAD(c1_);
    uint8_t           tmp[2 * 16];
    uint8_t           context_bytes[AES_BLOCK_LENGTH];
    aes_block_t       context;
    aes_block_t       k;
    aes_block_t       n;
    int               i;

    memcpy(tmp, key, 16);
    memcpy(tmp + 16, key, 16);
    k = AES_BLOCK_LOAD(tmp);

    memcpy(tmp, nonce, 16);
    memcpy(tmp + 16, nonce, 16);
    n = AES_BLOCK_LOAD(tmp);

    memset(context_bytes, 0, sizeof context_bytes);
    context_bytes[0 * 16]     = 0x00;
    context_bytes[0 * 16 + 1] = 0x01;
    context_bytes[1 * 16]     = 0x01;
    context_bytes[1 * 16 + 1] = 0x01;
    context                   = AES_BLOCK_LOAD(context_bytes);

    state[0] = AES_BLOCK_XOR(k, n);
    state[1] = c1;
    state[2] = c0;
    state[3] = c1;
    state[4] = AES_BLOCK_XOR(k, n);
    state[5] = AES_BLOCK_XOR(k, c0);
    state[6] = AES_BLOCK_XOR(k, c1);
    state[7] = AES_BLOCK_XOR(k, c0);
    for (i = 0; i < 10; i++) {
        state[3] = AES_BLOCK_XOR(state[3], context);
        state[7] = AES_BLOCK_XOR(state[7], context);
        aegis128x2_update(state, n, k);
    }
}

static void
aegis128x2_mac(uint8_t *mac, size_t maclen, size_t adlen, size_t mlen, aes_block_t *const state)
{
    uint8_t     mac_multi_0[AES_BLOCK_LENGTH];
    uint8_t     mac_multi_1[AES_BLOCK_LENGTH];
    aes_block_t tmp;
    int         i;

    tmp = AES_BLOCK_LOAD_64x2(((uint64_t) mlen) << 3, ((uint64_t) adlen) << 3);
    tmp = AES_BLOCK_XOR(tmp, state[2]);

    for (i = 0; i < 7; i++) {
        aegis128x2_update(state, tmp, tmp);
    }

    if (maclen == 16) {
        tmp = AES_BLOCK_XOR(state[6], AES_BLOCK_XOR(state[5], state[4]));
        tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_XOR(state[3], state[2]));
        tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_XOR(state[1], state[0]));
        AES_BLOCK_STORE(mac_multi_0, tmp);
        for (i = 0; i < 16; i++) {
            mac[i] = mac_multi_0[i] ^ mac_multi_0[1 * 16 + i];
        }
    } else if (maclen == 32) {
        tmp = AES_BLOCK_XOR(state[3], state[2]);
        tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_XOR(state[1], state[0]));
        AES_BLOCK_STORE(mac_multi_0, tmp);
        for (i = 0; i < 16; i++) {
            mac[i] = mac_multi_0[i] ^ mac_multi_0[1 * 16 + i];
        }

        tmp = AES_BLOCK_XOR(state[7], state[6]);
        tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_XOR(state[5], state[4]));
        AES_BLOCK_STORE(mac_multi_1, tmp);
        for (i = 0; i < 16; i++) {
            mac[i + 16] = mac_multi_1[i] ^ mac_multi_1[1 * 16 + i];
        }
    } else {
        memset(mac, 0, maclen);
    }
}

static inline void
aegis128x2_absorb(const uint8_t *const src, aes_block_t *const state)
{
    aes_block_t msg0, msg1;

    msg0 = AES_BLOCK_LOAD(src);
    msg1 = AES_BLOCK_LOAD(src + AES_BLOCK_LENGTH);
    aegis128x2_update(state, msg0, msg1);
}

static void
aegis128x2_enc(uint8_t *const dst, const uint8_t *const src, aes_block_t *const state)
{
    aes_block_t msg0, msg1;
    aes_block_t tmp0, tmp1;

    msg0 = AES_BLOCK_LOAD(src);
    msg1 = AES_BLOCK_LOAD(src + AES_BLOCK_LENGTH);
    tmp0 = AES_BLOCK_XOR(msg0, state[6]);
    tmp0 = AES_BLOCK_XOR(tmp0, state[1]);
    tmp1 = AES_BLOCK_XOR(msg1, state[5]);
    tmp1 = AES_BLOCK_XOR(tmp1, state[2]);
    tmp0 = AES_BLOCK_XOR(tmp0, AES_BLOCK_AND(state[2], state[3]));
    tmp1 = AES_BLOCK_XOR(tmp1, AES_BLOCK_AND(state[6], state[7]));
    AES_BLOCK_STORE(dst, tmp0);
    AES_BLOCK_STORE(dst + AES_BLOCK_LENGTH, tmp1);

    aegis128x2_update(state, msg0, msg1);
}

static void
aegis128x2_dec(uint8_t *const dst, const uint8_t *const src, aes_block_t *const state)
{
    aes_block_t msg0, msg1;

    msg0 = AES_BLOCK_LOAD(src);
    msg1 = AES_BLOCK_LOAD(src + AES_BLOCK_LENGTH);
    msg0 = AES_BLOCK_XOR(msg0, state[6]);
    msg0 = AES_BLOCK_XOR(msg0, state[1]);
    msg1 = AES_BLOCK_XOR(msg1, state[5]);
    msg1 = AES_BLOCK_XOR(msg1, state[2]);
    msg0 = AES_BLOCK_XOR(msg0, AES_BLOCK_AND(state[2], state[3]));
    msg1 = AES_BLOCK_XOR(msg1, AES_BLOCK_AND(state[6], state[7]));
    AES_BLOCK_STORE(dst, msg0);
    AES_BLOCK_STORE(dst + AES_BLOCK_LENGTH, msg1);

    aegis128x2_update(state, msg0, msg1);
}

static void
aegis128x2_declast(uint8_t *const dst, const uint8_t *const src, size_t len,
                   aes_block_t *const state)
{
    uint8_t     pad[RATE];
    aes_block_t msg0, msg1;

    memset(pad, 0, sizeof pad);
    memcpy(pad, src, len);

    msg0 = AES_BLOCK_LOAD(pad);
    msg1 = AES_BLOCK_LOAD(pad + AES_BLOCK_LENGTH);
    msg0 = AES_BLOCK_XOR(msg0, state[6]);
    msg0 = AES_BLOCK_XOR(msg0, state[1]);
    msg1 = AES_BLOCK_XOR(msg1, state[5]);
    msg1 = AES_BLOCK_XOR(msg1, state[2]);
    msg0 = AES_BLOCK_XOR(msg0, AES_BLOCK_AND(state[2], state[3]));
    msg1 = AES_BLOCK_XOR(msg1, AES_BLOCK_AND(state[6], state[7]));
    AES_BLOCK_STORE(pad, msg0);
    AES_BLOCK_STORE(pad + AES_BLOCK_LENGTH, msg1);

    memset(pad + len, 0, sizeof pad - len);
    memcpy(dst, pad, len);

    msg0 = AES_BLOCK_LOAD(pad);
    msg1 = AES_BLOCK_LOAD(pad + AES_BLOCK_LENGTH);

    aegis128x2_update(state, msg0, msg1);
}

static int
encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m, size_t mlen,
                 const uint8_t *ad, size_t adlen, const uint8_t *npub, const uint8_t *k)
{
    aes_block_t                state[8];
    CRYPTO_ALIGN(RATE) uint8_t src[RATE];
    CRYPTO_ALIGN(RATE) uint8_t dst[RATE];
    size_t                     i;

    aegis128x2_init(k, npub, state);

    for (i = 0; i + RATE <= adlen; i += RATE) {
        aegis128x2_absorb(ad + i, state);
    }
    if (adlen % RATE) {
        memset(src, 0, RATE);
        memcpy(src, ad + i, adlen % RATE);
        aegis128x2_absorb(src, state);
    }
#pragma unroll(2)
    for (i = 0; i + RATE <= mlen; i += RATE) {
        aegis128x2_enc(c + i, m + i, state);
    }
    if (mlen % RATE) {
        memset(src, 0, RATE);
        memcpy(src, m + i, mlen % RATE);
        aegis128x2_enc(dst, src, state);
        memcpy(c + i, dst, mlen % RATE);
    }

    aegis128x2_mac(mac, maclen, adlen, mlen, state);

    return 0;
}

static int
decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac, size_t maclen,
                 const uint8_t *ad, size_t adlen, const uint8_t *npub, const uint8_t *k)
{
    aes_block_t                state[8];
    CRYPTO_ALIGN(RATE) uint8_t src[RATE];
    CRYPTO_ALIGN(RATE) uint8_t dst[RATE];
    CRYPTO_ALIGN(16) uint8_t   computed_mac[32];
    const size_t               mlen = clen;
    size_t                     i;
    int                        ret;

    aegis128x2_init(k, npub, state);

    for (i = 0; i + RATE <= adlen; i += RATE) {
        aegis128x2_absorb(ad + i, state);
    }
    if (adlen % RATE) {
        memset(src, 0, RATE);
        memcpy(src, ad + i, adlen % RATE);
        aegis128x2_absorb(src, state);
    }
    if (m != NULL) {
        for (i = 0; i + RATE <= mlen; i += RATE) {
            aegis128x2_dec(m + i, c + i, state);
        }
    } else {
        for (i = 0; i + RATE <= mlen; i += RATE) {
            aegis128x2_dec(dst, c + i, state);
        }
    }
    if (mlen % RATE) {
        if (m != NULL) {
            aegis128x2_declast(m + i, c + i, mlen % RATE, state);
        } else {
            aegis128x2_declast(dst, c + i, mlen % RATE, state);
        }
    }

    COMPILER_ASSERT(sizeof computed_mac >= 32);
    aegis128x2_mac(computed_mac, maclen, adlen, mlen, state);
    ret = -1;
    if (maclen == 16) {
        ret = aegis_verify_16(computed_mac, mac);
    } else if (maclen == 32) {
        ret = aegis_verify_32(computed_mac, mac);
    }
    if (ret != 0 && m != NULL) {
        memset(m, 0, mlen);
    }
    return ret;
}

static void
stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k)
{
    aes_block_t                state[8];
    CRYPTO_ALIGN(RATE) uint8_t src[RATE];
    CRYPTO_ALIGN(RATE) uint8_t dst[RATE];
    size_t                     i;

    memset(src, 0, sizeof src);
    if (npub == NULL) {
        npub = src;
    }

    aegis128x2_init(k, npub, state);

    for (i = 0; i + RATE <= len; i += RATE) {
        aegis128x2_enc(out + i, src, state);
    }
    if (len % RATE) {
        aegis128x2_enc(dst, src, state);
        memcpy(out + i, dst, len % RATE);
    }
}

static void
encrypt_unauthenticated(uint8_t *c, const uint8_t *m, size_t mlen, const uint8_t *npub,
                        const uint8_t *k)
{
    aes_block_t                state[8];
    CRYPTO_ALIGN(RATE) uint8_t src[RATE];
    CRYPTO_ALIGN(RATE) uint8_t dst[RATE];
    size_t                     i;

    aegis128x2_init(k, npub, state);

    for (i = 0; i + RATE <= mlen; i += RATE) {
        aegis128x2_enc(c + i, m + i, state);
    }
    if (mlen % RATE) {
        memset(src, 0, RATE);
        memcpy(src, m + i, mlen % RATE);
        aegis128x2_enc(dst, src, state);
        memcpy(c + i, dst, mlen % RATE);
    }
}

static void
decrypt_unauthenticated(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *npub,
                        const uint8_t *k)
{
    aes_block_t  state[8];
    const size_t mlen = clen;
    size_t       i;

    aegis128x2_init(k, npub, state);

    for (i = 0; i + RATE <= mlen; i += RATE) {
        aegis128x2_dec(m + i, c + i, state);
    }
    if (mlen % RATE) {
        aegis128x2_declast(m + i, c + i, mlen % RATE, state);
    }
}

typedef struct _aegis128x2_state {
    aes_block_t state[8];
    uint8_t     buf[RATE];
    uint64_t    adlen;
    uint64_t    mlen;
    size_t      pos;
} _aegis128x2_state;

static void
state_init(aegis128x2_state *st_, const uint8_t *ad, size_t adlen, const uint8_t *npub,
           const uint8_t *k)
{
    _aegis128x2_state *const st =
        (_aegis128x2_state *) ((((uintptr_t) &st_->opaque) + (RATE - 1)) & ~(uintptr_t) (RATE - 1));
    size_t i;

    COMPILER_ASSERT((sizeof *st) + RATE <= sizeof *st_);
    st->mlen = 0;
    st->pos  = 0;

    aegis128x2_init(k, npub, st->state);
    for (i = 0; i + RATE <= adlen; i += RATE) {
        aegis128x2_absorb(ad + i, st->state);
    }
    if (adlen % RATE) {
        memset(st->buf, 0, RATE);
        memcpy(st->buf, ad + i, adlen % RATE);
        aegis128x2_absorb(st->buf, st->state);
    }
    st->adlen = adlen;
}

static int
state_encrypt_update(aegis128x2_state *st_, uint8_t *c, size_t clen_max, size_t *written,
                     const uint8_t *m, size_t mlen)
{
    _aegis128x2_state *const st =
        (_aegis128x2_state *) ((((uintptr_t) &st_->opaque) + (RATE - 1)) & ~(uintptr_t) (RATE - 1));
    size_t i = 0;
    size_t left;

    *written = 0;
    st->mlen += mlen;
    if (st->pos != 0) {
        const size_t available = (sizeof st->buf) - st->pos;
        const size_t n         = mlen < available ? mlen : available;

        if (n != 0) {
            memcpy(st->buf + st->pos, m + i, n);
            m += n;
            mlen -= n;
            st->pos += n;
        }
        if (st->pos == sizeof st->buf) {
            if (clen_max < RATE) {
                errno = ERANGE;
                return -1;
            }
            clen_max -= RATE;
            aegis128x2_enc(c, st->buf, st->state);
            *written += RATE;
            c += RATE;
            st->pos = 0;
        } else {
            return 0;
        }
    }
    if (clen_max < (mlen & ~(size_t) (RATE - 1))) {
        errno = ERANGE;
        return -1;
    }
    for (i = 0; i + RATE <= mlen; i += RATE) {
        aegis128x2_enc(c + i, m + i, st->state);
    }
    *written += i;
    left = mlen % RATE;
    if (left != 0) {
        memcpy(st->buf, m + i, left);
        st->pos = left;
    }
    return 0;
}

static int
state_encrypt_detached_final(aegis128x2_state *st_, uint8_t *c, size_t clen_max, size_t *written,
                             uint8_t *mac, size_t maclen)
{
    _aegis128x2_state *const st =
        (_aegis128x2_state *) ((((uintptr_t) &st_->opaque) + (RATE - 1)) & ~(uintptr_t) (RATE - 1));
    CRYPTO_ALIGN(RATE) uint8_t src[RATE];
    CRYPTO_ALIGN(RATE) uint8_t dst[RATE];

    *written = 0;
    if (clen_max < st->pos) {
        errno = ERANGE;
        return -1;
    }
    if (st->pos != 0) {
        memset(src, 0, sizeof src);
        memcpy(src, st->buf, st->pos);
        aegis128x2_enc(dst, src, st->state);
        memcpy(c, dst, st->pos);
    }
    aegis128x2_mac(mac, maclen, st->adlen, st->mlen, st->state);

    *written = st->pos;

    return 0;
}

static int
state_encrypt_final(aegis128x2_state *st_, uint8_t *c, size_t clen_max, size_t *written,
                    size_t maclen)
{
    _aegis128x2_state *const st =
        (_aegis128x2_state *) ((((uintptr_t) &st_->opaque) + (RATE - 1)) & ~(uintptr_t) (RATE - 1));
    CRYPTO_ALIGN(RATE) uint8_t src[RATE];
    CRYPTO_ALIGN(RATE) uint8_t dst[RATE];

    *written = 0;
    if (clen_max < st->pos + maclen) {
        errno = ERANGE;
        return -1;
    }
    if (st->pos != 0) {
        memset(src, 0, sizeof src);
        memcpy(src, st->buf, st->pos);
        aegis128x2_enc(dst, src, st->state);
        memcpy(c, dst, st->pos);
    }
    aegis128x2_mac(c + st->pos, maclen, st->adlen, st->mlen, st->state);

    *written = st->pos + maclen;

    return 0;
}

static int
state_decrypt_detached_update(aegis128x2_state *st_, uint8_t *m, size_t mlen_max, size_t *written,
                              const uint8_t *c, size_t clen)
{
    _aegis128x2_state *const st =
        (_aegis128x2_state *) ((((uintptr_t) &st_->opaque) + (RATE - 1)) & ~(uintptr_t) (RATE - 1));
    CRYPTO_ALIGN(RATE) uint8_t dst[RATE];
    size_t                     i = 0;
    size_t                     left;

    *written = 0;
    st->mlen += clen;

    if (st->pos != 0) {
        const size_t available = (sizeof st->buf) - st->pos;
        const size_t n         = clen < available ? clen : available;

        if (n != 0) {
            memcpy(st->buf + st->pos, c, n);
            c += n;
            clen -= n;
            st->pos += n;
        }
        if (st->pos < (sizeof st->buf)) {
            return 0;
        }
        st->pos = 0;
        if (m != NULL) {
            if (mlen_max < RATE) {
                errno = ERANGE;
                return -1;
            }
            mlen_max -= RATE;
            aegis128x2_dec(m, st->buf, st->state);
            m += RATE;
        } else {
            aegis128x2_dec(dst, st->buf, st->state);
        }
        *written += RATE;
    }

    if (m != NULL) {
        if (mlen_max < (clen % RATE)) {
            errno = ERANGE;
            return -1;
        }
        for (i = 0; i + RATE <= clen; i += RATE) {
            aegis128x2_dec(m + i, c + i, st->state);
        }
    } else {
        for (i = 0; i + RATE <= clen; i += RATE) {
            aegis128x2_dec(dst, c + i, st->state);
        }
    }
    *written += i;
    left = clen % RATE;
    if (left) {
        memcpy(st->buf, c + i, left);
        st->pos = left;
    }
    return 0;
}

static int
state_decrypt_detached_final(aegis128x2_state *st_, uint8_t *m, size_t mlen_max, size_t *written,
                             const uint8_t *mac, size_t maclen)
{
    CRYPTO_ALIGN(16) uint8_t   computed_mac[32];
    CRYPTO_ALIGN(RATE) uint8_t dst[RATE];
    _aegis128x2_state *const   st =
        (_aegis128x2_state *) ((((uintptr_t) &st_->opaque) + (RATE - 1)) & ~(uintptr_t) (RATE - 1));
    int ret;

    *written = 0;
    if (st->pos != 0) {
        if (m != NULL) {
            if (mlen_max < st->pos) {
                errno = ERANGE;
                return -1;
            }
            aegis128x2_declast(m, st->buf, st->pos, st->state);
        } else {
            aegis128x2_declast(dst, st->buf, st->pos, st->state);
        }
    }
    aegis128x2_mac(computed_mac, maclen, st->adlen, st->mlen, st->state);
    ret = -1;
    if (maclen == 16) {
        ret = aegis_verify_16(computed_mac, mac);
    } else if (maclen == 32) {
        ret = aegis_verify_32(computed_mac, mac);
    }
    if (ret == 0) {
        *written = st->pos;
    } else {
        memset(m, 0, st->pos);
    }
    return ret;
}

static int
state_mac_update(aegis128x2_state *st_, const uint8_t *ad, size_t adlen)
{
    _aegis128x2_state *const st =
        (_aegis128x2_state *) ((((uintptr_t) &st_->opaque) + (RATE - 1)) & ~(uintptr_t) (RATE - 1));
    size_t i;
    size_t left;

    left = st->adlen % RATE;
    st->adlen += adlen;
    if (left != 0) {
        if (left + adlen < RATE) {
            memcpy(st->buf + left, ad, adlen);
            return 0;
        }
        memcpy(st->buf + left, ad, RATE - left);
        aegis128x2_absorb(st->buf, st->state);
        ad += RATE - left;
        adlen -= RATE - left;
    }
    for (i = 0; i + RATE * 2 <= adlen; i += RATE * 2) {
        aes_block_t msg0, msg1, msg2, msg3;

        msg0 = AES_BLOCK_LOAD(ad + i + AES_BLOCK_LENGTH * 0);
        msg1 = AES_BLOCK_LOAD(ad + i + AES_BLOCK_LENGTH * 1);
        msg2 = AES_BLOCK_LOAD(ad + i + AES_BLOCK_LENGTH * 2);
        msg3 = AES_BLOCK_LOAD(ad + i + AES_BLOCK_LENGTH * 3);
        COMPILER_ASSERT(AES_BLOCK_LENGTH * 4 == RATE * 2);

        aegis128x2_update(st->state, msg0, msg1);
        aegis128x2_update(st->state, msg2, msg3);
    }
    for (; i + RATE <= adlen; i += RATE) {
        aegis128x2_absorb(ad + i, st->state);
    }
    if (i < adlen) {
        memset(st->buf, 0, RATE);
        memcpy(st->buf, ad + i, adlen - i);
    }
    return 0;
}

static int
state_mac_final(aegis128x2_state *st_, uint8_t *mac, size_t maclen)
{
    _aegis128x2_state *const st =
        (_aegis128x2_state *) ((((uintptr_t) &st_->opaque) + (RATE - 1)) & ~(uintptr_t) (RATE - 1));
    size_t left;

    left = st->adlen % RATE;
    if (left != 0) {
        memset(st->buf + left, 0, RATE - left);
        aegis128x2_absorb(st->buf, st->state);
    }
    aegis128x2_mac(mac, maclen, st->adlen, 0, st->state);

    return 0;
}

static void
state_clone(aegis128x2_state *dst, const aegis128x2_state *src)
{
    _aegis128x2_state *const dst_ =
        (_aegis128x2_state *) ((((uintptr_t) &dst->opaque) + (RATE - 1)) & ~(uintptr_t) (RATE - 1));
    const _aegis128x2_state *const src_ =
        (const _aegis128x2_state *) ((((uintptr_t) &src->opaque) + (RATE - 1)) &
                                     ~(uintptr_t) (RATE - 1));
    *dst_ = *src_;
}