#ifndef aegis256_H
#define aegis256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The length of an AEGIS key, in bytes */
#define aegis256_KEYBYTES 32

/* The length of an AEGIS nonce, in bytes */
#define aegis256_NPUBBYTES 32

/* The minimum length of an AEGIS authentication tag, in bytes */
#define aegis256_ABYTES_MIN 16

/* The maximum length of an AEGIS authentication tag, in bytes */
#define aegis256_ABYTES_MAX 32

/*
 * When using AEGIS in incremental mode, this is the maximum number
 * of leftover ciphertext bytes that can be returned at finalization.
 */
#define aegis256_TAILBYTES_MAX 15

/* An AEGIS state, for incremental updates */
typedef struct aegis256_state {
    CRYPTO_ALIGN(16) uint8_t opaque[192];
} aegis256_state;

/* An AEGIS state, only for MAC updates */
typedef struct aegis256_mac_state {
    CRYPTO_ALIGN(16) uint8_t opaque[288];
} aegis256_mac_state;

/* The length of an AEGIS key, in bytes */
size_t aegis256_keybytes(void);

/* The length of an AEGIS nonce, in bytes */
size_t aegis256_npubbytes(void);

/* The minimum length of an AEGIS authentication tag, in bytes */
size_t aegis256_abytes_min(void);

/* The maximum length of an AEGIS authentication tag, in bytes */
size_t aegis256_abytes_max(void);

/*
 * When using AEGIS in incremental mode, this is the maximum number
 * of leftover ciphertext bytes that can be returned at finalization.
 */
size_t aegis256_tailbytes_max(void);

/*
 * Encrypt a message with AEGIS in one shot mode, returning the tag and the ciphertext separately.
 *
 * c: ciphertext output buffer
 * mac: authentication tag output buffer
 * maclen: length of the authentication tag to generate (16 or 32)
 * m: plaintext input buffer
 * mlen: length of the plaintext
 * ad: additional data input buffer
 * adlen: length of the additional data
 * npub: nonce input buffer (32 bytes)
 * k: key input buffer (32 bytes)
 */
int aegis256_encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m,
                              size_t mlen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                              const uint8_t *k);

/*
 * Decrypt a message with AEGIS in one shot mode, returning the tag and the ciphertext separately.
 *
 * m: plaintext output buffer
 * c: ciphertext input buffer
 * clen: length of the ciphertext
 * mac: authentication tag input buffer
 * maclen: length of the authentication tag (16 or 32)
 * ad: additional data input buffer
 * adlen: length of the additional data
 * npub: nonce input buffer (32 bytes)
 * k: key input buffer (32 bytes)
 *
 * Returns 0 if the ciphertext is authentic, -1 otherwise.
 */
int aegis256_decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
                              size_t maclen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                              const uint8_t *k) __attribute__((warn_unused_result));

/*
 * Encrypt a message with AEGIS in one shot mode, returning the tag and the ciphertext together.
 *
 * c: ciphertext output buffer
 * maclen: length of the authentication tag to generate (16 or 32)
 * m: plaintext input buffer
 * mlen: length of the plaintext
 * ad: additional data input buffer
 * adlen: length of the additional data
 * npub: nonce input buffer (32 bytes)
 * k: key input buffer (32 bytes)
 */
int aegis256_encrypt(uint8_t *c, size_t maclen, const uint8_t *m, size_t mlen, const uint8_t *ad,
                     size_t adlen, const uint8_t *npub, const uint8_t *k);

/*
 * Decrypt a message with AEGIS in one shot mode, returning the tag and the ciphertext together.
 *
 * m: plaintext output buffer
 * c: ciphertext input buffer
 * clen: length of the ciphertext
 * maclen: length of the authentication tag (16 or 32)
 * ad: additional data input buffer
 * adlen: length of the additional data
 * npub: nonce input buffer (32 bytes)
 * k: key input buffer (32 bytes)
 *
 * Returns 0 if the ciphertext is authentic, -1 otherwise.
 */
int aegis256_decrypt(uint8_t *m, const uint8_t *c, size_t clen, size_t maclen, const uint8_t *ad,
                     size_t adlen, const uint8_t *npub, const uint8_t *k)
    __attribute__((warn_unused_result));

/*
 * Initialize a state for incremental encryption or decryption.
 *
 * st_: state to initialize
 * ad: additional data input buffer
 * adlen: length of the additional data
 * npub: nonce input buffer (32 bytes)
 * k: key input buffer (32 bytes)
 */
void aegis256_state_init(aegis256_state *st_, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                         const uint8_t *k);

/*
 * Encrypt a message chunk.
 * The same function can be used regardless of whether the tag will be attached or not.
 *
 * st_: state to update
 * c: ciphertext output buffer
 * clen_max: length of the ciphertext chunk buffer (must be >= mlen)
 * written: number of ciphertext bytes actually written
 * m: plaintext input buffer
 * mlen: length of the plaintext
 *
 * Return 0 on success, -1 on failure.
 */
int aegis256_state_encrypt_update(aegis256_state *st_, uint8_t *c, size_t clen_max, size_t *written,
                                  const uint8_t *m, size_t mlen);

/*
 * Finalize the incremental encryption and generate the authentication tag.
 *
 * st_: state to finalize
 * c: output buffer for the final ciphertext chunk
 * clen_max: length of the ciphertext chunk buffer (must be >= remaining bytes)
 * written: number of ciphertext bytes actually written
 * mac: authentication tag output buffer
 * maclen: length of the authentication tag to generate (16 or 32)
 *
 * Return 0 on success, -1 on failure.
 */
int aegis256_state_encrypt_detached_final(aegis256_state *st_, uint8_t *c, size_t clen_max,
                                          size_t *written, uint8_t *mac, size_t maclen);

/*
 * Finalize the incremental encryption and attach the authentication tag
 * to the final ciphertext chunk.
 *
 * st_: state to finalize
 * c: output buffer for the final ciphertext chunk
 * clen_max: length of the ciphertext chunk buffer (must be >= remaining bytes+maclen)
 * written: number of ciphertext bytes actually written
 * maclen: length of the authentication tag to generate (16 or 32)
 *
 * Return 0 on success, -1 on failure.
 */
int aegis256_state_encrypt_final(aegis256_state *st_, uint8_t *c, size_t clen_max, size_t *written,
                                 size_t maclen);

/*
 * Decrypt a message chunk.
 *
 * The output should never be released to the caller until the tag has been verified.
 *
 * st_: state to update
 * m: plaintext output buffer
 * mlen_max: length of the plaintext chunk buffer (must be >= clen)
 * written: number of plaintext bytes actually written
 * c: ciphertext chunk input buffer
 * clen: length of the ciphertext chunk
 *
 * Return 0 on success, -1 on failure.
 */
int aegis256_state_decrypt_detached_update(aegis256_state *st_, uint8_t *m, size_t mlen_max,
                                           size_t *written, const uint8_t *c, size_t clen)
    __attribute__((warn_unused_result));

/*
 * Decrypt the final message chunk and verify the authentication tag.
 *
 * st_: state to finalize
 * m: plaintext output buffer
 * mlen_max: length of the plaintext chunk buffer (must be >= remaining bytes)
 * written: number of plaintext bytes actually written
 * mac: authentication tag input buffer
 * maclen: length of the authentication tag (16 or 32)
 *
 * Return 0 on success, -1 on failure.
 */
int aegis256_state_decrypt_detached_final(aegis256_state *st_, uint8_t *m, size_t mlen_max,
                                          size_t *written, const uint8_t *mac, size_t maclen)
    __attribute__((warn_unused_result));

/*
 * Return a deterministic pseudo-random byte sequence.
 *
 * out: output buffer
 * len: number of bytes to generate
 * npub: nonce input buffer (32 bytes) - Can be set to `NULL` if only one sequence has to be
 * generated from a given key.
 * k: key input buffer (32 bytes)
 */
void aegis256_stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k);

/*
 * Encrypt a message WITHOUT AUTHENTICATION, similar to AES-CTR.
 *
 * WARNING: this is an insecure mode of operation, provided for compatibility with specific
 * protocols that bring their own authentication scheme.
 *
 * c: ciphertext output buffer
 * m: plaintext input buffer
 * mlen: length of the plaintext
 * npub: nonce input buffer (32 bytes)
 * k: key input buffer (32 bytes)
 */
void aegis256_encrypt_unauthenticated(uint8_t *c, const uint8_t *m, size_t mlen,
                                      const uint8_t *npub, const uint8_t *k);

/*
 * Decrypt a message WITHOUT AUTHENTICATION, similar to AES-CTR.
 *
 * WARNING: this is an insecure mode of operation, provided for compatibility with specific
 * protocols that bring their own authentication scheme.
 *
 * m: plaintext output buffer
 * c: ciphertext input buffer
 * clen: length of the ciphertext
 * npub: nonce input buffer (32 bytes)
 * k: key input buffer (32 bytes)
 */
void aegis256_decrypt_unauthenticated(uint8_t *m, const uint8_t *c, size_t clen,
                                      const uint8_t *npub, const uint8_t *k);

/*
 * Initialize a state for generating a MAC.
 *
 * st_: state to initialize
 * k: key input buffer (32 bytes)
 *
 * - The same key MUST NOT be used both for MAC and encryption.
 * - If the key is secret, the MAC is secure against forgery.
 * - However, if the key is known, arbitrary inputs matching a tag can be efficiently computed.
 *
 * The recommended way to use the MAC mode is to generate a random key and keep it secret.
 *
 * After initialization, the state can be reused to generate multiple MACs by cloning it
 * with `aegis256_mac_state_clone()`. It is only safe to copy a state directly without using
 * the clone function if the state is guaranteed to be properly aligned.
 *
 * A state can also be reset for reuse without cloning with `aegis256_mac_reset()`.
 */
void aegis256_mac_init(aegis256_mac_state *st_, const uint8_t *k, const uint8_t *npub);

/*
 * Update the MAC state with input data.
 *
 * st_: state to update
 * m: input data
 * mlen: length of the input data
 *
 * This function can be called multiple times.
 *
 * Once the full input has been absorb, call either `_mac_final` or `_mac_verify`.
 */
int aegis256_mac_update(aegis256_mac_state *st_, const uint8_t *m, size_t mlen);

/*
 * Finalize the MAC and generate the authentication tag.
 *
 * st_: state to finalize
 * mac: authentication tag output buffer
 * maclen: length of the authentication tag to generate (16 or 32. 32 is recommended).
 */
int aegis256_mac_final(aegis256_mac_state *st_, uint8_t *mac, size_t maclen);

/*
 * Verify a MAC in constant time.
 *
 * st_: state to verify
 * mac: authentication tag to verify
 * maclen: length of the authentication tag (16 or 32)
 *
 * Returns 0 if the tag is authentic, -1 otherwise.
 */
int aegis256_mac_verify(aegis256_mac_state *st_, const uint8_t *mac, size_t maclen);

/*
 * Reset an AEGIS_MAC state.
 */
void aegis256_mac_reset(aegis256_mac_state *st_);

/*
 * Clone an AEGIS-MAC state.
 *
 * dst: destination state
 * src: source state
 *
 * This function MUST be used in order to clone states.
 */
void aegis256_mac_state_clone(aegis256_mac_state *dst, const aegis256_mac_state *src);

#ifdef __cplusplus
}
#endif

#endif
