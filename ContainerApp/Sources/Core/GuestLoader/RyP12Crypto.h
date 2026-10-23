// RyP12Crypto — symmetric/PBKDF primitives for the in-app PKCS#12 fallback.
//
// Why this exists: SecPKCS12Import cannot read a p12 that OpenSSL 3.x wrote
// (PBES2 + AES-256-CBC + PBKDF2-HMAC-SHA256). Every "my distribution cert is
// not recognised" report we got traces back to that. We therefore parse the
// PKCS#12 ourselves (Swift side, RyP12.swift) and decrypt here.
//
// Kept in C on purpose: `#include <CommonCrypto/CommonCrypto.h>` always resolves
// for a C translation unit, whereas `import CommonCrypto` from Swift depends on
// the SDK shipping a module map — a build risk we do not need.
#ifndef RY_P12_CRYPTO_H
#define RY_P12_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

// PBKDF2. prf: 1=SHA1, 2=SHA256, 3=SHA512, 4=SHA224, 5=SHA384.
// Returns 0 on success, -1 otherwise.
int ry_pbkdf2(int prf,
              const uint8_t *pw, size_t pwLen,
              const uint8_t *salt, size_t saltLen,
              uint32_t rounds,
              uint8_t *out, size_t outLen);

// CBC decrypt with PKCS#7 padding. alg: 1=AES, 2=3DES.
// Returns the plaintext length, or -1 on failure.
int ry_cbc_decrypt(int alg,
                   const uint8_t *key, size_t keyLen,
                   const uint8_t *iv,
                   const uint8_t *in, size_t inLen,
                   uint8_t *out, size_t outCap);

// RFC 7292 Appendix B PKCS#12 key derivation (SHA-1 based).
// `pw` must already be the BMPString form (UTF-16BE + 2 NUL bytes).
// id: 1 = key material, 2 = IV. blockSize: 8 for 3DES.
// Returns the number of bytes written, or -1 on failure.
int ry_p12_kdf_sha1(const uint8_t *pw, size_t pwLen,
                    const uint8_t *salt, size_t saltLen,
                    uint32_t rounds, uint8_t id,
                    uint8_t *out, size_t outLen, size_t blockSize);

#endif /* RY_P12_CRYPTO_H */
