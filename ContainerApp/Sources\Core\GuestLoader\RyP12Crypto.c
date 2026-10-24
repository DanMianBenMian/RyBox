// RyP12Crypto — see RyP12Crypto.h for why this layer exists.
#include "RyP12Crypto.h"

#include <CommonCrypto/CommonCrypto.h>
#include <string.h>
#include <stdlib.h>

int ry_pbkdf2(int prf,
              const uint8_t *pw, size_t pwLen,
              const uint8_t *salt, size_t saltLen,
              uint32_t rounds,
              uint8_t *out, size_t outLen)
{
    CCPseudoRandomAlgorithm alg = kCCPRFHmacAlgSHA1;
    switch (prf) {
        case 2:  alg = kCCPRFHmacAlgSHA256; break;
        case 3:  alg = kCCPRFHmacAlgSHA512; break;
        case 4:  alg = kCCPRFHmacAlgSHA224; break;
        case 5:  alg = kCCPRFHmacAlgSHA384; break;
        default: alg = kCCPRFHmacAlgSHA1;   break;
    }
    if (rounds == 0) { rounds = 1; }
    int rc = CCKeyDerivationPBKDF(kCCPBKDF2,
                                  (const char *)pw, pwLen,
                                  salt, saltLen,
                                  alg, rounds,
                                  out, outLen);
    return rc == kCCSuccess ? 0 : -1;
}

int ry_cbc_decrypt(int alg,
                   const uint8_t *key, size_t keyLen,
                   const uint8_t *iv,
                   const uint8_t *in, size_t inLen,
                   uint8_t *out, size_t outCap)
{
    if (inLen == 0) { return -1; }
    CCAlgorithm cc = (alg == 2) ? kCCAlgorithm3DES : kCCAlgorithmAES;
    size_t block = (alg == 2) ? 8 : 16;
    if ((inLen % block) != 0) { return -1; }      // CBC needs whole blocks
    if (outCap < inLen) { return -1; }

    size_t moved = 0;
    CCCryptorStatus st = CCCrypt(kCCDecrypt, cc, kCCOptionPKCS7Padding,
                                 key, keyLen, iv,
                                 in, inLen,
                                 out, outCap, &moved);
    return st == kCCSuccess ? (int)moved : -1;
}

// ---- RFC 7292 App. B.2: PKCS#12 key derivation -----------------------------
#define RY_P12_V_MAX   128
#define RY_P12_BUF_MAX 4096

int ry_p12_kdf_sha1(const uint8_t *pw, size_t pwLen,
                    const uint8_t *salt, size_t saltLen,
                    uint32_t rounds, uint8_t id,
                    uint8_t *out, size_t outLen, size_t blockSize)
{
    const size_t u = CC_SHA1_DIGEST_LENGTH;      // 20
    const size_t v = blockSize;                  // 8 for 3DES
    if (v == 0 || v > RY_P12_V_MAX) { return -1; }
    if (outLen == 0) { return 0; }
    if (rounds == 0) { rounds = 1; }

    // S and P, each zero-padded up to a multiple of v.
    size_t sPad = ((saltLen + v - 1) / v) * v; if (sPad == 0) { sPad = v; }
    size_t pPad = ((pwLen   + v - 1) / v) * v; if (pPad == 0) { pPad = v; }
    if (sPad > RY_P12_BUF_MAX || pPad > RY_P12_BUF_MAX) { return -1; }

    uint8_t *S = (uint8_t *)calloc(sPad, 1);
    uint8_t *P = (uint8_t *)calloc(pPad, 1);
    if (!S || !P) { free(S); free(P); return -1; }
    memcpy(S, salt, saltLen);
    memcpy(P, pw, pwLen);

    // I = S || P
    size_t iLen = sPad + pPad;
    uint8_t *I = (uint8_t *)malloc(iLen);
    if (!I) { free(S); free(P); return -1; }
    memcpy(I, S, sPad);
    memcpy(I + sPad, P, pPad);
    free(S); free(P);

    // Stretch I to c*v bytes by cycling through it.
    size_t c = (outLen + u - 1) / u;
    uint8_t *bigI = (uint8_t *)malloc(c * v);
    if (!bigI) { free(I); return -1; }
    for (size_t k = 0; k < c * v; k++) { bigI[k] = I[k % iLen]; }
    free(I);

    uint8_t D[RY_P12_V_MAX];
    memset(D, id, v);

    size_t produced = 0;
    uint8_t cur[RY_P12_V_MAX + CC_SHA1_DIGEST_LENGTH];
    uint8_t dig[CC_SHA1_DIGEST_LENGTH];
    size_t curLen = v + v;
    for (size_t j = 0; j < c; j++) {
        memcpy(cur, D, v);
        memcpy(cur + v, bigI + (j * v), v);
        curLen = v + v;
        for (uint32_t r = 0; r < rounds; r++) {
            CC_SHA1(cur, (CC_LONG)curLen, dig);
            memcpy(cur, dig, u);
            curLen = u;
        }
        size_t take = (outLen - produced < u) ? (outLen - produced) : u;
        memcpy(out + produced, cur, take);
        produced += take;
    }
    free(bigI);
    return (int)produced;
}
