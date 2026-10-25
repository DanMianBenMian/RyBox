/*
 * verify_sign — local, byte-exact validation of RySignCore against a REAL
 * signed Mach-O (the official Sileo signature).
 *
 * WHY THIS EXISTS
 * ---------------
 * The device build can only be tested by pushing an IPA to a real iPad and
 * waiting for a boot attempt — a slow, indirect loop. But the code-signature
 * format is a pure byte layout, so it can be verified RIGHT HERE on the
 * desktop: rebuild the CodeDirectory from the official Sileo's own inputs and
 * compare it byte for byte with the one Apple actually embedded.
 *
 * The three "whole blob" inputs (requirements / entitlements / DER
 * entitlements) are passed in ALREADY BUILT, i.e. including their 8-byte
 * magic+length header — because the special slots -2 / -5 / -7 hash exactly
 * those bytes. That keeps this harness focused on the CodeDirectory builder.
 *
 * SHA-1 / SHA-256 are implemented here in plain C so the harness has NO
 * external dependency at all (RySignCore itself takes the hash functions via
 * function pointers, so the device build can hand it CommonCrypto instead).
 *
 * Build (Git Bash):
 *   gcc -std=gnu99 -O1 -I <dir> -o verify_sign.exe verify_sign.c RySignCore.c
 * Run:
 *   verify_sign.exe <macho> <info.plist> <code-resources> \
 *                   <req-blob> <ent-blob> <der-blob> \
 *                   <bundle-id> <team> <is-execute> \
 *                   <exec-seg-limit> <exec-seg-flags> <out-dir>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "RySignCore.h"

/* -------------------------------------------------------------------------
 * SHA-1
 * ------------------------------------------------------------------------- */

typedef struct {
    uint32_t h[5];
    uint64_t len;
    unsigned char buf[64];
    size_t buf_len;
} Sha1Ctx;

static uint32_t rol32(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }

static void sha1_block(Sha1Ctx *c, const unsigned char *p) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
    for (int i = 16; i < 80; i++)
        w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    uint32_t a = c->h[0], b = c->h[1], d = c->h[2], e = c->h[3], f = c->h[4];
    for (int i = 0; i < 80; i++) {
        uint32_t k, t;
        if (i < 20)      { t = (b & d) | ((~b) & e);        k = 0x5A827999; }
        else if (i < 40) { t = b ^ d ^ e;                     k = 0x6ED9EBA1; }
        else if (i < 60) { t = (b & d) | (b & e) | (d & e);   k = 0x8F1BBCDC; }
        else             { t = b ^ d ^ e;                     k = 0xCA62C1D6; }
        uint32_t tmp = rol32(a, 5) + t + f + k + w[i];
        f = e; e = d; d = rol32(b, 30); b = a; a = tmp;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += d; c->h[3] += e; c->h[4] += f;
}

static void sha1_init(Sha1Ctx *c) {
    c->h[0] = 0x67452301; c->h[1] = 0xEFCDAB89; c->h[2] = 0x98BADCFE;
    c->h[3] = 0x10325476; c->h[4] = 0xC3D2E1F0;
    c->len = 0; c->buf_len = 0;
}

static void sha1_update(Sha1Ctx *c, const void *data, size_t len) {
    const unsigned char *p = (const unsigned char *)data;
    c->len += len;
    while (len) {
        size_t take = 64 - c->buf_len;
        if (take > len) take = len;
        memcpy(c->buf + c->buf_len, p, take);
        c->buf_len += take; p += take; len -= take;
        if (c->buf_len == 64) { sha1_block(c, c->buf); c->buf_len = 0; }
    }
}

static void sha1_final(Sha1Ctx *c, unsigned char out[20]) {
    uint64_t bits = c->len * 8;
    unsigned char pad = 0x80;
    sha1_update(c, &pad, 1);
    unsigned char zero = 0;
    while (c->buf_len != 56) sha1_update(c, &zero, 1);
    unsigned char lenb[8];
    for (int i = 0; i < 8; i++) lenb[i] = (unsigned char)(bits >> (56 - 8 * i));
    sha1_update(c, lenb, 8);
    for (int i = 0; i < 5; i++) {
        out[i * 4]     = (unsigned char)(c->h[i] >> 24);
        out[i * 4 + 1] = (unsigned char)(c->h[i] >> 16);
        out[i * 4 + 2] = (unsigned char)(c->h[i] >> 8);
        out[i * 4 + 3] = (unsigned char)(c->h[i]);
    }
}

/* -------------------------------------------------------------------------
 * SHA-256
 * ------------------------------------------------------------------------- */

typedef struct {
    uint32_t h[8];
    uint64_t len;
    unsigned char buf[64];
    size_t buf_len;
} Sha256Ctx;

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static uint32_t ror32(uint32_t v, int n) { return (v >> n) | (v << (32 - n)); }

static void sha256_block(Sha256Ctx *c, const unsigned char *p) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ror32(w[i - 15], 7) ^ ror32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ror32(w[i - 2], 17) ^ ror32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3];
    uint32_t e = c->h[4], f = c->h[5], g = c->h[6], h = c->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22);
        uint32_t mj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
    c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

static void sha256_init(Sha256Ctx *c) {
    static const uint32_t iv[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    memcpy(c->h, iv, sizeof(iv));
    c->len = 0; c->buf_len = 0;
}

static void sha256_update(Sha256Ctx *c, const void *data, size_t len) {
    const unsigned char *p = (const unsigned char *)data;
    c->len += len;
    while (len) {
        size_t take = 64 - c->buf_len;
        if (take > len) take = len;
        memcpy(c->buf + c->buf_len, p, take);
        c->buf_len += take; p += take; len -= take;
        if (c->buf_len == 64) { sha256_block(c, c->buf); c->buf_len = 0; }
    }
}

static void sha256_final(Sha256Ctx *c, unsigned char out[32]) {
    uint64_t bits = c->len * 8;
    unsigned char pad = 0x80;
    sha256_update(c, &pad, 1);
    unsigned char zero = 0;
    while (c->buf_len != 56) sha256_update(c, &zero, 1);
    unsigned char lenb[8];
    for (int i = 0; i < 8; i++) lenb[i] = (unsigned char)(bits >> (56 - 8 * i));
    sha256_update(c, lenb, 8);
    for (int i = 0; i < 8; i++) {
        out[i * 4]     = (unsigned char)(c->h[i] >> 24);
        out[i * 4 + 1] = (unsigned char)(c->h[i] >> 16);
        out[i * 4 + 2] = (unsigned char)(c->h[i] >> 8);
        out[i * 4 + 3] = (unsigned char)(c->h[i]);
    }
}

/* ---- the two back-ends RySignCore expects ------------------------------ */

static int sha1_fn(const void *data, size_t len, unsigned char *out) {
    Sha1Ctx c; sha1_init(&c); sha1_update(&c, data, len); sha1_final(&c, out);
    return 0;
}

static int sha256_fn(const void *data, size_t len, unsigned char *out) {
    Sha256Ctx c; sha256_init(&c); sha256_update(&c, data, len); sha256_final(&c, out);
    return 0;
}

/* ---- helpers ------------------------------------------------------------ */

static unsigned char *read_all(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) { *len = 0; return NULL; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); *len = 0; return NULL; }
    unsigned char *b = (unsigned char *)malloc(sz ? (size_t)sz : 1);
    size_t r = fread(b, 1, (size_t)sz, f);
    fclose(f);
    *len = r;
    return b;
}

static void write_all(const char *path, const void *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return;
    fwrite(data, 1, len, f);
    fclose(f);
}

/* Locate LC_CODE_SIGNATURE in a little-endian arm64 Mach-O and report the
 * code limit (dataoff) — the bytes the code slots cover. */
static long macho_code_limit(const unsigned char *m, size_t n, int *is_exec) {
    if (n < 32) return -1;
    uint32_t magic = (uint32_t)m[0] | ((uint32_t)m[1] << 8) |
                     ((uint32_t)m[2] << 16) | ((uint32_t)m[3] << 24);
    if (magic != 0xFEEDFACFu) return -1;
    uint32_t filetype = (uint32_t)m[12] | ((uint32_t)m[13] << 8) |
                        ((uint32_t)m[14] << 16) | ((uint32_t)m[15] << 24);
    if (is_exec) *is_exec = (filetype == 2 /* MH_EXECUTE */);
    uint32_t ncmds = (uint32_t)m[16] | ((uint32_t)m[17] << 8) |
                     ((uint32_t)m[18] << 16) | ((uint32_t)m[19] << 24);
    size_t off = 32;
    for (uint32_t i = 0; i < ncmds; i++) {
        if (off + 8 > n) break;
        uint32_t cmd = (uint32_t)m[off] | ((uint32_t)m[off+1] << 8) |
                       ((uint32_t)m[off+2] << 16) | ((uint32_t)m[off+3] << 24);
        if (cmd == 0x1D) {   /* LC_CODE_SIGNATURE */
            uint32_t dataoff = (uint32_t)m[off+8] | ((uint32_t)m[off+9] << 8) |
                               ((uint32_t)m[off+10] << 16) | ((uint32_t)m[off+11] << 24);
            return (long)dataoff;
        }
        uint32_t cmdsize = (uint32_t)m[off+4] | ((uint32_t)m[off+5] << 8) |
                           ((uint32_t)m[off+6] << 16) | ((uint32_t)m[off+7] << 24);
        if (cmdsize == 0) break;
        off += cmdsize;
    }
    return -1;
}

/* __TEXT segment vmsize == the exec segment limit zsign records. */
static long macho_text_vmsize(const unsigned char *m, size_t n) {
    uint32_t ncmds = (uint32_t)m[16] | ((uint32_t)m[17] << 8) |
                     ((uint32_t)m[18] << 16) | ((uint32_t)m[19] << 24);
    size_t off = 32;
    for (uint32_t i = 0; i < ncmds; i++) {
        if (off + 72 > n) break;
        uint32_t cmd = (uint32_t)m[off] | ((uint32_t)m[off+1] << 8) |
                       ((uint32_t)m[off+2] << 16) | ((uint32_t)m[off+3] << 24);
        if (cmd == 0x19) {   /* LC_SEGMENT_64 */
            char name[17];
            memcpy(name, m + off + 8, 16);
            name[16] = 0;
            if (strcmp(name, "__TEXT") == 0) {
                uint64_t vmsize = 0;
                const unsigned char *p = m + off + 32;
                for (int k = 0; k < 8; k++) vmsize |= (uint64_t)p[k] << (8 * k);
                return (long)vmsize;
            }
        }
        uint32_t cmdsize = (uint32_t)m[off+4] | ((uint32_t)m[off+5] << 8) |
                           ((uint32_t)m[off+6] << 16) | ((uint32_t)m[off+7] << 24);
        if (cmdsize == 0) break;
        off += cmdsize;
    }
    return -1;
}

int main(int argc, char **argv) {
    if (argc < 13) {
        fprintf(stderr,
            "usage: %s <macho> <info.plist> <code-resources> <req-blob>\n"
            "          <ent-blob> <der-blob> <bundle-id> <team> <is-execute>\n"
            "          <exec-seg-limit> <exec-seg-flags> <out-dir>\n", argv[0]);
        return 2;
    }
    const char *macho_path = argv[1];
    const char *info_path  = argv[2];
    const char *res_path   = argv[3];
    const char *req_path   = argv[4];
    const char *ent_path   = argv[5];
    const char *der_path   = argv[6];
    const char *bundle_id  = argv[7];
    const char *team       = argv[8];
    int         is_exec    = atoi(argv[9]);
    uint64_t    exec_limit = strtoull(argv[10], NULL, 10);
    uint64_t    exec_flags = strtoull(argv[11], NULL, 10);
    const char *out_dir    = argv[12];
    // execSegBase (__TEXT vmaddr) — 0 for a dylib, 0x100000000 for a PIE
    // executable. Optional so the old argument list still works.
    uint64_t    exec_base  = (argc > 13) ? strtoull(argv[13], NULL, 10) : 0;

    size_t mlen = 0, ilen = 0, rlen = 0, qlen = 0, elen = 0, dlen = 0;
    unsigned char *m    = read_all(macho_path, &mlen);
    unsigned char *info = read_all(info_path, &ilen);
    unsigned char *res  = read_all(res_path, &rlen);
    unsigned char *req  = read_all(req_path, &qlen);
    unsigned char *ent  = read_all(ent_path, &elen);
    unsigned char *der  = read_all(der_path, &dlen);
    if (!m || !info || !req) { fprintf(stderr, "cannot read inputs\n"); return 3; }

    int macho_is_exec = 0;
    long code_limit = macho_code_limit(m, mlen, &macho_is_exec);
    if (code_limit < 0) {
        code_limit = (long)((mlen % 16 == 0) ? mlen : mlen + 16 - (mlen % 16));
    }
    if (code_limit > (long)mlen) code_limit = (long)mlen;
    printf("macho: size=%u codeLimit=%ld isExecute=%d  __TEXTvmsize=%ld\n",
           (unsigned)mlen, code_limit, macho_is_exec, macho_text_vmsize(m, mlen));

    RySignHash hash = { sha1_fn, sha256_fn };

    RySignMeta meta;
    memset(&meta, 0, sizeof(meta));
    meta.bundle_id = bundle_id;
    meta.team_id = (team && team[0]) ? team : NULL;
    meta.info_plist = info;               meta.info_plist_len = ilen;
    if (res) { meta.code_resources = res; meta.code_resources_len = rlen; }
    if (ent) { meta.entitlements_blob = ent; meta.entitlements_blob_len = elen; }
    if (der) { meta.der_entitlements_blob = der; meta.der_entitlements_blob_len = dlen; }
    meta.requirements_blob = req;         meta.requirements_blob_len = qlen;

    RyBuf cd1, cd2;
    if (ry_build_codedirectory(0, m, (size_t)code_limit, &meta,
                                is_exec, 0, exec_base, exec_limit, exec_flags, &hash, &cd1) != 0) {
        fprintf(stderr, "cd1 failed\n"); return 5;
    }
    if (ry_build_codedirectory(1, m, (size_t)code_limit, &meta,
                                is_exec, 0, exec_base, exec_limit, exec_flags, &hash, &cd2) != 0) {
        fprintf(stderr, "cd2 failed\n"); return 5;
    }

    char path[1024];
    snprintf(path, sizeof(path), "%s/cd1.bin", out_dir);
    write_all(path, cd1.p, cd1.len);
    snprintf(path, sizeof(path), "%s/cd2.bin", out_dir);
    write_all(path, cd2.p, cd2.len);

    printf("cd1=%u cd2=%u\n", (unsigned)cd1.len, (unsigned)cd2.len);
    return 0;
}
