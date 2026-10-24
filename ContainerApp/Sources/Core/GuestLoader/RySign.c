// RySign — on-device Mach-O code signer for RyBox guest apps.
//
// Re-signs a guest bundle (main executable + embedded dylibs) with the user's
// p12 identity and provisioning profile so the guest passes AMFI when dlopen'd
// inside the (non-jailbroken) RyBox process.
//
// Uses ONLY Security + CommonCrypto + libSystem (no OpenSSL, no third-party
// dependency) so it cross-compiles for iOS with a plain clang invocation.
//
// ---------------------------------------------------------------------------
// THE MODEL (measured, not guessed — validated byte-for-byte against the
// official Sileo signature, see ContainerApp/tools/golden_check.py)
// ---------------------------------------------------------------------------
//
//   * The signature lives in a SuperBlob inside `LC_CODE_SIGNATURE`.
//   * The CodeDirectory (CS_CodeDirectory, v0x20400) has an 88-byte header,
//     special slots BELOW hashOffset, code slots ABOVE it, and hashes only the
//     REAL remaining bytes of the last page.
//   * The new SuperBlob is written AT the existing `LC_CODE_SIGNATURE.dataoff`
//     (zsign's `ZArchO::Sign` → `memcpy(m_pBase + m_uCodeLength, …)`): the file
//     body NEVER moves, so no load-command offset needs repairing. Growing only
//     extends the file tail and bumps `__LINKEDIT`.
//   * The CMS is DETACHED (Apple codesign / zsign parity) with the two private
//     signed attributes 1.2.840.113635.100.9.1 (cdhashes plist) and
//     1.2.840.113635.100.9.2 (CDHashes2). An in-place (non-adhoc) signature is
//     what AMFI requires on a non-jailbroken device.
//
// The platform-independent byte layout lives in `RySignCore.c`; this file is
// the iOS glue: file IO, DER/CMS assembly, and the zsign-style write path.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdbool.h>
#include <dirent.h>

#include <CommonCrypto/CommonDigest.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/arch.h>
#include <libkern/OSByteOrder.h>

#include "RySignCore.h"

#ifndef MH_DYLIB
#define MH_DYLIB 0x6
#endif

// ---- CodeDirectory identifier override (LiveContainer parity) -------------
// ZSign is driven with `bundleId: NSBundle.mainBundle.bundleIdentifier` — the
// HOST app's identifier, because the guest is signed with the host's cert and
// profile. Swift sets this; NULL keeps the guest's own CFBundleIdentifier.
static char *g_ident_override = NULL;

/// The sub-code of the LAST failure inside `sign_macho_file_at`, exposed so the
/// Swift layer can tell the user WHERE signing died (the outer exit code 6
/// covers a dozen different causes). Read via `rysign_last_subcode()`.
static int g_sign_subcode = 0;
int rysign_last_subcode(void) { return g_sign_subcode; }

/// The guest's Info.plist FILE BYTES (special slot -1). Swift can hand them
/// over via `rysign_set_info_plist`; if it does not, the signer reads them from
/// disk. (The in-C parser that used to `strstr` for `<string` failed on every
/// binary plist — that is what produced rc=6.)
static unsigned char *g_info_plist = NULL;
static size_t g_info_plist_len = 0;
static char g_exe_name[1024] = {0};

/// The leaf certificate's subject CN, for the designated requirement.
static char g_subject_cn[256] = {0};

// ---- Explicit trust-chain certificates (set by Swift) --------------------
unsigned char **g_extra_certs = NULL;
size_t *g_extra_certs_lens = NULL;
int g_extra_certs_n = 0;

// ---- Provisioning profile bytes (embedded only) ---------------------------
static unsigned char *g_prov = NULL;
static size_t g_prov_len = 0;

// ---------------------------------------------------------------------------
// Public setters (Swift calls these before a signing run)
// ---------------------------------------------------------------------------

void rysign_set_code_identity(const char *ident) {
    if (g_ident_override) { free(g_ident_override); g_ident_override = NULL; }
    if (ident && ident[0]) {
        size_t n = strlen(ident) + 1;
        char *copy = (char *)malloc(n);
        if (copy) { memcpy(copy, ident, n); g_ident_override = copy; }
    }
}

void rysign_set_extra_certs(unsigned char **c, size_t *l, int n) {
    if (g_extra_certs) {
        for (int i = 0; i < g_extra_certs_n; i++) free(g_extra_certs[i]);
        free(g_extra_certs);
    }
    if (g_extra_certs_lens) free(g_extra_certs_lens);
    g_extra_certs = c;
    g_extra_certs_lens = l;
    g_extra_certs_n = n;
}

void rysign_set_info_plist(const char *exeName,
                           const unsigned char *plist, size_t len) {
    if (g_info_plist) { free(g_info_plist); g_info_plist = NULL; }
    g_info_plist_len = 0;
    if (plist && len) {
        g_info_plist = (unsigned char *)malloc(len);
        if (g_info_plist) { memcpy(g_info_plist, plist, len); g_info_plist_len = len; }
    }
    g_exe_name[0] = 0;
    if (exeName && exeName[0]) {
        strncpy(g_exe_name, exeName, sizeof(g_exe_name) - 1);
        g_exe_name[sizeof(g_exe_name) - 1] = 0;
    }
}

// ---------------------------------------------------------------------------
// Hash back-ends for RySignCore (CommonCrypto)
// ---------------------------------------------------------------------------

static int ry_sha1(const void *data, size_t len, unsigned char *out) {
    CC_SHA1(data, (CC_LONG)len, out);
    return 0;
}
static int ry_sha256(const void *data, size_t len, unsigned char *out) {
    CC_SHA256(data, (CC_LONG)len, out);
    return 0;
}
static const RySignHash g_hash = { ry_sha1, ry_sha256 };

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

static unsigned char *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return NULL; }
    unsigned char *buf = (unsigned char *)malloc(sz ? (size_t)sz : 1);
    size_t r = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    *len = r;
    return buf;
}
static int write_file(const char *path, const unsigned char *d, size_t n) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t w = fwrite(d, 1, n, f);
    fclose(f);
    return (w == n) ? 0 : -1;
}
static size_t rnd4(size_t v) { return (v + 3) & ~((size_t)3); }

// ---------------------------------------------------------------------------
// DER builders — used to build the CMS SignedData
// ---------------------------------------------------------------------------

typedef struct { unsigned char *p; size_t len; size_t cap; } Buf;

static void buf_init(Buf *b) { b->p = (unsigned char *)malloc(64); b->len = 0; b->cap = b->p ? 64 : 0; }
static void buf_free(Buf *b) { if (b->p) free(b->p); b->p = NULL; b->len = 0; b->cap = 0; }
static void buf_reserve(Buf *b, size_t n) {
    if (b->p && b->len + n <= b->cap) return;
    size_t nc = b->cap ? b->cap : 64;
    while (b->len + n > nc) nc *= 2;
    unsigned char *np = (unsigned char *)realloc(b->p, nc);
    if (!np) return;
    b->p = np; b->cap = nc;
}
static void buf_put(Buf *b, const void *d, size_t n) {
    if (!b->p) buf_init(b);
    buf_reserve(b, n);
    if (!b->p) return;
    memcpy(b->p + b->len, d, n);
    b->len += n;
}
static void buf_u8(Buf *b, unsigned char v) { buf_put(b, &v, 1); }
static void der_len(Buf *b, size_t n) {
    if (n < 0x80) { buf_u8(b, (unsigned char)n); }
    else if (n < 0x100) { buf_u8(b, 0x81); buf_u8(b, (unsigned char)n); }
    else if (n < 0x10000) { buf_u8(b, 0x82); buf_u8(b, (unsigned char)(n >> 8)); buf_u8(b, (unsigned char)(n & 0xff)); }
    else { buf_u8(b, 0x83); buf_u8(b, (unsigned char)(n >> 16)); buf_u8(b, (unsigned char)(n >> 8)); buf_u8(b, (unsigned char)(n & 0xff)); }
}
static void der_wrap(Buf *out, unsigned char tag, const Buf *c) {
    buf_u8(out, tag); der_len(out, c->len); buf_put(out, c->p, c->len);
}
#define der_seq(out, c)  der_wrap(out, 0x30, c)
#define der_set(out, c)  der_wrap(out, 0x31, c)
#define der_octet(out, c) der_wrap(out, 0x04, c)
static void der_oid(Buf *b, const unsigned char *d, size_t n) {
    Buf t; buf_init(&t); buf_put(&t, d, n); der_wrap(b, 0x06, &t); buf_free(&t);
}
static void der_int(Buf *b, const unsigned char *d, size_t n) {
    while (n > 1 && d[0] == 0) { d++; n--; }
    Buf t; buf_init(&t);
    if (n && (d[0] & 0x80)) { unsigned char z = 0; buf_put(&t, &z, 1); }
    buf_put(&t, d, n);
    der_wrap(b, 0x02, &t);
    buf_free(&t);
}
// [0] IMPLICIT — used for CMS eContent, signedAttrs and the cert set.
static void der_ctx0(Buf *b, const Buf *c) {
    buf_u8(b, 0xA0); der_len(b, c->len); buf_put(b, c->p, c->len);
}

// ---- OIDs ------------------------------------------------------------------
static const unsigned char OID_SHA256[]    = {0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01};
static const unsigned char OID_RSA[]       = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01};
static const unsigned char OID_DATA[]      = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x01};
static const unsigned char OID_SIGNED[]    = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x02};
static const unsigned char OID_SHA256RSA[] = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0B};
static const unsigned char OID_CTYPE[]     = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x03};
static const unsigned char OID_MSGDIGEST[] = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x04};
static const unsigned char OID_APPLE_CDHASHES[]  = {0x2A,0x86,0x48,0x86,0xF7,0x63,0x64,0x09,0x01};
static const unsigned char OID_APPLE_CDHASHES2[] = {0x2A,0x86,0x48,0x86,0xF7,0x63,0x64,0x09,0x02};

// ---------------------------------------------------------------------------
// Minimal DER cursor — for reading the leaf certificate
// ---------------------------------------------------------------------------

typedef struct { const unsigned char *p; size_t len; size_t pos; } Cur;

static int cur_read_len(Cur *c, size_t *out) {
    if (c->pos >= c->len) return -1;
    unsigned char b = c->p[c->pos++];
    if (b & 0x80) {
        int n = b & 0x7f; size_t v = 0;
        for (int i = 0; i < n; i++) { if (c->pos >= c->len) return -1; v = (v << 8) | c->p[c->pos++]; }
        *out = v;
    } else *out = b;
    return 0;
}
static int cur_read_tlv(Cur *c, unsigned char *tag, const unsigned char **content, size_t *clen) {
    if (c->pos >= c->len) return -1;
    *tag = c->p[c->pos++];
    size_t l;
    if (cur_read_len(c, &l) != 0) return -1;
    if (c->pos + l > c->len) return -1;
    *content = c->p + c->pos; *clen = l;
    c->pos += l;
    return 0;
}

static int parse_cert_ids(const unsigned char *cert, size_t certlen,
                          Buf *issuer, Buf *serial) {
    Cur c; c.p = cert; c.len = certlen; c.pos = 0;
    unsigned char tag; const unsigned char *content; size_t clen;
    if (cur_read_tlv(&c, &tag, &content, &clen) != 0 || tag != 0x30) return -1;
    Cur t; t.p = content; t.len = clen; t.pos = 0;
    if (cur_read_tlv(&t, &tag, &content, &clen) != 0 || tag != 0x30) return -1;
    Cur tbs; tbs.p = content; tbs.len = clen; tbs.pos = 0;
    if (tbs.pos < tbs.len && tbs.p[tbs.pos] == 0xA0) {
        if (cur_read_tlv(&tbs, &tag, &content, &clen) != 0) return -1;
    }
    if (cur_read_tlv(&tbs, &tag, &content, &clen) != 0 || tag != 0x02) return -1;
    buf_put(serial, content, clen);
    if (cur_read_tlv(&tbs, &tag, &content, &clen) != 0) return -1;
    if (cur_read_tlv(&tbs, &tag, &content, &clen) != 0 || tag != 0x30) return -1;
    buf_put(issuer, content, clen);
    return 0;
}

static int read_subject_cn(SecCertificateRef cert, char *out, size_t outcap) {
    CFStringRef cn = SecCertificateCopySubjectSummary(cert);
    if (!cn) return -1;
    const char *s = CFStringGetCStringPtr(cn, kCFStringEncodingUTF8);
    if (!s) { CFRelease(cn); return -1; }
    const char *p = strstr(s, "CN=");
    p = p ? p + 3 : s;
    size_t n = 0;
    while (p[n] && p[n] != ',' && n + 1 < outcap) n++;
    memcpy(out, p, n);
    out[n] = 0;
    CFRelease(cn);
    return out[0] ? 0 : -1;
}

// ---------------------------------------------------------------------------
// CMS / PKCS#7 SignedData (DETACHED — Apple codesign / zsign parity)
// ---------------------------------------------------------------------------

/// Build the detached CMS SignedData carrying the cert chain and the signature
/// over the primary CodeDirectory.
///
/// Per zsign (`openssl.cpp::GenerateCMS`):
///   * flags CMS_PARTIAL|CMS_DETACHED|CMS_NOSMIMECAP|CMS_BINARY
///   * eContent is ABSENT (detached) — the content is the primary CD, attested
///     to by the messageDigest signed attribute.
///   * signed attributes: contentType, messageDigest, 1.2.840.113635.100.9.1
///     (cdhashes plist) and 1.2.840.113635.100.9.2 (CDHashes2).
///   * SignedData / SignerInfo version 3 (signedAttrs present).
///
/// `cd1` is the primary (SHA-1) CodeDirectory; `cd2` the alternate (SHA-256).
/// On success `*out_cms` is the RAW CMS DER (the BLOBWRAPPER header is added by
/// the SuperBlob assembler).
static int build_cms(const unsigned char *cd1, size_t cd1_len,
                     const unsigned char *cd2, size_t cd2_len,
                     SecKeyRef privKey,
                     unsigned char **certs, size_t *cert_lens, int n_certs,
                     const unsigned char *issuer, size_t issuer_len,
                     const unsigned char *serial, size_t serial_len,
                     RyBuf *out_cms) {
    if (!privKey) return -1;

    unsigned char cd1_sha1[20], cd1_sha256[32], cd2_sha256[32];
    ry_sha1(cd1, cd1_len, cd1_sha1);
    ry_sha256(cd1, cd1_len, cd1_sha256);
    ry_sha256(cd2, cd2_len, cd2_sha256);

    // Apple 1.2.840.113635.100.9.1 — cdhashes plist: one entry per CD, the
    // 20-byte truncated hash. Primary uses SHA-1 directly; alternate uses
    // SHA-256 truncated to 20 bytes (zsign dual-hash rule).
    RyBuf plist;
    RyBuf cdr1 = { (unsigned char *)cd1, cd1_len, cd1_len };
    RyBuf cdr2 = { (unsigned char *)cd2, cd2_len, cd2_len };
    if (ry_build_cdhashes_plist(&cdr1, &cdr2, &g_hash, &plist) != 0) return -1;

    // Apple 1.2.840.113635.100.9.2 — CDHashes2. zsign builds this with
    // GenerateASN1Type(hex(SHA256(CD2))):
    //   SEQUENCE { OBJECT:sha256, OCTET STRING:<32 raw bytes of SHA-256(CD2)> }
    // (the OCTET STRING carries the 32 raw hash bytes, not a hex string).
    Buf cdh2; buf_init(&cdh2);
    {
        Buf inner; buf_init(&inner);
        der_oid(&inner, OID_SHA256, sizeof(OID_SHA256));
        Buf oct; buf_init(&oct);
        buf_put(&oct, cd2_sha256, 32);
        Buf octw; buf_init(&octw); der_octet(&octw, &oct);
        buf_put(&inner, octw.p, octw.len);
        der_seq(&cdh2, &inner);                 // cdh2 = SEQUENCE{ OID sha256, OCTET STRING 32 }
        buf_free(&inner); buf_free(&oct); buf_free(&octw);
    }

    // ---- signed attributes ------------------------------------------------
    Buf sa; buf_init(&sa);
    {
        Buf oid; buf_init(&oid); der_oid(&oid, OID_DATA, sizeof(OID_DATA));
        Buf vals; buf_init(&vals); der_set(&vals, &oid);
        Buf attr; buf_init(&attr); der_oid(&attr, OID_CTYPE, sizeof(OID_CTYPE));
        buf_put(&attr, vals.p, vals.len); der_seq(&sa, &attr);
        buf_free(&oid); buf_free(&vals); buf_free(&attr);
    }
    {
        Buf mdv; buf_init(&mdv); buf_put(&mdv, cd1_sha256, 32);
        Buf oct; buf_init(&oct); der_octet(&oct, &mdv);
        Buf vals; buf_init(&vals); der_set(&vals, &oct);
        Buf attr; buf_init(&attr); der_oid(&attr, OID_MSGDIGEST, sizeof(OID_MSGDIGEST));
        buf_put(&attr, vals.p, vals.len); der_seq(&sa, &attr);
        buf_free(&mdv); buf_free(&oct); buf_free(&vals); buf_free(&attr);
    }
    {
        Buf plv; buf_init(&plv); buf_put(&plv, plist.p, plist.len);
        Buf oct; buf_init(&oct); der_octet(&oct, &plv);
        Buf vals; buf_init(&vals); der_set(&vals, &oct);
        Buf attr; buf_init(&attr); der_oid(&attr, OID_APPLE_CDHASHES, sizeof(OID_APPLE_CDHASHES));
        buf_put(&attr, vals.p, vals.len); der_seq(&sa, &attr);
        buf_free(&plv); buf_free(&oct); buf_free(&vals); buf_free(&attr);
    }
    {
        Buf vals; buf_init(&vals); der_set(&vals, &cdh2);
        Buf attr; buf_init(&attr); der_oid(&attr, OID_APPLE_CDHASHES2, sizeof(OID_APPLE_CDHASHES2));
        buf_put(&attr, vals.p, vals.len); der_seq(&sa, &attr);
        buf_free(&vals); buf_free(&attr);
    }

    // Choose the signature algorithm by key type (LiveContainer parity):
    // RSA identities sign with PKCS#1 v1.5 SHA-256; EC identities sign with
    // ECDSA X9.62 SHA-256. Hard-coding RSA here makes build_cms() return -1
    // for EC certs — a silent second source of the "main exe sign failed"
    // rc=6 the user hit. Defaulting to RSA when attributes are unavailable
    // keeps the common (Apple RSA dev/dist cert) path exactly as before.
    SecKeyAlgorithm signAlgo = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256;
    {
        CFDictionaryRef kattrs = SecKeyCopyAttributes(privKey);
        if (kattrs) {
            CFStringRef kt = (CFStringRef)CFDictionaryGetValue(kattrs, kSecAttrKeyType);
            if (kt && CFEqual(kt, kSecAttrKeyTypeECSECPrimeRandom))
                signAlgo = kSecKeyAlgorithmECDSASignatureMessageX962SHA256;
            CFRelease(kattrs);
        }
    }

    // The signature is over the DER SET OF the attributes (CMS rule).
    Buf saSet; buf_init(&saSet); der_set(&saSet, &sa);
    CFDataRef sigData = NULL;
    OSStatus st = SecKeyCreateSignature(privKey, signAlgo,
        CFDataCreate(NULL, saSet.p, (CFIndex)saSet.len), &sigData);
    if (st != errSecSuccess) {
        // The OSStatus is the ONLY clue the device gives us here: -25338
        // (errSecUnsupportedAlgorithm?) style codes point at a key/algorithm
        // mismatch, which is exactly the failure that used to surface as a
        // bare "exit code 6".
        fprintf(stderr, "rysign: SecKeyCreateSignature failed osstatus=%d algo=%s\n",
                (int)st,
                CFEqual(signAlgo, kSecKeyAlgorithmECDSASignatureMessageX962SHA256)
                    ? "ecdsa-x9.62-sha256" : "rsa-pkcs1v15-sha256");
        buf_free(&sa); buf_free(&saSet); buf_free(&cdh2); ry_buf_free(&plist);
        return -1;
    }

    // ---- SignerInfo (version 3) -------------------------------------------
    Buf si; buf_init(&si);
    { unsigned char one[1] = {3}; der_int(&si, one, 1); }
    { Buf iasn; buf_init(&iasn); buf_put(&iasn, issuer, issuer_len);
      der_int(&iasn, serial, serial_len); der_wrap(&si, 0x30, &iasn); buf_free(&iasn); }
    { Buf da; buf_init(&da); der_oid(&da, OID_SHA256, sizeof(OID_SHA256));
      Buf dseq; buf_init(&dseq); der_wrap(&dseq, 0x30, &da);
      der_wrap(&si, 0x30, &dseq); buf_free(&da); buf_free(&dseq); }
    der_ctx0(&si, &sa);                                       // signedAttrs [0]
    { Buf ra; buf_init(&ra); der_oid(&ra, OID_SHA256RSA, sizeof(OID_SHA256RSA));
      Buf rseq; buf_init(&rseq); der_wrap(&rseq, 0x30, &ra);
      der_wrap(&si, 0x30, &rseq); buf_free(&ra); buf_free(&rseq); }
    { Buf sigOct; buf_init(&sigOct);
      buf_put(&sigOct, CFDataGetBytePtr(sigData), (size_t)CFDataGetLength(sigData));
      der_octet(&si, &sigOct); buf_free(&sigOct); }
    Buf signerInfo; buf_init(&signerInfo); der_wrap(&signerInfo, 0x30, &si);

    // ---- SignedData (version 3) -------------------------------------------
    Buf sd; buf_init(&sd);
    { unsigned char one[1] = {3}; der_int(&sd, one, 1); }
    { Buf da; buf_init(&da); der_oid(&da, OID_SHA256, sizeof(OID_SHA256));
      Buf dseq; buf_init(&dseq); der_wrap(&dseq, 0x30, &da);
      Buf dset; buf_init(&dset); der_set(&dset, &dseq);
      buf_put(&sd, dset.p, dset.len); buf_free(&da); buf_free(&dseq); buf_free(&dset); }
    { Buf eci; buf_init(&eci); der_oid(&eci, OID_DATA, sizeof(OID_DATA));
      der_wrap(&sd, 0x30, &eci); buf_free(&eci); }    // detached: NO eContent
    if (n_certs > 0) {
        Buf cc; buf_init(&cc);
        for (int i = 0; i < n_certs; i++) buf_put(&cc, certs[i], cert_lens[i]);
        der_ctx0(&sd, &cc); buf_free(&cc);
    }
    { Buf sset; buf_init(&sset); der_set(&sset, &signerInfo);
      buf_put(&sd, sset.p, sset.len); buf_free(&sset); }

    Buf signedData; buf_init(&signedData); der_wrap(&signedData, 0x30, &sd);
    Buf ci; buf_init(&ci); der_oid(&ci, OID_SIGNED, sizeof(OID_SIGNED));
    der_ctx0(&ci, &signedData);
    Buf ciSeq; buf_init(&ciSeq); der_wrap(&ciSeq, 0x30, &ci);

    ry_buf_init(out_cms);
    ry_buf_put(out_cms, ciSeq.p, ciSeq.len);

    buf_free(&sa); buf_free(&saSet); buf_free(&cdh2); ry_buf_free(&plist);
    buf_free(&si); buf_free(&signerInfo); buf_free(&sd);
    buf_free(&signedData); buf_free(&ci); buf_free(&ciSeq);
    if (sigData) CFRelease(sigData);
    return 0;
}

// ---------------------------------------------------------------------------
// Sign a single 64-bit Mach-O — zsign-style in-place overwrite
// ---------------------------------------------------------------------------

/// Offset of the first byte that is NOT load commands (the lowest section
/// fileoff), or 0 when it cannot be determined. Used to decide whether a new
/// load command can be appended into the header's slack.
static uint32_t loadCommandsBoundary(const struct mach_header_64 *hdr) {
    const struct load_command *lc =
        (const struct load_command *)((const uint8_t *)hdr + sizeof(*hdr));
    uint32_t best = 0;
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            const struct section_64 *sects = (const struct section_64 *)(seg + 1);
            for (uint32_t s = 0; s < seg->nsects; s++) {
                if (sects[s].offset > 0 && (best == 0 || sects[s].offset < best))
                    best = sects[s].offset;
            }
        }
        lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
    }
    return best;
}

/// zsign parity (`ZArchO::Sign` inserts one when the binary carries none): a
/// decrypted / tool-stripped IPA may have had its LC_CODE_SIGNATURE removed.
/// Without the command the whole signing model (write at `dataoff`) has no
/// anchor, so synthesise it at the end of the load commands, pointing at the
/// current file tail — the SuperBlob then grows the file exactly like zsign.
/// On success stores the new command in `*out_lc` and returns its dataoff;
/// returns 0 when there is no room (caller fails).
static uint32_t synthesizeCodeSignature(struct mach_header_64 *hdr, size_t file_len,
                                        struct linkedit_data_command **out_lc) {
    uint32_t boundary = loadCommandsBoundary(hdr);
    if (boundary == 0) return 0;
    uint8_t *cmdEnd = (uint8_t *)hdr + sizeof(*hdr) + hdr->sizeofcmds;
    if ((uintptr_t)cmdEnd + sizeof(struct linkedit_data_command) >
        (uintptr_t)hdr + boundary) return 0;         // no slack — cannot insert

    struct linkedit_data_command *nc = (struct linkedit_data_command *)cmdEnd;
    memset(nc, 0, sizeof(*nc));
    nc->cmd = LC_CODE_SIGNATURE;
    nc->cmdsize = (uint32_t)sizeof(*nc);             // 16
    nc->dataoff = (uint32_t)file_len;                // blob starts at file tail
    nc->datasize = 0;
    hdr->ncmds++;
    hdr->sizeofcmds += nc->cmdsize;
    if (out_lc) *out_lc = nc;
    fprintf(stderr, "rysign: synthesised LC_CODE_SIGNATURE dataoff=%u\n", nc->dataoff);
    return nc->dataoff;
}

static int sign_slice(unsigned char **pbuf, size_t *len,
                      const char *ident, const char *team,
                      const unsigned char *infoplist, size_t info_len,
                      const unsigned char *ent, size_t ent_len,
                      const unsigned char *code_resources, size_t cr_len,
                      SecKeyRef privKey,
                      unsigned char **certs, size_t *cert_lens, int n_certs,
                      const unsigned char *issuer, size_t issuer_len,
                      const unsigned char *serial, size_t serial_len) {
    unsigned char *buf = *pbuf;
    struct mach_header_64 *hdr = (struct mach_header_64 *)buf;
    if (hdr->magic != MH_MAGIC_64) { return -1; }

    uint32_t ncmds = hdr->ncmds;
    struct load_command *lc = (struct load_command *)(buf + sizeof(struct mach_header_64));
    uint32_t sig_dataoff = 0, sig_datasize = 0;
    struct linkedit_data_command *sig_lc = NULL;
    struct segment_command_64 *linkedit = NULL;
    struct segment_command_64 *textseg = NULL;
    for (uint32_t i = 0; i < ncmds; i++) {
        if (lc->cmd == LC_CODE_SIGNATURE) {
            sig_lc = (struct linkedit_data_command *)lc;
            sig_dataoff = sig_lc->dataoff;
            sig_datasize = sig_lc->datasize;
        } else if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            if (strcmp(seg->segname, "__LINKEDIT") == 0) linkedit = seg;
            else if (strcmp(seg->segname, "__TEXT") == 0) textseg = seg;
        }
        lc = (struct load_command *)((unsigned char *)lc + lc->cmdsize);
    }
    if (!sig_lc) {
        // No signature command at all (stripped/decrypted IPA). Synthesise one
        // instead of dying — zsign does exactly this.
        uint32_t new_off = synthesizeCodeSignature(hdr, *len, &sig_lc);
        if (new_off == 0) {
            fprintf(stderr, "rysign: missing LC_CODE_SIGNATURE and no room to add one\n");
            return -2;
        }
        sig_dataoff = new_off;
        sig_datasize = 0;
    }

    // CodeDirectory hashes everything before the signature — zsign's m_uCodeLength.
    uint64_t code_limit = (uint64_t)sig_dataoff;

    RySignMeta meta; memset(&meta, 0, sizeof(meta));
    meta.bundle_id = ident;
    meta.team_id = (team && team[0]) ? team : NULL;
    meta.subject_cn = g_subject_cn[0] ? g_subject_cn : NULL;
    meta.info_plist = infoplist; meta.info_plist_len = info_len;
    meta.code_resources = code_resources; meta.code_resources_len = cr_len;

    RyBuf req;
    if (ry_build_requirements(&meta, &req) != 0) return -3;
    meta.requirements_blob = req.p; meta.requirements_blob_len = req.len;

    // Entitlements blob (XML) WITH its native 8-byte header — what the special
    // slot -5 hashes, and what the SuperBlob slot 5 wraps.
    RyBuf ent_blob; ry_buf_init(&ent_blob);
    if (ent && ent_len) {
        ry_buf_be32(&ent_blob, RY_CSMAGIC_EMBEDDED_ENTITLEMENTS);
        ry_buf_be32(&ent_blob, (uint32_t)(8 + ent_len));
        ry_buf_put(&ent_blob, ent, ent_len);
    }
    meta.entitlements_blob = ent_blob.p; meta.entitlements_blob_len = ent_blob.len;
    // The DER entitlements blob (slot 7) is intentionally omitted for a dylib
    // guest — matching zsign's `IsExecute() ? … : ""`. AMFI falls back to slot
    // 5 (XML), which we DO populate with the real profile entitlements.

    // CodeDirectories: primary SHA-1 (cd1), alternate SHA-256 (cd2). is_execute
    // = 0 (guest patched to MH_DYLIB → five special slots, no -7/-6);
    // is_adhoc = 0 (real, in-place signature AMFI requires).
    uint64_t exec_seg_limit = textseg ? (uint64_t)textseg->vmsize : 0;
    uint64_t exec_seg_flags = 0;

    RyBuf cd1, cd2;
    if (ry_build_codedirectory(0, buf, code_limit, &meta, 0, 0,
                               exec_seg_limit, exec_seg_flags, &g_hash, &cd1) != 0) {
        ry_buf_free(&req); ry_buf_free(&ent_blob); return -4;
    }
    if (ry_build_codedirectory(1, buf, code_limit, &meta, 0, 0,
                               exec_seg_limit, exec_seg_flags, &g_hash, &cd2) != 0) {
        ry_buf_free(&req); ry_buf_free(&ent_blob); ry_buf_free(&cd1); return -4;
    }

    RyBuf cms;
    if (build_cms(cd1.p, cd1.len, cd2.p, cd2.len, privKey, certs, cert_lens, n_certs,
                  issuer, issuer_len, serial, serial_len, &cms) != 0) {
        fprintf(stderr, "rysign: build_cms failed\n");
        ry_buf_free(&req); ry_buf_free(&ent_blob); ry_buf_free(&cd1); ry_buf_free(&cd2);
        return -5;
    }

    RyBuf sb;
    if (ry_build_superblob(&cd1, &req, ent_blob.len ? &ent_blob : NULL, NULL,
                           &cd2, &cms, &sb) != 0) {
        ry_buf_free(&req); ry_buf_free(&ent_blob); ry_buf_free(&cd1);
        ry_buf_free(&cd2); ry_buf_free(&cms); return -6;
    }

    // Write in place at dataoff; grow the file tail only if the new blob is
    // larger than the old signature region (zsign parity).
    size_t avail = (*len) - (size_t)sig_dataoff;
    if (sb.len <= avail) {
        memcpy(buf + sig_dataoff, sb.p, sb.len);
        if (avail > sb.len) memset(buf + sig_dataoff + sb.len, 0, avail - sb.len);
        sig_lc->datasize = (uint32_t)sb.len;
    } else {
        size_t new_len = (size_t)sig_dataoff + sb.len;
        if (linkedit) {
            linkedit->filesize = (uint64_t)new_len - linkedit->fileoff;
            uint64_t new_vmsize = (linkedit->filesize + 0xFFFULL) & ~(uint64_t)0xFFFULL;
            if (new_vmsize > linkedit->vmsize) linkedit->vmsize = new_vmsize;
        } else {
            fprintf(stderr, "rysign: no __LINKEDIT segment; growing file without it\n");
        }
        sig_lc->datasize = (uint32_t)sb.len;
        unsigned char *nb = (unsigned char *)realloc(buf, new_len);
        if (!nb) {
            ry_buf_free(&req); ry_buf_free(&ent_blob); ry_buf_free(&cd1);
            ry_buf_free(&cd2); ry_buf_free(&cms); ry_buf_free(&sb);
            return -7;
        }
        memset(nb + *len, 0, new_len - *len);
        memcpy(nb + sig_dataoff, sb.p, sb.len);
        *pbuf = nb; *len = new_len;
    }

    ry_buf_free(&req); ry_buf_free(&ent_blob); ry_buf_free(&cd1);
    ry_buf_free(&cd2); ry_buf_free(&cms); ry_buf_free(&sb);
    return 0;
}

// ---------------------------------------------------------------------------
// Sign a whole Mach-O file (single 64-bit slice)
// ---------------------------------------------------------------------------
static int sign_macho_file_at(const char *path, const char *bundlePath,
                              SecCertificateRef leaf, SecKeyRef privKey,
                              const char *team, const char *ident,
                              const unsigned char *ent, size_t ent_len) {
    g_sign_subcode = 0;

    // A directory (e.g. a mangled exe path ending in "/") would otherwise sail
    // through read_file's fseek/ftell and hand sign_slice uninitialised bytes.
    struct stat pst;
    if (stat(path, &pst) != 0 || S_ISDIR(pst.st_mode)) {
        fprintf(stderr, "rysign: '%s' is not a regular file\n", path);
        g_sign_subcode = -8;
        return -8;
    }

    size_t len; unsigned char *buf = read_file(path, &len);
    if (!buf) { g_sign_subcode = -1; return -1; }
    if (len < sizeof(struct mach_header_64)) {
        fprintf(stderr, "rysign: '%s' too small (%zu bytes)\n", path, len);
        free(buf); g_sign_subcode = -1; return -1;
    }

    uint32_t magic = *(uint32_t *)buf;
    if (magic != MH_MAGIC_64) {
        fprintf(stderr, "rysign: '%s' is not a 64-bit Mach-O (magic %08x)\n", path, magic);
        free(buf); g_sign_subcode = -9; return -9;
    }

    // The leaf DER must outlive the CFDataRef it was borrowed from: certs[0]
    // pointed straight into that buffer, which used to be CFRelease'd before
    // build_cms read it (a use-after-free that only survived by luck).
    Buf issuer; Buf serial; buf_init(&issuer); buf_init(&serial);
    unsigned char *leaf_copy = NULL; size_t leaf_copy_len = 0;
    unsigned char **certs = NULL; size_t *cert_lens = NULL; int nc = 0;
    if (leaf) {
        CFDataRef ld = SecCertificateCopyData(leaf);
        if (ld) {
            const unsigned char *ldp = CFDataGetBytePtr(ld);
            size_t ldl = (size_t)CFDataGetLength(ld);
            leaf_copy = (unsigned char *)malloc(ldl ? ldl : 1);
            if (leaf_copy) {
                memcpy(leaf_copy, ldp, ldl);
                leaf_copy_len = ldl;
            }
            parse_cert_ids(ldp, ldl, &issuer, &serial);
            CFRelease(ld);
        }
        certs = malloc(sizeof(void *));
        cert_lens = malloc(sizeof(size_t));
        if (certs && cert_lens) {
            certs[0] = leaf_copy; cert_lens[0] = leaf_copy_len; nc = 1;
        }
        if (g_extra_certs_n > 0 && certs && cert_lens) {
            certs = realloc(certs, sizeof(void *) * (size_t)(nc + g_extra_certs_n));
            cert_lens = realloc(cert_lens, sizeof(size_t) * (size_t)(nc + g_extra_certs_n));
            for (int i = 0; i < g_extra_certs_n; i++) {
                // The provisioning profile's DeveloperCertificates array
                // repeats the leaf; a duplicated leaf in the CMS cert set can
                // confuse AMFI's trust evaluation, so skip identical DERs.
                bool dup = false;
                for (int j = 0; j < nc; j++) {
                    if (cert_lens[j] == g_extra_certs_lens[i] &&
                        memcmp(certs[j], g_extra_certs[i], g_extra_certs_lens[i]) == 0) {
                        dup = true; break;
                    }
                }
                if (dup) continue;
                certs[nc] = g_extra_certs[i]; cert_lens[nc] = g_extra_certs_lens[i]; nc++;
            }
        }
    }

    unsigned char *info = NULL; size_t info_len = 0;
    if (g_info_plist && g_info_plist_len) {
        info = g_info_plist; info_len = g_info_plist_len;
    } else if (bundlePath) {
        char ip[2048]; snprintf(ip, sizeof(ip), "%s/Info.plist", bundlePath);
        info = read_file(ip, &info_len);
    }
    unsigned char *cr = NULL; size_t cr_len = 0;
    if (bundlePath) {
        char crp[2048]; snprintf(crp, sizeof(crp), "%s/_CodeSignature/CodeResources", bundlePath);
        cr = read_file(crp, &cr_len);
    }

    fprintf(stderr, "rysign: signing '%s' (info=%zu cr=%zu ent=%zu certs=%d)\n",
            path, info_len, cr_len, ent_len, nc);

    int rc = sign_slice(&buf, &len, ident, team, info, info_len, ent, ent_len,
                        cr, cr_len, privKey, certs, cert_lens, nc,
                        issuer.p, issuer.len, serial.p, serial.len);
    if (rc == 0) {
        if (write_file(path, buf, len) != 0) {
            fprintf(stderr, "rysign: write-back failed for '%s'\n", path);
            rc = -10;
        }
    } else {
        fprintf(stderr, "rysign: sign_slice '%s' rc=%d\n", path, rc);
    }

    g_sign_subcode = rc;
    free(buf);
    if (leaf_copy) free(leaf_copy);
    if (certs) free(certs);
    if (cert_lens) free(cert_lens);
    if (info != g_info_plist && info) free(info);
    if (cr) free(cr);
    return rc;
}

// ---------------------------------------------------------------------------
// Recursively sign every Mach-O under a directory
// ---------------------------------------------------------------------------
static void sign_walk(const char *dir, SecCertificateRef leaf, SecKeyRef privKey,
                      const char *team, const char *ident,
                      const unsigned char *ent, size_t ent_len) {
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        char path[2048];
        snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        struct stat st;
        if (stat(path, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            sign_walk(path, leaf, privKey, team, ident, ent, ent_len);
        } else if (S_ISREG(st.st_mode)) {
            size_t n; unsigned char *b = read_file(path, &n);
            if (!b) continue;
            int is_macho = (n >= 4) &&
                (*(uint32_t *)b == MH_MAGIC_64 || *(uint32_t *)b == FAT_MAGIC ||
                 *(uint32_t *)b == FAT_CIGAM);
            free(b);
            if (is_macho) sign_macho_file_at(path, NULL, leaf, privKey, team, ident, ent, ent_len);
        }
    }
    closedir(d);
}

// ---------------------------------------------------------------------------
// Shared bundle-signing body (identity already in hand)
// ---------------------------------------------------------------------------
// Exit codes: 5 main executable not found · 6 signing the main executable failed
static int sign_bundle_core(const char *bundlePath,
                            SecCertificateRef leaf, SecKeyRef privKey,
                            const char *team,
                            const unsigned char *ent, size_t ent_len,
                            const char *provPath) {
    size_t provlen; unsigned char *prov = read_file(provPath, &provlen);
    if (!prov) { fprintf(stderr, "rysign: cannot read provisioning\n"); return 4; }
    g_prov = prov; g_prov_len = provlen;

    if (leaf) {
        if (read_subject_cn(leaf, g_subject_cn, sizeof(g_subject_cn)) != 0)
            g_subject_cn[0] = 0;
    }

    // main executable + bundle id from Info.plist (CoreFoundation parses BOTH
    // XML and binary plists — this is what fixes the old rc=6 on Sileo, whose
    // Info.plist is `bplist00`).
    char exe_path[2048];
    char exe_name[1024] = {0};
    char bid[256] = {0};
    {
        char ip[2048]; snprintf(ip, sizeof(ip), "%s/Info.plist", bundlePath);
        size_t il; unsigned char *info = read_file(ip, &il);
        if (info) {
            CFDataRef d = CFDataCreate(NULL, info, (CFIndex)il);
            CFPropertyListRef plist =
                CFPropertyListCreateWithData(NULL, d, kCFPropertyListImmutable, NULL, NULL);
            if (plist && CFGetTypeID(plist) == CFDictionaryGetTypeID()) {
                CFDictionaryRef dict = (CFDictionaryRef)plist;
                CFStringRef v;
                if ((v = CFDictionaryGetValue(dict, CFSTR("CFBundleExecutable"))))
                    CFStringGetCString(v, exe_name, sizeof(exe_name), kCFStringEncodingUTF8);
                if ((v = CFDictionaryGetValue(dict, CFSTR("CFBundleIdentifier"))))
                    CFStringGetCString(v, bid, sizeof(bid), kCFStringEncodingUTF8);
            }
            if (plist) CFRelease(plist);
            CFRelease(d);
            free(info);
        }
    }
    if (g_exe_name[0]) snprintf(exe_path, sizeof(exe_path), "%s/%s", bundlePath, g_exe_name);
    else snprintf(exe_path, sizeof(exe_path), "%s/%s", bundlePath, exe_name);

    if (access(exe_path, F_OK) != 0) {
        fprintf(stderr, "rysign: cannot locate main executable in bundle\n");
        free(prov); if (ent) free((void *)ent);
        return 5;
    }
    const char *ident = (g_ident_override && g_ident_override[0]) ? g_ident_override : bid;
    fprintf(stderr, "rysign: signing '%s' team='%s' ident='%s' hasEnt=%d\n",
            exe_path, team ? team : "", ident, (ent && ent_len > 0) ? 1 : 0);

    int rc = sign_macho_file_at(exe_path, bundlePath, leaf, privKey, team, ident, ent, ent_len);
    if (rc != 0) {
        fprintf(stderr, "rysign: sign main exe failed (%d)\n", rc);
        free(prov); if (ent) free((void *)ent);
        return 6;
    }

    const char *subdirs[] = { "Frameworks", "PlugIns", "SwiftSupport" };
    for (int s = 0; s < 3; s++) {
        char dd[2048]; snprintf(dd, sizeof(dd), "%s/%s", bundlePath, subdirs[s]);
        sign_walk(dd, leaf, privKey, team, ident, ent, ent_len);
    }

    char emb[2048]; snprintf(emb, sizeof(emb), "%s/embedded.mobileprovision", bundlePath);
    write_file(emb, prov, provlen);

    free(prov); if (ent) free((void *)ent);
    return 0;
}

// ---------------------------------------------------------------------------
// Robust bundle signing: all material pre-decoded by Swift
// ---------------------------------------------------------------------------
// Exit codes mirror sign_bundle_core: 4 prov · 5 no exe · 6 sign failed
//   7 cert/key DER unusable · 8 private key could not be created
int rysign_sign_bundle_robust(const char *bundlePath,
                              const char *leafCertDerPath,
                              const char *keyDerPath,
                              int keyIsEC,
                              const char *provPath,
                              const char *entitlementsPath,
                              const char *team,
                              const char *certsDir) {
    size_t clen = 0, klen = 0;
    unsigned char *cd = read_file(leafCertDerPath, &clen);
    unsigned char *kd = read_file(keyDerPath, &klen);
    if (!cd || !kd || clen == 0 || klen == 0) {
        fprintf(stderr, "rysign: cannot read cert/key DER\n");
        if (cd) free(cd); if (kd) free(kd);
        return 7;
    }
    CFDataRef certData = CFDataCreate(NULL, cd, (CFIndex)clen);
    SecCertificateRef leaf = SecCertificateCreateWithData(NULL, certData);
    if (!leaf) {
        fprintf(stderr, "rysign: SecCertificateCreateWithData failed\n");
        CFRelease(certData); free(cd); free(kd);
        return 7;
    }
    CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(NULL, 0, NULL, NULL);
    CFDictionarySetValue(attrs, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFDictionarySetValue(attrs, kSecAttrKeyType,
                         keyIsEC ? kSecAttrKeyTypeECSECPrimeRandom : kSecAttrKeyTypeRSA);
    if (!keyIsEC) {
        int bits = 0;
        Cur c; c.p = kd; c.len = klen; c.pos = 0;
        unsigned char tag; const unsigned char *content; size_t clen2;
        if (cur_read_tlv(&c, &tag, &content, &clen2) != 0 || tag != 0x30) { }
        else if (cur_read_tlv(&c, &tag, &content, &clen2) != 0 || tag != 0x02) { }
        else if (cur_read_tlv(&c, &tag, &content, &clen2) != 0 || tag != 0x02) { }
        else {
            const unsigned char *m = content; size_t n = clen2;
            while (n > 1 && m[0] == 0) { m++; n--; }
            bits = (int)(n * 8);
        }
        if (bits > 0) {
            int bitsRef = bits;
            CFNumberRef num = CFNumberCreate(NULL, kCFNumberIntType, &bitsRef);
            CFDictionarySetValue(attrs, kSecAttrKeySizeInBits, num);
            if (num) CFRelease(num);
        }
    }
    CFErrorRef keyErr = NULL;
    CFDataRef keyData = CFDataCreate(NULL, kd, (CFIndex)klen);
    SecKeyRef privKey = SecKeyCreateWithData(keyData, attrs, &keyErr);
    CFRelease(keyData); CFRelease(attrs);
    if (!privKey) {
        fprintf(stderr, "rysign: SecKeyCreateWithData failed\n");
        if (keyErr) CFRelease(keyErr);
        CFRelease(certData); CFRelease(leaf); free(cd); free(kd);
        return 8;
    }

    unsigned char **extra = NULL; size_t *extra_lens = NULL; int extra_n = 0;
    if (certsDir) {
        DIR *d = opendir(certsDir);
        if (d) {
            char **names = NULL; int nn = 0; struct dirent *de;
            while ((de = readdir(d)) != NULL) {
                if (de->d_name[0] == '.') continue;
                size_t l = strlen(de->d_name);
                if (l < 4 || strcmp(de->d_name + l - 4, ".der") != 0) continue;
                names = realloc(names, sizeof(char *) * (nn + 1));
                names[nn++] = strdup(de->d_name);
            }
            closedir(d);
            for (int i = 1; i < nn; i++)
                for (int j = i; j > 0 && strcmp(names[j-1], names[j]) > 0; j--) {
                    char *t = names[j-1]; names[j-1] = names[j]; names[j] = t;
                }
            if (nn) { extra = malloc(sizeof(void *) * nn); extra_lens = malloc(sizeof(size_t) * nn); }
            for (int i = 0; i < nn; i++) {
                char p[2048]; snprintf(p, sizeof(p), "%s/%s", certsDir, names[i]);
                size_t l = 0; unsigned char *b = read_file(p, &l);
                extra[i] = b; extra_lens[i] = l; free(names[i]);
            }
            if (names) free(names);
        }
    }
    rysign_set_extra_certs(extra, extra_lens, extra_n);

    unsigned char *ent = NULL; size_t ent_len = 0;
    if (entitlementsPath && access(entitlementsPath, F_OK) == 0)
        ent = read_file(entitlementsPath, &ent_len);

    int rc = sign_bundle_core(bundlePath, leaf, privKey, team, ent, ent_len, provPath);

    if (leaf) CFRelease(leaf);
    if (privKey) CFRelease(privKey);
    CFRelease(certData); free(cd); free(kd);
    return rc;
}

// ---------------------------------------------------------------------------
// Legacy entry: PKCS#12 file (kept for completeness; the app uses the DER path)
// ---------------------------------------------------------------------------
int rysign_sign_bundle(const char *bundlePath,
                       const char *p12Path,
                       const char *password,
                       const char *provPath,
                       const char *entitlementsPath) {
    size_t plen; unsigned char *p12 = read_file(p12Path, &plen);
    if (!p12) { fprintf(stderr, "rysign: cannot read p12\n"); return 2; }
    CFDataRef p12Data = CFDataCreate(NULL, p12, (CFIndex)plen);
    SecIdentityRef identity = NULL; SecKeyRef privKey = NULL; SecCertificateRef leaf = NULL;
    {
        CFStringRef pw = CFStringCreateWithCString(NULL, password, kCFStringEncodingUTF8);
        const void *keys[] = { kSecImportExportPassphrase };
        const void *vals[] = { pw };
        CFDictionaryRef opts = CFDictionaryCreate(NULL, keys, vals, 1, NULL, NULL);
        CFArrayRef items = NULL;
        OSStatus st = SecPKCS12Import(p12Data, opts, &items);
        if (st != errSecSuccess) {
            fprintf(stderr, "rysign: SecPKCS12Import failed (%d)\n", (int)st);
            CFRelease(p12Data); free(p12); if (pw) CFRelease(pw); if (opts) CFRelease(opts);
            return 3;
        }
        CFDictionaryRef dict = CFArrayGetValueAtIndex(items, 0);
        identity = (SecIdentityRef)CFDictionaryGetValue(dict, kSecImportItemIdentity);
        CFRetain(identity);
        if (pw) CFRelease(pw); if (opts) CFRelease(opts); if (items) CFRelease(items);
    }
    CFRelease(p12Data);
    SecIdentityCopyCertificate(identity, &leaf);
    SecIdentityCopyPrivateKey(identity, &privKey);

    int rc = sign_bundle_core(bundlePath, leaf, privKey, NULL, NULL, 0, provPath);

    if (leaf) CFRelease(leaf);
    if (privKey) CFRelease(privKey);
    if (identity) CFRelease(identity);
    free(p12);
    return rc;
}

// ---------------------------------------------------------------------------
// Bundle signing entry: DER certificate + DER private key (the path RyBox uses)
// ---------------------------------------------------------------------------
int rysign_sign_bundle_with_der(const char *bundlePath,
                                const char *certDerPath,
                                const char *keyDerPath,
                                int keyIsEC,
                                const char *provPath,
                                const char *entitlementsPath) {
    size_t clen = 0, klen = 0;
    unsigned char *cd = read_file(certDerPath, &clen);
    unsigned char *kd = read_file(keyDerPath, &klen);
    if (!cd || !kd || clen == 0 || klen == 0) {
        fprintf(stderr, "rysign: cannot read cert/key DER\n");
        if (cd) free(cd); if (kd) free(kd);
        return 7;
    }
    CFDataRef certData = CFDataCreate(NULL, cd, (CFIndex)clen);
    SecCertificateRef leaf = SecCertificateCreateWithData(NULL, certData);
    if (!leaf) {
        fprintf(stderr, "rysign: SecCertificateCreateWithData failed\n");
        CFRelease(certData); free(cd); free(kd);
        return 7;
    }
    CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(NULL, 0, NULL, NULL);
    CFDictionarySetValue(attrs, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFDictionarySetValue(attrs, kSecAttrKeyType,
                         keyIsEC ? kSecAttrKeyTypeECSECPrimeRandom : kSecAttrKeyTypeRSA);
    if (!keyIsEC) {
        int bits = 0;
        Cur c; c.p = kd; c.len = klen; c.pos = 0;
        unsigned char tag; const unsigned char *content; size_t clen2;
        if (cur_read_tlv(&c, &tag, &content, &clen2) != 0 || tag != 0x30) { }
        else if (cur_read_tlv(&c, &tag, &content, &clen2) != 0 || tag != 0x02) { }
        else if (cur_read_tlv(&c, &tag, &content, &clen2) != 0 || tag != 0x02) { }
        else {
            const unsigned char *m = content; size_t n = clen2;
            while (n > 1 && m[0] == 0) { m++; n--; }
            bits = (int)(n * 8);
        }
        if (bits > 0) {
            int bitsRef = bits;
            CFNumberRef num = CFNumberCreate(NULL, kCFNumberIntType, &bitsRef);
            CFDictionarySetValue(attrs, kSecAttrKeySizeInBits, num);
            if (num) CFRelease(num);
        }
    }
    CFErrorRef keyErr = NULL;
    CFDataRef keyData = CFDataCreate(NULL, kd, (CFIndex)klen);
    SecKeyRef privKey = SecKeyCreateWithData(keyData, attrs, &keyErr);
    CFRelease(keyData); CFRelease(attrs);
    if (!privKey) {
        fprintf(stderr, "rysign: SecKeyCreateWithData failed\n");
        if (keyErr) CFRelease(keyErr);
        CFRelease(certData); CFRelease(leaf); free(cd); free(kd);
        return 8;
    }

    int rc = sign_bundle_core(bundlePath, leaf, privKey, NULL, NULL, 0, provPath);

    CFRelease(privKey); CFRelease(leaf); CFRelease(certData);
    free(cd); free(kd);
    return rc;
}
