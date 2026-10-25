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
#include <stdarg.h>
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

/// The exact Security-framework status of the last failed Sec* call. A device
/// prints nothing but its own log line, so without this every key/algorithm
/// problem collapsed into a bare "exit code 6" and took three build cycles to
/// diagnose. Callers read it right after a failed sign and surface it.
static int g_sign_osstatus = 0;
int rysign_last_osstatus(void) { return g_sign_osstatus; }

/// One-line human-readable version of the last failure (for the app log).
static char g_sign_diag[512] = "";
const char *rysign_last_diag(void) { return g_sign_diag; }

static void rysign_set_diag(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vsnprintf(g_sign_diag, sizeof(g_sign_diag), fmt, ap);
    va_end(ap);
}

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
    if (!buf) { fclose(f); *len = 0; return NULL; }   // fread(NULL,…) would crash
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

    // Choose the signature algorithm by key type: RSA identities sign with
    // PKCS#1 v1.5 SHA-256, EC identities with ECDSA X9.62 SHA-256. Hard-coding
    // either one fails loudly for the other.
    //
    // IMPORTANT (2026-10-25 device finding): the key's own attributes are not
    // always authoritative on iOS 27+ — a SecKey round-tripped through
    // SecKeyCopyExternalRepresentation can report a type that does not match
    // the algorithm it can actually perform, and `SecKeyCreateSignature` then
    // refuses with the SAME error for a development AND a distribution
    // certificate (which is exactly what the user saw: both rejected). So we
    // try the preferred algorithm first and then the ALTERNATE one before
    // declaring failure. Signing with the wrong one fails harmlessly; signing
    // with the right one is what makes the guest loadable.
    // Try-list: for each key type there is a MESSAGE variant (framework hashes
    // the payload for us) and a DIGEST variant (we hand it a raw SHA-256). The
    // key's self-reported type is only a hint — on iOS 27 a key can end up
    // mismatched, so all four are attempted and the one that works is recorded
    // for the log. This is what turned "both certs are rejected, no idea why"
    // into "here is the exact call that succeeded".
    SecKeyAlgorithm msgA[2], digA[2];
    const char *msgName[2], *digName[2];
    bool preferEC = false;
    {
        CFDictionaryRef kattrs = SecKeyCopyAttributes(privKey);
        if (kattrs) {
            CFStringRef kt = (CFStringRef)CFDictionaryGetValue(kattrs, kSecAttrKeyType);
            if (kt && CFEqual(kt, kSecAttrKeyTypeECSECPrimeRandom)) preferEC = true;
            CFRelease(kattrs);
        }
    }
    if (preferEC) {
        msgA[0] = kSecKeyAlgorithmECDSASignatureMessageX962SHA256;
        msgName[0] = "ecdsa-x9.62-sha256(message)";
        digA[0] = kSecKeyAlgorithmECDSASignatureDigestX962SHA256;
        digName[0] = "ecdsa-x9.62-sha256(digest)";
        msgA[1] = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256;
        msgName[1] = "rsa-pkcs1v15-sha256(message)";
        digA[1] = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256;
        digName[1] = "rsa-pkcs1v15-sha256(digest)";
    } else {
        msgA[0] = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256;
        msgName[0] = "rsa-pkcs1v15-sha256(message)";
        digA[0] = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256;
        digName[0] = "rsa-pkcs1v15-sha256(digest)";
        msgA[1] = kSecKeyAlgorithmECDSASignatureMessageX962SHA256;
        msgName[1] = "ecdsa-x9.62-sha256(message)";
        digA[1] = kSecKeyAlgorithmECDSASignatureDigestX962SHA256;
        digName[1] = "ecdsa-x9.62-sha256(digest)";
    }

    // The signature is over the DER SET OF the attributes (CMS rule).
    Buf saSet; buf_init(&saSet); der_set(&saSet, &sa);
    if (!saSet.p || saSet.len == 0) {
        rysign_set_diag("CMS 待签数据为空（SET OF 未能构建）");
        buf_free(&sa); buf_free(&saSet); buf_free(&cdh2); ry_buf_free(&plist);
        return -1;
    }

    CFDataRef sigData = NULL;
    OSStatus st = errSecSuccess;
    const char *usedName = NULL;
    int skipped = 0;
    for (int attempt = 0; attempt < 4 && !sigData; attempt++) {
        bool useDigest = (attempt % 2) == 1;
        int idx = attempt / 2;
        SecKeyAlgorithm algo = useDigest ? digA[idx] : msgA[idx];
        const char *aName = useDigest ? digName[idx] : msgName[idx];
        // Feeding the key an algorithm it cannot perform (e.g. an ECDSA
        // constant to an RSA key) is at best an error and at worst a Security
        // framework assertion on iOS 27 — which is a hard crash, not a clean
        // failure. Ask first: SecKeyIsAlgorithmSupported answers without
        // touching the key.
        if (!SecKeyIsAlgorithmSupported(privKey, kSecKeyOperationTypeSign, algo)) {
            skipped++;
            fprintf(stderr, "rysign: key does not support %s — skipped\n", aName);
            continue;
        }
        // Never leave a stale error object lying around between attempts.
        CFErrorRef cferr = NULL;
        CFDataRef payload;
        if (useDigest) {
            unsigned char hash[CC_SHA256_DIGEST_LENGTH];
            CC_SHA256(saSet.p, (CC_LONG)saSet.len, hash);
            payload = CFDataCreate(NULL, hash, (CFIndex)sizeof(hash));
        } else {
            payload = CFDataCreate(NULL, saSet.p, (CFIndex)saSet.len);
        }
        // REAL API (confirmed in the CI build log 2026-10-25): the signature
        // is the RETURN VALUE (CFDataRef, NULL on failure) and the error comes
        // back through a CFErrorRef* out-parameter. The previous code assumed
        // an OSStatus return + CFDataRef* out-param — an API that does not
        // exist — which INVERTED every result: a real success returned a heap
        // pointer that truncated to a non-zero OSStatus (looked like failure,
        // and sigData was never set because the real out-param is the error),
        // while a real failure returned NULL (== errSecSuccess!) and the
        // CFError object landed in the sigData slot to be used as the
        // signature bytes. Both directions are now handled correctly.
        CFDataRef sig = SecKeyCreateSignature(privKey, algo, payload, &cferr);
        CFRelease(payload);
        if (sig) {
            sigData = sig; // ownership transferred to the CMS builder
            usedName = aName;
            g_sign_osstatus = errSecSuccess;
            break;
        }
        if (cferr) {
            st = (OSStatus)CFErrorGetCode(cferr);
            CFRelease(cferr);
        } else {
            st = errSecInternalComponent; // no error object: shouldn't happen
        }
        g_sign_osstatus = (int)st;
        fprintf(stderr, "rysign: SecKeyCreateSignature(%s) failed: osstatus=%d\n",
                aName, (int)st);
    }
    if (!sigData) {
        // The OSStatus is the ONLY clue the device gives us here: -25338
        // (errSecUnsupportedAlgorithm?) style codes point at a key/algorithm
        // mismatch, which is exactly the failure that used to surface as a
        // bare "exit code 6". It now reaches the user through RyLog.
        // Every variant was skipped by SecKeyIsAlgorithmSupported. The count
        // below already tells the story ("4 种算法密钥不支持"); the status is
        // just a placeholder because errSecUnsupportedAlgorithm does not
        // exist in the iOS SDK's SecBase.h.
        if (st == errSecSuccess) st = errSecInternalComponent; // all 4 skipped
        g_sign_osstatus = (int)st;
        fprintf(stderr, "rysign: SecKeyCreateSignature failed osstatus=%d "
                "(tried 4 algorithm variants, %d unsupported)\n", (int)st, skipped);
        rysign_set_diag("SecKeyCreateSignature 失败 osstatus=%d（已试 %s / %s / %s / %s，%d 种算法密钥不支持）",
                        (int)st, msgName[0], digName[0], msgName[1], digName[1], skipped);
        buf_free(&sa); buf_free(&saSet); buf_free(&cdh2); ry_buf_free(&plist);
        return -1;
    }
    rysign_set_diag("CMS 签名方式：%s", usedName ? usedName : "?");

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

    // LiveContainer parity (`ZArchO::BuildCodeSignature`):
    //     SlotBuildEntitlements(IsExecute() ? m_strEntitleData : "")
    //     SlotBuildDerEntitlements(IsExecute() ? … : "")
    //
    // The `IsExecute()` test is the ORIGINAL filetype. RyBox used to patch
    // every guest to MH_DYLIB before signing, so the branch was always the
    // empty one — and that is exactly what broke Sileo: a dylib carrying an
    // XML-only entitlements blob (slot 5) but no DER entitlements blob
    // (slot 7) sends AMFI down the "transmute" path, and the transmute for a
    // dylib being dlopen'd into an arbitrary host process is REFUSED. dyld
    // then reports exactly the failure Sileo hit:
    //     code signature invalid (errno=85)
    //
    // A real MH_EXECUTE does not have that problem: the kernel reads the
    // main image's entitlements straight out of slot 5 — no transmute, and no
    // library validation either. That is why the guest is now signed and run
    // as the executable it already is (see GuestRuntime.launchAsProcess).
    //
    // The guest's real capability set is NOT lost by emptying the slot for a
    // dylib: AppImporter reads the ORIGINAL entitlements before the re-sign
    // (`readOriginalEntitlements` → `EntitlementPolicy.recordOriginal`) and the
    // RyDyldHooks entitlement oracle answers runtime queries from that policy.
    int is_execute = (hdr->filetype == MH_EXECUTE);
    if (!is_execute) {
        // LiveContainer parity (`ZArchO::BuildCodeSignature`):
        //     SlotBuildEntitlements(IsExecute() ? m_strEntitleData : "")
        //     SlotBuildDerEntitlements(IsExecute() ? … : "")
        //
        // A MH_DYLIB therefore carries NO entitlements slot at all — not an
        // empty one, none. That matters: an XML-only entitlements blob
        // without a DER one sends AMFI down the "transmute" path, and the
        // transmute for a dylib being dlopen'd into an arbitrary host process
        // is REFUSED (dyld then reports `code signature invalid (errno=85)`).
        //
        // The CodeResources slot is likewise empty for a dylib: zsign is
        // handed an empty CodeResources blob and turns that into 20/32 zero
        // bytes, which the leading-zero trim then drops from the special
        // slot array entirely. The Info.plist slot (-1) IS kept — zsign
        // hashes the Info.plist it is given, and dropping it would shift
        // every slot index.
        ent = NULL; ent_len = 0;
        code_resources = NULL; cr_len = 0;
    }

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

    // Info.plist slot (-1) source, zsign semantics — DYLIB PATH ONLY.
    //
    // zsign hashes the Info.plist that is EMBEDDED IN THE MACH-O itself
    // (`__TEXT,__info_plist` section — `ZArchO::Init` collects it into
    // `m_strInfoPlist`, and `ZMachO::Sign` hashes it when the caller passes
    // no Info.plist SHA). Only if the binary has no such section does it fall
    // back to 20/32 zero bytes.
    //
    // This is applied ONLY for a MH_DYLIB. For a MH_EXECUTE the slot must
    // stay the bundle's Info.plist FILE bytes: that is what Apple's own
    // signing does, and the kernel compares the slot against the file on
    // disk for a main executable. LiveContainer only ever signs dylibs, so
    // zsign's shortcut is safe there and only there.
    if (!is_execute) {
        const unsigned char *embedded = NULL;
        size_t embedded_len = 0;
        uint32_t nc = hdr->ncmds;
        struct load_command *lc2 = (struct load_command *)(buf + sizeof(struct mach_header_64));
        for (uint32_t i = 0; i < nc; i++) {
            if (lc2->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *seg = (struct segment_command_64 *)lc2;
                if (strcmp(seg->segname, "__TEXT") == 0) {
                    struct section_64 *secs = (struct section_64 *)((unsigned char *)seg + sizeof(struct segment_command_64));
                    for (uint32_t j = 0; j < seg->nsects; j++) {
                        if (strcmp(secs[j].sectname, "__info_plist") == 0) {
                            if (secs[j].size && secs[j].offset < *len) {
                                embedded = buf + secs[j].offset;
                                embedded_len = secs[j].size;
                                if (embedded_len > *len - secs[j].offset) embedded_len = *len - secs[j].offset;
                            }
                            break;
                        }
                    }
                }
            }
            lc2 = (struct load_command *)((unsigned char *)lc2 + lc2->cmdsize);
        }
        if (embedded && embedded_len) {
            infoplist = embedded; info_len = embedded_len;
        } else {
            // No embedded section — zsign uses 20/32 zero bytes here, which
            // means the -1 slot is absent after the leading-zero trim.
            infoplist = NULL; info_len = 0;
        }
    }

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
    // slot -5 hashes, and what the SuperBlob slot 5 wraps. For a dylib guest
    // `ent` is NULL here (see the IsExecute() parity block above), so the slot
    // is omitted from the SuperBlob entirely — exactly like zsign/LC.
    RyBuf ent_blob; ry_buf_init(&ent_blob);
    if (ent && ent_len) {
        ry_buf_be32(&ent_blob, RY_CSMAGIC_EMBEDDED_ENTITLEMENTS);
        ry_buf_be32(&ent_blob, (uint32_t)(8 + ent_len));
        ry_buf_put(&ent_blob, ent, ent_len);
    }
    meta.entitlements_blob = ent_blob.p; meta.entitlements_blob_len = ent_blob.len;
    // The DER entitlements blob (slot 7) is not built: we have no DER encoder
    // yet. For a MH_EXECUTE that is fine — the kernel reads the MAIN image's
    // entitlements straight out of the XML slot 5, with no transmute involved
    // (the transmute refusal only ever bit the dylib guests). Slot 7 stays
    // all-zero and the leading-zero trim drops it together with its reserved
    // companion -6, which keeps the slot numbering contiguous.

    // CodeDirectories: primary SHA-1 (cd1), alternate SHA-256 (cd2).
    //
    // `is_execute` MUST mirror the file's real filetype (MH_EXECUTE vs
    // MH_DYLIB) — it decides the special-slot shape. A MH_EXECUTE carries
    // the DER-entitlements pair (-7/-6) and keeps its XML entitlements
    // (slot 5) / Info.plist (-1) / CodeResources (-3); a MH_DYLIB has five
    // slots (-5..-1) with the entitlement blob emptied. Getting this wrong
    // shifts `hashOffset` by two slots and AMFI rejects the whole signature.
    //
    // The exec-segment triple, per zsign (`SlotBuildCodeDirectory` +
    // `ZArchO::BuildCodeSignature`):
    //
    //   execSegBase  = 0   — zsign HARDCODES this to zero for every file it
    //                        signs, executables included. It is NOT the
    //                        __TEXT vmaddr: AltStore signs real app
    //                        executables with exactly this zsign code and
    //                        they run on device, so Apple's kernel clearly
    //                        does not require the vmaddr here.
    //   execSegLimit = __TEXT.vmsize  (zsign's `m_uExecSegLimit`, taken from
    //                        the __TEXT segment's vmsize).
    //   execSegFlags = 0 normally; zsign ORs in
    //                        CS_EXECSEG_MAIN_BINARY | CS_EXECSEG_ALLOW_UNSIGNED
    //                        when the entitlements blob contains
    //                        "<key>get-task-allow</key>" (i.e. a development
    //                        certificate). For a MH_DYLIB the entitlements
    //                        slot is empty, so the flag stays 0 — a dylib
    //                        must never claim to be a main binary.
    //
    // is_adhoc = 0 (real, in-place signature AMFI requires).
    uint64_t exec_seg_base  = 0;
    uint64_t exec_seg_limit = textseg ? (uint64_t)textseg->vmsize : 0;
    uint64_t exec_seg_flags = 0;
    if (is_execute && ent && ent_len) {
        static const char kGetTaskAllow[] = "<key>get-task-allow</key>";
        if (memmem(ent, ent_len, kGetTaskAllow, sizeof(kGetTaskAllow) - 1) != NULL) {
            exec_seg_flags = RY_EXECSEG_MAIN_BINARY | RY_EXECSEG_ALLOW_UNSIGNED;
        }
    }

    RyBuf cd1, cd2;
    if (ry_build_codedirectory(0, buf, code_limit, &meta, is_execute, 0,
                               exec_seg_base, exec_seg_limit, exec_seg_flags,
                               &g_hash, &cd1) != 0) {
        ry_buf_free(&req); ry_buf_free(&ent_blob); return -4;
    }
    if (ry_build_codedirectory(1, buf, code_limit, &meta, is_execute, 0,
                               exec_seg_base, exec_seg_limit, exec_seg_flags,
                               &g_hash, &cd2) != 0) {
        ry_buf_free(&req); ry_buf_free(&ent_blob); ry_buf_free(&cd1); return -4;
    }

    RyBuf cms;
    if (build_cms(cd1.p, cd1.len, cd2.p, cd2.len, privKey, certs, cert_lens, n_certs,
                  issuer, issuer_len, serial, serial_len, &cms) != 0) {
        fprintf(stderr, "rysign: build_cms failed\n");
        ry_buf_free(&req); ry_buf_free(&ent_blob); ry_buf_free(&cd1); ry_buf_free(&cd2);
        return -5;
    }
    fprintf(stderr, "rysign: CMS built (%zu bytes, %d certs)\n", cms.len, n_certs);

    RyBuf sb;
    if (ry_build_superblob(&cd1, &req, ent_blob.len ? &ent_blob : NULL, NULL,
                           &cd2, &cms, &sb) != 0) {
        ry_buf_free(&req); ry_buf_free(&ent_blob); ry_buf_free(&cd1);
        ry_buf_free(&cd2); ry_buf_free(&cms); return -6;
    }
    fprintf(stderr, "rysign: SuperBlob built (%zu bytes), writing at dataoff=%u\n",
            sb.len, sig_dataoff);

    // ---- write back (LiveContainer / zsign parity — the errno=85 fix) -----
    //
    // TWO RULES, both paid for on the device (2026-10-25/26):
    //
    // (1) The CodeDirectory hashes page 0, and page 0 CONTAINS the load
    //     commands. So a write to `LC_CODE_SIGNATURE.datasize` — or to
    //     __LINKEDIT.filesize/vmsize — AFTER the hashes were computed
    //     silently invalidates them, and the kernel refuses the image with
    //     `code signature invalid … (errno=85)`. The order is therefore
    //     fixed: mutate the hashed bytes FIRST, then compute the hashes, then
    //     build the blob. (This was the original bug: the code shrank
    //     `datasize` post-hash.)
    //
    // (2) The load command must advertise the blob's EXACT length. zsign
    //     writes `pcslc->datasize = uNewLength - m_uCodeLength` — the precise
    //     value — and Apple codesign does the same. Leaving a STALE, LARGER
    //     `datasize` behind (the "bare memcpy, don't touch the load
    //     commands" shortcut) is NOT safe: the kernel reads a code-signature
    //     region of the advertised size, whose SuperBlob header claims a
    //     different length, and rejects the whole image. That is exactly
    //     what the device reported:
    //
    //         code signature invalid in <F9EEDC94-…> (errno=85)
    //         sliceOffset=0x00000000, codeBlobOffset=0x00444890, codeBlobSize=0x0000FD50
    //
    //     0x0000FD50 = 64848 = the ORIGINAL Sileo `datasize`, while our
    //     SuperBlob was 61312 bytes. (The UUID in the message was OURS — so
    //     the signature was parsed, and the hashes inside were fine; what was
    //     wrong was the LENGTH the load command advertised.)
    //
    // Both rules together mean: whenever the blob's length differs from what
    // the load command says, we MUST touch page 0 and therefore MUST re-hash.
    // The re-hash produces a blob of the same length (the CodeDirectory
    // layout depends on `code_limit`, which does not change), so the
    // `datasize` we wrote stays correct — and the code below verifies that
    // explicitly instead of assuming it.
    //
    // A stale or corrupt LC_CODE_SIGNATURE can also point PAST EOF (a
    // decrypted or hand-patched binary). `avail` is a size_t subtraction,
    // so it would wrap around to a huge value and the memcpy below would
    // write far past the buffer — a hard crash instead of a clean error.
    // Refuse instead.
    if (sig_dataoff > *len) {
        fprintf(stderr, "rysign: LC_CODE_SIGNATURE.dataoff=%u is past EOF (%zu bytes)\n",
                sig_dataoff, *len);
        ry_buf_free(&req); ry_buf_free(&ent_blob); ry_buf_free(&cd1);
        ry_buf_free(&cd2); ry_buf_free(&cms); ry_buf_free(&sb);
        return -11;
    }
    size_t avail = (*len) - (size_t)sig_dataoff;
    int need_grow = (sb.len > avail);                          // blob doesn't fit
    // The LC's datasize MUST equal the blob's real length — exactly, in both
    // directions. Apple codesign always writes the precise value, and zsign
    // does too (it rebuilds the load command as part of the sign).
    //
    // Leaving a STALE, LARGER datasize behind (the "bare memcpy, don't touch
    // the load commands" shortcut) is what produced the device failure we
    // chased for days:
    //
    //     code signature invalid in <F9EEDC94-…> (errno=85)
    //     sliceOffset=0x00000000, codeBlobOffset=0x00444890, codeBlobSize=0x0000FD50
    //
    // 0x0000FD50 = 64848 — the ORIGINAL Sileo `LC_CODE_SIGNATURE.datasize`.
    // Our SuperBlob was 61312 bytes. The kernel therefore read a 64848-byte
    // "code signature" whose SuperBlob header claims 61312 → the sizes
    // disagree → the whole image is rejected, even though every hash inside
    // is perfectly correct. (The UUID in the message was OURS, which is why
    // it looked like "our signature is broken" — the signature was fine; the
    // LENGTH the load command advertised was not.)
    //
    // Fixing it means touching `datasize`, which lives in page 0, which the
    // CodeDirectory hashes. So the mutation MUST happen BEFORE the hashes are
    // computed — which is exactly what the branch below does: mutate, then
    // re-hash, then rebuild. The rebuilt blob has the same length (the CD
    // layout does not change), so the datasize we just wrote stays correct.
    int need_ds   = (sig_lc->datasize != (uint32_t)sb.len);    // LC length != blob length

    if (!need_grow && !need_ds) {
        // Fits, and the LC already claims EXACTLY the blob's length: a bare
        // memcpy, ZERO load-command mutation (zsign ZArchO::Sign parity).
        memcpy(buf + sig_dataoff, sb.p, sb.len);
        // Hygiene only: blank the tail of the OLD signature region, and
        // never past it — bytes beyond dataoff+datasize can be real
        // __LINKEDIT data (symbol tables etc.), and they sit outside the
        // hashed range anyway.
        size_t old_region = ((size_t)sig_datasize < avail) ? (size_t)sig_datasize : avail;
        if (old_region > sb.len)
            memset(buf + sig_dataoff + sb.len, 0, old_region - sb.len);
    } else {
        // The layout must change. Finalise EVERY hashed byte FIRST.
        if (need_grow) {
            size_t new_len = (size_t)sig_dataoff + sb.len;
            if (linkedit) {
                linkedit->filesize = (uint64_t)new_len - linkedit->fileoff;
                uint64_t new_vmsize = (linkedit->filesize + 0xFFFULL) & ~(uint64_t)0xFFFULL;
                if (new_vmsize > linkedit->vmsize) linkedit->vmsize = new_vmsize;
            } else {
                fprintf(stderr, "rysign: no __LINKEDIT segment; growing file without it\n");
            }
        }
        sig_lc->datasize = (uint32_t)sb.len;
        if (need_grow) {
            unsigned char *nb = (unsigned char *)realloc(buf, (size_t)sig_dataoff + sb.len);
            if (!nb) {
                ry_buf_free(&req); ry_buf_free(&ent_blob); ry_buf_free(&cd1);
                ry_buf_free(&cd2); ry_buf_free(&cms); ry_buf_free(&sb);
                return -7;
            }
            memset(nb + *len, 0, (size_t)sig_dataoff + sb.len - *len);
            buf = nb; *pbuf = nb; *len = (size_t)sig_dataoff + sb.len;
            // hdr/sig_lc/linkedit/textseg now dangle — nothing below
            // dereferences them; the rebuild only reads `buf`.
        }

        // ... then RE-HASH the now-final bytes and rebuild the signature.
        // Only page 0 changed, so every length is identical and the second
        // pass produces a blob of exactly the same size (the LC we just
        // wrote is therefore still correct).
        ry_buf_free(&cd1); ry_buf_free(&cd2); ry_buf_free(&cms); ry_buf_free(&sb);
        if (ry_build_codedirectory(0, buf, code_limit, &meta, is_execute, 0,
                                   exec_seg_base, exec_seg_limit, exec_seg_flags,
                                   &g_hash, &cd1) != 0 ||
            ry_build_codedirectory(1, buf, code_limit, &meta, is_execute, 0,
                                   exec_seg_base, exec_seg_limit, exec_seg_flags,
                                   &g_hash, &cd2) != 0) {
            ry_buf_free(&req); ry_buf_free(&ent_blob);
            ry_buf_free(&cd1); ry_buf_free(&cd2);
            return -4;
        }
        if (build_cms(cd1.p, cd1.len, cd2.p, cd2.len, privKey, certs, cert_lens, n_certs,
                      issuer, issuer_len, serial, serial_len, &cms) != 0) {
            fprintf(stderr, "rysign: build_cms (rebuild pass) failed\n");
            ry_buf_free(&req); ry_buf_free(&ent_blob); ry_buf_free(&cd1);
            ry_buf_free(&cd2); ry_buf_free(&cms);
            return -5;
        }
        if (ry_build_superblob(&cd1, &req, ent_blob.len ? &ent_blob : NULL, NULL,
                               &cd2, &cms, &sb) != 0) {
            ry_buf_free(&req); ry_buf_free(&ent_blob); ry_buf_free(&cd1);
            ry_buf_free(&cd2); ry_buf_free(&cms); ry_buf_free(&sb);
            return -6;
        }
        if (sb.len > (size_t)(*len - (size_t)sig_dataoff)) {
            // Paranoia: the rebuild must not have GROWN (a shrink would be
            // the harmless zsign-stale case; a grow would overflow the
            // region we just told the LC about). Never touches sig_lc —
            // after a grow it dangles.
            fprintf(stderr, "rysign: rebuild grew the blob past the region "
                            "(room %zu, blob %zu)\n",
                    (size_t)(*len - (size_t)sig_dataoff), sb.len);
            ry_buf_free(&req); ry_buf_free(&ent_blob); ry_buf_free(&cd1);
            ry_buf_free(&cd2); ry_buf_free(&cms); ry_buf_free(&sb);
            return -6;
        }
        // The rebuilt blob must be EXACTLY as long as the datasize we wrote
        // above. In practice it is (the CodeDirectory layout depends on
        // `code_limit`, which did not change), but if it ever were not, the
        // load command would advertise a length the blob does not have — the
        // very failure this whole branch exists to prevent. Detect it here
        // rather than on the device.
        //
        // NOTE: `!need_grow` is checked FIRST — after a realloc the `sig_lc`
        // pointer dangles and must not be dereferenced.
        if (!need_grow && sb.len != (size_t)sig_lc->datasize) {
            fprintf(stderr, "rysign: rebuilt blob length %zu != advertised datasize %u\n",
                    sb.len, sig_lc->datasize);
            ry_buf_free(&req); ry_buf_free(&ent_blob); ry_buf_free(&cd1);
            ry_buf_free(&cd2); ry_buf_free(&cms); ry_buf_free(&sb);
            return -6;
        }
        memcpy(buf + sig_dataoff, sb.p, sb.len);
        // Blank the bytes the OLD (larger) signature left behind in the
        // region we no longer claim. They sit outside the advertised
        // datasize, so the kernel never looks at them — but a stale blob
        // fragment there is exactly the kind of thing that makes the next
        // inspection of this binary confusing.
        if (sig_datasize > sb.len) {
            size_t tail = (size_t)sig_datasize - sb.len;
            if ((size_t)sig_dataoff + sb.len + tail <= *len)
                memset(buf + sig_dataoff + sb.len, 0, tail);
        }
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
            unsigned char **grown_c = realloc(certs, sizeof(void *) * (size_t)(nc + g_extra_certs_n));
            size_t *grown_l = realloc(cert_lens, sizeof(size_t) * (size_t)(nc + g_extra_certs_n));
            // Only adopt the new arrays when BOTH grew: a half-migrated pair
            // would leave certs/cert_lens disagreeing about their length.
            if (grown_c && grown_l) {
                certs = grown_c; cert_lens = grown_l;
                for (int i = 0; i < g_extra_certs_n; i++) {
                    // A chain entry that could not be read is NULL with a zero
                    // length; feeding that to memcmp/buf_put is undefined
                    // behaviour (and a NULL deref on some libc), so skip it.
                    if (!g_extra_certs[i] || g_extra_certs_lens[i] == 0) continue;
                    // The provisioning profile's DeveloperCertificates array
                    // repeats the leaf; a duplicated leaf in the CMS cert set can
                    // confuse AMFI's trust evaluation, so skip identical DERs.
                    bool dup = false;
                    for (int j = 0; j < nc; j++) {
                        if (certs[j] && cert_lens[j] == g_extra_certs_lens[i] &&
                            memcmp(certs[j], g_extra_certs[i], g_extra_certs_lens[i]) == 0) {
                            dup = true; break;
                        }
                    }
                    if (dup) continue;
                    certs[nc] = g_extra_certs[i]; cert_lens[nc] = g_extra_certs_lens[i]; nc++;
                }
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
// Building a USABLE private key from raw DER bytes
// ---------------------------------------------------------------------------
// Everything that can disagree here, does:
//   * the key type Swift inferred vs. what the bytes actually are,
//   * raw PKCS#1/SEC1 vs. a PKCS#8 wrapper around the inner key,
//   * "SecKeyCreateWithData succeeded" vs. "this key can actually sign".
//
// That last one is the trap that cost three build cycles on device: a key CAN
// be created successfully and still refuse every signature, which surfaces as
// CMS failure (sub-code -5) — identically for a development AND a distribution
// certificate, which is exactly what the user saw. So every plausible
// combination is tried against a signing CANARY, and only a key that really
// signs its first payload is handed back.

/// Parse the TLV header at `pos` expecting `tag`. Stores the content range and
/// returns the offset just past this value, or 0 when it does not fit.
static size_t tlv_read(const unsigned char *b, size_t len, size_t pos,
                       unsigned char tag, size_t *cpos, size_t *clen) {
    if (pos + 2 > len || b[pos] != tag) return 0;
    size_t p = pos + 1;
    size_t l = b[p];
    if (l & 0x80) {
        size_t nb = l & 0x7f;
        if (nb == 0 || nb > 4 || p + 1 + nb > len) return 0;
        l = 0; p += 1;
        for (size_t i = 0; i < nb; i++) l = (l << 8) | b[p++];
    } else {
        p += 1;
    }
    if (p + l > len) return 0;
    *cpos = p; *clen = l;
    return p + l;
}

/// If `b` is a PKCS#8 PrivateKeyInfo, locate the inner key inside its OCTET
/// STRING. Returns true and fills the inner range on success.
static bool pkcs8_inner(const unsigned char *b, size_t len,
                        size_t *cpos, size_t *clen) {
    if (len < 8 || b[0] != 0x30) return false;
    size_t cp = 0, cl = 0;
    if (!tlv_read(b, len, 0, 0x30, &cp, &cl)) return false;   // PrivateKeyInfo
    size_t q = cp, ep = 0, el = 0;
    q = tlv_read(b, len, q, 0x02, &ep, &el);                  // version INTEGER
    if (q == 0) return false;
    q = tlv_read(b, len, q, 0x30, &ep, &el);                  // privateKeyAlgorithm
    if (q == 0) return false;
    q = tlv_read(b, len, q, 0x04, &ep, &el);                  // privateKey OCTET STRING
    if (q == 0 || el == 0) return false;
    *cpos = ep; *clen = el;
    return true;
}

/// RSA modulus size straight out of the PKCS#1 INTEGER (n leads after version).
static int rsa_modulus_bits(const unsigned char *d, size_t l) {
    int bits = 0;
    size_t cp = 0, cl = 0, q;
    if (!tlv_read(d, l, 0, 0x30, &cp, &cl)) return 0;          // RSAPrivateKey
    q = tlv_read(d, l, cp, 0x02, &cp, &cl);                    // version
    if (!q) return 0;
    q = tlv_read(d, l, q, 0x02, &cp, &cl);                     // modulus n
    if (!q || cl == 0) return 0;
    const unsigned char *m = d + cp; size_t n = cl;
    while (n > 1 && m[0] == 0) { m++; n--; }                   // leading pad
    bits = (int)(n * 8);
    return bits;
}

/// Try to build a SecKey from `d`/`l` read as key type `type`.
///
/// `bitsHint` is the RSA modulus size measured on the PKCS#1 inner (0 when
/// unknown): the whole-PKCS#8 candidate cannot see the modulus directly, but
/// Security is happier when kSecAttrKeySizeInBits is present for RSA.
///
/// The CFError is NEVER dropped: on the device (iPadOS 27 beta, rc=8) this
/// constructor refused every reading of a well-formed key and the log said
/// only "osstatus=-1" — a placeholder this function itself wrote, because the
/// real reason lived in the CFError that was being released unread. Now both
/// the stderr log and the diag buffer carry domain + code + description.
static SecKeyRef try_create_key(const unsigned char *d, size_t l,
                                CFStringRef type, int bitsHint, int *out_os) {
    CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(NULL, 0, NULL, NULL);
    CFDictionarySetValue(attrs, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFDictionarySetValue(attrs, kSecAttrKeyType, type);
    if (CFEqual(type, kSecAttrKeyTypeRSA)) {
        int bits = rsa_modulus_bits(d, l);
        if (bits <= 0) bits = bitsHint;
        if (bits > 0) {
            CFNumberRef num = CFNumberCreate(NULL, kCFNumberIntType, &bits);
            CFDictionarySetValue(attrs, kSecAttrKeySizeInBits, num);
            if (num) CFRelease(num);
        }
    }
    CFDataRef kd = CFDataCreate(NULL, d, (CFIndex)l);
    CFErrorRef err = NULL;
    SecKeyRef k = SecKeyCreateWithData(kd, attrs, &err);
    CFRelease(kd); CFRelease(attrs);
    if (!k) {
        if (out_os) *out_os = (int)-1;
        char dom[128]; dom[0] = '\0';
        char desc[256]; desc[0] = '\0';
        long code = 0;
        if (err) {
            // CFErrorGetDomain is Get semantics (not owned) — do NOT release it.
            CFStringRef ds = CFErrorGetDomain(err);
            if (ds) {
                CFStringGetCString(ds, dom, sizeof(dom), kCFStringEncodingUTF8);
            }
            code = (long)CFErrorGetCode(err);
            CFStringRef dd = CFErrorCopyDescription(err);
            if (dd) {
                CFStringGetCString(dd, desc, sizeof(desc), kCFStringEncodingUTF8);
                CFRelease(dd);
            }
        }
        fprintf(stderr, "rysign: SecKeyCreateWithData(%s, %zu bytes) failed: [%s] code %ld: %s\n",
                CFEqual(type, kSecAttrKeyTypeRSA) ? "RSA" : "EC", l, dom, code, desc);
        // First failure wins: it is the most likely candidate (whole blob,
        // preferred type), so later attempts do not overwrite it.
        if (!g_sign_diag[0]) {
            rysign_set_diag("SecKeyCreateWithData 失败 [%s] 错误码 %ld：%s", dom, code, desc);
        }
    }
    if (err) CFRelease(err);
    return k;
}

/// Canary: a SecKey that cannot sign a four-byte payload will not sign a CMS
/// structure either. Cheap (one SHA-256), so it runs for every candidate.
static bool key_can_sign(SecKeyRef k, int *out_os) {
    static const unsigned char msg[4] = { 0x01, 0x02, 0x03, 0x04 };
    SecKeyAlgorithm algo = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256;
    CFDictionaryRef kat = SecKeyCopyAttributes(k);
    if (kat) {
        CFStringRef kt = (CFStringRef)CFDictionaryGetValue(kat, kSecAttrKeyType);
        if (kt && CFEqual(kt, kSecAttrKeyTypeECSECPrimeRandom))
            algo = kSecKeyAlgorithmECDSASignatureMessageX962SHA256;
        CFRelease(kat);
    }
    CFDataRef d = CFDataCreate(NULL, msg, (CFIndex)sizeof(msg));
    // REAL API: signature is the return value, error via CFErrorRef*. (The
    // old OSStatus/CFDataRef* form here silently rejected every working key.)
    CFErrorRef cferr = NULL;
    CFDataRef sig = SecKeyCreateSignature(k, algo, d, &cferr);
    CFRelease(d);
    if (sig) { CFRelease(sig); return true; }
    if (cferr) {
        if (out_os) *out_os = (int)CFErrorGetCode(cferr);
        CFRelease(cferr);
    } else if (out_os) {
        *out_os = errSecInternalComponent;
    }
    return false;
}

/// Canary self-check for a SecKey the CALLER holds (e.g. a keychain-backed
/// key from `fallbackSecKey`): sign a 4-byte payload and report.
///
/// Deliberately lives in C: the Swift overlay imports
/// `SecKeyCreateSignature`'s error parameter as
/// `UnsafeMutablePointer<Unmanaged<CFError>?>`, which is easy to get wrong —
/// and getting it wrong here inverts success and failure exactly the way the
/// CMS builder used to. In C the real API (CFDataRef return + CFErrorRef*)
/// is unambiguous.
///
/// Writes a short UTF-8 report into a static buffer (valid until the next
/// call — copy it immediately; Swift: String(cString:)):
///   "ok <RSA|ECDSA> <sigBytes> <blockBits>"   signed fine
///   "fail <code> <description>"               a supported algorithm refused
///   "skip"                                    no known algorithm supported
///   "null"                                    NULL key handed in
const char *rysign_canary(SecKeyRef key) {
    static char buf[256];
    if (!key) { snprintf(buf, sizeof(buf), "null"); return buf; }
    SecKeyAlgorithm algs[2];
    const char *names[2];
    algs[0] = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256; names[0] = "RSA";
    algs[1] = kSecKeyAlgorithmECDSASignatureMessageX962SHA256;  names[1] = "ECDSA";
    static const unsigned char msg[4] = { 'R', 'y', 'B', '!' };
    CFDataRef d = CFDataCreate(NULL, msg, (CFIndex)sizeof(msg));
    if (!d) { snprintf(buf, sizeof(buf), "fail cfdata-create"); return buf; }
    for (int i = 0; i < 2; i++) {
        // Ask before feeding: a mismatched algorithm is at best an error and
        // at worst a Security assertion (hard crash) on iOS 27.
        if (!SecKeyIsAlgorithmSupported(key, kSecKeyOperationTypeSign, algs[i])) continue;
        CFErrorRef cferr = NULL;
        CFDataRef sig = SecKeyCreateSignature(key, algs[i], d, &cferr);
        if (sig) {
            snprintf(buf, sizeof(buf), "ok %s %ld %d", names[i],
                     (long)CFDataGetLength(sig), (int)(SecKeyGetBlockSize(key) * 8));
            CFRelease(sig);
            CFRelease(d);
            return buf;
        }
        if (cferr) {
            char desc[160] = {0};
            CFStringRef ds = CFErrorCopyDescription(cferr);
            if (ds) {
                CFStringGetCString(ds, desc, sizeof(desc), kCFStringEncodingUTF8);
                CFRelease(ds);
            }
            snprintf(buf, sizeof(buf), "fail %ld %s",
                     (long)CFErrorGetCode(cferr), desc[0] ? desc : "(no description)");
            CFRelease(cferr);
        } else {
            snprintf(buf, sizeof(buf), "fail %d (no error object)", errSecInternalComponent);
        }
        CFRelease(d);
        return buf;
    }
    CFRelease(d);
    snprintf(buf, sizeof(buf), "skip");
    return buf;
}

/// Try every plausible reading of the key bytes and return one that WORKS.
///
/// Candidates: the input as-is (a PKCS#1/SEC1 inner when that is what the
/// caller staged, or a whole PKCS#8) and — when the input IS a PKCS#8 — its
/// inner key. Each candidate is tried with the caller's preferred key type and
/// then the other one, because "key says RSA but is really EC" (and the
/// reverse) is exactly what a mis-detected p12 produces.
static SecKeyRef create_signing_key(const unsigned char *kd, size_t klen,
                                    bool preferEC, int *out_os) {
    const unsigned char *cands[2]; size_t clens[2]; int nc = 1;
    cands[0] = kd; clens[0] = klen;
    size_t ip = 0, il = 0;
    if (pkcs8_inner(kd, klen, &ip, &il) && il > 0 && il < klen) {
        cands[1] = kd + ip; clens[1] = il; nc = 2;
    }
    // The RSA modulus is only visible in the PKCS#1 inner; carry its size over
    // so the whole-PKCS#8 attempt gets kSecAttrKeySizeInBits too.
    int innerBits = (nc == 2) ? rsa_modulus_bits(cands[1], clens[1]) : 0;
    CFStringRef pref = preferEC ? kSecAttrKeyTypeECSECPrimeRandom : kSecAttrKeyTypeRSA;
    CFStringRef alt  = preferEC ? kSecAttrKeyTypeRSA : kSecAttrKeyTypeECSECPrimeRandom;
    CFStringRef types[2] = { pref, alt };

    SecKeyRef result = NULL;
    for (int c = 0; c < nc && !result; c++) {
        for (int t = 0; t < 2 && !result; t++) {
            SecKeyRef k = try_create_key(cands[c], clens[c], types[t], innerBits, out_os);
            if (!k) continue;
            if (key_can_sign(k, out_os)) {
                result = k;
                if (c > 0 || t > 0)
                    fprintf(stderr, "rysign: usable key found via candidate %d type %d\n", c, t);
            } else {
                fprintf(stderr, "rysign: key from candidate %d type %d exists but cannot sign\n", c, t);
                CFRelease(k);
            }
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// Shared tail of the two material entries (DER key, live SecKey):
// install the trust chain, load the entitlements plist, run the core signer.
// ---------------------------------------------------------------------------
static int sign_bundle_tail(const char *bundlePath,
                            SecCertificateRef leaf, SecKeyRef privKey,
                            const char *team, const char *entitlementsPath,
                            const char *certsDir, const char *provPath) {
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
                free(names[i]);
                // A chain entry that could not be read (NULL, zero length)
                // must NOT enter the CMS: downstream memcmp/buf_put would
                // dereference it. `extra` has room for nn entries, and
                // extra_n only grows for entries that actually landed.
                if (!b || l == 0) { if (b) free(b); continue; }
                extra[extra_n] = b; extra_lens[extra_n] = l; extra_n++;
            }
            if (names) free(names);
        }
    }
    rysign_set_extra_certs(extra, extra_lens, extra_n);

    unsigned char *ent = NULL; size_t ent_len = 0;
    if (entitlementsPath && access(entitlementsPath, F_OK) == 0)
        ent = read_file(entitlementsPath, &ent_len);

    return sign_bundle_core(bundlePath, leaf, privKey, team, ent, ent_len, provPath);
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
    // Recover a key that actually works: raw/PKCS#8 × RSA/EC, each validated by
    // a signing canary (see create_signing_key). Previously this built ONE key
    // from ONE guess and trusted it, which is how a well-formed identity still
    // ended up unable to sign anything.
    g_sign_osstatus = 0;
    SecKeyRef privKey = create_signing_key(kd, klen, keyIsEC ? true : false,
                                           &g_sign_osstatus);
    if (!privKey) {
        fprintf(stderr, "rysign: no usable private key from key DER\n");
        if (!g_sign_diag[0])
            rysign_set_diag("没有任何一把可用私钥（raw/PKCS#8 × RSA/EC 四种组合都试过，最后 osstatus=%d）",
                            g_sign_osstatus);
        CFRelease(certData); CFRelease(leaf); free(cd); free(kd);
        return 8;
    }

    int rc = sign_bundle_tail(bundlePath, leaf, privKey, team,
                              entitlementsPath, certsDir, provPath);

    if (leaf) CFRelease(leaf);
    if (privKey) CFRelease(privKey);
    CFRelease(certData); free(cd); free(kd);
    return rc;
}

// ---------------------------------------------------------------------------
// Sign with a SecKey ALREADY held by the caller (the preferred path)
// ---------------------------------------------------------------------------
// Everything above rebuilds the private key from raw DER bytes with
// `SecKeyCreateWithData`. That round-trip is the weakest link in the chain: the
// reconstructed SecKey can come back with attributes that do not match what the
// original key can perform, and `SecKeyCreateSignature` then refuses — with the
// SAME error for a development AND a distribution certificate, which is exactly
// the symptom the user reported from the device.
//
// When RyBox already holds a real SecIdentity it therefore hands the SecKey
// itself down here and skips the reconstruction entirely.
int rysign_sign_bundle_with_key(const char *bundlePath,
                                SecKeyRef privKey,
                                const char *leafCertDerPath,
                                const char *provPath,
                                const char *entitlementsPath,
                                const char *team,
                                const char *certsDir) {
    g_sign_subcode = 0;
    g_sign_osstatus = 0;
    g_sign_diag[0] = '\0';
    if (!privKey) {
        rysign_set_diag("私钥为空（SecIdentityCopyPrivateKey 没给出密钥）");
        return 8;
    }
    size_t clen = 0;
    unsigned char *cd = read_file(leafCertDerPath, &clen);
    if (!cd || clen == 0) {
        if (cd) free(cd);
        rysign_set_diag("读不到叶子证书 DER（%s）", leafCertDerPath);
        return 7;
    }
    CFDataRef certData = CFDataCreate(NULL, cd, (CFIndex)clen);
    SecCertificateRef leaf = SecCertificateCreateWithData(NULL, certData);
    if (!leaf) {
        CFRelease(certData); free(cd);
        rysign_set_diag("SecCertificateCreateWithData 失败（叶子证书 DER 无法解析）");
        return 7;
    }

    CFRetain(privKey);
    int rc = sign_bundle_tail(bundlePath, leaf, privKey, team,
                              entitlementsPath, certsDir, provPath);
    CFRelease(privKey);

    CFRelease(leaf); CFRelease(certData); free(cd);
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
    // Recover a key that actually works: raw/PKCS#8 × RSA/EC, each validated by
    // a signing canary (see create_signing_key). Previously this built ONE key
    // from ONE guess and trusted it, which is how a well-formed identity still
    // ended up unable to sign anything.
    g_sign_osstatus = 0;
    SecKeyRef privKey = create_signing_key(kd, klen, keyIsEC ? true : false,
                                           &g_sign_osstatus);
    if (!privKey) {
        fprintf(stderr, "rysign: no usable private key from key DER\n");
        if (!g_sign_diag[0])
            rysign_set_diag("没有任何一把可用私钥（raw/PKCS#8 × RSA/EC 四种组合都试过，最后 osstatus=%d）",
                            g_sign_osstatus);
        CFRelease(certData); CFRelease(leaf); free(cd); free(kd);
        return 8;
    }

    int rc = sign_bundle_core(bundlePath, leaf, privKey, NULL, NULL, 0, provPath);

    CFRelease(privKey); CFRelease(leaf); CFRelease(certData);
    free(cd); free(kd);
    return rc;
}
