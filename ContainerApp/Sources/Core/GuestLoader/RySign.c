// RySign — on-device Mach-O code signer for RyBox guest apps.
//
// Re-signs a guest bundle (main executable + embedded dylibs) with the user's
// p12 identity and provisioning profile so the guest passes AMFI when dlopen'd
// inside the (non-jailbroken) RyBox process.
//
// Uses ONLY Security + CommonCrypto + libSystem (no OpenSSL, no third-party
// dependency) so it cross-compiles for iOS with a plain clang invocation and
// bundles as the `codesign` auxiliary executable.
//
// The output is a standard LC_CODE_SIGNATURE SuperBlob containing a
// CodeDirectory (SHA-256, v4 with team id), an embedded-entitlements blob, and a
// CMS/PKCS#7 SignedData (RSA PKCS#1 v1.5 over SHA-256) carrying the cert chain
// — the exact shape AMFI validates.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdint.h>
#include <dirent.h>

#include <CommonCrypto/CommonCrypto.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/arch.h>
#include <libkern/OSByteOrder.h>

#ifndef MH_DYLIB
#define MH_DYLIB 0x6
#endif

// ---- CS magic / slot numbers (from Apple's csblob.h) ----------------------
#define CSMAGIC_EMBEDDED_SIGNATURE 0xFADE0CC0u
#define CSMAGIC_CODEDIRECTORY     0xFADE0C02u
#define CSMAGIC_EMBEDDED_ENTITLEMENTS 0xFADE7171u
#define CSMAGIC_BLOBWRAPPER       0xFADE0B01u
#define CSSLOT_CODEDIRECTORY      0
#define CSSLOT_ENTITLEMENTS       5
#define CSSLOT_SIGNATURESLOT      0x10000u

// ---- Global provisioning-profile pointer (set once per bundle sign) --------
static const unsigned char *g_prov = NULL;
static size_t g_prov_len = 0;

// ---- DER builders --------------------------------------------------------
typedef struct { unsigned char *p; size_t len; size_t cap; } Buf;
static void buf_init(Buf *b){ b->p = malloc(64); b->len = 0; b->cap = 64; }
static void buf_free(Buf *b){ if(b->p){ free(b->p); } b->p = NULL; b->len = 0; b->cap = 0; }
static void buf_reserve(Buf *b, size_t n){
    if (b->len + n > b->cap){ size_t nc = b->cap; while (b->len + n > nc) nc *= 2; b->p = realloc(b->p, nc); b->cap = nc; }
}
static void buf_put(Buf *b, const void *d, size_t n){ buf_reserve(b, n); memcpy(b->p + b->len, d, n); b->len += n; }
static void buf_u8(Buf *b, unsigned char v){ buf_put(b, &v, 1); }
static void buf_be32(Buf *b, uint32_t v){
    unsigned char t[4] = { (v>>24)&0xff, (v>>16)&0xff, (v>>8)&0xff, v&0xff }; buf_put(b, t, 4);
}
static void der_len(Buf *b, size_t n){
    if (n < 0x80){ buf_u8(b, (unsigned char)n); }
    else if (n < 0x100){ buf_u8(b, 0x81); buf_u8(b, (unsigned char)n); }
    else if (n < 0x10000){ buf_u8(b, 0x82); buf_u8(b, (unsigned char)(n>>8)); buf_u8(b, (unsigned char)(n&0xff)); }
    else { buf_u8(b, 0x83); buf_u8(b, (unsigned char)(n>>16)); buf_u8(b, (unsigned char)(n>>8)); buf_u8(b, (unsigned char)(n&0xff)); }
}
static void der_wrap(Buf *out, unsigned char tag, const Buf *c){
    buf_u8(out, tag); der_len(out, c->len); buf_put(out, c->p, c->len);
}
#define der_seq(out, c)  der_wrap(out, 0x30, c)
#define der_set(out, c)  der_wrap(out, 0x31, c)
#define der_octet(out, c) der_wrap(out, 0x04, c)
static void der_int(Buf *b, const unsigned char *d, size_t n){
    // trim leading zero bytes (keep at least one), prepend 0x00 if high bit set
    while (n > 1 && d[0] == 0){ d++; n--; }
    if (d[0] & 0x80){
        Buf t; buf_init(&t); unsigned char z = 0; buf_put(&t, &z, 1); buf_put(&t, d, n);
        der_wrap(b, 0x02, &t); buf_free(&t);
    } else {
        Buf t; buf_init(&t); buf_put(&t, d, n); der_wrap(b, 0x02, &t); buf_free(&t);
    }
}
static void der_oid(Buf *b, const unsigned char *d, size_t n){
    Buf t; buf_init(&t); buf_put(&t, d, n); der_wrap(b, 0x06, &t); buf_free(&t);
}
// [n] IMPLICIT: tag 0xA0 + n
static void der_ctx0(Buf *b, int n, const Buf *c){
    buf_u8(b, (unsigned char)(0xA0 + n)); der_len(b, c->len); buf_put(b, c->p, c->len);
}
// [0] IMPLICIT OCTET STRING (tag 0x80) — used for CMS eContent
static void der_octet_implicit0(Buf *b, const unsigned char *d, size_t n){
    buf_u8(b, 0x80); der_len(b, n); buf_put(b, d, n);
}

// ---- OIDs ----------------------------------------------------------------
static const unsigned char OID_SHA256[]    = {0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01};
static const unsigned char OID_RSA[]       = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01};
static const unsigned char OID_DATA[]      = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x01};
static const unsigned char OID_SIGNED[]    = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x02};
static const unsigned char OID_SHA256RSA[] = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0B};
static const unsigned char OID_CTYPE[]     = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x03};
static const unsigned char OID_MSGDIGEST[] = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x04};

// ---- base64 (for extracting DeveloperCertificates from the profile) -------
static int b64_val(char c){
    if (c>='A'&&c<='Z') return c-'A';
    if (c>='a'&&c<='z') return c-'a'+26;
    if (c>='0'&&c<='9') return c-'0'+52;
    if (c=='+') return 62; if (c=='/') return 63;
    return -1;
}
static int b64_decode(const char *in, size_t inlen, unsigned char *out, size_t outcap, size_t *outlen){
    size_t bits=0, acc=0, o=0;
    for (size_t i=0;i<inlen;i++){
        int v = b64_val(in[i]);
        if (v<0) continue;
        acc = (acc<<6)|v; bits+=6;
        if (bits>=8){ bits-=8; unsigned char b=(acc>>bits)&0xff; if (o<outcap) out[o++]=b; }
    }
    *outlen=o; return 0;
}

// ---- SHA-256 helper ------------------------------------------------------
static void sha256(const unsigned char *d, size_t n, unsigned char out[CC_SHA256_DIGEST_LENGTH]){
    CC_SHA256(d, (CC_LONG)n, out);
}

// ---- Read / write whole file ---------------------------------------------
static unsigned char *read_file(const char *path, size_t *len){
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz < 0){ fclose(f); return NULL; }
    unsigned char *buf = malloc(sz ? (size_t)sz : 1);
    size_t r = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    *len = r; return buf;
}
static int write_file(const char *path, const unsigned char *d, size_t n){
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t w = fwrite(d, 1, n, f);
    fclose(f);
    return (w==n)?0:-1;
}

// ---- Minimal DER cursor (for parsing the leaf certificate) ----------------
typedef struct { const unsigned char *p; size_t len; size_t pos; } Cur;
static int cur_read_len(Cur *c, size_t *out){
    if (c->pos>=c->len) return -1;
    unsigned char b = c->p[c->pos++];
    if (b & 0x80){
        int n = b & 0x7f; size_t v=0;
        for (int i=0;i<n;i++){ if(c->pos>=c->len) return -1; v=(v<<8)|c->p[c->pos++]; }
        *out=v;
    } else *out=b;
    return 0;
}
static int cur_read_tlv(Cur *c, unsigned char *tag, const unsigned char **content, size_t *clen){
    if (c->pos>=c->len) return -1;
    *tag = c->p[c->pos++];
    size_t l; if (cur_read_len(c, &l)!=0) return -1;
    if (c->pos + l > c->len) return -1;
    *content = c->p + c->pos; *clen = l;
    c->pos += l;
    return 0;
}

// Extract (issuer Name DER, serial INTEGER DER) from a certificate DER.
static int parse_cert_ids(const unsigned char *cert, size_t certlen,
                          Buf *issuer, Buf *serial){
    Cur c; c.p=cert; c.len=certlen; c.pos=0;
    unsigned char tag; const unsigned char *content; size_t clen;
    if (cur_read_tlv(&c, &tag, &content, &clen)!=0 || tag!=0x30) return -1; // Certificate SEQUENCE
    Cur t; t.p=content; t.len=clen; t.pos=0;
    if (cur_read_tlv(&t, &tag, &content, &clen)!=0 || tag!=0x30) return -1; // TBSCertificate SEQUENCE
    Cur tbs; tbs.p=content; tbs.len=clen; tbs.pos=0;
    if (tbs.pos<tbs.len && tbs.p[tbs.pos]==0xA0){
        if (cur_read_tlv(&tbs, &tag, &content, &clen)!=0) return -1; // optional [0] version
    }
    if (cur_read_tlv(&tbs, &tag, &content, &clen)!=0 || tag!=0x02) return -1; // serialNumber INTEGER
    buf_put(serial, content, clen);
    if (cur_read_tlv(&tbs, &tag, &content, &clen)!=0) return -1;              // signature alg (skip)
    if (cur_read_tlv(&tbs, &tag, &content, &clen)!=0 || tag!=0x30) return -1; // issuer Name SEQUENCE
    buf_put(issuer, content, clen);
    return 0;
}

// Extract DeveloperCertificates (base64 DER) from a mobileprovision plist text.
static int extract_profile_certs(const unsigned char *prov, size_t provlen,
                                 unsigned char ***out_certs, size_t **out_lens, int *out_n){
    char *text = malloc(provlen+1);
    for (size_t i=0;i<provlen;i++) text[i] = (char)prov[i];
    text[provlen]=0;
    char *key = strstr(text, "DeveloperCertificates");
    if (!key){ free(text); return -1; }
    char *arr = strstr(key, "<array");
    if (!arr){ free(text); return -1; }
    char *end = strstr(arr, "</array>");
    if (!end) end = text + provlen;
    int n=0; for (char *s=arr; s<end; ){ char *d=strstr(s,"<data>"); if(!d||d>=end) break; n++; s=d+6; }
    if (n==0){ free(text); return -1; }
    unsigned char **certs = malloc(sizeof(void*)*n);
    size_t *lens = malloc(sizeof(size_t)*n);
    int k=0;
    for (char *s=arr; s<end; ){
        char *d = strstr(s,"<data>"); if(!d||d>=end) break;
        char *de = strstr(d,"</data>"); if(!de||de>=end) break;
        size_t blen = (size_t)(de - (d+6));
        unsigned char *dec = malloc(blen);
        size_t dl=0;
        b64_decode(d+6, blen, dec, blen, &dl);
        certs[k] = dec; lens[k] = dl; k++;
        s = de + 7;
    }
    free(text);
    *out_certs = certs; *out_lens = lens; *out_n = k;
    return 0;
}

// Extract the provisioning profile's embedded Entitlements dict and wrap it in
// a full XML plist (this is exactly what codesign embeds as the entitlements
// blob). Returns malloc'd buffer, or NULL if not found.
static unsigned char *extract_profile_entitlements(const unsigned char *prov, size_t provlen, size_t *outlen){
    char *text = malloc(provlen+1);
    for (size_t i=0;i<provlen;i++) text[i]=(char)prov[i]; text[provlen]=0;
    char *key = strstr(text, "Entitlements");
    if (!key){ free(text); return NULL; }
    char *dict = strstr(key, "<dict");
    if (!dict){ free(text); return NULL; }
    int depth=0; char *p=dict; char *end=NULL;
    while (*p){
        if (strncmp(p,"<dict",5)==0){ depth++; p+=5; continue; }
        if (strncmp(p,"</dict>",7)==0){ depth--; p+=7; if(depth==0){ end=p; break; } continue; }
        p++;
    }
    if (!end){ free(text); return NULL; }
    size_t dl = (size_t)(end - dict);
    const char *hdr = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n";
    const char *ftr = "\n</plist>\n";
    size_t total = strlen(hdr) + dl + strlen(ftr);
    unsigned char *out = malloc(total);
    size_t o=0;
    memcpy(out+o, hdr, strlen(hdr)); o+=strlen(hdr);
    memcpy(out+o, dict, dl); o+=dl;
    memcpy(out+o, ftr, strlen(ftr)); o+=strlen(ftr);
    free(text);
    *outlen = o;
    return out;
}

static size_t rnd4(size_t v){ return (v + 3) & ~((size_t)3); }

// ---- CodeDirectory (v4 / 0x20400) ----------------------------------------
#pragma pack(push,1)
struct CS_CodeDirectory {
    uint32_t magic;
    uint32_t length;
    uint32_t version;
    uint32_t flags;
    uint32_t hashOffset;
    uint32_t identOffset;
    uint32_t nSpecialSlots;
    uint32_t nCodeSlots;
    uint32_t codeLimit;
    uint8_t  hashSize;
    uint8_t  hashType;
    uint8_t  platform;
    uint8_t  pageSize;
    uint32_t spare2;
    uint32_t scatterOffset;
    uint32_t teamIDOffset;
    uint32_t spare3;
    uint32_t spare4;
    uint32_t spare5;
};
#pragma pack(pop)

static int build_codedirectory(const unsigned char *file, size_t file_len,
                               const char *ident, const char *team,
                               const unsigned char *infoplist, size_t info_len,
                               const unsigned char *ent, size_t ent_len,
                               Buf *out_cd){
    const uint32_t pageSize = 12;               // 2^12 = 4096
    const uint32_t hashSize = CC_SHA256_DIGEST_LENGTH;
    const int nSpecial = 4;                      // Info.plist, Requirements, Resources, Entitlements
    uint32_t codeLimit = (uint32_t)file_len;
    uint32_t nCodeSlots = (codeLimit + ((uint32_t)1<<pageSize) - 1) / ((uint32_t)1<<pageSize);

    size_t ident_len = strlen(ident) + 1;
    size_t team_len = (team && team[0]) ? strlen(team)+1 : 1;

    size_t off_ident = sizeof(struct CS_CodeDirectory);
    size_t off_team = off_ident + rnd4(ident_len);
    size_t off_hashes = off_team + rnd4(team_len);
    size_t total = off_hashes + (size_t)nSpecial*hashSize + (size_t)nCodeSlots*hashSize;

    unsigned char *cd = malloc(total);
    memset(cd, 0, total);
    struct CS_CodeDirectory *c = (struct CS_CodeDirectory*)cd;
    c->magic = OSSwapHostToBigInt32(CSMAGIC_CODEDIRECTORY);
    c->length = OSSwapHostToBigInt32((uint32_t)total);
    c->version = OSSwapHostToBigInt32(0x20400u);
    c->flags = 0;
    c->hashOffset = OSSwapHostToBigInt32((uint32_t)off_hashes);
    c->identOffset = OSSwapHostToBigInt32((uint32_t)off_ident);
    c->nSpecialSlots = OSSwapHostToBigInt32((uint32_t)nSpecial);
    c->nCodeSlots = OSSwapHostToBigInt32(nCodeSlots);
    c->codeLimit = OSSwapHostToBigInt32(codeLimit);
    c->hashSize = (uint8_t)hashSize;
    c->hashType = 2;                              // SHA-256
    c->platform = 0;
    c->pageSize = (uint8_t)pageSize;
    c->spare2 = 0;
    c->scatterOffset = 0;
    c->teamIDOffset = OSSwapHostToBigInt32((uint32_t)(team && team[0] ? off_team : 0));
    c->spare3 = 0; c->spare4 = 0; c->spare5 = 0;

    memcpy(cd + off_ident, ident, strlen(ident)+1);
    if (team && team[0]) memcpy(cd + off_team, team, strlen(team)+1);

    unsigned char *hp = cd + off_hashes;
    unsigned char empty[CC_SHA256_DIGEST_LENGTH];
    sha256((const unsigned char*)"", 0, empty);
    // Special slots are stored in memory in this order:
    //   index0 = slot -4 (Entitlements)
    //   index1 = slot -3 (Resources)
    //   index2 = slot -2 (Requirements)
    //   index3 = slot -1 (Info.plist)
    if (ent && ent_len) sha256(ent, ent_len, hp); else memcpy(hp, empty, hashSize);
    hp += hashSize;                               // -4 entitlements
    memcpy(hp, empty, hashSize); hp += hashSize;  // -3 resources
    memcpy(hp, empty, hashSize); hp += hashSize;  // -2 requirements
    if (infoplist && info_len) sha256(infoplist, info_len, hp); else memcpy(hp, empty, hashSize);
    hp += hashSize;                               // -1 Info.plist

    uint32_t ps = (uint32_t)1 << pageSize;
    for (uint32_t i=0;i<nCodeSlots;i++){
        size_t start = (size_t)i * ps;
        size_t end = start + ps; if (end > file_len) end = file_len;
        size_t plen = end - start;
        unsigned char page[4096]; memset(page, 0, ps);
        memcpy(page, file + start, plen);
        sha256(page, ps, hp);
        hp += hashSize;
    }

    buf_init(out_cd);
    buf_put(out_cd, cd, total);
    free(cd);
    return 0;
}

// ---- CMS / PKCS#7 SignedData over the CodeDirectory ----------------------
static int build_cms(const unsigned char *cd, size_t cd_len,
                     SecKeyRef privKey,
                     unsigned char **certs, size_t *cert_lens, int n_certs,
                     const unsigned char *issuer, size_t issuer_len,
                     const unsigned char *serial, size_t serial_len,
                     Buf *out_cms){
    unsigned char md[CC_SHA256_DIGEST_LENGTH];
    sha256(cd, cd_len, md);

    // signedAttrs — raw concatenation of attributes (no SET tag yet; the SET is
    // used for the signature, and the [0] IMPLICIT form for embedding).
    Buf sa; buf_init(&sa);
    { Buf ct; buf_init(&ct); der_oid(&ct, OID_DATA, sizeof(OID_DATA));
      Buf ctset; buf_init(&ctset); der_set(&ctset, &ct);
      Buf a1; buf_init(&a1); der_oid(&a1, OID_CTYPE, sizeof(OID_CTYPE)); der_set(&a1, &ctset);
      der_wrap(&sa, 0x30, &a1); buf_free(&ct); buf_free(&ctset); buf_free(&a1); }
    { Buf mos; buf_init(&mos); der_octet(&mos, md, sizeof(md));
      Buf mosset; buf_init(&mosset); der_set(&mosset, &mos);
      Buf a2; buf_init(&a2); der_oid(&a2, OID_MSGDIGEST, sizeof(OID_MSGDIGEST)); der_set(&a2, &mosset);
      der_wrap(&sa, 0x30, &a2); buf_free(&mos); buf_free(&mosset); buf_free(&a2); }

    // signature over the DER SET OF Attributes (PKCS#7 rule)
    Buf saSet; buf_init(&saSet); der_set(&saSet, &sa);
    CFDataRef sigData = NULL;
    OSStatus st = SecKeyCreateSignature(privKey,
        kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,
        CFDataCreate(NULL, saSet.p, (CFIndex)saSet.len), &sigData);
    if (st != errSecSuccess){ buf_free(&sa); buf_free(&saSet); return -1; }

    Buf si; buf_init(&si);
    { unsigned char one[1] = {1}; der_int(&si, one, 1); } // version
    // issuerAndSerialNumber
    { Buf iasn; buf_init(&iasn); buf_put(&iasn, issuer, issuer_len);
      der_int(&iasn, serial, serial_len);
      der_wrap(&si, 0x30, &iasn); buf_free(&iasn); }
    // digestAlgorithm (SEQUENCE, not SET)
    { Buf da; buf_init(&da); der_oid(&da, OID_SHA256, sizeof(OID_SHA256));
      Buf daSeq; buf_init(&daSeq); der_wrap(&daSeq, 0x30, &da);
      der_wrap(&si, 0x30, &daSeq); buf_free(&da); buf_free(&daSeq); }
    // signedAttrs [0] IMPLICIT
    der_ctx0(&si, 0, &sa);
    // signatureAlgorithm (sha256WithRSAEncryption)
    { Buf ra; buf_init(&ra); der_oid(&ra, OID_SHA256RSA, sizeof(OID_SHA256RSA));
      Buf raSeq; buf_init(&raSeq); der_wrap(&raSeq, 0x30, &ra);
      der_wrap(&si, 0x30, &raSeq); buf_free(&ra); buf_free(&raSeq); }
    // signature
    der_octet(&si, CFDataGetBytePtr(sigData), (size_t)CFDataGetLength(sigData));
    Buf signerInfo; buf_init(&signerInfo); der_wrap(&signerInfo, 0x30, &si);

    // SignedData
    Buf sd; buf_init(&sd);
    { unsigned char one[1]={1}; der_int(&sd, one, 1); }
    // digestAlgorithms SET OF AlgorithmIdentifier
    { Buf da; buf_init(&da); der_oid(&da, OID_SHA256, sizeof(OID_SHA256));
      Buf daSeq; buf_init(&daSeq); der_wrap(&daSeq, 0x30, &da);
      Buf daSet; buf_init(&daSet); der_set(&daSet, &daSeq);
      buf_put(&sd, daSet.p, daSet.len); buf_free(&da); buf_free(&daSeq); buf_free(&daSet); }
    // encapContentInfo
    { Buf eci; buf_init(&eci); der_oid(&eci, OID_DATA, sizeof(OID_DATA));
      der_octet_implicit0(&eci, cd, cd_len);
      der_wrap(&sd, 0x30, &eci); buf_free(&eci); }
    // certificates [0] IMPLICIT SET OF Certificate
    if (n_certs>0){
        Buf certsConcat; buf_init(&certsConcat);
        for (int i=0;i<n_certs;i++) buf_put(&certsConcat, certs[i], cert_lens[i]);
        der_ctx0(&sd, 0, &certsConcat);
        buf_free(&certsConcat);
    }
    // signerInfos SET OF SignerInfo
    { Buf siSet; buf_init(&siSet); der_set(&siSet, &signerInfo);
      buf_put(&sd, siSet.p, siSet.len); buf_free(&siSet); }

    Buf signedData; buf_init(&signedData); der_wrap(&signedData, 0x30, &sd);
    // ContentInfo
    Buf ci; buf_init(&ci); der_oid(&ci, OID_SIGNED, sizeof(OID_SIGNED));
    der_ctx0(&ci, 0, &signedData);
    Buf ciSeq; buf_init(&ciSeq); der_wrap(&ciSeq, 0x30, &ci);
    buf_init(out_cms); buf_put(out_cms, ciSeq.p, ciSeq.len);

    buf_free(&sa); buf_free(&saSet); buf_free(&si); buf_free(&signerInfo); buf_free(&sd);
    buf_free(&signedData); buf_free(&ci); buf_free(&ciSeq);
    if (sigData) CFRelease(sigData);
    return 0;
}

// ---- SuperBlob assembly --------------------------------------------------
static void make_blob(Buf *out, uint32_t magic, const unsigned char *data, size_t datalen){
    buf_be32(out, OSSwapHostToBigInt32(magic));
    buf_be32(out, OSSwapHostToBigInt32((uint32_t)(8 + datalen)));
    buf_put(out, data, datalen);
}
static int build_superblob(const unsigned char *cd, size_t cd_len,
                           const unsigned char *ent, size_t ent_len,
                           const unsigned char *cms, size_t cms_len,
                           Buf *out){
    int has_ent = (ent && ent_len>0);
    int n = has_ent ? 3 : 2;
    Buf cd_blob; buf_init(&cd_blob); make_blob(&cd_blob, CSMAGIC_CODEDIRECTORY, cd, cd_len);
    Buf ent_blob; buf_init(&ent_blob);
    if (has_ent) make_blob(&ent_blob, CSMAGIC_EMBEDDED_ENTITLEMENTS, ent, ent_len);
    Buf cms_blob; buf_init(&cms_blob); make_blob(&cms_blob, CSMAGIC_BLOBWRAPPER, cms, cms_len);

    size_t idx_size = 8 + (size_t)n*8;
    size_t off_cd = idx_size;
    size_t off_ent = off_cd + cd_blob.len;
    size_t off_cms = off_ent + ent_blob.len;
    size_t total = off_cms + cms_blob.len;

    unsigned char *sb = malloc(total);
    memset(sb, 0, total);
    uint32_t *w = (uint32_t*)sb;
    w[0] = OSSwapHostToBigInt32(CSMAGIC_EMBEDDED_SIGNATURE);
    w[1] = OSSwapHostToBigInt32((uint32_t)total);
    w[2] = OSSwapHostToBigInt32((uint32_t)n);
    uint32_t *idx = w + 3;
    int e = 0;
    idx[e*2]   = OSSwapHostToBigInt32((uint32_t)CSSLOT_CODEDIRECTORY);
    idx[e*2+1] = OSSwapHostToBigInt32((uint32_t)off_cd); e++;
    if (has_ent){
        idx[e*2]   = OSSwapHostToBigInt32((uint32_t)CSSLOT_ENTITLEMENTS);
        idx[e*2+1] = OSSwapHostToBigInt32((uint32_t)off_ent); e++;
    }
    idx[e*2]   = OSSwapHostToBigInt32((uint32_t)CSSLOT_SIGNATURESLOT);
    idx[e*2+1] = OSSwapHostToBigInt32((uint32_t)off_cms); e++;

    memcpy(sb + off_cd, cd_blob.p, cd_blob.len);
    if (has_ent) memcpy(sb + off_ent, ent_blob.p, ent_blob.len);
    memcpy(sb + off_cms, cms_blob.p, cms_blob.len);

    buf_init(out);
    buf_put(out, sb, total);
    free(sb); buf_free(&cd_blob); buf_free(&ent_blob); buf_free(&cms_blob);
    return 0;
}

// ---- Sign a single 64-bit Mach-O (in-place buffer via double pointer) -----
static int sign_slice(unsigned char **pbuf, size_t *len,
                      const char *ident, const char *team,
                      const unsigned char *infoplist, size_t info_len,
                      const unsigned char *ent, size_t ent_len,
                      SecKeyRef privKey,
                      unsigned char **certs, size_t *cert_lens, int n_certs,
                      const unsigned char *issuer, size_t issuer_len,
                      const unsigned char *serial, size_t serial_len){
    unsigned char *buf = *pbuf;
    struct mach_header_64 *hdr = (struct mach_header_64*)buf;
    if (hdr->magic != MH_MAGIC_64) return -1;

    size_t header_size = sizeof(struct mach_header_64);
    uint32_t old_ncmds = hdr->ncmds;
    uint32_t old_sizeofcmds = hdr->sizeofcmds;
    size_t cmds_end = header_size + old_sizeofcmds;

    // strip any pre-existing LC_CODE_SIGNATURE (re-signing safety)
    {
        struct load_command *lc = (struct load_command*)(buf + header_size);
        uint32_t n = old_ncmds;
        for (uint32_t i=0;i<n;i++){
            if (lc->cmd == LC_CODE_SIGNATURE){
                uint32_t csz = lc->cmdsize;
                size_t rest = old_sizeofcmds - (((unsigned char*)lc - (buf+header_size)) + csz);
                memmove(lc, (unsigned char*)lc + csz, rest);
                old_ncmds--; old_sizeofcmds -= csz;
                cmds_end = header_size + old_sizeofcmds;
                hdr->ncmds = old_ncmds; hdr->sizeofcmds = old_sizeofcmds;
                break;
            }
            lc = (struct load_command*)((unsigned char*)lc + lc->cmdsize);
        }
    }

    const size_t LC_SIZE = 16;
    size_t new_code_limit = *len + LC_SIZE;

    // Build new (unsigned) code region: header + old cmds + new LC + shifted data
    unsigned char *nbuf = malloc(new_code_limit);
    memcpy(nbuf, buf, header_size);
    memcpy(nbuf + header_size, buf + header_size, old_sizeofcmds);
    struct load_command *nlc = (struct load_command*)(nbuf + header_size + old_sizeofcmds);
    nlc->cmd = LC_CODE_SIGNATURE;
    nlc->cmdsize = (uint32_t)LC_SIZE;
    ((struct linkedit_data_command*)nlc)->dataoff = (uint32_t)new_code_limit;
    ((struct linkedit_data_command*)nlc)->datasize = 0;
    memcpy(nbuf + header_size + old_sizeofcmds + LC_SIZE, buf + cmds_end, *len - cmds_end);

    struct mach_header_64 *nh = (struct mach_header_64*)nbuf;
    nh->ncmds = old_ncmds + 1;
    nh->sizeofcmds = old_sizeofcmds + (uint32_t)LC_SIZE;

    struct load_command *lc = (struct load_command*)(nbuf + header_size);
    for (uint32_t i=0;i<nh->ncmds;i++){
        if (lc->cmd == LC_SEGMENT_64){
            struct segment_command_64 *seg = (struct segment_command_64*)lc;
            if (seg->fileoff >= (uint64_t)cmds_end) seg->fileoff += LC_SIZE;
            struct section_64 *sects = (struct section_64*)(seg + 1);
            for (uint32_t s=0;s<seg->nsects;s++){
                if (sects[s].offset >= (uint32_t)cmds_end) sects[s].offset += (uint32_t)LC_SIZE;
            }
        }
        lc = (struct load_command*)((unsigned char*)lc + lc->cmdsize);
    }

    // signature over the new code region
    Buf cd; if (build_codedirectory(nbuf, new_code_limit, ident, team, infoplist, info_len, ent, ent_len, &cd)!=0){ free(nbuf); return -2; }
    Buf cms; if (build_cms(cd.p, cd.len, privKey, certs, cert_lens, n_certs, issuer, issuer_len, serial, serial_len, &cms)!=0){ buf_free(&cd); free(nbuf); return -3; }
    Buf ent_blob; buf_init(&ent_blob); if (ent && ent_len) buf_put(&ent_blob, ent, ent_len);
    Buf sb; if (build_superblob(cd.p, cd.len, ent_blob.p, ent_blob.len, cms.p, cms.len, &sb)!=0){ buf_free(&cd); buf_free(&cms); buf_free(&ent_blob); free(nbuf); return -4; }

    ((struct linkedit_data_command*)nlc)->datasize = (uint32_t)sb.len;

    size_t final_len = new_code_limit + sb.len;
    unsigned char *final = malloc(final_len);
    memcpy(final, nbuf, new_code_limit);
    memcpy(final + new_code_limit, sb.p, sb.len);

    free(nbuf); buf_free(&cd); buf_free(&cms); buf_free(&ent_blob); buf_free(&sb);
    free(buf);
    *pbuf = final; *len = final_len;
    return 0;
}

// ---- Sign a whole file (fat or single) -----------------------------------
static int sign_macho_file_at(const char *path, SecIdentityRef identity, SecKeyRef privKey,
                              const char *team, const char *ident,
                              const unsigned char *ent, size_t ent_len){
    size_t len; unsigned char *buf = read_file(path, &len);
    if (!buf) return -1;

    uint32_t magic = *(uint32_t*)buf;

    if (magic == MH_MAGIC_64){
        SecCertificateRef leaf = NULL; SecIdentityCopyCertificate(identity, &leaf);
        Buf issuer; Buf serial; buf_init(&issuer); buf_init(&serial);
        unsigned char **certs=NULL; size_t *clens=NULL; int nc=0;
        if (leaf){
            CFDataRef ld = SecCertificateCopyData(leaf);
            const unsigned char *ldp = CFDataGetBytePtr(ld); size_t ldl = (size_t)CFDataGetLength(ld);
            parse_cert_ids(ldp, ldl, &issuer, &serial);
            certs = malloc(sizeof(void*)); clens = malloc(sizeof(size_t));
            certs[0] = (unsigned char*)ldp; clens[0] = ldl; nc = 1;
            unsigned char **pc=NULL; size_t *pl=NULL; int pn=0;
            if (extract_profile_certs(g_prov, g_prov_len, &pc, &pl, &pn)==0){
                certs = realloc(certs, sizeof(void*)*(1+pn));
                clens = realloc(clens, sizeof(size_t)*(1+pn));
                for (int i=0;i<pn;i++){ certs[1+i]=pc[i]; clens[1+i]=pl[i]; }
                nc = 1+pn;
            }
            int rc = sign_slice(&buf, &len, ident, team, NULL, 0, ent, ent_len,
                                privKey, certs, clens, nc, issuer.p, issuer.len, serial.p, serial.len);
            if (rc==0) write_file(path, buf, len);
            if (ld) CFRelease(ld);
        } else {
            free(buf);
            return -2;
        }
        if (leaf) CFRelease(leaf);
        // buf now points to the signed (final) data; intentionally not freed (one-shot)
        return 0;
    } else if (magic == FAT_MAGIC || magic == FAT_CIGAM){
        int swap = (magic == FAT_CIGAM);
        struct fat_header *fh = (struct fat_header*)buf;
        uint32_t n = swap ? OSSwapInt32(fh->nfat_arch) : fh->nfat_arch;
        typedef struct { unsigned char *b; size_t len; uint32_t cputype, cpusub; int signedd; } Slice;
        Slice *slices = calloc(n, sizeof(Slice));
        struct fat_arch *arch = (struct fat_arch*)(fh+1);
        for (uint32_t i=0;i<n;i++){
            struct fat_arch a = arch[i];
            if (swap){ a.cputype=OSSwapInt32(a.cputype); a.cpusubtype=OSSwapInt32(a.cpusubtype); a.offset=OSSwapInt32(a.offset); a.size=OSSwapInt32(a.size); }
            slices[i].cputype=a.cputype; slices[i].cpusub=a.cpusubtype; slices[i].off=a.offset; slices[i].size=a.size;
            if (a.cputype==CPU_TYPE_ARM64){
                unsigned char *sb = malloc(a.size);
                memcpy(sb, buf+a.offset, a.size);
                size_t sl = a.size;
                SecCertificateRef leaf=NULL; SecIdentityCopyCertificate(identity,&leaf);
                Buf issuer; Buf serial; buf_init(&issuer); buf_init(&serial);
                unsigned char **certs=NULL; size_t *clens=NULL; int nc=0;
                if (leaf){
                    CFDataRef ld=SecCertificateCopyData(leaf); const unsigned char*ldp=CFDataGetBytePtr(ld); size_t ldl=CFDataGetLength(ld);
                    parse_cert_ids(ldp,ldl,&issuer,&serial);
                    certs=malloc(sizeof(void*)); clens=malloc(sizeof(size_t)); certs[0]=(unsigned char*)ldp; clens[0]=ldl; nc=1;
                    unsigned char **pc=NULL; size_t *pl=NULL; int pn=0;
                    if (extract_profile_certs(g_prov,g_prov_len,&pc,&pl,&pn)==0){ certs=realloc(certs,sizeof(void*)*(1+pn)); clens=realloc(clens,sizeof(size_t)*(1+pn)); for(int j=0;j<pn;j++){certs[1+j]=pc[j];clens[1+j]=pl[j];} nc=1+pn; }
                    sign_slice(&sb, &sl, ident, team, NULL, 0, ent, ent_len, privKey, certs, clens, nc, issuer.p, issuer.len, serial.p, serial.len);
                    if (ld) CFRelease(ld);
                }
                if (leaf) CFRelease(leaf);
                slices[i].b=sb; slices[i].len=sl; slices[i].signedd=1;
            } else {
                slices[i].b = malloc(a.size); memcpy(slices[i].b, buf+a.offset, a.size); slices[i].len=a.size;
            }
        }
        size_t align = 0x4000;
        size_t head = sizeof(struct fat_header) + n*sizeof(struct fat_arch);
        size_t cur = (head + align - 1) & ~(align-1);
        size_t totalsize = cur;
        for (uint32_t i=0;i<n;i++){ totalsize = (totalsize + slices[i].len + align -1) & ~(align-1); }
        unsigned char *nf = malloc(totalsize);
        memset(nf, 0, totalsize);
        struct fat_header *nfh = (struct fat_header*)nf;
        nfh->magic = OSSwapHostToBigInt32(FAT_MAGIC);
        nfh->nfat_arch = OSSwapHostToBigInt32(n);
        struct fat_arch *na = (struct fat_arch*)(nfh+1);
        cur = (head + align -1) & ~(align-1);
        for (uint32_t i=0;i<n;i++){
            na[i].cputype = OSSwapHostToBigInt32(slices[i].cputype);
            na[i].cpusubtype = OSSwapHostToBigInt32(slices[i].cpusub);
            na[i].offset = OSSwapHostToBigInt32((uint32_t)cur);
            na[i].size = OSSwapHostToBigInt32((uint32_t)slices[i].len);
            na[i].align = OSSwapHostToBigInt32(14);
            na[i].reserved = 0;
            memcpy(nf+cur, slices[i].b, slices[i].len);
            cur = (cur + slices[i].len + align - 1) & ~(align-1);
        }
        write_file(path, nf, totalsize);
        for (uint32_t i=0;i<n;i++) free(slices[i].b);
        free(slices); free(nf); free(buf);
        return 0;
    }
    free(buf);
    return -9;
}

// ---- Recursively sign every Mach-O under a directory ----------------------
static int is_macho_at(const char *path){
    size_t n; unsigned char *b = read_file(path, &n);
    if (!b) return 0;
    int r = 0;
    if (n >= 4){
        uint32_t m = *(uint32_t*)b;
        if (m==MH_MAGIC_64 || m==FAT_MAGIC || m==FAT_CIGAM) r = 1;
    }
    free(b);
    return r;
}
static void sign_walk(const char *dir, SecIdentityRef identity, SecKeyRef privKey,
                      const char *team, const char *ident,
                      const unsigned char *ent, size_t ent_len){
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d)) != NULL){
        if (de->d_name[0]=='.') continue;
        char path[2048];
        snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        struct stat st;
        if (stat(path, &st)!=0) continue;
        if (S_ISDIR(st.st_mode)){
            sign_walk(path, identity, privKey, team, ident, ent, ent_len);
        } else if (S_ISREG(st.st_mode)){
            if (is_macho_at(path)){
                sign_macho_file_at(path, identity, privKey, team, ident, ent, ent_len);
            }
        }
    }
    closedir(d);
}

// ---- Bundle signing entry ------------------------------------------------
int rysign_sign_bundle(const char *bundlePath,
                       const char *p12Path,
                       const char *password,
                       const char *provPath,
                       const char *entitlementsPath){
    // 1. Read p12 -> identity + private key
    size_t plen; unsigned char *p12 = read_file(p12Path, &plen);
    if (!p12) { fprintf(stderr, "rysign: cannot read p12\n"); return 2; }
    CFDataRef p12Data = CFDataCreate(NULL, p12, (CFIndex)plen);
    SecIdentityRef identity = NULL; SecKeyRef privKey = NULL;
    {
        CFStringRef pw = CFStringCreateWithCString(NULL, password, kCFStringEncodingUTF8);
        const void *keys[] = { kSecImportExportPassphrase };
        const void *vals[] = { pw };
        CFDictionaryRef opts = CFDictionaryCreate(NULL, keys, vals, 1, NULL, NULL);
        CFArrayRef items = NULL;
        OSStatus st = SecPKCS12Import(p12Data, opts, &items);
        if (st != errSecSuccess){
            fprintf(stderr, "rysign: SecPKCS12Import failed (%d)\n", (int)st);
            CFRelease(p12Data); free(p12); if(pw)CFRelease(pw); if(opts)CFRelease(opts);
            return 3;
        }
        CFDictionaryRef dict = CFArrayGetValueAtIndex(items, 0);
        identity = (SecIdentityRef)CFDictionaryGetValue(dict, kSecImportItemIdentity);
        CFRetain(identity);
        if (pw) CFRelease(pw); if (opts) CFRelease(opts); if (items) CFRelease(items);
    }
    CFRelease(p12Data);
    SecIdentityCopyPrivateKey(identity, &privKey);

    // 2. Provisioning profile
    size_t provlen; unsigned char *prov = read_file(provPath, &provlen);
    if (!prov){ fprintf(stderr, "rysign: cannot read provisioning\n"); if(identity)CFRelease(identity); if(privKey)CFRelease(privKey); free(p12); return 4; }
    g_prov = prov; g_prov_len = provlen;

    // team id
    char team[64] = {0};
    {
        char *text = malloc(provlen+1);
        for (size_t i=0;i<provlen;i++) text[i]=(char)prov[i]; text[provlen]=0;
        char *ti = strstr(text, "TeamIdentifier");
        if (ti){
            char *arr = strstr(ti, "<array");
            char *sa = arr ? strstr(arr, "<string") : NULL;
            if (sa){
                char *se = strstr(sa, "</string>");
                if (se){ size_t l = (size_t)(se - (sa+8)); if (l < sizeof(team)){ memcpy(team, sa+8, l); team[l]=0; } }
            }
        }
        free(text);
    }

    // 3. entitlements (explicit file preferred, else from profile)
    unsigned char *ent = NULL; size_t ent_len = 0;
    if (entitlementsPath && access(entitlementsPath, F_OK)==0){
        ent = read_file(entitlementsPath, &ent_len);
    }
    if (!ent){
        ent = extract_profile_entitlements(prov, provlen, &ent_len);
    }

    // 4. main executable + bundle id from Info.plist
    char exe_path[2048];
    snprintf(exe_path, sizeof(exe_path), "%s/Info.plist", bundlePath);
    unsigned char *info = NULL; size_t info_len = 0;
    info = read_file(exe_path, &info_len);
    char bid[256]={0};
    if (info){
        char *t = malloc(info_len+1); for(size_t i=0;i<info_len;i++) t[i]=(char)info[i]; t[info_len]=0;
        char *fe = strstr(t, "CFBundleExecutable");
        if (fe){ char *s=strstr(fe,"<string"); if(s){ char *e=strstr(s+7,"</string>"); if(e){ size_t l=(size_t)(e-(s+7)); char exen[1024]={0}; if(l<1024){memcpy(exen,s+7,l);} snprintf(exe_path,sizeof(exe_path),"%s/%s",bundlePath,exen); } } }
        char *bi = strstr(t, "CFBundleIdentifier");
        if (bi){ char *s=strstr(bi,"<string"); if(s){ char *e=strstr(s+7,"</string>"); if(e){ size_t l=(size_t)(e-(s+7)); if(l<256){memcpy(bid,s+7,l);} } } }
        free(t); free(info);
    }
    if (access(exe_path, F_OK)!=0){
        fprintf(stderr, "rysign: cannot locate main executable in bundle\n");
        if(identity)CFRelease(identity); if(privKey)CFRelease(privKey); free(p12); free(prov); if(ent)free(ent);
        return 5;
    }
    int rc = sign_macho_file_at(exe_path, identity, privKey, team, bid, ent, ent_len);
    if (rc != 0){ fprintf(stderr, "rysign: sign main exe failed (%d)\n", rc); if(identity)CFRelease(identity); if(privKey)CFRelease(privKey); free(p12); free(prov); if(ent)free(ent); return 6; }

    // 5. sign frameworks / plugins dylibs
    const char *subdirs[] = { "Frameworks", "PlugIns", "SwiftSupport" };
    for (int s=0;s<3;s++){
        char d[2048]; snprintf(d,sizeof(d),"%s/%s",bundlePath,subdirs[s]);
        sign_walk(d, identity, privKey, team, bid, ent, ent_len);
    }

    // 6. embed provisioning profile (AMFI requires profile to match signature)
    char emb[2048]; snprintf(emb,sizeof(emb),"%s/embedded.mobileprovision",bundlePath);
    write_file(emb, prov, provlen);

    if (identity) CFRelease(identity);
    if (privKey) CFRelease(privKey);
    free(p12); free(prov); if (ent) free(ent);
    return 0;
}

// ---- main() --------------------------------------------------------------
int main(int argc, char **argv){
    const char *p12=NULL, *pw="", *prov=NULL, *ent=NULL, *bundle=NULL;
    for (int i=1;i<argc;i++){
        if (!strcmp(argv[i],"--p12") && i+1<argc) p12=argv[++i];
        else if (!strcmp(argv[i],"--password") && i+1<argc) pw=argv[++i];
        else if (!strcmp(argv[i],"--prov") && i+1<argc) prov=argv[++i];
        else if (!strcmp(argv[i],"--entitlements") && i+1<argc) ent=argv[++i];
        else if (!strcmp(argv[i],"--bundle") && i+1<argc) bundle=argv[++i];
        else if (argv[i][0]!='-') bundle=argv[i];
    }
    if (!p12 || !prov || !bundle){
        fprintf(stderr, "usage: rysign --p12 <p12> --password <pw> --prov <mobileprovision> [--entitlements <plist>] --bundle <app>\n");
        return 1;
    }
    return rysign_sign_bundle(bundle, p12, pw, prov, ent);
}
