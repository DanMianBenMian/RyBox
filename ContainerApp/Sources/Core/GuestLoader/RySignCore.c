// RySignCore — implementation. See RySignCore.h for the measured ground truth
// this file encodes.

#include "RySignCore.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ---------------------------------------------------------------------------
// Byte buffer
// ---------------------------------------------------------------------------

void ry_buf_init(RyBuf *b) {
    b->p = (unsigned char *)malloc(256);
    b->len = 0;
    b->cap = b->p ? 256 : 0;
}

void ry_buf_free(RyBuf *b) {
    if (b->p) free(b->p);
    b->p = NULL;
    b->len = 0;
    b->cap = 0;
}

static void ry_buf_reserve(RyBuf *b, size_t n) {
    if (b->p && b->len + n <= b->cap) return;
    size_t nc = b->cap ? b->cap : 256;
    while (b->len + n > nc) nc *= 2;
    unsigned char *np = (unsigned char *)realloc(b->p, nc);
    if (!np) return;                     // out of memory: keep the old buffer
    b->p = np;
    b->cap = nc;
}

void ry_buf_put(RyBuf *b, const void *d, size_t n) {
    if (!b->p) ry_buf_init(b);
    ry_buf_reserve(b, n);
    if (!b->p) return;
    memcpy(b->p + b->len, d, n);
    b->len += n;
}

void ry_buf_u8(RyBuf *b, unsigned char v) { ry_buf_put(b, &v, 1); }

void ry_buf_be32(RyBuf *b, uint32_t v) {
    unsigned char t[4] = { (unsigned char)(v >> 24), (unsigned char)(v >> 16),
                           (unsigned char)(v >> 8),  (unsigned char)v };
    ry_buf_put(b, t, 4);
}

void ry_buf_be64(RyBuf *b, uint64_t v) {
    unsigned char t[8];
    for (int i = 0; i < 8; i++) t[i] = (unsigned char)(v >> (56 - 8 * i));
    ry_buf_put(b, t, 8);
}

// ---------------------------------------------------------------------------
// base64 (for the `cdhashes` plist)
// ---------------------------------------------------------------------------

static const char kB64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void ry_base64(const unsigned char *in, size_t n, char *out, size_t outcap) {
    size_t o = 0;
    size_t i = 0;
    while (i + 3 <= n && o + 4 < outcap) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[o++] = kB64[(v >> 18) & 0x3f];
        out[o++] = kB64[(v >> 12) & 0x3f];
        out[o++] = kB64[(v >> 6) & 0x3f];
        out[o++] = kB64[v & 0x3f];
        i += 3;
    }
    if (i < n && o + 4 < outcap) {
        uint32_t v = (uint32_t)in[i] << 16;
        int rem = (int)(n - i);
        if (rem > 1) v |= (uint32_t)in[i + 1] << 8;
        out[o++] = kB64[(v >> 18) & 0x3f];
        out[o++] = kB64[(v >> 12) & 0x3f];
        out[o++] = (rem > 1) ? kB64[(v >> 6) & 0x3f] : '=';
        out[o++] = '=';
    }
    if (o < outcap) out[o] = 0;
}

// ---------------------------------------------------------------------------
// Requirements
// ---------------------------------------------------------------------------
//
// The designated requirement (DR) is a fixed byte template — LiveContainer's
// vendored zsign (`ZSign::SlotBuildRequirements`, lc_signing.cpp:136) builds
// the exact same bytes for every single app it signs, so this is the only
// reference that matters. The template is:
//
//   magic1  fade0c01                     (CSMAGIC_REQUIREMENTS)
//   uLength1
//   pack1   00000001 00000003 00000014    count=1, type=3 (designated), off=20
//   magic2  fade0c00                     (CSMAGIC_REQUIREMENT)
//   uLength2
//   pack2   00000001 00000006 00000002
//   uBundldIDLength  + padded bundle id
//   pack3   00000006 0000000f 00000006 0000000b 00000000 00000000
//            0000000a "subject.CN" 00000000 00000001
//   uSubjectCNLength  + padded subject CN
//   pack4   0000000e 00000001 0000000a
//            2a 86 48 86 f7 63 64 06 02 01 00000000 00000000
//
// Semantically: opAnd(opIdent(bundleID), opAnd(opAppleGenericAnchor,
// opAnd(opCertField(slot0,"subject.CN",equal,CN), opCertGeneric(slot1,WWDR-OID,exists)))).
//
// NOTE: strings are padded with NULs to a 4-byte boundary, but the *length*
// field keeps the UNPADDED length — that asymmetry is what zsign does and
// what the kernel's requirement parser expects.
//
// An earlier revision of this file hand-built an opTrue-prefixed expression
// tree instead. It was WRONG: the kernel's requirement parser rejected it and
// the whole signature was refused. This template is copied byte-for-byte from
// zsign, which is what LiveContainer ships and what AMFI accepts in the
// field.
int ry_build_requirements(const RySignMeta *meta, RyBuf *out) {
    if (!meta || !out) return -1;
    ry_buf_init(out);

    const char *bundle = (meta->bundle_id && meta->bundle_id[0]) ? meta->bundle_id : NULL;
    const char *cn = (meta->subject_cn && meta->subject_cn[0]) ? meta->subject_cn : NULL;

    // zsign's ldid-style empty requirement set: magic + length(12) + count(0).
    if (!bundle || !cn) {
        ry_buf_be32(out, RY_CSMAGIC_REQUIREMENTS);
        ry_buf_be32(out, 12);
        ry_buf_be32(out, 0);
        return 0;
    }

    static const unsigned char pack1[] = {
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x14
    };
    static const unsigned char pack2[] = {
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x02
    };
    static const unsigned char pack3[] = {
        0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x06,
        0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
        0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x2e, 0x43, 0x4e,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    static const unsigned char pack4[] = {
        0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0a,
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x02, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    size_t bundle_len = strlen(bundle);
    size_t cn_len = strlen(cn);
    size_t bundle_pad = (4 - (bundle_len % 4)) % 4;
    size_t cn_pad = (4 - (cn_len % 4)) % 4;

    // Lengths, computed exactly like zsign does.
    uint32_t uLength2 = (uint32_t)(sizeof(pack2) + 4 + sizeof(pack3) + 4 + sizeof(pack4)
                                  + 4 + bundle_len + bundle_pad
                                  + 4 + cn_len + cn_pad);
    uint32_t uLength1 = (uint32_t)(sizeof(pack1) + 4 + 4 + uLength2);

    ry_buf_be32(out, RY_CSMAGIC_REQUIREMENTS);   // magic1
    ry_buf_be32(out, uLength1);
    ry_buf_put(out, pack1, sizeof(pack1));
    ry_buf_be32(out, RY_CSMAGIC_REQUIREMENT);    // magic2
    ry_buf_be32(out, uLength2);
    ry_buf_put(out, pack2, sizeof(pack2));
    ry_buf_be32(out, (uint32_t)bundle_len);       // unpadded length
    ry_buf_put(out, bundle, bundle_len);
    for (size_t i = 0; i < bundle_pad; i++) ry_buf_u8(out, 0);
    ry_buf_put(out, pack3, sizeof(pack3));
    ry_buf_be32(out, (uint32_t)cn_len);           // unpadded length
    ry_buf_put(out, cn, cn_len);
    for (size_t i = 0; i < cn_pad; i++) ry_buf_u8(out, 0);
    ry_buf_put(out, pack4, sizeof(pack4));
    return 0;
}

// ---------------------------------------------------------------------------
// CodeDirectory
// ---------------------------------------------------------------------------

#define RY_CD_VERSION   0x20400u
#define RY_CD_PAGE_LOG  12u                  // 4096-byte pages
#define RY_CD_HEADER_LEN 88u
#define RY_CD_FLAG_ADHOC 0x0002u

/// The header is written field by field (big-endian) rather than through a
/// struct, because Apple's `CS_CodeDirectory` at 0x20400 is 88 bytes and its
/// last four fields are 64-bit — a hand-written struct with the wrong field
/// types silently produces a 64-byte header, which AMFI rejects.
///
/// `is_adhoc` sets CS_SEC_CODESIGNATURE_ADHOC (zsign's `isAdhoc`).
int ry_build_codedirectory(int alternate,
                           const unsigned char *code, size_t code_len,
                           const RySignMeta *meta,
                           int is_execute, int is_adhoc,
                           uint64_t exec_seg_base, uint64_t exec_seg_limit,
                           uint64_t exec_seg_flags,
                           const RySignHash *hash,
                           RyBuf *out) {
    if (!meta || !hash || !out || !code) return -1;
    if (!meta->bundle_id || !meta->bundle_id[0]) return -1;
    if (!hash->sha1 || !hash->sha256) return -1;

    const uint32_t hash_size = alternate ? 32u : 20u;
    const uint8_t  hash_type = alternate ? RY_HASH_SHA256 : RY_HASH_SHA1;
    const RyHashFn  hasher    = alternate ? hash->sha256 : hash->sha1;

    const uint32_t page_size = 1u << RY_CD_PAGE_LOG;
    uint32_t n_code = (uint32_t)((code_len + page_size - 1) / page_size);

    // ---- special slots ----------------------------------------------------
    //
    // Slot -k lives at `hashOffset - k*hashSize`, so the array is built in
    // DESCENDING slot order: index 0 is the most negative slot.
    //
    // The measured semantics (validated byte-for-byte against the official
    // Sileo signature, see ContainerApp/tools/golden_check.py):
    //   -1 Info.plist FILE BYTES       -5 Entitlements blob (WHOLE)
    //   -2 Requirements blob (WHOLE)    -6 empty
    //   -3 CodeResources FILE BYTES     -7 DER entitlements blob (WHOLE)
    //   -4 empty
    //
    // The three "WHOLE" ones hash the complete blob INCLUDING its 8-byte
    // magic+length header — that is why the metadata carries the finished
    // blobs rather than raw payloads.
    //
    // The array layout below is zsign's `arrSpecialSlots` verbatim: every
    // slot is pushed unconditionally, an absent one contributing an all-zero
    // hash. The DER-entitlements pair (-7/-6) is only pushed for a main
    // executable — a MH_DYLIB guest has five slots (-5..-1).
    unsigned char empty[32];
    memset(empty, 0, sizeof(empty));

    unsigned char sp_info[32], sp_req[32], sp_res[32], sp_ent[32], sp_der[32];
    memset(sp_info, 0, sizeof(sp_info));
    memset(sp_req, 0, sizeof(sp_req));
    memset(sp_res, 0, sizeof(sp_res));
    memset(sp_ent, 0, sizeof(sp_ent));
    memset(sp_der, 0, sizeof(sp_der));

    if (meta->info_plist && meta->info_plist_len)
        hasher(meta->info_plist, meta->info_plist_len, sp_info);
    if (meta->code_resources && meta->code_resources_len)
        hasher(meta->code_resources, meta->code_resources_len, sp_res);
    if (meta->requirements_blob && meta->requirements_blob_len)
        hasher(meta->requirements_blob, meta->requirements_blob_len, sp_req);
    if (meta->entitlements_blob && meta->entitlements_blob_len)
        hasher(meta->entitlements_blob, meta->entitlements_blob_len, sp_ent);
    if (meta->der_entitlements_blob && meta->der_entitlements_blob_len)
        hasher(meta->der_entitlements_blob, meta->der_entitlements_blob_len, sp_der);

    unsigned char slots[8][32];
    int n_slots = 0;

    // -7 DER entitlements, -6 empty  (main executable only)
    if (is_execute) {
        memcpy(slots[n_slots], sp_der, 32); n_slots++;
        memcpy(slots[n_slots], empty, 32); n_slots++;
    }
    // -5 entitlements, -4 empty
    memcpy(slots[n_slots], sp_ent, 32); n_slots++;
    memcpy(slots[n_slots], empty, 32); n_slots++;
    // -3 code resources
    memcpy(slots[n_slots], sp_res, 32); n_slots++;
    // -2 requirements
    memcpy(slots[n_slots], sp_req, 32); n_slots++;
    // -1 info.plist
    memcpy(slots[n_slots], sp_info, 32); n_slots++;

    // Trim the empty run at the MOST-NEGATIVE end of the array.
    //
    // This mirrors zsign's
    //     itLastUsedSpecialSlot = find_if(begin, end, sha != emptySHA);
    //     arrSpecialSlots.erase(begin, itLastUsedSpecialSlot);
    // i.e. the leading all-zero entries are dropped. Because the array is in
    // descending slot order, dropping entries from its FRONT removes the
    // most-negative slots — exactly the ones that are absent.
    //
    // Note that only a CONTIGUOUS leading run is removed: a hole in the
    // middle (e.g. slot -4, which is always empty) stays, because the slot
    // numbering must remain contiguous.
    {
        int first_used = 0;
        while (first_used < n_slots) {
            int all_zero = 1;
            for (uint32_t i = 0; i < hash_size; i++) {
                if (slots[first_used][i]) { all_zero = 0; break; }
            }
            if (!all_zero) break;
            first_used++;
        }
        if (first_used > 0) {
            memmove(slots[0], slots[first_used],
                    (size_t)(n_slots - first_used) * 32);
            n_slots -= first_used;
        }
    }

    // ---- layout -----------------------------------------------------------
    size_t ident_len = strlen(meta->bundle_id) + 1;
    size_t team_len = (meta->team_id && meta->team_id[0]) ? strlen(meta->team_id) + 1 : 0;

    size_t off_ident   = RY_CD_HEADER_LEN;
    size_t off_team    = off_ident + ident_len;
    size_t off_special = off_team + team_len;
    size_t off_hashes  = off_special + (size_t)n_slots * hash_size;
    size_t total       = off_hashes + (size_t)n_code * hash_size;

    unsigned char *cd = (unsigned char *)malloc(total);
    if (!cd) return -1;
    memset(cd, 0, total);

    // --- header (all big-endian) ---
    unsigned char *p = cd;
    #define RY_PUT_BE32(dst, v) do { \
        (dst)[0] = (unsigned char)((v) >> 24); (dst)[1] = (unsigned char)((v) >> 16); \
        (dst)[2] = (unsigned char)((v) >> 8);  (dst)[3] = (unsigned char)(v); } while (0)
    #define RY_PUT_BE64(dst, v) do { \
        for (int _i = 0; _i < 8; _i++) (dst)[_i] = (unsigned char)((v) >> (56 - 8 * _i)); } while (0)

    RY_PUT_BE32(p + 0,  RY_CSMAGIC_CODEDIRECTORY);      // magic
    RY_PUT_BE32(p + 4,  (uint32_t)total);               // length
    RY_PUT_BE32(p + 8,  RY_CD_VERSION);                 // version
    RY_PUT_BE32(p + 12, is_adhoc ? RY_CD_FLAG_ADHOC : 0u); // flags
    RY_PUT_BE32(p + 16, (uint32_t)off_hashes);          // hashOffset
    RY_PUT_BE32(p + 20, (uint32_t)off_ident);           // identOffset
    RY_PUT_BE32(p + 24, (uint32_t)n_slots);             // nSpecialSlots
    RY_PUT_BE32(p + 28, n_code);                        // nCodeSlots
    RY_PUT_BE32(p + 32, (uint32_t)code_len);            // codeLimit
    p[36] = (unsigned char)hash_size;                   // hashSize
    p[37] = (unsigned char)hash_type;                   // hashType
    p[38] = 0;                                          // spare1
    p[39] = (unsigned char)RY_CD_PAGE_LOG;              // pageSize (log2)
    RY_PUT_BE32(p + 40, 0);                             // spare2
    RY_PUT_BE32(p + 44, 0);                             // scatterOffset
    RY_PUT_BE32(p + 48, team_len ? (uint32_t)off_team : 0);  // teamOffset
    RY_PUT_BE32(p + 52, 0);                             // spare3
    RY_PUT_BE64(p + 56, 0);                             // codeLimit64
    RY_PUT_BE64(p + 64, exec_seg_base);                // execSegBase (__TEXT vmaddr)
    RY_PUT_BE64(p + 72, exec_seg_limit);                // execSegLimit
    RY_PUT_BE64(p + 80, exec_seg_flags);                // execSegFlags
    #undef RY_PUT_BE32
    #undef RY_PUT_BE64

    memcpy(cd + off_ident, meta->bundle_id, ident_len);
    if (team_len) memcpy(cd + off_team, meta->team_id, team_len);

    // The array was built with -7 first and -1 last, so writing it in order
    // puts -1 at the highest address — i.e. exactly `hashOffset - 1*hashSize`.
    for (int i = 0; i < n_slots; i++) {
        memcpy(cd + off_special + (size_t)i * hash_size, slots[i], hash_size);
    }

    // ---- code slots -------------------------------------------------------
    //
    // IMPORTANT: the LAST page hashes only its REAL bytes — it is NOT zero
    // padded to the page size. Verified against the official Sileo
    // signature: codeLimit=4475024 → 1092 full pages + 2192 remaining bytes,
    // and the final slot is SHA1 of exactly those 2192 bytes.
    unsigned char *hp = cd + off_hashes;
    uint32_t n_full = (uint32_t)(code_len / page_size);
    uint32_t rem    = (uint32_t)(code_len % page_size);
    for (uint32_t i = 0; i < n_full; i++) {
        hasher(code + (size_t)i * page_size, page_size, hp);
        hp += hash_size;
    }
    if (rem) {
        hasher(code + (size_t)n_full * page_size, rem, hp);
        hp += hash_size;
    }

    ry_buf_init(out);
    ry_buf_put(out, cd, total);
    free(cd);
    return 0;
}

// ---------------------------------------------------------------------------
// SuperBlob
// ---------------------------------------------------------------------------

/// A generic blob inside the SuperBlob: 8-byte header (magic + length) then
/// the payload.
static void ry_put_blob(RyBuf *out, uint32_t magic, const unsigned char *data, size_t len) {
    ry_buf_be32(out, magic);
    ry_buf_be32(out, (uint32_t)(8 + len));
    if (data && len) ry_buf_put(out, data, len);
}

int ry_build_superblob(const RyBuf *cd, const RyBuf *requirements,
                       const RyBuf *ents, const RyBuf *der_ents,
                       const RyBuf *alt_cd, const RyBuf *cms,
                       RyBuf *out) {
    if (!cd || !out) return -1;

    // Every slot blob is passed WITH its native 8-byte header (magic+length);
    // the SuperBlob stores them verbatim. (The CodeDirectory and the alternate
    // CD carry CSMAGIC_CODEDIRECTORY; entitlements carry FADE7171/FADE7172; the
    // CMS carries FADE0B01.) Adding a second header here would corrupt them.
    const RyBuf *slots[6];
    uint32_t    types[6];
    int n = 0;

    slots[n] = cd;                                   types[n] = RY_CSSLOT_CODEDIRECTORY;            n++;
    if (requirements && requirements->len) { slots[n] = requirements; types[n] = RY_CSSLOT_REQUIREMENTS;            n++; }
    if (ents        && ents->len)        { slots[n] = ents;        types[n] = RY_CSSLOT_ENTITLEMENTS;          n++; }
    if (der_ents    && der_ents->len)    { slots[n] = der_ents;    types[n] = RY_CSSLOT_DER_ENTITLEMENTS;      n++; }
    if (alt_cd      && alt_cd->len)      { slots[n] = alt_cd;      types[n] = RY_CSSLOT_ALTERNATE_CODEDIRECTORIES; n++; }
    if (cms         && cms->len)         { slots[n] = cms;         types[n] = RY_CSSLOT_SIGNATURESLOT;          n++; }

    size_t header_len = 12 + (size_t)n * 8;
    size_t cursor = header_len;
    uint32_t offsets[6];
    for (int i = 0; i < n; i++) {
        offsets[i] = (uint32_t)cursor;
        cursor += slots[i]->len;
    }
    size_t total = cursor;

    ry_buf_init(out);
    ry_buf_be32(out, RY_CSMAGIC_EMBEDDED_SIGNATURE);
    ry_buf_be32(out, (uint32_t)total);
    ry_buf_be32(out, (uint32_t)n);
    for (int i = 0; i < n; i++) {
        ry_buf_be32(out, types[i]);
        ry_buf_be32(out, offsets[i]);
    }
    for (int i = 0; i < n; i++) {
        ry_buf_put(out, slots[i]->p, slots[i]->len);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// The `cdhashes` plist (Apple signed attribute 1.2.840.113635.100.9.1)
// ---------------------------------------------------------------------------

/// Minimal XML plist writer for the `cdhashes` dictionary.
///
/// Apple's format:
///     <dict><key>cdhashes</key><array><data>…</data>…</array></dict>
/// with one entry per CodeDirectory, each the 20-byte TRUNCATED hash of that
/// CD: SHA-1 for the primary CD, SHA-256 truncated to 20 bytes for the
/// alternate.
int ry_build_cdhashes_plist(const RyBuf *cd_sha1, const RyBuf *cd_sha256,
                            const RySignHash *hash, RyBuf *out) {
    if (!hash || !out) return -1;
    ry_buf_init(out);

    const char *header =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\">\n<dict>\n\t<key>cdhashes</key>\n\t<array>\n";
    const char *footer = "\t</array>\n</dict>\n</plist>\n";
    ry_buf_put(out, header, strlen(header));

    unsigned char digest[32];
    char b64[64];
    char line[128];

    if (cd_sha1 && cd_sha1->len && hash->sha1) {
        hash->sha1(cd_sha1->p, cd_sha1->len, digest);
        ry_base64(digest, 20, b64, sizeof(b64));
        snprintf(line, sizeof(line), "\t\t<data>%s</data>\n", b64);
        ry_buf_put(out, line, strlen(line));
    }
    if (cd_sha256 && cd_sha256->len && hash->sha256) {
        hash->sha256(cd_sha256->p, cd_sha256->len, digest);
        ry_base64(digest, 20, b64, sizeof(b64));
        snprintf(line, sizeof(line), "\t\t<data>%s</data>\n", b64);
        ry_buf_put(out, line, strlen(line));
    }

    ry_buf_put(out, footer, strlen(footer));
    return 0;
}
