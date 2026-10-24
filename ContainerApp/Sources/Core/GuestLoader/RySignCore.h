// RySignCore — the platform-independent half of RyBox's code signer.
//
// This file holds everything about Apple's code-signature format that does
// NOT need a crypto library or an OS: the CodeDirectory layout, the
// Requirements expression blob, the DER entitlements, and the SuperBlob
// assembly.
//
// It is deliberately free of CommonCrypto / Security.framework / OpenSSL so
// that it can be compiled and byte-compared against zsign's output on a
// desktop machine (see ContainerApp/tools/verify_sign.py). The device build
// supplies the SHA-1/SHA-256 and RSA implementations through the function
// pointers in `RySignHash` / `RySignSigner`.
//
// ---------------------------------------------------------------------------
// GROUND TRUTH (measured, not guessed)
// ---------------------------------------------------------------------------
//
// These were read out of a real signed Mach-O (Sileo, signed by zsign) with
// ContainerApp/tools/golden_dump.py and cross-checked against zsign's own
// source (zhlynn/zsign, `signing.cpp` / `archo.cpp`):
//
//   CodeDirectory (CS_CodeDirectory, version 0x20400):
//     * the header is 88 bytes — 44 base + 4 (scatterOffset) + 4 (teamOffset)
//       + 4 (spare3) + 8 (codeLimit64) + 8*3 (execSegBase/Limit/Flags).
//       The old RySign.c used a 64-byte struct, which AMFI rejects.
//     * `identOffset` == 88 == the header length; the identifier string
//       follows the header immediately.
//     * the SPECIAL slots live BELOW `hashOffset`, i.e. in
//       [hashOffset - nSpecialSlots*hashSize, hashOffset), and slot -k sits
//       at `hashOffset - k*hashSize`.
//     * `hashOffset` points at the FIRST CODE slot.
//     * total length == header + identifier + special + code slots (no slack).
//     * the team id string, when present, sits between the identifier and
//       the special slots.
//
//   Special-slot semantics (measured by hashing every candidate):
//     -1  Info.plist FILE BYTES
//     -2  the Requirements blob, WHOLE (magic + length + payload)
//     -3  _CodeSignature/CodeResources FILE BYTES
//     -4  empty
//     -5  the Entitlements blob, WHOLE
//     -6  empty
//     -7  the DER entitlements blob, WHOLE
//
//   SuperBlob slot order (zsign `BuildCodeSignature`):
//     CodeDirectory(0) → Requirements(2) → Entitlements(5) →
//     DEREntitlements(7) → AlternateCodeDirectory(0x1000) → CMS(0x10000)
//
//   EVERY integer inside the code-signature containers is BIG-ENDIAN, while
//   the Mach-O container itself is little-endian. Mixing them up is the
//   classic "my signature is invalid" bug.
//
//   The Designated Requirement is a byte-coded expression tree
//   (zsign `SlotBuildRequirements`):
//     identifier "<bundleID>" and anchor apple generic
//       and certificate leaf[subject.CN] = "<CN>"
//       and certificate 1[field.1.2.840.113635.100.6.2.1] exists
//
// ---------------------------------------------------------------------------

#ifndef RYSIGN_CORE_H
#define RYSIGN_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---- Apple's csblob magic / slot numbers ---------------------------------
#define RY_CSMAGIC_EMBEDDED_SIGNATURE    0xFADE0CC0u
#define RY_CSMAGIC_CODEDIRECTORY         0xFADE0C02u
#define RY_CSMAGIC_REQUIREMENTS          0xFADE0C01u
#define RY_CSMAGIC_REQUIREMENT            0xFADE0C00u
#define RY_CSMAGIC_EMBEDDED_ENTITLEMENTS 0xFADE7171u
#define RY_CSMAGIC_EMBEDDED_DER_ENTITLEMENTS 0xFADE7172u
#define RY_CSMAGIC_BLOBWRAPPER           0xFADE0B01u

#define RY_CSSLOT_CODEDIRECTORY           0u
#define RY_CSSLOT_REQUIREMENTS            2u
#define RY_CSSLOT_ENTITLEMENTS            5u
#define RY_CSSLOT_DER_ENTITLEMENTS        7u
#define RY_CSSLOT_ALTERNATE_CODEDIRECTORIES 0x1000u
#define RY_CSSLOT_SIGNATURESLOT           0x10000u

// Requirement expression opcodes (Apple's csreq language).
#define RY_REQ_OP_TRUE                 1u
#define RY_REQ_OP_IDENT                2u
#define RY_REQ_OP_APPLE_GENERIC_ANCHOR 15u
#define RY_REQ_OP_AND                  6u
#define RY_REQ_OP_CERT_FIELD           11u
#define RY_REQ_OP_CERT_GENERIC         14u
#define RY_MATCH_EQUAL                 0u
#define RY_MATCH_EXISTS                0u
#define RY_DESIGNATED_REQUIREMENT_TYPE 3u

// Hash types (Apple's cdHashType*).
#define RY_HASH_SHA1   1u
#define RY_HASH_SHA256 2u

// Exec-segment flags.
#define RY_EXECSEG_MAIN_BINARY   0x1ull
#define RY_EXECSEG_ALLOW_UNSIGNED 0x10ull

// ---- growable byte buffer -------------------------------------------------
typedef struct {
    unsigned char *p;
    size_t len;
    size_t cap;
} RyBuf;

void ry_buf_init(RyBuf *b);
void ry_buf_free(RyBuf *b);
void ry_buf_put(RyBuf *b, const void *d, size_t n);
void ry_buf_u8(RyBuf *b, unsigned char v);
void ry_buf_be32(RyBuf *b, uint32_t v);
void ry_buf_be64(RyBuf *b, uint64_t v);

// ---- hash / sign back-ends (injected by the platform layer) ---------------
// Both return 0 on success.
typedef int (*RyHashFn)(const void *data, size_t len, unsigned char *out);
typedef int (*RySignFn)(const void *data, size_t len, unsigned char *out,
                         size_t *out_len);

typedef struct {
    RyHashFn sha1;    // 20-byte digest
    RyHashFn sha256;  // 32-byte digest
} RySignHash;

// ---- the pieces ----------------------------------------------------------

/// Everything the signer needs that is NOT the code bytes themselves.
///
/// NOTE on the three "*_blob" members: the special hash slots -2, -5 and -7
/// cover the WHOLE blob — magic + length + payload — not just the payload.
/// They therefore carry the FINISHED blob bytes, so the caller builds them
/// before hashing. (`info_plist` and `code_resources` are different: those
/// slots cover the raw FILE bytes.)
typedef struct {
    const char *bundle_id;      // identifier written into the CodeDirectory
    const char *team_id;        // may be NULL/empty
    const char *subject_cn;     // leaf certificate CN (for the requirement)

    // Special slot -1: the Info.plist FILE bytes.
    const unsigned char *info_plist;        size_t info_plist_len;
    // Special slot -3: the _CodeSignature/CodeResources FILE bytes.
    const unsigned char *code_resources;   size_t code_resources_len;

    // Special slot -2: the complete Requirements blob.
    const unsigned char *requirements_blob;    size_t requirements_blob_len;
    // Special slot -5: the complete Entitlements blob.
    const unsigned char *entitlements_blob;    size_t entitlements_blob_len;
    // Special slot -7: the complete DER-Entitlements blob.
    const unsigned char *der_entitlements_blob; size_t der_entitlements_blob_len;
} RySignMeta;

/// Build the Requirements blob (magic CSMAGIC_REQUIREMENTS) that carries the
/// designated requirement. Returns 0 on success; on failure `out` is empty.
int ry_build_requirements(const RySignMeta *meta, RyBuf *out);

/// Build a CodeDirectory blob for one hash type.
///
/// `code`/`code_len` are the bytes the code slots cover — i.e. the file up to
/// (but NOT including) the signature region, exactly as zsign computes
/// `m_uCodeLength` (the LC_CODE_SIGNATURE `dataoff`).
///
/// `hash_size` must be 20 for SHA-1 and 32 for SHA-256.
///
/// `is_execute` mirrors zsign's `IsExecute()`: only a MH_EXECUTE main binary
/// carries the DER-entitlements special slot (-7) and its reserved companion
/// (-6). A MH_DYLIB guest (which is what RyBox loads) therefore has FIVE
/// special slots (-5..-1) instead of seven. Getting this wrong shifts
/// `hashOffset` by two slots and AMFI rejects the whole signature.
///
/// `is_adhoc` sets `CS_SEC_CODESIGNATURE_ADHOC` in the flags field.
///
/// `exec_seg_limit` / `exec_seg_flags` come from the Mach-O's `__TEXT`
/// segment: the limit is that segment's `vmsize`, and the flags carry
/// `CS_EXECSEG_MAIN_BINARY` for a main executable (plus
/// `CS_EXECSEG_ALLOW_UNSIGNED` only when the entitlements really contain
/// `get-task-allow = true`).
int ry_build_codedirectory(int alternate,
                           const unsigned char *code, size_t code_len,
                           const RySignMeta *meta,
                           int is_execute, int is_adhoc,
                           uint64_t exec_seg_limit, uint64_t exec_seg_flags,
                           const RySignHash *hash,
                           RyBuf *out);

/// Assemble the whole SuperBlob from the already-built slot blobs.
///
/// The slot order is fixed: CodeDirectory, Requirements, Entitlements,
/// DEREntitlements, AlternateCodeDirectory, CMS.
int ry_build_superblob(const RyBuf *cd, const RyBuf *requirements,
                       const RyBuf *ents, const RyBuf *der_ents,
                       const RyBuf *alt_cd, const RyBuf *cms,
                       RyBuf *out);

/// The `cdhashes` plist (Apple's signed attribute 1.2.840.113635.100.9.1).
/// It lists one truncated (20-byte) hash per CodeDirectory present.
int ry_build_cdhashes_plist(const RyBuf *cd_sha1, const RyBuf *cd_sha256,
                            const RySignHash *hash, RyBuf *out);

#ifdef __cplusplus
}
#endif

#endif /* RYSIGN_CORE_H */
