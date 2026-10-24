#ifndef RyUnzip_h
#define RyUnzip_h

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Extract a zip archive (stored + deflate methods) into `destDir`.
///
/// Why not /usr/bin/unzip via posix_spawn: the iOS sandbox denies executing
/// binaries outside the app container (EPERM), so the import pipeline needs an
/// in-process extractor. Unix permission bits from the zip's external attrs
/// are preserved (executables stay executable).
///
/// Returns 0 on success, non-zero on failure.
int ry_unzip_extract(const char *zipPath, const char *destDir);

// ---------------------------------------------------------------------------
// ZIP64-aware, streaming helpers (added for firmware ingestion).
//
// A modern IPSW is 10 GB+, so the "read the whole archive into memory"
// approach of ry_unzip_extract() is impossible there — and dumping a 7.5 GB
// AEA system volume onto the device is pointless anyway. These two calls let
// RyBox look inside a huge archive and pull out ONLY what it wants (manifest,
// kernelcache, trustcaches, plaintext DMGs, or a curated rootfs tree):
//
//   1) ry_unzip_enumerate() writes a TSV index of every entry to `outListPath`
//   2) the caller picks entry names, writes them to a names file, and
//   3) ry_unzip_extract_selected() streams just those entries to disk.
//
// Both handle ZIP64 (0xFFFFFFFF sentinels + the 0x0001 extra field), which
// every current IPSW uses.

/// Write "name\tusize\tcsize\tmethod\tlocalHeaderOffset\n" for every entry.
/// Returns the entry count (>= 0) or a negative error code.
int ry_unzip_enumerate(const char *zipPath, const char *outListPath);

/// Extract every entry named in `namesFile` (newline separated) from
/// `zipPath` into `destDir`. `outBytes` (optional) receives the total written.
/// Returns the number of entries extracted (>= 0) or a negative error code.
int ry_unzip_extract_selected(const char *zipPath, const char *destDir,
                              const char *namesFile, uint64_t *outBytes);

#ifdef __cplusplus
}
#endif

#endif /* RyUnzip_h */
