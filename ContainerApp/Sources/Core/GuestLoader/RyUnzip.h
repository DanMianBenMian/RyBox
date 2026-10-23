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

#ifdef __cplusplus
}
#endif

#endif /* RyUnzip_h */
