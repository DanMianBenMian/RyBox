// RyUnzip.c — minimal in-process zip extractor (stored + deflate).
//
// Reads the whole archive into memory, walks the central directory, and
// inflates each entry with zlib (raw deflate, -MAX_WBITS). Sufficient for
// IPA payloads (a handful of MB, entries well under 4 GB, no zip64).

#include "RyUnzip.h"

#include <zlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

#define RD16(p) ((uint32_t)(p)[0] | ((uint32_t)(p)[1] << 8))
#define RD32(p) ((uint32_t)(p)[0] | ((uint32_t)(p)[1] << 8) | \
                 ((uint32_t)(p)[2] << 16) | ((uint32_t)(p)[3] << 24))

#define SIG_EOCD 0x06054b50
#define SIG_CEN  0x02014b50
#define SIG_LOC  0x04034b50

/// mkdir -p for a directory path (no trailing file component).
static int mkdirs(const char *path) {
    char tmp[4096];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(tmp)) return -1;
    memcpy(tmp, path, len + 1);
    while (len > 1 && tmp[len - 1] == '/') tmp[--len] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

/// Write one entry: create parent dirs, inflate/store to disk, chmod.
static int write_entry(const char *destDir, const char *name, size_t nlen,
                       const unsigned char *cdata, uint32_t csize,
                       uint32_t usize, uint16_t method, int executable) {
    char path[4096];
    if ((size_t)snprintf(path, sizeof(path), "%s/%.*s", destDir, (int)nlen, name)
            >= sizeof(path)) {
        return -1;
    }

    char parent[4096];
    if ((size_t)snprintf(parent, sizeof(parent), "%s", path) >= sizeof(parent)) return -2;
    char *slash = strrchr(parent, '/');
    if (slash && slash != parent) {
        *slash = '\0';
        if (mkdirs(parent) != 0) return -3;
    }

    FILE *out = fopen(path, "wb");
    if (!out) return -4;

    if (method == 0) {                       // stored
        if (csize > 0 && fwrite(cdata, 1, csize, out) != csize) {
            fclose(out);
            return -5;
        }
    } else if (method == 8) {                // deflate
        uInt outCap = (usize > 0) ? (uInt)usize : (uInt)1;
        unsigned char *obuf = (unsigned char *)malloc(outCap);
        if (!obuf) { fclose(out); return -6; }

        z_stream s;
        memset(&s, 0, sizeof(s));
        s.next_in  = (Bytef *)(uintptr_t)cdata;
        s.avail_in = (uInt)csize;
        s.next_out  = obuf;
        s.avail_out = outCap;

        if (inflateInit2(&s, -MAX_WBITS) != Z_OK) {   // raw deflate
            free(obuf);
            fclose(out);
            return -7;
        }
        int zr = inflate(&s, Z_FINISH);
        uInt produced = outCap - s.avail_out;
        inflateEnd(&s);

        if (zr != Z_STREAM_END && !(zr == Z_OK && produced == outCap)) {
            free(obuf);
            fclose(out);
            return -8;
        }
        if (produced > 0 && fwrite(obuf, 1, produced, out) != produced) {
            free(obuf);
            fclose(out);
            return -9;
        }
        free(obuf);
    } else {
        fclose(out);
        return -10;                          // unsupported compression method
    }

    fclose(out);
    chmod(path, executable ? 0755 : 0644);
    return 0;
}

int ry_unzip_extract(const char *zipPath, const char *destDir) {
    if (!zipPath || !destDir) return -1;

    FILE *f = fopen(zipPath, "rb");
    if (!f) return -2;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -3; }
    long fsize = ftell(f);
    if (fsize < 22) { fclose(f); return -4; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -5; }

    unsigned char *buf = (unsigned char *)malloc((size_t)fsize);
    if (!buf) { fclose(f); return -6; }
    if (fread(buf, 1, (size_t)fsize, f) != (size_t)fsize) {
        free(buf);
        fclose(f);
        return -7;
    }
    fclose(f);

    if (mkdirs(destDir) != 0) { free(buf); return -8; }

    // Locate the End Of Central Directory record (scan backwards for the
    // signature; allow up to 64 KB of trailing comment).
    long eocd = -1;
    long maxBack = (fsize < 66000) ? fsize : 66000;
    for (long i = fsize - 22; i >= fsize - maxBack; i--) {
        if (RD32(buf + i) == SIG_EOCD) { eocd = i; break; }
    }
    if (eocd < 0) { free(buf); return -9; }

    uint32_t cdCount = RD16(buf + eocd + 10);
    uint32_t cdSize  = RD32(buf + eocd + 12);
    uint32_t cdOff   = RD32(buf + eocd + 16);
    if ((uint64_t)cdOff + (uint64_t)cdSize > (uint64_t)fsize) { free(buf); return -10; }

    const unsigned char *p   = buf + cdOff;
    const unsigned char *end = buf + cdOff + cdSize;

    int rc = 0;
    for (uint32_t i = 0; i < cdCount && p + 46 <= end; i++) {
        if (RD32(p) != SIG_CEN) { rc = -11; break; }

        uint16_t method  = RD16(p + 10);
        uint32_t csize   = RD32(p + 20);
        uint32_t usize   = RD32(p + 24);
        uint16_t nlen    = RD16(p + 28);
        uint16_t elen    = RD16(p + 30);
        uint16_t clen    = RD16(p + 32);
        uint32_t extattr = RD32(p + 38);
        uint32_t lho     = RD32(p + 42);
        const char *name = (const char *)(p + 46);
        p += 46 + nlen + elen + clen;

        if (nlen == 0) continue;
        if (name[nlen - 1] == '/') {                    // directory entry
            char dirbuf[4096];
            if ((size_t)snprintf(dirbuf, sizeof(dirbuf), "%s/%.*s",
                                 destDir, (int)nlen, name) < sizeof(dirbuf)) {
                mkdirs(dirbuf);
            }
            continue;
        }

        if ((uint64_t)lho + 30 > (uint64_t)fsize) { rc = -12; break; }
        const unsigned char *lh = buf + lho;
        if (RD32(lh) != SIG_LOC) { rc = -13; break; }
        uint16_t lnlen = RD16(lh + 26);
        uint16_t lelen = RD16(lh + 28);
        const unsigned char *data = lh + 30 + lnlen + lelen;
        if ((uint64_t)(data - buf) + (uint64_t)csize > (uint64_t)fsize) { rc = -14; break; }

        int executable = ((extattr >> 16) & 0111) ? 1 : 0;

        if (write_entry(destDir, name, nlen, data, csize, usize, method,
                        executable) != 0) {
            rc = -15;
            break;
        }
    }

    free(buf);
    return rc;
}
