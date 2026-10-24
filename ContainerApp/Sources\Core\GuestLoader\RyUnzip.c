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

// ===========================================================================
// MARK: - ZIP64-aware index + selective extraction (firmware ingestion)
// ===========================================================================

#define SIG_EOCD64_LOC  0x07064b50
#define SIG_EOCD64      0x06064b50
#define SIG_EXTRA_ZIP64 0x0001

typedef struct {
    char    *name;      // malloc'd, NUL terminated
    uint64_t usize;
    uint64_t csize;
    uint64_t lho;       // local header offset
    uint16_t method;
    uint32_t extattr;
} ry_zip_entry;

/// Read the central directory of `zipPath` (ZIP64 aware).
/// Returns 0 on success with `*out` / `*count` filled (caller frees with
/// ry_zip_entries_free), or a negative error code.
static int ry_zip_read_cd(const char *zipPath, ry_zip_entry **out, uint64_t *count) {
    if (!zipPath || !out || !count) return -1;
    *out = NULL; *count = 0;

    FILE *f = fopen(zipPath, "rb");
    if (!f) return -2;
    if (fseeko(f, 0, SEEK_END) != 0) { fclose(f); return -3; }
    off_t fsize = ftello(f);
    if (fsize < 22) { fclose(f); return -4; }

    // 1) EOCD: scan backwards (allow a 64 KB trailing comment).
    unsigned char tail[66000];
    off_t maxBack = (fsize < (off_t)sizeof(tail)) ? fsize : (off_t)sizeof(tail);
    if (fseeko(f, fsize - maxBack, SEEK_SET) != 0) { fclose(f); return -5; }
    size_t got = fread(tail, 1, (size_t)maxBack, f);
    if (got < 22) { fclose(f); return -6; }

    off_t eocd = -1;
    for (off_t i = (off_t)got - 22; i >= 0; i--) {
        if (RD32(tail + i) == SIG_EOCD) { eocd = (fsize - (off_t)got) + i; break; }
    }
    if (eocd < 0) { fclose(f); return -7; }

    uint64_t cdCount = RD16(tail + (size_t)(eocd - (fsize - (off_t)got)) + 10);
    uint64_t cdSize  = RD32(tail + (size_t)(eocd - (fsize - (off_t)got)) + 12);
    uint64_t cdOff   = RD32(tail + (size_t)(eocd - (fsize - (off_t)got)) + 16);

    // 2) ZIP64: if anything is the 0xFFFFFFFF sentinel, go read the real 64-bit
    //    values from the ZIP64 EOCD (found through the locator that sits
    //    immediately before the classic EOCD).
    int need64 = (cdCount == 0xFFFF || cdSize == 0xFFFFFFFF || cdOff == 0xFFFFFFFF);
    if (!need64 && eocd >= 20) {
        unsigned char loc[20];
        if (fseeko(f, eocd - 20, SEEK_SET) == 0 && fread(loc, 1, 20, f) == 20
            && RD32(loc) == SIG_EOCD64_LOC) {
            uint64_t z64off = 0;
            memcpy(&z64off, loc + 8, 8);
            need64 = 1;
            unsigned char z64[56];
            if (fseeko(f, (off_t)z64off, SEEK_SET) == 0 && fread(z64, 1, 56, f) == 56
                && RD32(z64) == SIG_EOCD64) {
                memcpy(&cdCount, z64 + 32, 8);   // total entries
                memcpy(&cdSize,  z64 + 40, 8);   // size of CD
                memcpy(&cdOff,   z64 + 48, 8);   // offset of CD
            }
        }
    } else if (need64) {
        unsigned char loc[20];
        if (fseeko(f, eocd - 20, SEEK_SET) == 0 && fread(loc, 1, 20, f) == 20
            && RD32(loc) == SIG_EOCD64_LOC) {
            uint64_t z64off = 0;
            memcpy(&z64off, loc + 8, 8);
            unsigned char z64[56];
            if (fseeko(f, (off_t)z64off, SEEK_SET) == 0 && fread(z64, 1, 56, f) == 56
                && RD32(z64) == SIG_EOCD64) {
                memcpy(&cdCount, z64 + 32, 8);
                memcpy(&cdSize,  z64 + 40, 8);
                memcpy(&cdOff,   z64 + 48, 8);
            }
        }
    }

    if (cdSize == 0 || cdCount == 0 || cdCount > 4000000) { fclose(f); return -8; }
    if ((off_t)cdOff + (off_t)cdSize > fsize) { fclose(f); return -9; }

    unsigned char *cd = (unsigned char *)malloc((size_t)cdSize);
    if (!cd) { fclose(f); return -10; }
    if (fseeko(f, (off_t)cdOff, SEEK_SET) != 0
        || fread(cd, 1, (size_t)cdSize, f) != (size_t)cdSize) {
        free(cd); fclose(f); return -11;
    }

    ry_zip_entry *ents = (ry_zip_entry *)calloc((size_t)cdCount, sizeof(ry_zip_entry));
    if (!ents) { free(cd); fclose(f); return -12; }

    const unsigned char *p = cd;
    const unsigned char *end = cd + cdSize;
    uint64_t n = 0;
    for (uint64_t i = 0; i < cdCount && p + 46 <= end; i++) {
        if (RD32(p) != SIG_CEN) break;
        uint16_t method = RD16(p + 10);
        uint64_t csize  = RD32(p + 20);
        uint64_t usize  = RD32(p + 24);
        uint16_t nlen   = RD16(p + 28);
        uint16_t elen   = RD16(p + 30);
        uint16_t clen   = RD16(p + 32);
        uint32_t extattr= RD32(p + 38);
        uint64_t lho    = RD32(p + 42);
        const char *name = (const char *)(p + 46);

        // ZIP64 extra field: usize, csize, lho in that order, only for the
        // fields that carry the 0xFFFFFFFF sentinel.
        const unsigned char *ex = p + 46 + nlen;
        uint16_t remaining = elen;
        while (remaining >= 4) {
            uint16_t hid = RD16(ex);
            uint16_t hsz = RD16(ex + 2);
            if ((size_t)(hsz + 4) > (size_t)remaining) break;
            const unsigned char *body = ex + 4;
            uint16_t bleft = hsz;
            if (hid == SIG_EXTRA_ZIP64) {
                if (usize == 0xFFFFFFFF && bleft >= 8) { memcpy(&usize, body, 8); body += 8; bleft -= 8; }
                if (csize == 0xFFFFFFFF && bleft >= 8) { memcpy(&csize, body, 8); body += 8; bleft -= 8; }
                if (lho   == 0xFFFFFFFF && bleft >= 8) { memcpy(&lho,   body, 8); }
            }
            ex += 4 + hsz;
            remaining = (uint16_t)(remaining - (hsz + 4));
        }

        if (nlen > 0) {
            ents[n].name = (char *)malloc((size_t)nlen + 1);
            if (ents[n].name) {
                memcpy(ents[n].name, name, nlen);
                ents[n].name[nlen] = '\0';
            }
            ents[n].method  = method;
            ents[n].csize   = csize;
            ents[n].usize   = usize;
            ents[n].lho     = lho;
            ents[n].extattr = extattr;
            n++;
        }
        p += 46 + nlen + elen + clen;
    }

    free(cd);
    fclose(f);
    *out = ents;
    *count = n;
    return 0;
}

static void ry_zip_entries_free(ry_zip_entry *ents, uint64_t count) {
    if (!ents) return;
    for (uint64_t i = 0; i < count; i++) free(ents[i].name);
    free(ents);
}

/// Write one entry from an open file handle: seek to its data, inflate/store
/// into `destDir/<name>`, chmod from the external attributes.
static int ry_zip_write_entry(FILE *f, const char *destDir, const ry_zip_entry *e,
                              uint64_t *bytesOut) {
    char path[4096];
    if ((size_t)snprintf(path, sizeof(path), "%s/%s", destDir, e->name) >= sizeof(path)) {
        return -1;
    }

    char parent[4096];
    if ((size_t)snprintf(parent, sizeof(parent), "%s", path) >= sizeof(parent)) return -2;
    char *slash = strrchr(parent, '/');
    if (slash && slash != parent) {
        *slash = '\0';
        if (mkdirs(parent) != 0) return -3;
    }

    // Local header: name + extra length may differ from the central directory,
    // so read them from the local header itself.
    unsigned char lh[30];
    if (fseeko(f, (off_t)e->lho, SEEK_SET) != 0) return -4;
    if (fread(lh, 1, 30, f) != 30) return -5;
    if (RD32(lh) != SIG_LOC) return -6;
    uint16_t lnlen = RD16(lh + 26);
    uint16_t lelen = RD16(lh + 28);
    off_t dataOff = (off_t)e->lho + 30 + lnlen + lelen;

    FILE *out = fopen(path, "wb");
    if (!out) return -7;

    int rc = 0;
    if (e->method == 0) {                                   // stored: stream it
        unsigned char chunk[65536];
        uint64_t left = e->csize;
        if (fseeko(f, dataOff, SEEK_SET) != 0) { fclose(out); return -8; }
        while (left > 0) {
            size_t want = (left > sizeof(chunk)) ? sizeof(chunk) : (size_t)left;
            size_t rd = fread(chunk, 1, want, f);
            if (rd == 0) { rc = -9; break; }
            if (fwrite(chunk, 1, rd, out) != rd) { rc = -10; break; }
            left -= rd;
            if (bytesOut) *bytesOut += rd;
        }
    } else if (e->method == 8) {                            // deflate: buffer it
        if (e->csize > 0 && e->csize < 512u * 1024u * 1024u) {
            unsigned char *cbuf = (unsigned char *)malloc((size_t)e->csize);
            unsigned char *obuf = (unsigned char *)malloc((size_t)(e->usize > 0 ? e->usize : 1));
            if (!cbuf || !obuf) { free(cbuf); free(obuf); fclose(out); return -11; }
            if (fseeko(f, dataOff, SEEK_SET) != 0
                || fread(cbuf, 1, (size_t)e->csize, f) != (size_t)e->csize) {
                free(cbuf); free(obuf); fclose(out); return -12;
            }
            z_stream s;
            memset(&s, 0, sizeof(s));
            s.next_in = (Bytef *)cbuf;
            s.avail_in = (uInt)e->csize;
            s.next_out = obuf;
            s.avail_out = (uInt)(e->usize > 0 ? e->usize : 1);
            if (inflateInit2(&s, -MAX_WBITS) != Z_OK) {
                free(cbuf); free(obuf); fclose(out); return -13;
            }
            int zr = inflate(&s, Z_FINISH);
            uInt produced = (uInt)(e->usize > 0 ? e->usize : 1) - s.avail_out;
            inflateEnd(&s);
            if (zr != Z_STREAM_END && zr != Z_OK) {
                free(cbuf); free(obuf); fclose(out); return -14;
            }
            if (produced > 0 && fwrite(obuf, 1, produced, out) != produced) rc = -15;
            if (bytesOut) *bytesOut += produced;
            free(cbuf); free(obuf);
        } else {
            rc = -16;                                       // too big / unknown
        }
    } else {
        rc = -17;                                           // unsupported method
    }

    fclose(out);
    if (rc == 0) {
        int executable = ((e->extattr >> 16) & 0111) ? 1 : 0;
        chmod(path, executable ? 0755 : 0644);
    }
    return rc;
}

int ry_unzip_enumerate(const char *zipPath, const char *outListPath) {
    ry_zip_entry *ents = NULL;
    uint64_t count = 0;
    int rc = ry_zip_read_cd(zipPath, &ents, &count);
    if (rc != 0) return rc;

    FILE *out = fopen(outListPath, "wb");
    if (!out) { ry_zip_entries_free(ents, count); return -20; }
    for (uint64_t i = 0; i < count; i++) {
        fprintf(out, "%s\t%llu\t%llu\t%u\t%llu\n",
                ents[i].name ? ents[i].name : "",
                (unsigned long long)ents[i].usize,
                (unsigned long long)ents[i].csize,
                (unsigned)ents[i].method,
                (unsigned long long)ents[i].lho);
    }
    fclose(out);
    ry_zip_entries_free(ents, count);
    return (int)count;
}

int ry_unzip_extract_selected(const char *zipPath, const char *destDir,
                              const char *namesFile, uint64_t *outBytes) {
    if (!zipPath || !destDir || !namesFile) return -1;

    // Load the wanted-name set.
    FILE *nf = fopen(namesFile, "rb");
    if (!nf) return -2;
    char **wanted = NULL;
    size_t wcount = 0, wcap = 0;
    char line[4096];
    while (fgets(line, sizeof(line), nf)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) line[--len] = '\0';
        if (len == 0) continue;
        if (wcount == wcap) {
            size_t ncap = wcap ? wcap * 2 : 1024;
            char **tmp = (char **)realloc(wanted, ncap * sizeof(char *));
            if (!tmp) break;
            wanted = tmp; wcap = ncap;
        }
        wanted[wcount] = strdup(line);
        if (wanted[wcount]) wcount++;
    }
    fclose(nf);
    if (!wanted) return -3;

    ry_zip_entry *ents = NULL;
    uint64_t count = 0;
    int rc = ry_zip_read_cd(zipPath, &ents, &count);
    if (rc != 0) {
        for (size_t i = 0; i < wcount; i++) free(wanted[i]);
        free(wanted);
        return rc;
    }

    if (mkdirs(destDir) != 0) {
        ry_zip_entries_free(ents, count);
        for (size_t i = 0; i < wcount; i++) free(wanted[i]);
        free(wanted);
        return -4;
    }

    FILE *f = fopen(zipPath, "rb");
    if (!f) {
        ry_zip_entries_free(ents, count);
        for (size_t i = 0; i < wcount; i++) free(wanted[i]);
        free(wanted);
        return -5;
    }

    uint64_t total = 0;
    int done = 0;

    // Sentinel: a line containing exactly "*" means "extract EVERYTHING".
    // (Matching N wanted names against an M-entry central directory one by one
    // is O(N*M) — fatal for a .ryboxenv with tens of thousands of files.)
    int all = 0;
    for (size_t i = 0; i < wcount; i++) {
        if (wanted[i] && strcmp(wanted[i], "*") == 0) { all = 1; break; }
    }
    if (all) {
        for (uint64_t i = 0; i < count; i++) {
            if (!ents[i].name) continue;
            size_t nl = strlen(ents[i].name);
            if (nl > 0 && ents[i].name[nl - 1] == '/') {
                char dirbuf[4096];
                if ((size_t)snprintf(dirbuf, sizeof(dirbuf), "%s/%s",
                                     destDir, ents[i].name) < sizeof(dirbuf)) {
                    mkdirs(dirbuf);
                }
                continue;
            }
            if (ry_zip_write_entry(f, destDir, &ents[i], &total) == 0) done++;
        }
        fclose(f);
        ry_zip_entries_free(ents, count);
        for (size_t i = 0; i < wcount; i++) free(wanted[i]);
        free(wanted);
        if (outBytes) *outBytes = total;
        return done;
    }

    for (size_t w = 0; w < wcount; w++) {
        for (uint64_t i = 0; i < count; i++) {
            if (!ents[i].name || strcmp(ents[i].name, wanted[w]) != 0) continue;
            // Directories: just make sure the folder exists.
            size_t nl = strlen(ents[i].name);
            if (nl > 0 && ents[i].name[nl - 1] == '/') {
                char dirbuf[4096];
                if ((size_t)snprintf(dirbuf, sizeof(dirbuf), "%s/%s",
                                     destDir, ents[i].name) < sizeof(dirbuf)) {
                    mkdirs(dirbuf);
                }
                done++;
                break;
            }
            if (ry_zip_write_entry(f, destDir, &ents[i], &total) == 0) done++;
            break;
        }
    }

    fclose(f);
    ry_zip_entries_free(ents, count);
    for (size_t i = 0; i < wcount; i++) free(wanted[i]);
    free(wanted);
    if (outBytes) *outBytes = total;
    return done;
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
