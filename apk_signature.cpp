#include "apk_signature.h"
#include "sha256.h"
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <__algorithm/min.h>

// --- SVC wrappers ---
static inline long svc_openat(int dirfd, const char *path, int flags, mode_t mode) {
    register long x0 __asm__("x0") = (long) dirfd;
    register long x1 __asm__("x1") = (long) path;
    register long x2 __asm__("x2") = (long) flags;
    register long x3 __asm__("x3") = (long) mode;
    register long x8 __asm__("x8") = SYS_OPENAT;
    __asm__ __volatile__("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x8) : "memory");
    return x0;
}

static inline long svc_read(int fd, void *buf, size_t len) {
    register long x0 __asm__("x0") = (long) fd;
    register long x1 __asm__("x1") = (long) buf;
    register long x2 __asm__("x2") = (long) len;
    register long x8 __asm__("x8") = SYS_READ;
    __asm__ __volatile__("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    return x0;
}

static inline long svc_lseek(int fd, off_t offset, int whence) {
    register long x0 __asm__("x0") = (long) fd;
    register long x1 __asm__("x1") = (long) offset;
    register long x2 __asm__("x2") = (long) whence;
    register long x8 __asm__("x8") = SYS_LSEEK;
    __asm__ __volatile__("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    return x0;
}

static inline void svc_close(int fd) {
    register long x0 __asm__("x0") = (long) fd;
    register long x8 __asm__("x8") = SYS_CLOSE;
    __asm__ __volatile__("svc #0" : "+r"(x0) : "r"(x8) : "memory");
}

// --- utils ---
static bool svc_read_exact(int fd, void *buf, size_t len) {
    size_t total = 0;
    uint8_t *p = (uint8_t *) buf;
    while (total < len) {
        long n = svc_read(fd, p + total, len - total);
        if (n <= 0) return false;
        total += (size_t)n;
    }
    return true;
}

static void xor_decrypt(uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) data[i] ^= APK_SIG_XOR_KEY;
}

// --- ZIP struct ---
#pragma pack(push, 1)
struct ZipEocd {
    uint32_t signature;
    uint16_t diskNum;
    uint16_t cdStartDisk;
    uint16_t cdRecordOnDisk;
    uint16_t cdTotalRecord;
    uint32_t cdSize;
    uint32_t cdOffset;
    uint16_t commentLen;
};
#pragma pack(pop)

// --- core ---
static bool find_zip_eocd(int fd, ZipEocd &out) {
    off_t size = svc_lseek(fd, 0, SEEK_END);
    if (size < 22) return false;

    size_t max_search = 65535 + 22;
    size_t range = (size > (off_t)max_search) ? max_search : (size_t)size;

    uint8_t buf[2048];
    off_t pos = size;

    while (pos > (size - (off_t)range)) {
        size_t to_read = (size_t)(pos - (size - (off_t)range));
        if (to_read > sizeof(buf)) to_read = sizeof(buf);

        pos -= (off_t)to_read;
        svc_lseek(fd, pos, SEEK_SET);

        if (!svc_read_exact(fd, buf, to_read)) return false;

        for (int i = (int)to_read - 4; i >= 0; i--) {
            uint32_t sig;
            memcpy(&sig, &buf[i], 4);
            if (sig == 0x06054b50) {
                if (i + sizeof(ZipEocd) <= to_read) {
                    memcpy(&out, &buf[i], sizeof(ZipEocd));
                    return true;
                } else {
                    svc_lseek(fd, pos + i, SEEK_SET);
                    return svc_read_exact(fd, &out, sizeof(ZipEocd));
                }
            }
        }
    }
    return false;
}

static bool get_real_apk_path(char *out_path) {
    uint8_t path[] = {0x49,0x16,0x14,0x09,0x05,0x49,0x15,0x03,0x0a,0x00,0x49,0x0b,0x07,0x16,0x15,0x00};
    xor_decrypt(path, sizeof(path) - 1);

    int fd = svc_openat(-100, (char *)path, O_RDONLY, 0);
    if (fd < 0) return false;

    char buf[1024], line[512];
    int ptr = 0;
    bool found = false;

    long n;
    while ((n = svc_read(fd, buf, sizeof(buf))) > 0) {
        for (int i = 0; i < n; i++) {
            if (buf[i] == '\n' || ptr >= 511) {
                line[ptr] = '\0';
                if (strstr(line, " r-xp ") && strstr(line, "/base.apk")) {
                    char *p = strchr(line, '/');
                    if (p) {
                        size_t len = strlen(p);
                        memcpy(out_path, p, len);
                        out_path[len] = '\0';
                        found = true;
                        goto end;
                    }
                }
                ptr = 0;
            } else {
                line[ptr++] = buf[i];
            }
        }
    }

end:
    svc_close(fd);
    return found;
}

static bool get_apk_signing_block_hash(int fd, char *out) {
    ZipEocd eocd{};
    if (!find_zip_eocd(fd, eocd)) return false;

    uint32_t cd_offset = eocd.cdOffset;
    svc_lseek(fd, cd_offset - 24, SEEK_SET);

    uint64_t block_size;
    if (!svc_read_exact(fd, &block_size, 8)) return false;

    uint64_t pos = cd_offset - block_size - 8 + 8;
    uint64_t end = cd_offset - 24;

    while (pos + 12 <= end) {
        svc_lseek(fd, pos, SEEK_SET);

        uint64_t size;
        uint32_t id;
        if (!svc_read_exact(fd, &size, 8) || !svc_read_exact(fd, &id, 4)) return false;

        uint64_t entry_end = pos + 8 + size;
        if (entry_end > end) return false;

        if (id == 0x7109871a) {
            uint8_t buffer[4096];
            uint64_t scan = pos + 12;

            while (scan < entry_end) {
                size_t want = std::min(sizeof(buffer), (size_t)(entry_end - scan));
                svc_lseek(fd, scan, SEEK_SET);

                long n = svc_read(fd, buffer, want);
                if (n <= 0) return false;

                for (long i = 4; i < n - 1; i++) {
                    if (buffer[i] == 0x30 && buffer[i + 1] == 0x82) {
                        uint32_t cert_len;
                        memcpy(&cert_len, &buffer[i - 4], 4);

                        uint64_t cert_pos = scan + i;
                        if (cert_len > 100 && cert_len < 10000) {

                            SHA256_CTX ctx;
                            sha256_init(&ctx);

                            uint64_t remain = cert_len;
                            svc_lseek(fd, cert_pos, SEEK_SET);

                            while (remain > 0) {
                                uint8_t chunk[1024];
                                size_t r = std::min((size_t)remain, sizeof(chunk));

                                long got = svc_read(fd, chunk, r);
                                if (got <= 0) return false;

                                sha256_update(&ctx, chunk, got);
                                remain -= got;
                            }

                            uint8_t hash[32];
                            sha256_final(&ctx, hash);

                            for (int j = 0; j < 32; j++)
                                sprintf(out + j * 2, "%02x", hash[j]);

                            return true;
                        }
                    }
                }

                scan += n - 4;
            }
        }

        pos = entry_end;
    }

    return false;
}

// --- JNI ---
extern "C" JNIEXPORT jboolean JNICALL
Java_your_package_checkNative(JNIEnv *, jclass) {
    char path[512] = {0};
    char hash[65] = {0};

    if (!get_real_apk_path(path)) return JNI_FALSE;

    int fd = svc_openat(-100, path, O_RDONLY, 0);
    if (fd < 0) return JNI_FALSE;

    bool ok = get_apk_signing_block_hash(fd, hash);
    svc_close(fd);

    return (ok && strcmp(hash, APK_EXPECTED_SIGNATURE_HASH) == 0) ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jstring JNICALL
Java_your_package_getSignatureString(JNIEnv *env, jclass) {
    char path[512] = {0};
    char hash[65] = {0};

    if (!get_real_apk_path(path)) return env->NewStringUTF("failed");

    int fd = svc_openat(-100, path, O_RDONLY, 0);
    if (fd < 0) return env->NewStringUTF("failed");

    bool ok = get_apk_signing_block_hash(fd, hash);
    svc_close(fd);

    return ok ? env->NewStringUTF(hash) : env->NewStringUTF("failed");
}