/*
 * termux-etc-redirect.c — LD_PRELOAD library for Termux
 *
 * Intercepts libc file-access functions and redirects reads of
 *   /etc/resolv.conf, /etc/hosts, /etc/nsswitch.conf
 * to their Termux equivalents under $PREFIX/etc/.
 *
 * Only affects dynamically linked programs. For statically linked
 * binaries (e.g. Go CLIs), use the seccomp-based interceptor instead.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define TERMUX_DEFAULT_PREFIX "/data/data/com.termux/files/usr"

/*
 * Redirect table: source path -> destination suffix (appended to $PREFIX).
 * For SSL certs, Go looks in several hardcoded paths. We redirect them all
 * to Termux's cert bundle at $PREFIX/etc/tls/cert.pem.
 */
typedef struct {
    const char *src;
    const char *dest;
} redirect_entry;

static const redirect_entry REDIRECT_TABLE[] = {
    { "/etc/resolv.conf",       "/etc/resolv.conf" },
    { "/etc/hosts",             "/etc/hosts" },
    { "/etc/nsswitch.conf",     "/etc/nsswitch.conf" },
    { "/etc/ssl/certs/ca-certificates.crt", "/etc/tls/cert.pem" },
    { "/etc/pki/tls/certs/ca-bundle.crt",   "/etc/tls/cert.pem" },
    { "/etc/ssl/ca-bundle.pem",              "/etc/tls/cert.pem" },
    { "/etc/pki/tls/cacert.pem",             "/etc/tls/cert.pem" },
    { "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/etc/tls/cert.pem" },
    { "/etc/ssl/cert.pem",                   "/etc/tls/cert.pem" },
    { NULL, NULL }
};

/* Cached prefix path (populated on first call). */
static const char *g_prefix;
static int g_prefix_len;
static int g_prefix_inited;

static void init_prefix(void) {
    if (g_prefix_inited) return;
    const char *p = getenv("PREFIX");
    if (!p || !*p) p = TERMUX_DEFAULT_PREFIX;
    g_prefix = p;
    g_prefix_len = (int)strlen(p);
    g_prefix_inited = 1;
}

/*
 * If `path` matches one of the redirected files, write the
 * Termux-prefixed path into `buf` and return it. Otherwise return
 * the original `path` unchanged.
 */
static const char *redirect(const char *path, char *buf, size_t bufsz) {
    if (!path || path[0] != '/') return path;

    for (int i = 0; REDIRECT_TABLE[i].src; i++) {
        if (strcmp(path, REDIRECT_TABLE[i].src) != 0) continue;

        init_prefix();

        size_t need = (size_t)g_prefix_len + strlen(REDIRECT_TABLE[i].dest) + 1;
        if (need > bufsz) return path;

        memcpy(buf, g_prefix, (size_t)g_prefix_len);
        strcpy(buf + g_prefix_len, REDIRECT_TABLE[i].dest);

        /* Only redirect if the Termux file actually exists (raw syscall). */
        if (syscall(__NR_faccessat, AT_FDCWD, buf, F_OK, 0) == 0)
            return buf;

        return path;
    }
    return path;
}

/* ---------- original function pointers ---------- */

typedef int     (*open_fn)(const char *, int, ...);
typedef int     (*openat_fn)(int, const char *, int, ...);
typedef FILE   *(*fopen_fn)(const char *, const char *);
typedef int     (*access_fn)(const char *, int);
typedef int     (*faccessat_fn)(int, const char *, int, int);
typedef int     (*stat_fn)(const char *, struct stat *);
typedef int     (*lstat_fn)(const char *, struct stat *);

static open_fn      real_open;
static openat_fn    real_openat;
static fopen_fn     real_fopen;
static access_fn    real_access;
static faccessat_fn real_faccessat;
static stat_fn      real_stat;
static lstat_fn     real_lstat;

#define LOAD_REAL(name) do { \
    if (!real_##name) real_##name = (name##_fn)dlsym(RTLD_NEXT, #name); \
} while (0)

/* ---------- intercepted functions ---------- */

__attribute__((visibility("default")))
int open(const char *pathname, int flags, ...) {
    LOAD_REAL(open);
    char buf[PATH_MAX];
    const char *p = redirect(pathname, buf, sizeof(buf));

    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode_t mode = (mode_t)va_arg(ap, int);
        va_end(ap);
        return real_open(p, flags, mode);
    }
    return real_open(p, flags);
}

__attribute__((visibility("default")))
int openat(int dirfd, const char *pathname, int flags, ...) {
    LOAD_REAL(openat);
    char buf[PATH_MAX];
    /* Only redirect absolute paths. */
    const char *p = (pathname && pathname[0] == '/')
                    ? redirect(pathname, buf, sizeof(buf))
                    : pathname;

    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode_t mode = (mode_t)va_arg(ap, int);
        va_end(ap);
        return real_openat(dirfd, p, flags, mode);
    }
    return real_openat(dirfd, p, flags);
}

__attribute__((visibility("default")))
FILE *fopen(const char *pathname, const char *mode) {
    LOAD_REAL(fopen);
    char buf[PATH_MAX];
    return real_fopen(redirect(pathname, buf, sizeof(buf)), mode);
}

__attribute__((visibility("default")))
int access(const char *pathname, int mode) {
    LOAD_REAL(access);
    char buf[PATH_MAX];
    return real_access(redirect(pathname, buf, sizeof(buf)), mode);
}

__attribute__((visibility("default")))
int faccessat(int dirfd, const char *pathname, int mode, int flags) {
    LOAD_REAL(faccessat);
    char buf[PATH_MAX];
    const char *p = (pathname && pathname[0] == '/')
                    ? redirect(pathname, buf, sizeof(buf))
                    : pathname;
    return real_faccessat(dirfd, p, mode, flags);
}

__attribute__((visibility("default")))
int stat(const char *restrict pathname, struct stat *restrict statbuf) {
    LOAD_REAL(stat);
    char buf[PATH_MAX];
    return real_stat(redirect(pathname, buf, sizeof(buf)), statbuf);
}

__attribute__((visibility("default")))
int lstat(const char *restrict pathname, struct stat *restrict statbuf) {
    LOAD_REAL(lstat);
    char buf[PATH_MAX];
    return real_lstat(redirect(pathname, buf, sizeof(buf)), statbuf);
}
