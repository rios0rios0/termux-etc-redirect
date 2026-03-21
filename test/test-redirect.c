/*
 * test-redirect.c — unit test for libtermux-etc-redirect.so
 *
 * Run with: LD_PRELOAD=build/libtermux-etc-redirect.so build/test-redirect
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void test_fopen_resolv_conf(void) {
    FILE *f = fopen("/etc/resolv.conf", "r");
    assert(f != NULL && "fopen(/etc/resolv.conf) should succeed");
    char line[256];
    char *r = fgets(line, sizeof(line), f);
    assert(r != NULL);
    assert(strstr(line, "nameserver") != NULL &&
           "/etc/resolv.conf should contain 'nameserver'");
    fclose(f);
    printf("PASS: fopen /etc/resolv.conf -> redirected\n");
}

static void test_fopen_hosts(void) {
    FILE *f = fopen("/etc/hosts", "r");
    assert(f != NULL && "fopen(/etc/hosts) should succeed");
    char line[256];
    char *r = fgets(line, sizeof(line), f);
    assert(r != NULL);
    assert(strstr(line, "localhost") != NULL &&
           "/etc/hosts should contain 'localhost'");
    fclose(f);
    printf("PASS: fopen /etc/hosts -> redirected\n");
}

static void test_open_resolv_conf(void) {
    int fd = open("/etc/resolv.conf", O_RDONLY);
    assert(fd >= 0 && "open(/etc/resolv.conf) should succeed");
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    assert(n > 0);
    buf[n] = '\0';
    assert(strstr(buf, "nameserver") != NULL);
    close(fd);
    printf("PASS: open /etc/resolv.conf -> redirected\n");
}

static void test_access_resolv_conf(void) {
    int rc = access("/etc/resolv.conf", R_OK);
    assert(rc == 0 && "access(/etc/resolv.conf, R_OK) should succeed");
    printf("PASS: access /etc/resolv.conf -> redirected\n");
}

static void test_stat_resolv_conf(void) {
    struct stat st;
    int rc = stat("/etc/resolv.conf", &st);
    assert(rc == 0 && "stat(/etc/resolv.conf) should succeed");
    assert(st.st_size > 0 && "file should not be empty");
    printf("PASS: stat /etc/resolv.conf -> redirected\n");
}

static void test_unrelated_path_not_redirected(void) {
    /* /etc/passwd on Android exists but should NOT be redirected. */
    struct stat st1, st2;
    int rc1 = stat("/etc/passwd", &st1);
    int rc2 = stat("/system/etc/passwd", &st2);
    /* Both should give the same result (or both fail). */
    if (rc1 == 0 && rc2 == 0) {
        assert(st1.st_ino == st2.st_ino &&
               "unrelated /etc/ paths should NOT be redirected");
    }
    printf("PASS: /etc/passwd not redirected\n");
}

int main(void) {
    printf("--- libtermux-etc-redirect unit tests ---\n");
    test_fopen_resolv_conf();
    test_fopen_hosts();
    test_open_resolv_conf();
    test_access_resolv_conf();
    test_stat_resolv_conf();
    test_unrelated_path_not_redirected();
    printf("--- all tests passed ---\n");
    return 0;
}
