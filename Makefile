PREFIX ?= /data/data/com.termux/files/usr
CC     ?= clang
CFLAGS  = -O2 -Wall -Wextra -Werror -fPIC -D_GNU_SOURCE
LDFLAGS_SO = -shared -ldl
LDFLAGS_BIN =
# termux-etc-seccomp uses pthreads for the concurrent notif + tracer design
LDFLAGS_SECCOMP = -lpthread

LIBNAME      = libtermux-etc-redirect.so
BINNAME      = termux-etc-seccomp
MOUNTNAME    = termux-etc-mount
LAUNCHERNAME = sigsys_launcher

BUILD_DIR = build

.PHONY: all clean install test

all: $(BUILD_DIR)/$(LIBNAME) $(BUILD_DIR)/$(BINNAME) $(BUILD_DIR)/$(MOUNTNAME) $(BUILD_DIR)/$(LAUNCHERNAME)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/$(LIBNAME): src/termux-etc-redirect.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS_SO) -o $@ $<

$(BUILD_DIR)/$(BINNAME): src/termux-etc-seccomp.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS_BIN) $(LDFLAGS_SECCOMP) -o $@ $<

$(BUILD_DIR)/$(MOUNTNAME): src/termux-etc-mount.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS_BIN) -o $@ $<

$(BUILD_DIR)/$(LAUNCHERNAME): src/sigsys_launcher.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS_BIN) -o $@ $<

install: all
	install -d $(PREFIX)/lib $(PREFIX)/bin
	install -m 755 $(BUILD_DIR)/$(LIBNAME)      $(PREFIX)/lib/$(LIBNAME)
	install -m 755 $(BUILD_DIR)/$(BINNAME)      $(PREFIX)/bin/$(BINNAME)
	install -m 755 $(BUILD_DIR)/$(MOUNTNAME)    $(PREFIX)/bin/$(MOUNTNAME)
	install -m 755 $(BUILD_DIR)/$(LAUNCHERNAME) $(PREFIX)/bin/$(LAUNCHERNAME)

clean:
	rm -rf $(BUILD_DIR)

# NOTE: Tier 2 SIGSYS tests that call build/termux-etc-seccomp directly will
# short-circuit (via the reentrancy guard) when run inside an already-wrapped
# shell (TERMUX_ETC_WRAP_ACTIVE=1 or TracerPid>0). This is correct behavior —
# the outer wrapper handles both SIGSYS and openat redirects. The authoritative
# SIGSYS race test therefore uses sigsys_launcher, which is reentrancy-safe
# (no seccomp filter install, no double-listener issue).
test: all $(BUILD_DIR)/test-redirect $(BUILD_DIR)/test-faccessat2 $(BUILD_DIR)/test-mount \
         $(BUILD_DIR)/test-seccomp-reentrancy $(BUILD_DIR)/test-sigsys-threads
	@echo "=== Tier 1: LD_PRELOAD unit test ==="
	LD_PRELOAD=$(CURDIR)/$(BUILD_DIR)/$(LIBNAME) $(BUILD_DIR)/test-redirect
	@echo ""
	@echo "=== Tier 2: seccomp openat redirect test ==="
	$(CURDIR)/$(BUILD_DIR)/$(BINNAME) cat /etc/resolv.conf
	@echo ""
	@echo "=== Tier 2: faccessat2 SIGSYS suppression test ==="
	$(CURDIR)/$(BUILD_DIR)/$(LAUNCHERNAME) $(BUILD_DIR)/test-faccessat2
	@echo ""
	@echo "=== Tier 2: multithreaded clone() race test ==="
	$(CURDIR)/$(BUILD_DIR)/$(LAUNCHERNAME) $(BUILD_DIR)/test-sigsys-threads
	@echo ""
	@echo "=== Tier 2: reentrancy guard test ==="
	$(CURDIR)/$(BUILD_DIR)/$(BINNAME) $(BUILD_DIR)/test-seccomp-reentrancy
	@echo ""
	@echo "=== Tier 3: narrow seccomp (no ptrace) integration test ==="
	$(CURDIR)/$(BUILD_DIR)/$(MOUNTNAME) cat /etc/resolv.conf
	@echo ""
	@echo "=== Tier 3: reentrancy guard test ==="
	$(CURDIR)/$(BUILD_DIR)/$(MOUNTNAME) $(BUILD_DIR)/test-mount
	@echo ""
	@echo "=== All tests passed ==="

$(BUILD_DIR)/test-redirect: test/test-redirect.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $<

$(BUILD_DIR)/test-faccessat2: test/test-faccessat2.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $<

$(BUILD_DIR)/test-mount: test/test-mount.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $<

$(BUILD_DIR)/test-seccomp-reentrancy: test/test-seccomp-reentrancy.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $<

$(BUILD_DIR)/test-sigsys-threads: test/test-sigsys-threads.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -lpthread
