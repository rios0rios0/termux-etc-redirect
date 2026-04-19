PREFIX ?= /data/data/com.termux/files/usr
CC     ?= clang
CFLAGS  = -O2 -Wall -Wextra -Werror -fPIC -D_GNU_SOURCE
LDFLAGS_SO = -shared -ldl
LDFLAGS_BIN =

LIBNAME   = libtermux-etc-redirect.so
BINNAME   = termux-etc-seccomp
MOUNTNAME = termux-etc-mount

BUILD_DIR = build

.PHONY: all clean install test

all: $(BUILD_DIR)/$(LIBNAME) $(BUILD_DIR)/$(BINNAME) $(BUILD_DIR)/$(MOUNTNAME)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/$(LIBNAME): src/termux-etc-redirect.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS_SO) -o $@ $<

$(BUILD_DIR)/$(BINNAME): src/termux-etc-seccomp.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS_BIN) -o $@ $<

$(BUILD_DIR)/$(MOUNTNAME): src/termux-etc-mount.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS_BIN) -o $@ $<

install: all
	install -d $(PREFIX)/lib $(PREFIX)/bin
	install -m 755 $(BUILD_DIR)/$(LIBNAME)   $(PREFIX)/lib/$(LIBNAME)
	install -m 755 $(BUILD_DIR)/$(BINNAME)   $(PREFIX)/bin/$(BINNAME)
	install -m 755 $(BUILD_DIR)/$(MOUNTNAME) $(PREFIX)/bin/$(MOUNTNAME)

clean:
	rm -rf $(BUILD_DIR)

test: all $(BUILD_DIR)/test-redirect $(BUILD_DIR)/test-faccessat2 $(BUILD_DIR)/test-mount
	@echo "=== Tier 1: LD_PRELOAD unit test ==="
	LD_PRELOAD=$(CURDIR)/$(BUILD_DIR)/$(LIBNAME) $(BUILD_DIR)/test-redirect
	@echo ""
	@echo "=== Tier 2: seccomp integration test ==="
	$(CURDIR)/$(BUILD_DIR)/$(BINNAME) cat /etc/resolv.conf
	@echo ""
	@echo "=== Tier 2: faccessat2 SIGSYS suppression test ==="
	$(CURDIR)/$(BUILD_DIR)/$(BINNAME) $(BUILD_DIR)/test-faccessat2
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
