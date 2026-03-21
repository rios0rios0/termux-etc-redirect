PREFIX ?= /data/data/com.termux/files/usr
CC     ?= clang
CFLAGS  = -O2 -Wall -Wextra -Werror -fPIC -D_GNU_SOURCE
LDFLAGS_SO = -shared -ldl
LDFLAGS_BIN =

LIBNAME = libtermux-etc-redirect.so
BINNAME = termux-etc-seccomp

BUILD_DIR = build

.PHONY: all clean install test

all: $(BUILD_DIR)/$(LIBNAME) $(BUILD_DIR)/$(BINNAME)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/$(LIBNAME): src/termux-etc-redirect.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS_SO) -o $@ $<

$(BUILD_DIR)/$(BINNAME): src/termux-etc-seccomp.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS_BIN) -o $@ $<

install: all
	install -d $(PREFIX)/lib $(PREFIX)/bin
	install -m 755 $(BUILD_DIR)/$(LIBNAME) $(PREFIX)/lib/$(LIBNAME)
	install -m 755 $(BUILD_DIR)/$(BINNAME) $(PREFIX)/bin/$(BINNAME)

clean:
	rm -rf $(BUILD_DIR)

test: all $(BUILD_DIR)/test-redirect
	@echo "=== Tier 1: LD_PRELOAD unit test ==="
	LD_PRELOAD=$(CURDIR)/$(BUILD_DIR)/$(LIBNAME) $(BUILD_DIR)/test-redirect
	@echo ""
	@echo "=== Tier 2: seccomp integration test ==="
	$(CURDIR)/$(BUILD_DIR)/$(BINNAME) cat /etc/resolv.conf
	@echo ""
	@echo "=== All tests passed ==="

$(BUILD_DIR)/test-redirect: test/test-redirect.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $<
