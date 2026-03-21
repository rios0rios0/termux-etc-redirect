# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- added LD_PRELOAD shared library (`libtermux-etc-redirect.so`) for dynamically linked binaries
- added seccomp user_notif interceptor (`termux-etc-seccomp`) for all binaries including statically linked Go programs
- added DNS path redirection (`/etc/resolv.conf`, `/etc/hosts`, `/etc/nsswitch.conf`)
- added TLS CA certificate path redirection for Go's hardcoded SSL paths
- added install script with automatic `nsswitch.conf` and `resolv.conf` creation
- added unit tests for LD_PRELOAD library and integration tests for seccomp interceptor
