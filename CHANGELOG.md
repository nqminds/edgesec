# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### 🚀 Features

* **Recap** by @mereacre in https://github.com/nqminds/edgesec/pull/264

  Adds a new tool recap to save captured packets to SQLite db from a pcap file or from an input stream.

### 🐛 Fixed

* fix(debian): remove unused dependency on `jq` by @aloisklink in https://github.com/nqminds/edgesec/pull/219
* fix(debian): compile enabled header middleware by @aloisklink in https://github.com/nqminds/edgesec/pull/220
* fix(debian): remove `-s` opt from edgesec service by @aloisklink in https://github.com/nqminds/edgesec/pull/223
* fix: fix missing WITH_NETLINK_SERVICE in iface by @aloisklink in https://github.com/nqminds/edgesec/pull/227
* Fix some bugs in `list_dir` by @aloisklink in https://github.com/nqminds/edgesec/pull/237
* fix: fix if_nametoindex implicit declaration by @aloisklink in https://github.com/nqminds/edgesec/pull/267
* fix(dnsmasq): truncate interface names/prefix by @aloisklink in https://github.com/nqminds/edgesec/pull/269
* fix: create folders for SQLite macconn_db by @aloisklink in https://github.com/nqminds/edgesec/pull/168
* fix(nl): fix missing curly brackets by @aloisklink in https://github.com/nqminds/edgesec/pull/285
* Add fallback for unsupported abstract sockets by @aloisklink in https://github.com/nqminds/edgesec/pull/278
* fix(nl): fix potential missing NUL terminator by @aloisklink in https://github.com/nqminds/edgesec/pull/289
* fix(sockctl): fix cleanup of unix mkdtemp dirs by @aloisklink in https://github.com/nqminds/edgesec/pull/291

### 📦️ Dependencies

* chore(deps): bump hostapd to v2.10 by @aloisklink in https://github.com/nqminds/edgesec/pull/216
* build: download uthash and utarray from upstream by @aloisklink in https://github.com/nqminds/edgesec/pull/232
* build: bump cmocka to latest master commit by @aloisklink in https://github.com/nqminds/edgesec/pull/258

#### Debian

* ci(debs): build for ubuntu 22.04 jammy by @aloisklink in https://github.com/nqminds/edgesec/pull/221
* build(debian): link to sqlite3/libpcap shared libs by @aloisklink in https://github.com/nqminds/edgesec/pull/240

### 🧰 Chore

<details>
  <summary>Truncated for brevity</summary>

* ci(docs): use new github-pages CI action by @aloisklink in https://github.com/nqminds/edgesec/pull/208
* OpenWRT Raspberry Pi 3 Toolchain Preset by @aloisklink in https://github.com/nqminds/edgesec/pull/211
* Use `debian/control` to install dependencies by @aloisklink in https://github.com/nqminds/edgesec/pull/212
* ci(deb): fix caching in pbuilder base by @aloisklink in https://github.com/nqminds/edgesec/pull/213
* build(openwrt): fix broken tests for OpenWRT by @aloisklink in https://github.com/nqminds/edgesec/pull/214
* ci(publish): fix incorrect Debian data by @aloisklink in https://github.com/nqminds/edgesec/pull/218
* style(deb): fix `debian/changelog` formatting by @aloisklink in https://github.com/nqminds/edgesec/pull/222
* test: test crypt_service if `USE_CRYPTO_SERVICE` by @aloisklink in https://github.com/nqminds/edgesec/pull/224
* Add code coverage GitHub Action by @aloisklink in https://github.com/nqminds/edgesec/pull/225
* test: handle case where `/tmp/edgesec` exists by @aloisklink in https://github.com/nqminds/edgesec/pull/226
* docs: add codecov badge to README by @aloisklink in https://github.com/nqminds/edgesec/pull/228
* Run code coverage on more devices/presets by @aloisklink in https://github.com/nqminds/edgesec/pull/229
* Fix failing WITH_CRYPT_SERVICE test by @aloisklink in https://github.com/nqminds/edgesec/pull/230
* Fix CMake CMP0135 configure warning by @aloisklink in https://github.com/nqminds/edgesec/pull/231
* ci: output on ctest failure by @aloisklink in https://github.com/nqminds/edgesec/pull/233
* Fully test `make_dirs_to_path()` by @aloisklink in https://github.com/nqminds/edgesec/pull/236
* build: fix unknown autoconf os error message by @aloisklink in https://github.com/nqminds/edgesec/pull/245
* test: test for NULL string in string_append_char by @aloisklink in https://github.com/nqminds/edgesec/pull/244
* Test OpenWRT in CI by @aloisklink in https://github.com/nqminds/edgesec/pull/234
* build: convert LINK_FLAGS to target_link_options by @aloisklink in https://github.com/nqminds/edgesec/pull/243
* ci: limit `create-debs.yml` permissions by @aloisklink in https://github.com/nqminds/edgesec/pull/250
* refactor: remove linux/types.h and posix_types.h by @aloisklink in https://github.com/nqminds/edgesec/pull/249
* test: fix undeclared identifier AF_INET by @aloisklink in https://github.com/nqminds/edgesec/pull/251
* Tidies up the `uci_wrt.c` file by @aloisklink in https://github.com/nqminds/edgesec/pull/235
* ci: setup C CodeQL code quality scanner by @aloisklink in https://github.com/nqminds/edgesec/pull/238
* Add Clang support to edgesec by @aloisklink in https://github.com/nqminds/edgesec/pull/242
* refactor: replace <linux/if.h> with <net/if.h> by @aloisklink in https://github.com/nqminds/edgesec/pull/246
* refactor: fix const char * warnings by @aloisklink in https://github.com/nqminds/edgesec/pull/239
* refactor: remove `#include <linux/if_link.h>` by @aloisklink in https://github.com/nqminds/edgesec/pull/247
* refactor: replace ETH_ALEN with ETHER_ADDR_LEN by @aloisklink in https://github.com/nqminds/edgesec/pull/248
* refactor: change netinit/in.h #include order by @aloisklink in https://github.com/nqminds/edgesec/pull/253
* ci: fix intermittent disk I/O error by @aloisklink in https://github.com/nqminds/edgesec/pull/254
* refactor: remove unnecessary middlewares includes by @aloisklink in https://github.com/nqminds/edgesec/pull/255
* refactor: remove `#include <asm/types.h>` by @aloisklink in https://github.com/nqminds/edgesec/pull/256
* refactor: add #include <stdint.h> before cmocka by @aloisklink in https://github.com/nqminds/edgesec/pull/257
* test: remove incorrect error_t type by @aloisklink in https://github.com/nqminds/edgesec/pull/260
* refactor(wpabuf): simplify byte swaps by @aloisklink in https://github.com/nqminds/edgesec/pull/259
* refactor: use POSIX standard udphdr/tcphdr by @aloisklink in https://github.com/nqminds/edgesec/pull/261
* refactor: include sys/socket.h then netinet/in.h by @aloisklink in https://github.com/nqminds/edgesec/pull/262
* refactor: replace non-standard icmphdr with icmp by @aloisklink in https://github.com/nqminds/edgesec/pull/263
* test: fix invalid test variable type by @aloisklink in https://github.com/nqminds/edgesec/pull/266
* refactor(nl): mark subnet_mask param as const by @aloisklink in https://github.com/nqminds/edgesec/pull/268
* test(os): standardize test_run_command test by @aloisklink in https://github.com/nqminds/edgesec/pull/272
* Improve the GitHub Actions cache step by @aloisklink in https://github.com/nqminds/edgesec/pull/271
* Fix ifaceu test on FreeBSD by @aloisklink in https://github.com/nqminds/edgesec/pull/273
* refactor(sockctl): make data param `const` by @aloisklink in https://github.com/nqminds/edgesec/pull/274
* Cleanup sockctl tests by @aloisklink in https://github.com/nqminds/edgesec/pull/276
* Eloop test by @mereacre in https://github.com/nqminds/edgesec/pull/275
* test(os): support freebsd for test_list_dir() by @aloisklink in https://github.com/nqminds/edgesec/pull/277
* Standardise `test_run_commands` test by @aloisklink in https://github.com/nqminds/edgesec/pull/279
* refactor(middlewares): fix const stype difference by @aloisklink in https://github.com/nqminds/edgesec/pull/280
* refactor(radius_client): fix ptr to enum cast by @aloisklink in https://github.com/nqminds/edgesec/pull/283
* test(os): fix broken make_dirs_to_path teardown by @aloisklink in https://github.com/nqminds/edgesec/pull/282
* test(packet_queue): fix uninitialised warning by @aloisklink in https://github.com/nqminds/edgesec/pull/284
* test(hostapd): fix unused var in openwrt tests by @aloisklink in https://github.com/nqminds/edgesec/pull/286
* Better CMocka asserts by @aloisklink in https://github.com/nqminds/edgesec/pull/287
* test(sqlite_header): improve sqlite_header tests by @aloisklink in https://github.com/nqminds/edgesec/pull/288
* feat(os): add copy_argv() function by @aloisklink in https://github.com/nqminds/edgesec/pull/281
* refactor(sockctl): store tmp sock in /tmp/edgesec by @aloisklink in https://github.com/nqminds/edgesec/pull/290
* Error on all C/C++ compiler warnings in `src/` and `tests/` by @aloisklink in https://github.com/nqminds/edgesec/pull/292
* Replace pthread with threads in `test_eloop_threaded` by @aloisklink in https://github.com/nqminds/edgesec/pull/293
* Remove deprecated `tempnam()` from eloop tests by @aloisklink in https://github.com/nqminds/edgesec/pull/296
* Added const qualifiers by @mereacre in https://github.com/nqminds/edgesec/pull/297

</details>

### 📝 Documentation

<details>
  <summary>Truncated for brevity</summary>

* Improve build documentation by @aloisklink in https://github.com/nqminds/edgesec/pull/215
* docs: add badges for doxygen C docs by @aloisklink in https://github.com/nqminds/edgesec/pull/217
* docs: add a "code-style LLVM" badge by @aloisklink in https://github.com/nqminds/edgesec/pull/241
* docs: optimize doxygen docs for C code by @aloisklink in https://github.com/nqminds/edgesec/pull/270
* docs: link to cppreference.com in doxygen docs by @aloisklink in https://github.com/nqminds/edgesec/pull/295

</details>

## [0.0.8] - 2022-07-26
### Added
- If there are no VLAN interfaces created, edgesec will try to set an IP if no IP present
- Added changelog file starting from version 0.0.8
- Compile doxygen with CI actions and added docs as iframe to [https://edgesec.info](https://edgesec.info)


### Changed
- The dnsmasq config uses three types of interfaces (bridge, interface and wifi interface) for the config
- Changed the code licence info to linux kernel style licence

### Removed
- Quarantine parameter removed from the config.ini
- Docusaurus page moved to [https://edgesec.info](https://edgesec.info) site and repo [https://github.com/nqminds/edgesec.info](https://github.com/nqminds/edgesec.info)
