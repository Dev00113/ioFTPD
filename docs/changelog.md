---
title: Change log
---

# Changelog

All notable changes to ioFTPD are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [7.10.0] — 2026-03-03

### Added

- **Long-path support** — ioFTPD can now open, read, create, delete, and move files
  and directories whose absolute path exceeds the legacy `MAX_PATH` (260-character)
  limit on Windows 10 build 14393+ / Server 2016+.  New `[FTP] Long_Path_Support`
  ini config key accepts `Auto` (default — detects OS capability and the
  `HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\LongPathsEnabled` registry flag),
  `On` (force enable), or `Off` (disable).  New `src/LongPath.c` module handles OS
  detection and transparently prepends the `\\?\` prefix at Win32 API call sites in
  `File.c` and `DirectoryCache.c`; internal buffers in `IoMoveDirectory` widened from
  `MAX_PATH` to `_MAX_LONG_PATH` (4 096 characters).  Serialised on-disk structures
  (user/group VFS paths) are unchanged for binary compatibility.

- **`Certificate_Type`** per-service ini config key — selects the key algorithm
  used when auto-generating a certificate at startup (`Create_Certificate = True`)
  or when `SITE MAKECERT` is issued.  Accepted values: `RSA` (default, maximum
  client compatibility) and `ECDSA` (smaller keys, faster handshakes, recommended
  for new deployments).  Unrecognised values fall back to RSA.  Both code paths
  (`Secure_MakeCert` and `Admin_MakeCert`) log the selected type, emit a
  `LOG_ERROR` on invalid values, and note when the default is applied.
  `Admin_MakeCert` also writes the selection to the user's FTP response buffer.

### Fixed

- **`RMD` false "550 Directory not empty"** — when a directory contained only the
  internal `.ioFTPD` permissions file, `IoRemoveDirectory` used the no-op
  `LongPath_Prefix` + `DeleteFile` to remove it, which silently failed for long
  paths; the directory then appeared non-empty to `RemoveDirectory`.  Fixed by
  replacing that call with `IoDeleteFileEx`, which applies the `\\?\` retry
  automatically.

- **NTFS path-too-long error normalization** — `IoIsNtfsPathTooLongError` now
  recognizes all four Win32 error codes that Windows returns for path-length
  rejections, depending on OS version and path length:
  `ERROR_FILENAME_EXCED_RANGE` (206, always), `ERROR_INVALID_NAME` (123, always),
  `ERROR_PATH_NOT_FOUND` (3, always after a `\\?\` retry), and
  `ERROR_FILE_NOT_FOUND` (2, when path length ≥ `MAX_PATH` — returned by Windows
  during internal path normalisation before the filesystem API runs, instead of 206,
  on some Windows builds for very long paths).  All six long-path wrappers
  (`IoCreateFile`, `IoGetFileAttributesEx`, `IoDeleteFileEx`, `IoRemoveDirectoryEx`,
  `IoMoveFileEx`, `IoOpenReparsePointForDelete`) normalize these to
  `ERROR_FILENAME_EXCED_RANGE` after their `\\?\` retry, producing the consistent
  FTP reply `550 Path too long for NTFS.` across STOR, APPE, RETR, DELE, RMD,
  RNFR, RNTO, MDTM, SIZE, and MLST.  Previously these operations returned
  `550 Invalid filename.` or an OS-dependent message.

- **`IoRemoveReparsePoint` silent error loss** — `CloseHandle` called after a
  failed `FSCTL_GET_REPARSE_POINT` or `FSCTL_DELETE_REPARSE_POINT` clobbered
  `GetLastError()`, causing the caller to receive error 0 instead of the real
  failure code and log nothing useful.

---

## [7.9.0] — 2026-02-28

### Added

- **`MLST` command** (RFC 3659 §7) — single-entry listing on the control channel.
  Resolves the optional path argument via the same `PWD_CWD2` path as `FTP_Size`;
  returns `type`, `size`, `modify`, `UNIX.mode`, `UNIX.owner`, `UNIX.group` facts.
  `type=cdir` when argument is `.` or absent; `type=OS.Unix-slink:` for symbolic
  links. RFC 3659 §7.3.1 250 multi-line response format. Per RFC, advertising
  `MLST` in `FEAT` implies `MLSD` support as well. (`226357b`)
- **`[OpenSSL] OpenSSL_SecurityLevel`** ini config key — sets the OpenSSL security
  level (0–5), controlling minimum key sizes and cipher strength per service.
  (`fb21938`)
- **`[OpenSSL] OpenSSL_LoadLegacyProvider`** ini config key — controls loading of
  the OpenSSL 3.x legacy provider (default: `True`) to maintain DHE-RSA/AES-CBC
  FXP compatibility with older daemons. (`e672f49`)
- **`[Service] OpenSSL_Ciphers13`** per-service ini config key — restricts TLS 1.3
  ciphersuites; absent key leaves OpenSSL secure defaults in effect. (`e672f49`)
- **`Version.h`** — new header centralising application version constants; build
  system (`ioFTPD.rc`, `ioFTPD-v7.vcxproj`) updated to reference it. (`34f4472`)

### Changed

- **`AUTH SSL`** is now a direct synonym for `AUTH TLS`; the separate SSL handshake
  code path is removed. (`6a1f6f5`)
- **Minimum Windows version** raised to Vista; XP-era compatibility stubs removed
  from `IoKnock/stdafx.h` and `include/ioFTPD.h`. (`4ceb86a`)
- **`MessageVariables.c`** — major internal restructuring with no user-visible
  behaviour change. (`4ceb86a`)
- **`Socket.c`** — comprehensive overhaul: lock-order consistency, IOCP
  completion-key width, `INVALID_SOCKET` sentinel handling, linger/`CloseSocket`
  semantics, `SafeGetTickCount64` in the scheduler loop, `HostToAddress` safety
  improvements. (`351261b`, `566454b`, `083b848`, `84e39d9`)
- **`Services.c`** and **`FtpDataChannel.c`** — significant restructuring.
  (`c048f20`, `b22f2bd`)
- **`SocketAPI.c`** — restructured; data transfer reliability and throughput
  improved. (`b22f2bd`)
- **TLS cipher configuration** split into two distinct API calls:
  `SSL_CTX_set_cipher_list` for TLS 1.0–1.2 and `SSL_CTX_set_ciphersuites` for
  TLS 1.3, each now receiving the correct format string. (`e672f49`)
- **`SITE WHO` output** — formatting and accuracy improved. (`1ef6782`, `114c223`,
  `b22f2bd`)
- **`Compare.c`** — all `tolower()` calls now cast their input to
  `unsigned char` before evaluation, eliminating undefined behavior on
  Windows where `char` is signed. This prevents negative values in the
  0x80–0xFF range from triggering UB in the C standard library and
  ensures correct, stable matching semantics across `spCompare`,
  `iCompare`, and `PathCompare`. Return‑value comparisons were likewise
  updated to use unsigned arithmetic. (`f95886a4`)


### Fixed

- **Tcl idle time inflated to ~7 weeks** — `TCL_TIMEIDLE` used
  `Time_DifferenceDW64(dwIdleTickCount, SafeGetTickCount64())` where
  `dwIdleTickCount` is a DWORD-truncated tick value. After 49.7 days uptime the
  stored DWORD wraps around and the 64-bit subtraction inflates the result by
  ~4.3 billion ms (~7 weeks). Fixed to use the same DWORD unsigned-wraparound
  arithmetic `(DWORD)now - stored` already used by `Who.c`. (`cfc6046`)
- **OpenSSL shutdown crash** (`0xC0000005` in CRT `strnlen`) — `Security_DeInit`
  called `OSSL_PROVIDER_unload()` while FTP worker threads still held live SSL
  objects, causing a use-after-free. OpenSSL 3.x registers its own `atexit`
  cleanup handler; `Security_DeInit` now clears the provider pointers and lets
  the runtime handle unloading. (`9563e4a`)
- **XCRC FEAT suppression** — inverted boolean caused XCRC to be suppressed when
  it should be advertised and vice versa. (`9563e4a`)
- **TLS 1.3 ciphersuite API misuse** — `SSL_CTX_set_ciphersuites` was receiving a
  TLS 1.2 cipher string, causing silent failure on OpenSSL 3.x. It now receives
  correctly formatted TLS 1.3 suite names. (`e672f49`)
- **DH parameters — deprecated API** — replaced `PEM_read_DHparams` /
  `SSL_CTX_set_tmp_dh` / `DH_free` with `OSSL_DECODER_CTX_new_for_pkey` /
  `OSSL_DECODER_from_fp` / `SSL_CTX_set0_tmp_dh_pkey` (EVP_PKEY ownership
  transferred to the context on success). (`e672f49`)
- **`Config_Get_Int` pointer bug** — literal `-1` was passed instead of a
  `&secLevel` pointer when reading the security level config key. (`e672f49`)
- **FXP compatibility with FTPRush v2 and older ioFTPD daemons** — cipher and
  protocol negotiation corrected for site-to-site TLS transfers. (`84288ad`)
- **`SITE MAKECERT`** — certificate generation repaired. (`b22f2bd`)
- **Idle time counter storage** — `dwTransferLastUpdated` promoted to `ULONGLONG`
  in `Client.h`; idle tracking updated across `MessageHandler.c`,
  `FtpDataChannel.c`, `DataCopy.c` to avoid premature 32-bit wrap. (`cc99b6d`)
- **Buffer overruns and precision errors** in `Threads.c`, `Who.c`, `Tcl.c`.
  (`7841e6d`)
- **MessageWindow message handling** — incorrect window message calls corrected in
  `Socket.c`. (`083b848`, `114c223`)
- **Garbled OpenSSL log output** — in a Unicode build `Putlog` format strings are
  wide (`wchar_t*`), where `%s` expects a wide string argument.  Four messages
  in `Secure_Create_Ctx` passed narrow `char*` variables directly (DH param file
  path, DH-key application failure cert name, `OpenSSL_Groups` invalid-value
  message, `OpenSSL_Groups` default-fallback message), causing the raw bytes to be
  walked as UTF-16LE code points and printed as mojibake.  Changed to `%hs`, which
  forces narrow-string interpretation regardless of format string width.
- **OpenSSL legacy provider not loading on production servers** — `libcrypto-3.dll`
  embeds the build-time `--prefix` path as `MODULESDIR`.  On a server where that
  path does not exist, `OSSL_PROVIDER_load("legacy")` silently fails no matter
  where `legacy.dll` is placed.  `Security_Init` now calls
  `OSSL_PROVIDER_set_default_search_path(NULL, "<exedir>\lib\ossl-modules")`
  before loading any provider, directing OpenSSL to the runtime-correct location.

### Removed

- **OpenSSL ENGINE API** — `<openssl/engine.h>` and all ENGINE calls removed
  (ENGINE subsystem removed in OpenSSL 3.0). (`6a8462f`)
- **OpenSSL thread-locking callbacks** — `CRYPTO_dynlock_value` struct,
  `Secure_Dyn_Create/Lock/Destroy_Function`, `Secure_Locking_Callback`, and the
  lock-array allocation removed (superseded in OpenSSL 1.1.0). (`6a8462f`)
- **Deprecated OpenSSL 1.1.0 cleanup calls** — `ERR_remove_state`,
  `ENGINE_cleanup`, `ERR_free_strings`, `EVP_cleanup`,
  `CRYPTO_cleanup_all_ex_data`, `CRYPTO_set_locking_callback` removed from
  `Security_DeInit`. (`6a8462f`)
- **17 removed `SSL_OP_*` constants** — options no longer present in OpenSSL 3.0
  removed from `GetSslOptionBit`. (`6a8462f`)
- **AUTH SSL separate handler** — AUTH SSL is now a one-line alias for AUTH TLS;
  the distinct SSL-only path is gone. (`6a1f6f5`)
- **Dead commented-out code** — `BindSocketToDevice` and `UnbindSocket` stubs
  removed from `Socket.c`; `src/Unused-code.txt` and stale build capture file
  deleted. (`8ad6884`)

### Upgraded

- **OpenSSL** — full three-stage migration:
  - `1.0.x` → `1.1.1` — EVP abstraction layer, `TLS_method()` replacing
    `SSLv23_method()`, removal of locking layer (`6a8462f`)
  - `1.1.1` → **`3.6.1`** — provider model (`default` + optional `legacy`),
    `OSSL_DECODER` for DH params, `SSL_CTX_set0_tmp_dh_pkey` (`e672f49`)
- **Tcl** — `8.5.9` (required source patches) → **`9.0+`**:
  - Linker target updated to `tcl90.lib`
  - Version check changed from exact `9.0.2` match to `>= major 9`, accepting
    future patch/minor releases without a rebuild
  - Tcl source patches no longer required; handle inheritance handled natively
    in Tcl 9.0 (`50d64ee`)
- **Build system** — all three configurations (Debug / Release / Purify) aligned
  to shared OpenSSL 3.x and Tcl 9.0 library paths; `libeay32.lib`/`ssleay32.lib`
  replaced with `libssl.lib`/`libcrypto.lib`. (`6a8462f`)

### Documentation

- **`README.md`** — initial project documentation: prerequisites, build
  instructions, known issues, dependency table. Updated for Tcl 9.0.2 and
  OpenSSL 3.6.1. (`40ebe6d`, `50d64ee`)
- **`CHANGELOG.md`** — this file. (`HEAD`)
