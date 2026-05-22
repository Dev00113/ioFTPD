---
title: ioFTPD
---

# ioFTPD

A modernized continuation of the classic Windows FTP server, updated for today's platforms with native 64-bit support, long‑path support, improved filesystem handling, modern cryptography, and active maintenance.

---

## Latest Stable Release

**Version:** v8.0.0  
**Release date:** 2026‑05‑22  
**Download:**  
https://github.com/Dev00113/ioFTPD/releases/tag/v8.0.0

v8.0.0 is a major release that introduces a native 64-bit build alongside the existing Win32 build. Both ship from the same source.

### Prerequisites

**x64 build** — install both runtimes:
- [Visual C++ 2015-2022 x64](https://aka.ms/vs/17/release/vc_redist.x64.exe) — required by ioFTPD.exe
- [Visual C++ 2015-2022 x86](https://aka.ms/vs/17/release/vc_redist.x86.exe) — required by ioFTPD-Watch.exe

**Win32 build** — install:
- [Visual C++ 2015-2022 x86](https://aka.ms/vs/17/release/vc_redist.x86.exe)

### Breaking Change

> The **ioFTPD Message Window** (`WM_DATACOPY_FILEMAP` / `WM_SHMEM`) wire protocol
> has changed. External IPC clients must be rebuilt against the v8.0 headers.
> 32-bit IPC clients work with the Win32 build only — the x64 build rejects 32-bit senders.

### What's New in v8.0.0

- **Native 64-bit (AMD64) build** — no virtual-address ceiling, no `LARGEADDRESSAWARE` workaround; ASLR, DEP, and high-entropy ASLR enabled; Win32 build continues alongside x64
- **ioFTPD Message Window protocol redesigned** — wire format updated for 64-bit compatibility; `DC_MESSAGE_WIRE` uses fixed-width integer fields with no pointer-sized members so the layout is identical on 32-bit and 64-bit; `ONLINEDATA_WIRE` removes `LPTSTR` fields and raises the per-session transfer counter from 32-bit to 64-bit
- **Message Window security hardened** — per-command bounds validation, null-terminator checks on all string commands, least-privilege `OpenProcess`, 32-bit sender rejection with an actionable log entry
- **Fixed: `io link` stack buffer overflow** — could corrupt the stack silently and trigger `TerminateProcess` with no dump or log entry
- **Fixed: `Tcl_Init` failure in worker interpreter** — previously silent; now logged as an error
- **Multiple 64-bit correctness fixes** — IOCP completion keys, SOCKET atomics, Tcl wait objects, variable lookup, stack walker
- See [Changelog](changelog.md) for the full list.

---

## Previous Release: v7.10.1

**Release date:** 2026‑04‑20  
**Download:** https://github.com/Dev00113/ioFTPD/releases/tag/v7.10.1

- **Crash fix** — `ExecuteAsync` no longer crashes when running scheduler or Tcl-triggered events outside an FTP session
- **Crash fix** — Tcl panic handler logs to `ioFTPD_panic.log` and exits cleanly instead of falling through to an INT3 breakpoint
- **Stability** — NULL guards added to all UserFile and GroupFile Write callbacks
- **4 GB address space** — `LARGEADDRESSAWARE` enabled for the 32-bit build
- **`SITE IOVERSION`** — fixed garbled output caused by incorrect `%hs` format specifier

---

## Long‑Path Support

ioFTPD supports files and directories whose absolute path exceeds the legacy 260‑character MAX_PATH limit.

Supported operations: STOR / APPE, RETR, DELE / RMD, RNFR / RNTO, MKD, LIST / MLSD / STAT, SIZE / MDTM / MLST.

### Requirements

1. Windows 10 build 14393+ or Windows Server 2016+
2. Registry key enabled:
```
HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\LongPathsEnabled = 1
```
3. This build of ioFTPD (includes longPathAware manifest)

### Configuration

```
[FTP]
Long_Path_Support = Auto   ; Auto (default), On, or Off
```

### Backend Behavior

| Backend       | Status        | Notes |
|---------------|---------------|-------|
| Local NTFS    | Full support  | Deepest and most reliable |
| Mapped drive  | Full support  | Windows resolves UNC before ioFTPD sees it |
| UNC / SMB     | Partial       | SMB servers impose their own limits (typically 1–4 KB) |

When a path is too long, ioFTPD returns:
```
550 <path>: Path too long for NTFS.
```

---

## Certificate Generation (MAKECERT)

ioFTPD can auto‑generate TLS certificates at startup or via `SITE MAKECERT`.

```
[FTP_Service]
Certificate_Type = RSA     ; RSA (default) or ECDSA
```

- **RSA 2048‑bit** — maximum compatibility  
- **ECDSA P‑256** — smaller keys, faster handshakes  

---

## Upgrading

### Upgrading to v8.0.0

The ioFTPD Message Window wire protocol has changed. External IPC clients must be
rebuilt against the v8.0 headers before connecting to v8.0.0. No INI configuration
changes are required.

If upgrading from a release prior to v7.9.0, remove the old OpenSSL and Tcl DLLs
from `\system` before running the new build (`libssl-3-x64.dll` / `libcrypto-3-x64.dll`
replace the old names on x64; `tcl90.dll` replaces `tcl85t.dll`).

### Upgrading to v7.10.x from v7.9.x or earlier

No configuration changes required. All features are opt‑in via INI keys.
User and group file formats remain unchanged.

To enable long‑path support:
```
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1 /f
```

---

## Project Links

- Releases: https://github.com/Dev00113/ioFTPD/releases  
- Source Code: https://github.com/Dev00113/ioFTPD  
- Issues: https://github.com/Dev00113/ioFTPD/issues  

---

## License

ioFTPD is distributed under the GNU General Public License v2.  
See the repository for details.
