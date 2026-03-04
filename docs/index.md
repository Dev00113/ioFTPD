# ioFTPD

A modernized continuation of the classic Windows FTP server, updated for today’s platforms with long‑path support, improved filesystem handling, modern cryptography, and active maintenance.

---

## Overview

ioFTPD is a high‑performance FTP/FTPS server for Windows, designed for speed, extensibility, and deep filesystem integration.  
This project maintains and modernizes the original codebase with:

- Full long‑path support (beyond MAX_PATH)
- Improved UNC/SMB behavior
- Modern RSA and ECDSA certificate generation
- Updated error handling and diagnostics
- Compatibility with Windows 10/11 and Server 2016+

The goal is to preserve ioFTPD’s strengths while removing long‑standing Windows limitations and improving reliability on modern systems.

---

## Latest Release

**Version:** v7.10.0  
**Release date:** 2026‑03‑03  
**Download:**  
https://github.com/Dev00113/ioFTPD/releases/tag/v7.10.0

This release introduces full long‑path support across all FTP operations, modern certificate options, and several important fixes.

---

## Long‑Path Support

ioFTPD now supports files and directories whose absolute path exceeds the legacy 260‑character MAX_PATH limit.

Supported operations:

- Upload (STOR / APPE)
- Download (RETR)
- Delete (DELE / RMD)
- Rename / Move (RNFR / RNTO)
- Make directory (MKD)
- Directory listing (LIST / MLSD / STAT)
- Metadata operations (SIZE / MDTM / MLST)

### Requirements

Long‑path support requires:

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

- Auto — Detects OS support at startup  
- On — Forces long‑path mode (requires registry key)  
- Off — Reverts to MAX_PATH behavior  

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

A new INI key controls the algorithm:

```
[FTP_Service]
Certificate_Type = RSA     ; RSA (default) or ECDSA
```

### Supported Algorithms

- RSA 2048‑bit — Maximum compatibility  
- ECDSA P‑256 — Smaller keys, faster handshakes  

Unrecognized values fall back to RSA and log a warning.

---

## Fixes and Improvements

- Correct handling of `.ioFTPD` metadata on long paths  
- Consistent long‑path error reporting across all operations  
- Improved UNC/SMB behavior and diagnostics  
- Fixed error propagation in reparse‑point deletion  
- Updated directory recursion logic for deep paths  

---

## Upgrading from v7.9.0

No configuration changes are required.  
All new features are opt‑in via INI keys.  
User and group file formats remain unchanged.

To enable long‑path support:

```
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1 /f
```

Restart ioFTPD afterward.

---

## Project Links

- Releases: https://github.com/Dev00113/ioFTPD/releases  
- Source Code: https://github.com/Dev00113/ioFTPD  
- Issues: https://github.com/Dev00113/ioFTPD/issues  

---

## License

ioFTPD is distributed under its original license.  
See the repository for details.
