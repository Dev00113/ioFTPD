---
title: Long Path Support
---

# Long Path Support in ioFTPD

ioFTPD v7.10.0 introduces full long‑path support across all major FTP operations. This page explains how long‑path handling works, what Windows actually supports, and the real‑world limitations users will encounter on NTFS, mapped drives, and UNC/SMB shares.

Long‑path support allows ioFTPD to operate on paths longer than the legacy 260‑character MAX_PATH limit, but **not all backends support the same maximum length**. Understanding these differences is essential for reliable operation.

---

## Overview

Windows historically limited paths to 260 characters (MAX_PATH). Modern Windows versions allow paths up to ~32,767 UTF‑16 characters when long‑path support is enabled. ioFTPD now uses wide‑path (`\\?\`) APIs to support these extended paths.

Supported operations:

- STOR / APPE (upload)
- RETR (download)
- RNFR / RNTO (rename/move)
- DELE / RMD (delete)
- MKD (make directory)
- LIST / MLSD / STAT (directory listing)
- SIZE / MDTM / MLST (metadata)
- DirectoryCache recursion
- `.ioFTPD` metadata handling

---

## Requirements

Long‑path support requires:

1. Windows 10 build 14393+ or Windows Server 2016+
2. Registry key enabled:
```
HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\LongPathsEnabled = 1
```
3. ioFTPD v7.10.0 or later (includes longPathAware manifest)

---

## Configuration

```
[FTP]
Long_Path_Support = Auto   ; Auto (default), On, or Off
```

- Auto — Detects OS support at startup  
- On — Forces long‑path mode  
- Off — Reverts to MAX_PATH behavior  

---

# Compatibility Matrix

This matrix summarizes how long‑path support behaves across different backends.  
**This is the most important section for users to understand.**

| Scenario | Local NTFS | Mapped Drive (Z:) | UNC Path (\\server\share) | Notes |
|---------|-------------|-------------------|----------------------------|-------|
| Directory listing (LIST/MLSD) | ✔ Fully supported | ✔ Fully supported | ✔ Supported until SMB normalization fails | SMB often fails earlier than NTFS |
| CWD / PWD | ✔ | ✔ | ✔ | UNC normalization may fail at extreme depth |
| STOR / APPE (upload) | ✔ | ✔ | ⚠ May fail early | SMB rejects long normalized paths |
| RETR (download) | ✔ | ✔ | ⚠ Same as STOR | |
| DELE (file delete) | ✔ | ✔ | ✔ until SMB limit | |
| RMD (directory delete) | ✔ | ✔ | ✔ until SMB limit | `.ioFTPD` handling now correct |
| RNFR/RNTO (rename/move) | ✔ | ✔ | ⚠ Destination path often fails first | `.ioFTPD` creation triggers SMB limit |
| SIZE / MDTM / MLST | ✔ | ✔ | ✔ until SMB limit | |
| DirectoryCache recursion | ✔ | ✔ | ⚠ Deep UNC paths may fail | |
| Reparse points (junctions) | ✔ | ✔ | ❌ Not supported | SMB cannot expose reparse metadata |
| Maximum path length | ~32k UTF‑16 | ~32k UTF‑16 | ⚠ Typically 1–4k depending on SMB server | SMB is the limiting factor |
| Per‑component limit | 255 chars | 255 chars | ⚠ Often 200–255 | Some SMB servers enforce shorter limits |

---

# Why “Long Paths Enabled” Does *Not* Mean 32k Everywhere

Even with long‑path support enabled in Windows and ioFTPD:

- **Local NTFS** supports the full ~32k UTF‑16 path length  
- **Mapped drives** behave like NTFS because Windows resolves the UNC path before ioFTPD sees it  
- **UNC/SMB paths** are limited by the SMB server, not NTFS  

This means:

- A path that works locally may fail over UNC  
- A rename that works on NTFS may fail on SMB  
- A deep directory tree may list correctly but fail on upload  
- SMB servers often return misleading errors like `ERROR_FILE_NOT_FOUND` when the real cause is “path too long”

SMB servers impose their own internal limits:

- Normalization limits (often 1–4 KB total path length)
- Per‑component limits (200–255 characters)
- Share‑root restrictions
- DFS or junction expansion limits
- Server‑side canonicalization rules

These limits vary by:

- Windows version  
- SMB dialect  
- Whether the share is local or remote  
- Whether DFS is involved  

**ioFTPD cannot override SMB’s limits.**

---

# Error Messages

ioFTPD normalizes all long‑path failures to:

```
550 <path>: Path too long for NTFS.
```

This replaces older inconsistent messages such as:

- Invalid filename  
- File not found  
- Path not found  

This message is returned consistently across:

- STOR / APPE  
- RETR  
- DELE / RMD  
- MKD  
- RNFR / RNTO  
- MDTM / SIZE / MLST  

---

# Known SMB/UNC Limitations

UNC/SMB paths are the least reliable backend for long paths.  
Common limitations include:

- SMB servers may reject paths long before NTFS does  
- Some servers enforce per‑component limits (200–255 characters)  
- Deep directory recursion may fail  
- Rename operations may fail if `.ioFTPD` metadata cannot be created  
- SMB often returns misleading error codes (2, 3, 123, 206)  

Mapped drives avoid many UNC limitations because Windows resolves the UNC path before ioFTPD sees it.

---

# Practical Guidance

- Prefer **local NTFS** or **mapped drives** for deep directory structures  
- Avoid extremely long directory names on UNC shares  
- Keep per‑component names under 200 characters for maximum compatibility  
- Expect SMB to fail before NTFS does  
- Remember that `.ioFTPD` metadata files add extra characters to the path  

---

# Summary

ioFTPD now supports deep directory structures and long filenames on modern Windows systems.  
Local NTFS and mapped drives offer the best compatibility, while UNC/SMB paths depend heavily on the SMB server’s own limits.

Long‑path support is powerful, but **not all backends support the same maximum length**. Understanding these differences ensures reliable operation and avoids unexpected failures.
