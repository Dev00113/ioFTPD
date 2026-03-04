# UNC / SMB Path Limitations

UNC and SMB paths behave very differently from local NTFS paths, even when Windows long‑path support is enabled. This page explains the real limitations of SMB, why long paths may still fail, and how ioFTPD behaves when operating on UNC shares.

---

## Overview

ioFTPD v7.10.0 supports long paths on all backends, but **UNC/SMB paths remain the least reliable** due to server‑side restrictions. These limitations are imposed by the SMB protocol and the remote server, not by ioFTPD or NTFS.

Even with long‑path support enabled in Windows, SMB servers often reject paths far shorter than the 32k NTFS limit.

---

## Why SMB Has Its Own Limits

SMB servers perform their own:

- Path normalization  
- Canonicalization  
- Security checks  
- Share‑root validation  
- Component‑length validation  

These checks occur **before** NTFS sees the path. If the SMB server rejects the path, ioFTPD cannot override it.

Common SMB limits:

- Total path length: **1–4 KB** (varies by server)
- Per‑component length: **200–255 characters**
- Maximum nesting depth: varies by server
- DFS and junction expansion may reduce available length

---

## Typical Failure Symptoms

SMB servers often return misleading Windows error codes:

- `ERROR_FILE_NOT_FOUND (2)`
- `ERROR_PATH_NOT_FOUND (3)`
- `ERROR_INVALID_NAME (123)`
- `ERROR_FILENAME_EXCED_RANGE (206)`

These errors do **not** necessarily mean the file is missing — they often mean:

> “The SMB server rejected the path because it is too long.”

ioFTPD normalizes these into:

```
550 <path>: Path too long for NTFS.
```

This provides a consistent user‑visible error.

---

## Compatibility Matrix for UNC / SMB

| Operation | UNC Support | Notes |
|----------|-------------|-------|
| LIST / MLSD | ✔ Works | Until SMB normalization fails |
| CWD / PWD | ✔ Works | Deep paths may fail |
| STOR / APPE | ⚠ Unreliable | SMB rejects long normalized paths |
| RETR | ⚠ Unreliable | Same as STOR |
| DELE | ✔ Works | Until SMB limit |
| RMD | ✔ Works | `.ioFTPD` metadata may push path over limit |
| RNFR / RNTO | ⚠ Often fails | Destination path usually fails first |
| Directory recursion | ⚠ Unreliable | Deep UNC paths may fail |
| Reparse points | ❌ Unsupported | SMB does not expose reparse metadata |

---

## Why Mapped Drives Work Better

Mapped drives (e.g., `Z:\`) behave like local NTFS because:

- Windows resolves the UNC path internally  
- ioFTPD receives a local NTFS path  
- SMB normalization happens earlier and is more permissive  

Mapped drives avoid many UNC limitations and are recommended for deep directory structures.

---

## Practical Recommendations

- Prefer **local NTFS** or **mapped drives** for long paths  
- Avoid extremely long directory names on UNC shares  
- Keep per‑component names under **200 characters**  
- Expect SMB to fail before NTFS does  
- Remember that `.ioFTPD` metadata adds extra characters to the path  
- Use UNC only when necessary, and test deep paths before deployment  

---

## Summary

UNC/SMB paths are limited by the SMB server, not ioFTPD.  
Even with long‑path support enabled, SMB servers may reject paths far shorter than NTFS allows. ioFTPD handles these failures gracefully and returns consistent FTP error messages, but cannot override SMB’s internal limits.

For maximum reliability, use **local NTFS** or **mapped drives** when working with deep directory structures or long filenames.
