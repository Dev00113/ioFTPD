---
title: Change log
---

# Changelog

All notable changes to ioFTPD are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [8.1.0] — 2026-06-29

### Added

- **Native network mount manager** (`src/NetworkMount.c`, `include/NetworkMount.h`) —
  ioFTPD now monitors and automatically reconnects UNC network shares referenced in
  `.vfs` files without any manual intervention or daemon restart.

  - **Automatic health monitoring** — every UNC share root (`\\server\share`) found in
    any loaded `.vfs` file is registered in a health table at parse time.  One background
    timer per share root probes the share via `GetFileAttributesA` on a configurable
    interval (default 60 s).  Probes run on job-pool worker threads; FTP throughput and
    I/O threads are completely unaffected.

  - **Exponential backoff on failure** — when a probe fails the timer retries at 10 s,
    20 s, 40 s, 80 s, 160 s, capped at `Network_Max_Retry_Interval` (default 300 s).
    On recovery the interval returns to the configured check interval immediately.

  - **Inline reactive reconnect** — `IoCreateFile` detects `ERROR_NETNAME_DELETED`
    (dropped connection, server still reachable) and attempts one synchronous
    `WNetAddConnection2A` + file-open retry on the calling thread before returning a
    failure to the FTP layer.  All other network error codes mark the share down and
    let the background timer handle reconnection.

  - **`NotifyAddrChange` watch thread** — a dedicated low-priority thread listens for
    Windows network interface state changes via overlapped `NotifyAddrChange`
    (`iphlpapi.h`).  When any NIC comes back online all currently-down shares are
    immediately retried rather than waiting for the next timer tick.  If registration
    fails at startup (e.g. network stack not yet ready), the thread retries every 30 s.

  - **Optional credential file `etc\netmounts.cfg`** — provides per-share credentials
    (`username`, `password`, `domain`) for shares that require authentication different
    from the service account.  The file is entirely optional: shares without a
    credential entry are monitored and reconnected using the service account's own
    Windows identity.  Credentials are zeroed from memory with `SecureZeroMemory` at
    shutdown.  A fully documented template is included in `Documents\netmounts.cfg`.

  - **`SITE REHASH` support** — credential file and interval config keys are reloaded
    without a daemon restart.  Updated credentials take effect on the next reconnect
    attempt.

  - **Human-readable error messages** — all common `WNetAddConnection2A` failure codes
    (access denied, wrong password, server not found, network unreachable, no network)
    are translated to plain-English log entries with actionable hints.  On errors
    `ERROR_UNEXP_NET_ERR` (59) and `ERROR_NOT_SUPPORTED` (50) the registry key
    `HKLM\SYSTEM\CurrentControlSet\Services\MrxSmb10\Start` is checked: if SMBv1 is
    disabled a specific log message identifies the root cause and recommends upgrading
    the remote device to SMBv2 or later.

  - **Startup stagger** — initial probes are spread 2.5 s apart per share to avoid
    a thundering-herd of simultaneous `GetFileAttributesA` calls at service start.

- **New `[Ftp]` ini config keys:**
  - `Network_Mounts_File` — path to the optional credential file (relative to the
    ioFTPD.exe directory or absolute); absent key disables credential-based reconnect
    while keeping health monitoring active.
  - `Network_Check_Interval` — seconds between probes on a healthy share (default: 60,
    minimum: 5).
  - `Network_Max_Retry_Interval` — maximum seconds between reconnect attempts on an
    offline share (default: 300, minimum: 10).

### Build

- **`iphlpapi.lib`** and **`mpr.lib`** added to `AdditionalDependencies` in all linker
  configurations (Win32 Release, x64 Release, Win32 Debug) for `NotifyAddrChange` and
  the `WNet*` APIs respectively.

---

## [8.0.0] — 2026-05-22

> **Breaking change** — the DataCopy shared-memory IPC wire format has changed.
> External IPC clients that communicate with ioFTPD via
> `WM_DATACOPY_FILEMAP` must be rebuilt against the v8.0 headers.
> v8.0.0 is the sole active release line and ships both a Win32 (32-bit)
> and x64 (64-bit) build. 32-bit IPC clients are compatible with the Win32
> build only — the x64 build rejects 32-bit senders.

### Added

- **Native 64-bit (AMD64) build** — ioFTPD now compiles and runs as a 64-bit
  process.  No virtual-address ceiling; no `/LARGEADDRESSAWARE` workaround.
  ASLR (`/DYNAMICBASE`), DEP (`/NXCOMPAT`), and high-entropy ASLR
  (`/HIGHENTROPYVA`) are enabled for the x64 build.
  Win32 Release continues to ship alongside x64.
  Verified on x64 with OpenSSL 3.6.1: TLS 1.3 connections, upload, download,
  rename, and `SITE WHO` all confirmed working.

- **`DC_MESSAGE_WIRE`** — new fixed-width IPC message header for shared-memory
  DataCopy requests.  Replaces `DC_MESSAGE` (which had `HANDLE`/`LPVOID`
  pointer-sized fields that differed between 32/64-bit processes).
  `DC_MESSAGE_WIRE` uses only `UINT32`/`UINT64` fields; layout is identical
  regardless of sender/receiver architecture (24 bytes on both).

- **`ONLINEDATA_WIRE`** — new cross-process wire format for online data.
  The two `LPTSTR` pointer fields (`tszRealPath`, `tszRealDataPath`) are
  replaced by `UINT32 dwRealPathLen`/`UINT32 dwRealDataPathLen`; string data
  follows immediately after `DC_ONLINEDATA` in shared memory.
  `dwBytesTransfered` widened to `UINT64 qwBytesTransfered` (removes the 4 GB
  per-session transfer cap).

- **`USERFILE_WIRE_SIZE` / `GROUPFILE_WIRE_SIZE`** macros — byte count safe
  to copy across a process boundary (excludes the process-local `lpInternal`
  and `lpParent` pointer tail fields).

### Fixed

- **IOCP completion keys** (`Threads.c`, `File.c`, `Socket.c`) — all negative
  sentinel values normalised to `(ULONG_PTR)-N`.  On x64, `(DWORD)-N` does not
  equal `(ULONG_PTR)-N` in a pointer-width comparison.
- **`GetQueuedCompletionStatus` key type** (`Threads.c`) — completion-key
  parameter changed from `DWORD*` to `ULONG_PTR*`; was truncating 64-bit keys.
- **`InterlockedExchange` on `SOCKET`** (`Services.c`, `Identify.c`) — replaced
  with `IoAtomicExchangeSocket`; `SOCKET` is `UINT_PTR` (8 bytes on x64).
- **Stack-walker register selection** (`IoDebug.c`) — `#ifdef _M_X64` selects
  `Rip`/`Rbp`/`Rsp` and `IMAGE_FILE_MACHINE_AMD64` on x64 builds.
- **Tcl 9.0 `Tcl_Size` API** (`Tcl.c`) — `Tcl_GetStringFromObj` length
  parameter changed from `int` to `Tcl_Size` (`ptrdiff_t`, 64-bit on x64).
- **`DC_VFS.pBuffer`** — corrected from `PBYTE[1]` (array of pointers, wrong
  stride on x64) to `BYTE[1]` (flexible byte array).
- **Memory.c debug allocator** — header arithmetic replaced with explicit
  `MEM_DEBUG_HEADER` struct so canary placement is correct on both 32/64-bit.
- Five isolated pointer-truncation fixes: `IoDebug.c` `SIZE_T` subtraction,
  `Tcl.c` fiber handle `%p` format, `Threads.c` `srand` seed fold,
  `Memory.c` `%IX` format string, `Memory.c` debug header layout.
- **`Tcl_WaitObject` pointer-truncation — "create new" path missed by initial fix**
  (`Tcl.c`) — The initial `waitobject` fix changed the "find existing object" path
  (line 525) but missed a second identical `lResult = (LONG)(ULONG_PTR)lpWaitObject`
  assignment in the "create new object" path (same text, different leading whitespace,
  so the `replace_all` silently skipped it). A 64-bit `LPTCL_WAITOBJECT*` returned
  by `waitobject open` on this path was still truncated to 32 bits. Any subsequent
  `waitobject wait`, `set`, `reset`, or `close` call zero-extended the saved 32-bit
  value to address `0x00000000XXXXXXXX` — confirmed as the root cause of a live
  crash (access violation reading `0xC7DEB6E4`, RIP `ioFTPD.exe+0x794B3`
  = `Tcl_WaitObject+0xC93`). Fixed by changing the second assignment to
  `(Tcl_WideInt)(ULONG_PTR)lpWaitObject`.
- **`io var get` / `io var unset` crash on x64** (`Tcl.c`) — `Tcl_Variable` builds
  a synthetic `LPTCL_VARIABLE` search key by subtracting `offsetof(TCL_VARIABLE, szName)`
  from the incoming Tcl string pointer (`szArgument`). An intermediate `(LONG)` cast
  truncated the 64-bit pointer to 32 bits before the subtraction, producing a
  completely wrong key address. `bsearch` then received and dereferenced the garbage
  pointer. Fixed by removing the `(LONG)` cast; arithmetic now runs at `ULONG_PTR`
  width: `(ULONG_PTR)szArgument - offsetof(TCL_VARIABLE, szName)`.
- **`InterlockedExchange((LPLONG)&lpData, ...)` on `LPVOID` field — spinlock UB**
  (`Tcl.c`) — `TCL_WAITOBJECT.lpData` is `LPVOID volatile` (8 bytes on x64). The
  spinlock `wait`, `set`, and `reset` handlers passed `(LPLONG)&lpData` to
  `InterlockedExchange`, which expects a `LONG*` (4-byte operand). On x64 this
  aliases an 8-byte field through a 4-byte pointer, which is undefined behaviour and
  may interact poorly with compiler aliasing optimisations. Replaced all three sites
  with `InterlockedExchangePointer(&lpData, (LPVOID)TRUE/FALSE)`, which operates on
  the full pointer-width `LPVOID volatile` field.
- **Pointer-difference cast cleanup** (`DirectoryCache.c`, `IdDatabase.c`) — four
  `(ULONG)` casts on pointer-difference expressions changed to `(DWORD)` with a
  comment noting the value is bounded by a 4 KB stack buffer or a small ID-array
  count. The `SetFilePointer` offset cast clarified as `(LONG)(DWORD)` to make the
  intentional narrowing explicit. No runtime effect; fixes latent warnings.
- **`IoAtomicExchangeSocket` macro** (`Services.c`, `Identify.c`) — replaces
  `SOCKET`-typed `InterlockedExchangePointer` calls.  The `PVOID*` cast was
  strict-aliasing UB; the new macro uses `_InterlockedExchange64` on x64 and
  `InterlockedExchange` on x86.
- **`UserFile_New2Old` field copy** — `sizeof(lpOld->AdminGroups)` corrected to
  `sizeof(lpOld->Groups)` for the Groups array (symmetric fix to New2Old).
- **Stack buffer overflow in `io link` VFS command** (`Tcl.c`) — `temp3[_MAX_PWD+1]`
  is filled by walking mount-point parent directories backwards. On servers with many
  VFS entries `dwPathLen` can exceed the array size, placing the initial write past the
  end of `temp3`. Adjacent stack variables are overwritten; the `/GS` stack-cookie check
  fires on return and calls `TerminateProcess` directly — no dump, no log entry. Fix:
  guard the backwards walk; log and skip if `dwPathLen >= sizeof(temp3)`.
- **`Tcl_Init` failure in worker interpreter silently ignored** (`Tcl.c`) — the return
  value of `Tcl_Init` in `Tcl_GetInterpreter` was discarded; a failure left the
  interpreter in an inconsistent state with no log entry. Now logs a `LOG_ERROR`
  including the Tcl error string.

### Security

- **DataCopy per-command size validation** (`DataCopy.c`) — every `DC_*` case
  arm validates `dwContextAvailable >= sizeof(expected_struct)` before reading
  any fields.  Prevents out-of-bounds reads when `qwContextOffset` is near the
  end of the mapped region.
- **`SafeStringInRegion()` null-terminator check** (`DataCopy.c`) — all string
  command arms scan for a null terminator within bounds before passing to any
  string function.
- **`DC_FILEINFO_READ` condition corrected** — was copying into an
  undersized buffer (inverted `<`/`>=` test); now returns required size when
  buffer too small, copies only when large enough.
- **`DC_FILEINFO_WRITE` underflow guard** — rejects when `dwBuffer <
  dwFileNameBytes` before the subtraction, preventing unsigned wrap-around.
- **Least-privilege `OpenProcess`** — `PROCESS_ALL_ACCESS` replaced with
  `PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION`; only those rights
  are needed for `DuplicateHandle` and `IsWow64Process`.
- **32-bit sender rejection on x64** (`DataCopy_Allocate`) — `IsWow64Process`
  detects WoW64 callers and rejects them with a log entry.  A 32-bit sender
  cannot receive the `LRESULT` pointer returned by `SendMessage` because WoW64
  truncates it to 32 bits, causing a silent hang and handle leak.
- **`SafeGetTickCount64()` consistency** (`WindowMessage_DataExchange`) —
  `GetTickCount()` (32-bit, wraps at 49 days) replaced with `SafeGetTickCount64()`
  to avoid wrap-around against a `ULONGLONG` counter.
- **`USERFILE_Zero_Internal` / `GROUPFILE_Zero_Internal`** wired in — macros
  were defined but never called; process-local `lpInternal`/`lpParent` pointer
  values are now explicitly zeroed before every IPC write-back.
- **`static_assert(sizeof(ONLINEDATA_WIRE) == 1384)`** in `WinMessages.h` —
  compile-time pin; any accidental layout change breaks the build immediately.
- **`VirtualQuery` truncation documented** — `SIZE_T → DWORD` narrowing uses
  `min(mbi.RegionSize, MAXDWORD)` to make the intentional narrowing explicit.

---

## [7.10.1] — 2026-04-20

### Added

- **Git-stamped build versioning** — every build now embeds the git commit
  count and 7-character commit hash in its version string.  The new format is
  `Major.Minor.Patch.Build-hash` (e.g. `7.10.1.66-b2c9759`) or
  `7.10.1.66-b2c9759-dirty` for uncommitted builds.  The Build component is the
  monotonically increasing `git rev-list --count HEAD` value, making builds from
  a single branch numerically comparable.  The hash provides an exact source
  reference for crash reports from third-party deployments.
  - A new PowerShell script `scripts/generate_version.ps1` runs automatically
    as an MSBuild pre-build target (before both C compilation and RC
    compilation) and writes `include/GitVersion.h` (gitignored).
  - `Version.h` now derives `IOFTPD_VERSION_BUILD` from `IOFTPD_GIT_COMMIT_COUNT`
    and exposes `IOFTPD_VERSION_FULL` (the full version+hash string) for use in
    the PE version resource.
  - The startup log, `SITE VERSION`, crash-log header, and `io version` Tcl
    command all report `tszIoVersionFull` (e.g. `7.10.1.66-b2c9759`).
  - Falls back gracefully to `Major.Minor.Patch.0-unknown` when git is
    unavailable (e.g. source downloaded as a zip).
	
### Fixed

- **Crash on `userfile unlock` for newly-created users** (`0xC0000005` access
  violation) — `User_StandardWrite` in `UserFileModule.c` dereferenced
  `lpUserFile->lpInternal` without checking for NULL.  `lpInternal` is
  intentionally set to NULL by `User_Register` in the shared copy to prevent
  use-after-free on error paths; a Tcl bot calling `userfile open` / `userfile
  unlock` before the user had ever logged in (so no file handle had been opened
  by `User_StandardOpen`) would crash the daemon.  `User_StandardWrite` now
  mirrors the recovery pattern already present in `User_Default_Write`: when
  `lpInternal` is NULL it opens the user file by UID, stores the resulting
  `USERFILE_CONTEXT` back into the shared copy, and proceeds with the write.

- **User file open/read fails on long paths** — `User_StandardRead` opened user
  files via the raw `CreateFile` Win32 API, which cannot handle paths exceeding
  `MAX_PATH` (260 characters).  Replaced with `IoCreateFile`, which transparently
  retries with a `\\?\`-prefixed wide path when the ANSI call fails with a
  path-length error.  Relevant for deployments where the `User_Files` directory
  is nested inside a long directory tree (e.g. on a USB drive).

- **User file rename fails on long paths** (`User_StandardCreate`) — `MoveFileEx`
  used to rename the newly created user file from its temporary name to its
  UID-based name could fail for long paths.  Replaced with `IoMoveFileEx`.

- **`MKD`, `CWD`, and `LIST` fail for Windows reserved device names** (`Con`,
  `Con.hello`, `NUL`, `COM1`, etc.) — `CreateDirectoryA`, `GetFileAttributesExA`,
  and `FindFirstFileA` return `ERROR_DIRECTORY` (267) on some Windows versions
  when any path component matches a reserved device name, even when a full
  absolute path is given.  Three fixes applied:
  - `IoCreateDirectory` (`LongPath.c`): added `ERROR_DIRECTORY` to the
    `\\?\`-retry condition, allowing such directories to be created.
  - `IoGetFileAttributesEx` (`LongPath.c`): added `ERROR_DIRECTORY` to the
    `\\?\`-retry condition, allowing `CWD` and directory attribute queries to
    succeed.
  - `IoWin32FindFirstFile` (`LongPath.c`): added `ERROR_DIRECTORY` to the
    `\\?\`-retry condition, allowing directory enumeration inside such paths.
  - `UpdateDirectory` (`DirectoryCache.c`): added `ERROR_DIRECTORY` to the
    non-fatal child-open error list, preventing a CON-named subdirectory from
    aborting the scan of its parent and making the parent directory inaccessible.
  The `\\?\` extended-length prefix bypasses Win32 device-name interception
  entirely at the NT layer.

- **`ExecuteAsync` crashes with access violation when running non-FTP events**
  (`0xC0000005 EXCEPTION_ACCESS_VIOLATION` at `ioFTPD.exe+0x14FBC`) — the
  cleanup path of `ExecuteAsync` called `LockClient(dwCID)` unconditionally.
  `dwCID` is initialised to `-1` and only updated when the event originates
  from a connected FTP user (`lpEventData->dwData == C_FTP`).  For
  scheduler-triggered or Tcl-originated `EXEC` events `dwCID` stayed
  `0xFFFFFFFF`, causing `lpClientArray[0xFFFFFFFF]` — an out-of-bounds read
  that returned a garbage non-NULL pointer (`0x0000000A`).  The subsequent
  `NULL` check passed, and `lpClient->Static.dwFlags &= ~S_SCRIPT` crashed
  dereferencing `0x0000000E`.  Fix: guard the cleanup block with
  `if (dwCID != (DWORD)-1)`.

- **Tcl panic falls through to INT3 padding — process hangs instead of dying**
  (`0x80000003 EXCEPTION_BREAKPOINT`) — when Tcl's internal allocator
  (`TclAllocElemsEx`) cannot satisfy a realloc it calls `Tcl_Panic`.  The
  default Tcl panic handler calls `abort()`, which on Windows raises `SIGABRT`;
  if that signal is swallowed or the handler installed by a prior
  `SetUnhandledExceptionFilter` call doesn't terminate the process, Tcl's
  caller falls through into the `0xCC` (INT3) function-padding bytes that
  follow the panic call site — producing a confusing `EXCEPTION_BREAKPOINT`
  crash at an address inside `tcl90.dll` rather than at the true fault.
  Crash-dump analysis of a live incident confirmed this exact sequence: the
  exception address `tcl90.dll+0xF7C09` is a padding byte immediately after
  the `add esp, 0x24` that cleans up the panic-call stack frame.  Fixed by
  installing `IoFTPD_TclPanicProc` via `Tcl_SetPanicProc` during
  `Tcl_ModuleInit`.  The handler writes a diagnostic message using only stack
  and kernel resources (no heap allocation, since the heap may be corrupt at
  panic time), then calls `ExitProcess(1)` — which cannot return.  The
  message is written to `ioFTPD_panic.log` in the working directory and to the
  debug output stream; the unhandled-exception filter installed in `WinMain`
  will already have written a minidump before this point.

- **`User_StandardWrite` — ownership transfer of `lpInternal` leaves stale
  pointer in local `UserFile`** — the guard added in v7.10.1 to handle a NULL
  `lpInternal` in `User_StandardWrite` correctly transferred the newly-opened
  `USERFILE_CONTEXT` pointer from the local `UserFile` stack variable to
  `lpUserFile->lpInternal`, but did not null out `UserFile.lpInternal`
  afterward.  While harmless today (the local struct goes out of scope with no
  destructor), leaving the stale pointer in place is a latent double-free risk
  if cleanup code is ever added to that path.  Explicitly set
  `UserFile.lpInternal = NULL` immediately after the transfer.

- **`Group_Register` missing `lpInternal = NULL` — use-after-free risk**
  (`GroupNew.c`) — the group module's `Group_Register` function copies the
  caller's `GROUPFILE` struct into the shared copy via `CopyMemory` but did
  not null out `lpInternal` in the shared copy, unlike `User_Register` which
  already does this deliberately.  Both the caller and the shared copy would
  therefore hold the same `GROUPFILE_CONTEXT *` (open file handle).  If the
  caller's copy were closed first (`Group_StandardClose` → `Free(lpContext)`),
  the shared copy would retain a dangling pointer that `Group_StandardWrite`
  would later dereference.  Added `((LPGROUPFILE)lpMemory)->lpInternal = NULL`
  immediately after the `CopyMemory` call.

- **`Group_StandardWrite` missing NULL check — crash when group has no file
  context** (`GroupFileModule.c`) — exact parallel of the `User_StandardWrite`
  bug fixed in v7.10.1.  A Tcl bot calling `groupfile open` / `groupfile
  unlock` before any FTP session had opened the group file would reach
  `Group_StandardWrite` with `lpInternal == NULL`, causing an immediate NULL
  dereference on `lpContext->hFileHandle`.  Added a recovery block that opens
  the group file by GID, stores the resulting `GROUPFILE_CONTEXT` back into
  the shared copy, and proceeds with the write — matching the pattern in
  `User_StandardWrite`.

- **`Group_Default_Write` wrong type and missing NULL guard** (`GroupFileModule.c`)
  — `lpContext` was declared as `LPUSERFILE_CONTEXT` instead of
  `LPGROUPFILE_CONTEXT` (copy-paste error from the user-file equivalent;
  harmless at runtime because both structs contain only a single `HANDLE`
  field, but incorrect).  Also added a NULL guard before the file I/O: if
  `Group_Default_Write` is called without a prior successful
  `Group_Default_Open`, the function now returns `TRUE` (error) instead of
  crashing on the NULL context pointer.

- **`User_Default_Write` missing defensive NULL guard before file I/O**
  (`UserFileModule.c`) — for the Default=Group case (`Uid < -2`) the function
  already opens the file if `lpContext` is NULL.  For the normal Default user
  case (`Uid >= -2`) no such guard existed: if called without a prior
  successful `User_Default_Open`, the function would crash at the
  `SetFilePointer` call.  Added a defensive check that frees the write buffer
  and returns `TRUE` if `lpContext` is still NULL at that point.

- **`SITE IOVERSION` reports garbled Unicode entities instead of version string**
  (`RemoteAdmin.c`) — `FormatString` was called with `%hs` to print
  `tszIoVersionFull`.  Unlike standard `printf`, ioFTPD's custom `FormatString`
  engine treats the `h` size modifier as a URL-encode flag (`iVariableSize = -1`)
  rather than "narrow string", causing each byte-pair of the ASCII version string
  to be output as a `&#NNNNN;` HTML entity.  Fixed by changing `%hs` to `%s`,
  which correctly routes through the narrow-string printing path.

### Changed

- **`LARGEADDRESSAWARE` enabled — 32-bit process now uses up to 4 GB on 64-bit OS**
  (`ioFTPD-v7.vcxproj`) — ioFTPD was previously limited to a 2 GB virtual address
  space on 64-bit Windows.  Under load with many concurrent Tcl scripts and
  directory cache entries the working set approached this ceiling, leaving no
  headroom for diagnostic tools (e.g. AppVerifier PageHeap) or memory spikes.
  Enabled `IMAGE_FILE_LARGE_ADDRESS_AWARE` via `/LARGEADDRESSAWARE` linker flag
  across all three build configurations (Debug, Release, Purify).  On 64-bit
  Windows Server the process can now address up to ~3.8 GB.

### Build

- **`afxres.h` not found** — all four resource scripts (`ioFTPD.rc`,
  `ioFTPD-Start.rc`, `ioFTPD-Watch.rc`, `IoKnock.rc`) included `afxres.h`, an
  MFC-only header not present when the MFC component is absent from the VS
  install.  Replaced with `winresrc.h`, the standard Windows SDK equivalent for
  resource scripts.

- **`IDC_STATIC` undefined after `afxres.h` removal** — `IDC_STATIC (-1)` was
  only defined by `afxres.h` and is absent from the Windows SDK headers.  Added
  the definition to `IoKnock/resource.h` (included by all IoKnock resource
  files).

- **MFC libraries not found (`MSB8041`)** — MFC was installed only for the
  14.44.35207 toolset, but all projects specified `v143` without a version pin,
  causing MSBuild to select 14.42.34433 (where MFC is absent).  Fixed by adding
  `<VCToolsVersion>14.44.35207</VCToolsVersion>` to the Globals section of all
  six project files (`ioFTPD-v7.vcxproj`, `IoKnock.vcxproj`,
  `ioFTPD-Start.vcxproj`, `ioFTPD-Watch.vcxproj`, `ServiceInstaller.vcxproj`,
  `VersionAppend.vcxproj`).

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
