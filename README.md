# ioFTPD

**ioFTPD** is a high-performance, Windows-only FTP server originally developed by iniCom Networks, Inc. It is licensed under the GNU General Public License v2+. The project is effectively abandoned upstream; this repository represents a fork/continuation effort.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture Summary](#architecture-summary)
3. [Module Index](#module-index)
4. [Build Instructions](#build-instructions)
5. [Dependencies](#dependencies)
6. [Companion Tools](#companion-tools)
7. [Configuration](#configuration)
8. [Long-Path Support](#long-path-support)
9. [Known Issues](#known-issues)
10. [Modernization Roadmap](#modernization-roadmap)

---

## Project Overview

ioFTPD is a Win32 FTP daemon with:

- **RFC 959** FTP protocol support plus modern extensions (FTPS/AUTH TLS, MLSD, XCRC, CPSV, SSCN, REST STREAM)
- **I/O Completion Port (IOCP)** based async I/O for high connection concurrency (up to 16,384 clients, `MAX_CLIENTS`)
- **Tcl scripting** engine for server-side event hooks (login, logout, upload, download, etc.)
- **Virtual File System (VFS)** with configurable mount points
- **Per-user and per-group quotas**, ratio tracking, and transfer statistics across 25 sections (`MAX_SECTIONS`)
- **Bandwidth throttling** per network device and per user
- **Windows service** integration
- **TLS/FTPS** via an embedded OpenSSL integration
- **Flat-file user/group database**

The server runs as a standard Win32 GUI application (hidden window) or as a Windows service.

---

## Architecture Summary

### Execution Model

```
WinMain / ServiceMain
    └── DoSetup()               # Path, config, exception handler, uptime init
    └── InitializeDaemon()      # Sequential module init (Init_Table)
    └── CommonMain()
            ├── QueueJob(ServerStart)    # Fires OnServerStart Tcl events
            ├── ProcessMessages()        # Win32 message loop (blocks until shutdown)
            └── DaemonDeInitialize()     # Sequential module teardown
```

### Initialization Table (in order)

| Module          | Source           | Purpose                                      |
|-----------------|------------------|----------------------------------------------|
| Memory          | Memory.c         | Custom bucket allocator, shared-ref allocator |
| Time            | IoTime.c         | Time utilities                               |
| IoProc          | IoProcs.c        | I/O procedure dispatch                       |
| Timer           | Timer.c          | Async timer system                           |
| Config          | ConfigReader.c   | INI file parser                              |
| File            | File.c           | File I/O helpers                             |
| LogSystem       | LogSystem.c      | Logging subsystem                            |
| Thread          | Threads.c        | IOCP thread pool + job queue                 |
| Windows         | InternalMessageHandler.c | Hidden Win32 window + message loop  |
| Debug           | IoDebug.c        | Exception handler, symbol server             |
| Client          | IoProcs.c/Client.c | Client slot management                    |
| DataCopy        | DataCopy.c       | File-to-socket transmit (TransmitFile)       |
| Security        | OpenSSL.c        | TLS context management                       |
| Socket          | Socket.c         | Winsock, IOCP, bandwidth scheduler           |
| Message         | Message.c        | FTP response message formatting              |
| Help            | Help.c           | HELP file loading                            |
| MountFile       | File.c           | VFS mount-point loading                      |
| DirectoryCache  | DirectoryCache.c | Directory entry caching                      |
| Group           | GroupNew.c       | Group database                               |
| User            | UserNew.c        | User database                                |
| Identify        | Identify.c       | Ident/host resolution                        |
| Event           | Execute.c        | Tcl event runner                             |
| TransmitPackage | DataCopy.c       | Protocol-level send/recv packages            |
| FTP             | FtpServer.c      | FTP settings, new-client setup               |
| Services        | services.c       | Service/device binding and accept loop       |
| Scheduler       | Scheduler.c      | Periodic task scheduler                      |

### Threading Model

```
Main thread        ─ Win32 message loop (ProcessMessages)
IOCP threads       ─ Multiple (IoThreadEx) dequeuing from hCompletionPort
Worker threads     ─ Multiple (WorkerThread) running job queue items
Socket scheduler   ─ Single dedicated thread (SocketSchedulerThread) for bandwidth control
```

All async network I/O goes through Windows IOCP (`hCompletionPort`). Completion callbacks post jobs into the job queue (`QueueJob`), which worker threads pick up. Three priority levels exist: `JOB_PRIORITY_HIGH`, `JOB_PRIORITY_NORMAL`, `JOB_PRIORITY_LOW`.

### FTP Connection Lifecycle

```
AcceptEx (overlapped)
  └── Service_AcceptClient()
        └── FTP_New_Client()           # Allocate FTP_USER, bind IOCP, send 220 banner
              └── FTP_AcceptInput()    # Queue receive job with idle timeout
                    └── FTP_ReceiveLine()  # On data received
                          └── FTP_Command()     # Dispatch to command handler
                                └── FTP_Close_Connection()  # On QUIT or error
```

The command dispatch table (`FtpCommand[]` in `FtpBaseCommands.c`) maps command strings to handler functions. Commands are categorized as `LOGIN_CMD`, `OTHER_CMD`, or `XFER_CMD`.

### Async Socket Events

Historically the code used `WSAAsyncSelect` (Windows message-based). The current codebase replaces this with `WSAEventSelect` + `RegisterWaitForSingleObject` threadpool callbacks, which post `WM_ASYNC_CALLBACK` messages to the hidden window (`InternalMessageHandler.c`) to preserve the original dispatch path.

### Memory Management

The memory subsystem (`Memory.c`) provides:

- **`FragmentAllocate/FragmentFree`** – A 128-bucket (`MEMORY_BUCKETS`) free-list allocator over a private heap (`HeapCreate`). Bucket sizes start at 8 bytes, increment by 8, 16, 24, … (quadratic growth). Allocations store their bucket index in the header word immediately before the returned pointer.
- **`AllocateShared/_AllocateShared`** – Reference-counted shared allocations. A canary value (`0xDEADBEAF`) is stored in the header. `FreeShared` uses `InterlockedDecrement` on the refcount.
- When compiled with `USE_MALLOC`, all custom allocation is bypassed in favour of the CRT heap (used in Purify config for memory analysis).

### Locking Patterns

| Pattern | Mechanism | Location |
|---------|-----------|----------|
| Shared/Exclusive r-w lock | `LOCKOBJECT` (Event + Semaphore) | `Locking.c` |
| Spin lock | `InterlockedExchange` busy-wait | Throughout (Socket, Memory, FTP) |
| Per-socket lock | `CRITICAL_SECTION csLock` | `IOSOCKET` struct |
| Job queue lock | `CRITICAL_SECTION csJobQueue` | `Threads.c` |
| Debug memory lock | `CRITICAL_SECTION csMemoryDebug` | `Memory.c` |

---

## Module Index

### Source Files (`src/`)

| File | Purpose |
|------|---------|
| Array.c | Generic dynamic array |
| Buffer.c | String/response buffer with format support |
| Change.c | `SITE CHANGE` admin command |
| Command.c | FTP command logic (login, upload, download, delete, mkdir, rename) |
| Compare.c | Path/string comparison helpers |
| ConfigReader.c | INI-file parser (`Config_Get`, `Config_Get_Int`, `Config_Get_Bool`) |
| Crc32.c | CRC32 computation and combination |
| DataCopy.c | Async file transfer using `TransmitFile` |
| DataOffset.c | Transfer resume/restart offset handling |
| DirectoryCache.c | In-memory directory cache |
| Execute.c | Tcl event execution (`RunEvent`) |
| File.c | File I/O, VFS mount-point management |
| FtpBaseCommands.c | Core FTP commands (AUTH, USER, PASS, PASV, PORT, STOR, RETR, …) |
| FtpDataChannel.c | Data channel establishment and transfer management |
| FtpServer.c | FTP_Init, FTP_New_Client, upload/download completion, FTP settings |
| FtpSiteCommands.c | `SITE` subcommands (WHO, KICK, KILL, BAN, …) |
| GroupFileModule.c | Group database file I/O |
| GroupNew.c | Group lookup, creation, deletion |
| Help.c | HELP file display |
| IdDatabase.c | UID/GID allocation and name-to-id database |
| Identify.c | Ident protocol and hostname resolution |
| InternalMessageHandler.c | Hidden Win32 window, message dispatch, crash guard, restart heartbeat |
| IoDebug.c | Exception handler, stack trace, symbol server, version info |
| IoProcs.c | IOCP callback dispatch, client job queues |
| IoString.c | String utilities (`aswprintf`, `FormatString`, etc.) |
| IoTime.c | Tick count helpers, time difference utilities |
| Locking.c | `LOCKOBJECT` shared/exclusive lock implementation |
| LogSystem.c | Log queue, file rotation, log formatting |
| LongPath.c | Long-path support: OS detection, `\\?\` wrappers for all file APIs, `IoCanonicalizePath` |
| Main.c | Entry point, init table, daemon lifecycle, service support |
| Memory.c | Custom allocator, shared-ref allocator, debug memory tracking |
| Message.c | Message file display (`MessageFile_Show`) |
| MessageHandler.c | Message variable substitution engine |
| MessageObjects.c | Message object type dispatch |
| MessageVariables.c | Variable resolvers (`%[USER]`, `%[SPEED]`, etc.) |
| NewList.c | `LIST`, `NLIST`, `MLSD`, `STAT` directory listing |
| OpenSSL.c | TLS context creation/management, certificate generation |
| Permission.c | ACL and permission checking |
| PWD.c | Virtual path resolution |
| RemoteAdmin.c | Remote administration channel |
| RowParser.c | Tabular data parser for configuration |
| Scheduler.c | Periodic task scheduler |
| services.c | Service/device configuration, AcceptEx setup |
| sha1.c | SHA-1 hash implementation |
| Socket.c | Winsock2/IOCP socket layer, bandwidth scheduling, `WSAEventSelect` integration |
| SocketAPI.c | High-level socket API helpers |
| Stats.c | Server statistics collection |
| Tcl.c | Tcl interpreter lifecycle, command registration |
| Threads.c | Thread pool, job queue, CRC32 table |
| TickCountHelper.c | 64-bit tick count without 49.7-day rollover |
| Timer.c | Async timer creation/cancellation |
| UserFileModule.c | User database file I/O |
| UserNew.c | User lookup, creation, deletion |
| Who.c | `SITE WHO` / online data display |
| WinErrors.c | `FormatError` helper |

### Header Files (`include/`)

Key structural types:

| Header | Key Types |
|--------|-----------|
| Client.h | `CLIENT`, `CLIENTSLOT` |
| ConnectionInfo.h | `CONNECTION_INFO` |
| ControlConnection.h | `COMMAND`, FTP_USER control channel |
| DataConnection.h | `DATACHANNEL` |
| Ftp.h | `FTP_USER`, `FTP_SETTINGS`, `FTPCOMMAND` |
| GroupFile.h | `GROUPFILE` |
| IdDataBase.h | ID database types |
| IoService.h | `IOSERVICE`, `IODEVICE`, `BANDWIDTH` |
| IoSocket.h (iosocket.h) | `IOSOCKET`, `SETSOCKETOVERLAPPED` |
| IoOverlapped.h | `IOOVERLAPPED`, `SETSOCKETOVERLAPPED` |
| LockObject.h | `LOCKOBJECT` |
| LongPath.h | Long-path API declarations (`IoIsNtfsPathTooLongError`, `IoCreateFile`, `IoMoveFileEx`, etc.) |
| ServerLimits.h | All compile-time constants |
| Threads.h | `JOB`, `THREADDATA`, `THEME_FIELD` |
| UserFile.h | `USERFILE`, `USERFILE_OLD` |
| VirtualPath.h | `VIRTUALPATH` |

---

## Build Instructions

### Prerequisites

| Component | Required Version | Notes |
|-----------|-----------------|-------|
| Visual Studio | 2022 (v143 toolset) | MSVC C compiler |
| Windows SDK | 10.0.19041.0 or later | Minimum target: Vista (0x0600) |
| OpenSSL | 3.6.1 (Release) | See `DEV-SETUP.md` for build steps |
| Tcl | 9.0.2 | See `DEV-SETUP.md` for build steps; no source patches required |

> **Warning:** The Release and Debug build configurations reference library paths that may not exist on your machine. Update `AdditionalIncludeDirectories` and `AdditionalLibraryDirectories` in `ioFTPD-v7.vcxproj` before building.

### Build Configurations

| Configuration | Output | Notes |
|---------------|--------|-------|
| Release\|Win32 | `system\ioFTPD.exe` | Optimized, links `libssl.lib` + `libcrypto.lib`, `tcl90.lib` |
| Debug\|Win32 | `system\ioFTPD-debug.exe` | No optimization, `tcl90.lib`, OpenSSL |
| Purify\|Win32 | `system\ioFTPD.exe` | Debug + `EnableFastChecks`, `tcl90.lib`, `libssl.lib`/`libcrypto.lib`, memory analysis |

All configurations link against `tcl90.lib` and OpenSSL 3.x (`libssl.lib` / `libcrypto.lib`). Library paths are under `C:\Dev\Libs\VS2022\x86\`.

### Build Steps

1. Open `ioFTPD-v7.sln` in Visual Studio 2022.
2. Update include/library paths in the project properties to match your local library locations.
3. Ensure OpenSSL DLLs (`libssl-3.dll` / `libcrypto-3.dll`) and the Tcl DLL (`tcl90.dll`) are in the `system\` output directory.
4. Select the desired configuration and build.

### Required Libraries in `system\`

At runtime, `system\` must contain:
- `ioFTPD.exe` (or the appropriate build variant)
- OpenSSL DLLs
- Tcl DLL
- `ioFTPD.ini` (configuration file)
- VFS mount-point files

---

## Dependencies

| Library | Version | Status | CVEs / Notes |
|---------|---------|--------|--------------|
| **OpenSSL** | 3.6.1 | Active (LTS) | All known CVEs addressed; TLS 1.3 + ECDHE supported |
| **Tcl** | 9.0.2 | Active | No source patches required; official unmodified build |
| **Winsock2** | Windows SDK | Active | Used for all networking |
| **PDH** (Performance Data Helper) | Windows SDK | Active | Used for system uptime detection |
| **shlwapi** | Windows SDK | Active | Path utilities |
| **version.lib** | Windows SDK | Active | `GetFileVersionInfo` |
| **crypt32** | Windows SDK | Active | Certificate store |

### Tcl 9.0 — No Source Patches Required

ioFTPD v7.8+ uses Tcl 9.0, which can be built from the official unmodified source.
The handle-inheritance issues that required patching Tcl 8.5's `TclpCreateProcess`
and `TcpAccept` are resolved natively in Tcl 9.0:

- **`tclWinSock.c`**: `TcpAccept()` already calls `SetHandleInformation(HANDLE_FLAG_INHERIT, 0)` on newly accepted sockets.
- **`tclWinPipe.c`**: Pipe handles are created with `bInheritHandle = FALSE` in the `SECURITY_ATTRIBUTES` struct passed to `CreateProcess`.

ioFTPD still maintains its own `AcquireHandleLock()`/`ReleaseHandleLock()` critical section for its own `CreateProcess` calls (`Execute.c`) and socket-accept paths (`Socket.c`, `FtpDataChannel.c`), but these no longer need to reach into Tcl.

See `Tcl.txt` for build steps.

---

## Companion Tools

| Tool | Project | Purpose |
|------|---------|---------|
| `ioFTPD-Watch` | `ioFTPD-Watch/` | Watchdog process; monitors ioFTPD and restarts it on crash |
| `IoKnock` | `IoKnock/` | Port-knocking client GUI for firewall bypass |
| `ServiceInstaller` | `ServiceInstaller/` | Installs/uninstalls ioFTPD as a Windows service |
| `VersionAppend` | `VersionAppend/` | Build tool; appends version info to the executable |

---

## Configuration

The server reads `ioFTPD.ini` (or a path specified on the command line) at startup. Key INI sections:

| Section | Notable Keys |
|---------|-------------|
| `[FTP]` | `Idle_TimeOut`, `Login_TimeOut`, `Login_Attempts`, `Transfer_Buffer`, `Socket_Send_Buffer`, `Idle_Exempt`, `Banned_User_Flag`, `Quiet_Login_Flag`, `Long_Path_Support` |
| `[Events]` | `OnServerStart`, `OnServerStop`, `OnFtpLogOut`, `OnFtpUpload`, `OnFtpDownload` |
| `[Network]` | `Log_OpenSSL_Transfer_Errors`, `Scheduler_Update_Speed` |
| `[VFS_PreLoad]` | `DELAY` |
| `[Services]` | FTP service definitions (port, device binding, TLS settings) |

Configuration is live-reloadable for many settings via `SITE CONFIG RELOAD` or equivalent events.

---

## Long-Path Support

ioFTPD supports file system paths longer than the legacy `MAX_PATH` (260-character) Windows limit on
Windows 10 build 14393+ / Server 2016+, subject to the requirements below.

### Requirements

All three must be present:

1. **Windows 10 build 14393** (v1607) or Server 2016 or later.
2. **Registry opt-in** — `HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\LongPathsEnabled = 1`.
3. **Manifest** — `ioFTPD.exe` embeds `<longPathAware>true</longPathAware>` (built in at compile time via `ioFTPD.additional.manifest`).

Control via `ioFTPD.ini`:

```ini
[FTP]
Long_Path_Support = Auto   ; Auto (default), On, or Off
```

When `Auto`, ioFTPD probes the OS version and registry at startup and logs the result.

### Behavior by Backend

| FTP Command / Feature | Local NTFS | Mapped Drive (Z:\\) | UNC (\\\\server\\share) | Notes |
|-----------------------|-----------|---------------------|------------------------|-------|
| LIST / MLSD (directory listing) | ✔ | ✔ | ✔ (until SMB limit) | SMB often fails earlier than NTFS |
| CWD / PWD | ✔ | ✔ | ✔ | UNC normalisation may fail at extreme depth |
| STOR / APPE (upload) | ✔ | ✔ | ⚠ May fail early | SMB rejects long normalised paths |
| RETR (download) | ✔ | ✔ | ⚠ Same as STOR | |
| DELE (file delete) | ✔ | ✔ | ✔ (until SMB limit) | |
| RMD (directory delete) | ✔ | ✔ | ✔ (until SMB limit) | `.ioFTPD` handling fully long-path aware |
| RNFR / RNTO (rename/move) | ✔ | ✔ | ⚠ Destination path often fails first | `.ioFTPD` creation may trigger SMB limit |
| SIZE / MDTM / MLST | ✔ | ✔ | ✔ (until SMB limit) | |
| DirectoryCache recursion | ✔ | ✔ | ⚠ Deep UNC paths may fail | |
| Reparse points (junctions) | ✔ | ✔ | ❌ Not supported | SMB cannot expose reparse metadata |
| Maximum path length | ~32 767 UTF-16 chars | ~32 767 UTF-16 chars | ⚠ Typically 1–4 k (SMB server-dependent) | SMB is the limiting factor |
| Per-component limit | 255 chars | 255 chars | ⚠ 255 or less (some servers: 240 or 200) | |

### Key Points

- **Local NTFS** is the most robust backend for long paths.
- **Mapped drives** behave identically to local NTFS — Windows resolves the UNC path before ioFTPD sees it.
- **UNC / SMB paths** are the weakest: SMB servers impose their own normalisation limits, often failing long before NTFS would.  SMB normalisation commonly returns `ERROR_FILE_NOT_FOUND` (2) or `ERROR_PATH_NOT_FOUND` (3) for paths that exceed its limit — ioFTPD classifies these correctly and returns `550 Path too long for NTFS.` to the FTP client.
- **Error reporting** — when any file operation fails due to path length, the FTP client receives `550 <path>: Path too long for NTFS.` regardless of which underlying error code Windows produced.

---

## Known Issues

1. **OpenSSL upgraded to 3.6.1** (resolved — TLS 1.3, ECDHE, modern cipher suites; see OpenSSL.txt).
2. **Tcl upgraded to 9.0.2** (resolved — official unmodified build; no source patches required).
3. **32-bit only**. The build targets `MachineX86` exclusively, limiting address space to 4 GB and preventing use of modern mitigations.
4. **ASLR is explicitly disabled** (`RandomizedBaseAddress=false`) in all build configurations, making exploitation of memory-safety bugs trivial.
5. **DEP/NX is explicitly disabled** (`DataExecutionPrevention` tag left empty) in all configurations.
6. **Passwords hashed with SHA-1 (no salt)**. SHA-1 is broken for password storage; modern alternatives require bcrypt, scrypt, or Argon2.
7. **IPv4 only**. The codebase is hardcoded to `AF_INET`/`sockaddr_in`. IPv6 is not supported.
8. **Win32 message window dependency**. The async I/O dispatch relies on a hidden Win32 message window, a design pattern unsuitable for modern server applications.
9. **`GetVersionEx` is deprecated** since Windows 8.1. Behaviour may be incorrect on Windows 10/11/Server 2025.

---

## Modernization Roadmap

The following changes are recommended in rough priority order:

### Critical (Security)

1. ~~**Upgrade OpenSSL to 3.x**~~ **Done** – OpenSSL 3.6.1 with TLS 1.3 and ECDHE support (see `OpenSSL.txt`).
2. **Replace SHA-1 password hashing** – Migrate to `bcrypt`/`Argon2` with per-user salts. Provide a migration path for existing password files.
3. **Enable ASLR and DEP** – Set `RandomizedBaseAddress=true` and `DataExecutionPrevention=true` in all configurations.
4. ~~**Upgrade Tcl**~~ **Done** – Tcl 9.0.2, official unmodified build, no source patches required.
5. **Harden `DummyEncode`/`DummyDecode`** – Replace with a standard authenticated encryption scheme (AES-GCM).

### High Priority (Stability / Safety)

6. **Port to 64-bit** – Add an `x64` platform target. Eliminate all `(ULONG)` pointer casts in `Memory.c` (use `(UINTPTR_T)` / `SIZE_T`). This is a prerequisite for modern Windows hardening features.
7. **Enable Buffer Security Check (`/GS`)** – Currently disabled in Debug config; enable across all configurations.
8. **Replace spin-lock busy-waits** – Replace `while (InterlockedExchange(&lock, TRUE)) SwitchToThread()` with proper `CRITICAL_SECTION` or `SRWLock` usage.
9. **Fix `DummyEncode` unsigned underflow** – Guard the loop with an early-out if `dwIn < 4`.
10. **Replace `GetVersionEx`** – Use `VerifyVersionInfo` or `RtlGetVersion` (via `versionhelpers.h`).

### Medium Priority (Modernization)

11. **IPv6 support** – Generalize socket layer to `AF_UNSPEC`, `sockaddr_storage`, and `getaddrinfo`/`getnameinfo`.
12. **Replace Win32 message window** – Move async event dispatch to a dedicated I/O thread or use `PostQueuedCompletionStatus` exclusively.
13. **Replace INI-file user database** – Consider SQLite or a structured binary format with proper locking semantics.
14. **Remove commented-out dead code** – `Unused-code.txt`, commented `BindSocketToDevice`, `UnbindSocket`, deadlock detection.
15. **Replace `wsprintf` with safe alternatives** – Use `StringCbPrintf` or `snprintf_s`.

### Long Term (Architecture)

16. **Add automated tests** – No tests exist. Start with unit tests for `Memory.c`, `Compare.c`, `ConfigReader.c`, `RowParser.c`, and `Buffer.c`.
17. **Cross-platform consideration** – The IOCP and Win32 dependency is pervasive, but abstracting the platform layer would enable porting to Linux (io_uring) or BSD (kqueue).
18. **Replace custom memory allocator** – The bucket allocator is 32-bit only and unmaintainable. Modern MSVC CRT or `mimalloc` are safer alternatives.
