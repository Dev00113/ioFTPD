---
title: Development Environment Setup
---

# ioFTPD Development Environment Setup

This document describes how to reproduce the exact development environment used
to build ioFTPD v7.9+, including all required tools, libraries, and build steps.

---

## Table of Contents

1. [Directory Structure](#directory-structure)
2. [Prerequisites](#prerequisites)
3. [Build OpenSSL 3.6.1](#build-openssl-361)
4. [Build Tcl 9.0.2](#build-tcl-902)
5. [Build TclTLS (trunk)](#build-tcltls-trunk)
6. [Build ioFTPD](#build-ioftpd)
7. [Post-Build Deployment](#post-build-deployment)
8. [Crash Analysis Tools (Optional)](#crash-analysis-tools-optional)

---

## Directory Structure

The build system expects the following layout. Create these directories before
starting:

```
C:\Dev\
  Tools\
    nasm-2.15.05\      — NASM assembler (required for OpenSSL AES-NI)
    fossil\            — Fossil SCM binary (required for TclTLS checkout)
    Python314\         — Python 3.14 (optional; not required for ioFTPD build)
  Sources\
    openssl-3.6.1\     — OpenSSL source (extracted from tarball)
    tcl9.0.2\          — Tcl 9.0.2 source (extracted from tarball)
    tcltls-trunk\      — TclTLS (Fossil checkout; created during setup)
    ioFTPD\            — ioFTPD source (git clone)
  Libs\
    VS2022\x86\
      OpenSSL\Shared\Release\   — OpenSSL headers + libs (populated by nmake install)
      TCL\Shared\Release\       — Tcl headers + libs (populated by nmake install)
```

---

## Prerequisites

Install all tools before proceeding to the library builds.

### 1. Visual Studio 2022 Community

Required for the MSVC compiler (v143 toolset) and Windows SDK.

Download: https://visualstudio.microsoft.com/vs/community/

During installation, select:
- **Desktop development with C++** workload
- **Windows 11 SDK** (10.0.22621 or later; 10.0.19041 is the minimum)
- **MSVC v143 — VS 2022 C++ x86/x64 build tools**

> All ioFTPD builds are **Win32 (x86)** only. The x64 toolset is not required
> but does not cause harm if installed.

### 2. NASM 2.15.05

Required by OpenSSL's Configure script for AES-NI assembly optimizations.
Without NASM the build will fail during the `asm` generation step.

Download: https://www.nasm.us/pub/nasm/releasebuilds/2.15.05/win32/nasm-2.15.05-installer-x86.exe

Install to: `C:\Dev\Tools\nasm-2.15.05\`

> Do **not** add NASM to the system PATH — the build scripts add it temporarily.

### 3. Strawberry Perl

Required by OpenSSL's `Configure` script and by the TclTLS header-generation
step in `Build TclTLS.bat`.

Download: https://strawberryperl.com/

Install using the default installer. Strawberry Perl adds itself to the system
PATH automatically. Verify after install:

```
perl --version
```

### 4. Fossil 2.27

Required to check out the TclTLS trunk repository.

Download: https://www.fossil-scm.org/home/uv/download.html
(get the Win32 binary, `fossil.exe`)

Place `fossil.exe` at: `C:\Dev\Tools\fossil\fossil.exe`

### 5. Git

Required to clone the ioFTPD source repository.

Download: https://git-scm.com/download/win

Use the default installer options. Git adds itself to the system PATH.

---

## Build OpenSSL 3.6.1

OpenSSL provides the TLS/SSL layer (`libssl-3.dll`, `libcrypto-3.dll`) and
headers used by both ioFTPD and TclTLS.

### 3a. Download and extract source

Download the 3.6.1 tarball from:
https://github.com/openssl/openssl/releases/tag/openssl-3.6.1

Extract to: `C:\Dev\Sources\openssl-3.6.1\`

### 3b. Run the build script

A ready-made build script is at `C:\Dev\Sources\Build OpenSSL 3.6.1.bat`.
Double-click it from Explorer or run it from a plain `cmd.exe` prompt (not a
VS Developer Command Prompt — the script loads vcvars32.bat itself):

```bat
cd C:\Dev\Sources
"Build OpenSSL 3.6.1.bat"
```

The script:
1. Loads the VS 2022 x86 build environment (`vcvars32.bat`)
2. Adds NASM to PATH
3. Runs `perl Configure VC-WIN32 shared --prefix=C:\Dev\Libs\VS2022\x86\OpenSSL\Shared\Release`
4. Runs `nmake` (build)
5. Runs `nmake install` (copies headers, libs, and DLLs to the prefix)

### 3c. Copy the legacy provider

After the build completes, copy the legacy provider module to the ioFTPD
`system\` directory (needed for DHE-RSA / AES-CBC FXP compatibility):

```
C:\Dev\Libs\VS2022\x86\OpenSSL\Shared\Release\lib\ossl-modules\legacy.dll
  → C:\ioFTPD\system\lib\ossl-modules\legacy.dll
```

### Resulting layout

```
C:\Dev\Libs\VS2022\x86\OpenSSL\Shared\Release\
  bin\
    libssl-3.dll
    libcrypto-3.dll
    openssl.exe
  include\openssl\   (headers)
  lib\
    libssl.lib
    libcrypto.lib
    ossl-modules\
      legacy.dll
      legacy.pdb
```

---

## Build Tcl 9.0.2

Tcl provides the scripting engine (`tcl90.dll`) that ioFTPD embeds for
server-side event hooks.

> **No source patches are required** for Tcl 9.0.2. The official unmodified
> tarball builds cleanly with ioFTPD.

### 4a. Download and extract source

Download from: https://www.tcl.tk/software/tcltk/download.html
(choose `tcl9.0.2-src.tar.gz` or the equivalent `.zip`)

Extract to: `C:\Dev\Sources\tcl9.0.2\`

### 4b. Build (Release)

Open a **VS 2022 x86 Native Tools Command Prompt** (found in the Start menu
under Visual Studio 2022), then:

```bat
cd C:\Dev\Sources\tcl9.0.2\win

nmake -f makefile.vc OPTS=threads INSTALLDIR=C:\Dev\Libs\VS2022\x86\TCL\Shared\Release release
nmake -f makefile.vc OPTS=threads INSTALLDIR=C:\Dev\Libs\VS2022\x86\TCL\Shared\Release install
```

### 4c. Build (Debug — optional)

```bat
nmake -f makefile.vc OPTS=threads,symbols INSTALLDIR=C:\Dev\Libs\VS2022\x86\TCL\Shared\Debug release
nmake -f makefile.vc OPTS=threads,symbols INSTALLDIR=C:\Dev\Libs\VS2022\x86\TCL\Shared\Debug install
```

### Resulting layout

```
C:\Dev\Libs\VS2022\x86\TCL\Shared\Release\
  bin\
    tcl90.dll
    tclsh90.exe
  include\   (headers: tcl.h, tclDecls.h, etc.)
  lib\
    tcl90.lib
    tcl9.0\  (standard library scripts)
```

---

## Build TclTLS (trunk)

TclTLS is the OpenSSL TLS extension for Tcl. ioFTPD loads it as a Tcl package
to support `STARTTLS` and other TLS operations from Tcl scripts.

### 5a. Check out the repository

From a plain `cmd.exe` prompt:

```bat
cd C:\Dev\Sources
fossil clone https://core.tcl-lang.org/tcltls tcltls.fossil
mkdir tcltls-trunk
cd tcltls-trunk
fossil open ..\tcltls.fossil
```

This checks out the latest trunk into `C:\Dev\Sources\tcltls-trunk\`.

### 5b. Fix the makefile (required)

Open `C:\Dev\Sources\tcltls-trunk\win\makefile.vc` in any text editor.

Find this line:
```
TCLSH = "$(_INSTALLDIR)\..\bin\tclsh.exe"
```

Replace it with the explicit path to the installed Tcl 9.0 shell:
```
TCLSH = "C:\Dev\Libs\VS2022\x86\TCL\Shared\Release\bin\tclsh90.exe"
```

> Without this fix the makefile attempts to call a non-existent `tclsh.exe`
> and the header-generation step will fail.

### 5c. Run the build script

A ready-made build script is at `C:\Dev\Sources\Build TclTLS.bat`.
Run it from a plain `cmd.exe` prompt (the script loads vcvars32.bat itself):

```bat
cd C:\Dev\Sources
"Build TclTLS.bat"
```

The script:
1. Loads VS 2022 x86 build environment
2. Generates `generic\dh_params.h` using `openssl dhparam 2048`
3. Generates `generic\tls.tcl.h` from `library\tls.tcl` using Perl
4. Runs `nmake -f makefile.vc TCLDIR=... SSL_INSTALL_FOLDER=...`
5. Runs `nmake install` into `C:\Dev\Libs\VS2022\x86\TCL\Shared\Release\lib\`

### 5d. Manual build (alternative)

If you prefer to run the steps manually from a VS 2022 x86 Native Tools
Command Prompt:

```bat
REM Generate headers
cd C:\Dev\Sources\tcltls-trunk\generic
openssl dhparam 2048 | findstr /V /C:"--" > dh_params.h
perl -ne "chomp; @c=unpack('C*', $_); print join(', ', map { sprintf('0x%02x', $_) } @c), qq{, 0x0a, \n};" ^
    < ..\library\tls.tcl > tls.tcl.h

REM Build
cd ..\win
nmake -f makefile.vc ^
    TCLDIR=C:\Dev\Libs\VS2022\x86\TCL\Shared\Release ^
    SSL_INSTALL_FOLDER=C:\Dev\Libs\VS2022\x86\OpenSSL\Shared\Release ^
    TCLSH_PROG=C:\Dev\Libs\VS2022\x86\TCL\Shared\Release\bin\tclsh90.exe ^
    MACHINE=IX86

REM Install
nmake -f makefile.vc install ^
    TCLDIR=C:\Dev\Libs\VS2022\x86\TCL\Shared\Release ^
    INSTALLDIR=C:\Dev\Libs\VS2022\x86\TCL\Shared\Release\lib ^
    SSL_INSTALL_FOLDER=C:\Dev\Libs\VS2022\x86\OpenSSL\Shared\Release
```

---

## Build ioFTPD

### 6a. Clone the repository

```bat
cd C:\Dev\Sources
git clone <repository-url> ioFTPD
```

### 6b. Open the solution

Open `C:\Dev\Sources\ioFTPD\ioFTPD-v7.sln` in Visual Studio 2022.

The project already has the correct include and library paths configured:
- Includes: `C:\Dev\Libs\VS2022\x86\OpenSSL\Shared\Release\include`
            `C:\Dev\Libs\VS2022\x86\TCL\Shared\Release\include`
            `C:\Program Files\Debugging Tools for Windows\sdk\inc`  *(WinDbg SDK — optional)*
- Libraries: `C:\Dev\Libs\VS2022\x86\OpenSSL\Shared\Release\lib`
             `C:\Dev\Libs\VS2022\x86\TCL\Shared\Release\lib`

If your paths differ, update `AdditionalIncludeDirectories` and
`AdditionalLibraryDirectories` in the project properties.

### 6c. Build configurations

| Configuration | Output binary | Notes |
|---|---|---|
| `Release\|Win32` | `system\ioFTPD.exe` | Optimised production build |
| `Debug\|Win32` | `system\ioFTPD-debug.exe` | No optimisation, debug CRT |
| `Purify\|Win32` | `system\ioFTPD.exe` | Debug + `/RTC1` for runtime checks |

**From the command line (recommended for CI):**

```bat
"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" ^
    "C:\Dev\Sources\ioFTPD\ioFTPD-v7.sln" ^
    /p:Configuration=Release /p:Platform=Win32 ^
    /t:Build /m /nologo
```

---

## Post-Build Deployment

After building, copy the required runtime files to the ioFTPD `system\` directory.

### DLLs

```bat
REM OpenSSL
copy C:\Dev\Libs\VS2022\x86\OpenSSL\Shared\Release\bin\libssl-3.dll   C:\ioFTPD\system\
copy C:\Dev\Libs\VS2022\x86\OpenSSL\Shared\Release\bin\libcrypto-3.dll C:\ioFTPD\system\

REM Tcl runtime
copy C:\Dev\Libs\VS2022\x86\TCL\Shared\Release\bin\tcl90.dll           C:\ioFTPD\system\

REM OpenSSL legacy provider (for DHE-RSA / AES-CBC FXP compatibility)
mkdir C:\ioFTPD\system\lib\ossl-modules
copy C:\Dev\Libs\VS2022\x86\OpenSSL\Shared\Release\lib\ossl-modules\legacy.dll ^
     C:\ioFTPD\system\lib\ossl-modules\
```

### Tcl standard library

```bat
xcopy /s /i /y ^
    C:\Dev\Libs\VS2022\x86\TCL\Shared\Release\lib\tcl9.0 ^
    C:\ioFTPD\system\lib\tcl9.0
```

> The `encoding\` subdirectory is large. If startup time matters, only
> `utf-8`, `iso8859-1`, `cp1252`, and `ascii` encodings are required.

### Runtime directory contents

At startup `system\` must contain:

```
system\
  ioFTPD.exe
  libssl-3.dll
  libcrypto-3.dll
  tcl90.dll
  lib\
    ossl-modules\
      legacy.dll
    tcl9.0\         (Tcl standard library)
  ioFTPD.ini
```

---

## Crash Analysis Tools (Optional)

### WinDbg — Debugging Tools for Windows

Required to open `.dmp` minidump files generated by ioFTPD's built-in crash
handler (`crash_YYYYMMDD_HHMMSS.dmp`).

Download as part of the Windows SDK:
https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/

Install path used in this environment: `C:\Program Files\Debugging Tools for Windows\`

**Basic crash analysis workflow:**

```
windbg -z crash_20260101_143022.dmp
.symfix
.reload
!analyze -v
!heap -p -a <faulting-address>
```

The WinDbg SDK include directory (`sdk\inc`) is referenced in the ioFTPD project
for `dbgeng.h` / `dbghelp.h`. If WinDbg is not installed, remove that include
path from the project properties and the build will still succeed (it is only
used by `IoDebug.c` for symbol resolution).

---

## Quick-Reference Build Order

```
1. Install VS 2022 Community (Desktop C++ workload)
2. Install Strawberry Perl          → verify: perl --version
3. Install NASM 2.15.05 to C:\Dev\Tools\nasm-2.15.05\
4. Install Fossil to C:\Dev\Tools\fossil\fossil.exe
5. Install Git
6. Download & extract OpenSSL 3.6.1 → C:\Dev\Sources\openssl-3.6.1\
7. Download & extract Tcl 9.0.2     → C:\Dev\Sources\tcl9.0.2\
8. Run: "Build OpenSSL 3.6.1.bat"
9. Run (VS x86 prompt): nmake for Tcl 9.0.2  (release + install)
10. Fossil clone TclTLS trunk        → C:\Dev\Sources\tcltls-trunk\
11. Edit tcltls-trunk\win\makefile.vc (fix TCLSH path)
12. Run: "Build TclTLS.bat"
13. git clone ioFTPD
14. MSBuild ioFTPD-v7.sln /p:Configuration=Release /p:Platform=Win32
15. Copy DLLs and Tcl lib tree to system\
```
