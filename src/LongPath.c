#include <ioFTPD.h>

// ---------------------------------------------------------------------------
// Global flags — set once during LongPath_Init, read throughout the codebase.
// ---------------------------------------------------------------------------
BOOL g_LongPathsEnabled = FALSE;
BOOL g_bIoDebugLog      = FALSE;

// Forward declaration — defined near the bottom of this file.
static int IoBuildUNCPfx(LPCTSTR lpPath, SIZE_T cch, WCHAR *szOut, int cchOut);


// ---------------------------------------------------------------------------
// DetectLongPaths — returns TRUE when the OS and registry both enable the
// Windows long-path opt-in mechanism.
//
// Requirements:
//   1. Windows build >= 14393  (Windows 10 v1607 / Server 2016)
//   2. HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\LongPathsEnabled = 1
//
// The ioFTPD.exe manifest already declares <longPathAware>true</longPathAware>
// so once the registry key is set, ALL Win32 file APIs (CreateFileA, FindFirstFileA,
// etc.) accept paths up to ~32767 chars without any \\?\ prefix.
// ---------------------------------------------------------------------------
static BOOL
DetectLongPaths(VOID)
{
    typedef LONG (WINAPI *fpRtlGetVersion)(RTL_OSVERSIONINFOW *);
    fpRtlGetVersion  pfnRtlGetVersion;
    RTL_OSVERSIONINFOW ovi;
    HMODULE  hNtdll;
    HKEY     hKey;
    DWORD    dwEnabled, dwType, dwSize;

    // Step 1: check OS build number via RtlGetVersion (never lies, unlike GetVersionEx).
    hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    pfnRtlGetVersion = (fpRtlGetVersion)GetProcAddress(hNtdll, "RtlGetVersion");
    if (!pfnRtlGetVersion) return FALSE;

    ZeroMemory(&ovi, sizeof(ovi));
    ovi.dwOSVersionInfoSize = sizeof(ovi);
    if (pfnRtlGetVersion(&ovi) != 0 /* STATUS_SUCCESS */) return FALSE;

    // Build 14393 = Windows 10 v1607 / Server 2016 — first build with long path support.
    if (ovi.dwBuildNumber < 14393) return FALSE;

    // Step 2: check the registry opt-in key.
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\FileSystem",
            0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return FALSE;

    dwType    = REG_DWORD;
    dwSize    = sizeof(DWORD);
    dwEnabled = 0;
    RegQueryValueExW(hKey, L"LongPathsEnabled", NULL, &dwType,
                     (LPBYTE)&dwEnabled, &dwSize);
    RegCloseKey(hKey);

    return (dwEnabled == 1);
}


// ---------------------------------------------------------------------------
// LongPath_Init — called from Init_Table after LogSystem.
//
// INI key: [FTP] Long_Path_Support = Auto | On | Off
//   Auto (default) — enable iff OS (build >= 14393) and registry key
//                    LongPathsEnabled = 1 are both present.
//   On             — report as enabled regardless of OS detection.
//                    (The manifest opt-in is always embedded; the only
//                     remaining requirement is the registry key.)
//   Off            — disable; ioFTPD treats MAX_PATH as the path limit.
//
// Logs exactly one message describing the outcome.
// ---------------------------------------------------------------------------
BOOL
LongPath_Init(BOOL bFirstInitialization)
{
    LPTSTR tszMode;

    if (!bFirstInitialization) return TRUE;

    tszMode = Config_Get(&IniConfigFile, _T("FTP"), _T("Long_Path_Support"), NULL, NULL);

    if (!tszMode || !_tcsicmp(tszMode, _T("Auto")))
    {
        g_LongPathsEnabled = DetectLongPaths();
        if (g_LongPathsEnabled)
            Putlog(LOG_GENERAL,
                _T("Long path support: Auto — OS build and registry opt-in detected, enabled.\r\n"));
        else
            Putlog(LOG_GENERAL,
                _T("Long path support: Auto — OS build < 14393 or LongPathsEnabled registry key not set, disabled.\r\n"));
    }
    else if (!_tcsicmp(tszMode, _T("On")))
    {
        g_LongPathsEnabled = TRUE;
        Putlog(LOG_GENERAL,
            _T("Long path support: On (forced via Long_Path_Support=On; ensure LongPathsEnabled registry key is set).\r\n"));
    }
    else
    {
        // "Off" or any unrecognised value — disable.
        g_LongPathsEnabled = FALSE;
        Putlog(LOG_GENERAL,
            _T("Long path support: Off (disabled via Long_Path_Support=%s).\r\n"),
            tszMode ? tszMode : _T("Off"));
    }

    if (tszMode) Free(tszMode);

    // [FTP] IO_Debug_Log — enable verbose LOG_DEBUG output from Io* wrappers
    // and directory-cache functions.  Default: FALSE (off).  Set to True only
    // for temporary diagnostics; the output is written to Debug.log on every
    // failed ANSI call and every \\?\ retry attempt.
    g_bIoDebugLog = FALSE;
    Config_Get_Bool(&IniConfigFile, _T("FTP"), _T("IO_Debug_Log"), &g_bIoDebugLog);
    if (g_bIoDebugLog)
        Putlog(LOG_GENERAL, _T("IO_Debug_Log: enabled — verbose Io* wrapper diagnostics will be written to Debug.log.\r\n"));

    return TRUE;
}


// ---------------------------------------------------------------------------
// LongPath_Prefix — no-op pass-through.
//
// The manifest longPathAware opt-in lifts the MAX_PATH restriction from all
// Win32 ANSI APIs transparently; no \\?\ prefix is needed or applied.
// This function is retained so call sites compile unchanged, and to preserve
// the option of switching to explicit prefix mode in the future.
// ---------------------------------------------------------------------------
LPTSTR
LongPath_Prefix(LPCTSTR tszPath)
{
    return (LPTSTR)tszPath;
}


// ---------------------------------------------------------------------------
// LongPath_Free — release a string returned by LongPath_Prefix.
//
// Since LongPath_Prefix never allocates, this is always a no-op.
// ---------------------------------------------------------------------------
VOID
LongPath_Free(LPCTSTR tszOriginal, LPTSTR tszPrefixed)
{
    // no-op: LongPath_Prefix returns the original pointer unconditionally.
    (VOID)tszOriginal;
    (VOID)tszPrefixed;
}


// ---------------------------------------------------------------------------
// LongPath_Strip — return a pointer past any \\?\ or \\?\UNC\ prefix.
//
// Since LongPath_Prefix no longer adds a prefix, this is effectively a
// no-op for paths produced internally.  Retained for paths that may arrive
// from external sources already prefixed.
// ---------------------------------------------------------------------------
LPCTSTR
LongPath_Strip(LPCTSTR tszPath)
{
    if (!tszPath)
        return tszPath;

    // \\?\ prefix (local paths)
    if (tszPath[0] == _T('\\') && tszPath[1] == _T('\\') &&
        tszPath[2] == _T('?')  && tszPath[3] == _T('\\'))
    {
        // \\?\UNC\ — restore leading \\ for the UNC path
        if (tszPath[4] == _T('U') && tszPath[5] == _T('N') &&
            tszPath[6] == _T('C') && tszPath[7] == _T('\\'))
            return tszPath + 6;   // points at \server\share (\\?\UNC\ -> \\)

        return tszPath + 4;       // points at C:\path
    }

    return tszPath;
}


// ---------------------------------------------------------------------------
// IoCanonicalizePath — in-process path normalizer, replacing PathCanonicalize.
//
// Resolves '.' and '..' segments, normalises '/' to '\', and supports paths
// of any length up to cchOut characters.  No Win32 API is called.
//
// Does NOT:
//   - Call GetFullPathName, PathCanonicalize, or any other Win32 API
//   - Resolve junctions, reparse points, or symlinks
//   - Add or strip a \\?\ prefix (use with the manifest longPathAware opt-in)
//
// The input path should be absolute (drive-letter or UNC root).
// Relative paths are accepted; '..' above the recognised root is silently
// clamped (same behaviour as PathCanonicalize).
//
// Parameters:
//   pszOut  — output buffer, receives the normalised path
//   cchOut  — capacity of pszOut in TCHARs, including the NUL terminator
//   pszIn   — input path (may contain '/' separators, '.' and '..' segments)
//
// Returns TRUE on success, FALSE if pszOut is too small or pszIn is NULL.
// ---------------------------------------------------------------------------
BOOL
IoCanonicalizePath(LPTSTR pszOut, INT cchOut, LPCTSTR pszIn)
{
    TCHAR  szWork[_MAX_LONG_PATH + 1];
    INT    root_len;
    INT    out_pos;
    INT    i;
    LPTSTR pSeg, pEnd;

    if (!pszIn || !pszOut || cchOut <= 0)
        return FALSE;

    // Step 1: Copy input into working buffer, normalising '/' to '\\'.
    i = 0;
    while (pszIn[i] && i < _MAX_LONG_PATH)
    {
        szWork[i] = (pszIn[i] == _T('/')) ? _T('\\') : pszIn[i];
        i++;
    }
    szWork[i] = _T('\0');
    if (pszIn[i] != _T('\0'))
        return FALSE;   // input exceeds working buffer capacity

    // Step 2: \\?\ prefix — copy through unchanged.
    // The path component after \\?\ is a raw NT object path; '..' resolution
    // would be incorrect there.
    if (szWork[0] == _T('\\') && szWork[1] == _T('\\') &&
        szWork[2] == _T('?')  && szWork[3] == _T('\\'))
    {
        INT n = (INT)_tcslen(szWork);
        if (n + 1 > cchOut) return FALSE;
        _tcscpy_s(pszOut, (size_t)cchOut, szWork);
        return TRUE;
    }

    // Step 3: Determine the root length.
    root_len = 0;
    if (szWork[0] != _T('\0') && szWork[1] == _T(':') && szWork[2] == _T('\\'))
    {
        // Drive-letter root: "C:\".  Uppercase the drive letter for consistency.
        szWork[0] = (TCHAR)toupper((unsigned char)szWork[0]);
        root_len = 3;
    }
    else if (szWork[0] == _T('\\') && szWork[1] == _T('\\'))
    {
        // UNC root: "\\server\share[\...]"
        LPTSTR p = szWork + 2;
        while (*p && *p != _T('\\')) p++;   // end of server name
        if (*p == _T('\\')) p++;            // skip the separator
        while (*p && *p != _T('\\')) p++;   // end of share name
        if (*p == _T('\\')) p++;            // include trailing separator in root
        root_len = (INT)(p - szWork);
    }
    // else: no recognised absolute root — treat as relative, root_len = 0.

    // Step 4: Copy the root prefix into the output buffer.
    if (root_len + 1 > cchOut)
        return FALSE;
    if (root_len > 0)
        _tcsncpy_s(pszOut, (size_t)cchOut, szWork, (size_t)root_len);
    pszOut[root_len] = _T('\0');
    out_pos = root_len;

    // Step 5: Walk segments after the root, resolving '.' and '..'.
    pSeg = szWork + root_len;
    while (*pSeg == _T('\\')) pSeg++;   // skip any leading separators

    while (*pSeg != _T('\0'))
    {
        INT segLen;

        // Find the end of this segment.
        pEnd = pSeg;
        while (*pEnd && *pEnd != _T('\\')) pEnd++;
        segLen = (INT)(pEnd - pSeg);

        if (segLen == 0)
        {
            // Consecutive separators — skip.
        }
        else if (segLen == 1 && pSeg[0] == _T('.'))
        {
            // Current-directory reference — skip.
        }
        else if (segLen == 2 && pSeg[0] == _T('.') && pSeg[1] == _T('.'))
        {
            // Parent-directory reference — pop the last segment from output.
            if (out_pos > root_len)
            {
                INT pos = out_pos;
                // Walk back past the last segment name.
                while (pos > root_len && pszOut[pos - 1] != _T('\\'))
                    pos--;
                // Remove the separator that preceded the segment, unless it
                // is part of the root itself (e.g. the '\' in "C:\").
                if (pos > root_len)
                    pos--;
                out_pos = pos;
                pszOut[out_pos] = _T('\0');
            }
            // If already at (or above) root, '..' is silently clamped.
        }
        else
        {
            // Normal segment — append separator (if needed) then the segment.
            if (out_pos > 0 && pszOut[out_pos - 1] != _T('\\'))
            {
                if (out_pos + 1 >= cchOut) return FALSE;
                pszOut[out_pos++] = _T('\\');
                pszOut[out_pos]   = _T('\0');
            }
            if (out_pos + segLen >= cchOut) return FALSE;
            _tcsncpy_s(pszOut + out_pos, (size_t)(cchOut - out_pos), pSeg, (size_t)segLen);
            out_pos += segLen;
            pszOut[out_pos] = _T('\0');
        }

        // Advance past separator(s) to the start of the next segment.
        pSeg = pEnd;
        while (*pSeg == _T('\\')) pSeg++;
    }

    // Guard: if the result is empty (all segments cancelled, no root),
    // return '.' to represent the current directory.
    if (out_pos == 0)
    {
        if (cchOut < 2) return FALSE;
        pszOut[0] = _T('.');
        pszOut[1] = _T('\0');
    }

    return TRUE;
}


// ---------------------------------------------------------------------------
// IoIsNtfsPathTooLongError — classify a Win32 error as an NTFS path-length
// rejection so that all long-path wrappers can normalise to a single error
// code (ERROR_FILENAME_EXCED_RANGE) and produce a consistent FTP 550 reply.
//
// Rules:
//   ERROR_FILENAME_EXCED_RANGE (206) — always a path-too-long rejection.
//   ERROR_INVALID_NAME        (123) — always a path-too-long rejection.
//   ERROR_PATH_NOT_FOUND       (3)  — always a path-too-long rejection when
//                                     seen after the W+\\?\ retry; by that
//                                     point the path form is valid so the
//                                     error reflects an internal normalisation
//                                     limit, not a missing parent directory.
//   ERROR_FILE_NOT_FOUND       (2)  — a path-too-long rejection only when
//                                     cchPath >= MAX_PATH; Windows sometimes
//                                     returns this code during internal path
//                                     normalisation before the filesystem API
//                                     runs, rather than 206 or 3.
//
// Usage: call this AFTER the final W+\\?\ retry fails, passing the original
// path length (cch = _tcslen(lpPath)) as cchPath.  If TRUE is returned:
//   - SetLastError(ERROR_FILENAME_EXCED_RANGE)
//   - return FALSE / INVALID_HANDLE_VALUE as appropriate
// ---------------------------------------------------------------------------
BOOL
IoIsNtfsPathTooLongError(DWORD dwErr, SIZE_T cchPath)
{
    if (dwErr == ERROR_FILENAME_EXCED_RANGE ||
        dwErr == ERROR_INVALID_NAME         ||
        dwErr == ERROR_PATH_NOT_FOUND)
        return TRUE;

    // Windows sometimes returns ERROR_FILE_NOT_FOUND during internal path
    // normalisation for long paths, before the filesystem API runs.
    if (dwErr == ERROR_FILE_NOT_FOUND && cchPath >= MAX_PATH)
        return TRUE;

    return FALSE;
}


// ---------------------------------------------------------------------------
// IoGetAttributesByParentScan — last-resort fallback for Win32 device-name
// interception (ANSI ERROR_INVALID_HANDLE = 6).
//
// When the FINAL path component's stem matches a reserved Win32 device name
// (CON, NUL, PRN, AUX, COM1-COM9, LPT1-LPT9), GetFileAttributesEx returns
// ERROR_INVALID_HANDLE (6) and no \\?\ path form can bypass this when the
// drive is a session-specific SMB mapping (e.g. R: → \\VMHOST00\SITE$).
//
// Key insight: FindFirstFile("parent\*") has "*" as its last component — a
// wildcard, not a device name — so Win32 does NOT intercept it.  Win32 opens
// the parent directory (normal name, no issue) and issues a QUERY_DIRECTORY
// SMB operation, which the server handles at kernel level without device-name
// filtering.  This succeeds even when a direct GetFileAttributesEx query for
// the same path fails.
//
// The function enumerates "parent\*" and returns the WIN32_FILE_ATTRIBUTE_DATA
// for the entry whose filename matches the last component of lpPath.
// The parent path must not itself end in a device-named component (the caller
// — the final component — is the device-named one).
//
// Returns TRUE on success (attributes populated); FALSE otherwise.
// ---------------------------------------------------------------------------
// IoPathHasDeviceNameStem — returns TRUE if any backslash/slash-separated
// component of lpPath has a stem that matches a reserved Win32 device name
// (CON, AUX, PRN, NUL, COM0-COM9, LPT0-LPT9).  Stem = the part before the
// first '.' in the component.  Comparison is case-insensitive.
// Used to decide whether to attempt a parent-scan fallback for ERROR_FILE_NOT_FOUND
// (err=2) failures, which occur when GetFileAttributesEx cannot traverse an
// intermediate path component that is a device name.
static BOOL
IoPathHasDeviceNameStem(LPCSTR lpPath)
{
    static const CHAR * const kDevNames[] = {
        "CON","AUX","PRN","NUL",
        "COM0","COM1","COM2","COM3","COM4","COM5","COM6","COM7","COM8","COM9",
        "LPT0","LPT1","LPT2","LPT3","LPT4","LPT5","LPT6","LPT7","LPT8","LPT9",
        NULL
    };
    LPCSTR p = lpPath;
    while (*p)
    {
        // Skip leading separators and drive-root (C:\, C:/)
        if (*p == '\\' || *p == '/') { p++; continue; }
        if (*(p + 1) == ':')         { p += 2; continue; }

        // Find stem: characters up to the first '.', '\', '/', or end
        LPCSTR pStem = p;
        while (*p && *p != '.' && *p != '\\' && *p != '/') p++;
        SIZE_T cchStem = (SIZE_T)(p - pStem);

        // Compare stem against each device name
        for (int i = 0; kDevNames[i]; i++)
        {
            SIZE_T cchDev = strlen(kDevNames[i]);
            if (cchStem == cchDev && _strnicmp(pStem, kDevNames[i], cchDev) == 0)
                return TRUE;
        }

        // Advance past the rest of this component
        while (*p && *p != '\\' && *p != '/') p++;
    }
    return FALSE;
}


static BOOL
IoGetAttributesByParentScan(LPCSTR lpPath, SIZE_T cch, WIN32_FILE_ATTRIBUTE_DATA *pInfo)
{
    CHAR             szPattern[_MAX_LONG_PATH + 3]; // parent + \* + NUL
    WIN32_FIND_DATAA fd;
    HANDLE           hFind;
    LPCSTR           pLastSlash, pTarget;
    SIZE_T           cchParent;
    BOOL             bFound = FALSE;

    // Locate last separator (backslash or forward slash) to split parent / filename.
    // Forward slashes may appear in paths passed from VFS resolution (e.g. MDTM
    // "R:/0DAY/0314/Con.Lehane...").  Win32 FindFirstFileA accepts mixed slashes.
    pLastSlash = NULL;
    for (SIZE_T i = 0; i < cch; i++)
        if (lpPath[i] == '\\' || lpPath[i] == '/') pLastSlash = lpPath + i;

    if (!pLastSlash || pLastSlash == lpPath)
        return FALSE;   // root path or no parent component

    cchParent = (SIZE_T)(pLastSlash - lpPath);
    if (cchParent + 3 > _MAX_LONG_PATH)  // parent + \ + * + NUL
        return FALSE;

    // Build "parent\*"
    memcpy(szPattern, lpPath, cchParent);
    szPattern[cchParent]     = '\\';
    szPattern[cchParent + 1] = '*';
    szPattern[cchParent + 2] = '\0';

    hFind = FindFirstFileA(szPattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE)
        return FALSE;

    pTarget = pLastSlash + 1;   // filename portion (after the backslash)
    do {
        if (_stricmp(fd.cFileName, pTarget) == 0)
        {
            pInfo->dwFileAttributes  = fd.dwFileAttributes;
            pInfo->ftCreationTime    = fd.ftCreationTime;
            pInfo->ftLastAccessTime  = fd.ftLastAccessTime;
            pInfo->ftLastWriteTime   = fd.ftLastWriteTime;
            pInfo->nFileSizeHigh     = fd.nFileSizeHigh;
            pInfo->nFileSizeLow      = fd.nFileSizeLow;
            bFound = TRUE;
            break;
        }
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    return bFound;
}


// IoGetFileAttributesEx — like GetFileAttributesEx but handles paths > MAX_PATH.
//
// WIN32_FILE_ATTRIBUTE_DATA contains no string fields; its layout is identical
// between the A and W variants.  GetFileAttributesExW can therefore write
// directly into a WIN32_FILE_ATTRIBUTE_DATA pointer — no struct conversion needed.
//
// Strategy (same as IoCreateDirectory / IoWin32FindFirstFile):
//   Short paths (len < MAX_PATH): try the ANSI API first; retry with W + \\?\
//     on path-length errors OR ERROR_FILE_NOT_FOUND.
//   Long paths (len >= MAX_PATH): skip the ANSI API, go directly to W + \\?\.
//
// Retry errors (ANSI → W fallback is attempted):
//   ERROR_FILE_NOT_FOUND (2)    — ANSI API may return this instead of 206 on
//                                  Windows Server 2019 for paths near MAX_PATH.
//   ERROR_PATH_NOT_FOUND (3)    — parent component inaccessible via ANSI.
//   ERROR_FILENAME_EXCED_RANGE (206) — classic MAX_PATH rejection.
//   ERROR_INVALID_NAME (123)    — path form rejected by ANSI layer.
//
// Final fallback: when ANSI returns ERROR_INVALID_HANDLE (6) — Win32 device-name
//   interception — and all \\?\ retries also fail, IoGetAttributesByParentScan
//   enumerates the parent directory to find the entry by name.  This works
//   because "parent\*" uses "*" as the last component (not a device name).
//
// Returns the same BOOL as GetFileAttributesEx; GetLastError() is preserved.
// ---------------------------------------------------------------------------
BOOL
IoGetFileAttributesEx(LPCTSTR lpPath, GET_FILEEX_INFO_LEVELS fInfoLevelId,
                      LPVOID lpFileInfo)
{
    WCHAR  szWidePfx[_MAX_LONG_PATH + 9];
    BOOL   bResult;
    SIZE_T cch;
    DWORD  dwErr;
    int    cchWide;

    if (!lpPath || !lpFileInfo)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    cch = _tcslen(lpPath);

    if (cch < MAX_PATH)
    {
        bResult = GetFileAttributesEx(lpPath, fInfoLevelId, lpFileInfo);
        if (bResult) return TRUE;

        dwErr = GetLastError();
        // Retry with W + \\?\ for any error that may be a path-length rejection
        // or a Windows device-name interception.
        // ERROR_FILE_NOT_FOUND (2): Windows Server 2019 returns this instead of
        //   ERROR_FILENAME_EXCED_RANGE for paths near MAX_PATH.
        // ERROR_DIRECTORY (267): Some Windows versions return this when the final
        //   path component matches a reserved device name (CON, NUL, COM1, etc.)
        //   via the ANSI API.  The \\?\ prefix bypasses device-name interception.
        // ERROR_INVALID_HANDLE (6): Returned by some mapped network drives (e.g.
        //   Windows Server 2019 SMB) when the ANSI layer intercepts a device-named
        //   path component.  GetFileAttributesExA takes no handle, so this code
        //   indicates Win32 redirection, not a caller bug.  Retry with \\?\.
        if (dwErr != ERROR_FILE_NOT_FOUND      &&
            dwErr != ERROR_PATH_NOT_FOUND      &&
            dwErr != ERROR_FILENAME_EXCED_RANGE &&
            dwErr != ERROR_INVALID_NAME        &&
            dwErr != ERROR_DIRECTORY           &&
            dwErr != ERROR_INVALID_HANDLE)
        {
            SetLastError(dwErr);
            return FALSE;           // genuine error (e.g. access denied), no retry
        }
    }
    else
    {
        // Path >= MAX_PATH: skip ANSI and go directly to W + \\?\.
        dwErr = ERROR_FILENAME_EXCED_RANGE;
    }

    if (cch < 2)
    {
        SetLastError(dwErr);
        return FALSE;
    }

    // Build \\?\-prefixed wide path and call GetFileAttributesExW.
    if (lpPath[0] == _T('\\') && lpPath[1] == _T('\\') && lpPath[2] != _T('?'))
    {
        // UNC: \\server\share\... → \\?\UNC\server\share\...
        szWidePfx[0] = L'\\'; szWidePfx[1] = L'\\';
        szWidePfx[2] = L'?';  szWidePfx[3] = L'\\';
        szWidePfx[4] = L'U';  szWidePfx[5] = L'N';
        szWidePfx[6] = L'C';  szWidePfx[7] = L'\\';
        cchWide = MultiByteToWideChar(CP_ACP, 0,
                      lpPath + 2, -1,
                      szWidePfx + 8, (int)(_countof(szWidePfx) - 8));
    }
    else if (lpPath[1] == _T(':'))
    {
        // Drive-letter: C:\... → \\?\C:\...
        szWidePfx[0] = L'\\'; szWidePfx[1] = L'\\';
        szWidePfx[2] = L'?';  szWidePfx[3] = L'\\';
        cchWide = MultiByteToWideChar(CP_ACP, 0,
                      lpPath, -1,
                      szWidePfx + 4, (int)(_countof(szWidePfx) - 4));
    }
    else
    {
        SetLastError(dwErr);
        return FALSE;
    }

    if (cchWide == 0)
    {
        SetLastError(dwErr);
        return FALSE;
    }

    // WIN32_FILE_ATTRIBUTE_DATA has no string fields — layout is identical
    // for A and W, so GetFileAttributesExW writes directly into lpFileInfo.
    bResult = GetFileAttributesExW(szWidePfx, fInfoLevelId, lpFileInfo);
    if (!bResult)
    {
        DWORD dwErrW = GetLastError();
        BOOL  bUNCTried = FALSE;
        // If \\?\X:\ returned FILE_NOT_FOUND the drive may be a session-specific
        // mapped network drive not visible in the \\?\ (NT object) namespace.
        // Resolve via QueryDosDevice to build \\?\UNC\server\share\... and retry.
        // If \\?\UNC\ also fails, retry again with a plain UNC path \\server\share\...
        // Plain UNC paths route through the MUP without Win32 device-name filtering,
        // so they reach the server even when the final component's stem is a
        // reserved device name (CON, NUL, COM1, LPT1, etc.).
        if (dwErrW == ERROR_FILE_NOT_FOUND)
        {
            WCHAR szUNCPfx[_MAX_LONG_PATH + 9];
            if (IoBuildUNCPfx(lpPath, cch, szUNCPfx, _countof(szUNCPfx)))
            {
                bUNCTried = TRUE;
                bResult = GetFileAttributesExW(szUNCPfx, fInfoLevelId, lpFileInfo);
                if (bResult) return TRUE;
                dwErrW = GetLastError();
                if (dwErrW == ERROR_FILE_NOT_FOUND)
                {
                    // Retry 3: plain UNC \\server\share\path.
                    // szUNCPfx is \\?\UNC\server\share\path.
                    // Setting [6]='\\' [7]='\\' makes szUNCPfx+6 = \\server\share\path.
                    szUNCPfx[6] = L'\\'; szUNCPfx[7] = L'\\';
                    bResult = GetFileAttributesExW(szUNCPfx + 6, fInfoLevelId, lpFileInfo);
                    if (bResult) return TRUE;
                    dwErrW = GetLastError();
                }
            }
        }
        if (g_bIoDebugLog)
            Putlog(LOG_DEBUG,
                _T("IoGetFileAttributesEx: ANSI err=%u, W-retry err=%u, UNC=%d, path='%s'\r\n"),
                dwErr, dwErrW, (int)bUNCTried, lpPath);

        // Final fallback: parent-directory scan for Win32 device-name interception.
        //
        // Two cases where this applies:
        //
        // Case A — ANSI ERROR_INVALID_HANDLE (6): the FINAL component's stem is a
        //   device name (e.g. "Con.Foo", "NUL.bar").  Win32 intercepts the path
        //   before it reaches the SMB driver.  All \\?\ forms also fail for
        //   session-specific drives.  Solution: enumerate "parent\*" (wildcard last
        //   component, not a device name) and match by filename.
        //
        // Case B — ERROR_FILE_NOT_FOUND (2) with a device-name stem anywhere in the
        //   path: the FINAL component is normal but it resides inside (or below) a
        //   directory whose stem is a device name.  SMB QueryInfo cannot traverse the
        //   device-named intermediate directory.  Same solution: enumerate
        //   "parent\*" — Win32 opens the parent (device-named directory) via an
        //   NtOpenFile kernel call that does not apply device-name filtering, so the
        //   SMB QUERY_DIRECTORY operation succeeds.
        //
        // IoGetAttributesByParentScan handles both backslash and forward-slash paths.
        if ((dwErr == ERROR_INVALID_HANDLE ||
             (dwErrW == ERROR_FILE_NOT_FOUND && IoPathHasDeviceNameStem(lpPath))) &&
            IoGetAttributesByParentScan(lpPath, cch, (WIN32_FILE_ATTRIBUTE_DATA *)lpFileInfo))
        {
            if (g_bIoDebugLog)
                Putlog(LOG_DEBUG,
                    _T("IoGetFileAttributesEx: parent-scan fallback succeeded for '%s'\r\n"),
                    lpPath);
            return TRUE;
        }

        if (IoIsNtfsPathTooLongError(dwErrW, cch))
            SetLastError(ERROR_FILENAME_EXCED_RANGE);
        else
            SetLastError(dwErrW);
    }
    return bResult;
}


// ---------------------------------------------------------------------------
// IoGetFileAttributes — like GetFileAttributes but handles paths > MAX_PATH.
//
// Convenience wrapper around IoGetFileAttributesEx that returns only the
// dwFileAttributes field.  Returns INVALID_FILE_ATTRIBUTES on failure;
// GetLastError() is preserved.
// ---------------------------------------------------------------------------
DWORD
IoGetFileAttributes(LPCTSTR lpPath)
{
    WIN32_FILE_ATTRIBUTE_DATA data;
    if (IoGetFileAttributesEx(lpPath, GetFileExInfoStandard, &data))
        return data.dwFileAttributes;
    return INVALID_FILE_ATTRIBUTES;
}


// ---------------------------------------------------------------------------
// IoCreateDirectory — like CreateDirectory but handles paths > MAX_PATH.
//
// Strategy:
//   1. Try CreateDirectoryA directly (works when LongPathsEnabled registry
//      key + longPathAware manifest are both present, or for short paths).
//   2. On any path-length-related error, retry via CreateDirectoryW with the
//      \\?\ extended-length prefix.
//
// WHY CreateDirectoryW for the retry:
//   The \\?\ prefix is documented to work only with Unicode (W) variants of
//   Win32 file APIs.  Calling CreateDirectoryA("\\?\C:\...", NULL) on a path
//   already at or above MAX_PATH causes the ANSI→Unicode internal conversion
//   to fail silently — no kernel call is made, and Procmon shows no retry.
//   CreateDirectoryW + MultiByteToWideChar bypasses that limitation entirely.
//
// Errors that trigger the retry:
//   ERROR_PATH_NOT_FOUND      (3)   — Windows truncated the long ANSI path
//   ERROR_FILENAME_EXCED_RANGE(206) — ANSI layer rejected the long path
//   ERROR_INVALID_NAME        (123) — some Windows builds return this instead
//
// Both drive-letter (C:\...) and UNC (\\server\share\...) paths are handled.
// The path must already be absolute and use backslash separators.
//
// Returns the same BOOL as CreateDirectory; GetLastError() is preserved on
// all return paths.
// ---------------------------------------------------------------------------
BOOL
IoCreateDirectory(LPCTSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecAttr)
{
    // Wide-char buffer: \\?\UNC\ prefix (8) + up to _MAX_LONG_PATH chars + NUL
    WCHAR   szWidePfx[_MAX_LONG_PATH + 9];
    DWORD   dwErr;
    SIZE_T  cch;
    int     cchWide;
    BOOL    bResult;

    if (!lpPathName)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    cch = _tcslen(lpPathName);

    // Attempt 1: direct call (works when registry key + manifest are both set,
    // or for any path that fits within MAX_PATH).
    bResult = CreateDirectory(lpPathName, lpSecAttr);
    if (bResult)
    {
        return TRUE;
    }

    dwErr = GetLastError();
    // Retry with \\?\ for path-length rejections and Windows device-name
    // interception.  ERROR_DIRECTORY (267) is returned by some Windows versions
    // when CreateDirectory is called with a final component that matches a
    // reserved device name (CON, NUL, COM1, LPT1, etc.) via the ANSI API.
    // ERROR_INVALID_HANDLE (6): returned by some mapped network drives (e.g.
    //   Windows Server 2019 SMB) for device-named path components.
    // The \\?\ prefix bypasses both interception behaviours.
    if (dwErr != ERROR_PATH_NOT_FOUND      &&
        dwErr != ERROR_FILENAME_EXCED_RANGE &&
        dwErr != ERROR_INVALID_NAME        &&
        dwErr != ERROR_DIRECTORY           &&
        dwErr != ERROR_INVALID_HANDLE)
    {
        return FALSE;   // GetLastError() already set to dwErr
    }

    // If the path is short, the error is genuine (e.g. missing parent), not a
    // length overflow; skip the expensive retry.
    if (cch < 2)
    {
        SetLastError(dwErr);
        return FALSE;
    }

    // Attempt 2: build a \\?\-prefixed wide-char path and call CreateDirectoryW.
    // CreateDirectoryW handles \\?\ correctly and is not bound by MAX_PATH.
    if (lpPathName[0] == _T('\\') && lpPathName[1] == _T('\\') &&
        lpPathName[2] != _T('?'))
    {
        // UNC: \\server\share\... → \\?\UNC\server\share\...
        // Replace leading \\ with \\?\UNC\ (net +6 chars)
        szWidePfx[0] = L'\\'; szWidePfx[1] = L'\\';
        szWidePfx[2] = L'?';  szWidePfx[3] = L'\\';
        szWidePfx[4] = L'U';  szWidePfx[5] = L'N';
        szWidePfx[6] = L'C';  szWidePfx[7] = L'\\';
        cchWide = MultiByteToWideChar(CP_ACP, 0,
                      lpPathName + 2, -1,
                      szWidePfx + 8, (int)(_countof(szWidePfx) - 8));
    }
    else if (lpPathName[1] == _T(':'))
    {
        // Drive-letter: C:\... → \\?\C:\...
        szWidePfx[0] = L'\\'; szWidePfx[1] = L'\\';
        szWidePfx[2] = L'?';  szWidePfx[3] = L'\\';
        cchWide = MultiByteToWideChar(CP_ACP, 0,
                      lpPathName, -1,
                      szWidePfx + 4, (int)(_countof(szWidePfx) - 4));
    }
    else
    {
        SetLastError(dwErr);
        return FALSE;
    }

    if (cchWide == 0)
    {
        SetLastError(dwErr);
        return FALSE;
    }

    if (CreateDirectoryW(szWidePfx, lpSecAttr))
        return TRUE;
    dwErr = GetLastError();
    if (dwErr == ERROR_FILE_NOT_FOUND || dwErr == ERROR_PATH_NOT_FOUND)
    {
        WCHAR szUNCPfx[_MAX_LONG_PATH + 9];
        SIZE_T cch = _tcslen(lpPathName);
        if (IoBuildUNCPfx(lpPathName, cch, szUNCPfx, _countof(szUNCPfx)))
        {
            if (CreateDirectoryW(szUNCPfx, lpSecAttr)) return TRUE;
            dwErr = GetLastError();
            if (dwErr == ERROR_FILE_NOT_FOUND || dwErr == ERROR_PATH_NOT_FOUND)
            {
                // Plain UNC retry (see IoGetFileAttributesEx for the trick explanation).
                szUNCPfx[6] = L'\\'; szUNCPfx[7] = L'\\';
                if (CreateDirectoryW(szUNCPfx + 6, lpSecAttr)) return TRUE;
                dwErr = GetLastError();
            }
        }
    }
    SetLastError(dwErr);
    return FALSE;
}


// ---------------------------------------------------------------------------
// Io_ConvertFindDataW — copy WIN32_FIND_DATAW into a WIN32_FIND_DATAA buffer.
//
// The binary fields (attributes, times, sizes, reserved) are bit-identical
// between the two structures; only the string members differ in width.
// WideCharToMultiByte with CP_ACP converts them.  NTFS limits each filename
// component to 255 UTF-16 code units, so the 260-char ANSI cFileName buffer
// is always sufficient.
// ---------------------------------------------------------------------------
static VOID
Io_ConvertFindDataW(const WIN32_FIND_DATAW *pW, WIN32_FIND_DATAA *pA)
{
    pA->dwFileAttributes = pW->dwFileAttributes;
    pA->ftCreationTime   = pW->ftCreationTime;
    pA->ftLastAccessTime = pW->ftLastAccessTime;
    pA->ftLastWriteTime  = pW->ftLastWriteTime;
    pA->nFileSizeHigh    = pW->nFileSizeHigh;
    pA->nFileSizeLow     = pW->nFileSizeLow;
    pA->dwReserved0      = pW->dwReserved0;
    pA->dwReserved1      = pW->dwReserved1;

    if (!WideCharToMultiByte(CP_ACP, 0,
            pW->cFileName, -1,
            pA->cFileName, MAX_PATH, NULL, NULL))
        pA->cFileName[0] = '\0';

    if (!WideCharToMultiByte(CP_ACP, 0,
            pW->cAlternateFileName, -1,
            pA->cAlternateFileName,
            (int)sizeof(pA->cAlternateFileName), NULL, NULL))
        pA->cAlternateFileName[0] = '\0';
}


// ---------------------------------------------------------------------------
// IoWin32FindFirstFile — drop-in for FindFirstFile that handles paths > MAX_PATH.
//
// NOTE on naming: DirectoryCache.c already defines IoFindFirstFile / IoFindNextFile
// for ioFTPD's internal cache API (different signatures, different purpose).
// These Win32-layer wrappers are therefore named IoWin32FindFirstFile /
// IoWin32FindNextFile to avoid a linker conflict.
//
// Strategy:
//   Short paths (len < MAX_PATH):
//     1. Try FindFirstFileA.  If it succeeds AND cFileName is non-empty, return
//        the handle directly — enumeration is complete and correct.
//     2. If FindFirstFileA succeeds but cFileName is empty (ANSI shim truncated
//        the first result), close the handle and fall through to the W path.
//     3. If FindFirstFileA fails with a path-length error, fall through to the
//        W path.  Any other failure is returned as-is (genuine error).
//
//   Long paths (len >= MAX_PATH):
//     FindFirstFileA on a path at or above MAX_PATH may return an incomplete
//     or empty enumeration even when the directory exists and has children —
//     the ANSI shim enumerates child names into WIN32_FIND_DATAA.cFileName[MAX_PATH]
//     but the combined parent+child path can exceed what the ANSI layer tracks.
//     Skip FindFirstFileA entirely and go directly to FindFirstFileW + \\?\.
//
// WHY FindFirstFileW for long paths (same rationale as IoCreateDirectory):
//   The \\?\ prefix only works reliably with Unicode (W) Win32 APIs.  Calling
//   FindFirstFileA("\\?\C:\...", ...) when the ANSI string is already at or
//   above MAX_PATH silently fails inside the Windows ANSI→Unicode shim.
//
// Returns INVALID_HANDLE_VALUE on failure; GetLastError() is preserved.
// ---------------------------------------------------------------------------
HANDLE
IoWin32FindFirstFile(LPCSTR lpPath, LPWIN32_FIND_DATAA pFindDataA)
{
    WIN32_FIND_DATAW wFindData;
    WCHAR            szWidePfx[_MAX_LONG_PATH + 9];
    HANDLE           hFind;
    SIZE_T           cch;
    DWORD            dwErr;
    int              cchWide;

    if (!lpPath || !pFindDataA)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }

    cch = strlen(lpPath);

    if (cch < MAX_PATH)
    {
        // Short path: try the ANSI API first.
        hFind = FindFirstFileA(lpPath, pFindDataA);
        if (hFind != INVALID_HANDLE_VALUE)
        {
            if (pFindDataA->cFileName[0] != '\0')
            {
                // Normal success path: cFileName populated, enumeration is valid.
                return hFind;
            }
            // cFileName is empty — ANSI shim may have returned a partial result.
            // Close and fall through to the W path.
            FindClose(hFind);
            hFind = INVALID_HANDLE_VALUE;
            dwErr = ERROR_FILENAME_EXCED_RANGE;  // synthetic trigger for W path
        }
        else
        {
            dwErr = GetLastError();
            // Retry via W for path-length errors and device-name interception.
            // ERROR_DIRECTORY (267): local drives — ANSI intercepts a reserved
            //   device name (CON, NUL, COM1…) in a path component.
            // ERROR_FILE_NOT_FOUND (2): network-mapped drives — some Windows
            //   versions return FILE_NOT_FOUND instead of ERROR_DIRECTORY when
            //   the ANSI layer intercepts a device-named component in a UNC or
            //   mapped-drive path. Retry with \\?\ to bypass interception.
            // ERROR_INVALID_HANDLE (6): returned by some mapped network drives
            //   (e.g. Windows Server 2019 SMB) for device-named path components.
            //   FindFirstFileA takes no handle; this is Win32 redirection.
            // A genuine access error or unexpected failure is returned as-is.
            if (dwErr != ERROR_PATH_NOT_FOUND      &&
                dwErr != ERROR_FILENAME_EXCED_RANGE &&
                dwErr != ERROR_INVALID_NAME        &&
                dwErr != ERROR_DIRECTORY           &&
                dwErr != ERROR_FILE_NOT_FOUND      &&
                dwErr != ERROR_INVALID_HANDLE)
            {
                return INVALID_HANDLE_VALUE;    // GetLastError() = dwErr
            }
        }
    }
    else
    {
        // Path >= MAX_PATH: skip ANSI entirely — FindFirstFileA on a >= MAX_PATH
        // pattern silently returns an incomplete enumeration on some Windows builds.
        // Go directly to FindFirstFileW with the \\?\ extended-length prefix.
        dwErr = ERROR_FILENAME_EXCED_RANGE;
    }

    if (cch < 2)
    {
        SetLastError(dwErr);
        return INVALID_HANDLE_VALUE;
    }

    // Build a \\?\-prefixed wide path and call FindFirstFileW.
    if (lpPath[0] == '\\' && lpPath[1] == '\\' && lpPath[2] != '?')
    {
        // UNC: \\server\share\...\* → \\?\UNC\server\share\...\*
        szWidePfx[0] = L'\\'; szWidePfx[1] = L'\\';
        szWidePfx[2] = L'?';  szWidePfx[3] = L'\\';
        szWidePfx[4] = L'U';  szWidePfx[5] = L'N';
        szWidePfx[6] = L'C';  szWidePfx[7] = L'\\';
        cchWide = MultiByteToWideChar(CP_ACP, 0,
                      lpPath + 2, -1,
                      szWidePfx + 8, (int)(_countof(szWidePfx) - 8));
    }
    else if (lpPath[1] == ':')
    {
        // Drive-letter: C:\...\* → \\?\C:\...\*
        szWidePfx[0] = L'\\'; szWidePfx[1] = L'\\';
        szWidePfx[2] = L'?';  szWidePfx[3] = L'\\';
        cchWide = MultiByteToWideChar(CP_ACP, 0,
                      lpPath, -1,
                      szWidePfx + 4, (int)(_countof(szWidePfx) - 4));
    }
    else
    {
        SetLastError(dwErr);
        return INVALID_HANDLE_VALUE;
    }

    if (cchWide == 0)
    {
        SetLastError(dwErr);
        return INVALID_HANDLE_VALUE;
    }

    ZeroMemory(&wFindData, sizeof(wFindData));
    hFind = FindFirstFileW(szWidePfx, &wFindData);
    if (hFind != INVALID_HANDLE_VALUE)
    {
        Io_ConvertFindDataW(&wFindData, pFindDataA);
    }
    else
    {
        DWORD dwErrW = GetLastError();
        BOOL  bUNCTried = FALSE;
        // If \\?\X:\ returned FILE_NOT_FOUND the drive may be a session-specific
        // mapped network drive.  Resolve via QueryDosDevice and retry as \\?\UNC\.
        // If that also fails, retry with a plain UNC path \\server\share\... which
        // bypasses Win32 device-name filtering entirely.
        if (dwErrW == ERROR_FILE_NOT_FOUND)
        {
            WCHAR szUNCPfx[_MAX_LONG_PATH + 9];
            if (IoBuildUNCPfx(lpPath, cch, szUNCPfx, _countof(szUNCPfx)))
            {
                bUNCTried = TRUE;
                ZeroMemory(&wFindData, sizeof(wFindData));
                hFind = FindFirstFileW(szUNCPfx, &wFindData);
                if (hFind != INVALID_HANDLE_VALUE)
                {
                    Io_ConvertFindDataW(&wFindData, pFindDataA);
                    return hFind;
                }
                dwErrW = GetLastError();
                if (dwErrW == ERROR_FILE_NOT_FOUND)
                {
                    // Plain UNC retry.
                    szUNCPfx[6] = L'\\'; szUNCPfx[7] = L'\\';
                    ZeroMemory(&wFindData, sizeof(wFindData));
                    hFind = FindFirstFileW(szUNCPfx + 6, &wFindData);
                    if (hFind != INVALID_HANDLE_VALUE)
                    {
                        Io_ConvertFindDataW(&wFindData, pFindDataA);
                        return hFind;
                    }
                    dwErrW = GetLastError();
                }
            }
        }
        if (g_bIoDebugLog)
            Putlog(LOG_DEBUG,
                _T("IoWin32FindFirstFile: ANSI err=%u, W-retry err=%u, UNC=%d, path='%s'\r\n"),
                dwErr, dwErrW, (int)bUNCTried, lpPath);
        SetLastError(dwErrW);
    }

    return hFind;
}


// ---------------------------------------------------------------------------
// IoCreateFile — like CreateFile but handles paths > MAX_PATH.
//
// Strategy (same as IoCreateDirectory):
//   1. Try CreateFileA directly.  Works for short paths, or for any path when
//      the longPathAware manifest + LongPathsEnabled registry key are both set.
//   2. On any path-length-related error, retry via CreateFileW with the \\?\
//      extended-length prefix built via MultiByteToWideChar.
//
// Errors that trigger the retry:
//   ERROR_PATH_NOT_FOUND      (3)   — Windows truncated the long ANSI path
//   ERROR_FILENAME_EXCED_RANGE(206) — ANSI layer rejected the long path
//   ERROR_INVALID_NAME        (123) — some Windows builds return this instead
//
// Both drive-letter (C:\...) and UNC (\\server\share\...) paths are handled.
// Returns INVALID_HANDLE_VALUE on failure; GetLastError() is preserved.
// ---------------------------------------------------------------------------
HANDLE
IoCreateFile(LPCTSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
             LPSECURITY_ATTRIBUTES lpSecurityAttributes,
             DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
             HANDLE hTemplateFile)
{
    WCHAR  szWidePfx[_MAX_LONG_PATH + 9];
    HANDLE hFile;
    DWORD  dwErr;
    SIZE_T cch;
    int    cchWide;

    if (!lpFileName)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }

    cch = _tcslen(lpFileName);

    // Attempt 1: direct ANSI call.
    hFile = CreateFile(lpFileName, dwDesiredAccess, dwShareMode,
                       lpSecurityAttributes, dwCreationDisposition,
                       dwFlagsAndAttributes, hTemplateFile);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        return hFile;
    }

    dwErr = GetLastError();
    // Retry for path-length rejections and Win32 device-name interception.
    // ERROR_DIRECTORY (267): Some Windows versions return this when CreateFile
    //   is called with a path whose component matches a reserved device name
    //   (CON, NUL, COM1, etc.) via the ANSI API. The \\?\ prefix bypasses it.
    // ERROR_INVALID_HANDLE (6): returned by some mapped network drives (e.g.
    //   Windows Server 2019 SMB) for device-named path components. CreateFile
    //   takes no handle at this point; this is Win32 redirection, not a bug.
    if (dwErr != ERROR_PATH_NOT_FOUND      &&
        dwErr != ERROR_FILENAME_EXCED_RANGE &&
        dwErr != ERROR_INVALID_NAME        &&
        dwErr != ERROR_DIRECTORY           &&
        dwErr != ERROR_INVALID_HANDLE)
    {
        SetLastError(dwErr);
        return INVALID_HANDLE_VALUE;
    }

    if (cch < 2)
    {
        SetLastError(dwErr);
        return INVALID_HANDLE_VALUE;
    }

    // Attempt 2: build a \\?\-prefixed wide-char path and call CreateFileW.
    if (lpFileName[0] == _T('\\') && lpFileName[1] == _T('\\') &&
        lpFileName[2] != _T('?'))
    {
        // UNC: \\server\share\... → \\?\UNC\server\share\...
        szWidePfx[0] = L'\\'; szWidePfx[1] = L'\\';
        szWidePfx[2] = L'?';  szWidePfx[3] = L'\\';
        szWidePfx[4] = L'U';  szWidePfx[5] = L'N';
        szWidePfx[6] = L'C';  szWidePfx[7] = L'\\';
        cchWide = MultiByteToWideChar(CP_ACP, 0,
                      lpFileName + 2, -1,
                      szWidePfx + 8, (int)(_countof(szWidePfx) - 8));
    }
    else if (lpFileName[1] == _T(':'))
    {
        // Drive-letter: C:\... → \\?\C:\...
        szWidePfx[0] = L'\\'; szWidePfx[1] = L'\\';
        szWidePfx[2] = L'?';  szWidePfx[3] = L'\\';
        cchWide = MultiByteToWideChar(CP_ACP, 0,
                      lpFileName, -1,
                      szWidePfx + 4, (int)(_countof(szWidePfx) - 4));
    }
    else
    {
        SetLastError(dwErr);
        return INVALID_HANDLE_VALUE;
    }

    if (cchWide == 0)
    {
        SetLastError(dwErr);
        return INVALID_HANDLE_VALUE;
    }

    hFile = CreateFileW(szWidePfx, dwDesiredAccess, dwShareMode,
                        lpSecurityAttributes, dwCreationDisposition,
                        dwFlagsAndAttributes, hTemplateFile);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        dwErr = GetLastError();
        if (dwErr == ERROR_FILE_NOT_FOUND || dwErr == ERROR_PATH_NOT_FOUND)
        {
            WCHAR szUNCPfx[_MAX_LONG_PATH + 9];
            if (IoBuildUNCPfx(lpFileName, cch, szUNCPfx, _countof(szUNCPfx)))
            {
                hFile = CreateFileW(szUNCPfx, dwDesiredAccess, dwShareMode,
                                    lpSecurityAttributes, dwCreationDisposition,
                                    dwFlagsAndAttributes, hTemplateFile);
                if (hFile != INVALID_HANDLE_VALUE) return hFile;
                dwErr = GetLastError();
                if (dwErr == ERROR_FILE_NOT_FOUND || dwErr == ERROR_PATH_NOT_FOUND)
                {
                    // Plain UNC retry.
                    szUNCPfx[6] = L'\\'; szUNCPfx[7] = L'\\';
                    hFile = CreateFileW(szUNCPfx + 6, dwDesiredAccess, dwShareMode,
                                        lpSecurityAttributes, dwCreationDisposition,
                                        dwFlagsAndAttributes, hTemplateFile);
                    if (hFile != INVALID_HANDLE_VALUE) return hFile;
                    dwErr = GetLastError();
                }
            }
        }
        SetLastError(IoIsNtfsPathTooLongError(dwErr, cch)
                     ? ERROR_FILENAME_EXCED_RANGE : dwErr);
    }
    return hFile;
}


// ---------------------------------------------------------------------------
// IoMoveFileEx — like MoveFileEx but handles paths > MAX_PATH.
//
// Strategy: try MoveFileExA first; on path-length errors, retry with
// MoveFileExW + \\?\ prefixes for both source and destination.
//
// Returns TRUE on success; GetLastError() is preserved on failure.
// ---------------------------------------------------------------------------
BOOL
IoMoveFileEx(LPCTSTR lpExistingFileName, LPCTSTR lpNewFileName, DWORD dwFlags)
{
    WCHAR  szWideSrc[_MAX_LONG_PATH + 9];
    WCHAR  szWideDst[_MAX_LONG_PATH + 9];
    DWORD  dwErr;
    int    cchWideSrc, cchWideDst;

    if (!lpExistingFileName || !lpNewFileName)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    // Attempt 1: direct ANSI call.
    if (MoveFileEx(lpExistingFileName, lpNewFileName, dwFlags))
    {
        return TRUE;
    }

    dwErr = GetLastError();
    // Retry for path-length rejections and Win32 device-name interception.
    // ERROR_DIRECTORY (267): ANSI layer intercepts a device-named final component.
    // ERROR_INVALID_HANDLE (6): some mapped network drives return this instead.
    if (dwErr != ERROR_PATH_NOT_FOUND      &&
        dwErr != ERROR_FILENAME_EXCED_RANGE &&
        dwErr != ERROR_INVALID_NAME        &&
        dwErr != ERROR_DIRECTORY           &&
        dwErr != ERROR_INVALID_HANDLE)
    {
        SetLastError(dwErr);
        return FALSE;
    }

    // Build wide \\?\ path for the source.
    if (lpExistingFileName[0] == _T('\\') && lpExistingFileName[1] == _T('\\') &&
        lpExistingFileName[2] != _T('?'))
    {
        szWideSrc[0] = L'\\'; szWideSrc[1] = L'\\';
        szWideSrc[2] = L'?';  szWideSrc[3] = L'\\';
        szWideSrc[4] = L'U';  szWideSrc[5] = L'N';
        szWideSrc[6] = L'C';  szWideSrc[7] = L'\\';
        cchWideSrc = MultiByteToWideChar(CP_ACP, 0,
                         lpExistingFileName + 2, -1,
                         szWideSrc + 8, (int)(_countof(szWideSrc) - 8));
    }
    else if (lpExistingFileName[1] == _T(':'))
    {
        szWideSrc[0] = L'\\'; szWideSrc[1] = L'\\';
        szWideSrc[2] = L'?';  szWideSrc[3] = L'\\';
        cchWideSrc = MultiByteToWideChar(CP_ACP, 0,
                         lpExistingFileName, -1,
                         szWideSrc + 4, (int)(_countof(szWideSrc) - 4));
    }
    else
    {
        SetLastError(dwErr);
        return FALSE;
    }

    // Build wide \\?\ path for the destination.
    if (lpNewFileName[0] == _T('\\') && lpNewFileName[1] == _T('\\') &&
        lpNewFileName[2] != _T('?'))
    {
        szWideDst[0] = L'\\'; szWideDst[1] = L'\\';
        szWideDst[2] = L'?';  szWideDst[3] = L'\\';
        szWideDst[4] = L'U';  szWideDst[5] = L'N';
        szWideDst[6] = L'C';  szWideDst[7] = L'\\';
        cchWideDst = MultiByteToWideChar(CP_ACP, 0,
                         lpNewFileName + 2, -1,
                         szWideDst + 8, (int)(_countof(szWideDst) - 8));
    }
    else if (lpNewFileName[1] == _T(':'))
    {
        szWideDst[0] = L'\\'; szWideDst[1] = L'\\';
        szWideDst[2] = L'?';  szWideDst[3] = L'\\';
        cchWideDst = MultiByteToWideChar(CP_ACP, 0,
                         lpNewFileName, -1,
                         szWideDst + 4, (int)(_countof(szWideDst) - 4));
    }
    else
    {
        SetLastError(dwErr);
        return FALSE;
    }

    if (cchWideSrc == 0 || cchWideDst == 0)
    {
        SetLastError(dwErr);
        return FALSE;
    }

    if (MoveFileExW(szWideSrc, szWideDst, dwFlags))
        return TRUE;
    dwErr = GetLastError();
    if (dwErr == ERROR_FILE_NOT_FOUND || dwErr == ERROR_PATH_NOT_FOUND)
    {
        WCHAR szUNCSrc[_MAX_LONG_PATH + 9];
        WCHAR szUNCDst[_MAX_LONG_PATH + 9];
        SIZE_T cchSrc = _tcslen(lpExistingFileName);
        SIZE_T cchDst = _tcslen(lpNewFileName);
        if (IoBuildUNCPfx(lpExistingFileName, cchSrc, szUNCSrc, _countof(szUNCSrc)) &&
            IoBuildUNCPfx(lpNewFileName,       cchDst, szUNCDst, _countof(szUNCDst)))
        {
            if (MoveFileExW(szUNCSrc, szUNCDst, dwFlags)) return TRUE;
            dwErr = GetLastError();
            if (dwErr == ERROR_FILE_NOT_FOUND || dwErr == ERROR_PATH_NOT_FOUND)
            {
                // Plain UNC retry for both src and dst.
                szUNCSrc[6] = L'\\'; szUNCSrc[7] = L'\\';
                szUNCDst[6] = L'\\'; szUNCDst[7] = L'\\';
                if (MoveFileExW(szUNCSrc + 6, szUNCDst + 6, dwFlags)) return TRUE;
                dwErr = GetLastError();
            }
        }
    }
    if (IoIsNtfsPathTooLongError(dwErr, _tcslen(lpExistingFileName)))
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
    else
        SetLastError(dwErr);
    return FALSE;
}


// ---------------------------------------------------------------------------
// IoWin32FindNextFile — drop-in for FindNextFile, always uses FindNextFileW.
//
// Windows' find HANDLE is a kernel enumeration object; FindNextFileW and
// FindNextFileA operate identically on the same HANDLE — they differ only in
// how they format the enumerated name (Wide vs. ANSI).  Using FindNextFileW
// universally therefore works correctly with handles obtained from either
// FindFirstFileA (short-path fast path) or FindFirstFileW (\\?\ path), without
// any per-handle mode tracking.
//
// Returns FALSE on failure; GetLastError() preserved.
// ---------------------------------------------------------------------------
BOOL
IoWin32FindNextFile(HANDLE hFind, LPWIN32_FIND_DATAA pFindDataA)
{
    WIN32_FIND_DATAW wFindData;
    BOOL             bResult;

    if (hFind == INVALID_HANDLE_VALUE || !pFindDataA)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(&wFindData, sizeof(wFindData));
    bResult = FindNextFileW(hFind, &wFindData);
    if (bResult)
        Io_ConvertFindDataW(&wFindData, pFindDataA);

    return bResult;
}


// ---------------------------------------------------------------------------
// IoBuildWidePfx — internal helper: builds a \\?\-prefixed wide path.
//
// Converts the ANSI path lpPath to a wide-char \\?\C:\... or \\?\UNC\...
// form suitable for passing to W-variant APIs that bypass MAX_PATH.
//
// Parameters:
//   lpPath  — ANSI source path (NUL-terminated)
//   cch     — _tcslen(lpPath)
//   szOut   — output buffer for the wide path
//   cchOut  — capacity of szOut in wide chars
//
// Returns the number of wide chars written into szOut (including NUL), or
// 0 on failure (path form unrecognised, buffer too small, or conversion failed).
// ---------------------------------------------------------------------------
static int
IoBuildWidePfx(LPCTSTR lpPath, SIZE_T cch, WCHAR *szOut, int cchOut)
{
    if (cch < 2)
        return 0;

    if (lpPath[0] == _T('\\') && lpPath[1] == _T('\\') && lpPath[2] != _T('?'))
    {
        // UNC: \\server\share\... → \\?\UNC\server\share\...
        if (cchOut < 9) return 0;
        szOut[0] = L'\\'; szOut[1] = L'\\';
        szOut[2] = L'?';  szOut[3] = L'\\';
        szOut[4] = L'U';  szOut[5] = L'N';
        szOut[6] = L'C';  szOut[7] = L'\\';
        return MultiByteToWideChar(CP_ACP, 0, lpPath + 2, -1, szOut + 8, cchOut - 8);
    }
    else if (lpPath[1] == _T(':'))
    {
        // Drive-letter: C:\... → \\?\C:\...
        if (cchOut < 5) return 0;
        szOut[0] = L'\\'; szOut[1] = L'\\';
        szOut[2] = L'?';  szOut[3] = L'\\';
        return MultiByteToWideChar(CP_ACP, 0, lpPath, -1, szOut + 4, cchOut - 4);
    }
    return 0;
}


// ---------------------------------------------------------------------------
// IoBuildUNCPfx — resolve a drive-letter path to \\?\UNC\server\share\...
//
// When \\?\X:\ fails with ERROR_FILE_NOT_FOUND for a mapped network drive,
// the drive letter exists only in the session-specific DOS device namespace
// (\Sessions\N\DosDevices\X:) and is invisible to the NT object namespace
// (\GLOBAL??\) used by \\?\.  QueryDosDeviceW resolves the drive through the
// current process's namespace, giving the true device path from which we
// extract the UNC server\share and build \\?\UNC\server\share\rest\of\path.
//
// QueryDosDeviceW output format for a mapped network drive:
//   \Device\LanmanRedirector\;R:00000000000d8ae9\server\share
//                              ^^^^^^^^^^^^^^^^^^
//                              skip this tag to reach \server\share
//
// Local drives (e.g. \Device\HarddiskVolume3) have no ';' and return 0.
//
// Returns number of wide chars written to szOut (including NUL), or 0 on
// failure.  szOut must be at least _MAX_LONG_PATH + 9 wide chars.
// ---------------------------------------------------------------------------
static int
IoBuildUNCPfx(LPCTSTR lpPath, SIZE_T cch, WCHAR *szOut, int cchOut)
{
    // 1024 chars: larger than MAX_PATH+1 to handle long SMB device strings.
    WCHAR  szDevice[1024];
    WCHAR  szDrive[3];
    WCHAR *pSemi, *pSlash;
    int    cchShare, cchRest;

    if (cch < 2 || lpPath[1] != _T(':'))
        return 0;   // not a drive-letter path

    szDrive[0] = (WCHAR)(unsigned char)lpPath[0];
    szDrive[1] = L':';
    szDrive[2] = L'\0';

    if (!QueryDosDeviceW(szDrive, szDevice, _countof(szDevice)))
    {
        if (g_bIoDebugLog)
            Putlog(LOG_DEBUG,
                _T("IoBuildUNCPfx: QueryDosDeviceW('%c:') failed err=%u\r\n"),
                lpPath[0], GetLastError());
        return 0;
    }

    if (g_bIoDebugLog)
        Putlog(LOG_DEBUG,
            _T("IoBuildUNCPfx: QueryDosDeviceW('%c:') = '%S'\r\n"),
            lpPath[0], szDevice);

    // A ';' in the device name indicates a network redirector entry.
    // Device path format examples:
    //   \Device\LanmanRedirector\;R:SESSIONID\server\share
    //   \Device\Mup\;LanmanRedirector\;R:SESSIONID\server\share
    // Use wcsrchr (last ';') so that both single- and double-semicolon
    // formats resolve to the correct ;X:SESSIONID\server\share segment.
    pSemi = wcsrchr(szDevice, L';');
    if (!pSemi)
    {
        if (g_bIoDebugLog)
            Putlog(LOG_DEBUG,
                _T("IoBuildUNCPfx: no ';' in device string for '%c:' — local drive, skipping\r\n"),
                lpPath[0]);
        return 0;   // local drive, no UNC equivalent
    }

    pSlash = wcschr(pSemi, L'\\');
    if (!pSlash)
    {
        if (g_bIoDebugLog)
            Putlog(LOG_DEBUG,
                _T("IoBuildUNCPfx: no '\\' after ';' in device string for '%c:'\r\n"),
                lpPath[0]);
        return 0;
    }

    pSlash++;                       // skip leading '\' -> "server\share"
    cchShare = (int)wcslen(pSlash);

    // Need: 8 (\\?\UNC\) + cchShare + 1 (\) + rest + NUL
    if (cchOut < 8 + cchShare + 2)
    {
        if (g_bIoDebugLog)
            Putlog(LOG_DEBUG,
                _T("IoBuildUNCPfx: output buffer too small (%d) for '%c:'\r\n"),
                cchOut, lpPath[0]);
        return 0;
    }

    szOut[0] = L'\\'; szOut[1] = L'\\';
    szOut[2] = L'?';  szOut[3] = L'\\';
    szOut[4] = L'U';  szOut[5] = L'N';
    szOut[6] = L'C';  szOut[7] = L'\\';
    wcscpy(szOut + 8, pSlash);      // append "server\share"

    if (cch > 3)
    {
        // Append '\' + rest of path (after "X:\")
        szOut[8 + cchShare] = L'\\';
        cchRest = MultiByteToWideChar(CP_ACP, 0,
                      lpPath + 3, -1,
                      szOut + 8 + cchShare + 1,
                      cchOut - 8 - cchShare - 1);
        if (!cchRest)
        {
            if (g_bIoDebugLog)
                Putlog(LOG_DEBUG,
                    _T("IoBuildUNCPfx: MultiByteToWideChar failed for '%s'\r\n"), lpPath);
            return 0;
        }
        if (g_bIoDebugLog)
            Putlog(LOG_DEBUG, _T("IoBuildUNCPfx: built '\\\\?\\UNC\\%S'\r\n"), szOut + 8);
        return 8 + cchShare + 1 + cchRest;
    }
    szOut[8 + cchShare] = L'\0';
    if (g_bIoDebugLog)
        Putlog(LOG_DEBUG, _T("IoBuildUNCPfx: built '\\\\?\\UNC\\%S'\r\n"), szOut + 8);
    return 8 + cchShare + 1;
}


// ---------------------------------------------------------------------------
// IoDeleteFileEx — like DeleteFile but handles paths > MAX_PATH.
//
// Strategy: try DeleteFileA first; on path-length errors (or err=2 which
// Windows Server 2019 may return for paths near MAX_PATH), retry with
// DeleteFileW + the \\?\ extended-length prefix.
//
// Errors that trigger the W retry:
//   ERROR_FILE_NOT_FOUND      (2)   — Win Server 2019 false-negative near MAX_PATH
//   ERROR_PATH_NOT_FOUND      (3)   — path truncated by ANSI layer
//   ERROR_FILENAME_EXCED_RANGE(206) — ANSI layer rejected the long path
//   ERROR_INVALID_NAME        (123) — some Windows builds return this instead
//
// Returns TRUE on success; GetLastError() is preserved on failure.
// ---------------------------------------------------------------------------
BOOL
IoDeleteFileEx(LPCTSTR lpPath)
{
    WCHAR  szWidePfx[_MAX_LONG_PATH + 9];
    DWORD  dwErr;
    SIZE_T cch;
    int    cchWide;

    if (!lpPath)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    cch = _tcslen(lpPath);
    // Attempt 1: direct ANSI call.
    if (DeleteFile(lpPath))
    {
        return TRUE;
    }

    dwErr = GetLastError();
    // Retry for path-length rejections and Win32 device-name interception.
    // ERROR_DIRECTORY (267): ANSI layer intercepts a device-named path component.
    // ERROR_INVALID_HANDLE (6): some mapped network drives return this instead.
    if (dwErr != ERROR_FILE_NOT_FOUND      &&
        dwErr != ERROR_PATH_NOT_FOUND      &&
        dwErr != ERROR_FILENAME_EXCED_RANGE &&
        dwErr != ERROR_INVALID_NAME        &&
        dwErr != ERROR_DIRECTORY           &&
        dwErr != ERROR_INVALID_HANDLE)
    {
        SetLastError(dwErr);
        return FALSE;
    }

    // Attempt 2: build \\?\ wide path and call DeleteFileW.
    cchWide = IoBuildWidePfx(lpPath, cch, szWidePfx, (int)_countof(szWidePfx));
    if (cchWide == 0)
    {
        SetLastError(dwErr);
        return FALSE;
    }

    if (DeleteFileW(szWidePfx))
        return TRUE;
    dwErr = GetLastError();
    if (dwErr == ERROR_FILE_NOT_FOUND || dwErr == ERROR_PATH_NOT_FOUND)
    {
        WCHAR szUNCPfx[_MAX_LONG_PATH + 9];
        if (IoBuildUNCPfx(lpPath, cch, szUNCPfx, _countof(szUNCPfx)))
        {
            if (DeleteFileW(szUNCPfx)) return TRUE;
            dwErr = GetLastError();
            if (dwErr == ERROR_FILE_NOT_FOUND || dwErr == ERROR_PATH_NOT_FOUND)
            {
                szUNCPfx[6] = L'\\'; szUNCPfx[7] = L'\\';
                if (DeleteFileW(szUNCPfx + 6)) return TRUE;
                dwErr = GetLastError();
            }
        }
    }
    if (IoIsNtfsPathTooLongError(dwErr, cch))
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
    else
        SetLastError(dwErr);
    return FALSE;
}


// ---------------------------------------------------------------------------
// IoRemoveDirectoryEx — like RemoveDirectory but handles paths > MAX_PATH.
//
// Strategy (mirrors IoWin32FindFirstFile / IoGetFileAttributesEx):
//   Short paths (len < MAX_PATH):
//     1. Try RemoveDirectoryA directly.
//     2. On path-length related errors, retry with RemoveDirectoryW + \\?\ prefix.
//   Long paths (len >= MAX_PATH):
//     Skip ANSI entirely — go directly to RemoveDirectoryW + \\?\ prefix.
//     RemoveDirectoryA silently fails or returns ERROR_FILENAME_EXCED_RANGE on
//     some Windows builds for paths at or above MAX_PATH.
//
// Errors that trigger the W retry (short-path path only):
//   ERROR_FILE_NOT_FOUND      (2)   — Win Server 2019 false-negative near MAX_PATH
//   ERROR_PATH_NOT_FOUND      (3)   — path truncated by ANSI layer
//   ERROR_FILENAME_EXCED_RANGE(206) — ANSI layer rejected the long path
//   ERROR_INVALID_NAME        (123) — some Windows builds return this instead
//
// ERROR_ACCESS_DENIED (5) and other hard errors are never retried.
// Returns TRUE on success; GetLastError() is preserved on failure.
// ---------------------------------------------------------------------------
BOOL
IoRemoveDirectoryEx(LPCTSTR lpPath)
{
    WCHAR  szWidePfx[_MAX_LONG_PATH + 9];
    DWORD  dwErr;
    SIZE_T cch;
    int    cchWide;

    if (!lpPath)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    cch = _tcslen(lpPath);
    if (cch < MAX_PATH)
    {
        // Attempt 1: direct ANSI call for short paths.
        if (RemoveDirectory(lpPath))
        {
            return TRUE;
        }

        dwErr = GetLastError();
        // Retry for path-length rejections and Win32 device-name interception.
        // ERROR_DIRECTORY (267): ANSI layer intercepts a device-named final component.
        // ERROR_INVALID_HANDLE (6): some mapped network drives return this instead.
        if (dwErr != ERROR_FILE_NOT_FOUND      &&
            dwErr != ERROR_PATH_NOT_FOUND      &&
            dwErr != ERROR_FILENAME_EXCED_RANGE &&
            dwErr != ERROR_INVALID_NAME        &&
            dwErr != ERROR_DIRECTORY           &&
            dwErr != ERROR_INVALID_HANDLE)
        {
            SetLastError(dwErr);
            return FALSE;
        }
    }
    else
    {
        // Path >= MAX_PATH: skip ANSI, use RemoveDirectoryW with \\?\ directly.
        dwErr = ERROR_FILENAME_EXCED_RANGE;
    }

    // Attempt 2 (always for long paths): build \\?\ wide path and call RemoveDirectoryW.
    cchWide = IoBuildWidePfx(lpPath, cch, szWidePfx, (int)_countof(szWidePfx));
    if (cchWide == 0)
    {
        SetLastError(dwErr);
        return FALSE;
    }

    if (RemoveDirectoryW(szWidePfx))
        return TRUE;
    dwErr = GetLastError();
    if (dwErr == ERROR_FILE_NOT_FOUND || dwErr == ERROR_PATH_NOT_FOUND)
    {
        WCHAR szUNCPfx[_MAX_LONG_PATH + 9];
        if (IoBuildUNCPfx(lpPath, cch, szUNCPfx, _countof(szUNCPfx)))
        {
            if (RemoveDirectoryW(szUNCPfx)) return TRUE;
            dwErr = GetLastError();
            if (dwErr == ERROR_FILE_NOT_FOUND || dwErr == ERROR_PATH_NOT_FOUND)
            {
                szUNCPfx[6] = L'\\'; szUNCPfx[7] = L'\\';
                if (RemoveDirectoryW(szUNCPfx + 6)) return TRUE;
                dwErr = GetLastError();
            }
        }
    }
    if (IoIsNtfsPathTooLongError(dwErr, cch))
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
    else
        SetLastError(dwErr);
    return FALSE;
}


// ---------------------------------------------------------------------------
// IoOpenReparsePointForDelete — open a junction/symlink for reparse-point
// manipulation, with long-path support.
//
// Opens lpPath with FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS
// so the caller can issue FSCTL_GET_REPARSE_POINT / FSCTL_DELETE_REPARSE_POINT.
//
// On success: sets *phFile to the open handle, returns TRUE.
//   The caller is responsible for closing the handle via CloseHandle.
// On failure: sets *phFile to INVALID_HANDLE_VALUE, returns FALSE.
//
// Same ANSI-then-W retry strategy as IoCreateFile; retry errors: {2, 3, 206, 123}.
// ---------------------------------------------------------------------------
BOOL
IoOpenReparsePointForDelete(LPCTSTR lpPath, HANDLE *phFile)
{
    WCHAR  szWidePfx[_MAX_LONG_PATH + 9];
    HANDLE hFile;
    DWORD  dwErr;
    SIZE_T cch;
    int    cchWide;

    if (!lpPath || !phFile)
    {
        if (phFile) *phFile = INVALID_HANDLE_VALUE;
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *phFile = INVALID_HANDLE_VALUE;
    cch = _tcslen(lpPath);
    // Attempt 1: direct ANSI call.
    hFile = CreateFile(lpPath,
                       GENERIC_READ | GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL,
                       OPEN_EXISTING,
                       FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                       NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        *phFile = hFile;
        return TRUE;
    }

    dwErr = GetLastError();
    // Retry for path-length rejections and Win32 device-name interception.
    // ERROR_DIRECTORY (267): ANSI layer intercepts a device-named path component.
    // ERROR_INVALID_HANDLE (6): some mapped network drives return this instead.
    if (dwErr != ERROR_FILE_NOT_FOUND      &&
        dwErr != ERROR_PATH_NOT_FOUND      &&
        dwErr != ERROR_FILENAME_EXCED_RANGE &&
        dwErr != ERROR_INVALID_NAME        &&
        dwErr != ERROR_DIRECTORY           &&
        dwErr != ERROR_INVALID_HANDLE)
    {
        SetLastError(dwErr);
        return FALSE;
    }

    // Attempt 2: build \\?\ wide path and call CreateFileW.
    cchWide = IoBuildWidePfx(lpPath, cch, szWidePfx, (int)_countof(szWidePfx));
    if (cchWide == 0)
    {
        SetLastError(dwErr);
        return FALSE;
    }

    hFile = CreateFileW(szWidePfx,
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL,
                        OPEN_EXISTING,
                        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                        NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        *phFile = hFile;
        return TRUE;
    }
    dwErr = GetLastError();
    if (dwErr == ERROR_FILE_NOT_FOUND || dwErr == ERROR_PATH_NOT_FOUND)
    {
        WCHAR szUNCPfx[_MAX_LONG_PATH + 9];
        if (IoBuildUNCPfx(lpPath, cch, szUNCPfx, _countof(szUNCPfx)))
        {
            hFile = CreateFileW(szUNCPfx,
                                GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                NULL,
                                OPEN_EXISTING,
                                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                                NULL);
            if (hFile != INVALID_HANDLE_VALUE)
            {
                *phFile = hFile;
                return TRUE;
            }
            dwErr = GetLastError();
            if (dwErr == ERROR_FILE_NOT_FOUND || dwErr == ERROR_PATH_NOT_FOUND)
            {
                szUNCPfx[6] = L'\\'; szUNCPfx[7] = L'\\';
                hFile = CreateFileW(szUNCPfx + 6,
                                    GENERIC_READ | GENERIC_WRITE,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    NULL,
                                    OPEN_EXISTING,
                                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                                    NULL);
                if (hFile != INVALID_HANDLE_VALUE)
                {
                    *phFile = hFile;
                    return TRUE;
                }
                dwErr = GetLastError();
            }
        }
    }
    if (IoIsNtfsPathTooLongError(dwErr, cch))
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
    else
        SetLastError(dwErr);
    return FALSE;
}
