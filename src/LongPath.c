#include <ioFTPD.h>

// ---------------------------------------------------------------------------
// Global flag — set once during LongPath_Init, read throughout the codebase.
// ---------------------------------------------------------------------------
BOOL g_LongPathsEnabled = FALSE;


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
        // Retry with W + \\?\ for any error that may be a path-length rejection.
        // ERROR_FILE_NOT_FOUND (2) is included because Windows Server 2019 can
        // return it instead of ERROR_FILENAME_EXCED_RANGE for paths near MAX_PATH.
        if (dwErr != ERROR_FILE_NOT_FOUND      &&
            dwErr != ERROR_PATH_NOT_FOUND      &&
            dwErr != ERROR_FILENAME_EXCED_RANGE &&
            dwErr != ERROR_INVALID_NAME)
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
        dwErr = GetLastError();
        if (IoIsNtfsPathTooLongError(dwErr, cch))
        {
            SetLastError(ERROR_FILENAME_EXCED_RANGE);
        }
        else
        {
            SetLastError(dwErr);
        }
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
    // Only retry for errors that indicate a path-length rejection.
    if (dwErr != ERROR_PATH_NOT_FOUND &&
        dwErr != ERROR_FILENAME_EXCED_RANGE &&
        dwErr != ERROR_INVALID_NAME)
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

    return CreateDirectoryW(szWidePfx, lpSecAttr);
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
            // Only retry via W for path-length errors; a genuine "not found"
            // or access error should be returned to the caller as-is.
            if (dwErr != ERROR_PATH_NOT_FOUND      &&
                dwErr != ERROR_FILENAME_EXCED_RANGE &&
                dwErr != ERROR_INVALID_NAME)
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
        Io_ConvertFindDataW(&wFindData, pFindDataA);

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
    // Only retry for errors that indicate a path-length rejection.
    if (dwErr != ERROR_PATH_NOT_FOUND &&
        dwErr != ERROR_FILENAME_EXCED_RANGE &&
        dwErr != ERROR_INVALID_NAME)
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
    // Only retry for path-length related errors.
    if (dwErr != ERROR_PATH_NOT_FOUND &&
        dwErr != ERROR_FILENAME_EXCED_RANGE &&
        dwErr != ERROR_INVALID_NAME)
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
    {
        return TRUE;
    }
    dwErr = GetLastError();
    if (IoIsNtfsPathTooLongError(dwErr, _tcslen(lpExistingFileName)))
    {
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
    }
    else
    {
        SetLastError(dwErr);
    }
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
    // Only retry for errors that may indicate a path-length rejection.
    if (dwErr != ERROR_FILE_NOT_FOUND      &&
        dwErr != ERROR_PATH_NOT_FOUND      &&
        dwErr != ERROR_FILENAME_EXCED_RANGE &&
        dwErr != ERROR_INVALID_NAME)
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
    {
        return TRUE;
    }
    dwErr = GetLastError();
    if (IoIsNtfsPathTooLongError(dwErr, cch))
    {
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
    }
    else
    {
        SetLastError(dwErr);
    }
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
        // Only retry for errors that may indicate a path-length rejection.
        if (dwErr != ERROR_FILE_NOT_FOUND      &&
            dwErr != ERROR_PATH_NOT_FOUND      &&
            dwErr != ERROR_FILENAME_EXCED_RANGE &&
            dwErr != ERROR_INVALID_NAME)
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
    {
        return TRUE;
    }
    dwErr = GetLastError();
    if (IoIsNtfsPathTooLongError(dwErr, cch))
    {
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
    }
    else
    {
        SetLastError(dwErr);
    }
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
    // Only retry for errors that may indicate a path-length rejection.
    if (dwErr != ERROR_FILE_NOT_FOUND      &&
        dwErr != ERROR_PATH_NOT_FOUND      &&
        dwErr != ERROR_FILENAME_EXCED_RANGE &&
        dwErr != ERROR_INVALID_NAME)
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
    if (IoIsNtfsPathTooLongError(dwErr, cch))
    {
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
    }
    else
    {
        SetLastError(dwErr);
    }
    return FALSE;
}
