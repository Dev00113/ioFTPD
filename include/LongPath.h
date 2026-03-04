// ---------------------------------------------------------------------------
// Long path support
//
// ioFTPD uses the Windows manifest longPathAware opt-in to lift the MAX_PATH
// (260-char) restriction from all Win32 ANSI APIs transparently.  No \\?\
// prefix is applied or needed.
//
// Requirements:
//   1. Windows 10 build 14393+ / Server 2016+
//   2. HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\LongPathsEnabled = 1
//   3. ioFTPD.exe manifest declares <longPathAware>true</longPathAware>
//      (embedded via ioFTPD.additional.manifest at build time)
//
// When all three conditions are met, CreateFile, FindFirstFile, and every
// other Win32 A-variant API transparently accept paths up to ~32,767 chars.
//
// _MAX_LONG_PATH — practical upper bound for ioFTPD internal path buffers.
//   True Win32 maximum is 32,767 but 4,096 is sufficient for all realistic
//   paths and avoids excessively large stack allocations.
//
// g_LongPathsEnabled — set at startup by LongPath_Init().  Used to gate
//   internal path-length guards; does NOT affect LongPath_Prefix behaviour
//   (which is always a no-op pass-through).
//
// LongPath_Prefix / LongPath_Free — retained no-op pass-through helpers.
//   All call sites compile unchanged; no prefix is added at runtime.
//
// LongPath_Strip — removes a \\?\ prefix from a path arriving from external
//   sources.  Internally generated paths never carry such a prefix.
// ---------------------------------------------------------------------------

#ifndef _LONGPATH_H_
#define _LONGPATH_H_

// Practical maximum for ioFTPD path buffers when long path support is active.
// Must be at least MAX_PATH+1 (261) and no larger than 32,767.
#define _MAX_LONG_PATH  4096

// Globally set at startup by LongPath_Init().
// TRUE  = OS build >= 14393 and LongPathsEnabled registry key are both present.
// FALSE = Long paths not available; internal guards enforce _MAX_PATH limits.
extern BOOL g_LongPathsEnabled;

// Returns TRUE if dwErr is an NTFS path-length rejection for a path of length
// cchPath.  Call this after the final W+\\?\ retry fails to decide whether to
// normalise the error to ERROR_FILENAME_EXCED_RANGE so that FTP clients see
// "550 Path too long for NTFS." instead of the less informative
// "550 Invalid filename."
//
// ERROR_FILENAME_EXCED_RANGE (206) and ERROR_INVALID_NAME (123) always qualify.
// ERROR_PATH_NOT_FOUND (3) always qualifies (post-retry, always a length limit).
// ERROR_FILE_NOT_FOUND (2) qualifies only when cchPath >= MAX_PATH (Windows
//   internal normalisation can return 2 instead of 206 for very long paths).
BOOL    IoIsNtfsPathTooLongError(DWORD dwErr, SIZE_T cchPath);

// Initialise long path support.  Reads [FTP] Long_Path_Support from the INI
// file and, in Auto mode, probes the OS and registry.  Logs one startup
// message describing the outcome.
// Called via the Init_Table; bFirstInitialization is always TRUE on first start.
BOOL    LongPath_Init(BOOL bFirstInitialization);

// No-op pass-through.  Returns tszPath unchanged.
// Retained so call sites compile without modification.
// The manifest longPathAware opt-in makes a \\?\ prefix unnecessary for ANSI APIs.
LPTSTR  LongPath_Prefix(LPCTSTR tszPath);

// No-op.  LongPath_Prefix never allocates; nothing to free.
// Safe to call unconditionally at every LongPath_Prefix call site.
VOID    LongPath_Free(LPCTSTR tszOriginal, LPTSTR tszPrefixed);

// Returns a pointer past the \\?\ (or \\?\UNC\) prefix in tszPath, or
// returns tszPath unchanged if no such prefix is present.
// Never allocates; the returned pointer points into the original string.
LPCTSTR LongPath_Strip(LPCTSTR tszPath);

// In-process path normalizer replacing PathCanonicalize (shlwapi).
// Normalises '/' to '\', resolves '.' and '..' segments without calling any
// Win32 API, and supports paths of any length up to cchOut characters.
// Does NOT resolve junctions or reparse points.  '..' above the root is
// silently clamped (same behaviour as PathCanonicalize).
// Returns TRUE on success, FALSE if pszOut is too small or pszIn is NULL.
BOOL    IoCanonicalizePath(LPTSTR pszOut, INT cchOut, LPCTSTR pszIn);

// Drop-in replacement for GetFileAttributesEx that supports paths > MAX_PATH.
// WIN32_FILE_ATTRIBUTE_DATA has no string fields — layout is identical for A and W,
// so GetFileAttributesExW writes directly into the same struct.
// On path-length failures with short paths, or for any path >= MAX_PATH,
// retries with GetFileAttributesExW + the \\?\ extended-length prefix.
BOOL    IoGetFileAttributesEx(LPCTSTR lpPath, GET_FILEEX_INFO_LEVELS fInfoLevelId,
                              LPVOID lpFileInfo);

// Drop-in replacement for GetFileAttributes that supports paths > MAX_PATH.
// Wraps IoGetFileAttributesEx; returns INVALID_FILE_ATTRIBUTES on failure.
DWORD   IoGetFileAttributes(LPCTSTR lpPath);

// Drop-in replacement for CreateDirectory that supports paths > MAX_PATH.
// On path-length failures it retries with the \\?\ extended-length prefix.
// Accepts drive-letter (C:\...) and UNC (\\server\share\...) absolute paths.
// The path must already use backslash separators and contain no . or .. segments.
BOOL    IoCreateDirectory(LPCTSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecAttr);

// Drop-in replacement for CreateFile that supports paths > MAX_PATH.
// On path-length failures it retries with CreateFileW + the \\?\ prefix.
// Accepts the same parameters as CreateFile.
// Returns INVALID_HANDLE_VALUE on failure; GetLastError() is preserved.
HANDLE  IoCreateFile(LPCTSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
                     LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                     DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
                     HANDLE hTemplateFile);

// Drop-in replacement for MoveFileEx that supports paths > MAX_PATH.
// On path-length failures it retries with MoveFileExW + the \\?\ prefix for
// both the source and destination paths.
// Returns FALSE on failure; GetLastError() is preserved.
BOOL    IoMoveFileEx(LPCTSTR lpExistingFileName, LPCTSTR lpNewFileName, DWORD dwFlags);

// Drop-in replacement for DeleteFile that supports paths > MAX_PATH.
// On path-length failures (including ERROR_FILE_NOT_FOUND which Windows Server 2019
// may return for paths near MAX_PATH), retries with DeleteFileW + the \\?\ prefix.
// Returns FALSE on failure; GetLastError() is preserved.
BOOL    IoDeleteFileEx(LPCTSTR lpPath);

// Drop-in replacement for RemoveDirectory that supports paths > MAX_PATH.
// On path-length failures, retries with RemoveDirectoryW + the \\?\ prefix.
// Returns FALSE on failure; GetLastError() is preserved.
BOOL    IoRemoveDirectoryEx(LPCTSTR lpPath);

// Opens a filesystem junction/symlink with FILE_FLAG_OPEN_REPARSE_POINT for
// reparse-point manipulation (FSCTL_GET/DELETE_REPARSE_POINT), with long-path support.
// On path-length failures, retries with CreateFileW + the \\?\ prefix.
// On success: sets *phFile to the handle, returns TRUE.  Caller must CloseHandle.
// On failure: sets *phFile to INVALID_HANDLE_VALUE, returns FALSE.
BOOL    IoOpenReparsePointForDelete(LPCTSTR lpPath, HANDLE *phFile);

// NOTE: IoFindFirstFile / IoFindNextFile are already defined in DirectoryCache.h
// for ioFTPD's internal cache API.  The Win32-layer wrappers below use the
// IoWin32* prefix to avoid a linker conflict.

// Drop-in replacement for FindFirstFile (ANSI) that handles paths > MAX_PATH.
// Attempt 1: FindFirstFileA directly.
// Attempt 2 (on path-length error or len >= MAX_PATH): FindFirstFileW with
//   the \\?\ extended-length prefix; result is converted back to WIN32_FIND_DATAA.
// Returns INVALID_HANDLE_VALUE on failure; use the returned HANDLE with
// IoWin32FindNextFile and the regular FindClose.
HANDLE  IoWin32FindFirstFile(LPCSTR lpPath, LPWIN32_FIND_DATAA pFindDataA);

// Drop-in replacement for FindNextFile (ANSI) that works with handles from
// both FindFirstFileA and FindFirstFileW (see IoWin32FindFirstFile).
// Internally always calls FindNextFileW and converts the result to DATAA.
// Returns FALSE when no more files; GetLastError() preserved.
BOOL    IoWin32FindNextFile(HANDLE hFind, LPWIN32_FIND_DATAA pFindDataA);

#endif // _LONGPATH_H_
