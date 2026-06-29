#include <ioFTPD.h>
#include <winnetwk.h>   // WNet* APIs
#include <iphlpapi.h>   // NotifyAddrChange

// ---------------------------------------------------------------------------
// Configuration defaults (overridden by ioFTPD.ini [Ftp] section)
// ---------------------------------------------------------------------------
#define NM_CHECK_INTERVAL_DEFAULT_MS   (60  * 1000)  // 60s healthy probe
#define NM_MAX_RETRY_MS                (300 * 1000)  // 300s max backoff
#define NM_INITIAL_RETRY_MS            (10  * 1000)  // 10s first retry after failure

// ---------------------------------------------------------------------------
// Module globals
// ---------------------------------------------------------------------------
static LPNETWORK_MOUNT   g_lpMountList     = NULL;
static CRITICAL_SECTION  g_csMountList;
static BOOL              g_bInitialized    = FALSE;
static volatile LONG     g_lShutdown       = 0;
static HANDLE            g_hWatchThread    = NULL;
static HANDLE            g_hWatchStop      = NULL;  // signalled during DeInit
static DWORD             g_dwCheckMs       = NM_CHECK_INTERVAL_DEFAULT_MS;
static DWORD             g_dwMaxRetryMs    = NM_MAX_RETRY_MS;
static volatile LONG     g_lStaggerMs      = 0;     // stagger initial probe start times

// ---------------------------------------------------------------------------
// Network error codes that indicate a transient share failure
// ---------------------------------------------------------------------------
static BOOL IsNetworkError(DWORD dw)
{
    switch (dw)
    {
    case ERROR_NETNAME_DELETED:      // 64  — connection dropped
    case ERROR_BAD_NETPATH:          // 53  — server unreachable
    case ERROR_NO_NET_OR_BAD_PATH:   // 67
    case ERROR_NETWORK_BUSY:         // 54
    case ERROR_DEV_NOT_EXIST:        // 55
    case ERROR_REM_NOT_LIST:         // 51
    case ERROR_NOT_CONNECTED:        // 2250
    case ERROR_CONNECTION_ABORTED:   // 1236
    case ERROR_CONNECTION_INVALID:   // 1229
        return TRUE;
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
// Normalise a UNC path to \\server\share (lowercase, no trailing \).
// Converts forward slashes, strips trailing \, lowercases.
// Validates that the result starts with \\ and has a server + share component.
// Returns FALSE if the path is not a valid UNC share root.
// ---------------------------------------------------------------------------
static BOOL NM_NormaliseRoot(LPCSTR szIn, char *szOut, DWORD dwOutMax)
{
    char   szBuf[NETMOUNT_UNC_MAX];
    DWORD  n = 0;
    LPCSTR p;

    if (!szIn || !szOut || dwOutMax < 5) return FALSE;

    // Copy input, converting forward slashes to backslashes
    for (p = szIn; *p && n < sizeof(szBuf) - 1; p++, n++)
        szBuf[n] = (*p == '/') ? '\\' : *p;
    szBuf[n] = '\0';

    // Strip trailing backslashes
    while (n > 0 && szBuf[n - 1] == '\\') szBuf[--n] = '\0';

    // Must start with double-backslash
    if (n < 4 || szBuf[0] != '\\' || szBuf[1] != '\\') return FALSE;
    // Must have a share component (a \ somewhere after the server name)
    if (!strchr(szBuf + 2, '\\')) return FALSE;

    if (n >= dwOutMax) return FALSE;

    _strlwr_s(szBuf, sizeof(szBuf));
    strcpy_s(szOut, dwOutMax, szBuf);
    return TRUE;
}

// ---------------------------------------------------------------------------
// Extract \\server\share from a full UNC path like \\server\share\sub\path.
// Returns FALSE if szPath is not a UNC path.
// ---------------------------------------------------------------------------
static BOOL NM_ExtractRoot(LPCSTR szPath, char *szRoot, DWORD dwRootMax)
{
    const char *p;
    const char *pServerStart;
    DWORD       len;
    char        szBuf[NETMOUNT_UNC_MAX];

    if (!szPath) return FALSE;

    // Normalise slashes to locate the start
    p = szPath;
    if ((p[0] != '\\' && p[0] != '/') ||
        (p[1] != '\\' && p[1] != '/')) return FALSE;

    // Copy first up to 4th separator (\\server\share)
    // Skip the initial double-backslash
    pServerStart = p + 2;

    // Find end of share name — the char after the next backslash
    const char *pSlash1 = strpbrk(pServerStart, "\\/");   // end of server
    if (!pSlash1) return FALSE;
    const char *pShareStart = pSlash1 + 1;
    const char *pSlash2     = strpbrk(pShareStart, "\\/");// end of share
    if (!pSlash2) pSlash2 = pShareStart + strlen(pShareStart); // share is last component

    // len = from start of szPath to end of share name
    len = (DWORD)(pSlash2 - szPath);
    if (len == 0 || len >= sizeof(szBuf)) return FALSE;

    strncpy_s(szBuf, sizeof(szBuf), szPath, len);
    szBuf[len] = '\0';

    return NM_NormaliseRoot(szBuf, szRoot, dwRootMax);
}

// ---------------------------------------------------------------------------
// Find an entry in the mount list whose root is a prefix of szPath.
// Caller must NOT hold g_csMountList (this takes no lock — lAvailable is volatile).
// List is append-only after init so pointer traversal is safe.
// ---------------------------------------------------------------------------
LPNETWORK_MOUNT NetworkMount_Find(LPCSTR szPath)
{
    LPNETWORK_MOUNT lpMount;
    char            szRoot[NETMOUNT_UNC_MAX];
    size_t          cchRoot;

    if (!g_bInitialized || !szPath) return NULL;

    // Fast check: must be a UNC path
    if (szPath[0] != '\\' || szPath[1] != '\\') return NULL;

    if (!NM_ExtractRoot(szPath, szRoot, sizeof(szRoot))) return NULL;
    cchRoot = strlen(szRoot);

    for (lpMount = g_lpMountList; lpMount; lpMount = lpMount->lpNext)
    {
        if (_strnicmp(lpMount->szUncRoot, szRoot, cchRoot) == 0 &&
            lpMount->szUncRoot[cchRoot] == '\0')
            return lpMount;
    }
    return NULL;
}

// ---------------------------------------------------------------------------
// Attempt WNet connection for a single mount entry.
// Logs the result.  Updates lpMount->lAvailable.
// ---------------------------------------------------------------------------
static BOOL NM_Connect(LPNETWORK_MOUNT lpMount)
{
    NETRESOURCE nr;
    DWORD       dwErr;
    char        szProvErr[256] = {0};
    DWORD       dwProvErrSize  = sizeof(szProvErr);
    DWORD       dwErrCode      = 0;

    ZeroMemory(&nr, sizeof(nr));
    nr.dwType      = RESOURCETYPE_DISK;
    nr.lpRemoteName = lpMount->szUncRoot;

    LPCSTR pszUser = lpMount->bHasCredentials
                     ? (lpMount->szUsername[0] ? lpMount->szUsername : NULL)
                     : NULL;
    LPCSTR pszPass = lpMount->bHasCredentials
                     ? lpMount->szPassword   // may be "" for explicit blank password
                     : NULL;

    dwErr = WNetAddConnection2A(&nr, pszPass, pszUser, 0);
    if (dwErr == NO_ERROR || dwErr == ERROR_ALREADY_ASSIGNED || dwErr == ERROR_SESSION_CREDENTIAL_CONFLICT)
    {
        InterlockedExchange(&lpMount->lAvailable, 1);
        InterlockedExchange(&lpMount->lFailCount, 0);
        Putlog(LOG_GENERAL, _T("Network mount connected: %hs\r\n"), lpMount->szUncRoot);
        return TRUE;
    }

    // Gather extra context from the provider
    WNetGetLastErrorA(&dwErrCode, szProvErr, sizeof(szProvErr) - 1, NULL, 0);

    InterlockedExchange(&lpMount->lAvailable, 0);

    // Translate common errors into actionable messages
    switch (dwErr)
    {
    case ERROR_BAD_NET_NAME:
        Putlog(LOG_ERROR, _T("Network mount: cannot find %hs — check server name and share path\r\n"),
               lpMount->szUncRoot);
        break;
    case ERROR_ACCESS_DENIED:
        Putlog(LOG_ERROR, _T("Network mount: access denied to %hs — check username and password in etc\\netmounts.cfg\r\n"),
               lpMount->szUncRoot);
        break;
    case ERROR_LOGON_FAILURE:
    case ERROR_INVALID_PASSWORD:
        Putlog(LOG_ERROR, _T("Network mount: login failed for %hs — incorrect username or password\r\n"),
               lpMount->szUncRoot);
        break;
    case ERROR_NETWORK_UNREACHABLE:
    case ERROR_HOST_UNREACHABLE:
        Putlog(LOG_ERROR, _T("Network mount: cannot reach %hs — check network connectivity\r\n"),
               lpMount->szUncRoot);
        break;
    case ERROR_NO_NETWORK:
    case ERROR_NO_NET_OR_BAD_PATH:
        Putlog(LOG_ERROR, _T("Network mount: no network available for %hs — service may have started before network\r\n"),
               lpMount->szUncRoot);
        break;
    case ERROR_UNEXP_NET_ERR:
    case ERROR_NOT_SUPPORTED:
        // Detect SMBv1 incompatibility
        {
            HKEY  hKey         = NULL;
            BOOL  bSmb1Disabled = TRUE;  // assume disabled if key absent
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                    "SYSTEM\\CurrentControlSet\\Services\\MrxSmb10",
                    0, KEY_READ, &hKey) == ERROR_SUCCESS)
            {
                DWORD dwStart = 0, dwSize = sizeof(DWORD);
                if (RegQueryValueExA(hKey, "Start", NULL, NULL,
                        (LPBYTE)&dwStart, &dwSize) == ERROR_SUCCESS)
                    bSmb1Disabled = (dwStart == 4);  // SERVICE_DISABLED
                else
                    bSmb1Disabled = FALSE;           // key exists, Start absent: SMBv1 likely enabled
                RegCloseKey(hKey);
            }
            if (bSmb1Disabled)
                Putlog(LOG_ERROR,
                       _T("Network mount: %hs requires SMBv1 which is disabled on this server. ")
                       _T("The remote device must support SMBv2 or later, or SMBv1 must be re-enabled ")
                       _T("via 'Turn Windows features on or off' (not recommended).\r\n"),
                       lpMount->szUncRoot);
            else
                Putlog(LOG_ERROR,
                       _T("Network mount: protocol error connecting to %hs — check server availability and SMB configuration\r\n"),
                       lpMount->szUncRoot);
        }
        break;
    default:
        Putlog(LOG_ERROR, _T("Network mount: %hs failed — error %lu%hs%hs\r\n"),
               lpMount->szUncRoot, dwErr,
               szProvErr[0] ? ": " : "",
               szProvErr[0] ? szProvErr : "");
        break;
    }

    // Hint for access-denied when no credentials are configured
    if ((dwErr == ERROR_ACCESS_DENIED || dwErr == ERROR_LOGON_FAILURE) && !lpMount->bHasCredentials)
    {
        Putlog(LOG_ERROR,
               _T("Network mount: no credentials configured for %hs. Add an entry to etc\\netmounts.cfg if this share requires a username and password.\r\n"),
               lpMount->szUncRoot);
    }

    return FALSE;
}

// ---------------------------------------------------------------------------
// Probe a share by calling GetFileAttributesA on the share root.
// Returns TRUE if the share root is accessible.
// ---------------------------------------------------------------------------
static BOOL NM_Probe(LPNETWORK_MOUNT lpMount)
{
    DWORD dw = GetFileAttributesA(lpMount->szUncRoot);
    if (dw != INVALID_FILE_ATTRIBUTES) return TRUE;
    return !IsNetworkError(GetLastError());  // non-network errors (e.g. permission) count as "up"
}

// ---------------------------------------------------------------------------
// Timer callback — runs on a job pool worker thread.
// Probes the share; if down, attempts reconnect.
// Returns next delay in ms.
// ---------------------------------------------------------------------------
DWORD __cdecl NetworkMount_Reconnect(LPVOID lpContext, LPTIMER lpTimer)
{
    LPNETWORK_MOUNT lpMount = (LPNETWORK_MOUNT)lpContext;

    if (InterlockedCompareExchange(&g_lShutdown, 0, 0) != 0)
        return INFINITE;  // shutting down — stop timer

    if (NM_Probe(lpMount))
    {
        if (InterlockedCompareExchange(&lpMount->lAvailable, 0, 0) == 0)
        {
            // Was down, now up
            InterlockedExchange(&lpMount->lAvailable, 1);
            InterlockedExchange(&lpMount->lFailCount, 0);
            Putlog(LOG_GENERAL, _T("Network mount back online: %hs\r\n"), lpMount->szUncRoot);
        }
        lpMount->dwTimerDelayMs = g_dwCheckMs;
        return g_dwCheckMs;
    }

    // Probe failed — attempt reconnect
    WNetCancelConnection2A(lpMount->szUncRoot, 0, TRUE);
    if (NM_Connect(lpMount))
    {
        // NM_Connect succeeded: lFailCount already reset to 0, success logged inside NM_Connect
        lpMount->dwTimerDelayMs = g_dwCheckMs;
        return g_dwCheckMs;
    }

    // Reconnect failed — exponential backoff
    LONG fails = InterlockedIncrement(&lpMount->lFailCount);
    DWORD dwDelay = NM_INITIAL_RETRY_MS;
    LONG  n;
    for (n = 1; n < fails && dwDelay < g_dwMaxRetryMs; n++)
        dwDelay = min(dwDelay * 2, g_dwMaxRetryMs);

    lpMount->dwTimerDelayMs = dwDelay;
    return dwDelay;
}

// ---------------------------------------------------------------------------
// Wake-all-down: reset all currently-down timers to a 1s delay so they
// retry on the next job queue cycle.  Called by the WatchThread on network
// address change.
// ---------------------------------------------------------------------------
static VOID NM_WakeAllDown(VOID)
{
    LPNETWORK_MOUNT lpMount;
    for (lpMount = g_lpMountList; lpMount; lpMount = lpMount->lpNext)
    {
        if (InterlockedCompareExchange(&lpMount->lAvailable, 0, 0) == 0 && lpMount->lpTimer)
        {
            // Restart the timer with a 1s delay
            lpMount->lpTimer = StartIoTimer(lpMount->lpTimer, NetworkMount_Reconnect, lpMount, 1000);
        }
    }
}

// ---------------------------------------------------------------------------
// Watch thread — blocks on NotifyAddrChange (network interface state change).
// When a NIC comes back online, immediately retries all down mounts.
// ---------------------------------------------------------------------------
static DWORD WINAPI NM_WatchThread(LPVOID lpParam)
{
    HANDLE    hAddrChange = NULL;
    OVERLAPPED ov;
    HANDLE    hWait[2];

    ZeroMemory(&ov, sizeof(ov));
    ov.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!ov.hEvent) return 1;

    hWait[0] = ov.hEvent;
    hWait[1] = g_hWatchStop;

    for (;;)
    {
        // Register for the next address change notification
        if (NotifyAddrChange(&hAddrChange, &ov) != ERROR_IO_PENDING)
        {
            // Failure is non-fatal — network stack may not be ready at service startup.
            // Wait 30s then retry; exit only if the stop event fires.
            Putlog(LOG_DEBUG,
                   _T("Network mount: NotifyAddrChange failed (error %lu) — retrying in 30s\r\n"),
                   GetLastError());
            hAddrChange = NULL;
            ZeroMemory(&ov, sizeof(ov));
            ov.hEvent = hWait[0];  // restore event handle after ZeroMemory
            if (WaitForSingleObject(g_hWatchStop, 30000) != WAIT_TIMEOUT) break;
            continue;
        }

        DWORD dw = WaitForMultipleObjects(2, hWait, FALSE, INFINITE);
        if (dw == WAIT_OBJECT_0 + 1) break;  // stop event signalled
        if (dw != WAIT_OBJECT_0)      break;  // unexpected

        if (InterlockedCompareExchange(&g_lShutdown, 0, 0) != 0) break;

        // Network interface changed — immediately retry all down mounts
        NM_WakeAllDown();
    }

    if (hAddrChange) CloseHandle(hAddrChange);
    CloseHandle(ov.hEvent);
    return 0;
}

// ---------------------------------------------------------------------------
// Register a UNC root for health monitoring.  Idempotent.
// Called from MountFile_Parse whenever a UNC real path is encountered.
// ---------------------------------------------------------------------------
VOID NetworkMount_Register(LPCSTR szPath)
{
    LPNETWORK_MOUNT lpMount, lpTail;
    char            szRoot[NETMOUNT_UNC_MAX];
    DWORD           dwDelay;

    if (!g_bInitialized) return;
    if (!szPath || (szPath[0] != '\\' && szPath[0] != '/')) return;

    if (!NM_ExtractRoot(szPath, szRoot, sizeof(szRoot))) return;

    EnterCriticalSection(&g_csMountList);

    // Check if already registered
    for (lpMount = g_lpMountList, lpTail = NULL;
         lpMount;
         lpTail = lpMount, lpMount = lpMount->lpNext)
    {
        if (_stricmp(lpMount->szUncRoot, szRoot) == 0)
        {
            // Already exists — no action needed
            LeaveCriticalSection(&g_csMountList);
            return;
        }
    }

    // Allocate new entry
    lpMount = (LPNETWORK_MOUNT)Allocate("NetworkMount", sizeof(NETWORK_MOUNT));
    if (!lpMount)
    {
        LeaveCriticalSection(&g_csMountList);
        return;
    }
    ZeroMemory(lpMount, sizeof(NETWORK_MOUNT));
    strcpy_s(lpMount->szUncRoot, sizeof(lpMount->szUncRoot), szRoot);
    lpMount->lAvailable = 1;  // optimistically assume up until first probe
    lpMount->dwTimerDelayMs = g_dwCheckMs;

    // Append to list
    if (lpTail) lpTail->lpNext = lpMount;
    else        g_lpMountList  = lpMount;

    // Stagger initial probe time (2.5s apart per share)
    dwDelay = (DWORD)InterlockedExchangeAdd(&g_lStaggerMs, 2500);
    if (dwDelay == 0) dwDelay = 2500;  // first share probes at 2.5s, same cadence as the rest

    lpMount->lpTimer = StartIoTimer(NULL, NetworkMount_Reconnect, lpMount, dwDelay);

    LeaveCriticalSection(&g_csMountList);
}

// ---------------------------------------------------------------------------
// Mark a share as potentially down and accelerate its reconnect timer.
// Called from IoCreateFile on network error.
// ---------------------------------------------------------------------------
VOID NetworkMount_MarkDown(LPCSTR szPath)
{
    LPNETWORK_MOUNT lpMount = NetworkMount_Find(szPath);
    if (!lpMount) return;

    if (InterlockedExchange(&lpMount->lAvailable, 0) == 1)
    {
        // Was up — log the event
        Putlog(LOG_ERROR, _T("Network mount offline: %hs\r\n"), lpMount->szUncRoot);
    }

    // Wake the timer for a fast retry (1s)
    if (lpMount->lpTimer)
        lpMount->lpTimer = StartIoTimer(lpMount->lpTimer, NetworkMount_Reconnect, lpMount, 1000);
}

// ---------------------------------------------------------------------------
// Inline reconnect for IoCreateFile — only for ERROR_NETNAME_DELETED (connection
// dropped but server likely still reachable).  One synchronous attempt; returns
// a valid handle on success, INVALID_HANDLE_VALUE (SetLastError preserved) on failure.
// ---------------------------------------------------------------------------
HANDLE NetworkMount_TryReconnect(LPCSTR lpFileName,
                                  DWORD dwDesiredAccess, DWORD dwShareMode,
                                  LPSECURITY_ATTRIBUTES lpSA,
                                  DWORD dwCreationDisposition,
                                  DWORD dwFlagsAndAttributes,
                                  HANDLE hTemplateFile,
                                  DWORD dwOriginalError)
{
    LPNETWORK_MOUNT lpMount;
    NETRESOURCE     nr;
    HANDLE          hFile;
    LPCSTR          pszUser, pszPass;

    // Only attempt inline reconnect for "connection dropped" — server likely reachable
    if (dwOriginalError != ERROR_NETNAME_DELETED)
    {
        NetworkMount_MarkDown(lpFileName);
        SetLastError(dwOriginalError);
        return INVALID_HANDLE_VALUE;
    }

    lpMount = NetworkMount_Find(lpFileName);
    if (!lpMount)
    {
        SetLastError(dwOriginalError);
        return INVALID_HANDLE_VALUE;
    }

    // Attempt reconnect
    WNetCancelConnection2A(lpMount->szUncRoot, 0, TRUE);

    ZeroMemory(&nr, sizeof(nr));
    nr.dwType       = RESOURCETYPE_DISK;
    nr.lpRemoteName = lpMount->szUncRoot;

    pszUser = lpMount->bHasCredentials
              ? (lpMount->szUsername[0] ? lpMount->szUsername : NULL)
              : NULL;
    pszPass = lpMount->bHasCredentials ? lpMount->szPassword : NULL;

    {
        DWORD dwWnet = WNetAddConnection2A(&nr, pszPass, pszUser, 0);
        if (dwWnet == NO_ERROR ||
            dwWnet == ERROR_ALREADY_ASSIGNED ||
            dwWnet == ERROR_SESSION_CREDENTIAL_CONFLICT)
        {
            InterlockedExchange(&lpMount->lAvailable, 1);
            InterlockedExchange(&lpMount->lFailCount, 0);

            // Retry the file operation — use IoCreateFile so long paths get the \\?\ fallback
            hFile = IoCreateFile(lpFileName, dwDesiredAccess, dwShareMode,
                                 lpSA, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
            if (hFile != INVALID_HANDLE_VALUE) return hFile;
        }
    }

    NetworkMount_MarkDown(lpFileName);
    SetLastError(dwOriginalError);
    return INVALID_HANDLE_VALUE;
}

// ---------------------------------------------------------------------------
// Parse etc\netmounts.cfg.
// Format per line:  <UNC_root>  [username]  [password]  [domain]
// Fields may be quoted with "" to include spaces.  "" = empty string.
// ---------------------------------------------------------------------------
static VOID NM_ParseCredFile(LPCSTR szFilePath)
{
    HANDLE hFile;
    DWORD  dwSize, dwRead;
    char  *pBuf, *pLine, *pEnd, *pNewline;
    char   szRoot[NETMOUNT_UNC_MAX];
    char   szUser[NETMOUNT_USER_MAX];
    char   szPass[NETMOUNT_PASS_MAX];
    char   szDom[NETMOUNT_DOM_MAX];
    DWORD  dwLine = 0;

    hFile = CreateFileA(szFilePath, GENERIC_READ, FILE_SHARE_READ,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    dwSize = GetFileSize(hFile, NULL);
    if (dwSize == INVALID_FILE_SIZE || dwSize == 0) { CloseHandle(hFile); return; }

    pBuf = (char *)Allocate("NetMountCfg", dwSize + 2);
    if (!pBuf) { CloseHandle(hFile); return; }

    if (!ReadFile(hFile, pBuf, dwSize, &dwRead, NULL)) { Free(pBuf); CloseHandle(hFile); return; }
    CloseHandle(hFile);

    pBuf[dwRead]     = '\n';
    pBuf[dwRead + 1] = '\0';
    pEnd = pBuf + dwRead + 1;

    for (pLine = pBuf; pLine < pEnd; pLine = pNewline + 1)
    {
        pNewline = (char *)memchr(pLine, '\n', pEnd - pLine);
        if (!pNewline) pNewline = pEnd - 1;

        dwLine++;
        *pNewline = '\0';

        // Strip \r and trailing whitespace
        char *pTail = pNewline - 1;
        while (pTail >= pLine && isspace((unsigned char)*pTail)) *pTail-- = '\0';

        // Skip leading whitespace
        while (*pLine == ' ' || *pLine == '\t') pLine++;

        // Skip blank lines and comments
        if (*pLine == '\0' || *pLine == '#') continue;

        // -- Parse UNC root field (first field) --
        szRoot[0] = szUser[0] = szPass[0] = szDom[0] = '\0';

        char *pField = pLine;

        // Helper lambda (inline) to extract one field into dst (max cchDst chars incl. NUL)
        // Returns pointer to first char after the field, or NULL on parse error.
        // Sets *pbHadQuotes = TRUE if the field was "..."
#define NM_READ_FIELD(src, dst, cchDst, pbHadQuotes) \
        do { \
            char *_s = (src); \
            while (*_s == ' ' || *_s == '\t') _s++; \
            if (*_s == '"') { \
                *(pbHadQuotes) = TRUE; \
                _s++; \
                char *_e = strchr(_s, '"'); \
                if (!_e) { pField = NULL; break; } \
                DWORD _n = (DWORD)(_e - _s); \
                if (_n >= (cchDst)) _n = (cchDst) - 1; \
                strncpy_s((dst), (cchDst), _s, _n); \
                (src) = _e + 1; \
            } else { \
                *(pbHadQuotes) = FALSE; \
                char *_e = _s; \
                while (*_e && *_e != ' ' && *_e != '\t') _e++; \
                DWORD _n = (DWORD)(_e - _s); \
                if (_n >= (cchDst)) _n = (cchDst) - 1; \
                strncpy_s((dst), (cchDst), _s, _n); \
                (src) = _e; \
            } \
        } while (0)

        BOOL bQ;
        NM_READ_FIELD(pField, szRoot, sizeof(szRoot), &bQ);
        if (!pField || szRoot[0] == '\0') continue;

        // Normalise the UNC root
        char szNormRoot[NETMOUNT_UNC_MAX];
        if (!NM_NormaliseRoot(szRoot, szNormRoot, sizeof(szNormRoot)))
        {
            Putlog(LOG_ERROR, _T("netmounts.cfg line %lu: invalid UNC path '%hs' — must be \\\\server\\share\r\n"),
                   dwLine, szRoot);
            continue;
        }

        // Optional: username
        BOOL bHasUser = FALSE, bHasPass = FALSE;
        while (*pField == ' ' || *pField == '\t') pField++;
        if (*pField && *pField != '#')
        {
            BOOL bQu;
            NM_READ_FIELD(pField, szUser, sizeof(szUser), &bQu);
            if (!pField)
            {
                Putlog(LOG_ERROR, _T("netmounts.cfg line %lu: unclosed quote in username field — skipping\r\n"), dwLine);
                continue;
            }
            bHasUser = TRUE;
        }

        // Optional: password
        while (*pField == ' ' || *pField == '\t') pField++;
        if (bHasUser && *pField && *pField != '#')
        {
            BOOL bQp;
            NM_READ_FIELD(pField, szPass, sizeof(szPass), &bQp);
            if (!pField)
            {
                Putlog(LOG_ERROR, _T("netmounts.cfg line %lu: unclosed quote in password field — skipping\r\n"), dwLine);
                continue;
            }
            bHasPass = TRUE;
        }

        // Optional: domain
        while (*pField == ' ' || *pField == '\t') pField++;
        if (bHasPass && *pField && *pField != '#')
        {
            BOOL bQd;
            NM_READ_FIELD(pField, szDom, sizeof(szDom), &bQd);
            if (!pField)
            {
                Putlog(LOG_ERROR, _T("netmounts.cfg line %lu: unclosed quote in domain field — skipping\r\n"), dwLine);
                continue;
            }
        }

#undef NM_READ_FIELD

        // Check if already in the list (may have been auto-registered from .vfs)
        LPNETWORK_MOUNT lpMount = NULL, lpTail = NULL;
        EnterCriticalSection(&g_csMountList);
        {
            LPNETWORK_MOUNT lp;
            for (lp = g_lpMountList; lp; lpTail = lp, lp = lp->lpNext)
            {
                if (_stricmp(lp->szUncRoot, szNormRoot) == 0) { lpMount = lp; break; }
            }
        }
        if (lpMount)
        {
            // Update credentials on existing entry
            strcpy_s(lpMount->szUsername, sizeof(lpMount->szUsername), szUser);
            strcpy_s(lpMount->szPassword, sizeof(lpMount->szPassword), szPass);
            strcpy_s(lpMount->szDomain,   sizeof(lpMount->szDomain),   szDom);
            lpMount->bHasCredentials = bHasUser;
            LeaveCriticalSection(&g_csMountList);
        }
        else
        {
            // New entry — create it
            lpMount = (LPNETWORK_MOUNT)Allocate("NetworkMount:Cred", sizeof(NETWORK_MOUNT));
            if (!lpMount) { LeaveCriticalSection(&g_csMountList); continue; }
            ZeroMemory(lpMount, sizeof(NETWORK_MOUNT));
            strcpy_s(lpMount->szUncRoot,  sizeof(lpMount->szUncRoot),  szNormRoot);
            strcpy_s(lpMount->szUsername, sizeof(lpMount->szUsername), szUser);
            strcpy_s(lpMount->szPassword, sizeof(lpMount->szPassword), szPass);
            strcpy_s(lpMount->szDomain,   sizeof(lpMount->szDomain),   szDom);
            lpMount->bHasCredentials  = bHasUser;
            lpMount->lAvailable       = 1;
            lpMount->dwTimerDelayMs   = g_dwCheckMs;
            if (lpTail) lpTail->lpNext = lpMount;
            else        g_lpMountList  = lpMount;
            LeaveCriticalSection(&g_csMountList);

            // Stagger timer start
            DWORD dwDelay = (DWORD)InterlockedExchangeAdd(&g_lStaggerMs, 2500);
            if (dwDelay == 0) dwDelay = g_dwCheckMs;
            lpMount->lpTimer = StartIoTimer(NULL, NetworkMount_Reconnect, lpMount, dwDelay);
        }

        // Attempt initial connection immediately for credentialed entries
        if (bHasUser)
            NM_Connect(lpMount);
    }

    // Zero the password memory before freeing
    SecureZeroMemory(pBuf, dwRead);
    Free(pBuf);
}

// ---------------------------------------------------------------------------
// Resolve the credential file path from config and call NM_ParseCredFile.
// Shared by first-init and rehash paths.
// ---------------------------------------------------------------------------
static VOID NM_LoadCredFile(VOID)
{
    TCHAR  tszCfgPath[_MAX_LONG_PATH + 1];
    TCHAR  tszExeDir[MAX_PATH];
    LPTSTR tszFile;

    tszFile = Config_Get(&IniConfigFile, _T("Ftp"), _T("Network_Mounts_File"), NULL, NULL);
    if (!tszFile) return;

    // Relative paths are resolved from the exe directory
    if (tszFile[0] != '\\' && tszFile[1] != ':')
    {
        GetModuleFileName(NULL, tszExeDir, MAX_PATH);
        LPTSTR pSlash = _tcsrchr(tszExeDir, '\\');
        if (pSlash) *(pSlash + 1) = '\0';
        _sntprintf_s(tszCfgPath, _countof(tszCfgPath), _TRUNCATE, _T("%s%s"), tszExeDir, tszFile);
    }
    else
    {
        _tcsncpy_s(tszCfgPath, _countof(tszCfgPath), tszFile, _TRUNCATE);
    }
    Free(tszFile);

#ifdef _UNICODE
    char szCfgA[_MAX_LONG_PATH + 1];
    WideCharToMultiByte(CP_ACP, 0, tszCfgPath, -1, szCfgA, sizeof(szCfgA), NULL, NULL);
    NM_ParseCredFile(szCfgA);
#else
    NM_ParseCredFile(tszCfgPath);
#endif
}

// ---------------------------------------------------------------------------
// Init / DeInit
// ---------------------------------------------------------------------------
BOOL NetworkMount_Init(BOOL bFirstInitialization)
{
    int iVal;

    if (!bFirstInitialization)
    {
        if (!g_bInitialized) return TRUE;

        // Re-read interval config (changes take effect on next timer reschedule)
        iVal = 60;
        Config_Get_Int(&IniConfigFile, _T("Ftp"), _T("Network_Check_Interval"), &iVal);
        if (iVal < 5) iVal = 5;
        g_dwCheckMs = (DWORD)iVal * 1000;

        iVal = 300;
        Config_Get_Int(&IniConfigFile, _T("Ftp"), _T("Network_Max_Retry_Interval"), &iVal);
        if (iVal < 10) iVal = 10;
        g_dwMaxRetryMs = (DWORD)iVal * 1000;

        // Re-parse credential file: updates credentials on existing entries,
        // adds entries for any new UNC shares, and retries credentialed connects
        NM_LoadCredFile();
        Putlog(LOG_GENERAL, _T("Network mount: credential file reloaded\r\n"));
        return TRUE;
    }

    if (!InitializeCriticalSectionAndSpinCount(&g_csMountList, 1000)) return FALSE;

    g_bInitialized = TRUE;
    g_lShutdown    = 0;

    // Read config
    iVal = 60;
    Config_Get_Int(&IniConfigFile, _T("Ftp"), _T("Network_Check_Interval"), &iVal);
    if (iVal < 5) iVal = 5;
    g_dwCheckMs = (DWORD)iVal * 1000;

    iVal = 300;
    Config_Get_Int(&IniConfigFile, _T("Ftp"), _T("Network_Max_Retry_Interval"), &iVal);
    if (iVal < 10) iVal = 10;
    g_dwMaxRetryMs = (DWORD)iVal * 1000;

    NM_LoadCredFile();

    // Start the NotifyAddrChange watch thread
    g_hWatchStop = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_hWatchStop)
    {
        g_hWatchThread = CreateThread(NULL, 64 * 1024, NM_WatchThread, NULL, 0, NULL);
        if (g_hWatchThread)
            SetThreadPriority(g_hWatchThread, THREAD_PRIORITY_BELOW_NORMAL);
    }

    return TRUE;
}

VOID NetworkMount_DeInit(VOID)
{
    LPNETWORK_MOUNT lpMount, lpNext;

    if (!g_bInitialized) return;

    // Signal shutdown
    InterlockedExchange(&g_lShutdown, 1);

    // Stop the watch thread
    if (g_hWatchStop)  SetEvent(g_hWatchStop);
    if (g_hWatchThread)
    {
        WaitForSingleObject(g_hWatchThread, 3000);
        CloseHandle(g_hWatchThread);
        g_hWatchThread = NULL;
    }
    if (g_hWatchStop) { CloseHandle(g_hWatchStop); g_hWatchStop = NULL; }

    // Stop all timers and disconnect all shares
    EnterCriticalSection(&g_csMountList);
    for (lpMount = g_lpMountList; lpMount; lpMount = lpMount->lpNext)
    {
        if (lpMount->lpTimer) StopIoTimer(lpMount->lpTimer, FALSE);
        lpMount->lpTimer = NULL;
        WNetCancelConnection2A(lpMount->szUncRoot, 0, TRUE);
    }
    LeaveCriticalSection(&g_csMountList);

    // StopIoTimer(lpTimer, FALSE) above spins until any in-flight callback returns,
    // so no additional sleep is needed before freeing mount entries.

    // Free all entries
    EnterCriticalSection(&g_csMountList);
    for (lpMount = g_lpMountList; lpMount; lpMount = lpNext)
    {
        lpNext = lpMount->lpNext;
        SecureZeroMemory(lpMount->szPassword, sizeof(lpMount->szPassword));
        Free(lpMount);
    }
    g_lpMountList = NULL;
    LeaveCriticalSection(&g_csMountList);

    DeleteCriticalSection(&g_csMountList);
    g_bInitialized = FALSE;
}
