/*
 * sitewho_x64.cpp — DataCopy IPC sample for ioFTPD v8.0+ (x64 build)
 *
 * Demonstrates how a 64-bit client enumerates online users via the
 * DataCopy shared-memory IPC channel using the DC_MESSAGE_WIRE v2 protocol.
 *
 * v8.0.0 ships both an x64 and a Win32 build; this sample targets the x64
 * build, which is the primary release.  The Win32 v8 build also uses
 * DC_MESSAGE_WIRE, but accepts 32-bit senders — compile this sample as x86
 * and point it at the Win32 ioFTPD if needed.
 *
 * TARGET: ioFTPD v8.0+ x64 (primary).  Also compatible with v8.0+ Win32
 *         when compiled as x86.
 *   - Uses DC_MESSAGE_WIRE v2 (fixed 24-byte header, no pointer fields).
 *   - ioFTPD v8.x x64 rejects 32-bit (WoW64) senders; tool MUST be
 *     compiled as x64 when targeting the x64 ioFTPD build.
 *   - For ioFTPD v7.x legacy deployments, see sitewho_x86.cpp.
 *
 * PROTOCOL OVERVIEW
 *   Shared-memory layout (one contiguous CreateFileMapping region):
 *
 *     Offset 0                        : DC_MESSAGE_WIRE  (24 bytes, fixed)
 *     Offset sizeof(DC_MESSAGE_WIRE)  : DC_ONLINEDATA    (context struct)
 *     Offset sizeof(DC_MESSAGE_WIRE)
 *         + sizeof(DC_ONLINEDATA)     : real-path chars  (dwRealPathLen TCHARs)
 *                                       real-data-path chars follow immediately
 *
 *   The context offset (qwContextOffset = 24) tells ioFTPD where DC_ONLINEDATA
 *   begins within the mapping.  On each WM_SHMEM the server writes the next
 *   user's ONLINEDATA_WIRE into the context slot and appends path strings
 *   directly after it, then signals dwEventHandle.
 *
 * COMPILE: cl /W4 /Zi sitewho_x64.cpp
 *   Requires: link against user32.lib
 *
 * Copyright (c) ioFTPD Project. Distributed under GPL v2.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>

/* -------------------------------------------------------------------------
 * Protocol constants
 * ---------------------------------------------------------------------- */
#define WM_SHMEM            (WM_USER + 101)
#define WM_DATACOPY_FREE    (WM_USER + 20)
#define WM_DATACOPY_FILEMAP (WM_USER + 21)

#define DC_GET_ONLINEDATA   13

#define DC_MESSAGE_VERSION  2   /* dwVersion field must equal this */


/* -------------------------------------------------------------------------
 * DC_MESSAGE_WIRE — v8 wire header, 24 bytes on all architectures.
 *
 * Placed at offset 0 of the shared-memory mapping.  All fields are
 * fixed-width integers — no handles or pointers — so the layout is
 * identical whether read by a 32-bit or 64-bit process.
 * ---------------------------------------------------------------------- */
#pragma pack(push, 1)
typedef struct _DC_MESSAGE_WIRE
{
    uint32_t    dwVersion;       /* Must be DC_MESSAGE_VERSION (2) */
    uint32_t    dwIdentifier;    /* Command ID — set before each WM_SHMEM post */
    uint32_t    dwReturn;        /* Result written by ioFTPD on completion:
                                      0          = success, data ready
                                      (DWORD)-1  = end of list / fatal error
                                      other      = required buffer bytes (buffer too small) */
    uint32_t    dwEventHandle;   /* The local auto-reset event handle stored as a
                                    raw 32-bit kernel index (HANDLE is always ≤ 32 bits
                                    on Windows).  ioFTPD signals this when done. */
    uint64_t    qwContextOffset; /* Byte offset from start of mapped view to context data.
                                    Set to sizeof(DC_MESSAGE_WIRE) = 24 so the context
                                    (DC_ONLINEDATA) immediately follows the header. */
} DC_MESSAGE_WIRE, *LPDC_MESSAGE_WIRE;
#pragma pack(pop)

static_assert(sizeof(DC_MESSAGE_WIRE) == 24, "DC_MESSAGE_WIRE must be exactly 24 bytes");


/* -------------------------------------------------------------------------
 * ONLINEDATA_WIRE — cross-process online-data record.
 *
 * Replaces the legacy ONLINEDATA struct's two LPTSTR pointer fields with
 * UINT32 character counts.  The actual path strings are appended as
 * null-terminated TCHAR arrays immediately after the DC_ONLINEDATA struct.
 *
 * Layout after the DC_ONLINEDATA struct in shared memory:
 *   [dwRealPathLen TCHARs for real path]
 *   [dwRealDataPathLen TCHARs for real data path]
 *
 * Access helpers (assuming lpBase = start of mapping, ioFTPD is ANSI/CHAR):
 *   LPDC_ONLINEDATA lpOD = (LPDC_ONLINEDATA)((BYTE*)lpBase + sizeof(DC_MESSAGE_WIRE));
 *   const char *pRealPath     = (const char *)(&lpOD[1]);
 *   const char *pRealDataPath = pRealPath + lpOD->OnlineData.dwRealPathLen;
 *
 * If you have the v8 ioFTPD headers, #include <WinMessages.h> instead.
 * ---------------------------------------------------------------------- */
#define _MAX_NAME       31
#define _MAX_PWD        259
#define MAX_HOSTNAME    64
#define MAX_IDENT       20

typedef struct _ONLINEDATA_WIRE
{
    int32_t     Uid;
    uint32_t    dwFlags;
    char        tszServiceName[_MAX_NAME + 1];
    char        tszAction[64];
    uint32_t    ulClientIp;
    uint16_t    usClientPort;
    char        szHostName[MAX_HOSTNAME];
    char        szIdent[MAX_IDENT];
    char        tszVirtualPath[_MAX_PWD + 1];
    uint32_t    dwRealPathLen;          /* Char count of real-path string appended after struct */
    uint32_t    dwOnlineTime;
    uint32_t    dwIdleTickCount;
    uint8_t     bTransferStatus;        /* 0=idle 1=upload 2=download 3=list */
    uint16_t    usDeviceNum;
    uint32_t    ulDataClientIp;
    uint16_t    usDataClientPort;
    char        tszVirtualDataPath[_MAX_PWD + 1];
    uint32_t    dwRealDataPathLen;      /* Char count of real-data-path string appended after real path */
    uint64_t    qwBytesTransfered;      /* Bytes transferred in current interval (no 4 GB cap) */
    uint32_t    dwIntervalLength;
    int64_t     i64TotalBytesTransfered;
} ONLINEDATA_WIRE, *PONLINEDATA_WIRE;

/* If your build has the v8 headers, verify the size matches the server's assertion: */
/* static_assert(sizeof(ONLINEDATA_WIRE) == 1384, "ONLINEDATA_WIRE size mismatch"); */


/* DC_ONLINEDATA — context struct placed at qwContextOffset in the mapping */
typedef struct _DC_ONLINEDATA
{
    ONLINEDATA_WIRE OnlineData;         /* ioFTPD fills this on each reply */
    int             iOffset;            /* Client sets to 0; ioFTPD advances per user */
    uint32_t        dwSharedMemorySize; /* Total mapped bytes (including DC_MESSAGE_WIRE header) */
} DC_ONLINEDATA, *LPDC_ONLINEDATA;


/* -------------------------------------------------------------------------
 * Allocation tracking
 * ---------------------------------------------------------------------- */
#define CONTEXT_OFFSET  ((uint64_t)sizeof(DC_MESSAGE_WIRE))   /* = 24 */

typedef struct _ALLOCATION
{
    LPDC_MESSAGE_WIRE   lpMessage;  /* Start of mapped view (= DC_MESSAGE_WIRE) */
    LPDC_ONLINEDATA     lpContext;  /* = lpMessage + CONTEXT_OFFSET = DC_ONLINEDATA */
    HANDLE              hObject;    /* File-mapping kernel object */
    HANDLE              hEvent;     /* Local auto-reset event */
    LRESULT             hRemote;    /* Opaque cookie returned by WM_DATACOPY_FILEMAP */
    DWORD               dwMapSize;  /* Total bytes in the mapping */
} ALLOCATION, *LPALLOCATION;


/* -------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------- */
static HWND
GetDaemonWindow(void)
{
    return FindWindowA("ioFTPD::MessageWindow", NULL);
}


static LPALLOCATION
SharedAllocate(HWND hDaemon, DWORD dwContextBytes)
{
    LPALLOCATION        lpAlloc;
    LPDC_MESSAGE_WIRE   lpMessage;
    HANDLE              hObject = NULL, hEvent = NULL;
    DWORD               dwMapSize;
    LRESULT             hRemote;

    /* Total mapping = wire header + context data */
    dwMapSize = (DWORD)(CONTEXT_OFFSET + dwContextBytes);

    hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (!hEvent) return NULL;

    lpAlloc = (LPALLOCATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ALLOCATION));
    if (!lpAlloc) { CloseHandle(hEvent); return NULL; }

    hObject = CreateFileMapping(INVALID_HANDLE_VALUE, NULL,
                                PAGE_READWRITE | SEC_COMMIT, 0, dwMapSize, NULL);
    if (!hObject) goto fail;

    lpMessage = (LPDC_MESSAGE_WIRE)MapViewOfFile(hObject, FILE_MAP_ALL_ACCESS, 0, 0, dwMapSize);
    if (!lpMessage) goto fail;

    /* Initialise DC_MESSAGE_WIRE header.
     * dwEventHandle stores the raw handle value; on Windows, HANDLE kernel
     * indices always fit in 32 bits even on x64.                           */
    lpMessage->dwVersion       = DC_MESSAGE_VERSION;
    lpMessage->dwIdentifier    = 0;
    lpMessage->dwReturn        = 0;
    lpMessage->dwEventHandle   = (uint32_t)(uintptr_t)hEvent;
    lpMessage->qwContextOffset = CONTEXT_OFFSET;

    /* Register the mapping with ioFTPD; it returns an opaque remote cookie.
     * SendMessage blocks until ioFTPD has mapped the region.               */
    SetLastError(0);
    hRemote = SendMessage(hDaemon, WM_DATACOPY_FILEMAP,
                          (WPARAM)GetCurrentProcessId(), (LPARAM)hObject);
    if (!hRemote || GetLastError() != NO_ERROR)
    {
        UnmapViewOfFile(lpMessage);
        goto fail;
    }

    lpAlloc->lpMessage  = lpMessage;
    lpAlloc->lpContext  = (LPDC_ONLINEDATA)((BYTE*)lpMessage + CONTEXT_OFFSET);
    lpAlloc->hObject    = hObject;
    lpAlloc->hEvent     = hEvent;
    lpAlloc->hRemote    = hRemote;
    lpAlloc->dwMapSize  = dwMapSize;
    return lpAlloc;

fail:
    if (hObject) CloseHandle(hObject);
    CloseHandle(hEvent);
    HeapFree(GetProcessHeap(), 0, lpAlloc);
    return NULL;
}


static void
SharedFree(HWND hDaemon, LPALLOCATION lpAlloc)
{
    /* Tell ioFTPD to release its internal EXCHANGE_REQUEST */
    SendMessage(hDaemon, WM_DATACOPY_FREE, 0, (LPARAM)lpAlloc->hRemote);
    UnmapViewOfFile(lpAlloc->lpMessage);
    CloseHandle(lpAlloc->hObject);
    CloseHandle(lpAlloc->hEvent);
    HeapFree(GetProcessHeap(), 0, lpAlloc);
}


/* Post one DC_GET_ONLINEDATA request and wait for the reply.
 * Returns: 0=success, (DWORD)-1=end/error, other=required buffer bytes. */
static DWORD
QueryOnlineData(HWND hDaemon, LPALLOCATION lpAlloc, DWORD dwTimeoutMs)
{
    lpAlloc->lpMessage->dwIdentifier = DC_GET_ONLINEDATA;
    PostMessage(hDaemon, WM_SHMEM, 0, (LPARAM)lpAlloc->hRemote);
    if (WaitForSingleObject(lpAlloc->hEvent, dwTimeoutMs) == WAIT_TIMEOUT)
        return (DWORD)-1;
    return lpAlloc->lpMessage->dwReturn;
}


/* -------------------------------------------------------------------------
 * main
 * ---------------------------------------------------------------------- */
int main(void)
{
    HWND            hDaemon;
    LPALLOCATION    lpAlloc;
    LPDC_ONLINEDATA lpOD;
    DWORD           dwResult, dwUsers = 0;

    hDaemon = GetDaemonWindow();
    if (!hDaemon)
    {
        fprintf(stderr, "ioFTPD message window not found — is the server running?\n");
        return 1;
    }

    /* Allocate shared memory: DC_MESSAGE_WIRE header + DC_ONLINEDATA context
     * + space for two real-path strings (each up to _MAX_PWD characters).  */
    lpAlloc = SharedAllocate(hDaemon,
                             sizeof(DC_ONLINEDATA) + (_MAX_PWD + 1) * 2 * sizeof(char));
    if (!lpAlloc)
    {
        fprintf(stderr, "SharedAllocate failed (error %lu)\n", GetLastError());
        return 1;
    }

    lpOD = lpAlloc->lpContext;
    lpOD->iOffset            = 0;
    lpOD->dwSharedMemorySize = lpAlloc->dwMapSize;

    printf("%-4s  %-20s  %-4s  %-30s  %s\n",
           "UID", "Action", "St", "Virtual path", "Real path");
    printf("%-4s  %-20s  %-4s  %-30s  %s\n",
           "---", "------", "--", "------------", "---------");

    for (;;)
    {
        dwResult = QueryOnlineData(hDaemon, lpAlloc, 5000);

        if (dwResult == (DWORD)-1)
            break;  /* End of list or timeout */

        if (dwResult != 0)
        {
            /* Buffer too small — ioFTPD holds iOffset on the same entry for
             * a retry.  For simplicity this sample does not reallocate.    */
            fprintf(stderr, "Buffer too small for this entry (need %lu bytes)\n", dwResult);
            /* Force past this entry to avoid an infinite retry loop */
            lpOD->iOffset++;
            continue;
        }

        /* dwResult == 0: ONLINEDATA_WIRE is ready in lpOD->OnlineData.
         *
         * String data layout immediately after DC_ONLINEDATA:
         *   [dwRealPathLen chars = real path, not null-terminated by ioFTPD]
         *   [dwRealDataPathLen chars = real data path]
         *
         * The path arrays are written without a null terminator; index by
         * char count.  We copy to a local buffer and add '\0' ourselves.   */
        ONLINEDATA_WIRE *pOD = &lpOD->OnlineData;
        const char *pStrBase    = (const char *)(&lpAlloc->lpContext[1]);
        const char *pRealPath   = pStrBase;
        const char *pRealDataPath = pStrBase + pOD->dwRealPathLen;

        /* Copy to null-terminated local buffers */
        char szRealPath[_MAX_PWD + 1]     = {0};
        char szRealDataPath[_MAX_PWD + 1] = {0};
        if (pOD->dwRealPathLen > 0)
        {
            size_t n = min((size_t)pOD->dwRealPathLen, (size_t)_MAX_PWD);
            memcpy(szRealPath, pRealPath, n);
        }
        if (pOD->dwRealDataPathLen > 0)
        {
            size_t n = min((size_t)pOD->dwRealDataPathLen, (size_t)_MAX_PWD);
            memcpy(szRealDataPath, pRealDataPath, n);
        }

        static const char *xferStatus[] = {"idle", "up  ", "down", "list"};
        printf("%-4d  %-20s  %-4s  %-30s  %s\n",
               pOD->Uid,
               pOD->tszAction,
               (pOD->bTransferStatus < 4) ? xferStatus[pOD->bTransferStatus] : "?",
               pOD->tszVirtualPath,
               szRealPath[0] ? szRealPath : "(none)");
        dwUsers++;
    }

    printf("\n%lu user(s) online.\n", dwUsers);

    SharedFree(hDaemon, lpAlloc);
    return 0;
}
