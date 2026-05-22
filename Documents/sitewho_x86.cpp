/*
 * sitewho_x86.cpp — DataCopy IPC sample for ioFTPD v7.x (Win32 build)
 *                    HISTORICAL REFERENCE ONLY
 *
 * Demonstrates how a 32-bit client enumerates online users via the legacy
 * DC_MESSAGE-based DataCopy IPC used by ioFTPD v7.x and earlier.
 *
 * This sample is provided as a reference for anyone still running the last
 * v7.x release.  v8.0.0 is the sole active release line; new deployments
 * should use ioFTPD v8.0+ and the DC_MESSAGE_WIRE v2 protocol instead
 * (see sitewho_x64.cpp).
 *
 * TARGET: ioFTPD v7.x Win32 (32-bit) only.
 *   - Uses DC_MESSAGE (legacy wire header, pointer-based, 32-bit fields).
 *   - ioFTPD v8.x (any build) uses DC_MESSAGE_WIRE v2 — see sitewho_x64.cpp.
 *
 * COMPILE: cl /W4 sitewho_x86.cpp
 *
 * Copyright (c) ioFTPD Project. Distributed under GPL v2.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

/* -------------------------------------------------------------------------
 * Protocol constants
 * ---------------------------------------------------------------------- */
#define WM_SHMEM            (WM_USER + 101)
#define WM_DATACOPY_FREE    (WM_USER + 20)
#define WM_DATACOPY_FILEMAP (WM_USER + 21)

/* DataCopy command identifiers */
#define DC_GET_ONLINEDATA   13

/* Allocation type */
#define FILEMAP             1

/* -------------------------------------------------------------------------
 * DC_MESSAGE — legacy v7.x wire header (32-bit processes only).
 *
 * Placed at the start of the shared-memory mapping.  Context data
 * (e.g. DC_ONLINEDATA_V7) follows immediately at &lpMessage[1].
 *
 * ioFTPD v7.x uses lpMemoryBase to relocate LPTSTR pointer fields in
 * ONLINEDATA before writing them: the pointer value written into
 * OnlineData.tszRealPath is valid in the *client* address space.
 * The client can dereference it directly after WaitForSingleObject.
 * ---------------------------------------------------------------------- */
typedef struct _DC_MESSAGE
{
    HANDLE  hEvent;         /* Auto-reset event; ioFTPD signals it on completion */
    LPVOID  lpContext;      /* Points to context data in client address space
                               (= &lpMessage[1], set by client before first call) */
    LPVOID  lpMemoryBase;   /* Base of this mapping in client address space
                               (= lpMessage, used by ioFTPD to relocate pointers) */
    DWORD   dwIdentifier;   /* Command ID — set before each WM_SHMEM post */
    DWORD   dwReturn;       /* Return value written by ioFTPD on completion:
                                 0          = success, data ready
                                 (DWORD)-1  = end of list / fatal error
                                 other      = required buffer bytes (too small) */
} DC_MESSAGE, *LPDC_MESSAGE;


/* -------------------------------------------------------------------------
 * ONLINEDATA — v7.x internal/wire format (pointer fields are 32-bit).
 *
 * tszRealPath and tszRealDataPath are LPTSTR pointers.  ioFTPD writes
 * the string data into the shared buffer and relocates the pointer to
 * be valid in the client's address space (using DC_MESSAGE.lpMemoryBase).
 * Access them directly after a successful WM_SHMEM reply.
 *
 * If you have the v7.x ioFTPD headers, you can #include <WinMessages.h>
 * instead of redefining ONLINEDATA here.
 * ---------------------------------------------------------------------- */
#define _MAX_NAME       31
#define _MAX_PWD        259
#define MAX_HOSTNAME    64
#define MAX_IDENT       20

typedef struct _ONLINEDATA
{
    INT32       Uid;
    DWORD       dwFlags;
    CHAR        tszServiceName[_MAX_NAME + 1];
    CHAR        tszAction[64];
    ULONG       ulClientIp;
    USHORT      usClientPort;
    CHAR        szHostName[MAX_HOSTNAME];
    CHAR        szIdent[MAX_IDENT];
    CHAR        tszVirtualPath[_MAX_PWD + 1];
    LPTSTR      tszRealPath;        /* Pointer valid in client address space */
    DWORD       dwRealPath;         /* Character count of tszRealPath */
    DWORD       dwOnlineTime;
    DWORD       dwIdleTickCount;
    BYTE        bTransferStatus;    /* 0=idle 1=upload 2=download 3=list */
    USHORT      usDeviceNum;
    ULONG       ulDataClientIp;
    USHORT      usDataClientPort;
    CHAR        tszVirtualDataPath[_MAX_PWD + 1];
    LPTSTR      tszRealDataPath;    /* Pointer valid in client address space */
    DWORD       dwRealDataPath;     /* Character count of tszRealDataPath */
    DWORD       dwBytesTransfered;
    DWORD       dwIntervalLength;
    INT64       i64TotalBytesTransfered;
} ONLINEDATA, *PONLINEDATA;


/* DC_ONLINEDATA — context struct written after DC_MESSAGE in shared memory */
typedef struct _DC_ONLINEDATA
{
    ONLINEDATA  OnlineData;         /* ioFTPD fills this on each reply */
    INT         iOffset;            /* Client sets to 0; ioFTPD advances per user */
    DWORD       dwSharedMemorySize; /* Total bytes after DC_MESSAGE header (set by client) */
} DC_ONLINEDATA, *LPDC_ONLINEDATA;


/* -------------------------------------------------------------------------
 * Internal allocation tracking
 * ---------------------------------------------------------------------- */
typedef struct _ALLOCATION
{
    LPDC_MESSAGE    lpMessage;  /* Start of shared-memory mapping */
    LPVOID          lpContext;  /* = &lpMessage[1] = start of DC_ONLINEDATA */
    HANDLE          hObject;    /* File-mapping kernel object */
    HANDLE          hEvent;     /* Auto-reset event */
    LRESULT         hRemote;    /* Opaque cookie returned by WM_DATACOPY_FILEMAP */
    DWORD           dwBytes;    /* Bytes available for context (excluding DC_MESSAGE) */
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
    LPALLOCATION    lpAlloc;
    LPDC_MESSAGE    lpMessage;
    HANDLE          hObject = NULL, hEvent = NULL;
    DWORD           dwTotal = sizeof(DC_MESSAGE) + dwContextBytes;
    LRESULT         hRemote;

    hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!hEvent) return NULL;

    lpAlloc = (LPALLOCATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ALLOCATION));
    if (!lpAlloc) { CloseHandle(hEvent); return NULL; }

    hObject = CreateFileMapping(INVALID_HANDLE_VALUE, NULL,
                                PAGE_READWRITE | SEC_COMMIT, 0, dwTotal, NULL);
    if (!hObject) goto fail;

    lpMessage = (LPDC_MESSAGE)MapViewOfFile(hObject, FILE_MAP_ALL_ACCESS, 0, 0, dwTotal);
    if (!lpMessage) goto fail;

    /* Initialise DC_MESSAGE header */
    lpMessage->hEvent       = hEvent;
    lpMessage->lpContext    = &lpMessage[1];    /* Context follows header */
    lpMessage->lpMemoryBase = (LPVOID)lpMessage;
    lpMessage->dwIdentifier = 0;

    /* Register mapping with ioFTPD — returns opaque remote cookie */
    SetLastError(0);
    hRemote = SendMessage(hDaemon, WM_DATACOPY_FILEMAP,
                          (WPARAM)GetCurrentProcessId(), (LPARAM)hObject);
    if (!hRemote || GetLastError() != NO_ERROR)
    {
        UnmapViewOfFile(lpMessage);
        goto fail;
    }

    lpAlloc->lpMessage  = lpMessage;
    lpAlloc->lpContext  = &lpMessage[1];
    lpAlloc->hObject    = hObject;
    lpAlloc->hEvent     = hEvent;
    lpAlloc->hRemote    = hRemote;
    lpAlloc->dwBytes    = dwContextBytes;
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
    /* Tell ioFTPD to release its internal tracking structure */
    SendMessage(hDaemon, WM_DATACOPY_FREE, 0, (LPARAM)lpAlloc->hRemote);
    UnmapViewOfFile(lpAlloc->lpMessage);
    CloseHandle(lpAlloc->hObject);
    CloseHandle(lpAlloc->hEvent);
    HeapFree(GetProcessHeap(), 0, lpAlloc);
}


/* Send one DC_GET_ONLINEDATA request and wait for the reply.
 * Returns: 0=success, (DWORD)-1=end/error, other=required buffer size. */
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

    /* Allocate shared memory: DC_MESSAGE header + DC_ONLINEDATA context +
     * space for two real-path strings (each up to _MAX_PWD characters).     */
    lpAlloc = SharedAllocate(hDaemon,
                             sizeof(DC_ONLINEDATA) + (_MAX_PWD + 1) * 2 * sizeof(CHAR));
    if (!lpAlloc)
    {
        fprintf(stderr, "SharedAllocate failed (error %lu)\n", GetLastError());
        return 1;
    }

    lpOD = (LPDC_ONLINEDATA)lpAlloc->lpContext;
    lpOD->iOffset           = 0;
    lpOD->dwSharedMemorySize = lpAlloc->dwBytes;

    printf("%-4s  %-20s  %-4s  %s\n", "UID", "Action", "St", "Real path");
    printf("%-4s  %-20s  %-4s  %s\n", "---", "------", "--", "---------");

    for (;;)
    {
        dwResult = QueryOnlineData(hDaemon, lpAlloc, 5000);

        if (dwResult == (DWORD)-1)
            break;  /* End of list or timeout */

        if (dwResult != 0)
        {
            /* Buffer too small — ioFTPD retains same iOffset for retry.
             * For simplicity this sample does not reallocate; just skip.  */
            fprintf(stderr, "Buffer too small for this entry (need %lu bytes)\n", dwResult);
            lpOD->iOffset++;
            continue;
        }

        /* dwResult == 0: data is ready in OnlineData */
        printf("%-4d  %-20s  %-4d  %s\n",
               lpOD->OnlineData.Uid,
               lpOD->OnlineData.tszAction,
               (int)lpOD->OnlineData.bTransferStatus,
               lpOD->OnlineData.tszRealPath ? lpOD->OnlineData.tszRealPath : "(none)");
        dwUsers++;
    }

    printf("\n%lu user(s) online.\n", dwUsers);

    SharedFree(hDaemon, lpAlloc);
    return 0;
}
