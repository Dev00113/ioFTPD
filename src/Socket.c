/*
 * Copyright(c) 2006 iniCom Networks, Inc.
 *
 * This file is part of ioFTPD.
 *
 * ioFTPD is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * ioFTPD is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ioFTPD; see the file COPYING.  if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 */

#include <ioFTPD.h>
#include <ws2tcpip.h>  // inet_pton, getaddrinfo

LPFN_GETACCEPTEXSOCKADDRS GetAcceptSockAddrs;
LPFN_ACCEPTEX             Accept;
BOOL volatile             bLogOpenSslErrors;
DWORD                     dwDeadlockPort;
SOCKET                    DeadlockSocket;

static CRITICAL_SECTION          csSelectList;
static volatile PSELECT          pSelectList;
static WSADATA                   wsaData;
static volatile LPIODEVICE       lpSchedulerDeviceList;
static DWORD volatile            dwSchedulerUpdateSpeed;
static ULONGLONG volatile        dwSchedulerWakeUp;
static LONG volatile             lSchedulerDeviceList;
static LONG volatile             lIdentifier;

#define SELECT_CONTINUE 0001
#define SELECT_SET      0002
#define SELECT_REMOVED  0010

// --------------------------
// WSAEventSelect integration
// --------------------------

typedef struct _SELECT_EVENT_NODE {
    struct _SELECT_EVENT_NODE* pNext;
    struct _SELECT_EVENT_NODE* pPrev;
    SOCKET           Socket;
    WSAEVENT         hEvent;
    HANDLE           hWait;
    DWORD            dwFlags;     // FD_XXX mask we registered for
    LPIOSOCKET       lpIoSocket;  // backref for safety/logging
    volatile LONG    lRefCount;   // ref count: 1 (DisarmEventSelect) + N (in-flight callbacks)
} SELECT_EVENT_NODE, * PSELECT_EVENT_NODE;

static PSELECT_EVENT_NODE g_pEventListHead = NULL;

// Must be called with csSelectList held
static PSELECT_EVENT_NODE FindEventNodeBySocket(SOCKET s) {
    for (PSELECT_EVENT_NODE n = g_pEventListHead; n; n = n->pNext) {
        if (n->Socket == s) return n;
    }
    return NULL;
}

// Must be called with csSelectList held
static VOID LinkEventNode(PSELECT_EVENT_NODE n) {
    n->pPrev = NULL;
    n->pNext = g_pEventListHead;
    if (g_pEventListHead) g_pEventListHead->pPrev = n;
    g_pEventListHead = n;
}

// Must be called with csSelectList held
static VOID UnlinkEventNode(PSELECT_EVENT_NODE n) {
    if (n->pPrev) n->pPrev->pNext = n->pNext; else g_pEventListHead = n->pNext;
    if (n->pNext) n->pNext->pPrev = n->pPrev;
    n->pPrev = n->pNext = NULL;
}

// Threadpool wait callback for socket events.
// We do not manipulate PSELECT here; we just post a WM_ASYNC_CALLBACK message
// to keep the original AsyncSelectProc flow intact.
static VOID CALLBACK SelectEventWaitCallback(PVOID lpParameter, BOOLEAN bTimedOut) {
    UNREFERENCED_PARAMETER(bTimedOut);
    PSELECT_EVENT_NODE node = (PSELECT_EVENT_NODE)lpParameter;
    if (!node) return;

    // Increment ref count before doing any work to prevent DisarmEventSelect
    // from freeing the node while we are still running.
    InterlockedIncrement(&node->lRefCount);

    WSANETWORKEVENTS ne;
    ZeroMemory(&ne, sizeof(ne));

    // Acquire list lock to safely read node->hEvent. DisarmEventSelect sets
    // hEvent to WSA_INVALID_EVENT under this same lock, so the check and the
    // WSAEnumNetworkEvents call are mutually exclusive with disarm.
    EnterCriticalSection(&csSelectList);
    if (node->hEvent != WSA_INVALID_EVENT &&
        WSAEnumNetworkEvents(node->Socket, node->hEvent, &ne) == 0) {
        // Post one message per event bit set (to emulate WSAAsyncSelect behavior).
        // Compose lParam as MAKELONG(event, error) since:
        //   WSAGETSELECTEVENT(lParam) == LOWORD(lParam)
        //   WSAGETSELECTERROR(lParam) == HIWORD(lParam)
        DWORD events[] = { FD_READ, FD_WRITE, FD_OOB, FD_ACCEPT, FD_CONNECT, FD_CLOSE, FD_QOS, FD_GROUP_QOS, FD_ROUTING_INTERFACE_CHANGE, FD_ADDRESS_LIST_CHANGE };
        const int bits[] = { FD_READ_BIT, FD_WRITE_BIT, FD_OOB_BIT, FD_ACCEPT_BIT, FD_CONNECT_BIT, FD_CLOSE_BIT, FD_QOS_BIT, FD_GROUP_QOS_BIT, FD_ROUTING_INTERFACE_CHANGE_BIT, FD_ADDRESS_LIST_CHANGE_BIT };
        for (int i = 0; i < (int)(sizeof(events) / sizeof(events[0])); ++i) {
            if ((ne.lNetworkEvents & events[i]) && (node->dwFlags & events[i])) {
                LPARAM lParam = MAKELONG(events[i], (WORD)ne.iErrorCode[bits[i]]);
                PostMessage(GetMainWindow(), WM_ASYNC_CALLBACK, (WPARAM)node->Socket, lParam);
            }
        }
    }
    LeaveCriticalSection(&csSelectList);

    // Release our temporary ref. If DisarmEventSelect already dropped its ref
    // and this is the last one, free the node now.
    if (InterlockedDecrement(&node->lRefCount) == 0) {
        Free(node);
    }
}

// Forward declaration: DisarmEventSelect is defined after ArmEventSelect but called by it.
static VOID DisarmEventSelect(SOCKET s);

// Helper to arm WSAEventSelect on a socket with desired flags.
// Must NOT be called while holding csSelectList.
static BOOL ArmEventSelect(LPIOSOCKET lpIoSocket, DWORD dwFlags) {
    SOCKET s = lpIoSocket->Socket;
    if (s == INVALID_SOCKET) return FALSE;

    // Disarm any existing node BEFORE acquiring csSelectList. Although
    // DisarmEventSelect is now non-blocking, it still acquires csSelectList
    // internally and must not be called while we already hold it.
    DisarmEventSelect(s);

    EnterCriticalSection(&csSelectList);
    PSELECT_EVENT_NODE node = (PSELECT_EVENT_NODE)Allocate("Socket:EventNode", sizeof(SELECT_EVENT_NODE));
    if (!node) {
        LeaveCriticalSection(&csSelectList);
        return FALSE;
    }
    ZeroMemory(node, sizeof(*node));
    node->lRefCount = 1;  // DisarmEventSelect holds the initial ref
    node->Socket = s;
    node->dwFlags = dwFlags;
    node->lpIoSocket = lpIoSocket;
    node->hEvent = WSACreateEvent();
    if (node->hEvent == WSA_INVALID_EVENT) {
        Free(node);
        LeaveCriticalSection(&csSelectList);
        return FALSE;
    }
    if (WSAEventSelect(s, node->hEvent, dwFlags) == SOCKET_ERROR) {
        WSACloseEvent(node->hEvent);
        Free(node);
        LeaveCriticalSection(&csSelectList);
        return FALSE;
    }
    // Register a threadpool wait to be notified when the event is signaled
    if (!RegisterWaitForSingleObject(&node->hWait, node->hEvent, SelectEventWaitCallback, node, INFINITE, WT_EXECUTEDEFAULT)) {
        WSAEventSelect(s, NULL, 0);
        WSACloseEvent(node->hEvent);
        Free(node);
        LeaveCriticalSection(&csSelectList);
        return FALSE;
    }
    LinkEventNode(node);
    LeaveCriticalSection(&csSelectList);
    return TRUE;
}

// Disarm and remove event select for a socket.
// Must NOT be called while csSelectList is held by the current thread.
// Uses blocking UnregisterWaitEx(INVALID_HANDLE_VALUE) to guarantee that
// all in-flight SelectEventWaitCallback invocations have completed before
// the initial lRefCount reference is dropped.  This prevents a use-after-free
// race where a queued-but-not-yet-started callback calls InterlockedIncrement
// on a node that DisarmEventSelect has already freed.
// No deadlock risk: SelectEventWaitCallback acquires only csSelectList (not
// lpIoSocket->csLock), and csSelectList is released before UnregisterWaitEx.
static VOID DisarmEventSelect(SOCKET s) {
    PSELECT_EVENT_NODE node = NULL;
    HANDLE hWait = NULL;
    WSAEVENT hEvent = WSA_INVALID_EVENT;

    EnterCriticalSection(&csSelectList);
    node = FindEventNodeBySocket(s);
    if (node) {
        WSAEventSelect(node->Socket, NULL, 0);  // stop new events
        hWait  = node->hWait;  node->hWait  = NULL;
        hEvent = node->hEvent; node->hEvent = WSA_INVALID_EVENT;
        UnlinkEventNode(node);
        // node stays alive until the ref count reaches zero.
        // Callbacks check hEvent == WSA_INVALID_EVENT under csSelectList and
        // do no further work; they will drop their refs and free if last.
    }
    LeaveCriticalSection(&csSelectList);

    if (hWait) {
        // Block until all in-flight callbacks have finished.  hEvent was set to
        // WSA_INVALID_EVENT under csSelectList above, so any callback still running
        // will see the sentinel, do no work, and return quickly.
        UnregisterWaitEx(hWait, INVALID_HANDLE_VALUE);
    }
    // Safe to close the event handle now: callbacks that already acquired
    // csSelectList and read hEvent already have a local snapshot. Callbacks
    // that have not yet run will check node->hEvent (== WSA_INVALID_EVENT)
    // and skip WSAEnumNetworkEvents, so the closed handle is never passed to it.
    if (hEvent != WSA_INVALID_EVENT) WSACloseEvent(hEvent);

    // Drop the initial ref. If no callbacks are in-flight, this reaches 0 here.
    if (node && InterlockedDecrement(&node->lRefCount) == 0) {
        Free(node);
    }
}

// --------------------------
// Original select helpers
// --------------------------

BOOL
WSAAsyncSelectRemove(PSELECT pSelect)
{
    if (pSelect->dwFlags & SELECT_REMOVED)
    {
        return FALSE;
    }
    // Remove from list
    if (pSelect->pNext) pSelect->pNext->pPrevious = pSelect->pPrevious;
    if (pSelect->pPrevious) pSelect->pPrevious->pNext = pSelect->pNext;
    if (pSelect == pSelectList) pSelectList = pSelect->pNext;
    pSelect->dwFlags |= SELECT_REMOVED;
    return TRUE;
}

DWORD
WSAAsyncSelectTimerProc(LPIOSOCKET lpIoSocket,
    LPTIMER lpTimer)
{
    PSELECT pSelect;
    BOOL    bQueueJob;
    DWORD   dwError;
    SOCKET  socketToDisarm;

    UNREFERENCED_PARAMETER(lpTimer);

    bQueueJob = FALSE;
    socketToDisarm = INVALID_SOCKET;

    // Lock order: list first, then socket to avoid ABBA deadlocks
    EnterCriticalSection(&csSelectList);
    EnterCriticalSection(&lpIoSocket->csLock);

    if ((pSelect = lpIoSocket->lpSelectEvent) != NULL)
    {
        if (WSAAsyncSelectRemove(pSelect) && (lpIoSocket->Socket != INVALID_SOCKET))
        {
            // Save socket to disarm AFTER releasing locks; DisarmEventSelect
            // acquires csSelectList internally and must not be called while
            // it is already held.
            socketToDisarm = lpIoSocket->Socket;
        }

        bQueueJob = (pSelect->dwFlags & SELECT_CONTINUE);
        if (bQueueJob)
        {
            lpIoSocket->lpSelectEvent = NULL;
        }
        pSelect->dwResult = WSAETIMEDOUT;
        pSelect->dwFlags |= SELECT_SET;
    }

    LeaveCriticalSection(&lpIoSocket->csLock);
    LeaveCriticalSection(&csSelectList);

    // Disarm after releasing locks to avoid deadlock with SelectEventWaitCallback
    if (socketToDisarm != INVALID_SOCKET)
    {
        DisarmEventSelect(socketToDisarm);
    }

    // Queue job
    if (bQueueJob)
    {
        pSelect->lpResult[0] = pSelect->dwResult;
        QueueJob(pSelect->lpProc, pSelect->lpContext, JOB_PRIORITY_NORMAL);
        Free(pSelect);
        return INFINITE;
    }

    return 0;
}

BOOL
WSAAsyncSelectWithTimeout(LPIOSOCKET lpIoSocket,
    DWORD dwTimeOut,
    DWORD dwFlags,
    LPDWORD lpResult)
{
    PSELECT pSelect, pTest;
    BOOL    bSelect;
    DWORD   dwError;

    bSelect = TRUE;
    // Allocate memory for object
    pSelect = (PSELECT)Allocate("Socket:AsyncSelect", sizeof(SELECT));
    if (!pSelect) return TRUE;

    // Initialize structure
    pSelect->lpResult = lpResult;
    pSelect->lpIoSocket = lpIoSocket;
    pSelect->dwResult = NO_ERROR;
    pSelect->dwFlags = SELECT_REMOVED;
    pSelect->pNext = NULL;
    pSelect->pPrevious = NULL;
    pSelect->lpProc = NULL;
    pSelect->lpContext = NULL;

    // Create timer
    pSelect->lpTimer = StartIoTimer(NULL, WSAAsyncSelectTimerProc, lpIoSocket, dwTimeOut);

    // Lock order: list, then socket
    EnterCriticalSection(&csSelectList);
    EnterCriticalSection(&lpIoSocket->csLock);

    lpIoSocket->lpSelectEvent = pSelect;

    // Check if timer already fired
    if (!(pSelect->dwFlags & SELECT_SET))
    {
        pSelect->dwFlags = 0;

        for (pTest = pSelectList; pTest; pTest = pTest->pNext)
        {
            if (pTest->lpIoSocket && (pTest->lpIoSocket->Socket == lpIoSocket->Socket))
            {
                Putlog(LOG_DEBUG, "WSAAsyncSelectWithTimeout socket re-use: %d - Flags: %d\r\n", lpIoSocket->Socket, pTest->dwFlags);
                WSAAsyncSelectRemove(pTest);
                break;
            }
        }

        // Add item to list
        if (pSelectList) pSelectList->pPrevious = pSelect;
        pSelect->pNext = pSelectList;
        pSelect->pPrevious = NULL;
        pSelectList = pSelect;
    }
    else
    {
        bSelect = FALSE;
    }

    LeaveCriticalSection(&lpIoSocket->csLock);
    LeaveCriticalSection(&csSelectList);

    // Arm event-based async "select"
    if (bSelect)
    {
        if (!ArmEventSelect(lpIoSocket, dwFlags))
        {
            dwError = WSAGetLastError();
            Putlog(LOG_DEBUG, _T("WSAEventSelect arm error: %lu\r\n"), dwError);
        }
    }
    else
    {
        Putlog(LOG_DEBUG, _T("WSA select timer fired immediately.\r\n"));
    }

    return FALSE;
}

BOOL
WSAAsyncSelectCancel(LPIOSOCKET lpIoSocket)
{
    PSELECT pSelect;
    DWORD   dwError;
    SOCKET  socketToDisarm;

    socketToDisarm = INVALID_SOCKET;

    // lpSelectEvent can be NULL in which case we do nothing
    if (!lpIoSocket->lpSelectEvent)
    {
        return FALSE;
    }

    // Lock order: list, then socket
    EnterCriticalSection(&csSelectList);
    EnterCriticalSection(&lpIoSocket->csLock);

    // Remove item from list
    pSelect = lpIoSocket->lpSelectEvent;

    if (pSelect)
    {
        if (WSAAsyncSelectRemove(pSelect) && (lpIoSocket->Socket != INVALID_SOCKET))
        {
            // Save socket to disarm AFTER releasing locks; DisarmEventSelect
            // acquires csSelectList internally and must not be called while
            // it is already held.
            socketToDisarm = lpIoSocket->Socket;
        }
        lpIoSocket->lpSelectEvent = NULL;
    }

    LeaveCriticalSection(&lpIoSocket->csLock);
    LeaveCriticalSection(&csSelectList);

    // Disarm after releasing locks to avoid deadlock with SelectEventWaitCallback
    if (socketToDisarm != INVALID_SOCKET)
    {
        DisarmEventSelect(socketToDisarm);
    }

    if (pSelect)
    {
        // Free resources
        StopIoTimer(pSelect->lpTimer, FALSE);
        Free(pSelect);
        return TRUE;
    }

    return FALSE;
}

BOOL
WSAAsyncSelectContinue(LPIOSOCKET lpIoSocket,
    LPVOID lpProc,
    LPVOID lpContext)
{
    PSELECT pSelect;
    BOOL    bQueueJob;

    // Lock order: list, then socket
    EnterCriticalSection(&csSelectList);
    EnterCriticalSection(&lpIoSocket->csLock);

    if (!(pSelect = lpIoSocket->lpSelectEvent))
    {
        LeaveCriticalSection(&lpIoSocket->csLock);
        LeaveCriticalSection(&csSelectList);
        return TRUE;
    }

    // Copy information
    pSelect->lpProc = lpProc;
    pSelect->lpContext = lpContext;

    if ((bQueueJob = (pSelect->dwFlags & SELECT_SET)) != 0)
    {
        // Remove item from list since event already signaled
        WSAAsyncSelectRemove(pSelect);
        lpIoSocket->lpSelectEvent = NULL;
    }
    else
    {
        pSelect->dwFlags |= SELECT_CONTINUE;
    }

    LeaveCriticalSection(&lpIoSocket->csLock);
    LeaveCriticalSection(&csSelectList);

    // Queue job
    if (bQueueJob)
    {
        StopIoTimer(pSelect->lpTimer, FALSE);
        pSelect->lpResult[0] = pSelect->dwResult;
        QueueJob(lpProc, lpContext, JOB_PRIORITY_NORMAL);
        Free(pSelect);
    }
    return FALSE;
}

LRESULT
AsyncSelectProc(WPARAM wParam,
    LPARAM lParam)
{
    PSELECT  pSelect = NULL;
    BOOL     bQueueJob = FALSE;
    BOOL     bDisarm = FALSE;
    DWORD    dwError = WSAGETSELECTERROR(lParam);
    DWORD    dwEvent = WSAGETSELECTEVENT(lParam);
    SOCKET   sock = (SOCKET)wParam;

    UNREFERENCED_PARAMETER(dwEvent); // Available for deeper debugging/logging if needed

    EnterCriticalSection(&csSelectList);
    // Event message received
    for (pSelect = pSelectList; pSelect; pSelect = pSelect->pNext)
    {
        if (pSelect->lpIoSocket->Socket != sock) continue;
        if (pSelect->lpIoSocket->Socket == INVALID_SOCKET)
        {
            Putlog(LOG_DEBUG, _T("AsyncSelectProc: closed socket found.\r\n"));
            continue;
        }
        // Try to lock item; give up after a few attempts
        DWORD dwTry = 5;
        while (dwTry)
        {
            if (TryEnterCriticalSection(&pSelect->lpIoSocket->csLock)) break;
            Sleep(10);
            dwTry--;
        }
        if (dwTry)
        {
            // Double-check now that we hold the lock
            if ((pSelect->lpIoSocket->Socket != sock) || (pSelect != pSelect->lpIoSocket->lpSelectEvent))
            {
                LeaveCriticalSection(&pSelect->lpIoSocket->csLock);
                Putlog(LOG_DEBUG, _T("AsyncSelectProc: Data mismatch.\r\n"));
                continue;
            }

            // Remove object from list
            WSAAsyncSelectRemove(pSelect);
            // Update structure
            pSelect->dwResult = dwError;
            pSelect->dwFlags |= SELECT_SET;

            // Mark socket for disarm AFTER releasing csSelectList; DisarmEventSelect
            // acquires csSelectList internally and must not be called while it
            // is already held (SelectEventWaitCallback also acquires it).
            bDisarm = TRUE;

            if ((bQueueJob = (pSelect->dwFlags & SELECT_CONTINUE)) != 0)
            {
                pSelect->lpIoSocket->lpSelectEvent = NULL;
            }
            LeaveCriticalSection(&pSelect->lpIoSocket->csLock);
            break;
        }
        else
        {
            Putlog(LOG_DEBUG, _T("AsyncSelectProc: Failed locking socket: %d\r\n"), (int)(UINT_PTR)sock);
        }
    }
    LeaveCriticalSection(&csSelectList);

    // Disarm after releasing csSelectList (DisarmEventSelect acquires it internally).
    // DisarmEventSelect is now non-blocking so this is safe on the message thread.
    if (bDisarm)
    {
        DisarmEventSelect(sock);
    }

    if (!pSelect)
    {
        Putlog(LOG_DEBUG, _T("AsyncSelectProc: Socket %d not found.\r\n"), (int)(UINT_PTR)sock);
    }

    // Queue job
    if (bQueueJob)
    {
        StopIoTimer(pSelect->lpTimer, FALSE);
        pSelect->lpResult[0] = pSelect->dwResult;
        QueueJob(pSelect->lpProc, pSelect->lpContext, JOB_PRIORITY_NORMAL);
        Free(pSelect);
    }
    return FALSE;
}

BOOL
CloseSocket(LPIOSOCKET lpIoSocket,
    BOOL bNoLinger)
{
    if (!lpIoSocket->bInitialized)
    {
        Putlog(LOG_ERROR, _T("Uninitialized socket used!\r\n"));
        return TRUE;
    }

    EnterCriticalSection(&lpIoSocket->csLock);

    if (lpIoSocket->lpSelectEvent)
    {
        // Cancel any outstanding async select
        // Note: WSAAsyncSelectCancel handles its own locking
        LeaveCriticalSection(&lpIoSocket->csLock);
        WSAAsyncSelectCancel(lpIoSocket);
        EnterCriticalSection(&lpIoSocket->csLock);
    }

    if (lpIoSocket->Socket != INVALID_SOCKET)
    {
        // Disarm any lingering event select
        DisarmEventSelect(lpIoSocket->Socket);

        // Apply linger behavior according to bNoLinger
        // bNoLinger == TRUE => hard close (RST)
        // bNoLinger == FALSE => graceful shutdown (FIN), no hard close
        struct linger ling;
        if (bNoLinger)
        {
            ling.l_onoff = 1;
            ling.l_linger = 0;
            setsockopt(lpIoSocket->Socket, SOL_SOCKET, SO_LINGER, (const char*)&ling, sizeof(ling));
        }
        else
        {
            ling.l_onoff = 0; // disable hard close
            ling.l_linger = 0;
            setsockopt(lpIoSocket->Socket, SOL_SOCKET, SO_LINGER, (const char*)&ling, sizeof(ling));
            shutdown(lpIoSocket->Socket, SD_BOTH);
        }

        closesocket(lpIoSocket->Socket);
        lpIoSocket->Socket = INVALID_SOCKET;
        LeaveCriticalSection(&lpIoSocket->csLock);
        return FALSE;
    }

    LeaveCriticalSection(&lpIoSocket->csLock);
    return TRUE;
}

// Drop one reference to a SECURITY struct.  When the count reaches zero the
// struct, its critical section, and the SSL/BIO objects are freed.  Callers
// must NOT hold lpSecure->csLock when calling this — the decrement itself is
// atomic, and if it reaches 0 we delete the CS (which requires no one to hold it).
VOID Security_Release(LPSECURITY lpSecure)
{
    if (InterlockedDecrement(&lpSecure->lRefCount) == 0)
    {
        DeleteCriticalSection(&lpSecure->csLock);
        if (lpSecure->SSL)
        {
            SSL_free(lpSecure->SSL);         // implicitly frees InternalBio
            BIO_free(lpSecure->NetworkBio);
        }
        Free(lpSecure);
    }
}

BOOL
ioCloseSocket(LPIOSOCKET lpIoSocket, BOOL bNoLinger)
{
    LPSECURITY lpSecure;
    BOOL       bReturn;

    // Close socket if it was initialized
    bReturn = CloseSocket(lpIoSocket, bNoLinger);
    UnbindSocket(lpIoSocket);

    // Release the linebuffer owner reference.  If an IOCP abort completion or a queued
    // TransmitPackages_Callback job is still in-flight for the ReceiveLine transfer,
    // lRefCount will be > 1 and the free is deferred to ReceiveLine_Complete.
    if (lpIoSocket->lpLineBuffer)
    {
        LPLINEBUFFER lpLineBuffer = lpIoSocket->lpLineBuffer;
        lpIoSocket->lpLineBuffer = NULL;   // null first so reentrant calls see NULL
        if (InterlockedDecrement(&lpLineBuffer->lRefCount) == 0)
        {
            if (lpLineBuffer->lpTransfer) Free(lpLineBuffer->lpTransfer);
            Free(lpLineBuffer);
        }
    }

    // Release the SendQuick owner reference.  If a PostQueuedCompletionStatus IOCP
    // operation is in-flight (lRefCount == 2), the free and CloseHandle are deferred to
    // SendQuickComplete, which still needs SQ.lpTransfer and SQ.hEvent to be valid.
    // ioCloseSocket is called exactly once per socket (guarded by ioDeleteSocket's
    // bInitialized check), so there is no double-decrement risk.
    if (lpIoSocket->SQ.lpTransfer)
    {
        if (InterlockedDecrement(&lpIoSocket->SQ.lRefCount) == 0)
        {
            HANDLE hEvent = lpIoSocket->SQ.hEvent;
            Free(lpIoSocket->SQ.lpTransfer);
            lpIoSocket->SQ.lpTransfer = NULL;
            lpIoSocket->SQ.hEvent     = INVALID_HANDLE_VALUE;
            if (hEvent && hEvent != INVALID_HANDLE_VALUE) CloseHandle(hEvent);
        }
        // else: IOCP in-flight; SendQuickComplete will free lpTransfer and close hEvent.
    }

    ZeroMemory(&lpIoSocket->Options, sizeof(SOCKET_OPTIONS));
    ZeroMemory(&lpIoSocket->dwBandwidthLimit, sizeof(lpIoSocket->dwBandwidthLimit));

    // Process secure socket: null the pointer under IOSOCKET lock so any
    // concurrent TLS callback that calls Security_Acquire will see NULL and
    // bail out, then drop the socket-owner reference.  Security_Release frees
    // the struct only when the last reference (owner + any in-progress IOCP
    // TLS callback) is dropped, preventing use-after-free on SSL* / BIO*.
    EnterCriticalSection(&lpIoSocket->csLock);
    lpSecure = lpIoSocket->lpSecure;
    lpIoSocket->lpSecure = NULL;
    LeaveCriticalSection(&lpIoSocket->csLock);
    if (lpSecure != NULL)
    {
        Security_Release(lpSecure);
    }

    return bReturn;
}

BOOL
ioDeleteSocket(LPIOSOCKET lpIoSocket, BOOL bNoLinger)
{
    if (lpIoSocket->bInitialized)
    {
        ioCloseSocket(lpIoSocket, bNoLinger);
        DeleteCriticalSection(&lpIoSocket->csLock);
        lpIoSocket->bInitialized = FALSE;
    }
    return FALSE;
}

BOOL
SendQueuedIO(LPSOCKETOVERLAPPED lpOverlapped)
{
    LPIOSOCKET  lpSocket;
    DWORD       dwBytesSent;

    lpSocket = lpOverlapped->hSocket;
    // Send data
    if ((WSASend(lpSocket->Socket, &lpOverlapped->Buffer, 1, &dwBytesSent, 0, (LPWSAOVERLAPPED)lpOverlapped, NULL) == SOCKET_ERROR) &&
        (WSAGetLastError() != WSA_IO_PENDING))
    {
        return TRUE;
    }
    return FALSE;
}

BOOL
ReceiveQueuedIO(LPSOCKETOVERLAPPED lpOverlapped)
{
    LPIOSOCKET  lpSocket;
    DWORD       dwFlags, dwBytesReceived;

    lpSocket = lpOverlapped->hSocket;
    dwFlags = 0;
    // Receive data
    if ((WSARecv(lpSocket->Socket, &lpOverlapped->Buffer, 1, &dwBytesReceived, &dwFlags, (LPWSAOVERLAPPED)lpOverlapped, NULL) == SOCKET_ERROR) &&
        (WSAGetLastError() != WSA_IO_PENDING))
    {
        return TRUE;
    }
    return FALSE;
}

// Returns TRUE if an error occurred, else FALSE
BOOL
SendOverlapped(LPIOSOCKET lpSocket, LPSOCKETOVERLAPPED lpOverlapped)
{
    LPIODEVICE   lpDevice;
    LPBANDWIDTH  lpBandwidth;
    DWORD        dwBytesSent, dwResult, dwError;
    LONG         lIdent;

    if (dwSchedulerUpdateSpeed &&
        (lpDevice = lpSocket->lpDevice) &&
        (lpDevice->Outbound.bGlobalBandwidthLimit || lpSocket->Options.dwSendLimit))
    {
        lpBandwidth = &lpDevice->Outbound;
        if (lpOverlapped->Buffer.len > 1024)
        {
            lpOverlapped->Buffer.len = 1024;
        }

        while (InterlockedExchange(&lpBandwidth->lLock, TRUE)) SwitchToThread();
        // Check available bandwidth on device
        if (!lpBandwidth->dwGlobalBandwidthLeft)
        {
            // Push item to queue
            if (!lpBandwidth->lpIOQueue[0][HEAD])
            {
                lpBandwidth->lpIOQueue[0][HEAD] = lpOverlapped;
            }
            else lpBandwidth->lpIOQueue[0][TAIL]->lpNext = lpOverlapped;
            lpBandwidth->lpIOQueue[0][TAIL] = lpOverlapped;
            lpBandwidth->dwIOQueue[0]++;
            InterlockedExchange(&lpBandwidth->lLock, FALSE);
            return FALSE;
        }
        // Check available bandwidth for user
        if (lpSocket->Options.dwSendLimit &&
            !lpSocket->dwBandwidthLimit[0]--)
        {
            if (!lpBandwidth->lpIOQueue[1][HEAD])
            {
                lpBandwidth->lpIOQueue[1][HEAD] = lpOverlapped;
            }
            else lpBandwidth->lpIOQueue[1][TAIL]->lpNext = lpOverlapped;
            lpBandwidth->lpIOQueue[1][TAIL] = lpOverlapped;
            lpBandwidth->dwIOQueue[1]++;
            lpSocket->dwBandwidthLimit[0] = lpSocket->Options.dwSendLimit - 1;
            InterlockedExchange(&lpBandwidth->lLock, FALSE);
            return FALSE;
        }
        lpBandwidth->dwGlobalBandwidthLeft--;
        InterlockedExchange(&lpBandwidth->lLock, FALSE);
    }

    lpOverlapped->Internal = 0;
    lpOverlapped->InternalHigh = 0;
    lpOverlapped->Offset = 0;
    lpOverlapped->OffsetHigh = 0;
    // hEvent is never set and thus is zero anyway

    lIdent = InterlockedIncrement(&lIdentifier);
    if (InterlockedExchange(&lpOverlapped->lIdentifier, lIdent) != 0)
    {
        Putlog(LOG_ERROR, "Detected overlapped re-use (send).\r\n");
    }

    dwBytesSent = 0;
    // Send data
    EnterCriticalSection(&lpSocket->csLock);
    if (lpSocket->Socket == INVALID_SOCKET)
    {
        LeaveCriticalSection(&lpSocket->csLock);
        SetLastError(ERROR_CLOSED_SOCKET);
        return TRUE;
    }
    dwResult = WSASend(lpSocket->Socket, &lpOverlapped->Buffer, 1, &dwBytesSent, 0, (LPWSAOVERLAPPED)lpOverlapped, NULL);
    LeaveCriticalSection(&lpSocket->csLock);
    if (dwResult == SOCKET_ERROR)
    {
        dwError = WSAGetLastError();
        if (dwError == WSA_IO_PENDING)
        {
            // Notification will be via overlapped callback
            return FALSE;
        }
        return TRUE;
    }
    return FALSE;
}

// Returns TRUE if an error occurred, else FALSE
BOOL
ReceiveOverlapped(LPIOSOCKET lpSocket,
    LPSOCKETOVERLAPPED lpOverlapped)
{
    LPIODEVICE   lpDevice;
    LPBANDWIDTH  lpBandwidth;
    DWORD        dwFlags, dwBytesReceived, dwResult, dwError;
    LONG         lIdent;

    if (dwSchedulerUpdateSpeed &&
        (lpDevice = lpSocket->lpDevice) &&
        (lpDevice->Inbound.bGlobalBandwidthLimit || lpSocket->Options.dwReceiveLimit))
    {
        lpBandwidth = &lpDevice->Inbound;
        // Calculate maximum receive amount
        if (lpOverlapped->Buffer.len > 1024)
        {
            lpOverlapped->Buffer.len = 1024;
        }

        while (InterlockedExchange(&lpBandwidth->lLock, TRUE)) SwitchToThread();
        // Check available bandwidth on device
        if (!lpBandwidth->dwGlobalBandwidthLeft)
        {
            // Push item to queue
            if (!lpBandwidth->lpIOQueue[0][HEAD])
            {
                lpBandwidth->lpIOQueue[0][HEAD] = lpOverlapped;
            }
            else lpBandwidth->lpIOQueue[0][TAIL]->lpNext = lpOverlapped;
            lpBandwidth->lpIOQueue[0][TAIL] = lpOverlapped;
            lpBandwidth->dwIOQueue[0]++;
            InterlockedExchange(&lpBandwidth->lLock, FALSE);
            return FALSE;
        }
        // Check available bandwidth for user
        if (lpSocket->Options.dwReceiveLimit &&
            !lpSocket->dwBandwidthLimit[1]--)
        {
            // Push item to queue
            if (!lpBandwidth->lpIOQueue[1][HEAD])
            {
                lpBandwidth->lpIOQueue[1][HEAD] = lpOverlapped;
            }
            else lpBandwidth->lpIOQueue[1][TAIL]->lpNext = lpOverlapped;
            lpBandwidth->lpIOQueue[1][TAIL] = lpOverlapped;
            lpBandwidth->dwIOQueue[1]++;
            lpSocket->dwBandwidthLimit[1] = lpSocket->Options.dwReceiveLimit - 1;

            InterlockedExchange(&lpBandwidth->lLock, FALSE);
            return FALSE;
        }
        lpBandwidth->dwGlobalBandwidthLeft--;
        InterlockedExchange(&lpBandwidth->lLock, FALSE);
    }

    lpOverlapped->Internal = 0;
    lpOverlapped->InternalHigh = 0;
    lpOverlapped->Offset = 0;
    lpOverlapped->OffsetHigh = 0;
    // hEvent is never set and thus is zero anyway

    dwFlags = 0;
    dwBytesReceived = 0;

    if (lpOverlapped->Buffer.len > 65536)
    {
        lpOverlapped->Buffer.len = 65536;
    }

    lIdent = InterlockedIncrement(&lIdentifier);
    if (InterlockedExchange(&lpOverlapped->lIdentifier, lIdent) != 0)
    {
        Putlog(LOG_ERROR, "Detected overlapped re-use (recv).\r\n");
    }

    // Receive data
    EnterCriticalSection(&lpSocket->csLock);
    if (lpSocket->Socket == INVALID_SOCKET)
    {
        LeaveCriticalSection(&lpSocket->csLock);
        SetLastError(ERROR_CLOSED_SOCKET);
        return TRUE;
    }
    dwResult = WSARecv(lpSocket->Socket, &lpOverlapped->Buffer, 1, &dwBytesReceived, &dwFlags, (LPWSAOVERLAPPED)lpOverlapped, NULL);
    LeaveCriticalSection(&lpSocket->csLock);
    if (dwResult == SOCKET_ERROR)
    {
        dwError = WSAGetLastError();
        if (dwError == WSA_IO_PENDING)
        {
            // Notification will be via overlapped callback
            return FALSE;
        }
        return TRUE;
    }
    return FALSE;
}


BOOL BindSocket(SOCKET Socket, ULONG lAddress, USHORT sPort, BOOL bReuse)
{
    struct sockaddr_in SockAddr;
    INT iReturn;

    // Initialize structure
    ZeroMemory(&SockAddr, sizeof(SockAddr));
    SockAddr.sin_port = htons(sPort);
    SockAddr.sin_addr.s_addr = lAddress;
    SockAddr.sin_family = AF_INET;

    // Reuse address
    if (bReuse)
    {
        int opt = 1;
        setsockopt(Socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
    }
    // Bind socket
    iReturn = bind(Socket, (struct sockaddr*)&SockAddr, sizeof(struct sockaddr_in));

    return (iReturn != SOCKET_ERROR ? FALSE : TRUE);
}


ULONG HostToAddress(LPSTR szHostName)
{
    if (!szHostName) return INADDR_NONE;

    // Try IPv4 numeric string first
    struct in_addr addr4;
    if (inet_pton(AF_INET, szHostName, &addr4) == 1) {
        return addr4.s_addr;
    }

    // Resolve via getaddrinfo (IPv4 only)
    struct addrinfo hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo* res = NULL;
    ULONG lAddress = INADDR_NONE;

    if (getaddrinfo(szHostName, NULL, &hints, &res) == 0 && res) {
        struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr;
        if (ipv4) {
            lAddress = ipv4->sin_addr.s_addr;
        }
        freeaddrinfo(res);
    }
    return lAddress;
}

BOOL SetSocketOption(LPIOSOCKET lpSocket, INT iLevel, INT iOptionName, LPVOID lpValue, INT iValue)
{
    if (iLevel != IO_SOCKET)
    {
        return setsockopt(lpSocket->Socket, iLevel, iOptionName, (LPCSTR)lpValue, iValue);
    }

    switch (iOptionName)
    {
    case RECEIVE_LIMIT:
        // Receive limit, kb/sec
        if (((LPDWORD)lpValue)[0])
        {
            lpSocket->Options.dwReceiveLimit = ((LPDWORD)lpValue)[0];
            lpSocket->dwBandwidthLimit[1] =
                max(2, (DWORD)(((LPDWORD)lpValue)[0] / 1000. * min(Time_DifferenceDW64(SafeGetTickCount64(), dwSchedulerWakeUp), 1000)));
        }
        break;
    case SEND_LIMIT:
        // Send limit, kb/sec
        if (((LPDWORD)lpValue)[0])
        {
            lpSocket->Options.dwSendLimit = ((LPDWORD)lpValue)[0];
            lpSocket->dwBandwidthLimit[0] =
                max(2, (DWORD)(((LPDWORD)lpValue)[0] / 1000. * min(Time_DifferenceDW64(SafeGetTickCount64(), dwSchedulerWakeUp), 1000)));
        }
        break;
    case SOCKET_PRIORITY:
        // Socket priority
        lpSocket->Options.dwPriority = ((LPDWORD)lpValue)[0];
        break;
    default:
        return SOCKET_ERROR;
    }
    return FALSE;
}

VOID RegisterSchedulerDevice(LPIODEVICE lpDevice)
{
    while (InterlockedExchange(&lSchedulerDeviceList, TRUE)) SwitchToThread();
    // Push new device to scheduler device list
    if (lpSchedulerDeviceList) lpSchedulerDeviceList->lpPrevSDevice = lpSchedulerDeviceList;
    lpDevice->lpNextSDevice = lpSchedulerDeviceList;
    lpSchedulerDeviceList = lpDevice;
    lpDevice->lpPrevSDevice = NULL;
    InterlockedExchange(&lSchedulerDeviceList, FALSE);
}

VOID UnregisterSchedulerDevice(LPIODEVICE lpDevice)
{
    while (InterlockedExchange(&lSchedulerDeviceList, TRUE)) SwitchToThread();
    // Unregister device from scheduler
    if (lpDevice->lpNextSDevice) lpDevice->lpNextSDevice->lpPrevSDevice = lpDevice->lpPrevSDevice;
    if (lpDevice->lpPrevSDevice)
    {
        lpDevice->lpPrevSDevice->lpNextSDevice = lpDevice->lpNextSDevice;
    }
    else lpSchedulerDeviceList = lpDevice->lpNextSDevice;
    InterlockedExchange(&lSchedulerDeviceList, FALSE);
}

UINT WINAPI SocketSchedulerThread(LPVOID lpNull)
{
    LPSOCKETOVERLAPPED  lpQueue[2][2], lpOverlapped;
    LPBANDWIDTH         lpBandwidth;
    LPIODEVICE          lpDevice;
    BOOL                bGetAll;
    DWORD               dwQueue[2];
    DWORD               dwUpStream, dwDownStream, dwSleep, dwLoops;
    ULONGLONG           dwNextWakeUp;

    UNREFERENCED_PARAMETER(lpNull);

    for (dwLoops = 1;;)
    {
        dwNextWakeUp = SafeGetTickCount64() + (1000 / dwSchedulerUpdateSpeed);
        if ((bGetAll = (dwLoops++ % dwSchedulerUpdateSpeed ? FALSE : TRUE))) dwSchedulerWakeUp = dwNextWakeUp;

        while (InterlockedExchange(&lSchedulerDeviceList, TRUE)) SwitchToThread();
        // Go through all devices
        for (lpDevice = lpSchedulerDeviceList; lpDevice; lpDevice = lpDevice->lpNextSDevice)
        {
            lpBandwidth = &lpDevice->Outbound;
            dwUpStream = lpBandwidth->dwGlobalBandwidthLimit / dwSchedulerUpdateSpeed;
            dwQueue[0] = lpBandwidth->dwIOQueue[2];
            lpQueue[0][HEAD] = lpBandwidth->lpIOQueue[2][HEAD];
            lpQueue[0][TAIL] = lpBandwidth->lpIOQueue[2][TAIL];

            while (InterlockedExchange(&lpBandwidth->lLock, TRUE)) SwitchToThread();
            // Get primary upstream queue
            if (lpQueue[0][HEAD])
            {
                lpQueue[0][TAIL]->lpNext = lpBandwidth->lpIOQueue[0][HEAD];
            }
            else lpQueue[0][HEAD] = lpBandwidth->lpIOQueue[0][HEAD];
            lpQueue[0][TAIL] = lpBandwidth->lpIOQueue[0][TAIL];
            dwQueue[0] += lpBandwidth->dwIOQueue[0];

            lpBandwidth->lpIOQueue[0][HEAD] = NULL;
            lpBandwidth->dwIOQueue[0] = 0;
            dwUpStream += (lpBandwidth->dwGlobalBandwidthLeft > dwUpStream / 2 ? dwUpStream : lpBandwidth->dwGlobalBandwidthLeft) / 2;

            // Get secondary queue (once per sec)
            if (bGetAll)
            {
                if (lpBandwidth->lpIOQueue[1][HEAD])
                {
                    if (lpQueue[0][HEAD])
                    {
                        lpQueue[0][TAIL]->lpNext = lpBandwidth->lpIOQueue[1][HEAD];
                    }
                    else lpQueue[0][HEAD] = lpBandwidth->lpIOQueue[1][HEAD];
                    lpQueue[0][TAIL] = lpBandwidth->lpIOQueue[1][TAIL];
                    dwQueue[0] += lpBandwidth->dwIOQueue[1];
                }
                lpBandwidth->lpIOQueue[1][HEAD] = NULL;
                lpBandwidth->dwIOQueue[1] = 0;
                dwUpStream += (lpBandwidth->dwGlobalBandwidthLimit % dwSchedulerUpdateSpeed);
            }
            // Set upstream limit
            lpBandwidth->dwGlobalBandwidthLeft = (dwQueue[0] >= dwUpStream ? 0 : dwUpStream - dwQueue[0]);
            InterlockedExchange(&lpBandwidth->lLock, FALSE);

            lpBandwidth = &lpDevice->Inbound;
            dwDownStream = lpBandwidth->dwGlobalBandwidthLimit / dwSchedulerUpdateSpeed;
            dwQueue[1] = lpBandwidth->dwIOQueue[2];
            lpQueue[1][HEAD] = lpBandwidth->lpIOQueue[2][HEAD];
            lpQueue[1][TAIL] = lpBandwidth->lpIOQueue[2][TAIL];
            while (InterlockedExchange(&lpBandwidth->lLock, TRUE)) SwitchToThread();
            // Get primary downstream queue
            if (lpQueue[1][HEAD])
            {
                lpQueue[1][TAIL]->lpNext = lpBandwidth->lpIOQueue[0][HEAD];
            }
            else lpQueue[1][HEAD] = lpBandwidth->lpIOQueue[0][HEAD];
            lpQueue[1][TAIL] = lpBandwidth->lpIOQueue[0][TAIL];
            dwQueue[1] += lpBandwidth->dwIOQueue[0];

            lpBandwidth->lpIOQueue[0][HEAD] = NULL;
            lpBandwidth->dwIOQueue[0] = 0;
            dwDownStream += (lpBandwidth->dwGlobalBandwidthLeft > dwDownStream / 2 ? dwDownStream : lpBandwidth->dwGlobalBandwidthLeft) / 2;

            // Get secondary queue (once per sec)
            if (bGetAll)
            {
                if (lpBandwidth->lpIOQueue[1][HEAD])
                {
                    if (lpQueue[1][HEAD])
                    {
                        lpQueue[1][TAIL]->lpNext = lpBandwidth->lpIOQueue[1][HEAD];
                    }
                    else lpQueue[1][HEAD] = lpBandwidth->lpIOQueue[1][HEAD];
                    lpQueue[1][TAIL] = lpBandwidth->lpIOQueue[1][TAIL];
                    dwQueue[1] += lpBandwidth->dwIOQueue[1];
                }
                lpBandwidth->lpIOQueue[1][HEAD] = NULL;
                lpBandwidth->dwIOQueue[1] = 0;
                dwDownStream += (lpBandwidth->dwGlobalBandwidthLimit % dwSchedulerUpdateSpeed);
            }

            // Set downstream limit
            lpBandwidth->dwGlobalBandwidthLeft = (dwQueue[1] >= dwDownStream ? 0 : dwDownStream - dwQueue[1]);
            InterlockedExchange(&lpBandwidth->lLock, FALSE);

            dwUpStream = min(dwUpStream, dwQueue[0]);
            dwDownStream = min(dwDownStream, dwQueue[1]);
            if (!(dwQueue[0] -= dwUpStream) && dwUpStream) lpQueue[0][TAIL]->lpNext = NULL;
            if (!(dwQueue[1] -= dwDownStream) && dwDownStream) lpQueue[1][TAIL]->lpNext = NULL;

            // Release upstream queues
            for (; dwUpStream--;)
            {
                lpQueue[0][HEAD] = (lpOverlapped = lpQueue[0][HEAD])->lpNext;
                // Post continue notification to io thread
                PostQueuedCompletionStatus(hCompletionPort, 0, (ULONG_PTR)-2, (LPOVERLAPPED)lpOverlapped);
            }
            // Release downstream queues
            for (; dwDownStream--;)
            {
                lpQueue[1][HEAD] = (lpOverlapped = lpQueue[1][HEAD])->lpNext;
                // Post continue notification to io thread
                PostQueuedCompletionStatus(hCompletionPort, 0, (ULONG_PTR)-3, (LPOVERLAPPED)lpOverlapped);
            }

            // Add remaining queues for device
            lpDevice->Outbound.lpIOQueue[2][HEAD] = lpQueue[0][HEAD];
            lpDevice->Outbound.lpIOQueue[2][TAIL] = lpQueue[0][TAIL];
            lpDevice->Outbound.dwIOQueue[2] = dwQueue[0];
            lpDevice->Inbound.lpIOQueue[2][HEAD] = lpQueue[1][HEAD];
            lpDevice->Inbound.lpIOQueue[2][TAIL] = lpQueue[1][TAIL];
            lpDevice->Inbound.dwIOQueue[2] = dwQueue[1];
        }
        InterlockedExchange(&lSchedulerDeviceList, FALSE);

        // Sleep
        dwSleep = (DWORD)Time_DifferenceDW64(SafeGetTickCount64(), dwNextWakeUp);
        if (dwSleep <= (1000 / dwSchedulerUpdateSpeed))
        {
            Sleep(dwSleep);
        }
    }
    ExitThread(0);
}

SOCKET
OpenSocket()
{
    DWORD dwError;
    SOCKET s;

    AcquireHandleLock();
    // Wide-char version to avoid ANSI deprecation warnings
    s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);

    if (s == INVALID_SOCKET)
    {
        Putlog(LOG_ERROR, _T("Unable to create socket.\r\n"));
    }
    else if (!SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0))
    {
        dwError = GetLastError();
        Putlog(LOG_DEBUG, _T("SetHandleInformation failed: %lu\r\n"), dwError);
    }
    ReleaseHandleLock();

    // Do NOT force SO_LINGER here. Linger strategy is applied in CloseSocket based on bNoLinger.

    return s;
}

VOID
IoSocketInit(LPIOSOCKET lpSocket)
{
    if (!lpSocket->bInitialized)
    {
        InitializeCriticalSectionAndSpinCount(&lpSocket->csLock, 1000);
        lpSocket->bInitialized = TRUE;
    }
    lpSocket->Overlapped[0].hSocket = lpSocket;
    lpSocket->Overlapped[1].hSocket = lpSocket;
    lpSocket->Overlapped[0].lpProc = TransmitPackage_ReadSocket;
    lpSocket->Overlapped[1].lpProc = TransmitPackage_WriteSocket;
}

#if 0
// ... ioAsyncCallbackTest unchanged, omitted for brevity ...
#endif

BOOL
Socket_Init(BOOL bFirstInitialization)
{
    GUID            GuidAcceptEx = WSAID_ACCEPTEX;
    GUID            GuidGetAcceptExSockAddrs = WSAID_GETACCEPTEXSOCKADDRS;
    OSVERSIONINFO   VersionInfo;
    SOCKET          Socket;
    DWORD           dwThreadID, dwBytes, dwLastError;
    HANDLE          hThread;
    LPTSTR          tszSchedulerUpdateSpeed;
    BOOL            bLogErrors;

    bLogErrors = FALSE;
    Config_Get_Bool(&IniConfigFile, _TEXT("Network"), _TEXT("Log_OpenSSL_Transfer_Errors"), &bLogErrors);
    InterlockedExchange((LONG*)&bLogOpenSslErrors, bLogErrors);

    if (!bFirstInitialization) return TRUE;

    // Reset variables
    Accept = NULL;
    GetAcceptSockAddrs = NULL;
    pSelectList = NULL;
    lpSchedulerDeviceList = NULL;
    lSchedulerDeviceList = FALSE;
    dwSchedulerUpdateSpeed = 10;

    // Get windows version
    VersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    if (!GetVersionEx(&VersionInfo)) return FALSE;

    if ((tszSchedulerUpdateSpeed = Config_Get(&IniConfigFile, _TEXT("Network"), _TEXT("Scheduler_Update_Speed"), NULL, NULL)))
    {
        if (!_tcsnicmp(tszSchedulerUpdateSpeed, _TEXT("High"), 4))
        {
            dwSchedulerUpdateSpeed = 20;
        }
        else if (!_tcsnicmp(tszSchedulerUpdateSpeed, _TEXT("Low"), 3))
        {
            dwSchedulerUpdateSpeed = 4;
        }
        else if (!_tcsnicmp(tszSchedulerUpdateSpeed, _TEXT("Disabled"), 8))
        {
            dwSchedulerUpdateSpeed = 0;
        }
        Free(tszSchedulerUpdateSpeed);
    }

    // Initialize WinSock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData)) return FALSE;

    // Install event select handler
    if (!InitializeCriticalSectionAndSpinCount(&csSelectList, 50) ||
        !InstallMessageHandler(WM_ASYNC_CALLBACK, AsyncSelectProc, TRUE, TRUE)) return FALSE;

    if (dwSchedulerUpdateSpeed)
    {
        // Create socket scheduler
        hThread = CreateThread(NULL, 0, SocketSchedulerThread, NULL, 0, &dwThreadID);
        if (hThread == INVALID_HANDLE_VALUE) return FALSE;
        // Raise thread priority
        SetThreadPriority(hThread, THREAD_PRIORITY_HIGHEST);
        CloseHandle(hThread);
    }

    // Get AcceptEx & GetAcceptExSockAddrs addresses
    Socket = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);

    if (WSAIoctl(Socket,
        SIO_GET_EXTENSION_FUNCTION_POINTER,
        &GuidAcceptEx,
        sizeof(GuidAcceptEx),
        &Accept,
        sizeof(Accept),
        &dwBytes,
        NULL,
        NULL) == SOCKET_ERROR
        || WSAIoctl(Socket,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            &GuidGetAcceptExSockAddrs,
            sizeof(GuidGetAcceptExSockAddrs),
            &GetAcceptSockAddrs,
            sizeof(GetAcceptSockAddrs),
            &dwBytes,
            NULL,
            NULL) == SOCKET_ERROR)
    {
        dwLastError = GetLastError();
    }
    else
    {
        dwLastError = NO_ERROR;
    }
    closesocket(Socket);

    if (dwLastError != NO_ERROR || !Accept || !GetAcceptSockAddrs)
        ERROR_RETURN(dwLastError ? dwLastError : ERROR_INVALID_FUNCTION, FALSE);

#if 0
    dwDeadlockPort = 0;
    DeadlockSocket = INVALID_SOCKET;;
    if (!Config_Get_Int(&IniConfigFile, _TEXT("Network"), _TEXT("Deadlock_Port"), (PINT)&dwDeadlockPort) && dwDeadlockPort)
    {
        DeadlockSocket = OpenSocket();
        if (DeadlockSocket == INVALID_SOCKET)
        {
            dwLastError = WSAGetLastError();
            ERROR_RETURN(dwLastError, FALSE);
        }
        // Listen socket
        if (listen(DeadlockSocket, SOMAXCONN))
        {
            dwLastError = WSAGetLastError();
            closesocket(DeadlockSocket);
            ERROR_RETURN(dwLastError, FALSE);
        }
    }
#endif
    return TRUE;
}

VOID Socket_DeInit(VOID)
{
    DWORD dwError;

    // Disarm and free any remaining event nodes.
    // Stop new events while holding the lock, then release before the blocking
    // UnregisterWaitEx calls so that any in-flight SelectEventWaitCallback can
    // acquire csSelectList and exit cleanly before we free the nodes.
    {
        PSELECT_EVENT_NODE pSnapshot;
        EnterCriticalSection(&csSelectList);
        for (PSELECT_EVENT_NODE n = g_pEventListHead; n; n = n->pNext) {
            WSAEventSelect(n->Socket, NULL, 0);  // stop new socket events immediately
        }
        pSnapshot = g_pEventListHead;
        g_pEventListHead = NULL;
        LeaveCriticalSection(&csSelectList);

        for (PSELECT_EVENT_NODE n = pSnapshot, next; n; n = next) {
            next = n->pNext;
            if (n->hWait) UnregisterWaitEx(n->hWait, INVALID_HANDLE_VALUE);  // blocking
            if (n->hEvent != WSA_INVALID_EVENT) WSACloseEvent(n->hEvent);
            Free(n);
        }
    }

    // Free resources
    if (WSACleanup())
    {
        dwError = WSAGetLastError();
        Putlog(LOG_ERROR, "WSACleanup reported error #%d\r\n", dwError);
    }
    DeleteCriticalSection(&csSelectList);
}
