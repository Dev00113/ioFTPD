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

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <Windows.h>
#include <ioFTPD.h>

#pragma comment(lib, "Kernel32.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Mswsock.lib")

 // NOTE: We want all I/O operations on sockets to be performed by the IO Threads.
 // This ensures that when a worker thread exits (only happens when one created on
 // demand because too few were defined) there are no outstanding I/O operations
 // in progress.  Even using completion ports, I believe the thread that started
 // the overlapped operation cannot exit without it being interrupted.  This is
 // arranged by simplying posting a -1 (max DWORD) bytes transferred to the
 // completion port so that when the callback routine gets that it knows to make
 // the request...

 // clear->SSL transitions on control channel only occur when there are no
 // outstanding overlapped requests.  In particular the 2 cases are:
 //  1) Implicit SSL socket - happens immediately after connection of control
 //     channel before any data send or requested.
 //  2) AUTH SSL/TLS - ReceiveLine callback in progress means no active read
 //     request because we won't start another one until FTP_Command finishes
 //     sending the output of the command and the last package of that is to
 //     enable encryption...
 // 
 // There is currently no method of SSL->clear supported though the RFC does
 // describe one.  However case #2 would still apply and a simple shutdown of
 // the SSL connection (making sure not to read more data than openSSL requested)
 // and then switching over to the plain read/write functions would work.

 // The trickiest problem is handling openSSL's protocol read requests during
 // file transfers because the server outputs one immediate response, listens
 // for commands, and then outputs another response.  Without a data transfer in
 // progress it's always read->response->read (except for the initial line upon
 // connection) and either a read or a write is taking place but never both so
 // any requests by openSSL to perform the other operation don't interfere with
 // anything.  However, during the 2nd response from a file transfer the client
 // could be doing a read and a write at the same time!
 //
 // This means we must now lock protect the BIO and SSL objects because they are
 // not thread safe and we can't guarantee to be only doing one thing at a time.
 // Even worse, if the client requests a key re-negotiation (I've never seen
 // that at any time!) we could be forced into arbitrarily sending/receiving
 // data...  That would be really tricky.  I'm not sure the code handles that,
 // but it does detect the situation in the logfile so we can figure out if we
 // do need to handle it...
 //

 // Modern half-close helper (replaces deprecated WSASendDisconnect)
static __inline void Socket_HalfCloseSend(SOCKET s)
{
    // Best-effort half-close; ignore errors.
    shutdown(s, SD_SEND);
}

// Atomically read lpSocket->lpSecure and increment its reference count.
// Returns the SECURITY pointer (with refcount bumped), or NULL if the socket
// has no TLS context or ioCloseSocket has already nulled the pointer.
// The caller MUST call Security_Release() when done, unless this returns NULL.
// We hold lpSocket->csLock only for the pointer read + increment, then release
// it before acquiring lpSecure->csLock, preserving the documented lock order:
//   SECURITY.csLock (outer) -> IOSOCKET.csLock (inner).
static __inline LPSECURITY Security_Acquire(LPIOSOCKET lpSocket)
{
    LPSECURITY lpSecure;
    EnterCriticalSection(&lpSocket->csLock);
    lpSecure = lpSocket->lpSecure;
    if (lpSecure) InterlockedIncrement(&lpSecure->lRefCount);
    LeaveCriticalSection(&lpSocket->csLock);
    return lpSecure;
}

static BOOL TransmitPackages_Update(LPPACKAGETRANSFER lpTransfer, BOOL bIoCallback);

// Now returns the OpenSSL error in the callback...
static BOOL
TransmitPackages_Callback(LPPACKAGETRANSFER lpTransfer)
{
    BOOL bNoFree;

    // in the case of a kick/kill/shutdown/etc which forces the socket closed it's possible this
    // have been the last job and thus FTP_Close_Connection gets called which cleans everything
    // up including us if we are processing a quick send / receive line.  These are marked bNoFree
    // so that isn't a problem, but we must test for that BEFORE calling the callback as it may
    // be invalid afterwords...
    bNoFree = lpTransfer->bNoFree;

    lpTransfer->lpCallBack(lpTransfer->lpContext, lpTransfer->dwLastError, lpTransfer->i64Total, lpTransfer->ulOpenSslError);
    if (!bNoFree)
    {
        Free(lpTransfer);
    }
    return FALSE;
}

static
BOOL TransmitPackages_Complete(LPPACKAGETRANSFER lpTransfer)
{
    // Fix #6: CAS gate — if two IOCP cancellation completions arrive simultaneously
    // (e.g. both recv and send overlapped cancelled when CloseSocket is called during
    // an ABOR), only the first call queues the callback.  The second is silently
    // dropped.  lCompleted is initialised to 0 by ZeroMemory in the callers; the CAS
    // atomically sets it to 1 and returns 0 only on the first call.
    //
    // bNoFree transfers (ReceiveLine control channel, SendQuick) are allocated once
    // and reused for every operation on the socket.  Their lCompleted is never reset
    // between uses, so the CAS gate must be bypassed for them — otherwise every
    // completion after the first would be silently dropped, causing the control
    // channel to stop responding (421 Timeout regression).
    if (!lpTransfer->bNoFree && InterlockedCompareExchange(&lpTransfer->lCompleted, 1, 0) != 0)
        return FALSE;   // already completing on another thread

    if (lpTransfer->lpTimer) StopIoTimer(lpTransfer->lpTimer, FALSE);
    if (lpTransfer->dwBuffer)
    {
        //  Free allocated buffers
        if (lpTransfer->lpIoBuffer->bAllocated) Free(lpTransfer->lpIoBuffer->buf);
    }
    QueueJob(TransmitPackages_Callback, lpTransfer, JOB_PRIORITY_NORMAL);
    return FALSE;
}

static
VOID TransmitPackages_Continue(LPPACKAGETRANSFER lpTransfer)
{
    if (lpTransfer->lpContinueProc)
    {
        (lpTransfer->lpContinueProc)(lpTransfer, (DWORD)-1, NO_ERROR);
        return;
    }
    TransmitPackages_Update(lpTransfer, TRUE);
}

static
VOID TransmitPackages_Error(LPPACKAGETRANSFER lpTransfer, DWORD dwLastError)
{
    CHAR szBuf[512], * szError;
    unsigned long err;
    int i;

    // Fix #5: if the timer fired first it set bTimedOut via InterlockedExchange.
    // The IOCP error that arrives after CloseSocket is typically ERROR_OPERATION_ABORTED;
    // we override it with WSAETIMEDOUT so callers see the real reason.
    if (InterlockedOr((LONG*)&lpTransfer->bTimedOut, 0))
        dwLastError = WSAETIMEDOUT;

    lpTransfer->dwLastError = dwLastError;
    if (dwLastError == IO_SSL_FAIL)
    {
        if (!(lpTransfer->ulOpenSslError = ERR_get_error()))
        {
            Putlog(LOG_DEBUG, _T("OpenSSL error: <non-recorded>.\r\n"));
        }
        else if (bLogOpenSslErrors)
        {
            ERR_error_string_n(lpTransfer->ulOpenSslError, szBuf, sizeof(szBuf));
            szError = szBuf;
            if (szError)
            {
                Putlog(LOG_DEBUG, _T("OpenSSL error: %s\r\n"), szError);
            }
            else
            {
                Putlog(LOG_DEBUG, _T("OpenSSL error: #%d\r\n"), lpTransfer->ulOpenSslError);
            }
        }

        // now flush anything left on this threads error queue...
        for (i = 2; (err = ERR_get_error()); i++)
        {
            ERR_error_string_n(err, szBuf, sizeof(szBuf));
            szError = szBuf;
            if (szError)
            {
                Putlog(LOG_DEBUG, _T("OpenSSL error%d: %s\r\n"), i, szError);
            }
            else
            {
                Putlog(LOG_DEBUG, _T("OpenSSL error%d: #%d\r\n"), i, lpTransfer->ulOpenSslError);
            }
        }
    }
    TransmitPackages_Complete(lpTransfer);
}

static
VOID TransmitPackages_Closed(LPPACKAGETRANSFER lpTransfer)
{
    // should only happen once...
    lpTransfer->bClosed = TRUE;

    // call the completion proc in case it needs to do something like finish
    // write to a file, etc or else call the complete routine...
    if (lpTransfer->lpContinueProc)
    {
        (lpTransfer->lpContinueProc)(lpTransfer, (DWORD)-1, NO_ERROR);
        return;
    }
    TransmitPackages_Update(lpTransfer, TRUE);
}

static
DWORD TransmitPackage_Timer(LPPACKAGETRANSFER lpTransfer, LPTIMER lpTimer)
{
    ULONGLONG  dwReturn;

    //  Calculate timeout
    dwReturn = Time_DifferenceDW64(lpTransfer->dwTime, SafeGetTickCount64());

    if ((dwReturn + 100) >= lpTransfer->lpIoBuffer->dwTimeOut)
    {
        if (lpTransfer->dwLastError != NO_ERROR)
        {
            Putlog(LOG_DEBUG, "SOCKET: Timeout on socket with existing error id=0x%X error=%d\r\n",
                lpTransfer->lpSocket->Socket, lpTransfer->dwLastError);
        }

        //  Cancel pending IO
        switch (lpTransfer->lpIoBuffer->dwType)
        {
#if 0
        case PACKAGE_FILE_RECEIVE:
        case PACKAGE_FILE_SEND:
        case PACKAGE_BUFFER_SEND:
        case PACKAGE_LIST_BUFFER_SEND:
        case PACKAGE_BUFFER_RECEIVE:
        case PACKAGE_SSL_CLOSE:
        case PACKAGE_SSL_ACCEPT:
        case PACKAGE_SSL_CONNECT:
#endif
        default:
            // Fix #5: mark timeout BEFORE CloseSocket so the IOCP error callback sees it.
            // Do NOT write dwLastError here — that write could race with Free(lpTransfer)
            // if the callback runs and frees the struct before we return from CloseSocket.
            // TransmitPackages_Error checks bTimedOut and maps the error to WSAETIMEDOUT.
            InterlockedExchange((LONG*)&lpTransfer->bTimedOut, TRUE);
        case PACKAGE_SHUTDOWN:
            CloseSocket(lpTransfer->lpSocket, TRUE);
            break;
        }
        return 0;
    }
    return lpTransfer->lpIoBuffer->dwTimeOut - (DWORD)dwReturn;
}

VOID TransmitPackages(LPIOSOCKET lpSocket, LPIOBUFFER lpBuffer, DWORD dwBuffer, VOID(*lpTransferRateCallBack)(LPVOID, ULONGLONG, ULONGLONG, ULONGLONG), VOID(*lpCallBack)(LPVOID, DWORD, INT64, ULONG), LPVOID lpContext)
{
    LPPACKAGETRANSFER   lpTransfer;
    ULONGLONG           dwTickCount;

    //  Allocate memory
    lpTransfer = (LPPACKAGETRANSFER)Allocate("TransmitPackage",
        sizeof(IOBUFFER) * dwBuffer + sizeof(PACKAGETRANSFER) + (lpTransferRateCallBack ? sizeof(TRANSFERRATE) : 0));
    if (!lpTransfer)
    {
        lpCallBack(lpContext, ERROR_NOT_ENOUGH_MEMORY, 0, 0);
        return;
    }

    ZeroMemory(lpTransfer, sizeof(*lpTransfer) + sizeof(IOBUFFER) * dwBuffer + (lpTransferRateCallBack ? sizeof(TRANSFERRATE) : 0));
    dwTickCount = SafeGetTickCount64();
    lpTransfer->dwTime = dwTickCount;
    lpTransfer->dwLastError = NO_ERROR;
    lpTransfer->lpCallBack = lpCallBack;
    lpTransfer->lpContext = lpContext;
    lpTransfer->lpSocket = lpSocket;

    lpTransfer->lpIoBuffer = (LPIOBUFFER)&lpTransfer[1];
    lpTransfer->dwBuffer = dwBuffer;
    CopyMemory(lpTransfer->lpIoBuffer, lpBuffer, sizeof(IOBUFFER) * dwBuffer);

    lpTransfer->lpIoBuffer->bProcessed = FALSE;
    lpTransfer->lpIoBuffer->bAllocated = FALSE;

    if (lpTransferRateCallBack)
    {
        lpTransfer->lpTransferRate = (LPTRANSFERRATE)((ULONG_PTR)&lpTransfer[1] + sizeof(IOBUFFER) * dwBuffer);

        lpTransfer->lpTransferRate->dwTickCount = dwTickCount;
        lpTransfer->lpTransferRate->dwBytesTransferred = 0;
        lpTransfer->lpTransferRate->lpCallBack = lpTransferRateCallBack;
    }
    else lpTransfer->lpTransferRate = NULL;

    //  Callback is being called after this point
    TransmitPackages_Update(lpTransfer, FALSE);
}

static __inline
VOID TransmitPackagePerTransmit(LPPACKAGETRANSFER lpTransfer, DWORD dwBytesTransferred)
{
    LPTRANSFERRATE  lpTransferRate;
    ULONGLONG       dwDifference, dwTickCount;

    if (lpTransfer->lpIoBuffer->dwTimerType == NO_TIMER) return;

    lpTransferRate = lpTransfer->lpTransferRate;
    //  Get system tickcount, if necessary
    if (lpTransfer->lpIoBuffer->dwTimerType == TIMER_PER_TRANSMIT)
    {
        dwTickCount = SafeGetTickCount64();
        //  Reset TIMER_PER_TRANSMIT type timer
        lpTransfer->dwTime = dwTickCount;
        if (!lpTransferRate) return;
    }
    else if (lpTransferRate)
    {
        dwTickCount = SafeGetTickCount64();
    }
    else return;

    //  Update transferrate counter
    lpTransferRate->dwBytesTransferred += dwBytesTransferred;
    dwDifference = Time_DifferenceDW64(lpTransferRate->dwTickCount, dwTickCount);
    //  Call callback, if interval between last update is longer than 100 milliseconds
    if (dwDifference >= 100 && dwBytesTransferred > 0)
    {
        lpTransferRate->lpCallBack(lpTransfer->lpContext, lpTransferRate->dwBytesTransferred, dwDifference, dwTickCount);
        lpTransferRate->dwBytesTransferred = 0;
        lpTransferRate->dwTickCount = dwTickCount;
    }
}

static VOID
TransmitPackage_ReadSecure(LPPACKAGETRANSFER lpTransfer, DWORD dwBytesRead, DWORD dwLastError)
{
    LPIOSOCKET          lpSocket;
    LPIOBUFFER          lpIoBuffer;
    LPSECURITY          lpSecure;
    LPSOCKETOVERLAPPED  lpOverlapped;
    int                 iNum, iErr;
    DWORD               dwError;
    unsigned long       ulErr;
    HANDLE              hThread;

    if ((dwBytesRead != (DWORD)-1) && dwBytesRead)
    {
        lpTransfer->i64Total += dwBytesRead;
        TransmitPackagePerTransmit(lpTransfer, dwBytesRead);
    }

    //  Handle transfer error
    if (dwLastError != NO_ERROR)
    {
        TransmitPackages_Error(lpTransfer, dwLastError);
        return;
    }

    lpSocket = lpTransfer->lpSocket;
    // Safely addref lpSecure so ioCloseSocket cannot free SSL under us.
    // If the socket was already closed (lpSecure==NULL) bail out cleanly.
    lpSecure = Security_Acquire(lpSocket);
    if (!lpSecure)
    {
        TransmitPackages_Error(lpTransfer, ERROR_OPERATION_ABORTED);
        return;
    }
    lpIoBuffer = lpTransfer->lpIoBuffer;
    lpOverlapped = &lpSocket->Overlapped[0];

    EnterCriticalSection(&lpSecure->csLock);

    if (dwBytesRead != (DWORD)-1)
    {
        // ok, we wrote something directly into the BIO, update the BIO with it's size first.
        if (dwBytesRead)
        {
            if (BIO_nwrite(lpSecure->NetworkBio, &lpOverlapped->Buffer.buf, dwBytesRead) <= 0)
            {
                LeaveCriticalSection(&lpSecure->csLock);
                Security_Release(lpSecure);
                TransmitPackages_Error(lpTransfer, IO_SSL_FAIL);
                return;
            }
        }
        else
        {
            // end of stream, this is the last call...
            lpTransfer->bClosed = TRUE;
        }
    }

    hThread = GetCurrentThread();
    // Removed thread priority changes (no measurable benefit, can hurt fairness)

    do {
        // now figure out how many bytes of the stream we actually got (there might by crypto overhead, checksums, etc)
        iNum = SSL_read(lpSecure->SSL, &lpIoBuffer->buf[lpIoBuffer->offset], lpIoBuffer->len - lpIoBuffer->offset);

        if (!SSL_is_init_finished(lpSecure->SSL))
        {
            Putlog(LOG_DEBUG, "SSL/TSL re-negotiation requested.\r\n");
        }

        if (iNum > 0)
        {
            if (((lpIoBuffer->offset += iNum) == lpIoBuffer->len) || (lpIoBuffer->ReturnAfter && (lpIoBuffer->offset >= lpIoBuffer->ReturnAfter)))
            {
                // all done filling up this buffer, or immediate return requested
                LeaveCriticalSection(&lpSecure->csLock);
                Security_Release(lpSecure);
                TransmitPackages_Continue(lpTransfer);
                return;
            }
            // we need to read more data or request more data, don't know yet...
            continue;
        }
        else
        {
            iErr = SSL_get_error(lpSecure->SSL, iNum);
            if (iErr == SSL_ERROR_WANT_READ)
            {
                // this is the commonly hoped for case... we need to request more data!
                break;
            }
            if (iErr == SSL_ERROR_WANT_WRITE)
            {
                // Fix #7: SSL needs to send data (e.g. TLS 1.2 re-key) before we can
                // continue reading.  Flush whatever SSL_read placed in the write BIO,
                // then loop back — the next SSL_read call will continue from here.
                Putlog(LOG_DEBUG, "SSL read wanted to write — flushing write BIO.\r\n");
                {
                    LPSOCKETOVERLAPPED lpSendOv = lpTransfer->bQuick
                        ? &lpSocket->SQ.Overlapped
                        : &lpSocket->Overlapped[1];
                    int iSendNum = BIO_nread0(lpSecure->NetworkBio, &lpSendOv->Buffer.buf);
                    if (iSendNum > 0)
                    {
                        lpSendOv->Buffer.len = (ULONG)iSendNum;
                        if (SendOverlapped(lpSocket, lpSendOv))
                        {
                            LeaveCriticalSection(&lpSecure->csLock);
                            Security_Release(lpSecure);
                            TransmitPackages_Error(lpTransfer, WSAGetLastError());
                            return;
                        }
                        // Send posted; we'll be called back on completion and retry SSL_read.
                        LeaveCriticalSection(&lpSecure->csLock);
                        Security_Release(lpSecure);
                        return;
                    }
                }
                // Nothing to flush; fall through to post a new network read below.
                break;
            }
            if (iErr == SSL_ERROR_ZERO_RETURN)
            {
                // we got a close notification...
                lpTransfer->bClosed = TRUE;
                LeaveCriticalSection(&lpSecure->csLock);
                Security_Release(lpSecure);
                TransmitPackages_Continue(lpTransfer);
                return;
            }
            else if (iErr == SSL_ERROR_SSL)
            {
                if ((ulErr = ERR_peek_error()) == 0)
                {
                    // we got an EOF that violated the protocol, just close up...
                    lpTransfer->bClosed = TRUE;
                    LeaveCriticalSection(&lpSecure->csLock);
                    Security_Release(lpSecure);
                    TransmitPackages_Continue(lpTransfer);
                    return;
                }
            }
            // something bad happened
            LeaveCriticalSection(&lpSecure->csLock);
            Security_Release(lpSecure);
            TransmitPackages_Error(lpTransfer, IO_SSL_FAIL);
            return;
        }
    } while (1);

    if (lpTransfer->bClosed)
    {
        // we're finished...
        LeaveCriticalSection(&lpSecure->csLock);
        Security_Release(lpSecure);
        TransmitPackages_Continue(lpTransfer);
        return;
    }

    // Find out where to write directly into the bio so we don't have to copy it in later.
    iNum = BIO_nwrite0(lpSecure->NetworkBio, &lpOverlapped->Buffer.buf);
    LeaveCriticalSection(&lpSecure->csLock);
    if (iNum <= 0)
    {
        Security_Release(lpSecure);
        TransmitPackages_Error(lpTransfer, IO_SSL_FAIL);
        return;
    }
    lpOverlapped->Buffer.len = (ULONG)iNum;

    if (ReceiveOverlapped(lpSocket, lpOverlapped))
    {
        dwError = WSAGetLastError();
        Security_Release(lpSecure);
        if (dwError == WSAECONNRESET)
        {
            // the socket was closed on the other side, close gracefully...
            TransmitPackages_Closed(lpTransfer);
            return;
        }
        TransmitPackages_Error(lpTransfer, dwError);
        return;
    }
    // WSARecv posted successfully; next callback will call Security_Acquire again.
    Security_Release(lpSecure);
}

// Read from socket until buffer full or we get anything if bReceiveAny is set then call
// TransmitPackage_Continue to process the data or go onto the next package.
VOID
TransmitPackage_ReadSocket(LPPACKAGETRANSFER lpTransfer, DWORD dwBytesRead, DWORD dwLastError)
{
    LPIOSOCKET          lpSocket;
    LPIOBUFFER          lpIoBuffer;
    LPSOCKETOVERLAPPED  lpOverlapped;
    DWORD               dwError;

    if ((dwBytesRead != (DWORD)-1) && dwBytesRead)
    {
        lpTransfer->i64Total += dwBytesRead;
        TransmitPackagePerTransmit(lpTransfer, dwBytesRead);
    }

    //  Handle transfer error
    if (dwLastError != NO_ERROR)
    {
        TransmitPackages_Error(lpTransfer, dwLastError);
        return;
    }

    //  Handle end of stream
    if (!dwBytesRead)
    {
        TransmitPackages_Closed(lpTransfer);
        return;
    }

    lpIoBuffer = lpTransfer->lpIoBuffer;

    if (dwBytesRead != (DWORD)-1)
    {
        if (((lpIoBuffer->offset += dwBytesRead) == lpIoBuffer->len) || (lpIoBuffer->offset >= lpIoBuffer->ReturnAfter))
        {
            // all done filling up this buffer, or immediate return requested
            TransmitPackages_Continue(lpTransfer);
            return;
        }
    }

    // we need more input, so request it...
    lpSocket = lpTransfer->lpSocket;
    lpOverlapped = &lpSocket->Overlapped[0];

    lpOverlapped->Buffer.len = lpIoBuffer->len - lpIoBuffer->offset;
    lpOverlapped->Buffer.buf = &lpIoBuffer->buf[lpIoBuffer->offset];

    if (ReceiveOverlapped(lpSocket, lpOverlapped))
    {
        dwError = WSAGetLastError();
        if (dwError == WSAECONNRESET)
        {
            // the socket was closed on the other side, close gracefully...
            // Or we forced it close because of a timeout and it just happened
            TransmitPackages_Closed(lpTransfer);
            return;
        }
        TransmitPackages_Error(lpTransfer, dwError);
    }
}

// Take the buffer, encrypt the contents and send it.  It may require reading/writing additional
// data to the socket to perform a SSL handshake or re-negotiation and thus it is possible that
// multiple calls to try and encrypt the buffer will be necessary.  After each call flush anything
// in the network bio write buffer and if requested read data in from the socket and store it in
// the network bio before trying to encrypt the remaining contents of the original buffer again.
// The lpIoBuffer will track progress in encrypting the original buffer, the network bio will be
// use do the actual read/writes to the socket.
static VOID
TransmitPackage_WriteSecure(LPPACKAGETRANSFER lpTransfer, DWORD dwBytesWritten, DWORD dwLastError)
{
    LPIOSOCKET          lpSocket;
    LPIOBUFFER          lpIoBuffer;
    LPSECURITY          lpSecure;
    LPSOCKETOVERLAPPED  lpOverlapped;
    int                 iNum, iErr;

    if ((dwBytesWritten != (DWORD)-1) && dwBytesWritten)
    {
        lpTransfer->i64Total += dwBytesWritten;
        TransmitPackagePerTransmit(lpTransfer, dwBytesWritten);
    }

    //  Handle transfer error
    if (dwLastError != NO_ERROR)
    {
        TransmitPackages_Error(lpTransfer, dwLastError);
        return;
    }

    //  Handle end of stream
    if (!dwBytesWritten)
    {
        // is this even possible?
        TransmitPackages_Closed(lpTransfer);
        return;
    }

    lpSocket = lpTransfer->lpSocket;
    // Safely addref lpSecure — same pattern as TransmitPackage_ReadSecure.
    lpSecure = Security_Acquire(lpSocket);
    if (!lpSecure)
    {
        TransmitPackages_Error(lpTransfer, ERROR_OPERATION_ABORTED);
        return;
    }
    lpIoBuffer = lpTransfer->lpIoBuffer;

    EnterCriticalSection(&lpSecure->csLock);

    if (dwBytesWritten != (DWORD)-1)
    {
        // we wrote something...
        if (BIO_nread(lpSecure->NetworkBio, NULL, (int)dwBytesWritten) <= 0)
        {
            LeaveCriticalSection(&lpSecure->csLock);
            Security_Release(lpSecure);
            TransmitPackages_Error(lpTransfer, IO_SSL_FAIL);
            return;
        }
    }

    if (lpIoBuffer->offset != lpIoBuffer->len)
    {
        // encrypt the buffer so we can write out whatever it spits out into the bio..
        iNum = SSL_write(lpSecure->SSL, &lpIoBuffer->buf[lpIoBuffer->offset], lpIoBuffer->len - lpIoBuffer->offset);

        if (!SSL_is_init_finished(lpSecure->SSL))
        {
            Putlog(LOG_ERROR, "SSL/TSL re-negotiation requested.\r\n");
        }

        // Observe pending data in BIO (optional debug)
        iErr = BIO_pending(lpSecure->NetworkBio);
        (void)iErr;

        if (iNum > 0)
        {
            // check to see if we encrypted it all.
            if ((lpIoBuffer->offset += iNum) != lpIoBuffer->len)
            {
                LeaveCriticalSection(&lpSecure->csLock);
                Security_Release(lpSecure);
                TransmitPackages_Error(lpTransfer, IO_SSL_FAIL2);
                return;
            }
            // now go write the encrypted contents in the bio below...
        }
        else
        {
            iErr = SSL_get_error(lpSecure->SSL, iNum);
            if (iErr == SSL_ERROR_WANT_READ)
            {
                // Fix #7: SSL needs incoming data (e.g. TLS 1.2 re-key response) before
                // it can encrypt more application data.  Post a receive into the BIO;
                // the read completion callback will call SSL_write again via WriteSecure.
                Putlog(LOG_DEBUG, "SSL write wanted to read — posting network receive.\r\n");
                {
                    // Use Overlapped[0] (the recv slot) — lpOverlapped (send slot)
                    // is not assigned until further below; using it here would be UB.
                    LPSOCKETOVERLAPPED lpRecvOv = &lpSocket->Overlapped[0];
                    int iRecvNum = BIO_nwrite0(lpSecure->NetworkBio, &lpRecvOv->Buffer.buf);
                    if (iRecvNum > 0)
                    {
                        lpRecvOv->Buffer.len = (ULONG)iRecvNum;
                        if (ReceiveOverlapped(lpSocket, lpRecvOv))
                        {
                            LeaveCriticalSection(&lpSecure->csLock);
                            Security_Release(lpSecure);
                            TransmitPackages_Error(lpTransfer, WSAGetLastError());
                            return;
                        }
                        LeaveCriticalSection(&lpSecure->csLock);
                        Security_Release(lpSecure);
                        return;
                    }
                }
                // BIO full; fall through and try flushing the write BIO below.
            }
            else if (iErr == SSL_ERROR_ZERO_RETURN)
            {
                // we got a close notification...
                lpTransfer->bClosed = TRUE;
                LeaveCriticalSection(&lpSecure->csLock);
                Security_Release(lpSecure);
                TransmitPackages_Continue(lpTransfer);
                return;
            }
            else if (iErr != SSL_ERROR_WANT_WRITE)
            {
                LeaveCriticalSection(&lpSecure->csLock);
                Security_Release(lpSecure);
                TransmitPackages_Error(lpTransfer, IO_SSL_FAIL);
                return;
            }
            // just go ahead and write something...
        }
    }

    if (lpTransfer->bQuick)
    {
        lpOverlapped = &lpSocket->SQ.Overlapped;
    }
    else
    {
        lpOverlapped = &lpSocket->Overlapped[1];
    }

    // Fix #4: hold csLock from BIO_nread0 through SendOverlapped.
    // BIO_nread0 returns a BORROWED pointer into OpenSSL's internal ring buffer.
    // Releasing the lock before SendOverlapped allows a concurrent SSL_read (which
    // can acquire csLock and drive a TLS 1.2 re-negotiation) to overwrite the ring
    // buffer while Winsock is still reading from the pointer — use-after-free / data
    // corruption.  SendOverlapped acquires ioSocket.csLock internally; the safe lock
    // order is csLock -> ioSocket.csLock, which is the same order used everywhere else.
    iNum = BIO_nread0(lpSecure->NetworkBio, &lpOverlapped->Buffer.buf);
    if (iNum == -1)
    {
        // we're done
        LeaveCriticalSection(&lpSecure->csLock);
        Security_Release(lpSecure);
        TransmitPackages_Continue(lpTransfer);
        return;
    }
    if (iNum <= 0)
    {
        LeaveCriticalSection(&lpSecure->csLock);
        Security_Release(lpSecure);
        TransmitPackages_Error(lpTransfer, IO_SSL_FAIL);
        return;
    }
    lpOverlapped->Buffer.len = (ULONG)iNum;

    if (SendOverlapped(lpSocket, lpOverlapped))
    {
        LeaveCriticalSection(&lpSecure->csLock);
        Security_Release(lpSecure);
        TransmitPackages_Error(lpTransfer, WSAGetLastError());
        return;
    }
    LeaveCriticalSection(&lpSecure->csLock);
    // WSASend posted successfully; next callback will call Security_Acquire again.
    Security_Release(lpSecure);
}

// Write contents of buffer until finished then call TransmitPackage_Continue to prepare more
// data for sending, or go onto the next package...
VOID
TransmitPackage_WriteSocket(LPPACKAGETRANSFER lpTransfer, DWORD dwBytesWritten, DWORD dwLastError)
{
    LPIOSOCKET          lpSocket;
    LPIOBUFFER          lpIoBuffer;
    LPSOCKETOVERLAPPED  lpOverlapped;

    if ((dwBytesWritten != (DWORD)-1) && dwBytesWritten)
    {
        lpTransfer->i64Total += dwBytesWritten;
        TransmitPackagePerTransmit(lpTransfer, dwBytesWritten);
    }

    //  Handle transfer error
    if (dwLastError != NO_ERROR)
    {
        TransmitPackages_Error(lpTransfer, dwLastError);
        return;
    }

    //  Handle end of stream
    if (!dwBytesWritten)
    {
        TransmitPackages_Closed(lpTransfer);
        return;
    }

    lpIoBuffer = lpTransfer->lpIoBuffer;

    if (dwBytesWritten != (DWORD)-1)
    {
        if ((lpIoBuffer->offset += dwBytesWritten) == lpIoBuffer->len)
        {
            // all done sending the buffer
            TransmitPackages_Continue(lpTransfer);
            return;
        }
    }

    // we have stuff to write out...
    lpSocket = lpTransfer->lpSocket;
    if (lpTransfer->bQuick)
    {
        lpOverlapped = &lpSocket->SQ.Overlapped;
    }
    else
    {
        lpOverlapped = &lpSocket->Overlapped[1];
    }

    lpOverlapped->Buffer.len = lpIoBuffer->len - lpIoBuffer->offset;
    lpOverlapped->Buffer.buf = &lpIoBuffer->buf[lpIoBuffer->offset];

    if (SendOverlapped(lpSocket, lpOverlapped))
    {
        // error occurred
        TransmitPackages_Error(lpTransfer, WSAGetLastError());
    }
}

// Called via the lpProc callback for [Secure]WriteSocket when it has finished
// sending the contents of the old buffer.  We generate a new one and request it be
// sent and if the last then remove the callback.
static VOID
TransmitPackage_SendListBuffer(LPPACKAGETRANSFER lpTransfer,
    DWORD dwBytesWritten, DWORD dwLastError)
{
    // Very special case... we know context passed to transmit package was an FTPUSER
    LPFTPUSER  lpUser = (LPFTPUSER)lpTransfer->lpContext;
    LPIOBUFFER lpIoBuffer;

    // Fix #9: an admin kick/kill sets U_KILL or U_LOGOFF on the connection and then
    // calls FTP_Close_Connection from a worker thread, which can free
    // lpUser->DataChannel.Buffer.buf while this I/O callback is still reading it.
    // Bail out immediately if the user is being terminated so we never touch freed memory.
    if (!lpUser || (lpUser->Connection.dwStatus & (U_KILL | U_LOGOFF)))
    {
        TransmitPackages_Error(lpTransfer, ERROR_OPERATION_ABORTED);
        return;
    }

    //  Handle transfer error
    if (dwLastError != NO_ERROR)
    {
        TransmitPackages_Error(lpTransfer, dwLastError);
        return;
    }

    if (lpTransfer->bClosed)
    {
        TransmitPackages_Update(lpTransfer, TRUE);
    }

    if ((dwBytesWritten != (DWORD)-1) || !lpUser || !lpUser->Listing)
    {
        // shouldn't be called any other way...
        TransmitPackages_Error(lpTransfer, ERROR_INVALID_ARGUMENTS);
        return;
    }

    // hey, there's more stuff to send after we generate it...
    lpIoBuffer = lpTransfer->lpIoBuffer;

    // clear old contents
    lpUser->DataChannel.Buffer.len = 0;

    // generate new listings
    FTP_ContinueListing(lpUser);

    lpIoBuffer->buf = lpUser->DataChannel.Buffer.buf;
    lpIoBuffer->size = lpUser->DataChannel.Buffer.size;
    lpIoBuffer->len = lpUser->DataChannel.Buffer.len;
    lpIoBuffer->offset = 0;

    if (!lpIoBuffer->len)
    {
        // nothing more to send...
        TransmitPackages_Update(lpTransfer, TRUE);
        return;
    }

    if (!lpUser->Listing)
    {
        // this is the last one to send, so no need to call us again
        lpTransfer->lpContinueProc = NULL;
    }

    (lpTransfer->lpSocket->Overlapped[1].lpProc)(lpTransfer, (DWORD)-1, NO_ERROR);
    return;
}

// When dwBytesRead == -1 it means we are just starting out and need to fill up the read
// buffer and send it, or called via lpProc callback from [Secure]WriteSocket when the
// connection was closed or it finished sending the buffer.  Otherwise the result is
// from the file overlapped request we made and we need to handle it normally.
static VOID
TransmitPackage_ReadFile(LPPACKAGETRANSFER lpTransfer, DWORD dwBytesRead, DWORD dwLastError)
{
    LPFILEOVERLAPPED lpOverlapped;
    LPIOBUFFER lpIoBuffer;

    //  Handle read error/EOF
    if (dwLastError != NO_ERROR)
    {
        if (dwLastError != ERROR_HANDLE_EOF)
        {
            TransmitPackages_Error(lpTransfer, dwLastError);
            return;
        }
        // We hit the end of file.  Windows always returns an error with 0 bytes read so there
        // isn't anything in the buffer that would need to be sent at this point.
        // NOTE: Don't call _Continue since that would just call us back via lpProc...
        TransmitPackages_Update(lpTransfer, TRUE);
        return;
    }

    lpIoBuffer = lpTransfer->lpIoBuffer;
    lpOverlapped = &lpIoBuffer->ioFile->Overlapped;

    if ((dwBytesRead == (DWORD)-1) && lpOverlapped->bDoCrc)
    {
        //  Calculate crc-32 on the existing bytes in buffer (offset)
        CalculateCrc32(lpIoBuffer->buf, lpIoBuffer->offset, &lpOverlapped->Crc32);
    }

    if (lpTransfer->bClosed)
    {
        // The socket was closed, no sense trying to send anything more...
        TransmitPackages_Update(lpTransfer, TRUE);
        return;
    }

    if (dwBytesRead != (DWORD)-1)
    {
        // update file pointer
        OVERLAPPED_INC(lpIoBuffer->ioFile->Overlapped, dwBytesRead);

        // send whatever we read
        lpIoBuffer->len = dwBytesRead;
        lpIoBuffer->offset = 0;
        (lpTransfer->lpSocket->Overlapped[1].lpProc)(lpTransfer, (DWORD)-1, NO_ERROR);
        return;
    }

    //  Call lower level function to do the actual read
    IoReadFile(lpIoBuffer->ioFile, lpIoBuffer->buf, lpIoBuffer->size);
}

// When dwBytesRead == -1 it means we have been called via the lpProc callback from
// [Secure]WriteSocket when the connection was closed or it finished filling up the buffer
// and we need to finish writing whatever is in our buffer and then do the right thing...
static VOID
TransmitPackage_WriteFile(LPPACKAGETRANSFER lpTransfer, DWORD dwBytesWritten, DWORD dwLastError)
{
    LPFILEOVERLAPPED lpOverlapped;
    LPIOBUFFER       lpIoBuffer;

    //  Handle write error
    if (dwLastError != NO_ERROR)
    {
        TransmitPackages_Error(lpTransfer, dwLastError);
        return;
    }

    lpIoBuffer = lpTransfer->lpIoBuffer;

    // we connected so it's an established connection...
    lpIoBuffer->ioFile->dwFlags |= IOFILE_VALID;

    if (dwBytesWritten != (DWORD)-1)
    {
        // we wrote something to the file so update file pointer
        OVERLAPPED_INC(lpIoBuffer->ioFile->Overlapped, dwBytesWritten);

        // unlike reading we want to make sure we write it all out...
        if ((lpIoBuffer->offset += dwBytesWritten) == lpIoBuffer->len)
        {
            // everything got written...
            if (lpTransfer->bClosed)
            {
                // that's all we got, socket was closed
                TransmitPackages_Update(lpTransfer, TRUE);
                return;
            }
            // go get more from the socket
            lpIoBuffer->len = lpIoBuffer->size;
            lpIoBuffer->offset = 0;
            (lpTransfer->lpSocket->Overlapped[0].lpProc)(lpTransfer, (DWORD)-1, NO_ERROR);
            return;
        }
    }
    else
    {
        if (lpIoBuffer->offset)
        {
            // something was read in so we need to write it out...
            lpOverlapped = &lpIoBuffer->ioFile->Overlapped;

            //  Calculate crc-32
            if (lpOverlapped->bDoCrc)
            {
                CalculateCrc32(lpIoBuffer->buf, lpIoBuffer->offset, &lpOverlapped->Crc32);
            }

            lpIoBuffer->len = lpIoBuffer->offset;
            lpIoBuffer->offset = 0;
        }
        else // lpTransfer->bClosed should be only possible outcome here...
        {
            // nothing was read and socket closed, we're done...
            TransmitPackages_Update(lpTransfer, TRUE);
            return;
        }
    }

    //  Call lower level function
    IoWriteFile(lpIoBuffer->ioFile, &lpIoBuffer->buf[lpIoBuffer->offset], lpIoBuffer->len - lpIoBuffer->offset);
}

VOID TransmitPackage_SecureHandshake(LPPACKAGETRANSFER lpTransfer, DWORD dwBytesTransmitted, DWORD dwLastError)
{
    LPSOCKETOVERLAPPED lpOverlapped;
    LPIOSOCKET  lpSocket;
    LPSECURITY  lpSecure;
    LPIOBUFFER  lpIoBuffer;
    int         iNum, iWriteBytes;

    lpSocket = lpTransfer->lpSocket;
    // Safely addref lpSecure — same pattern as ReadSecure/WriteSecure.
    lpSecure = Security_Acquire(lpSocket);
    if (!lpSecure)
    {
        TransmitPackages_Error(lpTransfer, IO_SSL_FAIL2);
        return;
    }

    if ((dwBytesTransmitted != (DWORD)-1) && dwBytesTransmitted)
    {
        lpTransfer->i64Total += dwBytesTransmitted;
        TransmitPackagePerTransmit(lpTransfer, dwBytesTransmitted);
    }

    //  Handle transfer error
    if (dwLastError != NO_ERROR)
    {
        Security_Release(lpSecure);
        TransmitPackages_Error(lpTransfer, dwLastError);
        return;
    }

    if (!dwBytesTransmitted)
    {
        //  Handle end of stream
        lpTransfer->bClosed = TRUE;
        Security_Release(lpSecure);
        TransmitPackages_Update(lpTransfer, TRUE);
        return;
    }

    lpIoBuffer = lpTransfer->lpIoBuffer;

    // Fix #3: serialise all SSL/BIO access with csLock.  The timer thread can call
    // CloseSocket (which only holds ioSocket.csLock) while this function is mid-way
    // through SSL_do_handshake, delivering a second completion to another I/O thread.
    // Without csLock the two threads would race on the SSL* / BIO* objects.
    // Lock order: csLock -> ioSocket.csLock (SendOverlapped/ReceiveOverlapped acquire
    // ioSocket.csLock internally; CloseSocket acquires only ioSocket.csLock — no inversion).
    EnterCriticalSection(&lpSecure->csLock);

    if (lpSecure->bCommunicating)
    {
        if (dwBytesTransmitted == (DWORD)-1)
        {
            LeaveCriticalSection(&lpSecure->csLock);
            Security_Release(lpSecure);
            TransmitPackages_Error(lpTransfer, IO_SSL_FAIL2);
            return;
        }

        if (lpSecure->bSending)
        {
            // we sent something
            if (BIO_nread(lpSecure->NetworkBio, NULL, (int)dwBytesTransmitted) <= 0)
            {
                LeaveCriticalSection(&lpSecure->csLock);
                Security_Release(lpSecure);
                TransmitPackages_Error(lpTransfer, IO_SSL_FAIL);
                return;
            }

            if ((lpIoBuffer->offset += dwBytesTransmitted) == lpIoBuffer->len)
            {
                // all done sending the buffer
                lpSecure->bSending = FALSE;
                if (!lpSecure->bReceiving)
                {
                    // time to try SSL_do_handshake again...
                    lpSecure->bCommunicating = FALSE;
                }
            }
        }
        else
        {
            // we received some bytes; update the bio
            lpOverlapped = &lpSocket->Overlapped[0];

            if (BIO_nwrite(lpSecure->NetworkBio, &lpOverlapped->Buffer.buf, (int)dwBytesTransmitted) <= 0)
            {
                LeaveCriticalSection(&lpSecure->csLock);
                Security_Release(lpSecure);
                TransmitPackages_Error(lpTransfer, IO_SSL_FAIL);
                return;
            }
            lpSecure->bCommunicating = FALSE;
            lpSecure->bReceiving = FALSE;
        }
    }

    if (!lpSecure->bCommunicating)
    {
        iNum = SSL_do_handshake(lpSecure->SSL);

        iWriteBytes = BIO_pending(lpSecure->NetworkBio);
        if (iWriteBytes)
        {
            lpSecure->bSending = TRUE;
        }

        if (iNum > 0)
        {
            if (!lpSecure->bSending)
            {
                // we're done
                lpSecure->bCommunicating = FALSE;
                lpSecure->bSending = FALSE;
                lpSecure->bReceiving = FALSE;
                lpSocket->Overlapped[0].lpProc = TransmitPackage_ReadSecure;
                lpSocket->Overlapped[1].lpProc = TransmitPackage_WriteSecure;
                LeaveCriticalSection(&lpSecure->csLock);
                Security_Release(lpSecure);
                TransmitPackages_Update(lpTransfer, TRUE);
                return;
            }
            // we need to write out some data before we're completely done...
        }
        else
        {
            switch (SSL_get_error(lpSecure->SSL, iNum))
            {
            case SSL_ERROR_WANT_READ:
                lpSecure->bReceiving = TRUE;
                break;
            case SSL_ERROR_WANT_WRITE:
                lpSecure->bSending = TRUE;
                break;
            default:
                LeaveCriticalSection(&lpSecure->csLock);
                Security_Release(lpSecure);
                TransmitPackages_Error(lpTransfer, IO_SSL_FAIL);
                return;
            }
        }
        lpSecure->bCommunicating = TRUE;
    }

    if (lpSecure->bSending)
    {
        // we always finish sending, then we can start receiving...
        lpOverlapped = &lpSocket->Overlapped[1];

        // Hold csLock through SendOverlapped: BIO_nread0 returns a borrowed pointer
        // into the BIO ring buffer that must remain valid until after the send is posted.
        iNum = BIO_nread0(lpSecure->NetworkBio, &lpIoBuffer->buf);
        if (iNum <= 0)
        {
            LeaveCriticalSection(&lpSecure->csLock);
            Security_Release(lpSecure);
            TransmitPackages_Error(lpTransfer, IO_SSL_FAIL);
            return;
        }

        lpIoBuffer->len = (ULONG)iNum;
        lpOverlapped->Buffer.len = (ULONG)iNum;
        lpOverlapped->Buffer.buf = lpIoBuffer->buf;
        lpIoBuffer->offset = 0;

        if (SendOverlapped(lpSocket, lpOverlapped))
        {
            LeaveCriticalSection(&lpSecure->csLock);
            Security_Release(lpSecure);
            TransmitPackages_Error(lpTransfer, WSAGetLastError());
            return;
        }
        LeaveCriticalSection(&lpSecure->csLock);
        // WSASend posted; next callback will call Security_Acquire again.
        Security_Release(lpSecure);
        return;
    }

    // we must be receiving...
    lpIoBuffer = lpTransfer->lpIoBuffer;
    lpOverlapped = &lpSocket->Overlapped[0];

    // Hold csLock through ReceiveOverlapped: BIO_nwrite0 returns a writable region
    // in the BIO ring buffer; we must own csLock until the receive is posted so no
    // other SSL call re-uses that region before the socket data fills it.
    iNum = BIO_nwrite0(lpSecure->NetworkBio, &lpIoBuffer->buf);
    if (iNum <= 0)
    {
        LeaveCriticalSection(&lpSecure->csLock);
        Security_Release(lpSecure);
        TransmitPackages_Error(lpTransfer, IO_SSL_FAIL);
        return;
    }

    lpIoBuffer->len = (ULONG)iNum;
    lpOverlapped->Buffer.len = (ULONG)iNum;
    lpOverlapped->Buffer.buf = lpIoBuffer->buf;
    lpIoBuffer->offset = 0;

    if (ReceiveOverlapped(lpSocket, lpOverlapped))
    {
        LeaveCriticalSection(&lpSecure->csLock);
        Security_Release(lpSecure);
        TransmitPackages_Error(lpTransfer, WSAGetLastError());
        return;
    }
    LeaveCriticalSection(&lpSecure->csLock);
    // WSARecv posted; next callback will call Security_Acquire again.
    Security_Release(lpSecure);
    return;
}

static VOID TransmitPackage_Shutdown(LPPACKAGETRANSFER lpTransfer,
    DWORD dwBytesTransmitted,
    DWORD dwLastError)
{
    // Sentinel used by the caller to indicate "we initiated shutdown" events.
    const DWORD kShutdownSentinel = (DWORD)-1;

    // Sanity checks
    if (!lpTransfer || !lpTransfer->lpSocket) {
        return;
    }

    LPIOSOCKET          lpSocket = lpTransfer->lpSocket;
    LPSOCKETOVERLAPPED  lpOverRecv = &lpSocket->Overlapped[0];
    LPSOCKETOVERLAPPED  lpOverSend = &lpSocket->Overlapped[1];
    LPIOBUFFER          lpIoBuffer = lpTransfer->lpIoBuffer;

    // Defensive: ensure we have an IO buffer
    if (!lpIoBuffer) {
        TransmitPackages_Error(lpTransfer, ERROR_INVALID_PARAMETER);
        return;
    }

    // Account for actual bytes transmitted (not the sentinel)
    if (dwBytesTransmitted != kShutdownSentinel && dwBytesTransmitted) {
        lpTransfer->i64Total += dwBytesTransmitted;
        TransmitPackagePerTransmit(lpTransfer, dwBytesTransmitted);
    }

    // Handle an explicit error from the transport
    if (dwLastError != NO_ERROR) {
        if (dwLastError == ERROR_NETNAME_DELETED) {
            // Peer closed while we were orderly-shutting-down; treat as graceful.
            lpTransfer->bClosed = TRUE;
            TransmitPackages_Complete(lpTransfer);
            return;
        }
        TransmitPackages_Error(lpTransfer, dwLastError);
        return;
    }

    // A completed read of 0 bytes means clean shutdown from peer.
    if (dwBytesTransmitted == 0) {
        lpTransfer->bClosed = TRUE;
        TransmitPackages_Complete(lpTransfer);
        return;
    }

    // Safely addref lpSecure AFTER the non-SSL early-exit checks above.
    // Security_Acquire returns NULL for non-TLS sockets (lpSecure==NULL) or when
    // ioCloseSocket has already nulled the pointer — both handled below.
    LPSECURITY lpSecure = Security_Acquire(lpSocket);

    // Non-secure path
    if (!lpSecure) {
        if (dwBytesTransmitted == kShutdownSentinel) {
            // Send our half-close indication; ignore errors.
            Socket_HalfCloseSend(lpSocket->Socket);

            // Now wait for a 0-byte read from the peer to confirm closure.
            lpOverRecv->Buffer.len = sizeof(lpIoBuffer->buf);
            lpOverRecv->Buffer.buf = (PCHAR)lpIoBuffer->buf;

            if (ReceiveOverlapped(lpSocket, lpOverRecv)) {
                DWORD dwErr = WSAGetLastError();
                if (dwErr == WSAECONNRESET) {
                    // Treat reset during shutdown as graceful enough.
                    lpTransfer->bClosed = TRUE;
                    TransmitPackages_Complete(lpTransfer);
                    return;
                }
                TransmitPackages_Error(lpTransfer, dwErr);
            }
            // Either I/O pending or completed; done here.
            return;
        }

        // If we received something during shutdown, just complete; nothing more to do.
        TransmitPackages_Complete(lpTransfer);
        return;
    }

    // Secure (TLS) path
    // Fix #1: serialise all SSL/BIO access with csLock.  The timer thread drives
    // CloseSocket which only holds ioSocket.csLock; without csLock, the timer cancel
    // delivers a second IOCP completion whose callback can race with the in-progress
    // SSL_shutdown / BIO_nread0 call — heap corruption / undefined behaviour.
    // Lock order: csLock -> ioSocket.csLock (same as WriteSecure / SecureHandshake).
    EnterCriticalSection(&lpSecure->csLock);

    // If already in "communicating" phase, continue that state machine
    if (lpSecure->bCommunicating) {
        if (dwBytesTransmitted == kShutdownSentinel) {
            LeaveCriticalSection(&lpSecure->csLock);
            Security_Release(lpSecure);
            TransmitPackages_Error(lpTransfer, IO_SSL_FAIL2);
            return;
        }

        if (lpSecure->bSending) {
            // We pushed encrypted bytes to the socket; drain them from the BIO.
            if (BIO_nread(lpSecure->NetworkBio, NULL, (int)dwBytesTransmitted) <= 0) {
                LeaveCriticalSection(&lpSecure->csLock);
                Security_Release(lpSecure);
                TransmitPackages_Error(lpTransfer, IO_SSL_FAIL);
                return;
            }

            if ((lpIoBuffer->offset += (int)dwBytesTransmitted) == lpIoBuffer->len) {
                // Finished sending what's in NetworkBio
                lpSecure->bSending = FALSE;

                // We have completed our shutdown records; close send-half on socket.
                Socket_HalfCloseSend(lpSocket->Socket);
                lpTransfer->bClosed = TRUE;
                LeaveCriticalSection(&lpSecure->csLock);
                Security_Release(lpSecure);

                // TLS says we're done; complete transfer.
                TransmitPackages_Complete(lpTransfer);
                return;
            }
        }
        else {
            // Receiving side: any non-zero bytes here means unexpected data; consider done.
            if (dwBytesTransmitted == 0) {
                lpTransfer->bClosed = TRUE;
            }
            LeaveCriticalSection(&lpSecure->csLock);
            Security_Release(lpSecure);
            TransmitPackages_Complete(lpTransfer);
            return;
        }
    }

    // If we haven't started the TLS shutdown handshake yet, initiate it.
    if (!lpSecure->bCommunicating) {
        lpSecure->bCommunicating = TRUE;
        lpSecure->bSending = FALSE;

        int iNum = SSL_shutdown(lpSecure->SSL);            // 1 = success, 0 = need more, <0 = error
        int iToWrite = BIO_pending(lpSecure->NetworkBio);      // bytes we need to write out (close_notify etc.)

        if (iToWrite > 0) {
            lpSecure->bSending = TRUE;
        }

        if (iNum > 0) {
            // Bi-directional shutdown complete at the TLS layer
            if (iToWrite == 0) {
                lpTransfer->bClosed = TRUE;
                Socket_HalfCloseSend(lpSocket->Socket);
                LeaveCriticalSection(&lpSecure->csLock);
                Security_Release(lpSecure);
                TransmitPackages_Complete(lpTransfer);
                return;
            }
            // else: still have shutdown bytes to send; fall through to bSending.
        }
        else {
            int iErr = SSL_get_error(lpSecure->SSL, iNum);
            switch (iErr) {
            case SSL_ERROR_WANT_READ:
                // Need peer data; will post a receive (handled below).
                break;
            case SSL_ERROR_WANT_WRITE:
                lpSecure->bSending = TRUE;
                break;
            case SSL_ERROR_ZERO_RETURN:
                // Peer sent close_notify; treat as graceful close.
                lpTransfer->bClosed = TRUE;
                Socket_HalfCloseSend(lpSocket->Socket);
                LeaveCriticalSection(&lpSecure->csLock);
                Security_Release(lpSecure);
                TransmitPackages_Complete(lpTransfer);
                return;
            case SSL_ERROR_SYSCALL:
                if (iNum != 0) {
                    Socket_HalfCloseSend(lpSocket->Socket);
                    lpTransfer->bClosed = TRUE;
                    LeaveCriticalSection(&lpSecure->csLock);
                    Security_Release(lpSecure);
                    TransmitPackages_Error(lpTransfer, IO_SSL_FAIL);
                    return;
                }
                // iNum == 0 case can be ignored per OpenSSL docs.
                break;
            default:
                LeaveCriticalSection(&lpSecure->csLock);
                Security_Release(lpSecure);
                TransmitPackages_Error(lpTransfer, IO_SSL_FAIL);
                return;
            }
        }
    }

    // If we have TLS bytes to send, push them to the socket.
    // Hold csLock through SendOverlapped: BIO_nread0 returns a borrowed pointer.
    if (lpSecure->bSending) {
        int iNum = BIO_nread0(lpSecure->NetworkBio, &lpIoBuffer->buf);
        if (iNum <= 0) {
            LeaveCriticalSection(&lpSecure->csLock);
            Security_Release(lpSecure);
            TransmitPackages_Error(lpTransfer, IO_SSL_FAIL);
            return;
        }

        lpIoBuffer->len = (ULONG)iNum;
        lpIoBuffer->offset = 0;

        lpOverSend->Buffer.len = (DWORD)iNum;
        lpOverSend->Buffer.buf = lpIoBuffer->buf;

        if (SendOverlapped(lpSocket, lpOverSend)) {
            LeaveCriticalSection(&lpSecure->csLock);
            Security_Release(lpSecure);
            TransmitPackages_Error(lpTransfer, WSAGetLastError());
            return;
        }
        LeaveCriticalSection(&lpSecure->csLock);
        // WSASend posted; next callback will call Security_Acquire again.
        Security_Release(lpSecure);
        return;
    }

    // Otherwise we must be waiting to receive peer's shutdown data.
    if (lpTransfer->bClosed) {
        // No point in receiving; peer won't send more.
        LeaveCriticalSection(&lpSecure->csLock);
        Security_Release(lpSecure);
        TransmitPackages_Complete(lpTransfer);
        return;
    }

    // Hold csLock through ReceiveOverlapped: BIO_nwrite0 returns a writable BIO region.
    {
        int iRecvLen = BIO_nwrite0(lpSecure->NetworkBio, &lpIoBuffer->buf);
        if (iRecvLen <= 0) {
            LeaveCriticalSection(&lpSecure->csLock);
            Security_Release(lpSecure);
            TransmitPackages_Error(lpTransfer, IO_SSL_FAIL);
            return;
        }

        lpIoBuffer->len = (ULONG)iRecvLen;
        lpIoBuffer->offset = 0;

        lpOverRecv->Buffer.len = (DWORD)iRecvLen;
        lpOverRecv->Buffer.buf = lpIoBuffer->buf;

        if (ReceiveOverlapped(lpSocket, lpOverRecv)) {
            LeaveCriticalSection(&lpSecure->csLock);
            Security_Release(lpSecure);
            TransmitPackages_Error(lpTransfer, WSAGetLastError());
            return;
        }
        LeaveCriticalSection(&lpSecure->csLock);
        // WSARecv posted; next callback will call Security_Acquire again.
        Security_Release(lpSecure);
    }
}

// Fix #2: dedicated completion handler for the TransmitFile zero-copy fast path.
// TransmitPackage_WriteSocket must not be used here because the fast path leaves
// lpIoBuffer->len = 0, which triggers a DWORD underflow (0 - fileSize ≈ 4 GB).
// This handler simply credits the bytes and advances the state machine.
static VOID
TransmitPackage_WriteFileDirect(LPPACKAGETRANSFER lpTransfer,
    DWORD dwBytesWritten, DWORD dwLastError)
{
    if (dwLastError != NO_ERROR)
    {
        TransmitPackages_Error(lpTransfer, dwLastError);
        return;
    }
    if (dwBytesWritten == 0)
    {
        TransmitPackages_Closed(lpTransfer);
        return;
    }
    lpTransfer->i64Total += dwBytesWritten;
    TransmitPackagePerTransmit(lpTransfer, dwBytesWritten);
    // Fix #2: TransmitFile sent the entire file in one shot; lpBuffer->bProcessed is already
    // TRUE (set before TransmitFile was posted).  Call TransmitPackages_Update directly —
    // NOT TransmitPackages_Continue — because lpContinueProc is set to TransmitPackage_ReadFile
    // (the buffered path's chunk loop) and calling it would spuriously re-initiate a file read
    // with lpIoBuffer->buf == NULL (fast path never allocated a buffer), causing heap corruption.
    TransmitPackages_Update(lpTransfer, TRUE);
}

static
BOOL TransmitPackages_Update(LPPACKAGETRANSFER lpTransfer, BOOL bIoCallback)
{
    LPSOCKETOVERLAPPED  lpOverlapped;  // this might not be true in all cases!
    LPIOBUFFER          lpBuffer;
    LPIOSOCKET          lpSocket;

    if (!lpTransfer->dwBuffer)
    {
        TransmitPackages_Complete(lpTransfer);
        return FALSE;
    }

    lpBuffer = lpTransfer->lpIoBuffer;
    if (lpBuffer->bProcessed)
    {
        //  Free allocated buffers
        if (lpBuffer->bAllocated) Free(lpBuffer->buf);
        //  Reduce amount of buffers left
        if (!--lpTransfer->dwBuffer)
        {
            TransmitPackages_Complete(lpTransfer);
            return FALSE;
        }

        lpTransfer->lpIoBuffer = ++lpBuffer;
        lpTransfer->dwTime = SafeGetTickCount64();
        lpTransfer->lpIoBuffer->bProcessed = FALSE;
        lpTransfer->lpIoBuffer->ReturnAfter = 0;
    }

    lpSocket = lpTransfer->lpSocket;

    //  Get asynchronous handlers
    lpBuffer->bAllocated = FALSE;

    switch (lpBuffer->dwType)
    {
    case PACKAGE_BUFFER_SEND:
        // Since we just want to send the contents of the buffer, we can just use [Secure]WriteSocket.
        lpTransfer->lpContinueProc = NULL;

        lpOverlapped = &lpSocket->Overlapped[1];
        break;

    case PACKAGE_LIST_BUFFER_SEND:
        // To handle recursive directory listings where the output spans more than one buffer
        // we need to send the current buffer, then see if there are more to send
        lpTransfer->lpContinueProc = TransmitPackage_SendListBuffer;

        lpOverlapped = &lpSocket->Overlapped[1];
        break;

    case PACKAGE_FILE_SEND:
    {
        lpTransfer->lpContinueProc = TransmitPackage_ReadFile;

        // Ensure a WAN-friendly minimum buffer size for the TLS buffered path.
        // Only bump when we will allocate the buffer ourselves (buf == NULL).
        // If the caller supplied a pre-allocated buffer its capacity is fixed;
        // exceeding it with IoReadFile writes past the allocation boundary.
        if (!lpBuffer->buf && lpBuffer->size < (128 * 1024)) lpBuffer->size = (128 * 1024);

        // Fast path for non-TLS: use TransmitFile to maximize throughput (zero-copy)
        if (!lpSocket->lpSecure && lpBuffer->ioFile && lpBuffer->ioFile->FileHandle != INVALID_HANDLE_VALUE)
        {
            LPSOCKETOVERLAPPED lpSendOv = &lpSocket->Overlapped[1];

            // Fix #2: route the IOCP completion to the dedicated handler, NOT to
            // TransmitPackage_WriteSocket which would compute (0 - fileSize) underflow.
            lpSendOv->lpProc    = TransmitPackage_WriteFileDirect;
            lpSendOv->lpContext = lpTransfer;

            // Mark processed BEFORE TransmitFile so state is consistent if the timer
            // fires or a cancellation arrives during/after the post.
            lpBuffer->bProcessed = TRUE;

            // Start the timer BEFORE TransmitFile.  If the timer is started after,
            // a race exists: TransmitFile can complete, the IOCP fires, the transfer
            // advances through TransmitPackages_Update → Complete → QueueJob, a
            // worker thread calls Free(lpTransfer) — all before StartIoTimer returns
            // on this thread.  When that timer then fires it accesses freed memory →
            // STATUS_HEAP_CORRUPTION (0xc0000374).  Starting the timer first ensures
            // lpTransfer->lpTimer is set before any other thread can touch lpTransfer.
            if (lpBuffer->dwTimerType != NO_TIMER && !lpTransfer->lpTimer)
            {
                lpTransfer->lpTimer = StartIoTimer(NULL, TransmitPackage_Timer, lpTransfer, lpBuffer->dwTimeOut);
                if (!lpTransfer->lpTimer)
                {
                    lpBuffer->bProcessed = FALSE;   // undo; TransmitFile not yet posted
                    TransmitPackages_Error(lpTransfer, GetLastError());
                    return FALSE;
                }
            }

            // Send entire file (0 size => entire file), overlapped completion via IOCP.
            // After this call returns, lpTransfer may be freed by a concurrent IOCP
            // thread at any moment — do not touch lpTransfer after this point.
            BOOL ok = TransmitFile(lpSocket->Socket,
                lpBuffer->ioFile->FileHandle,
                0, 0,
                (LPOVERLAPPED)lpSendOv,
                NULL,
                0);
            if (!ok)
            {
                int err = WSAGetLastError();
                if (err != WSA_IO_PENDING)
                {
                    TransmitPackages_Error(lpTransfer, err);
                    return FALSE;
                }
            }
            return TRUE;
        }

        // Buffered path (TLS or no TransmitFile)
        lpOverlapped = &lpSocket->Overlapped[1];
        lpOverlapped->lpContext = lpTransfer;

        lpOverlapped = (LPSOCKETOVERLAPPED)&lpBuffer->ioFile->Overlapped;
        lpOverlapped->lpProc = TransmitPackage_ReadFile;
        lpOverlapped->lpContext = lpTransfer;

        // Set up the requested send size, offset is cleared below
        lpBuffer->len = lpBuffer->size;

        //  Have transfer buffer?
        if (!lpBuffer->buf) lpBuffer->bAllocated = TRUE;
        break;
    }

    case PACKAGE_FILE_RECEIVE:
        lpTransfer->lpContinueProc = TransmitPackage_WriteFile;

        // Ensure a WAN-friendly minimum buffer size.
        // Only bump when we will allocate the buffer ourselves (buf == NULL).
        // If the caller supplied a pre-allocated buffer (e.g. lpData->Buffer.buf,
        // default 64 KB), its capacity is fixed; exceeding it with WSARecv causes
        // the receive to write past the allocation → STATUS_HEAP_CORRUPTION (0xc0000374).
        if (!lpBuffer->buf && lpBuffer->size < (128 * 1024)) lpBuffer->size = (128 * 1024);

        lpOverlapped = (LPSOCKETOVERLAPPED)&lpBuffer->ioFile->Overlapped;
        lpOverlapped->lpProc = TransmitPackage_WriteFile;
        lpOverlapped->lpContext = lpTransfer;

        // we need to start out reading since nothing to write yet...
        lpOverlapped = &lpSocket->Overlapped[0];
        lpOverlapped->lpContext = lpTransfer;

        // Set up the requested receive size, offset is cleared below
        lpBuffer->len = lpBuffer->size;

        //  Have transfer buffer?
        if (!lpBuffer->buf) lpBuffer->bAllocated = TRUE;
        break;

    case PACKAGE_SSL_ACCEPT:
    case PACKAGE_SSL_CONNECT:
        lpTransfer->lpContinueProc = NULL;

        lpOverlapped = &lpSocket->Overlapped[0];
        lpOverlapped->lpProc = TransmitPackage_SecureHandshake;
        lpOverlapped->lpContext = lpTransfer;

        lpOverlapped = &lpSocket->Overlapped[1];
        lpOverlapped->lpProc = TransmitPackage_SecureHandshake;
        lpOverlapped->lpContext = lpTransfer;
        break;

    case PACKAGE_SHUTDOWN:
        lpTransfer->lpContinueProc = NULL;

        lpOverlapped = &lpSocket->Overlapped[1];
        lpOverlapped->lpProc = TransmitPackage_Shutdown;
        lpOverlapped->lpContext = lpTransfer;

        lpOverlapped = &lpSocket->Overlapped[0];
        lpOverlapped->lpProc = TransmitPackage_Shutdown;
        lpOverlapped->lpContext = lpTransfer;
        break;

        // case PACKAGE_RECEIVE_LINE: shouldn't happen
    default:
        lpOverlapped = NULL;
    }

    lpBuffer->bProcessed = TRUE;
    lpBuffer->offset = 0;

    //  Stop timer
    if (lpTransfer->lpTimer && lpBuffer->dwTimerType == NO_TIMER)
    {
        if (StopIoTimer(lpTransfer->lpTimer, FALSE)) lpOverlapped = NULL;
        lpTransfer->lpTimer = NULL;
    }

    if (lpOverlapped)
    {
        lpOverlapped->lpContext = lpTransfer;

        //  Allocate transfer buffer, and start timer
        if (lpBuffer->bAllocated &&
            !(lpBuffer->buf = Allocate("TransferBuffer", lpBuffer->size)))
        {
            lpBuffer->bAllocated = FALSE;
            lpTransfer->dwLastError = ERROR_NOT_ENOUGH_MEMORY;
        }
        else if (lpBuffer->dwTimerType == NO_TIMER ||
            (lpTransfer->lpTimer ||
                (lpTransfer->lpTimer = StartIoTimer(NULL, TransmitPackage_Timer, lpTransfer, lpBuffer->dwTimeOut))))
        {
            if (bIoCallback)
            {
                // no need to post it, we are already running on an ioThread
                (lpOverlapped->lpProc)(lpOverlapped->lpContext, (DWORD)-1, NO_ERROR);
                return TRUE;
            }
            else if (PostQueuedCompletionStatus(hCompletionPort, (DWORD)-1, 0, (LPOVERLAPPED)lpOverlapped))
            {
                return TRUE;
            }
            lpTransfer->dwLastError = GetLastError();
        }
        else lpTransfer->dwLastError = GetLastError();
    }
    TransmitPackages_Complete(lpTransfer);
    return FALSE;
}

BOOL
ReceiveLine_Complete(LPLINEBUFFER lpLine, DWORD dwLastError, INT64 i64Total, ULONG ulSslError)
{
    LPPACKAGETRANSFER lpTransfer;
    DWORD             dwOffset;

    lpTransfer = lpLine->lpTransfer;

    if (lpTransfer->bClosed || lpTransfer->dwLastError != NO_ERROR)
    {
        (lpLine->lpCallBack)(lpLine->lpContext, NULL, lpTransfer->dwLastError, ulSslError);
    }
    else
    {
        dwOffset = lpLine->dwSlack;
        lpLine->dwSlack = lpLine->dwOffset;
        (lpLine->lpCallBack)(lpLine->lpContext, &lpLine->pBuffer[dwOffset], NO_ERROR, 0);
    }

    // Release the in-flight reference acquired in ReceiveLine().
    // The FTP callback above may have called FTP_Close_Connection -> ioCloseSocket, which
    // already released the owner ref and nulled lpSocket->lpLineBuffer.  But since we still
    // hold our own ref the struct is valid here.  Free only when the last ref drops to zero.
    if (InterlockedDecrement(&lpLine->lRefCount) == 0)
    {
        Free(lpTransfer);
        Free(lpLine);
    }
    return FALSE;
}

#if 0
DWORD FlushLineBuffer(LPIOSOCKET lpSocket, PCHAR pBuffer, DWORD dwBuffer)
{
    LPLINEBUFFER    lpLine;

    lpLine = lpSocket->lpLineBuffer;
    //  Flush line buffer, to external buffer
    dwBuffer = min(dwBuffer, lpLine->dwLength - lpLine->dwSlack);
    CopyMemory(pBuffer, &lpLine->pBuffer[lpLine->dwSlack], dwBuffer);
    lpLine->dwOffset += dwBuffer;
    lpLine->dwSlack = lpLine->dwOffset;

    return dwBuffer;
}
#endif

// bDirect TRUE if called from a worker thread and not the io threads.
BOOL ReceiveLine_Update(LPLINEBUFFER lpLine, BOOL bDirect)
{
    LPIOBUFFER         lpIoBuffer;
    LPSOCKETOVERLAPPED lpOverlapped;
    PCHAR              pOffset;

    for (;;)
    {
        //  Find newline
        pOffset = (PCHAR)memchr(&lpLine->pBuffer[lpLine->dwOffset], '\n', lpLine->dwLength - lpLine->dwOffset);

        if (!pOffset)
        {
            //  No newline found
            if (lpLine->bOverflow)
            {
                lpLine->dwLength = 0;
                break;
            }
            if (lpLine->dwLength < lpLine->dwSize) break;
            if (lpLine->dwSlack)
            {
                //  Compact buffer
                MoveMemory(lpLine->pBuffer, &lpLine->pBuffer[lpLine->dwSlack], lpLine->dwLength - lpLine->dwSlack);
                lpLine->dwLength -= lpLine->dwSlack;
                lpLine->dwSlack = 0;
                break;
            }
            lpLine->bOverflow = TRUE;
            pOffset = &lpLine->pBuffer[lpLine->dwSize - 1];
        }
        else if (lpLine->bOverflow)
        {
            lpLine->dwSlack =
                lpLine->dwOffset = (DWORD)(&pOffset[1] - lpLine->pBuffer);
            lpLine->bOverflow = FALSE;
            continue;
        }
        pOffset[(pOffset > &lpLine->pBuffer[lpLine->dwOffset] && pOffset[-1] == '\r' ? -1 : 0)] = '\0';
        lpLine->dwOffset = (DWORD)(&pOffset[1] - lpLine->pBuffer);
        TransmitPackages_Complete(lpLine->lpTransfer);
        return FALSE;
    }
    lpLine->dwOffset = lpLine->dwLength;

    lpIoBuffer = lpLine->lpTransfer->lpIoBuffer;
    lpIoBuffer->len = lpLine->dwSize - lpLine->dwOffset;
    lpIoBuffer->buf = &lpLine->pBuffer[lpLine->dwOffset];
    lpIoBuffer->offset = 0;

    if (lpLine->lpTransfer->bClosed)
    {
        TransmitPackages_Complete(lpLine->lpTransfer);
        return FALSE;
    }

    lpOverlapped = &lpLine->lpTransfer->lpSocket->Overlapped[0];
    if (bDirect)
    {
        if (!PostQueuedCompletionStatus(hCompletionPort, (DWORD)-1, 0, (LPOVERLAPPED)lpOverlapped))
        {
            TransmitPackages_Error(lpLine->lpTransfer, GetLastError());
        }
    }
    else
    {
        // just call it directly...
        lpOverlapped->lpProc(lpOverlapped->lpContext, (DWORD)-1, NO_ERROR);
    }
    return FALSE;
}

// only called by [Secure]ReadSocket as the lpTransfer->lpProc callback so always NO_ERROR and -1 bytes
VOID TransmitPackage_ReceiveLine(LPPACKAGETRANSFER lpTransfer, DWORD dwBytesRead, DWORD dwLastError)
{
    // Very special case... we know context passed to transmit package was an LPLINEBUFFER
    LPLINEBUFFER lpLine = (LPLINEBUFFER)lpTransfer->lpContext;

    lpLine->dwLength += lpTransfer->lpIoBuffer->offset;
    ReceiveLine_Update(lpLine, FALSE);
    return;
}

// A specialized version TransmitPackage() for reading a single line of input on the control channel
VOID ReceiveLine(LPIOSOCKET lpSocket, DWORD dwLineLength, VOID(*lpCallBack)(LPVOID, LPSTR, DWORD, ULONG), LPVOID lpContext)
{
    LPPACKAGETRANSFER  lpTransfer;
    LPLINEBUFFER       lpLine;
    LPIOBUFFER         lpIoBuffer;
    LPSOCKETOVERLAPPED lpOverlapped;

    //  Allocate line buffer
    if (!(lpLine = lpSocket->lpLineBuffer) || lpSocket->lpLineBuffer->dwSize < dwLineLength)
    {
        lpLine = (LPLINEBUFFER)ReAllocate(lpLine, "LineBuffer", sizeof(LINEBUFFER) + dwLineLength - 1);
        if (!lpLine)
        {
            //  Out of memory
            lpCallBack(lpContext, NULL, ERROR_NOT_ENOUGH_MEMORY, 0);
            return;
        }

        if (!lpSocket->lpLineBuffer)
        {
            ZeroMemory(lpLine, sizeof(LINEBUFFER));
            lpLine->lRefCount = 1;   // socket owner holds the initial reference
        }
        lpSocket->lpLineBuffer = lpLine;
        lpLine->dwSize = dwLineLength;
    }

    //  No buffer copying is required to clear slack
    if (lpLine->dwSlack > 0)
    {
        if (lpLine->dwSlack == lpLine->dwLength)
        {
            lpLine->dwOffset = 0;
            lpLine->dwSlack = 0;
            lpLine->dwLength = 0;
        }
        else if (lpLine->dwSlack > lpLine->dwSize / 3)
        {
            MoveMemory(lpLine->pBuffer, &lpLine->pBuffer[lpLine->dwSlack], lpLine->dwLength - lpLine->dwSlack);
            lpLine->dwOffset -= lpLine->dwSlack;
            lpLine->dwLength -= lpLine->dwSlack;  // Fix #10: keep dwLength consistent after compaction
            lpLine->dwSlack = 0;
        }
    }

    lpTransfer = lpLine->lpTransfer;

    if (!lpTransfer)
    {
        //  Allocate transfer structure
        lpTransfer = (LPPACKAGETRANSFER)Allocate("LineTransfer", sizeof(PACKAGETRANSFER) + sizeof(IOBUFFER));
        if (!lpTransfer)
        {
            lpCallBack(lpContext, NULL, GetLastError(), 0);
            return;
        }
        ZeroMemory(lpTransfer, sizeof(PACKAGETRANSFER) + sizeof(IOBUFFER));
        lpIoBuffer = (LPIOBUFFER)&lpTransfer[1];
        lpTransfer->lpIoBuffer = lpIoBuffer;
        lpTransfer->bNoFree = TRUE;
        lpTransfer->lpSocket = lpSocket;
        lpTransfer->lpCallBack = ReceiveLine_Complete;
        lpTransfer->lpContinueProc = TransmitPackage_ReceiveLine;
        // because we use a lpContinueProc we never call TransmitPackage_Update so dwBuffer never touched...
        lpTransfer->dwBuffer = 1;

        lpIoBuffer->size = dwLineLength;
        lpIoBuffer->dwType = PACKAGE_RECEIVE_LINE;
        lpIoBuffer->dwTimerType = NO_TIMER;
        lpIoBuffer->ReturnAfter = 1; // return on even 1 byte received

        lpLine->lpTransfer = lpTransfer;
    }

    lpIoBuffer = lpTransfer->lpIoBuffer;
    lpIoBuffer->len = lpLine->dwSize - lpLine->dwOffset;
    lpIoBuffer->buf = &lpLine->pBuffer[lpLine->dwOffset];
    lpIoBuffer->offset = 0;

    // reset fields
    lpTransfer->dwLastError = NO_ERROR;
    lpTransfer->lpContext = lpLine;
    lpTransfer->ulOpenSslError = 0;
    lpTransfer->i64Total = 0;

    lpLine->lpCallBack = lpCallBack;
    lpLine->lpContext = lpContext;

    lpOverlapped = &lpSocket->Overlapped[0];
    lpOverlapped->lpContext = lpTransfer;

    // Increment before handing off to the IOCP/completion system.
    // ReceiveLine_Complete will decrement (and free if the owner ref is gone).
    InterlockedIncrement(&lpLine->lRefCount);

    if (lpLine->dwOffset == lpLine->dwLength)
    {
        if (!PostQueuedCompletionStatus(hCompletionPort, (DWORD)-1, 0, (LPOVERLAPPED)lpOverlapped))
        {
            InterlockedDecrement(&lpLine->lRefCount);  // post failed; ReceiveLine_Complete will not fire
            lpCallBack(lpContext, NULL, GetLastError(), 0);
            return;
        }
    }
    else
    {
        ReceiveLine_Update(lpLine, TRUE);
    }
}

static BOOL SendQuickProc(LPIOSOCKET lpSocket)
{
    SetEvent(lpSocket->SQ.hEvent);
    return FALSE;
}

static VOID SendQuickCancel(LPIOSOCKET lpSocket)
{
    lpSocket->SQ.dwLastError = ERROR_OPERATION_ABORTED;
    SetEvent(lpSocket->SQ.hEvent);
}

static DWORD SendQuickTimeOut(LPIOSOCKET lpSocket, LPTIMER lpTimer)
{
    lpSocket->SQ.dwLastError = ERROR_TIMEOUT;
    SetEvent(lpSocket->SQ.hEvent);
    return 0;
}

static VOID SendQuickComplete(LPIOSOCKET lpSocket, DWORD dwLastError, INT64 i64Total, ULONG ulSslError)
{
    lpSocket->SQ.dwLastError = dwLastError;
    SetEvent(lpSocket->SQ.hEvent);   // wake SendQuick worker BEFORE releasing the ref
    // Release the IOCP reference.  If ioCloseSocket already released the owner ref,
    // the count drops to 0 here and we are responsible for freeing the resources.
    if (InterlockedDecrement(&lpSocket->SQ.lRefCount) == 0)
    {
        HANDLE hEvent = lpSocket->SQ.hEvent;
        Free(lpSocket->SQ.lpTransfer);
        lpSocket->SQ.lpTransfer = NULL;
        lpSocket->SQ.hEvent     = INVALID_HANDLE_VALUE;
        CloseHandle(hEvent);
    }
}

// A specialized version TransmitPackage() for reading a single line of input on the control channel
BOOL SendQuick(LPIOSOCKET lpSocket, LPTSTR tszString, DWORD dwBytes)
{
    LPPACKAGETRANSFER   lpTransfer;
    LPIOBUFFER          lpIoBuffer;
    LPSOCKETOVERLAPPED  lpOverlapped;

    if (!lpSocket->SQ.lpTransfer)
    {
        lpTransfer = (LPPACKAGETRANSFER)Allocate("LineTransfer", sizeof(PACKAGETRANSFER) + sizeof(IOBUFFER));
        if (!lpTransfer)
        {
            return TRUE;
        }
        lpSocket->SQ.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
        if (!lpSocket->SQ.hEvent)
        {
            Free(lpTransfer);
            return TRUE;
        }

        lpSocket->SQ.lpTransfer = lpTransfer;
        lpSocket->SQ.lRefCount  = 1;   // socket owner holds the initial reference

        ZeroMemory(lpTransfer, sizeof(PACKAGETRANSFER) + sizeof(IOBUFFER));

        lpTransfer->lpTimer = NULL;
        lpIoBuffer = (LPIOBUFFER)&lpTransfer[1];
        lpTransfer->lpIoBuffer = lpIoBuffer;
        lpTransfer->bNoFree = TRUE;
        lpTransfer->bQuick = TRUE;
        lpTransfer->lpSocket = lpSocket;
        lpTransfer->lpContext = lpSocket;
        lpTransfer->lpContinueProc = NULL;
        lpTransfer->lpCallBack = SendQuickComplete;

        lpIoBuffer->dwType = PACKAGE_BUFFER_SEND;
        lpIoBuffer->dwTimerType = NO_TIMER;
        lpIoBuffer->bAllocated = FALSE;

        lpOverlapped = &lpSocket->SQ.Overlapped;
        lpOverlapped->hSocket = lpSocket;
        lpOverlapped->lpContext = lpTransfer;
    }

    lpTransfer = lpSocket->SQ.lpTransfer;
    lpIoBuffer = lpTransfer->lpIoBuffer;

    lpIoBuffer->buf = tszString;
    lpIoBuffer->size = dwBytes;
    lpIoBuffer->len = dwBytes;
    lpIoBuffer->offset = 0;
    lpIoBuffer->bProcessed = TRUE;

    // reset fields
    lpTransfer->dwLastError = NO_ERROR;
    lpTransfer->ulOpenSslError = 0;
    lpTransfer->i64Total = 0;
    lpTransfer->bClosed = FALSE;
    lpTransfer->dwBuffer = 1;
    lpSocket->SQ.dwLastError = NO_ERROR;

    ResetEvent(lpSocket->SQ.hEvent);

    SetBlockingThreadFlag();

    // first let's queue a client job (#2) so that when the callback is called we know
    // that there are no active overlapped sends to the control connection in progress
    // and we block all new ones from occurring until we finish.
    if (!AddExclusiveClientJob(lpSocket->dwClientId, 2, CJOB_SECONDARY | CJOB_INSTANT, INFINITE, SendQuickProc, SendQuickCancel, SendQuickTimeOut, lpSocket))
    {
        SetNonBlockingThreadFlag();
        return FALSE;
    }

    // Fix #8: replace INFINITE waits with bounded timeouts.
    // With INFINITE waits and a large enough thread pool all worker threads can block
    // here simultaneously (e.g. 50 users finishing at once), exhausting the pool.
    // The SendQuickTimeOut / SendQuickCancel callbacks will signal the event when the
    // timeout fires or the job is aborted, so 30 s is a safe upper bound.
#define SENDQUICK_WAIT_MS 30000

    // one of the client job procedures will set this...
    if (WaitForSingleObject(lpSocket->SQ.hEvent, SENDQUICK_WAIT_MS) == WAIT_TIMEOUT)
        lpSocket->SQ.dwLastError = ERROR_TIMEOUT;

    if (lpSocket->SQ.dwLastError != NO_ERROR)
    {
        SetNonBlockingThreadFlag();
        EndClientJob(lpSocket->dwClientId, 2);
        return FALSE;
    }

    // need to set this each time in case we switched SSL/clear
    lpOverlapped = &lpSocket->SQ.Overlapped;
    lpOverlapped->lpProc = lpSocket->Overlapped[1].lpProc;

    // Increment before posting: IOCP op now in-flight; SendQuickComplete releases this ref.
    InterlockedIncrement(&lpSocket->SQ.lRefCount);
    if (!PostQueuedCompletionStatus(hCompletionPort, (DWORD)-1, 0, (LPOVERLAPPED)lpOverlapped))
    {
        // Post failed; SendQuickComplete will never fire — undo the increment and
        // signal the event so the wait below returns immediately with an error.
        InterlockedDecrement(&lpSocket->SQ.lRefCount);
        lpSocket->SQ.dwLastError = GetLastError();
        SetEvent(lpSocket->SQ.hEvent);
    }

    // this will always be triggered, by SendQuickCancel, SendQuickTimeOut, or SendQuickComplete...
    if (WaitForSingleObject(lpSocket->SQ.hEvent, SENDQUICK_WAIT_MS) == WAIT_TIMEOUT)
        lpSocket->SQ.dwLastError = ERROR_TIMEOUT;

    SetNonBlockingThreadFlag();

    EndClientJob(lpSocket->dwClientId, 2);

    if (lpSocket->SQ.dwLastError != NO_ERROR)
    {
        return FALSE;
    }
    return TRUE;
}

BOOL TransmitPackage_Init(BOOL bFirstInitialization)
{
    if (!bFirstInitialization) return TRUE;
    return TRUE;
}

VOID TransmitPackage_DeInit(VOID)
{
}