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

// NetworkMount.h — Network share connection manager
//
// Manages WNet connections to UNC shares referenced in .vfs files.
// Health monitoring and automatic reconnect run as background timers.
// The credential file (etc\netmounts.cfg) is optional — shares without
// credentials are monitored for health but rely on Windows implicit auth.

#pragma once

#define NETMOUNT_UNC_MAX   512
#define NETMOUNT_USER_MAX  128
#define NETMOUNT_PASS_MAX  256
#define NETMOUNT_DOM_MAX    64

typedef struct _NETWORK_MOUNT {
    char          szUncRoot[NETMOUNT_UNC_MAX];   // normalised \\server\share (lowercase, no trailing \)
    char          szUsername[NETMOUNT_USER_MAX];
    char          szPassword[NETMOUNT_PASS_MAX];
    char          szDomain[NETMOUNT_DOM_MAX];
    BOOL          bHasCredentials;   // TRUE = explicit credentials from netmounts.cfg
    volatile LONG lAvailable;        // 1 = reachable, 0 = down
    volatile LONG lFailCount;        // consecutive probe failures
    DWORD         dwTimerDelayMs;    // current/next timer interval
    LPTIMER       lpTimer;
    struct _NETWORK_MOUNT *lpNext;   // linked list (append-only)
} NETWORK_MOUNT, *LPNETWORK_MOUNT;

// Init/DeInit — registered in Main.c Init_Table
BOOL NetworkMount_Init(BOOL bFirstInitialization);
VOID NetworkMount_DeInit(VOID);

// Auto-register a UNC root discovered in a .vfs file — idempotent, thread-safe.
// szPath may be the full real path (\\server\share\deep\path) or just the share root.
VOID NetworkMount_Register(LPCSTR szPath);

// Return the health entry whose UNC root is a prefix of szPath, or NULL.
LPNETWORK_MOUNT NetworkMount_Find(LPCSTR szPath);

// Called by IoCreateFile when a network error occurs on szPath.
// Flags the share as potentially down and wakes its reconnect timer.
VOID NetworkMount_MarkDown(LPCSTR szPath);

// Attempt an inline reconnect for a single dropped connection (ERROR_NETNAME_DELETED).
// Returns a valid HANDLE if reconnect + retry succeeded, INVALID_HANDLE_VALUE otherwise.
// SetLastError is preserved on failure.
HANDLE NetworkMount_TryReconnect(LPCSTR lpFileName,
                                  DWORD dwDesiredAccess, DWORD dwShareMode,
                                  LPSECURITY_ATTRIBUTES lpSA,
                                  DWORD dwCreationDisposition,
                                  DWORD dwFlagsAndAttributes,
                                  HANDLE hTemplateFile,
                                  DWORD dwOriginalError);

// Timer callback — probe + reconnect cycle for one share.
DWORD __cdecl NetworkMount_Reconnect(LPVOID lpContext, LPTIMER lpTimer);
