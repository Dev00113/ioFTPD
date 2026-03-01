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

#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS 1

#include <ioFTPD.h>

 /* -----------------------------------------------------------------------------
    Globals
 ----------------------------------------------------------------------------- */

static LOCKOBJECT     loDeviceList;
static LPIODEVICE     lpDeviceList;
static LPIOSERVICE    lpServiceList;
static LOCKOBJECT     loServiceList;
static volatile LONG  lDeviceCounter;

static volatile BOOL  bServicesInitialized;
static DWORD          dwNeedCerts;

static LPIOADDRESSLIST lpDefaultPortDenyList;

/* -----------------------------------------------------------------------------
   Helpers
----------------------------------------------------------------------------- */

VOID RemoveSpaces(LPSTR szString)
{
    PCHAR pOffset, pCopyOffset;

    for (pCopyOffset = pOffset = (PCHAR)szString;; pOffset++)
    {
        switch (pOffset[0])
        {
        case '\t':
        case ' ':
            break;
        default:
            if (pOffset != pCopyOffset) pCopyOffset[0] = pOffset[0];
            if (pOffset[0] == '\0') return;
            pCopyOffset++;
        }
    }
}

/* -----------------------------------------------------------------------------
   Device share/unshare
----------------------------------------------------------------------------- */

VOID Device_Share(LPIODEVICE lpDevice)
{
    if (InterlockedIncrement(&lpDevice->lShareCount) == 1)
    {
        RegisterSchedulerDevice(lpDevice);
    }
}

#pragma warning(push)
#pragma warning(disable: 6001) // 6001 = Using uninitialized memory '*var' (Code Analysis warning)

VOID Device_Unshare(LPIODEVICE lpDevice)
{
    LPIOPORT lpPort = NULL;

    if (!InterlockedDecrement(&lpDevice->lShareCount))
    {
        UnregisterSchedulerDevice(lpDevice);

        while ((lpPort = lpDevice->lpPort) != NULL)
        {
            lpDevice->lpPort = lpPort->lpNext;
            Free(lpPort);
        }
        while ((lpPort = lpDevice->lpOutPorts) != NULL)
        {
            lpDevice->lpOutPorts = lpPort->lpNext;
            Free(lpPort);
        }

        AcquireExclusiveLock(&loDeviceList);
        if (lpDevice->lpNext) lpDevice->lpNext->lpPrev = lpDevice->lpPrev;
        if (lpDevice->lpPrev) lpDevice->lpPrev->lpNext = lpDevice->lpNext;
        else                  lpDeviceList = lpDevice->lpNext;
        ReleaseExclusiveLock(&loDeviceList);

        Free(lpDevice);
    }
}
#pragma warning(pop)

/* -----------------------------------------------------------------------------
   Bind/unbind sockets to devices
----------------------------------------------------------------------------- */

BOOL BindSocketToDevice(LPIOSERVICE lpService, LPIOSOCKET lpSocket,
    PULONG pNetworkAddress, PUSHORT pPort, DWORD dwFlags)
{
    LPIODEVICE lpDevice;
    LPIOPORT   lpPort;
    ULONG      lHostAddress, lBindAddress;
    ULONG      lPort;
    DWORD      n, dwDevice, dwPorts;
    USHORT     sPort;

    AcquireSharedLock(&lpService->loLock);
    AcquireSharedLock(&loDeviceList);

    if ((dwFlags & BIND_DATA) && lpService->lpDataDevices)
    {
        if (!lpService->bRandomDataDevices)
            dwDevice = InterlockedIncrement(&lpService->lLastDataDevice) - 1;
        else
            dwDevice = (DWORD)rand();

        dwDevice = dwDevice % lpService->dwDataDevices;

        for (n = lpService->dwDataDevices; n > 0 && !lpService->lpDataDevices[dwDevice]->bActive; n--)
        {
            if (++dwDevice >= lpService->dwDataDevices) dwDevice = 0;
        }
        lpDevice = lpService->lpDataDevices[dwDevice];
    }
    else lpDevice = lpService->lpDevice;

    if (!lpDevice || !lpDevice->bActive)
    {
        ReleaseSharedLock(&loDeviceList);
        ReleaseSharedLock(&lpService->loLock);
        SetLastError(ERROR_NO_ACTIVE_DEVICE);
        return TRUE;
    }

    lHostAddress = lpDevice->lHostAddress;
    lBindAddress = (lpDevice->lBindAddress != INADDR_NONE ? lpDevice->lBindAddress : lpDevice->lHostAddress);

    if ((dwFlags & BIND_PORT) && lpDevice->lpPort)
    {
        dwPorts = 0;

        if (!lpDevice->bRandomizePorts)
            lPort = InterlockedIncrement(&lpDevice->lLastPort) - 1;
        else
            lPort = (ULONG)rand();

        for (lpPort = lpDevice->lpPort; lpPort; lpPort = lpPort->lpNext)
        {
            dwPorts += lpPort->sHighPort - lpPort->sLowPort + 1;
        }

        lPort = lPort % dwPorts;
        for (lpPort = lpDevice->lpPort;; lpPort = lpPort->lpNext)
        {
            if (lPort < lpPort->sHighPort - lpPort->sLowPort + 1U)
            {
                sPort = (USHORT)(lpPort->sLowPort + lPort);
                break;
            }
            lPort -= (lpPort->sHighPort - lpPort->sLowPort + 1);
        }
    }
    else if (dwFlags & BIND_MINUS_PORT)
    {
        if ((dwFlags & BIND_TRY_AGAIN) && !lpDevice->lpOutPorts)
        {
            ReleaseSharedLock(&loDeviceList);
            ReleaseSharedLock(&lpService->loLock);
            return TRUE;
        }

        if (!lpDevice->lpOutPorts)
        {
            sPort = (USHORT)(lpService->sPort - 1);
        }
        else if (lpDevice->lpOutPorts->sLowPort == 0)
        {
            sPort = 0;
        }
        else
        {
            lPort = InterlockedDecrement(&lpDevice->lLastOutPort);

            if ((lPort > lpDevice->lpOutPorts->sHighPort) || (lPort < lpDevice->lpOutPorts->sLowPort))
            {
                lPort = lpDevice->lpOutPorts->sHighPort;
                InterlockedExchange(&lpDevice->lLastOutPort, lPort);
            }
            sPort = (USHORT)lPort;
        }
    }
    else sPort = 0;

    Device_Share(lpDevice);
    lpSocket->lpDevice = lpDevice;

    ReleaseSharedLock(&loDeviceList);
    ReleaseSharedLock(&lpService->loLock);

    if (!(dwFlags & BIND_FAKE) &&
        BindSocket(lpSocket->Socket, lBindAddress, sPort, ((dwFlags & BIND_REUSE) ? TRUE : FALSE)))
    {
        lpSocket->usPort = 0;
        UnbindSocket(lpSocket);
        return TRUE;
    }

    lpSocket->usPort = sPort;

    SetSocketOption(lpSocket, IO_SOCKET, SEND_LIMIT, &lpDevice->Outbound.dwClientBandwidthLimit, sizeof(DWORD));
    SetSocketOption(lpSocket, IO_SOCKET, RECEIVE_LIMIT, &lpDevice->Inbound.dwClientBandwidthLimit, sizeof(DWORD));

    if (pNetworkAddress) pNetworkAddress[0] = lHostAddress;
    if (pPort)           pPort[0] = sPort;

    return FALSE;
}

VOID UnbindSocket(LPIOSOCKET lpSocket)
{
    if (lpSocket->lpDevice)
    {
        Device_Unshare(lpSocket->lpDevice);
        lpSocket->lpDevice = NULL;
    }
}

/* -----------------------------------------------------------------------------
   Device lookup
----------------------------------------------------------------------------- */

LPIODEVICE Device_FindByName(LPTSTR tszDeviceName)
{
    LPIODEVICE lpDevice;

    AcquireSharedLock(&loDeviceList);
    for (lpDevice = lpDeviceList; lpDevice; lpDevice = lpDevice->lpNext)
    {
        if (!_tcsicmp(lpDevice->tszName, tszDeviceName)) break;
    }
    if (!lpDevice)
    {
        ReleaseSharedLock(&loDeviceList);
    }
    return lpDevice;
}

VOID Device_ReleaseLock(LPIODEVICE lpDevice)
{
    UNREFERENCED_PARAMETER(lpDevice);
    ReleaseSharedLock(&loDeviceList);
}

/* -----------------------------------------------------------------------------
   Service lookup and message location
----------------------------------------------------------------------------- */

LPIOSERVICE _Service_FindByName(LPTSTR tszServiceName)
{
    LPIOSERVICE lpService;

    for (lpService = lpServiceList; lpService; lpService = lpService->lpNext)
    {
        if (!_tcsicmp(tszServiceName, lpService->tszName)) return lpService;
    }
    return NULL;
}

LPTSTR Service_MessageLocation(LPIOSERVICE lpService)
{
    LPTSTR tszMessageLocation;

    AcquireSharedLock(&lpService->loLock);
    tszMessageLocation = (lpService->tszMessageLocation ? AllocateShared(lpService->tszMessageLocation, NULL, 0) : NULL);
    ReleaseSharedLock(&lpService->loLock);
    return tszMessageLocation;
}

LPIOSERVICE Service_FindByName(LPSTR szServiceName)
{
    LPIOSERVICE lpService;

    AcquireSharedLock(&loServiceList);
    lpService = _Service_FindByName(szServiceName);
    if (lpService)
    {
        AcquireSharedLock(&lpService->loLock);
    }
    ReleaseSharedLock(&loServiceList);
    return lpService;
}

VOID Service_ReleaseLock(LPIOSERVICE lpService)
{
    ReleaseSharedLock(&lpService->loLock);
}

/* -----------------------------------------------------------------------------
   Service policies
----------------------------------------------------------------------------- */

BOOL Service_IsAllowedUser(LPIOSERVICE lpService, LPUSERFILE lpUserFile)
{
    BOOL bReturn = TRUE;

    AcquireSharedLock(&lpService->loLock);
    if (lpService->tszAllowedUsers && !HavePermission(lpUserFile, lpService->tszAllowedUsers))
        bReturn = FALSE;
    ReleaseSharedLock(&lpService->loLock);
    return bReturn;
}

BOOL Service_RequireSecureAuth(LPIOSERVICE lpService, LPUSERFILE lpUserFile)
{
    BOOL bReturn = TRUE;

    AcquireSharedLock(&lpService->loLock);
    if (lpService->tszRequireSecureAuth && !HavePermission(lpUserFile, lpService->tszRequireSecureAuth))
        bReturn = FALSE;
    ReleaseSharedLock(&lpService->loLock);
    return bReturn;
}

BOOL Service_RequireSecureData(LPIOSERVICE lpService, LPUSERFILE lpUserFile)
{
    BOOL bReturn = TRUE;

    AcquireSharedLock(&lpService->loLock);
    if (lpService->tszRequireSecureData && !HavePermission(lpUserFile, lpService->tszRequireSecureData))
        bReturn = FALSE;
    ReleaseSharedLock(&lpService->loLock);
    return bReturn;
}

/* -----------------------------------------------------------------------------
   Device load from config
----------------------------------------------------------------------------- */

LPIODEVICE Device_Load(LPTSTR tszDeviceName)
{
    LPIODEVICE lpDevice;
    LPIOPORT   lpPort, lpFirstPort, lpLastPort, lpOutPort, lpFirstOutPort;
    DWORD      dwGlobalInboundBandwidthLimit, dwGlobalOutboundBandwidthLimit;
    DWORD      dwClientInboundBandwidthLimit, dwClientOutboundBandwidthLimit;
    BOOL       bGlobalInboundBandwidthLimit, bGlobalOutboundBandwidthLimit;
    LPVOID     lpMemory;
    TCHAR      pBuffer[_INI_LINE_LENGTH + 1];
    LPTSTR     tszHostName, tszPorts;
    TCHAR* tpCheck;
    DWORD      dwDeviceName, dwPort[2], dwRequired, dwTemp;
    BOOL       bRandomizePorts, bPortError, bNew;
    ULONG      lHostAddress, lBindAddress;

    lpMemory = NULL;
    bPortError = FALSE;
    bRandomizePorts = FALSE;
    bNew = FALSE;
    lpFirstPort = NULL;
    lpFirstOutPort = NULL;

    AcquireSharedLock(&loDeviceList);
    for (lpDevice = lpDeviceList; lpDevice; lpDevice = lpDevice->lpNext)
    {
        if (!_tcsicmp(lpDevice->tszName, tszDeviceName))
        {
            Device_Share(lpDevice);
            break;
        }
    }
    ReleaseSharedLock(&loDeviceList);

    if (!lpDevice)
    {
        bNew = TRUE;
        dwDeviceName = (DWORD)_tcslen(tszDeviceName);
        lpDevice = (LPIODEVICE)Allocate("ioFTPD:Device", sizeof(IODEVICE) + (dwDeviceName + 1) * sizeof(TCHAR));
        if (lpDevice)
        {
            ZeroMemory(lpDevice, sizeof(IODEVICE));
            lpDevice->tszName = (LPTSTR)&lpDevice[1];
            lpDevice->dwLastUpdate = SafeGetTickCount64() - 1000;
            lpDevice->lHostAddress = INADDR_NONE;
            lpDevice->lBindAddress = INADDR_NONE;
            _tcscpy(lpDevice->tszName, tszDeviceName);
            lpDevice->lDeviceNum = InterlockedIncrement(&lDeviceCounter);
            lpMemory = (LPVOID)lpDevice;
        }
    }

    if (lpDevice)
    {
        dwRequired = (lpDevice->bActive ? 30000 : 500);
        dwTemp = dwConfigCounter;
        if (dwTemp != lpDevice->dwLastConfigCounter)
        {
            lpDevice->dwLastConfigCounter = dwTemp;
            dwRequired = 0;
        }

        if (Time_DifferenceDW64(lpDevice->dwLastUpdate, SafeGetTickCount64()) >= dwRequired)
        {
            if (Config_Get_Int(&IniConfigFile, tszDeviceName, _TEXT("Global_Inbound_Bandwidth"), (PINT)&dwGlobalInboundBandwidthLimit) ||
                !dwGlobalInboundBandwidthLimit)
            {
                dwGlobalInboundBandwidthLimit = (DWORD)-1;
                bGlobalInboundBandwidthLimit = FALSE;
            }
            else bGlobalInboundBandwidthLimit = TRUE;

            if (Config_Get_Int(&IniConfigFile, tszDeviceName, _TEXT("Client_Inbound_Bandwidth"), (PINT)&dwClientInboundBandwidthLimit))
            {
                dwClientInboundBandwidthLimit = 0;
            }

            if (Config_Get_Int(&IniConfigFile, tszDeviceName, _TEXT("Global_Outbound_Bandwidth"), (PINT)&dwGlobalOutboundBandwidthLimit) ||
                !dwGlobalOutboundBandwidthLimit)
            {
                dwGlobalOutboundBandwidthLimit = (DWORD)-1;
                bGlobalOutboundBandwidthLimit = FALSE;
            }
            else bGlobalOutboundBandwidthLimit = TRUE;

            if (Config_Get_Int(&IniConfigFile, tszDeviceName, _TEXT("Client_Outbound_Bandwidth"), (PINT)&dwClientOutboundBandwidthLimit))
            {
                dwClientOutboundBandwidthLimit = 0;
            }

            if ((tszHostName = Config_Get(&IniConfigFile, tszDeviceName, _TEXT("Host"), pBuffer, NULL)))
            {
                lHostAddress = HostToAddress(tszHostName);
                if (lHostAddress == INADDR_NONE)
                {
                    if (lpDevice->lHostAddress != INADDR_NONE)
                    {
                        lHostAddress = lpDevice->lHostAddress;
                        Putlog(LOG_ERROR, _T("Unable to read/resolve host address: '%s' (using old value) Device='%s'\r\n"), tszHostName, tszDeviceName);
                    }
                    else
                    {
                        Putlog(LOG_ERROR, _T("Unable to read/resolve host address: '%s' Device='%s'\r\n"), tszHostName, tszDeviceName);
                    }
                }
            }
            else lHostAddress = INADDR_NONE;

            if ((tszHostName = Config_Get(&IniConfigFile, tszDeviceName, _TEXT("Bind"), pBuffer, NULL)))
            {
                lBindAddress = HostToAddress(tszHostName);
                if (lBindAddress == INADDR_NONE)
                {
                    Putlog(LOG_ERROR, _T("Unable to read/resolve bind address: '%s' (using all interfaces) Device='%s'\r\n"), tszHostName, tszDeviceName);
                    lBindAddress = INADDR_ANY;
                }
            }
            else lBindAddress = INADDR_ANY;

            if ((tszPorts = Config_Get(&IniConfigFile, tszDeviceName, _TEXT("Ports"), pBuffer, NULL)))
            {
                RemoveSpaces(tszPorts);
                Config_Get_Bool(&IniConfigFile, tszDeviceName, _TEXT("Random"), &bRandomizePorts);

                for (;;)
                {
                    while (!_istdigit(tszPorts[0]) && tszPorts[0] != _TEXT('\0')) tszPorts++;
                    if (tszPorts[0] == _TEXT('\0')) break;

                    dwPort[0] = (DWORD)_tcstoul(tszPorts, &tpCheck, 10);

                    if (tpCheck > tszPorts && tpCheck[0] == _TEXT('-'))
                    {
                        tszPorts = &tpCheck[1];
                        dwPort[1] = (DWORD)_tcstoul(tszPorts, &tpCheck, 10);
                    }
                    else dwPort[1] = dwPort[0];

                    if (tpCheck > tszPorts && (tpCheck[0] == _TEXT(',') || tpCheck[0] == _TEXT('\0')))
                    {
                        lpPort = (LPIOPORT)Allocate("Device:Port", sizeof(IOPORT));
                        if (!lpPort)
                        {
                            bPortError = TRUE;
                            break;
                        }

                        lpPort->sLowPort = (USHORT)min(dwPort[0], dwPort[1]);
                        lpPort->sHighPort = (USHORT)max(dwPort[0], dwPort[1]);
                        lpPort->lpNext = NULL;

                        if (lpFirstPort) lpLastPort->lpNext = lpPort;
                        else             lpFirstPort = lpPort;

                        lpLastPort = lpPort;
                        tszPorts = tpCheck;
                    }
                }
            }

            if ((tszPorts = Config_Get(&IniConfigFile, tszDeviceName, _TEXT("Out_Ports"), pBuffer, NULL)))
            {
                RemoveSpaces(tszPorts);

                for (;;)
                {
                    while (!_istdigit(tszPorts[0]) && tszPorts[0] != _TEXT('\0')) tszPorts++;
                    if (tszPorts[0] == _TEXT('\0')) break;

                    dwPort[0] = (DWORD)_tcstoul(tszPorts, &tpCheck, 10);

                    if (tpCheck > tszPorts && tpCheck[0] == _TEXT('-'))
                    {
                        tszPorts = &tpCheck[1];
                        dwPort[1] = (DWORD)_tcstoul(tszPorts, &tpCheck, 10);
                    }
                    else dwPort[1] = dwPort[0];

                    if (tpCheck > tszPorts && (tpCheck[0] == _TEXT(',') || tpCheck[0] == _TEXT('\0')))
                    {
                        lpPort = (LPIOPORT)Allocate("Device:OutPort", sizeof(IOPORT));
                        if (!lpPort)
                        {
                            bPortError = TRUE;
                            break;
                        }

                        lpPort->sLowPort = (USHORT)min(dwPort[0], dwPort[1]);
                        lpPort->sHighPort = (USHORT)max(dwPort[0], dwPort[1]);
                        lpPort->lpNext = NULL;

                        if (lpFirstOutPort) lpLastPort->lpNext = lpPort;
                        else                lpFirstOutPort = lpPort;

                        lpLastPort = lpPort;
                        tszPorts = tpCheck;
                    }
                }
            }

            if (lHostAddress != INADDR_NONE && !bPortError)
            {
                AcquireExclusiveLock(&loDeviceList);

                lpPort = lpDevice->lpPort;
                lpOutPort = lpDevice->lpOutPorts;

                lpDevice->lHostAddress = lHostAddress;
                lpDevice->lBindAddress = lBindAddress;
                lpDevice->dwLastUpdate = SafeGetTickCount64();
                lpDevice->lpPort = lpFirstPort;
                lpDevice->lpOutPorts = lpFirstOutPort;
                lpDevice->bRandomizePorts = bRandomizePorts;
                if (!lpDevice->bDisabled) lpDevice->bActive = TRUE;

                lpDevice->Inbound.dwClientBandwidthLimit = dwClientInboundBandwidthLimit;
                lpDevice->Outbound.dwClientBandwidthLimit = dwClientOutboundBandwidthLimit;
                lpDevice->Inbound.bGlobalBandwidthLimit = bGlobalInboundBandwidthLimit;
                lpDevice->Outbound.bGlobalBandwidthLimit = bGlobalOutboundBandwidthLimit;
                lpDevice->Inbound.dwGlobalBandwidthLimit = dwGlobalInboundBandwidthLimit;
                lpDevice->Outbound.dwGlobalBandwidthLimit = dwGlobalOutboundBandwidthLimit;

                if (lpMemory)
                {
                    if (lpDeviceList) lpDeviceList->lpPrev = lpDevice;
                    lpDevice->lpNext = lpDeviceList;
                    lpDeviceList = lpDevice;
                    lpMemory = NULL;
                }

                lpFirstPort = lpPort;
                lpFirstOutPort = lpOutPort;

                ReleaseExclusiveLock(&loDeviceList);
            }
            else
            {
                Putlog(LOG_ERROR, _T("Device '%s' failed to start due to HOST/BIND/PORT error.\r\n"), tszDeviceName);
                lpDevice = NULL;
            }

            while ((lpPort = lpFirstPort) != NULL)
            {
                lpFirstPort = lpFirstPort->lpNext;
                Free(lpPort);
            }
            while ((lpOutPort = lpFirstOutPort) != NULL)
            {
                lpFirstOutPort = lpFirstOutPort->lpNext;
                Free(lpOutPort);
            }
        }
    }
    Free(lpMemory);

    if (lpDevice && bNew)
    {
        Device_Share(lpDevice);
    }

    return lpDevice;
}

/* -----------------------------------------------------------------------------
   Service data devices helper
----------------------------------------------------------------------------- */

VOID Service_FreeDataDevices(LPIODEVICE* lpDevices)
{
    DWORD n;
    if (lpDevices)
    {
        for (n = 0; lpDevices[n]; n++) Device_Unshare(lpDevices[n]);
        Free(lpDevices);
    }
}

/* -----------------------------------------------------------------------------
   Service type and config getters
----------------------------------------------------------------------------- */

BOOL Service_GetType(LPTSTR tszServiceName, LPIOSERVICE lpService)
{
    LPTSTR tszType;
    BOOL   bReturn = FALSE;

    tszType = Config_Get(&IniConfigFile, tszServiceName, _TEXT("Type"), NULL, NULL);
    if (!tszType) return TRUE;

    if (!_tcsicmp(tszType, "FTP"))
    {
        lpService->dwType = C_FTP;
        lpService->lpAcceptProc = FTP_New_Client;
        lpService->lpCloseProc = FTP_Close_Connection;
    }
    else bReturn = TRUE;

    Free(tszType);
    return bReturn;
}

LPIODEVICE* Service_GetDataDevices(LPTSTR tszServiceName, LPDWORD lpDeviceCount)
{
    IO_STRING   DeviceList;
    LPIODEVICE* lpDevices, lpDevice;
    DWORD       dwDevices, dwDevice, n;
    LPTSTR      tszDeviceList, tszDevice;

    lpDevices = NULL;
    if (!(tszDeviceList = Config_Get(&IniConfigFile, tszServiceName, _TEXT("Data_Devices"), NULL, NULL))) return NULL;

    if (!SplitString(tszDeviceList, &DeviceList))
    {
        dwDevice = 0;
        dwDevices = GetStringItems(&DeviceList);

        lpDevices = (LPIODEVICE*)Allocate("Service:DataDevice", sizeof(LPIODEVICE) * (dwDevices + 1));

        if (lpDevices)
        {
            for (n = 0; n < dwDevices; n++)
            {
                tszDevice = GetStringIndexStatic(&DeviceList, n);
                lpDevice = Device_Load(tszDevice);
                if (lpDevice) lpDevices[dwDevice++] = lpDevice;
            }
        }

        if (!dwDevice)
        {
            Free(lpDevices);
            lpDevices = NULL;
        }
        else
        {
            lpDevices[dwDevice] = NULL;
            lpDeviceCount[0] = dwDevice;
        }

        FreeString(&DeviceList);
    }
    Free(tszDeviceList);
    return lpDevices;
}

/* -----------------------------------------------------------------------------
   Service lifecycle: shutdown and start/stop
----------------------------------------------------------------------------- */

VOID Service_Shutdown(LPIOSERVICE lpService)
{
    SOCKET      Socket;
    LPNEWCLIENT lpNC;
    long        lNumClients;
    long        i;
    DWORD       dwError;

    lpService->bActive = FALSE;
    lNumClients = lpService->lAcceptClients;

    Socket = (SOCKET)InterlockedExchange(&lpService->Socket, INVALID_SOCKET);
    if (Socket != INVALID_SOCKET)
    {
        closesocket(Socket);
    }

    for (i = 0; i < 10; i++)
    {
        lpNC = (LPNEWCLIENT)InterlockedExchangePointer(&lpService->lpAcceptClients[i], 0);
        if (lpNC && (lpNC != (LPNEWCLIENT)-1))
        {
            Socket = (SOCKET)InterlockedExchange(&lpNC->Socket, INVALID_SOCKET);
            if (Socket != INVALID_SOCKET)
            {
                if (closesocket(Socket))
                {
                    dwError = WSAGetLastError();
                    UNREFERENCED_PARAMETER(dwError);
                }
            }
        }
    }

    for (i = 0; i < 50; i++)
    {
        if (!lpService->lAcceptClients) break;
        SleepEx(50, TRUE);
    }

    {
        long stillOpen = lpService->lAcceptClients;
        if (stillOpen)
        {
            Putlog(LOG_ERROR, _T("Failed to close %d of %d pre-created sockets.\r\n"), stillOpen, lNumClients);
        }
    }

    lpService->dwTestCounter = 0;
}

LONG Service_GetMaxClients(LPTSTR tszServiceName)
{
    LONG lMaxClients = 10;
    Config_Get_Int(&IniConfigFile, tszServiceName, _TEXT("User_Limit"), (PINT)&lMaxClients);
    return lMaxClients;
}

LPTSTR Service_GetAllowedUsers(LPTSTR tszServiceName)
{
    return Config_Get(&IniConfigFile, tszServiceName, _TEXT("Allowed_Users"), NULL, NULL);
}

LPTSTR Service_GetListenDevice(LPTSTR tszServiceName)
{
    return Config_Get(&IniConfigFile, tszServiceName, _TEXT("Device_Name"), NULL, NULL);
}

LPTSTR Service_GetRequireSecureAuth(LPTSTR tszServiceName)
{
    return Config_Get(&IniConfigFile, tszServiceName, _TEXT("Require_Encrypted_Auth"), NULL, NULL);
}

LPTSTR Service_GetRequireSecureData(LPTSTR tszServiceName)
{
    return Config_Get(&IniConfigFile, tszServiceName, _TEXT("Require_Encrypted_Data"), NULL, NULL);
}

BOOL Service_GetExternalIdentity(LPTSTR tszServiceName)
{
    BOOL bExternalIdentity = FALSE;
    Config_Get_Bool(&IniConfigFile, tszServiceName, _TEXT("Get_External_Ident"), &bExternalIdentity);
    return bExternalIdentity;
}

BOOL Service_GetRandomizeDataDeviceUse(LPTSTR tszServiceName)
{
    BOOL bRandomize = FALSE;
    Config_Get_Bool(&IniConfigFile, tszServiceName, _TEXT("Random_Devices"), &bRandomize);
    return bRandomize;
}

/* -----------------------------------------------------------------------------
   SSL credentials
----------------------------------------------------------------------------- */

VOID Service_GetCredentials(LPIOSERVICE lpService, BOOL bCreate)
{
    TCHAR   pBuffer[_INI_LINE_LENGTH + 1];
    BOOL    bResult;
    LPTSTR  tszEncryptionProtocol, tszCert;
    size_t  stLen;
    const SSL_METHOD* Method;

    if (lpService->pSecureCtx)
    {
        return;
    }

    lpService->bExplicitEncryption = TRUE;
    Config_Get_Bool(&IniConfigFile, lpService->tszName, _TEXT("Explicit_Encryption"), &lpService->bExplicitEncryption);

    Method = TLS_method();
    lpService->bTlsSupported = TRUE;
    lpService->bSslSupported = TRUE;

    tszEncryptionProtocol = Config_Get(&IniConfigFile, lpService->tszName, _TEXT("Encryption_Protocol"), pBuffer, NULL);
    if (tszEncryptionProtocol)
    {
        Method = TLS_method();
        lpService->bTlsSupported = TRUE;
        lpService->bSslSupported = FALSE;

        tszEncryptionProtocol = Config_Get(&IniConfigFile, lpService->tszName, _TEXT("Encryption_Protocol"), pBuffer, NULL);
        if (tszEncryptionProtocol)
        {
            if (!_tcsicmp(tszEncryptionProtocol, _TEXT("SSL2")) ||
                !_tcsicmp(tszEncryptionProtocol, _TEXT("SSL3")) ||
                !_tcsicmp(tszEncryptionProtocol, _TEXT("SSL")))
            {
                Putlog(LOG_GENERAL, _T("SSL: \"Legacy protocol requested (%s)\" \"Service=%s\" \"Falling back to TLS\"\r\n"),
                    tszEncryptionProtocol, lpService->tszName);
                Method = TLS_method();
                lpService->bTlsSupported = TRUE;
                lpService->bSslSupported = FALSE;
            }
            else if (!_tcsicmp(tszEncryptionProtocol, _TEXT("TLS")))
            {
                Method = TLS_method();
                lpService->bTlsSupported = TRUE;
                lpService->bSslSupported = FALSE;
            }
            else
            {
                Putlog(LOG_GENERAL, _T("SSL: \"Unknown Encryption_Protocol=%s\" \"Service=%s\" \"Defaulting to TLS\"\r\n"),
                    tszEncryptionProtocol, lpService->tszName);
                Method = TLS_method();
                lpService->bTlsSupported = TRUE;
                lpService->bSslSupported = FALSE;
            }
        }
    }

    if ((tszCert = Config_Get(&IniConfigFile, lpService->tszName, _TEXT("Certificate_Name"), pBuffer, 0)) != NULL)
    {
        if (!lpService->tszServiceValue || _tcscmp(lpService->tszServiceValue, tszCert))
        {
            stLen = _tcslen(tszCert);
            tszCert = (TCHAR*)Allocate("Service::ServiceValue", (stLen + 1) * sizeof(TCHAR));
            if (!tszCert)
            {
                return;
            }
            _tcscpy(tszCert, pBuffer);

            if (lpService->tszServiceValue) Free(lpService->tszServiceValue);
            lpService->tszServiceValue = tszCert;
        }

        if (lpService->dwFoundCredentials == 0 || lpService->tszServiceValue == tszCert)
        {
            bResult = Secure_Create_Ctx(lpService->tszName, tszCert, Method, &lpService->pSecureCtx);
            if (!bResult)
            {
                lpService->dwFoundCredentials = 1;
                Putlog(LOG_GENERAL, _T("SSL: \"Found certificate\" \"name=%s\" \"Service=%s\" \"(Certificate_name)\"\r\n"),
                    tszCert, lpService->tszName);
                return;
            }

            if (!lpService->dwFoundCredentials && !bCreate)
            {
                Putlog(LOG_ERROR, _T("SSL: \"Unable to locate certificate\" \"name=%s\" \"Service=%s\" \"(Certificate_name)\"\r\n"),
                    tszCert, lpService->tszName);
            }
        }
    }
    else
    {
        if (lpService->tszServiceValue) Free(lpService->tszServiceValue);
        lpService->tszServiceValue = NULL;
    }

    if (lpService->lpDevice && lpService->lpDevice->lHostAddress != INADDR_ANY)
    {
        if ((tszCert = Config_Get(&IniConfigFile, lpService->lpDevice->tszName, _TEXT("HOST"), pBuffer, 0)) != NULL)
        {
            if (!lpService->tszHostValue || _tcscmp(lpService->tszHostValue, tszCert))
            {
                stLen = _tcslen(tszCert);
                tszCert = (TCHAR*)Allocate("Service::HostValue", (stLen + 1) * sizeof(TCHAR));
                if (!tszCert)
                {
                    return;
                }
                _tcscpy(tszCert, pBuffer);

                if (lpService->tszHostValue) Free(lpService->tszHostValue);
                lpService->tszHostValue = tszCert;
            }

            if (lpService->dwFoundCredentials == 0 || lpService->tszHostValue == tszCert)
            {
                bResult = Secure_Create_Ctx(lpService->tszName, tszCert, Method, &lpService->pSecureCtx);
                if (!bResult)
                {
                    lpService->dwFoundCredentials = 2;
                    Putlog(LOG_GENERAL, _T("SSL: \"Found certificate\" \"name=%s\" \"Service=%s\" \"Device=%s\" \"(HOST=)\"\r\n"),
                        tszCert, lpService->tszName, lpService->lpDevice->tszName);
                    return;
                }

                if (!lpService->dwFoundCredentials && !bCreate)
                {
                    Putlog(LOG_GENERAL, _T("SSL: \"Unable to locate certificate\" \"name=%s\" \"Service=%s\" \"Device=%s\" \"(HOST=)\"\r\n"),
                        tszCert, lpService->tszName, lpService->lpDevice->tszName);
                }
            }
        }
    }
    else
    {
        if (lpService->tszHostValue) Free(lpService->tszHostValue);
        lpService->tszHostValue = NULL;
    }

    if (lpService->dwFoundCredentials)
    {
        return;
    }

    bResult = Secure_Create_Ctx(lpService->tszName, _T("ioFTPD"), Method, &lpService->pSecureCtx);
    if (!bResult)
    {
        lpService->dwFoundCredentials = 3;
        Putlog(LOG_GENERAL, _T("SSL: \"Found default certificate\" \"name=ioFTPD\" \"Service=%s\"\r\n"), lpService->tszName);
        return;
    }

    if (!bCreate)
    {
        lpService->dwFoundCredentials = 4;
        Putlog(LOG_GENERAL, _T("SSL: \"Unable to locate default certificate\" \"name=ioFTPD\" \"Service=%s\"\r\n"), lpService->tszName);
        dwNeedCerts++;
    }
}

/* -----------------------------------------------------------------------------
   Listen port and messages path
----------------------------------------------------------------------------- */

USHORT Service_GetListenPort(LPTSTR tszServiceName)
{
    INT iPort = 0;
    Config_Get_Int(&IniConfigFile, tszServiceName, _TEXT("Port"), &iPort);
    return (USHORT)iPort;
}

LPTSTR Service_GetMessageLocation(LPTSTR tszServiceName)
{
    TCHAR  pBuffer[_INI_LINE_LENGTH + 1];
    LPTSTR tszLocation;
    DWORD  dwLocation;

    tszLocation = Config_Get(&IniConfigFile, tszServiceName, _TEXT("Messages"), pBuffer, NULL);
    if (tszLocation)
    {
        dwLocation = (DWORD)_tcslen(tszLocation);
        tszLocation = AllocateShared(NULL, "Service:Messages", (dwLocation + 1) * sizeof(TCHAR));
        if (tszLocation) _tcscpy(tszLocation, pBuffer);
    }
    return tszLocation;
}

/* -----------------------------------------------------------------------------
   AcceptEx
----------------------------------------------------------------------------- */

LRESULT Service_AcceptEx(WPARAM wParam, LPARAM lParam)
{
    LPIOSERVICE lpService = (LPIOSERVICE)lParam;
    LPNEWCLIENT lpNewClient;
    DWORD       dwNull;

    if (!lpService->bActive)
    {
        InterlockedExchangePointer(&lpService->lpAcceptClients[wParam], (PVOID)-1);
        return TRUE;
    }

    lpNewClient = (LPNEWCLIENT)Allocate("Service:Accept:Socket", sizeof(NEWCLIENT));
    if (!lpNewClient)
    {
        InterlockedExchangePointer(&lpService->lpAcceptClients[wParam], (PVOID)-1);
        return TRUE;
    }

    ZeroMemory(lpNewClient, sizeof(NEWCLIENT));
    lpNewClient->Overlapped.lpProc = (LPVOID)Service_AcceptClient;
    lpNewClient->Overlapped.lpContext = (LPVOID)lpNewClient;
    lpNewClient->lpService = lpService;
    lpNewClient->dwAcceptIndex = (DWORD)wParam;
    lpNewClient->Socket = OpenSocket();

    if (lpNewClient->Socket != INVALID_SOCKET)
    {
        if (Accept(lpService->Socket, lpNewClient->Socket, (LPVOID)lpNewClient->pBuffer, 0,
            sizeof(struct sockaddr_in) + 32, sizeof(struct sockaddr_in) + 32, &dwNull,
            (LPOVERLAPPED)&lpNewClient->Overlapped) || WSAGetLastError() == ERROR_IO_PENDING)
        {
            InterlockedExchangePointer(&lpService->lpAcceptClients[wParam], lpNewClient);
            InterlockedIncrement(&lpService->lAcceptClients);
            return FALSE;
        }
        closesocket(lpNewClient->Socket);
    }

    Putlog(LOG_ERROR, _T("Failed in Service_AcceptEx: index = %d\r\n"), (int)wParam);
    InterlockedExchangePointer(&lpService->lpAcceptClients[wParam], (PVOID)-1);
    Free(lpNewClient);
    return TRUE;
}

BOOL Service_LogError(LPVOID lError)
{
    Putlog(LOG_ERROR, "AcceptEx() failed with error: %u\r\n", (DWORD)lError);
    return FALSE;
}

VOID Service_AcceptClient(LPVOID lpNewClient, DWORD dwBytesReceived, DWORD dwLastError)
{
    LPNEWCLIENT        lpNC = (LPNEWCLIENT)lpNewClient;
    LPIOSERVICE        lpService = lpNC->lpService;
    SOCKET             Socket;
    INT                iSize[2];
    LONG               lLastConnect;
    struct sockaddr_in* pRemoteAddr;

    if (dwDaemonStatus != DAEMON_SHUTDOWN)
    {
        InterlockedExchangePointer(&lpService->lpAcceptClients[lpNC->dwAcceptIndex], 0);
        InterlockedDecrement(&lpService->lAcceptClients);
    }

    if ((dwDaemonStatus != DAEMON_ACTIVE) || (lpNC->Socket == INVALID_SOCKET))
    {
        dwLastError = ERROR_OPERATION_ABORTED;
    }
    else if (lpService->bActive)
    {
        PostMessage(GetMainWindow(), WM_ACCEPTEX, lpNC->dwAcceptIndex, (LPARAM)(lpNC->lpService));
    }

    switch (dwLastError)
    {
    case NO_ERROR:
        GetAcceptSockAddrs(lpNC->pBuffer,
            0, sizeof(struct sockaddr_in) + 32, sizeof(struct sockaddr_in) + 32,
            (LPSOCKADDR*)&lpNC->lpLocalSockAddress, &iSize[0],
            (LPSOCKADDR*)&lpNC->lpRemoteSockAddress, &iSize[1]);

        lLastConnect = (LONG)time(NULL);
        InterlockedExchange(&lpService->lLastConnect, lLastConnect);

        pRemoteAddr = (struct sockaddr_in*)lpNC->lpRemoteSockAddress;
        if ((pRemoteAddr->sin_family == lpNC->lpService->addrLocal.sin_family) &&
            (pRemoteAddr->sin_port == lpNC->lpService->addrLocal.sin_port) &&
            (pRemoteAddr->sin_addr.s_addr == lpNC->lpService->addrLocal.sin_addr.s_addr))
        {
            lpService->addrLocal.sin_port = 0;
            Socket = (SOCKET)InterlockedExchange(&lpNC->Socket, INVALID_SOCKET);
            if (Socket != INVALID_SOCKET)
            {
                closesocket(Socket);
            }
            Free(lpNC);
            return;
        }

        lpNC->lpHostInfo = RegisterNetworkAddress(
            (PBYTE)&lpNC->lpRemoteSockAddress->sin_addr.s_addr,
            sizeof(lpNC->lpRemoteSockAddress->sin_addr.s_addr));
        if (!lpNC->lpHostInfo)
        {
            goto CLEANUP;
        }

        if (QueueJob(IdentifyClient, lpNewClient, JOB_PRIORITY_NORMAL))
        {
            goto CLEANUP;
        }
        break;

    default:
        QueueJob(Service_LogError, (LPVOID)dwLastError, JOB_PRIORITY_LOW);
        /* fallthrough */
    case ERROR_OPERATION_ABORTED:
    CLEANUP:
        Socket = (SOCKET)InterlockedExchange(&lpNC->Socket, INVALID_SOCKET);
        if (Socket != INVALID_SOCKET)
        {
            closesocket(Socket);
        }
        Free(lpNC);
        return;
    }
}

/* -----------------------------------------------------------------------------
   Address list helpers
----------------------------------------------------------------------------- */

VOID ioAddressListFree(LPIOADDRESSLIST lpAddressList)
{
    LPIOADDRESS lpAddress;
    DWORD n;

    if (!InterlockedDecrement(&lpAddressList->lReferenceCount))
    {
        for (n = 0; n < lpAddressList->dwAddressArray; n++)
        {
            lpAddress = &lpAddressList->lpAddressArray[n];
            if (lpAddress->tszString) Free(lpAddress->tszString);
        }
        if (lpAddressList->dwAddressArray && lpAddressList->lpAddressArray)
        {
            Free(lpAddressList->lpAddressArray);
        }
        Free(lpAddressList);
    }
}

BOOL ioAddressFind(LPIOADDRESSLIST lpAddressList, struct in_addr Addr)
{
    LPSTR       szHost;
    LPIOADDRESS lpAddress;
    DWORD       n;

    szHost = inet_ntoa(Addr);

    for (n = 0; n < lpAddressList->dwAddressArray; n++)
    {
        lpAddress = &lpAddressList->lpAddressArray[n];
        if (lpAddress->Addr.s_addr != INADDR_NONE)
        {
            if (lpAddress->Addr.s_addr == Addr.s_addr)
                return TRUE;
            continue;
        }
        if (!lpAddress->tszString || !szHost) continue;
        if (!iCompare(lpAddress->tszString, szHost))
            return TRUE;
    }
    return FALSE;
}

/* -----------------------------------------------------------------------------
   Start/Stop a service and manage config changes
----------------------------------------------------------------------------- */

BOOL Service_Start(LPTSTR tszServiceName)
{
    LPIOSERVICE       lpService;
    LPIODEVICE        lpDevice, * lpDevices;
    ULONG             lAddress;
    USHORT            sPort;
    BOOL              bReturn, bSame, bNew;
    LPTSTR            tszDevice, tszField, tszTemp;
    TCHAR             tszFieldName[_MAX_NAME];
    DWORD             dwServiceName, n, m;
    LPIOADDRESSLIST   lpAddrList;
    LPIOADDRESS       lpNewAddr, lpOldAddr;

    if (!tszServiceName) return TRUE;

    bReturn = TRUE;
    bNew = FALSE;
    dwServiceName = (DWORD)_tcslen(tszServiceName);

    AcquireExclusiveLock(&loServiceList);
    lpService = _Service_FindByName(tszServiceName);

    if (!lpService)
    {
        lpService = (LPIOSERVICE)Allocate("ioFTPD:Service", sizeof(IOSERVICE) + (dwServiceName + 1) * sizeof(TCHAR));
        if (lpService)
        {
            ZeroMemory(lpService, sizeof(IOSERVICE));
            lpService->tszName = (LPSTR)&lpService[1];
            lpService->tszMessageLocation = Service_GetMessageLocation(tszServiceName);
            _tcscpy(lpService->tszName, tszServiceName);
            lpService->Socket = INVALID_SOCKET;

            if (lpService->tszMessageLocation &&
                !Service_GetType(tszServiceName, lpService) &&
                InitializeLockObject(&lpService->loLock))
            {
                lpService->lpNext = lpServiceList;
                lpServiceList = lpService;
            }
            else
            {
                FreeShared(lpService->tszMessageLocation);
                lpService->tszMessageLocation = NULL;
                Free(lpService);
                lpService = NULL;
            }

            lpService->addrLocal.sin_family = AF_INET;
            lpService->addrService.sin_family = AF_INET;
            bNew = TRUE;
        }
    }

    if (lpService)
    {
        tszDevice = Service_GetListenDevice(tszServiceName);

        lpDevice = NULL;
        lAddress = INADDR_NONE;
        sPort = 0;

        if (tszDevice)
        {
            lpDevice = Device_Load(tszDevice);
            sPort = Service_GetListenPort(tszServiceName);

            if (lpDevice && lpDevice->lHostAddress != INADDR_NONE && sPort != 0 && lpDevice->bActive)
            {
                lAddress = (lpDevice->lBindAddress != INADDR_NONE ? lpDevice->lBindAddress : lpDevice->lHostAddress);

                if (lAddress != lpService->lAddress ||
                    sPort != lpService->sPort ||
                    !lpService->bActive)
                {
                    Service_Shutdown(lpService);

                    lpService->Socket = OpenSocket();
                    if (lpService->Socket != INVALID_SOCKET)
                    {
                        if (!BindSocket(lpService->Socket, lAddress, sPort, TRUE) &&
                            !listen(lpService->Socket, SOMAXCONN) &&
                            !BindCompletionPort((HANDLE)lpService->Socket))
                        {
                            lpService->bActive = TRUE;
                            for (n = 0; n < 10; n++) PostMessage(GetMainWindow(), WM_ACCEPTEX, n, (LPARAM)lpService);
                        }
                    }

                    if (!lpService->bActive) Service_Shutdown(lpService);
                }
            }
            else
            {
                Service_Shutdown(lpService);
                lpDevice = NULL;
            }

            Free(tszDevice);
        }
        else Service_Shutdown(lpService);

        AcquireExclusiveLock(&lpService->loLock);

        lpDevices = lpService->lpDataDevices;
        if (lpService->tszRequireSecureAuth) Free(lpService->tszRequireSecureAuth);
        if (lpService->tszRequireSecureData) Free(lpService->tszRequireSecureData);
        if (lpService->tszAllowedUsers)      Free(lpService->tszAllowedUsers);
        if (lpDevice) Device_Share(lpDevice);
        if (lpService->lpDevice) Device_Unshare(lpService->lpDevice);

        lpService->lAddress = lAddress;
        lpService->sPort = sPort;

        if (lAddress == INADDR_ANY)
        {
            lpService->addrService.sin_addr.s_addr = 0x0100007F;
            lpService->addrLocal.sin_addr.s_addr = 0x0100007F;
        }
        else
        {
            lpService->addrService.sin_addr.s_addr = lpService->lAddress;
            lpService->addrLocal.sin_addr.s_addr = lpService->lAddress;
        }

        lpService->addrService.sin_port = htons(sPort);
        lpService->lpDevice = lpDevice;
        lpService->lpDataDevices = Service_GetDataDevices(tszServiceName, &lpService->dwDataDevices);
        lpService->bRandomDataDevices = Service_GetRandomizeDataDeviceUse(tszServiceName);
        lpService->tszRequireSecureAuth = Service_GetRequireSecureAuth(tszServiceName);
        lpService->tszRequireSecureData = Service_GetRequireSecureData(tszServiceName);
        lpService->lMaxClients = Service_GetMaxClients(tszServiceName);
        lpService->tszAllowedUsers = Service_GetAllowedUsers(tszServiceName);

        _tcscpy(tszFieldName, _T("BNC_HOST_"));
        for (m = 0; m <= 9; m++)
        {
            if (lpService->tszBncAddressArray[m])
            {
                Free(lpService->tszBncAddressArray[m]);
                lpService->tszBncAddressArray[m] = NULL;
            }
        }

        for (n = 1, m = 0; n <= 10; n++)
        {
            itoa(n, &tszFieldName[9], 10);
            if (!(lpService->tszBncAddressArray[m++] = Config_Get(&IniConfigFile, tszServiceName, tszFieldName, NULL, NULL)))
            {
                break;
            }
        }

        lpAddrList = Allocate(_T("lpPortDeniedAddresses"), sizeof(*lpAddrList));
        if (lpAddrList)
        {
            lpAddrList->lReferenceCount = 1;
            lpAddrList->dwAddressArray = 0;
            lpAddrList->lpAddressArray = NULL;

            m = 0;
            bSame = TRUE;

            _tcscpy(tszFieldName, _T("Deny_Port_Host_"));
            for (n = 1; ; n++)
            {
                itoa(n, &tszFieldName[15], 10);
                tszField = Config_Get(&IniConfigFile, tszServiceName, tszFieldName, NULL, NULL);
                if (!tszField)
                {
                    if (bSame && lpService->lpPortDeniedAddresses && (n - 1 == lpService->lpPortDeniedAddresses->dwAddressArray))
                    {
                        ioAddressListFree(lpAddrList);
                        lpAddrList = NULL;
                        break;
                    }
                    if (lpService->lpPortDeniedAddresses)
                    {
                        ioAddressListFree(lpService->lpPortDeniedAddresses);
                    }
                    if (lpAddrList->dwAddressArray)
                    {
                        lpService->lpPortDeniedAddresses = lpAddrList;
                    }
                    else
                    {
                        lpService->lpPortDeniedAddresses = NULL;
                        ioAddressListFree(lpAddrList);
                        lpAddrList = NULL;
                    }
                    break;
                }

                if (n - 1 >= m)
                {
                    if ((m == 0) && lpService->lpPortDeniedAddresses && lpService->lpPortDeniedAddresses->dwAddressArray)
                    {
                        m = lpService->lpPortDeniedAddresses->dwAddressArray;
                    }
                    if (n - 1 >= m)
                    {
                        m += 10;
                    }
                    lpOldAddr = ReAllocate(lpAddrList->lpAddressArray, _T("lpAddressArray"), sizeof(*lpAddrList->lpAddressArray) * m);
                    if (!lpOldAddr)
                    {
                        ioAddressListFree(lpAddrList);
                        break;
                    }
                    lpAddrList->lpAddressArray = lpOldAddr;
                }

                lpAddrList->dwAddressArray++;
                lpNewAddr = &lpAddrList->lpAddressArray[n - 1];

                tszTemp = tszField;
                while (*tszTemp && *tszTemp != _T('*') && *tszTemp != _T('?') && *tszTemp != _T('[') && *tszTemp != _T(']')) tszTemp++;
                if (!*tszTemp && IsNumericIP(tszField) && ((lpNewAddr->Addr.s_addr = inet_addr(tszField)) != INADDR_NONE))
                {
                    lpNewAddr->tszString = NULL;
                    Free(tszField);
                }
                else
                {
                    lpNewAddr->Addr.s_addr = INADDR_NONE;
                    lpNewAddr->tszString = tszField;
                }

                if (bSame && lpService->lpPortDeniedAddresses && (n - 1 <= lpService->lpPortDeniedAddresses->dwAddressArray))
                {
                    lpOldAddr = &lpService->lpPortDeniedAddresses->lpAddressArray[n - 1];
                    if ((lpOldAddr->Addr.s_addr == lpNewAddr->Addr.s_addr) &&
                        (lpOldAddr->tszString && lpNewAddr->tszString && !_tcscmp(lpOldAddr->tszString, lpNewAddr->tszString)))
                    {
                        // same
                    }
                    else
                    {
                        bSame = FALSE;
                    }
                }
            }
        }

        if (!lpService->lpPortDeniedAddresses || !lpService->lpPortDeniedAddresses->dwAddressArray)
        {
            if (lpService->lpPortDeniedAddresses)
            {
                ioAddressListFree(lpService->lpPortDeniedAddresses);
            }
            lpService->lpPortDeniedAddresses = lpDefaultPortDenyList;
            InterlockedIncrement(&lpDefaultPortDenyList->lReferenceCount);
        }

        if (lpService->bActive)
        {
            Service_GetCredentials(lpService, FALSE);
        }

        ReleaseExclusiveLock(&lpService->loLock);

        Service_FreeDataDevices(lpDevices);
    }

    ReleaseExclusiveLock(&loServiceList);
    UNREFERENCED_PARAMETER(bNew);
    UNREFERENCED_PARAMETER(bReturn);
    return FALSE;
}

BOOL Service_Stop(LPTSTR tszServiceName, BOOL bKillClients)
{
    LPIOSERVICE lpService;

    AcquireExclusiveLock(&loServiceList);
    lpService = _Service_FindByName(tszServiceName);

    if (lpService)
    {
        Service_Shutdown(lpService);
        if (bKillClients)
        {
            KillService(lpService);
        }
    }
    ReleaseExclusiveLock(&loServiceList);

    return FALSE;
}

/* -----------------------------------------------------------------------------
   Cert creation pass (async)
----------------------------------------------------------------------------- */

BOOL Service_CreateMissingCerts(LPVOID lpIgnored)
{
    LPIOSERVICE lpService;
    CHAR        szName[_INI_LINE_LENGTH];
    LPSTR       szCert;
    BOOL        bCreate, bCreated;

    UNREFERENCED_PARAMETER(lpIgnored);
    bCreated = FALSE;

    AcquireSharedLock(&loServiceList);
    for (lpService = lpServiceList; lpService; lpService = lpService->lpNext)
    {
        if (lpService->bActive && !lpService->pSecureCtx)
        {
            ReleaseSharedLock(&loServiceList);

            AcquireExclusiveLock(&lpService->loLock);

            if (lpService->pSecureCtx)
            {
                ReleaseExclusiveLock(&lpService->loLock);
                AcquireSharedLock(&loServiceList);
                continue;
            }

            lpService->dwFoundCredentials = 0;
            Service_GetCredentials(lpService, TRUE);

            if (lpService->pSecureCtx)
            {
                ReleaseExclusiveLock(&lpService->loLock);
                AcquireSharedLock(&loServiceList);
                continue;
            }

            bCreate = FALSE;
            Config_Get_Bool(&IniConfigFile, lpService->tszName, _TEXT("Create_Certificate"), &bCreate);
            if (lpService->bActive && !lpService->pSecureCtx && bCreate)
            {
                if (lpService->tszServiceValue)
                {
                    strcpy_s(szName, sizeof(szName), lpService->tszServiceValue);
                    szCert = szName;
                }
                else if (lpService->tszHostValue)
                {
                    strcpy_s(szName, sizeof(szName), lpService->tszHostValue);
                    szCert = szName;
                }
                else
                {
                    szCert = "ioFTPD";
                }

                ReleaseExclusiveLock(&lpService->loLock);

                Putlog(LOG_GENERAL, _T("SSL: \"Attempting to auto-generate certificate, this may take a bit\" \"name=%s\" \"Service=%s\"\r\n"),
                    szCert, lpService->tszName);

                if (Secure_MakeCert(szCert, lpService->tszName))
                {
                    bCreated = TRUE;
                    Putlog(LOG_GENERAL, _T("SSL: \"Created new certificate\" \"name=%s\" \"Service=%s\"\r\n"),
                        szCert, lpService->tszName);

                    AcquireExclusiveLock(&lpService->loLock);

                    lpService->dwFoundCredentials = 0;
                    Service_GetCredentials(lpService, TRUE);

                    ReleaseExclusiveLock(&lpService->loLock);
                }
            }
            else
            {
                ReleaseExclusiveLock(&lpService->loLock);
                AcquireSharedLock(&loServiceList);
            }
        }
    }
    ReleaseSharedLock(&loServiceList);

    if (!bCreated)
    {
        return FALSE;
    }

    AcquireSharedLock(&loServiceList);
    for (lpService = lpServiceList; lpService; lpService = lpService->lpNext)
    {
        if (lpService->bActive && !lpService->pSecureCtx)
        {
            ReleaseSharedLock(&loServiceList);

            AcquireExclusiveLock(&lpService->loLock);
            if (!lpService->pSecureCtx)
            {
                lpService->dwFoundCredentials = 0;
                Service_GetCredentials(lpService, TRUE);
            }
            ReleaseExclusiveLock(&lpService->loLock);
            AcquireSharedLock(&loServiceList);
        }
    }
    ReleaseSharedLock(&loServiceList);

    return FALSE;
}

/* -----------------------------------------------------------------------------
   Services init/deinit
----------------------------------------------------------------------------- */

BOOL Services_Init(BOOL bFirstInitialization)
{
    IO_STRING  ActiveServices;
    LPTSTR     tszActiveServices, tszService;
    DWORD      n, dwLen;
    LPIOADDRESS lpAddr;
    LPTSTR     tszNet;
    LPTSTR     tszNetArray[] = { _T("10.*"), _T("127.*"), _T("172.16.*"), _T("192.168.*") };

    if (bFirstInitialization)
    {
        lpServiceList = NULL;
        lpDeviceList = NULL;
        InitializeLockObject(&loDeviceList);
        InitializeLockObject(&loServiceList);
        InstallMessageHandler(WM_ACCEPTEX, Service_AcceptEx, TRUE, FALSE);

        lpDefaultPortDenyList = Allocate(_T("lpPortDeniedAddresses"), sizeof(*lpDefaultPortDenyList));
        if (!lpDefaultPortDenyList)
        {
            return FALSE;
        }

        lpDefaultPortDenyList->lReferenceCount = 1;
        lpDefaultPortDenyList->dwAddressArray = 0;
        lpDefaultPortDenyList->lpAddressArray = Allocate(_T("lpAddressArray"),
            sizeof(*lpDefaultPortDenyList->lpAddressArray) * (DWORD)(sizeof(tszNetArray) / sizeof(*tszNetArray)));
        if (!lpDefaultPortDenyList->lpAddressArray)
        {
            return FALSE;
        }

        lpAddr = lpDefaultPortDenyList->lpAddressArray;
        for (n = 0; n < sizeof(tszNetArray) / sizeof(*tszNetArray); n++, lpAddr++)
        {
            tszNet = tszNetArray[n];
            dwLen = (DWORD)((_tcslen(tszNet) + 1) * sizeof(TCHAR));
            lpAddr->Addr.s_addr = INADDR_NONE;
            lpAddr->tszString = Allocate(_T("lpIoAddress"), dwLen);
            if (!lpAddr->tszString)
            {
                return FALSE;
            }
            CopyMemory(lpAddr->tszString, tszNet, dwLen);
            lpDefaultPortDenyList->dwAddressArray++;
        }
    }

    tszActiveServices = Config_Get(&IniConfigFile, _TEXT("Network"), _TEXT("Active_Services"), NULL, NULL);
    if (!tszActiveServices) return FALSE;

    if (!SplitString(tszActiveServices, &ActiveServices))
    {
        for (n = 0; (tszService = GetStringIndexStatic(&ActiveServices, n)); n++)
        {
            if (Service_Start(tszService))
            {
                Putlog(LOG_ERROR, _T("Unable to start service '%s'.\r\n"), tszService);
            }
        }
        FreeString(&ActiveServices);
    }
    Free(tszActiveServices);

    if (bFirstInitialization && dwNeedCerts)
    {
        QueueJob(Service_CreateMissingCerts, NULL, JOB_PRIORITY_NORMAL);
    }

    if (lpServiceList)
    {
        bServicesInitialized = TRUE;
        return TRUE;
    }

    return FALSE;
}

VOID Services_DeInit(VOID)
{
    LPIOSERVICE lpService;
    LPCLIENT    lpClient;
    DWORD       dwNumClients, n, dwLoops;
    ULONGLONG   dwTickCount;

    bServicesInitialized = FALSE;

    AcquireExclusiveLock(&loServiceList);
    for (lpService = lpServiceList; lpService; lpService = lpService->lpNext)
    {
        Service_Shutdown(lpService);
    }
    ReleaseExclusiveLock(&loServiceList);

    KillService(NULL);

    dwNumClients = 0;
    for (n = 0; n < MAX_CLIENTS; n++)
    {
        if ((lpClient = LockClient(n)))
        {
            dwNumClients++;
            lpClient->Static.dwFlags |= S_TERMINATE;
            UnlockClient(n);
        }
    }

    dwLoops = 0;
    dwTickCount = SafeGetTickCount64() + 60000;
    while (dwNumClients && SafeGetTickCount64() < dwTickCount)
    {
        SleepEx(100, TRUE);
        dwNumClients = 0;
        for (n = 0; n < MAX_CLIENTS; n++)
        {
            if ((lpClient = LockClient(n)))
            {
                dwNumClients++;
                UnlockClient(n);
            }
        }
        if (dwLoops++ > 100)
        {
            dwLoops = 0;
            if (hRestartHeartbeat != INVALID_HANDLE_VALUE)
            {
                SetEvent(hRestartHeartbeat);
            }
        }
    }

    if (dwNumClients)
    {
        Putlog(LOG_ERROR, _T("%d clients must be zombies - terminating process.\r\n"), dwNumClients);
        exit(1);
    }

    SetDaemonStatus(DAEMON_SHUTDOWN);

    AcquireExclusiveLock(&loServiceList);
    while ((lpService = lpServiceList) != NULL)
    {
        Service_FreeDataDevices(lpService->lpDataDevices);
        Secure_Free_Ctx(lpService->pSecureCtx);
        if (lpService->lpDevice) Device_Unshare(lpService->lpDevice);
        FreeShared(lpService->tszMessageLocation);
        if (lpService->tszRequireSecureAuth)  Free(lpService->tszRequireSecureAuth);
        if (lpService->tszRequireSecureData)  Free(lpService->tszRequireSecureData);
        if (lpService->tszAllowedUsers)       Free(lpService->tszAllowedUsers);
        if (lpService->tszServiceValue)       Free(lpService->tszServiceValue);
        if (lpService->tszHostValue)          Free(lpService->tszHostValue);
        if (lpService->lpPortDeniedAddresses) ioAddressListFree(lpService->lpPortDeniedAddresses);
        for (n = 0; n <= 9; n++)
        {
            if (lpService->tszBncAddressArray[n])
            {
                Free(lpService->tszBncAddressArray[n]);
            }
        }
        DeleteLockObject(&lpService->loLock);
        lpServiceList = lpServiceList->lpNext;
        Free(lpService);
    }

    ioAddressListFree(lpDefaultPortDenyList);

    ReleaseExclusiveLock(&loServiceList);

    DeleteLockObject(&loDeviceList);
    DeleteLockObject(&loServiceList);
}

/* -----------------------------------------------------------------------------
   Admin commands
----------------------------------------------------------------------------- */

LPTSTR Admin_Services(LPFTPUSER lpUser, LPTSTR tszMultilinePrefix, LPIO_STRING Args)
{
    CONNECTION_INFO  Connection;
    LPIOSERVICE      lpService;
    LPTSTR           tszFileName;
    DWORD            dwLen;
    LPBYTE           pMsgBuf;
    LPTSTR           tszBasePath, tszAction, tszState, tszServiceName;
    LPBUFFER         lpBuffer;
    BOOL             bDisabled;

    lpBuffer = &lpUser->CommandChannel.Out;

    tszAction = (GetStringItems(Args) > 1) ? GetStringIndexStatic(Args, 1) : NULL;

    if ((GetStringItems(Args) < 2) || !_tcsicmp(tszAction, _T("list")))
    {
        tszBasePath = Service_MessageLocation(lpUser->Connection.lpService);
        if (!tszBasePath)
        {
            ERROR_RETURN(IO_NO_ACCESS, GetStringIndexStatic(Args, 0));
        }

        if (!aswprintf(&tszFileName, _TEXT("%s\\Services.Header"), tszBasePath))
        {
            FreeShared(tszBasePath);
            return GetStringIndexStatic(Args, 0);
        }
        FreeShared(tszBasePath);

        dwLen = (DWORD)_tcslen(tszFileName);

        CopyMemory(&Connection, &lpUser->Connection, sizeof(lpUser->Connection));
        Connection.lpDoService = NULL;

        MessageFile_Show(tszFileName, lpBuffer, lpUser, DT_FTPUSER, tszMultilinePrefix, NULL);

        _tcscpy(&tszFileName[dwLen - 6], "Body");

        pMsgBuf = Message_Load(tszFileName);
        if (pMsgBuf)
        {
            AcquireSharedLock(&loServiceList);
            for (lpService = lpServiceList; lpService; lpService = lpService->lpNext)
            {
                ReleaseSharedLock(&loServiceList);

                Connection.lpDoService = lpService;
                Message_Compile(pMsgBuf, lpBuffer, FALSE, &Connection, DT_CONNECTION, tszMultilinePrefix, NULL);

                AcquireSharedLock(&loServiceList);
            }
            ReleaseSharedLock(&loServiceList);

            Free(pMsgBuf);
        }

        _tcscpy(&tszFileName[dwLen - 6], "Footer");
        MessageFile_Show(tszFileName, lpBuffer, lpUser, DT_FTPUSER, tszMultilinePrefix, NULL);

        Free(tszFileName);
        return NULL;
    }

    if (!_tcsicmp(tszAction, _T("enable")))
    {
        bDisabled = FALSE;
        tszState = _T("Enabled");
    }
    else if (!_tcsicmp(tszAction, _T("disable")))
    {
        bDisabled = TRUE;
        tszState = _T("Disabled");
    }
    else
    {
        ERROR_RETURN(ERROR_INVALID_ARGUMENTS, tszAction);
    }

    if (GetStringItems(Args) < 3)
    {
        ERROR_RETURN(ERROR_MISSING_ARGUMENT, GetStringIndexStatic(Args, 0));
    }

    tszServiceName = GetStringIndexStatic(Args, 2);
    if (!tszServiceName || !*tszServiceName)
    {
        ERROR_RETURN(ERROR_MISSING_ARGUMENT, GetStringIndexStatic(Args, 0));
    }

    AcquireSharedLock(&loServiceList);
    for (lpService = lpServiceList; lpService; lpService = lpService->lpNext)
    {
        if (!_tcsicmp(tszServiceName, lpService->tszName)) break;
    }
    ReleaseSharedLock(&loServiceList);

    if (!lpService)
    {
        ERROR_RETURN(ERROR_SERVICE_NAME_NOT_FOUND, tszServiceName);
    }
    if (lpService->bActive == !bDisabled)
    {
        FormatString(lpBuffer, _TEXT("%sService '%4T%s%0T' is already %4T%s%0T.\r\n"), tszMultilinePrefix, tszServiceName, tszState);
        return NULL;
    }

    if (bDisabled && (lpUser->Connection.lpService == lpService))
    {
        FormatString(lpBuffer, _TEXT("%sService '%4T%s%0T' is the service you are using.\r\n"), tszMultilinePrefix, tszServiceName);
        ERROR_RETURN(ERROR_WRITE_PROTECT, tszServiceName);
    }

    if (bDisabled) Service_Shutdown(lpService);
    else           Service_Start(tszServiceName);

    FormatString(lpBuffer, _TEXT("%sService '%4T%s%0T' has been %4T%s%0T.\r\n"), tszMultilinePrefix, tszServiceName, tszState);
    return NULL;
}

LPTSTR Admin_Devices(LPFTPUSER lpUser, LPTSTR tszMultilinePrefix, LPIO_STRING Args)
{
    CONNECTION_INFO  Connection;
    LPIOSERVICE      lpService;
    LPIODEVICE       lpDevice, lpDeviceArray[50], lpTempDevice;
    LPTSTR           tszFileName, tszAction, tszDeviceName, tszState, tszType;
    DWORD            dwLen, dwDevices, n, dwActive;
    LPBYTE           pMsgBuf;
    LPTSTR           tszBasePath;
    LPBUFFER         lpBuffer;
    BOOL             bDisabled, bOK, bFound;

    lpBuffer = &lpUser->CommandChannel.Out;

    tszAction = (GetStringItems(Args) > 1) ? GetStringIndexStatic(Args, 1) : NULL;

    if ((GetStringItems(Args) < 2) || !_tcsicmp(tszAction, _T("list")))
    {
        tszBasePath = Service_MessageLocation(lpUser->Connection.lpService);
        if (!tszBasePath)
        {
            ERROR_RETURN(IO_NO_ACCESS, GetStringIndexStatic(Args, 0));
        }

        if (!aswprintf(&tszFileName, _TEXT("%s\\Devices.Header"), tszBasePath))
        {
            FreeShared(tszBasePath);
            return GetStringIndexStatic(Args, 0);
        }
        FreeShared(tszBasePath);

        dwLen = (DWORD)_tcslen(tszFileName);

        CopyMemory(&Connection, &lpUser->Connection, sizeof(lpUser->Connection));
        Connection.lpDevice = lpUser->CommandChannel.Socket.lpDevice;
        Connection.lpDoDevice = NULL;

        MessageFile_Show(tszFileName, lpBuffer, lpUser, DT_FTPUSER, tszMultilinePrefix, NULL);

        _tcscpy(&tszFileName[dwLen - 6], "Body");

        pMsgBuf = Message_Load(tszFileName);
        if (pMsgBuf)
        {
            dwDevices = 0;
            AcquireSharedLock(&loDeviceList);
            for (lpDevice = lpDeviceList;
                lpDevice && dwDevices < (DWORD)(sizeof(lpDeviceArray) / sizeof(*lpDeviceArray));
                lpDevice = lpDevice->lpNext)
            {
                lpDeviceArray[dwDevices++] = lpDevice;
                Device_Share(lpDevice);
            }

            for (n = 0; n < dwDevices; n++)
            {
                lpDevice = lpDeviceArray[n];
                ReleaseSharedLock(&loDeviceList);

                Connection.lpDoDevice = lpDevice;
                Message_Compile(pMsgBuf, lpBuffer, FALSE, &Connection, DT_CONNECTION, tszMultilinePrefix, NULL);

                Device_Unshare(lpDevice);

                AcquireSharedLock(&loDeviceList);
            }
            ReleaseSharedLock(&loDeviceList);

            Free(pMsgBuf);
        }

        _tcscpy(&tszFileName[dwLen - 6], "Footer");
        MessageFile_Show(tszFileName, lpBuffer, lpUser, DT_FTPUSER, tszMultilinePrefix, NULL);

        Free(tszFileName);
        return NULL;
    }

    if (!_tcsicmp(tszAction, _T("enable")))
    {
        bDisabled = FALSE;
        tszState = _T("Enabled");
    }
    else if (!_tcsicmp(tszAction, _T("disable")))
    {
        bDisabled = TRUE;
        tszState = _T("Disabled");
    }
    else
    {
        ERROR_RETURN(ERROR_INVALID_ARGUMENTS, tszAction);
    }

    if (GetStringItems(Args) < 3)
    {
        ERROR_RETURN(ERROR_MISSING_ARGUMENT, GetStringIndexStatic(Args, 0));
    }

    tszDeviceName = GetStringIndexStatic(Args, 2);
    if (!tszDeviceName || !*tszDeviceName)
    {
        ERROR_RETURN(ERROR_MISSING_ARGUMENT, GetStringIndexStatic(Args, 0));
    }

    AcquireSharedLock(&loDeviceList);
    for (lpDevice = lpDeviceList; lpDevice; lpDevice = lpDevice->lpNext)
    {
        if (!_tcsicmp(tszDeviceName, lpDevice->tszName)) break;
    }
    if (!lpDevice)
    {
        ReleaseSharedLock(&loDeviceList);
        ERROR_RETURN(ERROR_SERVICE_NAME_NOT_FOUND, tszDeviceName);
    }
    if (lpDevice->bDisabled == bDisabled)
    {
        ReleaseSharedLock(&loDeviceList);
        FormatString(lpBuffer, _TEXT("%sDevice '%4T%s%0T' is already %4T%s%0T.\r\n"), tszMultilinePrefix, tszDeviceName, tszState);
        return NULL;
    }

    if (bDisabled && lpUser->Connection.lpService && (lpUser->Connection.lpService->lpDevice == lpDevice))
    {
        ReleaseSharedLock(&loDeviceList);
        FormatString(lpBuffer, _TEXT("%sDevice '%4T%s%0T' is the active device for the service you are using.\r\n"), tszMultilinePrefix, tszDeviceName);
        ERROR_RETURN(ERROR_WRITE_PROTECT, tszDeviceName);
    }

    bOK = TRUE;
    if (bDisabled)
    {
        AcquireSharedLock(&loServiceList);
        for (lpService = lpServiceList; lpService; lpService = lpService->lpNext)
        {
            if (!lpService->bActive && !lpService->lClients) continue;

            tszType = (lpService->bActive ? _T("active") : _T("remaining users of"));

            if (!lpService->dwDataDevices)
            {
                if (lpService->lpDevice != lpDevice) continue;

                FormatString(lpBuffer, _TEXT("%sDevice '%4T%s%0T' is the default device for the %s service '%4T%s%0T'.\r\n"),
                    tszMultilinePrefix, tszDeviceName, tszType, lpService->tszName);
                bOK = FALSE;
                continue;
            }

            dwActive = 0;
            bFound = FALSE;
            for (n = 0; n < lpService->dwDataDevices; n++)
            {
                lpTempDevice = lpService->lpDataDevices[n];
                if (lpTempDevice->bActive) dwActive++;
                if (lpService->lpDevice == lpTempDevice) bFound = TRUE;
            }
            if (!bFound) continue;

            if (dwActive <= 1)
            {
                FormatString(lpBuffer, _TEXT("%sDevice '%4T%s%0T' is the last active data device for the %s service '%4T%s%0T'.\r\n"),
                    tszMultilinePrefix, tszDeviceName, tszType, lpService->tszName);
                bOK = FALSE;
            }
        }
        ReleaseSharedLock(&loServiceList);
    }

    if (bOK)
    {
        lpDevice->bDisabled = bDisabled;
        lpDevice->bActive = !bDisabled;
        ReleaseSharedLock(&loDeviceList);
        FormatString(lpBuffer, _TEXT("%sDevice '%4T%s%0T' has been %4T%s%0T.\r\n"), tszMultilinePrefix, tszDeviceName, tszState);
        return NULL;
    }

    ReleaseSharedLock(&loDeviceList);
    ERROR_RETURN(ERROR_WRITE_PROTECT, tszDeviceName);
}

/* -----------------------------------------------------------------------------
   Services test
----------------------------------------------------------------------------- */

BOOL Services_Test(PINT lpiNumServices, PINT lpiActiveServices, PINT lpiOnlineServices, PINT lpiFailedServices)
{
    LPIOSERVICE        lpService;
    SOCKET             Socket;
    BOOL               bFailed;
    struct sockaddr_in boundAddr;
    int                iAddrLen, iNum, iActive, iOnline, iFailed;
    DWORD              dwError;

    if (!bServicesInitialized) return TRUE;

    iNum = 0;
    iActive = 0;
    iOnline = 0;
    iFailed = 0;

    AcquireSharedLock(&loServiceList);

    for (lpService = lpServiceList; lpService; lpService = lpService->lpNext)
    {
        iNum++;
        if (!lpService->bActive) continue;

        if (!bServicesInitialized)
        {
            ReleaseSharedLock(&loServiceList);
            return TRUE;
        }

        ReleaseSharedLock(&loServiceList);
        AcquireSharedLock(&lpService->loLock);

        if (!lpService->bActive)
        {
            goto next;
        }

        iActive++;

        if ((lpService->lAddress == INADDR_NONE) || (lpService->sPort == 0))
        {
            Putlog(LOG_DEBUG, _T("Services_Test: No address or port defined for active service '%s'.\r\n"), lpService->tszName);
            goto next;
        }

        Socket = INVALID_SOCKET;
        bFailed = FALSE;

        if (lpService->addrLocal.sin_port != 0)
        {
            bFailed = TRUE;
        }

        if (!lpService->lAcceptClients)
        {
            Putlog(LOG_DEBUG, _T("Services_Test: No accept clients for service '%s'.\r\n"), lpService->tszName);
            goto failure;
        }

        lpService->addrLocal.sin_port = 0;

        Socket = OpenSocket();

        if (Socket == INVALID_SOCKET)
        {
            Putlog(LOG_DEBUG, _T("Services_Test: Invalid socket returned.\r\n"));
            goto failure;
        }

        if (bind(Socket, (struct sockaddr*)&lpService->addrLocal, sizeof(lpService->addrLocal)))
        {
            dwError = WSAGetLastError();
            Putlog(LOG_DEBUG, _T("Services_Test: Bind failed for service '%s' IP=%s: %d.\r\n"),
                lpService->tszName, inet_ntoa(lpService->addrLocal.sin_addr), dwError);
            goto failure;
        }

        iAddrLen = sizeof(boundAddr);
        if (getsockname(Socket, (struct sockaddr*)&boundAddr, &iAddrLen))
        {
            goto failure;
        }

        lpService->addrLocal.sin_port = boundAddr.sin_port;
        if (WSAConnect(Socket, (struct sockaddr*)&lpService->addrService, sizeof(lpService->addrService), NULL, NULL, NULL, NULL))
        {
            dwError = WSAGetLastError();
            Putlog(LOG_DEBUG, _T("Services_Test: Connect failed for service '%s' IP=%s: %d.\r\n"),
                lpService->tszName, inet_ntoa(lpService->addrLocal.sin_addr), dwError);
            goto failure;
        }

        closesocket(Socket);

        if (bFailed)
        {
            goto failure;
        }

        iOnline++;
        lpService->dwTestCounter = 0;
        goto next;

    failure:
        if (Socket != INVALID_SOCKET)
        {
            closesocket(Socket);
        }
        if (++lpService->dwTestCounter > 2)
        {
            iFailed++;
            if (lpService->dwTestCounter == 3)
            {
                Putlog(LOG_ERROR, _T("Services_Test: Failed to connect to service '%s' (IP=%s) %d times in a row!\r\n"),
                    lpService->tszName, inet_ntoa(lpService->addrLocal.sin_addr), lpService->dwTestCounter);
            }
            Putlog(LOG_DEBUG, _T("Services_Test: Failed to connect to service '%s' (IP=%s) %d times in a row!\r\n"),
                lpService->tszName, inet_ntoa(lpService->addrLocal.sin_addr), lpService->dwTestCounter);
        }

    next:
        ReleaseSharedLock(&lpService->loLock);
        AcquireSharedLock(&loServiceList);
    }
    ReleaseSharedLock(&loServiceList);

    if (lpiNumServices)    *lpiNumServices = iNum;
    if (lpiActiveServices) *lpiActiveServices = iActive;
    if (lpiOnlineServices) *lpiOnlineServices = iOnline;
    if (lpiFailedServices) *lpiFailedServices = iFailed;

    return FALSE;
}