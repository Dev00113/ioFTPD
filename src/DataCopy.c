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

// On x64, pointer fields shrink (LPTSTR 8→4) so the wire struct must be smaller.
// On x86 the pointers were already 4 bytes so the UINT64 widening makes WIRE slightly larger — expected.
#ifdef _M_X64
static_assert(sizeof(ONLINEDATA_WIRE) < sizeof(ONLINEDATA), "ONLINEDATA_WIRE must be smaller than ONLINEDATA on x64");
#endif

static LPEXCHANGE_REQUEST	lpExchangeRequestList[2];
static CRITICAL_SECTION		csExchangeRequestList;


__inline static
BOOL FindExchangeRequest(LPEXCHANGE_REQUEST lpExchangeRequest)
{
	LPEXCHANGE_REQUEST	lpSeek;

	// Find request
	for (lpSeek = lpExchangeRequestList[HEAD];lpSeek;lpSeek = lpSeek->lpNext)
	{
		if (lpSeek == lpExchangeRequest) return TRUE;
	}
	return FALSE;
}


// Returns TRUE if the memory region [lpBase, lpBase+dwBytes) contains at least one null byte.
// Used to validate that string commands won't scan off the end of the shared mapping.
static __inline BOOL SafeStringInRegion(LPCVOID lpBase, DWORD dwBytes)
{
	const BYTE *p = (const BYTE *)lpBase;
	DWORD i;
	for (i = 0; i < dwBytes; i++)
		if (p[i] == '\0') return TRUE;
	return FALSE;
}


__inline static
LPDC_USERFILE_REQUEST FindUserFileRequest(LPEXCHANGE_REQUEST lpReq, LPUSERFILE lpUserFile)
{
	LPDC_USERFILE_REQUEST	lpSeek;

	// Find request
	for (lpSeek = lpReq->lpUserFileReqList[HEAD];lpSeek;lpSeek = lpSeek->lpNext)
	{
		if (&lpSeek->UserFile == lpUserFile) return lpSeek;
	}
	return NULL;
}




static
DWORD DataCopy_OnlineData(LPDC_ONLINEDATA lpdcOnlineData, DWORD dwAvailableBytes)
{
	LPCLIENT			lpClient;
	PONLINEDATA			lpSrc;
	PONLINEDATA_WIRE	lpDst;
	LPTSTR				tszRealPath, tszRealDataPath;
	DWORD				dwReturn, dwRealPathChars, dwRealDataPathChars;
	ULONGLONG			dwLastCount;
	ULONGLONG			dwTickCount;

	if (lpdcOnlineData->iOffset-- < -1) return (DWORD)-1;
	//	Find next client
	for (;;)
	{
		if (++lpdcOnlineData->iOffset >= (INT32) dwMaxClientId) return (DWORD)-1;
		lpClient	= LockClient(lpdcOnlineData->iOffset);
		if (lpClient) break;
	}

	lpSrc	= &lpClient->Static;
	//	Acquire shared strings before releasing client lock
	tszRealPath     = (LPTSTR)(lpSrc->dwRealPath     ? AllocateShared(lpSrc->tszRealPath,     NULL, 0) : NULL);
	tszRealDataPath = (LPTSTR)(lpSrc->dwRealDataPath ? AllocateShared(lpSrc->tszRealDataPath, NULL, 0) : NULL);
	dwLastCount = lpClient->dwTransferLastUpdated;
	UnlockClient(lpdcOnlineData->iOffset);

	//	Serialize ONLINEDATA (internal) → ONLINEDATA_WIRE (cross-process fixed-width)
	lpDst = &lpdcOnlineData->OnlineData;
	lpDst->Uid              = lpSrc->Uid;
	lpDst->dwFlags          = lpSrc->dwFlags;
	memcpy(lpDst->tszServiceName, lpSrc->tszServiceName, sizeof(lpDst->tszServiceName));
	memcpy(lpDst->tszAction,      lpSrc->tszAction,      sizeof(lpDst->tszAction));
	lpDst->ulClientIp       = lpSrc->ulClientIp;
	lpDst->usClientPort     = lpSrc->usClientPort;
	memcpy(lpDst->szHostName, lpSrc->szHostName, sizeof(lpDst->szHostName));
	memcpy(lpDst->szIdent,    lpSrc->szIdent,    sizeof(lpDst->szIdent));
	memcpy(lpDst->tszVirtualPath, lpSrc->tszVirtualPath, sizeof(lpDst->tszVirtualPath));
	lpDst->dwOnlineTime     = lpSrc->dwOnlineTime;
	lpDst->dwIdleTickCount  = lpSrc->dwIdleTickCount;
	lpDst->bTransferStatus  = lpSrc->bTransferStatus;
	lpDst->usDeviceNum      = lpSrc->usDeviceNum;
	lpDst->ulDataClientIp   = lpSrc->ulDataClientIp;
	lpDst->usDataClientPort = lpSrc->usDataClientPort;
	memcpy(lpDst->tszVirtualDataPath, lpSrc->tszVirtualDataPath, sizeof(lpDst->tszVirtualDataPath));
	lpDst->qwBytesTransfered        = lpSrc->dwBytesTransfered;
	lpDst->dwIntervalLength         = lpSrc->dwIntervalLength;
	lpDst->i64TotalBytesTransfered  = lpSrc->i64TotalBytesTransfered;

	if (lpDst->bTransferStatus)
	{
		dwTickCount = SafeGetTickCount64();
		dwTickCount = Time_DifferenceDW64(dwLastCount, dwTickCount);
		if (dwTickCount > ZERO_SPEED_DELAY)
		{
			lpDst->dwIntervalLength  = 1;
			lpDst->qwBytesTransfered = 0;
		}
	}

	//	String data appended immediately after DC_ONLINEDATA in shared memory.
	//	External tools find them at: (TCHAR*)(&lpdcOnlineData[1]) + 0 and + dwRealPathLen.
	dwRealPathChars     = tszRealPath     ? lpSrc->dwRealPath     : 0;
	dwRealDataPathChars = tszRealDataPath ? lpSrc->dwRealDataPath : 0;
	lpDst->dwRealPathLen     = dwRealPathChars;
	lpDst->dwRealDataPathLen = dwRealDataPathChars;

	dwReturn = (dwRealPathChars + dwRealDataPathChars) * sizeof(TCHAR) + sizeof(DC_ONLINEDATA) + sizeof(DC_MESSAGE_WIRE);
	if (dwReturn < dwAvailableBytes)
	{
		if (tszRealPath)
			CopyMemory(&lpdcOnlineData[1], tszRealPath, dwRealPathChars * sizeof(TCHAR));
		if (tszRealDataPath)
			CopyMemory((TCHAR *)&lpdcOnlineData[1] + dwRealPathChars, tszRealDataPath, dwRealDataPathChars * sizeof(TCHAR));
		lpdcOnlineData->iOffset++;
		dwReturn = 0;
	}
	if (tszRealPath) FreeShared(tszRealPath);
	if (tszRealDataPath) FreeShared(tszRealDataPath);

	return dwReturn;
}


VOID
UserFile_Old2New(LPUSERFILE_OLD lpOld, LPUSERFILE lpNew)
{
	lpNew->Uid = lpOld->Uid;
	lpNew->Gid = lpOld->Gid;
	memcpy(lpNew->Tagline, lpOld->Tagline, sizeof(lpOld->Tagline));
	memcpy(lpNew->MountFile, lpOld->MountFile, sizeof(lpOld->MountFile));
	memcpy(lpNew->Home, lpOld->Home, sizeof(lpOld->Home));
	memcpy(lpNew->Flags, lpOld->Flags, sizeof(lpOld->Flags));
	memcpy(lpNew->Limits, lpOld->Limits, sizeof(lpOld->Limits));
	memcpy(lpNew->Password, lpOld->Password, sizeof(lpOld->Password));

	memcpy(lpNew->Ratio, lpOld->Ratio, sizeof(lpOld->Ratio)); // 10 vs 25
	memcpy(lpNew->Credits, lpOld->Credits, sizeof(lpOld->Credits)); // 10 vs 25

	memcpy(lpNew->DayUp, lpOld->DayUp, sizeof(lpOld->DayUp)); // 10 vs 25
	memcpy(lpNew->DayDn, lpOld->DayDn, sizeof(lpOld->DayDn)); // 10 vs 25
	memcpy(lpNew->WkUp, lpOld->WkUp, sizeof(lpOld->WkUp)); // 10 vs 25
	memcpy(lpNew->WkDn, lpOld->WkDn, sizeof(lpOld->WkUp)); // 10 vs 25
	memcpy(lpNew->MonthUp, lpOld->MonthUp, sizeof(lpOld->MonthUp)); // 10 vs 25
	memcpy(lpNew->MonthDn, lpOld->MonthDn, sizeof(lpOld->MonthDn)); // 10 vs 25
	memcpy(lpNew->AllUp, lpOld->AllUp, sizeof(lpOld->AllUp)); // 10 vs 25
	memcpy(lpNew->AllDn, lpOld->AllDn, sizeof(lpOld->AllDn)); // 10 vs 25

	memcpy(lpNew->AdminGroups, lpOld->AdminGroups, sizeof(lpOld->AdminGroups));
	memcpy(lpNew->Groups, lpOld->Groups, sizeof(lpOld->Groups));
	memcpy(lpNew->Ip, lpOld->Ip, sizeof(lpOld->Ip));

	lpNew->lpInternal = lpOld->lpInternal;
	lpNew->lpParent = lpOld->lpParent;

}


VOID
UserFile_New2Old(LPUSERFILE lpNew, LPUSERFILE_OLD lpOld)
{
	lpOld->Uid = lpNew->Uid;
	lpOld->Gid = lpNew->Gid;
	memcpy(lpOld->Tagline, lpNew->Tagline, sizeof(lpOld->Tagline));
	memcpy(lpOld->MountFile, lpNew->MountFile, sizeof(lpOld->MountFile));
	memcpy(lpOld->Home, lpNew->Home, sizeof(lpOld->Home));
	memcpy(lpOld->Flags, lpNew->Flags, sizeof(lpOld->Flags));
	memcpy(lpOld->Limits, lpNew->Limits, sizeof(lpOld->Limits));
	memcpy(lpOld->Password, lpNew->Password, sizeof(lpOld->Password));

	memcpy(lpOld->Ratio, lpNew->Ratio, sizeof(lpOld->Ratio)); // 10 vs 25
	memcpy(lpOld->Credits, lpNew->Credits, sizeof(lpOld->Credits)); // 10 vs 25

	memcpy(lpOld->DayUp, lpNew->DayUp, sizeof(lpOld->DayUp)); // 10 vs 25
	memcpy(lpOld->DayDn, lpNew->DayDn, sizeof(lpOld->DayDn)); // 10 vs 25
	memcpy(lpOld->WkUp, lpNew->WkUp, sizeof(lpOld->WkUp)); // 10 vs 25
	memcpy(lpOld->WkDn, lpNew->WkDn, sizeof(lpOld->WkUp)); // 10 vs 25
	memcpy(lpOld->MonthUp, lpNew->MonthUp, sizeof(lpOld->MonthUp)); // 10 vs 25
	memcpy(lpOld->MonthDn, lpNew->MonthDn, sizeof(lpOld->MonthDn)); // 10 vs 25
	memcpy(lpOld->AllUp, lpNew->AllUp, sizeof(lpOld->AllUp)); // 10 vs 25
	memcpy(lpOld->AllDn, lpNew->AllDn, sizeof(lpOld->AllDn)); // 10 vs 25

	memcpy(lpOld->AdminGroups, lpNew->AdminGroups, sizeof(lpOld->AdminGroups));
	memcpy(lpOld->Groups, lpNew->Groups, sizeof(lpOld->Groups));
	memcpy(lpOld->Ip, lpNew->Ip, sizeof(lpOld->Ip));

	lpOld->lpInternal = lpNew->lpInternal;
	lpOld->lpParent = lpNew->lpParent;
}




static
DWORD DataCopy_Process(LPEXCHANGE_REQUEST lpRequest, LPDC_MESSAGE_WIRE lpMessage)
{
	EVENT_COMMAND	Event;
	LPFILEINFO		lpFileInfo;
	VFSUPDATE		UpdateData;
	DWORD			dwReturn, dwFileName, Id;
	LPVOID			lpBuffer, lpContext;
	LPTSTR			tszUserName, tszGroupName, tszFileName;
	LPDC_USERFILE_REQUEST lpUserFileReq;
	LPUSERFILE      lpUserFile;

	//	Reject mismatched protocol versions before touching any other fields
	if (lpMessage->dwVersion != DC_MESSAGE_VERSION) return (DWORD)-1;

	//	Bounds-check context offset against the actual mapped region size to prevent
	//	an untrusted sending process from causing out-of-bounds pointer arithmetic
	if (lpRequest->dwMappedSize < sizeof(DC_MESSAGE_WIRE) ||
		lpMessage->qwContextOffset < sizeof(DC_MESSAGE_WIRE) ||
		lpMessage->qwContextOffset >= (UINT64)lpRequest->dwMappedSize) return (DWORD)-1;

	//	Process request
	dwReturn	= (DWORD)-1;
	lpBuffer	= (BYTE *)lpMessage + lpMessage->qwContextOffset;

	//	Bytes available for context data (guaranteed > 0 by the bounds check above)
	{
	DWORD dwContextAvailable = lpRequest->dwMappedSize - (DWORD)lpMessage->qwContextOffset;

	switch (lpMessage->dwIdentifier)
	{
	case DC_EXECUTE:
		//	Execute script — context is a null-terminated command string
		if (!SafeStringInRegion(lpBuffer, dwContextAvailable)) break;
		ZeroMemory(&Event, sizeof(EVENT_COMMAND));
		Event.tszCommand	= (LPTSTR)lpBuffer;
		dwReturn	= RunEvent(&Event);
		break;
	case DC_CREATE_USER:
		//	Create new user
		if (dwContextAvailable < sizeof(DC_NAMEID)) break;
		dwReturn	= CreateUser(((LPDC_NAMEID)lpBuffer)->tszName, -1);
		break;
	case DC_RENAME_USER:
		//	Rename user
		if (dwContextAvailable < sizeof(DC_RENAME)) break;
		dwReturn	= RenameUser(((LPDC_RENAME)lpBuffer)->tszName, ((LPDC_RENAME)lpBuffer)->tszNewName);
		break;
	case DC_DELETE_USER:
		//	Delete existing user
		if (dwContextAvailable < sizeof(DC_NAMEID)) break;
		dwReturn	= DeleteUser(((LPDC_NAMEID)lpBuffer)->tszName);
		break;
	case DC_RENAME_GROUP:
		//	Rename group
		if (dwContextAvailable < sizeof(DC_RENAME)) break;
		dwReturn	= RenameGroup(((LPDC_RENAME)lpBuffer)->tszName, ((LPDC_RENAME)lpBuffer)->tszNewName);
		break;
	case DC_CREATE_GROUP:
		//	Create new group
		if (dwContextAvailable < sizeof(DC_NAMEID)) break;
		dwReturn	= CreateGroup(((LPDC_NAMEID)lpBuffer)->tszName);
		break;
	case DC_DELETE_GROUP:
		//	Delete existing group
		if (dwContextAvailable < sizeof(DC_NAMEID)) break;
		dwReturn	= DeleteGroup(((LPDC_NAMEID)lpBuffer)->tszName);
		break;
	case DC_USER_TO_UID:
		//	Convert user name to id — context is a null-terminated user name string
		if (!SafeStringInRegion(lpBuffer, dwContextAvailable)) break;
		dwReturn	= User2Uid((LPTSTR)lpBuffer);
		break;
	case DC_GROUP_TO_GID:
		//	Convert group name to id — context is a null-terminated group name string
		if (!SafeStringInRegion(lpBuffer, dwContextAvailable)) break;
		dwReturn	= Group2Gid((LPTSTR)lpBuffer);
		break;
	case DC_UID_TO_USER:
		//	Convert user id to name
		if (dwContextAvailable < sizeof(DC_NAMEID)) break;
		Id	= ((LPDC_NAMEID)lpBuffer)->Id;
		if (Id < MAX_UID)
		{
			tszUserName	= Uid2User(Id);
			if (tszUserName)
			{
				_tcscpy(((LPDC_NAMEID)lpBuffer)->tszName, tszUserName);
				dwReturn	= FALSE;
			}
		}
		break;
	case DC_GID_TO_GROUP:
		//	Convert group id to name
		if (dwContextAvailable < sizeof(DC_NAMEID)) break;
		Id	= ((LPDC_NAMEID)lpBuffer)->Id;
		if (Id < MAX_GID)
		{
			tszGroupName	= Gid2Group(Id);
			if (tszGroupName)
			{
				//	Copy group name to buffer
				_tcscpy(((LPDC_NAMEID)lpBuffer)->tszName, tszGroupName);
				dwReturn	= FALSE;
			}
		}
		break;
	case DC_NEW_USERFILE_OPEN:
		//	Open userfile
		if (dwContextAvailable < sizeof(USERFILE)) break;
		if (((LPUSERFILE)lpBuffer)->Uid < 0 ||
			((LPUSERFILE)lpBuffer)->Uid >= MAX_UID) break;
		dwReturn	= UserFile_OpenPrimitive(((LPUSERFILE)lpBuffer)->Uid, (LPUSERFILE *)&lpBuffer, STATIC_SOURCE);
		//	Zero process-local pointer fields before the caller reads the struct from shared memory
		USERFILE_Zero_Internal((LPUSERFILE)lpBuffer);
		break;
	case DC_NEW_USERFILE_LOCK:
		//	Lock userfile
		if (dwContextAvailable < sizeof(USERFILE)) break;
		dwReturn	= UserFile_Lock((LPUSERFILE *)&lpBuffer, STATIC_SOURCE);
		USERFILE_Zero_Internal((LPUSERFILE)lpBuffer);
		break;
	case DC_NEW_USERFILE_UNLOCK:
		//	Unlock userfile
		if (dwContextAvailable < sizeof(USERFILE)) break;
		dwReturn	= UserFile_Unlock((LPUSERFILE *)&lpBuffer, STATIC_SOURCE);
		USERFILE_Zero_Internal((LPUSERFILE)lpBuffer);
		break;
	case DC_NEW_USERFILE_CLOSE:
		//	Close userfile
		if (dwContextAvailable < sizeof(USERFILE)) break;
		dwReturn	= UserFile_Close((LPUSERFILE *)&lpBuffer, STATIC_SOURCE);
		USERFILE_Zero_Internal((LPUSERFILE)lpBuffer);
		break;
	case DC_USERFILE_OPEN:
		//	Open userfile
		if (dwContextAvailable < sizeof(USERFILE_OLD)) break;
		if (((LPUSERFILE_OLD)lpBuffer)->Uid < 0 ||
			((LPUSERFILE_OLD)lpBuffer)->Uid >= MAX_UID) break;
		lpUserFileReq = Allocate("DC_USERFILE_REQUEST", sizeof(DC_USERFILE_REQUEST));
		if (!lpUserFileReq)	break;

		// OK, this needs to use the OLD userfile structure...
		lpUserFile = &lpUserFileReq->UserFile;
		dwReturn   = UserFile_OpenPrimitive(((LPUSERFILE_OLD)lpBuffer)->Uid, &lpUserFile, STATIC_SOURCE);
		if (dwReturn)
		{
			Free(lpUserFileReq);
			break;
		}

		APPENDLIST(lpUserFileReq, lpRequest->lpUserFileReqList);

		UserFile_New2Old(&lpUserFileReq->UserFile, lpBuffer);
		//	Ensure process-local pointers are never visible to the external tool
		((LPUSERFILE_OLD)lpBuffer)->lpInternal = NULL;
		((LPUSERFILE_OLD)lpBuffer)->lpParent   = NULL;
		break;
	case DC_USERFILE_LOCK:
		//	Lock userfile
		lpUserFileReq = FindUserFileRequest(lpRequest, lpBuffer);

		if (!lpUserFileReq)
		{
			dwReturn = ERROR_USER_NOT_FOUND;
			break;
		}

		lpUserFile = &lpUserFileReq->UserFile;
		dwReturn   = UserFile_Lock(&lpUserFile, STATIC_SOURCE);
		break;
	case DC_USERFILE_UNLOCK:
		//	Unlock userfile
		lpUserFileReq = FindUserFileRequest(lpRequest, lpBuffer);

		if (!lpUserFileReq)
		{
			dwReturn = ERROR_USER_NOT_FOUND;
			break;
		}

		lpUserFile = &lpUserFileReq->UserFile;
		dwReturn   = UserFile_Unlock(&lpUserFile, STATIC_SOURCE);
		break;
	case DC_USERFILE_CLOSE:
		//	Close userfile
		lpUserFileReq = FindUserFileRequest(lpRequest, lpBuffer);

		if (!lpUserFileReq)
		{
			dwReturn = ERROR_USER_NOT_FOUND;
			break;
		}

		lpUserFile = &lpUserFileReq->UserFile;
		dwReturn   = UserFile_Close(&lpUserFile, STATIC_SOURCE);

		DELETELIST(lpUserFileReq, lpRequest->lpUserFileReqList);
		Free(lpUserFileReq);

		break;
	case DC_GROUPFILE_OPEN:
		//	Open groupfile
		if (dwContextAvailable < sizeof(GROUPFILE)) break;
		if (((LPGROUPFILE)lpBuffer)->Gid < 0 ||
			((LPGROUPFILE)lpBuffer)->Gid >= MAX_GID) break;
		dwReturn	= GroupFile_OpenPrimitive(((LPGROUPFILE)lpBuffer)->Gid, (LPGROUPFILE *)&lpBuffer, STATIC_SOURCE);
		GROUPFILE_Zero_Internal((LPGROUPFILE)lpBuffer);
		break;
	case DC_GROUPFILE_LOCK:
		//	Lock groupfile
		if (dwContextAvailable < sizeof(GROUPFILE)) break;
		dwReturn	= GroupFile_Lock((LPGROUPFILE *)&lpBuffer, STATIC_SOURCE);
		GROUPFILE_Zero_Internal((LPGROUPFILE)lpBuffer);
		break;
	case DC_GROUPFILE_UNLOCK:
		//	Unlock groupfile
		if (dwContextAvailable < sizeof(GROUPFILE)) break;
		dwReturn	= GroupFile_Unlock((LPGROUPFILE *)&lpBuffer, STATIC_SOURCE);
		GROUPFILE_Zero_Internal((LPGROUPFILE)lpBuffer);
		break;
	case DC_GROUPFILE_CLOSE:
		//	Close groupfile
		if (dwContextAvailable < sizeof(GROUPFILE)) break;
		dwReturn	= GroupFile_Close((LPGROUPFILE *)&lpBuffer, STATIC_SOURCE);
		GROUPFILE_Zero_Internal((LPGROUPFILE)lpBuffer);
		break;
	case DC_DIRECTORY_MARKDIRTY:
		//	Mark directory as dirty — context is a null-terminated path string
		if (!SafeStringInRegion(lpBuffer, dwContextAvailable)) break;
		tszFileName	= (LPTSTR)lpBuffer;
		dwReturn	= MarkDirectory(tszFileName);
		break;
	case DC_FILEINFO_READ:
		//	Get fileinfo
		if (dwContextAvailable < sizeof(DC_VFS) + sizeof(TCHAR)) break;
		if (!SafeStringInRegion(((LPDC_VFS)lpBuffer)->pBuffer,
			dwContextAvailable - sizeof(DC_VFS))) break;
		tszFileName	= (LPTSTR)((LPDC_VFS)lpBuffer)->pBuffer;
		lpContext	= (LPVOID)((LPDC_VFS)lpBuffer)->pBuffer;

		if (GetFileInfo(tszFileName, &lpFileInfo))
		{
			//	Copy fileinfo
			((LPDC_VFS)lpBuffer)->Uid	= lpFileInfo->Uid;
			((LPDC_VFS)lpBuffer)->Gid	= lpFileInfo->Gid;
			((LPDC_VFS)lpBuffer)->dwFileMode	= lpFileInfo->dwFileMode;

			dwReturn	= 0;
			//	Copy context
			if (lpFileInfo->dwFileAttributes & FILE_ATTRIBUTE_IOFTPD &&
				lpFileInfo->Context.dwData)
			{
				if (((LPDC_VFS)lpBuffer)->dwBuffer >= lpFileInfo->Context.dwData)
				{
					// Buffer is large enough — copy context data and signal success
					CopyMemory(lpContext, lpFileInfo->Context.lpData, lpFileInfo->Context.dwData);
				}
				else
				{
					// Buffer too small — return required size so caller can retry with larger buffer
					((LPDC_VFS)lpBuffer)->dwBuffer	= lpFileInfo->Context.dwData;
					dwReturn	= lpFileInfo->Context.dwData;
				}
			}
			else ((LPDC_VFS)lpBuffer)->dwBuffer	= 0;
			CloseFileInfo(lpFileInfo);
		}
		break;
	case DC_FILEINFO_WRITE:
		//	Get new data
		if (dwContextAvailable < sizeof(DC_VFS) + sizeof(TCHAR)) break;
		if (!SafeStringInRegion(((LPDC_VFS)lpBuffer)->pBuffer,
			dwContextAvailable - sizeof(DC_VFS))) break;
		UpdateData.Uid	= ((LPDC_VFS)lpBuffer)->Uid;
		UpdateData.Gid	= ((LPDC_VFS)lpBuffer)->Gid;
		UpdateData.dwFileMode	= ((LPDC_VFS)lpBuffer)->dwFileMode;

		if (UpdateData.Uid >= 0 && UpdateData.Uid < MAX_UID &&
			UpdateData.Gid >= 0 && UpdateData.Gid < MAX_GID &&
			UpdateData.dwFileMode <= 0777)
		{
			tszFileName	= (LPTSTR)((LPDC_VFS)lpBuffer)->pBuffer;
			dwFileName	= (DWORD)_tcslen(tszFileName);
			{
				DWORD dwFileNameBytes = (dwFileName + 1) * sizeof(TCHAR);
				// Guard against DWORD underflow if dwBuffer is smaller than the filename
				if (((LPDC_VFS)lpBuffer)->dwBuffer < dwFileNameBytes) break;
				UpdateData.Context.lpData	= (LPVOID)&((LPDC_VFS)lpBuffer)->pBuffer[dwFileNameBytes];
				UpdateData.Context.dwData	= ((LPDC_VFS)lpBuffer)->dwBuffer - dwFileNameBytes;
			}

			if (GetFileInfo(tszFileName, &lpFileInfo))
			{
				UpdateData.ftAlternateTime  = lpFileInfo->ftAlternateTime;
				UpdateData.dwUploadTimeInMs = lpFileInfo->dwUploadTimeInMs;
				CloseFileInfo(lpFileInfo);

				//	Update fileinfo
				if (UpdateFileInfo(tszFileName, &UpdateData)) dwReturn	= 0;
			}
		}
		break;
	case DC_GET_ONLINEDATA:
		if (dwContextAvailable < sizeof(DC_ONLINEDATA)) break;
		dwReturn = DataCopy_OnlineData((LPDC_ONLINEDATA)lpBuffer, dwContextAvailable);
		break;
	}
	} // dwContextAvailable scope
	return dwReturn;
}




static
BOOL DataCopy_Free(LPEXCHANGE_REQUEST lpRequest, BOOL bNoCheck)
{
	LPDC_USERFILE_REQUEST lpUserFileReq, lpNext;
	BOOL	bFree;

	if (! bNoCheck)
	{
		if (! lpRequest) return FALSE;

		bFree	= FALSE;
		//	Find message from list
		EnterCriticalSection(&csExchangeRequestList);
		if (FindExchangeRequest(lpRequest))
		{
			//	Delete request
			if (lpRequest->wStatus == ER_AVAILABLE)
			{
				DELETELIST(lpRequest, lpExchangeRequestList);
				bFree	= TRUE;
			}
			lpRequest->wStatus	= ER_REMOVED;
		}
		LeaveCriticalSection(&csExchangeRequestList);

		if (! bFree) return FALSE;
	}

	//	Free resources associated with request
	if (lpRequest->wType == FILEMAP)
		UnmapViewOfFile(lpRequest->lpMessage);
	if (lpRequest->hEvent) CloseHandle(lpRequest->hEvent);
	if (lpRequest->hMemory != INVALID_HANDLE_VALUE) CloseHandle(lpRequest->hMemory);
	for(lpUserFileReq = lpRequest->lpUserFileReqList[HEAD] ; lpUserFileReq ; lpUserFileReq=lpNext)
	{
		lpNext = lpUserFileReq->lpNext;
		Free(lpUserFileReq);
	}
	Free(lpRequest);
	return TRUE;
}






static
LRESULT DataCopy_Allocate(DWORD dwProcessId, HANDLE hSharedMemory)
{
	LPDC_MESSAGE_WIRE	lpMessage;
	LPEXCHANGE_REQUEST	lpRequest, lpGhost[2], lpSeek;
	HANDLE				hProcess;
	BOOL				bReturn;

	//	Allocate request object
	lpRequest	= (LPEXCHANGE_REQUEST)Allocate("DataExchange:Request", sizeof(EXCHANGE_REQUEST));
	if (! lpRequest) return 0;

	//	Open process
	hProcess	= OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwProcessId);
	if (hProcess)
	{
		//	Reject 32-bit senders when ioFTPD is 64-bit.  The WM_DATACOPY_FILEMAP LRESULT
		//	is a 64-bit heap pointer that WoW64 truncates to 32 bits before returning it to
		//	the 32-bit caller.  When the caller echoes the truncated value back via WM_SHMEM,
		//	FindExchangeRequest fails and the IPC call silently never completes.
		//	32-bit external tools must be rebuilt as 64-bit to work with ioFTPD v8+.
#ifdef _M_X64
		{
			BOOL bIs32Bit = FALSE;
			if (IsWow64Process(hProcess, &bIs32Bit) && bIs32Bit)
			{
				Putlog(LOG_ERROR, _T("DataCopy: rejected IPC request from 32-bit process PID=%lu — rebuild the tool as 64-bit.\r\n"), dwProcessId);
				CloseHandle(hProcess);
				Free(lpRequest);
				return 0;
			}
		}
#endif
		lpMessage	= NULL;
		lpRequest->hEvent	= NULL;
		lpRequest->hMemory	= INVALID_HANDLE_VALUE;
		//	Get access to shared allocation via file-mapped memory
		bReturn	= DuplicateHandle(hProcess, hSharedMemory,
			GetCurrentProcess(), &lpRequest->hMemory, 0, FALSE, DUPLICATE_SAME_ACCESS);
		if (bReturn) lpMessage	= (LPDC_MESSAGE_WIRE)MapViewOfFile(lpRequest->hMemory, FILE_MAP_ALL_ACCESS, 0, 0, 0);
		if (lpMessage)
		{
			MEMORY_BASIC_INFORMATION mbi;
			lpRequest->dwMappedSize = (VirtualQuery(lpMessage, &mbi, sizeof(mbi)) == sizeof(mbi))
				? (DWORD)min(mbi.RegionSize, (SIZE_T)MAXDWORD) : 0;
		}

		//	Duplicate event handle.  dwEventHandle is the raw handle value from the sending
		//	process; Windows handles are always ≤32-bit so UINT32 holds them safely.
		if (lpMessage &&
			(lpMessage->dwEventHandle != 0 && lpMessage->dwEventHandle != 0xFFFFFFFFU))
		{
			bReturn	= DuplicateHandle(hProcess, (HANDLE)(UINT_PTR)lpMessage->dwEventHandle,
				GetCurrentProcess(), &lpRequest->hEvent, 0, FALSE, DUPLICATE_SAME_ACCESS);
		}
		CloseHandle(hProcess);

		if (bReturn)
		{
			lpRequest->wStatus	= ER_AVAILABLE;
			lpRequest->wType	= FILEMAP;
			lpRequest->lpMessage	= lpMessage;
			lpRequest->dwTickCount	= SafeGetTickCount64();
			lpRequest->lpUserFileReqList[HEAD] = NULL;
			lpRequest->lpUserFileReqList[TAIL] = NULL;

			lpGhost[HEAD]	= NULL;
			lpGhost[TAIL]	= NULL;

			EnterCriticalSection(&csExchangeRequestList);
			//	Get ghost entries (allocated for longer than 10minutes)
			while (lpExchangeRequestList[HEAD] &&
				lpExchangeRequestList[HEAD]->wStatus == ER_AVAILABLE &&
				Time_DifferenceDW64(lpExchangeRequestList[HEAD]->dwTickCount, lpRequest->dwTickCount) > 600000)
			{
				if (! lpGhost[HEAD]) lpGhost[HEAD]	= lpExchangeRequestList[HEAD];
				lpGhost[TAIL]	= lpExchangeRequestList[HEAD];
				lpExchangeRequestList[HEAD]	= lpExchangeRequestList[HEAD]->lpNext;
				if (lpExchangeRequestList[HEAD]) lpExchangeRequestList[HEAD]->lpPrev	= NULL;
			}
			//	Add request to global list
			APPENDLIST(lpRequest, lpExchangeRequestList);
			LeaveCriticalSection(&csExchangeRequestList);

			//	Free ghost resources
			if (lpGhost[HEAD])
			{
				lpGhost[TAIL]->lpNext	= NULL;
				do
				{
					lpSeek	= lpGhost[HEAD]->lpNext;
					DataCopy_Free(lpGhost[HEAD], TRUE);

				} while (lpGhost[HEAD] = lpSeek);
			}

			return (LRESULT)lpRequest;
		}

		//	Free resources
		if (lpMessage) UnmapViewOfFile(lpMessage);
		if (lpRequest->hEvent) CloseHandle(lpRequest->hEvent);
		if (lpRequest->hMemory != INVALID_HANDLE_VALUE) CloseHandle(lpRequest->hMemory);
	}
	Free(lpRequest);
	return 0;
}




static
LRESULT WindowMessage_DataExchange(WPARAM wParam, LPARAM lParam)
{
	LPEXCHANGE_REQUEST	lpRequest;
	ULONGLONG			dwTickCount;
	BOOL				bFree;


	lpRequest	= (LPEXCHANGE_REQUEST)lParam;
	dwTickCount	= SafeGetTickCount64();

	//	Validate request, and update position & status
	EnterCriticalSection(&csExchangeRequestList);
	if (FindExchangeRequest(lpRequest) &&
		lpRequest->wStatus == ER_AVAILABLE)
	{
		DELETELIST(lpRequest, lpExchangeRequestList);
		APPENDLIST(lpRequest, lpExchangeRequestList);
		lpRequest->dwTickCount	= dwTickCount;
		lpRequest->wStatus	= ER_IN_USE;
	}
	else lpRequest	= NULL;
	LeaveCriticalSection(&csExchangeRequestList);

	if (lpRequest)
	{
		//	Process request and signal event
		lpRequest->lpMessage->dwReturn	= DataCopy_Process(lpRequest, lpRequest->lpMessage);

		bFree	= FALSE;
		dwTickCount	= SafeGetTickCount64();
		//	Update status and position
		EnterCriticalSection(&csExchangeRequestList);
		DELETELIST(lpRequest, lpExchangeRequestList);
		if (lpRequest->wStatus == ER_IN_USE)
		{
			APPENDLIST(lpRequest, lpExchangeRequestList);
			lpRequest->dwTickCount	= dwTickCount;
			if (lpRequest->hEvent) SetEvent(lpRequest->hEvent);
		}
		else bFree	= TRUE;
		lpRequest->wStatus	= ER_AVAILABLE;
		LeaveCriticalSection(&csExchangeRequestList);

		if (bFree) DataCopy_Free(lpRequest, TRUE);
	}
	return FALSE;
}




static
LRESULT WindowMessage_ProcessId(WPARAM wParam, LPARAM lParam)
{
	return (LRESULT)GetCurrentProcessId();
}

static
LRESULT WindowMessage_ProcessHandle(WPARAM wParam, LPARAM lParam)
{
	return (LRESULT)GetCurrentProcess();
}

static
LRESULT WindowMessage_FreeMemory(WPARAM wParam, LPARAM lParam)
{
	return DataCopy_Free((LPEXCHANGE_REQUEST)lParam, FALSE);
}

static
LRESULT WindowMessage_FileMap(WPARAM wParam, LPARAM lParam)
{
	return DataCopy_Allocate((DWORD)wParam, (HANDLE)lParam);
}

static
LRESULT WindowMessage_KillUser(WPARAM wParam, LPARAM lParam)
{
	return KillUser((UINT32)wParam);
}

static
LRESULT WindowMessage_KickUser(WPARAM wParam, LPARAM lParam)
{
	return KickUser((INT)lParam);
}









BOOL DataCopy_Init(BOOL bFirstInitialization)
{
	if (! bFirstInitialization) return TRUE;
	//	Install message handlers
	InstallMessageHandler(WM_PID, WindowMessage_ProcessId, TRUE, FALSE);
	InstallMessageHandler(WM_PHANDLE, WindowMessage_ProcessHandle, TRUE, FALSE);
	InstallMessageHandler(WM_DATACOPY_FREE, WindowMessage_FreeMemory, TRUE, FALSE);
	InstallMessageHandler(WM_DATACOPY_FILEMAP, WindowMessage_FileMap, FALSE, FALSE);
	InstallMessageHandler(WM_SHMEM, WindowMessage_DataExchange, FALSE, FALSE);
	InstallMessageHandler(WM_KICK, WindowMessage_KickUser, FALSE, FALSE);
	InstallMessageHandler(WM_KILL, WindowMessage_KillUser, FALSE, FALSE);

	lpExchangeRequestList[HEAD]	= NULL;
	lpExchangeRequestList[TAIL]	= NULL;
	return InitializeCriticalSectionAndSpinCount(&csExchangeRequestList, 100);
}


VOID DataCopy_DeInit(VOID)
{
	LPEXCHANGE_REQUEST	lpSeek, lpNext;

	// Find request
	for (lpSeek = lpExchangeRequestList[HEAD];lpSeek;lpSeek = lpNext)
	{
		lpNext = lpSeek->lpNext;
		DataCopy_Free(lpSeek, TRUE);
	}

	DeleteCriticalSection(&csExchangeRequestList);
}
