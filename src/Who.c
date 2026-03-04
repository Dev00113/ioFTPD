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


/*
 * ReplaceSuffix — safely overwrite the trailing suffix of a path that was
 * built by aswprintf(..., "%s\\<prefix>.<original_suffix>", tszBase).
 *
 * dwBase        : value returned by aswprintf (length of the full string,
 *                 not counting the null terminator).
 * dwSuffixLen   : character count of the CURRENT suffix being replaced
 *                 (e.g. 8 for "Download").
 * tszNewSuffix  : replacement suffix string.
 *
 * The buffer was allocated for exactly dwBase+1 characters, so any new
 * suffix that is shorter than or equal to the original fits without
 * reallocation.  We assert this with a compile-time-friendly check and
 * use _tcscpy_s for the actual write.
 *
 * Returns FALSE on success, TRUE if the replacement is too long (the
 * caller should treat this as a logic error; it cannot happen with the
 * fixed-length suffix names used in this file).
 */
static __inline BOOL
ReplaceSuffix(LPTSTR tszFileName, DWORD dwBase,
              DWORD dwSuffixLen, LPCTSTR tszNewSuffix)
{
    DWORD cchNew = (DWORD)_tcslen(tszNewSuffix);
    // New suffix must not exceed the space occupied by the original suffix
    // (dwSuffixLen chars + null terminator = dwSuffixLen+1 bytes available).
    if (cchNew > dwSuffixLen) return TRUE;
    _tcscpy_s(&tszFileName[dwBase - dwSuffixLen],
              dwSuffixLen + 1,
              tszNewSuffix);
    return FALSE;
}


VOID HoursMinutesSeconds(LPDWORD lpHours, LPDWORD lpMinutes, LPDWORD lpSeconds)
{
	DWORD	dwSeconds;

	dwSeconds = lpSeconds[0];
	lpHours[0] = dwSeconds / 3600;
	lpMinutes[0] = (dwSeconds % 3600) / 60;
	lpSeconds[0] = (dwSeconds % 3600) % 60;
}






DWORD ClientToIoWho(LPCLIENT lpClient, DWORD dwTimeNow, ULONGLONG dwTickCount, LPIO_WHO lpWho)
{
	PONLINEDATA    lpOnlineData;

	lpOnlineData = &lpWho->OnlineData;

	//  Copy data
	CopyMemory(lpOnlineData, &lpClient->Static, sizeof(*lpOnlineData));

	// increment ref count so these stay valid after we release client lock
	lpOnlineData->tszRealPath = (lpOnlineData->dwRealPath ? AllocateShared(lpOnlineData->tszRealPath, NULL, 0) : NULL);
	lpOnlineData->tszRealDataPath = (lpOnlineData->dwRealDataPath ? AllocateShared(lpOnlineData->tszRealDataPath, NULL, 0) : NULL);

	// Diagnostic: show whether AllocateShared succeeded and sizes requested
	//Putlog(LOG_DEBUG, _T("ClientToIoWho: lpClient=%p Uid=%d dwRealPath=%u tszRealPath=%p dwRealDataPath=%u tszRealDataPath=%p\n"),
	//	(PVOID)lpClient,
	//	lpOnlineData->Uid,
	//	lpOnlineData->dwRealPath,
	//	(PVOID)lpOnlineData->tszRealPath,
	//	lpOnlineData->dwRealDataPath,
	//	(PVOID)lpOnlineData->tszRealDataPath);

	lpWho->dwLoginSeconds = dwTimeNow - lpOnlineData->dwOnlineTime;
	lpWho->dwIdleSeconds = (DWORD)(((DWORD)dwTickCount - lpOnlineData->dwIdleTickCount) / 1000);

	HoursMinutesSeconds(&lpWho->dwLoginHours, &lpWho->dwLoginMinutes, &lpWho->dwLoginSeconds);
	HoursMinutesSeconds(&lpWho->dwIdleHours, &lpWho->dwIdleMinutes, &lpWho->dwIdleSeconds);

	lpWho->dwUsers++;
	lpWho->i64FileSize = 0;

	//	Load userfile
	if (lpOnlineData->Uid == -1 || UserFile_OpenPrimitive(lpOnlineData->Uid, &lpWho->lpUserFile, 0))
	{
		lpWho->lpUserFile = NULL;
	}

	//	Copy transfer information
	if (lpOnlineData->bTransferStatus)
	{
		if (lpOnlineData->dwIntervalLength)
		{
			lpWho->fTransferSpeed = lpOnlineData->dwBytesTransfered * 0.9765625 / lpOnlineData->dwIntervalLength;
		}
		else lpWho->fTransferSpeed = 0.;

		switch (lpOnlineData->bTransferStatus)
		{
		case 1:
			lpWho->dwDownloads++;
			lpWho->fTotalDnSpeed += lpWho->fTransferSpeed;
			return W_DOWNLOAD;
		case 2:
			lpWho->dwUploads++;
			lpWho->fTotalUpSpeed += lpWho->fTransferSpeed;
			return W_UPLOAD;
		}
		return W_LIST;
	}
	lpWho->fTransferSpeed = 0.;
	return (lpWho->lpUserFile ? W_IDLE : W_LOGIN);
}






LPTSTR Admin_UsersOnline(LPFTPUSER lpUser, LPTSTR tszMultilinePrefix, LPIO_STRING Args)
{
	IO_WHO			Who;
	LPCLIENT        lpClient;
	LPBUFFER		lpBuffer;
	PBYTE			pBuffer[6];
	DWORD			dwFileName, dwSystemTime, dwStatus, n, dwHidden;
	ULONGLONG	    dwTickCount;
	INT				i, iLimit;
	TCHAR* tpCheck;
	LPTSTR			tszBasePath, tszFileName, tszStatus, tszClientId;
	LPUSERSEARCH    lpSearch;


	if (GetStringItems(Args) > 2) ERROR_RETURN(ERROR_INVALID_ARGUMENTS, GetStringRange(Args, 2, STR_END));

	ZeroMemory(&Who, sizeof(IO_WHO));
	Who.dwMyCID = lpUser->Connection.dwUniqueId;
	Who.dwMyUID = lpUser->UserFile->Uid;

	lpBuffer = &lpUser->CommandChannel.Out;

	dwSystemTime = (DWORD)time((time_t*)NULL);
	dwTickCount = SafeGetTickCount64();

	if (GetStringItems(Args) == 2)
	{
		tszClientId = GetStringIndexStatic(Args, 1);

		i = _tcstol(tszClientId, &tpCheck, 10);

		if ((tpCheck != tszClientId) && (tpCheck[0] == 0))
		{
			// it was a number all by itself
			if (i < 0 || i >= MAX_CLIENTS)
			{
				// but not a valid one...
				ERROR_RETURN(ERROR_INVALID_ARGUMENTS, tszClientId);
			}

			//	Get client data
			lpClient = LockClient(i);
			if (lpClient)
			{
				Who.dwConnectionId = i;

				switch (ClientToIoWho(lpClient, dwSystemTime, dwTickCount, &Who))
				{
				case W_LIST:
					tszStatus = _TEXT("List");
					break;
				case W_UPLOAD:
					tszStatus = _TEXT("Upload");
					break;
				case W_DOWNLOAD:
					tszStatus = _TEXT("Download");
					break;
				case W_IDLE:
					tszStatus = _TEXT("Idle");
					break;
				case W_LOGIN:
					tszStatus = _TEXT("Login");
					break;
				}
				UnlockClient(i);

				Who.dwMyCID = lpUser->Connection.dwUniqueId;
				Who.dwMyUID = lpUser->UserFile->Uid;

				//	Show message file
				tszBasePath = Service_MessageLocation(lpUser->Connection.lpService);
				if (tszBasePath)
				{
					dwFileName = aswprintf(&tszFileName, _TEXT("%s\\ClientInfo.%s"), tszBasePath, tszStatus);
					FreeShared(tszBasePath);

					if (dwFileName)
					{
						MessageFile_Show(tszFileName, lpBuffer, &Who, DT_WHO, tszMultilinePrefix, NULL);
						Free(tszFileName);
					}
				}
				FreeShared(Who.OnlineData.tszRealPath);
				FreeShared(Who.OnlineData.tszRealDataPath);
				UserFile_Close(&Who.lpUserFile, 0);
				return NULL;
			}
			SetLastError(ERROR_USER_NOT_FOUND);
			return GetStringIndexStatic(Args, 1);
		}
	}

	iLimit = -1;
	lpSearch = NULL;
	n = 1;
	if (GetStringItems(Args) > 1)
	{
		//	Get arguments
		tszClientId = GetStringIndexStatic(Args, 1);

		if (!_tcsicmp(tszClientId, _T("up")))
		{
			iLimit = W_UPLOAD;
			n++;
		}
		else if (!_tcsicmp(tszClientId, _T("down")))
		{
			iLimit = W_DOWNLOAD;
			n++;
		}
		else if (!_tcsicmp(tszClientId, _T("idle")))
		{
			iLimit = W_IDLE;
			n++;
		}
		else if (!_tcsicmp(tszClientId, _T("bw")))
		{
			iLimit = W_NONE;
			n++;
		}

		tszClientId = GetStringRange(Args, n, STR_END);
		if (tszClientId && *tszClientId)
		{
			// this should be a site admin only command so no need to pass lpUserFile to check for limited info...
			lpSearch = FindParse(tszClientId, NULL, lpUser, TRUE);
			if (!lpSearch)
			{
				return tszClientId;
			}
		}
	}

	//	Load messages
	tszBasePath = Service_MessageLocation(lpUser->Connection.lpService);
	if (!tszBasePath)
	{
		if (lpSearch) FindFinished(lpSearch);
		ERROR_RETURN(ERROR_COMMAND_FAILED, GetStringIndexStatic(Args, 1));
	}
	dwFileName = aswprintf(&tszFileName, _TEXT("%s\\ClientList.Download"), tszBasePath);
	FreeShared(tszBasePath);
	if (!dwFileName)
	{
		if (lpSearch) FindFinished(lpSearch);
		ERROR_RETURN(ERROR_NOT_ENOUGH_MEMORY, GetStringIndexStatic(Args, 1));
	}

	// The base path ends in "ClientList.Download" (suffix = "Download", 8 chars).
	// ReplaceSuffix overwrites only that 8-char suffix, staying within the
	// buffer allocated by aswprintf.
	pBuffer[W_DOWNLOAD] = Message_Load(tszFileName);
	ReplaceSuffix(tszFileName, dwFileName, 8, _TEXT("Upload"));
	pBuffer[W_UPLOAD] = Message_Load(tszFileName);
	ReplaceSuffix(tszFileName, dwFileName, 8, _TEXT("Idle"));
	pBuffer[W_IDLE] = Message_Load(tszFileName);
	ReplaceSuffix(tszFileName, dwFileName, 8, _TEXT("List"));
	pBuffer[W_LIST] = Message_Load(tszFileName);
	ReplaceSuffix(tszFileName, dwFileName, 8, _TEXT("Login"));
	pBuffer[W_LOGIN] = Message_Load(tszFileName);
	pBuffer[W_NONE] = 0;


	//	Show header
	ReplaceSuffix(tszFileName, dwFileName, 8, _TEXT("Header"));
	MessageFile_Show(tszFileName, lpBuffer, lpUser, DT_FTPUSER, tszMultilinePrefix, NULL);

	dwHidden = 0;


	//	List users online
	for (Who.dwConnectionId = 0; Who.dwConnectionId <= dwMaxClientId; Who.dwConnectionId++)
	{
		lpClient = LockClient(Who.dwConnectionId);
		if (!lpClient) continue;

		dwStatus = ClientToIoWho(lpClient, dwSystemTime, dwTickCount, &Who);

		UnlockClient(Who.dwConnectionId);

		if ((iLimit != -1) && (dwStatus != iLimit))
		{
			// don't print non-matching entries
			dwHidden++;
		}
		else if (!pBuffer[dwStatus])
		{
			// no template to display user...
			// If this is a Login-state entry and the specific template is missing,
			// emit a compact default line instead of silently skipping the user.
			if (dwStatus == W_LOGIN)
			{
				LPTSTR tszUserName = NULL;
				LPTSTR tszGroupName = NULL;

				if (Who.lpUserFile)
				{
					tszUserName = Uid2User(Who.lpUserFile->Uid);
					tszGroupName = Gid2Group(Who.lpUserFile->Gid);
				}

				FormatString(lpBuffer, _TEXT("%s%-15s | %-10s | %s\r\n"),
					tszMultilinePrefix,
					(tszUserName ? tszUserName : _T("")),
					(tszGroupName ? tszGroupName : _T("")),
					Who.OnlineData.tszAction);
			}
			else
			{
				dwHidden++;
			}
		}
		else if (!lpSearch || (Who.lpUserFile && !FindIsMatch(lpSearch, Who.lpUserFile, TRUE)))
		{
			//	Show message
			Message_Compile(pBuffer[dwStatus], lpBuffer, FALSE, &Who, DT_WHO, tszMultilinePrefix, NULL);
		}
		else
		{
			dwHidden++;
		}

		//	Free resources
		FreeShared(Who.OnlineData.tszRealPath);
		FreeShared(Who.OnlineData.tszRealDataPath);
		UserFile_Close(&Who.lpUserFile, 0);
	}

	Who.dwLoginHours = dwHidden;

	//	Show footer
	ReplaceSuffix(tszFileName, dwFileName, 8, _TEXT("Footer"));
	MessageFile_Show(tszFileName, lpBuffer, &Who, DT_WHO, tszMultilinePrefix, NULL);

	if (lpSearch) FindFinished(lpSearch);
	if (pBuffer[W_UPLOAD])   Free(pBuffer[W_UPLOAD]);
	if (pBuffer[W_DOWNLOAD]) Free(pBuffer[W_DOWNLOAD]);
	if (pBuffer[W_IDLE])     Free(pBuffer[W_IDLE]);
	if (pBuffer[W_LIST])     Free(pBuffer[W_LIST]);
	if (pBuffer[W_LOGIN])    Free(pBuffer[W_LOGIN]);
	Free(tszFileName);
	return NULL;
}


INT __cdecl WhoSortCmp(VOID* pBuffer, LPCVOID Who1, LPCVOID Who2)
{
	LPSTR Array = (LPSTR)pBuffer;
	LPSORT_WHO w1 = (LPSORT_WHO)Who1;
	LPSORT_WHO w2 = (LPSORT_WHO)Who2;

	return _tcsicmp(&Array[w1->dwNameIndex], &Array[w2->dwNameIndex]);
}



LPTSTR Admin_Who(LPFTPUSER lpUser, LPTSTR tszMultilinePrefix, LPIO_STRING Args)
{
	IO_WHO Who;
	LPCLIENT lpClient;
	DWORD dwSystemTime, dwFileName, dwStatus, n, dwPaths = 0, dwHidden = 0, dwError = NO_ERROR, dwSorted = 0, dwMaxSorted = 200;
	ULONGLONG dwTickCount;
	INT iOffset = 0, ActionLimit;
	LPBUFFER lpBuffer = &lpUser->CommandChannel.Out;
	PBYTE pBuffer[6] = { 0 };
	LPTSTR tszBasePath = NULL, tszFileName = NULL, tszSearch = NULL, tszSpace = NULL, tszSlash = NULL, tszName = NULL;
	TCHAR tszHiddenKey[64];
	LPTSTR tszPathsArr[20] = { 0 };
	LPUSERSEARCH lpSearch = NULL, lpExclude = NULL;
	BOOL bIsAdmin = !HasFlag(lpUser->UserFile, _T("M1")), bHidden = FALSE, bSorting = FALSE;
	BUFFER TempBuf = { 0 };
	LPSORT_WHO lpSortWhoArray = NULL, lpNext = NULL, lpSortWhoTemp = NULL;

	ZeroMemory(&Who, sizeof(IO_WHO));

	tszBasePath = Service_MessageLocation(lpUser->Connection.lpService);
	if (!tszBasePath) return NULL;

	// Diagnostic: log message base path
	Putlog(LOG_DEBUG, _T("Admin_Who: MessageLocation for service '%s' -> %p ('%s')\r\n"),
		lpUser->Connection.lpService ? lpUser->Connection.lpService->tszName : _T("<null>"),
		(PVOID)tszBasePath,
		tszBasePath ? tszBasePath : _T("<null>"));

	dwFileName = aswprintf(&tszFileName, _TEXT("%s\\Who.Download"), tszBasePath);
	FreeShared(tszBasePath);
	if (!dwFileName || !tszFileName) {
		Putlog(LOG_DEBUG, _T("Admin_Who: aswprintf failed, dwFileName=%u tszFileName=%p\r\n"), dwFileName, (PVOID)tszFileName);
		return NULL;
	}

	// Diagnostic: log constructed filename
	Putlog(LOG_DEBUG, _T("Admin_Who: constructed message filename=%p (%s) dwFileName=%u\r\n"),
		(PVOID)tszFileName, tszFileName, dwFileName);

	{
		TCHAR tszFullPath[_MAX_LONG_PATH+1] = { 0 };
		if (GetFullPathName(tszFileName, _countof(tszFullPath), tszFullPath, NULL))
		{
			Putlog(LOG_DEBUG, _T("Admin_Who: constructed message filename=%p (%s) dwFileName=%u fullpath=%s\r\n"),
				(PVOID)tszFileName, tszFileName, dwFileName, tszFullPath);
		}
		else
		{
			Putlog(LOG_DEBUG, _T("Admin_Who: constructed message filename=%p (%s) dwFileName=%u (GetFullPathName failed)\r\n"),
				(PVOID)tszFileName, tszFileName, dwFileName);
		}
	}

	// The base path ends in "Who.Download" (suffix = "Download", 8 chars).
	// ReplaceSuffix overwrites only that 8-char suffix within the existing buffer.
	pBuffer[W_DOWNLOAD] = Message_Load(tszFileName);
	if (!pBuffer[W_DOWNLOAD]) {
		Putlog(LOG_DEBUG, _T("Admin_Who: Message_Load failed for '%s' (Download) GetLastError=%u\r\n"),
			tszFileName, GetLastError());
	}
	ReplaceSuffix(tszFileName, dwFileName, 8, _TEXT("Upload"));
	pBuffer[W_UPLOAD] = Message_Load(tszFileName);
	if (!pBuffer[W_UPLOAD]) {
		Putlog(LOG_DEBUG, _T("Admin_Who: Message_Load failed for '%s' (Upload) GetLastError=%u\r\n"),
			tszFileName, GetLastError());
	}
	ReplaceSuffix(tszFileName, dwFileName, 8, _TEXT("Idle"));
	pBuffer[W_IDLE] = Message_Load(tszFileName);
	if (!pBuffer[W_IDLE]) {
		Putlog(LOG_DEBUG, _T("Admin_Who: Message_Load failed for '%s' (Idle) GetLastError=%u\r\n"),
			tszFileName, GetLastError());
	}
	ReplaceSuffix(tszFileName, dwFileName, 8, _TEXT("List"));
	pBuffer[W_LIST] = Message_Load(tszFileName);
	if (!pBuffer[W_LIST]) {
		Putlog(LOG_DEBUG, _T("Admin_Who: Message_Load failed for '%s' (List) GetLastError=%u\r\n"),
			tszFileName, GetLastError());
	}
	ReplaceSuffix(tszFileName, dwFileName, 8, _TEXT("Login"));
	pBuffer[W_LOGIN] = Message_Load(tszFileName);
	if (!pBuffer[W_LOGIN]) {
		Putlog(LOG_DEBUG, _T("Admin_Who: Message_Load failed for '%s' (Login) GetLastError=%u\r\n"),
			tszFileName, GetLastError());
	}
	pBuffer[W_NONE] = 0;

	if ((tszSearch = Config_Get(&IniConfigFile, _TEXT("FTP"), _TEXT("Who_Hidden_Users"), NULL, NULL))) {
		lpExclude = FindParse(tszSearch, NULL, NULL, FALSE);
		Free(tszSearch);
	}

	for (n = 1; n <= 20; n++) {
		_stprintf_s(tszHiddenKey, _countof(tszHiddenKey), _TEXT("Who_Hidden_Paths_%u"), n);
		tszPathsArr[dwPaths] = Allocate("WhoHiddenPath", (_INI_LINE_LENGTH + 1) * sizeof(TCHAR));
		if (!tszPathsArr[dwPaths]) { dwError = ERROR_OUTOFMEMORY; goto cleanup; }

		if (!Config_Get(&IniConfigFile, _TEXT("FTP"), tszHiddenKey, tszPathsArr[dwPaths], &iOffset)) {
			Free(tszPathsArr[dwPaths]);
			tszPathsArr[dwPaths] = NULL;
			break;
		}
		dwPaths++;
	}

	ActionLimit = W_ANY;
	if (GetStringItems(Args) >= 2) {
		n = 1;
		tszSearch = GetStringIndexStatic(Args, 1);

		if (!_tcsicmp(tszSearch, _T("up"))) { ActionLimit = W_UPLOAD; n++; }
		else if (!_tcsicmp(tszSearch, _T("down"))) { ActionLimit = W_DOWNLOAD; n++; }
		else if (!_tcsicmp(tszSearch, _T("idle"))) { ActionLimit = W_IDLE; n++; }
		else if (!_tcsicmp(tszSearch, _T("bw"))) { ActionLimit = W_NONE; n++; }

		tszSearch = GetStringRange(Args, n, STR_END);
		if (tszSearch && *tszSearch) {
			lpSearch = FindParse(tszSearch, lpUser->UserFile, lpUser, FALSE);
			if (!lpSearch) { dwError = GetLastError(); goto cleanup; }
		}
	}

	if ((bSorting = FtpSettings.bWhoSortOutput)) {
		// Allocate TempBuf for sorting; AllocateBuffer returns non-zero on failure.
		if (AllocateBuffer(&TempBuf, 8192)) {
			dwError = ERROR_OUTOFMEMORY;
			goto cleanup;
		}
		lpSortWhoArray = Allocate("SortWhoArray", dwMaxSorted * sizeof(*lpSortWhoArray));
		if (!lpSortWhoArray) { dwError = ERROR_OUTOFMEMORY; goto cleanup; }
	}

	_tcscpy(&tszFileName[dwFileName - 8], _TEXT("Header"));
	MessageFile_Show(tszFileName, lpBuffer, lpUser, DT_FTPUSER, tszMultilinePrefix, NULL);

	dwSystemTime = (DWORD)time(NULL);
	dwTickCount = SafeGetTickCount64();

	Who.dwMyCID = lpUser->Connection.dwUniqueId;
	Who.dwMyUID = lpUser->UserFile->Uid;

	for (Who.dwConnectionId = 0; Who.dwConnectionId <= dwMaxClientId; Who.dwConnectionId++) {
		lpClient = LockClient(Who.dwConnectionId);
		if (!lpClient) continue;

		dwStatus = ClientToIoWho(lpClient, dwSystemTime, dwTickCount, &Who);
		UnlockClient(Who.dwConnectionId);

		/* If action limit doesn't match, skip. If there's no template for this status,
		   normally skip; but provide a compact fallback line for LOGIN entries so
		   connected users are still visible when Who.Login is missing. */
		if (ActionLimit != W_ANY && dwStatus != ActionLimit) {
			dwHidden++;
			FreeShared(Who.OnlineData.tszRealPath);
			FreeShared(Who.OnlineData.tszRealDataPath);
			UserFile_Close(&Who.lpUserFile, 0);
			continue;
		}

		if (!pBuffer[dwStatus]) {
			if (dwStatus == W_LOGIN) {
				LPTSTR tszUserName = NULL;
				LPTSTR tszGroupName = NULL;

				if (Who.lpUserFile) {
					tszUserName = Uid2User(Who.lpUserFile->Uid);
					tszGroupName = Gid2Group(Who.lpUserFile->Gid);
				}

				// Compact fallback matching header columns: User | Group | Action
				FormatString(lpBuffer, _T("%s%-15s | %-10s | %s\r\n"),
					tszMultilinePrefix,
					(tszUserName ? tszUserName : _T("")),
					(tszGroupName ? tszGroupName : _T("")),
					Who.OnlineData.tszAction);

				FreeShared(Who.OnlineData.tszRealPath);
				FreeShared(Who.OnlineData.tszRealDataPath);
				UserFile_Close(&Who.lpUserFile, 0);
				continue;
			}

			dwHidden++;
			FreeShared(Who.OnlineData.tszRealPath);
			FreeShared(Who.OnlineData.tszRealDataPath);
			UserFile_Close(&Who.lpUserFile, 0);
			continue;
		}

		// Who.lpUserFile is NULL for connecting users (Uid == -1) or when
		// UserFile_OpenPrimitive fails.  FindIsMatch dereferences lpUserFile
		// immediately, so we must guard both calls.  A NULL userfile is treated
		// as "not matched" by any search/exclusion filter: excluded users without
		// a userfile are shown (exclude list cannot match them) and search
		// filters that cannot match will hide them.
		BOOL bHasUserFile = (Who.lpUserFile != NULL);
		BOOL shouldDisplay =
			(!lpExclude || !bHasUserFile ||
			 FindIsMatch(lpExclude, Who.lpUserFile, FALSE) ||
			 (bIsAdmin && (dwStatus == W_UPLOAD || dwStatus == W_DOWNLOAD))) &&
			(!lpSearch  || !bHasUserFile ||
			 !FindIsMatch(lpSearch, Who.lpUserFile, TRUE));

		if (!shouldDisplay) {
			dwHidden++;
			FreeShared(Who.OnlineData.tszRealPath);
			FreeShared(Who.OnlineData.tszRealDataPath);
			UserFile_Close(&Who.lpUserFile, 0);
			continue;
		}

		bHidden = FALSE;
		if (!bIsAdmin) {
			for (n = 0; n < dwPaths; n++) {
				if (!PathCompare(tszPathsArr[n], Who.OnlineData.tszVirtualPath)) {
					bHidden = TRUE;
					_tcscpy(Who.OnlineData.tszVirtualPath, _T("<hidden>"));
				}
				if (!PathCompare(tszPathsArr[n], Who.OnlineData.tszVirtualDataPath)) {
					bHidden = TRUE;
					_tcscpy(Who.OnlineData.tszVirtualDataPath, _T("<hidden>"));
				}
			}
		}

		tszSpace = _tcschr(Who.OnlineData.tszAction, _T(' '));
		if (tszSpace && !bIsAdmin) {
			if (!_tcsnicmp(Who.OnlineData.tszAction, _T("site "), 5)) {
				tszSpace = _tcschr(&Who.OnlineData.tszAction[5], _T(' '));
				if (tszSpace) *tszSpace = 0;
			}
			else if (!_tcsnicmp(Who.OnlineData.tszAction, _T("PORT "), 5)) {
				*tszSpace = 0;
			}
			else if (bHidden) {
				*tszSpace = 0;
			}
			else if ((tszSlash = _tcschr(Who.OnlineData.tszAction, _T('/')))) {
				if ((tszSlash - Who.OnlineData.tszAction) < (_countof(Who.OnlineData.tszAction) - 9)) {
					_tcscpy(tszSlash, _T("<hidden>"));
				}
				else {
					*tszSpace = 0;
				}
			}
		}

		if (!bSorting) {
			Message_Compile(pBuffer[dwStatus], lpBuffer, FALSE, &Who, DT_WHO, tszMultilinePrefix, NULL);
		}
		else {
			if (dwSorted == dwMaxSorted) {
				dwMaxSorted *= 2;
				lpSortWhoTemp = ReAllocate(lpSortWhoArray, "SortWhoArray", dwMaxSorted * sizeof(*lpSortWhoArray));
				if (!lpSortWhoTemp) {
					dwError = ERROR_OUTOFMEMORY;
					FreeShared(Who.OnlineData.tszRealPath);
					FreeShared(Who.OnlineData.tszRealDataPath);
					UserFile_Close(&Who.lpUserFile, 0);
					break;
				}
				lpSortWhoArray = lpSortWhoTemp;
			}

			// Who.lpUserFile may be NULL for connecting users; skip name lookup in that case.
			tszName = (Who.lpUserFile ? Uid2User(Who.lpUserFile->Uid) : NULL);
			if (tszName) {
				lpNext = &lpSortWhoArray[dwSorted++];

				// Store the name into the temporary buffer
				lpNext->dwNameIndex = TempBuf.len;
				Put_Buffer(&TempBuf, tszName, (_tcslen(tszName) + 1) * sizeof(TCHAR));

				// Compile the message line and store its offset and length
				lpNext->dwLineIndex = TempBuf.len;
				Message_Compile(pBuffer[dwStatus], &TempBuf, FALSE, &Who, DT_WHO, tszMultilinePrefix, NULL);
				lpNext->dwLineLen = TempBuf.len - lpNext->dwLineIndex;
			}

		}

		FreeShared(Who.OnlineData.tszRealPath);
		FreeShared(Who.OnlineData.tszRealDataPath);
		UserFile_Close(&Who.lpUserFile, 0);
	}

	Who.dwLoginHours = dwHidden;

	if (bSorting)
	{
		qsort_s(lpSortWhoArray, dwSorted, sizeof(*lpSortWhoArray), WhoSortCmp, TempBuf.buf);

		// AllocateBuffer returns non-zero on failure; treat non-zero as OOM.
		if (AllocateBuffer(lpBuffer, lpBuffer->len + TempBuf.len))
		{
			dwError = ERROR_OUTOFMEMORY;
			goto cleanup;
		}

		for (n = 0; n < dwSorted; n++)
		{
			lpNext = &lpSortWhoArray[n];
			CopyMemory(&lpBuffer->buf[lpBuffer->len], &TempBuf.buf[lpNext->dwLineIndex], lpNext->dwLineLen);
			lpBuffer->len += lpNext->dwLineLen;
		}
	}

	_tcscpy(&tszFileName[dwFileName - 8], _TEXT("Footer"));
	MessageFile_Show(tszFileName, lpBuffer, &Who, DT_WHO, tszMultilinePrefix, NULL);

cleanup:
	if (lpSearch) FindFinished(lpSearch);
	if (lpExclude) FindFinished(lpExclude);

	for (n = 0; n < 20; n++)
	{
		if (tszPathsArr[n]) Free(tszPathsArr[n]);
	}

	if (pBuffer[W_UPLOAD])   Free(pBuffer[W_UPLOAD]);
	if (pBuffer[W_DOWNLOAD]) Free(pBuffer[W_DOWNLOAD]);
	if (pBuffer[W_IDLE])     Free(pBuffer[W_IDLE]);
	if (pBuffer[W_LIST])     Free(pBuffer[W_LIST]);
	if (pBuffer[W_LOGIN])    Free(pBuffer[W_LOGIN]);
	Free(tszFileName);

	if (bSorting)
	{
		if (TempBuf.buf) Free(TempBuf.buf);
		if (lpSortWhoArray) Free(lpSortWhoArray);
	}

	if (dwError && tszSearch)
	{
		ERROR_RETURN(ERROR_INVALID_ARGUMENTS, tszSearch);
	}
	if (dwError)
	{
		ERROR_RETURN(dwError, GetStringIndexStatic(Args, 1));
	}

	return NULL;
}

LPTSTR Admin_Groups(LPFTPUSER lpUser, LPTSTR tszMultilinePrefix, LPIO_STRING Args)
{
	LPGROUPFILE		lpGroupFile;
	LPBUFFER		lpBuffer;
	PBYTE			pBuffer;
	INT				iOffset, i, Gid;
	LPTSTR			tszFileName, tszBasePath, tszArg;
	DWORD			dwFileName, dwHidden;
	BOOL            bAdmin, bAll;

	if (GetStringItems(Args) > 2) ERROR_RETURN(ERROR_INVALID_ARGUMENTS, GetStringRange(Args, 2, STR_END));

	bAll = FALSE;
	if (GetStringItems(Args) == 2)
	{
		tszArg = GetStringIndexStatic(Args, 1);
		if (!tszArg || _tcsicmp(tszArg, _T("-all")))
		{
			ERROR_RETURN(ERROR_INVALID_ARGUMENTS, tszArg);
		}
		bAll = TRUE;
	}

	lpBuffer = &lpUser->CommandChannel.Out;

	//	Show header
	tszBasePath = Service_MessageLocation(lpUser->Connection.lpService);
	if (!tszBasePath) return NULL;
	dwFileName = aswprintf(&tszFileName, _TEXT("%s\\GroupList.Header"), tszBasePath);
	FreeShared(tszBasePath);
	if (!dwFileName) return NULL;
	MessageFile_Show(tszFileName, lpBuffer, lpUser, DT_FTPUSER, tszMultilinePrefix, NULL);

	bAdmin = !HasFlag(lpUser->UserFile, "1M");
	dwHidden = 0;

	//	Load body
	_tcscpy(&tszFileName[dwFileName - 6], _TEXT("Body"));
	pBuffer = Message_Load(tszFileName);

	if (pBuffer)
	{
		iOffset = -1;
		while (!GroupFile_OpenNext(&lpGroupFile, &iOffset))
		{
			if (!bAdmin)
			{
				for (i = 0; i < MAX_GROUPS && ((Gid = lpUser->UserFile->AdminGroups[i]) != -1); i++)
				{
					if (Gid == lpGroupFile->Gid) break;
				}
				if (((i >= MAX_GROUPS) || (Gid == -1)) && (lpGroupFile->Gid != 1))
				{
					GroupFile_Close(&lpGroupFile, 0);
					dwHidden++;
					continue;
				}
			}

			if (!bAll && !lpGroupFile->Users && !stricmp(lpGroupFile->szDescription, "-"))
			{
				dwHidden++;
			}
			else
			{
				Message_Compile(pBuffer, lpBuffer, FALSE, lpGroupFile, DT_GROUPFILE, tszMultilinePrefix, NULL);
			}
			GroupFile_Close(&lpGroupFile, 0);
		}
		Free(pBuffer);
	}

	//	Show footer
	lpUser->FtpVariables.iPos = dwHidden;
	_tcscpy(&tszFileName[dwFileName - 6], _TEXT("Footer"));
	MessageFile_Show(tszFileName, lpBuffer, lpUser, DT_FTPUSER, tszMultilinePrefix, NULL);


	Free(tszFileName);
	return NULL;
}



LPTSTR Admin_Users(LPFTPUSER lpUser, LPTSTR tszMultilinePrefix, LPIO_STRING Args)
{
	LPUSERFILE		lpUserFile;
	LPBUFFER		lpBuffer;
	PBYTE			pBuffer;
	LPUSERSEARCH	lpSearch;
	LPTSTR			tszWildCard, tszFileName, tszBasePath, tszName;
	DWORD			dwFileName, dwError, dwMatches, dwUsers, n, dwBad;
	USERFILE_PLUS   UserFile_Plus;
	BOOL            bShowErrors;
	INT32           Uid;
	TCHAR           tszAsterisk[] = _T("*");

	//	Get arguments
	lpBuffer = &lpUser->CommandChannel.Out;
	bShowErrors = FALSE;

	if (GetStringItems(Args) > 1)
	{
		tszWildCard = GetStringIndexStatic(Args, 1);
		if (!_tcsicmp(tszWildCard, _T("-errors")))
		{
			bShowErrors = TRUE;
			if (GetStringItems(Args) > 2)
			{
				tszWildCard = GetStringRange(Args, 2, STR_END);
			}
			else
			{
				tszWildCard = tszAsterisk;
			}
		}
		else
		{
			tszWildCard = GetStringRange(Args, 1, STR_END);
		}
	}
	else tszWildCard = tszAsterisk;

	// let's test the user match string for errors before displaying anything...
	lpSearch = FindParse(tszWildCard, lpUser->UserFile, lpUser, TRUE);
	if (!lpSearch)
	{
		if (tszWildCard == tszAsterisk)
		{
			return GetStringIndexStatic(Args, 0);
		}
		return tszWildCard;
	}

	//	Show header
	tszBasePath = Service_MessageLocation(lpUser->Connection.lpService);
	if (!tszBasePath)
	{
		FindFinished(lpSearch);
		return NULL;
	}
	dwFileName = aswprintf(&tszFileName, _TEXT("%s\\UserList.Header"), tszBasePath);
	FreeShared(tszBasePath);
	if (!dwFileName)
	{
		FindFinished(lpSearch);
		return NULL;
	}
	MessageFile_Show(tszFileName, lpBuffer, lpUser, DT_FTPUSER, tszMultilinePrefix, NULL);

	//	Load body
	_tcscpy(&tszFileName[dwFileName - 6], _TEXT("Body"));
	pBuffer = Message_Load(tszFileName);

	dwMatches = 0;
	dwUsers = 0;
	dwError = NO_ERROR;

	if (pBuffer)
	{
		dwUsers = lpSearch->dwUidList; // this is number of id's returned...
		//	List users matching globber
		while (!FindNextUser(lpSearch, &lpUserFile))
		{
			dwMatches++;
			UserFile_Plus.lpCommandChannel = &lpUser->CommandChannel;
			UserFile_Plus.lpFtpUserCaller = lpUser;
			UserFile_Plus.lpUserFile = lpUserFile;
			Message_Compile(pBuffer, lpBuffer, FALSE, &UserFile_Plus, DT_USERFILE_PLUS, tszMultilinePrefix, NULL);
			UserFile_Close(&lpUserFile, 0);
		}
		Free(pBuffer);
	}
	else
	{
		FindFinished(lpSearch);
	}

	dwBad = 0;
	if (!dwError)
	{
		//	Show footer
		lpUser->FtpVariables.iPos = dwMatches;
		lpUser->FtpVariables.iMax = dwUsers;
		_tcscpy(&tszFileName[dwFileName - 6], _TEXT("Footer"));
		MessageFile_Show(tszFileName, lpBuffer, lpUser, DT_FTPUSER, tszMultilinePrefix, NULL);

		// now run through and report users with errors if caller is 1M user.
		if (!HasFlag(lpUser->UserFile, _T("M1")) && lpUser->FtpVariables.lpUidList && lpUser->FtpVariables.lpUidMatches)
		{
			for (n = 0; n < lpUser->FtpVariables.dwUidList; n++)
			{
				if ((lpUser->FtpVariables.lpUidMatches[n] < -1) && ((Uid = lpUser->FtpVariables.lpUidList[n]) > -1))
				{
					dwBad++;
					if (bShowErrors)
					{
						if (dwBad == 1)
						{
							FormatString(lpBuffer, _T("%s%2TErrors:%0T\r\n"), tszMultilinePrefix);
						}

						//  Seek by id
						tszName = IdDataBase_SearchById(Uid, &dbUserId);
						if (tszName)
						{
							FormatString(lpBuffer, _T("%s  %4T[Uid: %d, Name: \"%s\"]%0T\r\n"), tszMultilinePrefix, Uid, tszName);
						}
						else
						{
							FormatString(lpBuffer, _T("%s  %4T[Uid: %d, Name: ?]%0T\r\n"), tszMultilinePrefix, Uid);
						}
					}
				}
			}
			if (!bShowErrors && dwBad)
			{
				FormatString(lpBuffer, _T("%s%2TErrors: %4T%d%0T\r\n%s Use 'site %s -errors' to see them.\r\n"),
					tszMultilinePrefix, dwBad, tszMultilinePrefix, GetStringIndexStatic(Args, 0));
			}
		}
	}
	Free(tszFileName);
	if (dwError)
	{
		ERROR_RETURN(dwError, tszWildCard);
	}
	return NULL;
}



LPTSTR Admin_Kill(LPFTPUSER lpUser, LPTSTR tszMultilinePrefix, LPIO_STRING Args)
{
	DWORD		dwError;
	LPTSTR		tszConnectionId;
	TCHAR* tpCheck;
	DWORD		dwConnectionId;

	dwError = NO_ERROR;
	if (GetStringItems(Args) < 2) ERROR_RETURN(ERROR_MISSING_ARGUMENT, GetStringIndexStatic(Args, 0));
	if (GetStringItems(Args) > 2) ERROR_RETURN(ERROR_INVALID_ARGUMENTS, GetStringRange(Args, 2, STR_END));

	//	Get arguments
	tszConnectionId = GetStringIndexStatic(Args, 1);
	dwConnectionId = _tcstoul(tszConnectionId, &tpCheck, 10);
	if (dwConnectionId >= MAX_CLIENTS ||
		tpCheck <= tszConnectionId ||
		tpCheck[0] != _TEXT('\0')) ERROR_RETURN(ERROR_INVALID_ARGUMENTS, tszConnectionId);

	if (KillUser(dwConnectionId))
	{
		ERROR_RETURN(ERROR_USER_NOT_ONLINE, tszConnectionId);
	}
	return NULL;
}





LPTSTR Admin_Kick(LPFTPUSER lpUser, LPTSTR tszMultilinePrefix, LPIO_STRING Args)
{
	LPUSERFILE		lpUserFile;
	DWORD			dwError;
	LPTSTR			tszUserName;
	LRESULT			lResult;

	dwError = NO_ERROR;
	if (GetStringItems(Args) < 2) ERROR_RETURN(ERROR_MISSING_ARGUMENT, GetStringIndexStatic(Args, 0));
	if (GetStringItems(Args) > 2) ERROR_RETURN(ERROR_INVALID_ARGUMENTS, GetStringRange(Args, 2, STR_END));

	//	Get arguments
	tszUserName = GetStringIndexStatic(Args, 1);

	if (!UserFile_Open(tszUserName, &lpUserFile, 0))
	{
		//	Check permission
		dwError = CheckForMasterAccount(lpUser, lpUserFile);

		//	Kick user
		if (dwError == NO_ERROR)
		{
			lResult = KickUser(lpUserFile->Uid);
			if (!lResult) dwError = ERROR_USER_NOT_ONLINE;
		}

		UserFile_Close(&lpUserFile, 0);
		if (dwError == NO_ERROR) return NULL;
		SetLastError(dwError);
	}
	return tszUserName;
}
