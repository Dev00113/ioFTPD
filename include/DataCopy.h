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

#define DC_EXECUTE		0	//	Context = LPSTR
#define DC_USER_TO_UID		1	//	Context = DC_NAMEID
#define DC_UID_TO_USER		2	//	Context = DC_NAMEID
#define DC_GROUP_TO_GID		3	//	Context = DC_NAMEID
#define DC_GID_TO_GROUP		4	//	Context = DC_NAMEID
#define DC_USERFILE_OPEN	5	//	Context = USERFILE_OLD
#define DC_USERFILE_LOCK	6	//	Context = USERFILE_OLD
#define DC_USERFILE_UNLOCK	7	//	Context = USERFILE_OLD
#define DC_USERFILE_CLOSE	8	//	Context = USERFILE_OLD
#define DC_GROUPFILE_OPEN	9	//	Context = GROUPFILE
#define DC_GROUPFILE_CLOSE	10	//	Context = GROUPFILE
#define DC_FILEINFO_READ	11	//	Context = DC_VFS
#define DC_FILEINFO_WRITE	12	//	Context = DC_VFS
#define	DC_GET_ONLINEDATA	13	//	Context = DC_ONLINEDATA
#define DC_CREATE_USER		14	//	Context = DC_NAMEID
#define DC_RENAME_USER		15	//	Context = DC_RENAME
#define DC_DELETE_USER		16	//	Context = DC_NAMEID
#define DC_CREATE_GROUP		17	//	Context	= DC_NAMEID
#define DC_RENAME_GROUP		18	//	Context = DC_RENAME
#define DC_DELETE_GROUP		19	//	Context = DC_NAMEID
#define DC_GROUPFILE_LOCK	20	//	Context = GROUPFILE
#define DC_GROUPFILE_UNLOCK	21	//	Context = GROUPFILE
#define DC_DIRECTORY_MARKDIRTY	 22 //  Context = LPTSTR
#define DC_NEW_USERFILE_OPEN     23 //  Context = USERFILE
#define DC_NEW_USERFILE_LOCK     24 //  Context = USERFILE
#define DC_NEW_USERFILE_UNLOCK   25 //  Context = USERFILE
#define DC_NEW_USERFILE_CLOSE    26 //  Context = USERFILE



// Wire-format IPC message header written by the sending process into shared memory.
// All fields are fixed-width integers — no handles or pointers — so layout is
// identical regardless of whether sender (32-bit) or receiver (64-bit) reads it.
// Size: 4+4+4+4+8 = 24 bytes on both architectures (qwContextOffset is at offset 16,
// which is already 8-byte aligned after four UINT32 fields).
#define DC_MESSAGE_VERSION	2
typedef struct _DC_MESSAGE_WIRE
{
	UINT32		dwVersion;		// Must be DC_MESSAGE_VERSION
	UINT32		dwIdentifier;	// Command identifier
	UINT32		dwReturn;		// Result written by ioFTPD
	UINT32		dwEventHandle;	// Event HANDLE value as seen by sending process (always ≤32-bit)
	UINT64		qwContextOffset;// Byte offset from start of shared-mem view to context data

} DC_MESSAGE_WIRE, *LPDC_MESSAGE_WIRE;

static_assert(sizeof(DC_MESSAGE_WIRE) == 24, "DC_MESSAGE_WIRE must be exactly 24 bytes on all architectures");



#define ER_AVAILABLE	0x0000
#define ER_IN_USE		0x0001
#define ER_REMOVED		0x0002

typedef struct _DC_USERFILE_REQUEST
{
	USERFILE           UserFile;

	struct _DC_USERFILE_REQUEST *lpNext;
	struct _DC_USERFILE_REQUEST *lpPrev;
} DC_USERFILE_REQUEST, *LPDC_USERFILE_REQUEST;


typedef struct _EXCHANGE_REQUEST
{
	WORD				  wType;		// Type of allocation
	WORD				  wStatus;		// Request status
	HANDLE				  hEvent;		// Event handle
	HANDLE				  hMemory;		// Memory object handle
	ULONGLONG			  dwTickCount;	// When request was issued
	DWORD				  dwMappedSize;	// Size of mapped region (from VirtualQuery), for bounds checking
	LPDC_USERFILE_REQUEST lpUserFileReqList[2]; // linked list of open userfile requests
	LPDC_MESSAGE_WIRE	  lpMessage;	// pointer into MapViewOfFile region

	struct _EXCHANGE_REQUEST	*lpNext;
	struct _EXCHANGE_REQUEST	*lpPrev;

} EXCHANGE_REQUEST, * LPEXCHANGE_REQUEST;



typedef struct _DC_RENAME
{
	TCHAR	tszName[_MAX_NAME + 1];
	TCHAR	tszNewName[_MAX_NAME + 1];
} DC_RENAME, * LPDC_RENAME;



typedef struct _DC_NAMEID
{
	TCHAR	tszName[_MAX_NAME + 1];
	INT32		Id;

} DC_NAMEID, * LPDC_NAMEID;



typedef struct _DC_ONLINEDATA
{
	ONLINEDATA_WIRE	OnlineData;		// wire format — identical layout on 32/64-bit
	INT				iOffset;
	DWORD			dwSharedMemorySize;

} DC_ONLINEDATA, * LPDC_ONLINEDATA;



typedef struct _DC_VFS
{
	UINT32			Uid;
	UINT32			Gid;
	DWORD			dwFileMode;
	DWORD			dwBuffer;
	BYTE			pBuffer[];		// C99 flexible array member — variable-length byte data follows fixed fields

} DC_VFS, * LPDC_VFS;


#define FILEMAP		1

VOID DataCopy_DeInit(VOID);
BOOL DataCopy_Init(BOOL bFirstInitialization);
