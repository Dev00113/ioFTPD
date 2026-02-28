/*
* Copyright(c) 2006 Yil@Wondernet.nu
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

#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>
#include <openssl/provider.h>
#include <openssl/decoder.h>
#include <openssl/params.h>     // OSSL_PARAM, OSSL_PARAM_construct_*
#include <openssl/core_names.h> // OSSL_PKEY_PARAM_GROUP_NAME, OSSL_PKEY_PARAM_RSA_BITS

// include the "glue" for handling different runtime libraries
#include <openssl/applink.c>
#include <windows.h>

// OpenSSL 3.x provider handles. Loaded in Security_Init, unloaded in Security_DeInit.
static OSSL_PROVIDER *g_pDefaultProvider = NULL;
static OSSL_PROVIDER *g_pLegacyProvider  = NULL;

typedef struct _OPENSSLPROGRESS
{
	LPIOSOCKET lpIoSocket;
	LPBUFFER   lpBuffer;
	LPTSTR     tszPrefix;
	LPTSTR     tszBlank;
	BOOL       bShowDots;
	//VOID      (*OutputFunc)(LPOPENSSLPROGRESS, LPSTR, ...);
	VOID(*OutputFunc)(struct _OPENSSLPROGRESS* lpProgress, LPTSTR szFormat, ...);

} OPENSSLPROGRESS, * LPOPENSSLPROGRESS;


VOID MyOpenSSL_PutLog(LPOPENSSLPROGRESS lpProgress, LPSTR szFormat, ...)
{
	va_list	Arguments;

	va_start(Arguments, szFormat);
	PutlogVA(LOG_DEBUG, szFormat, Arguments);
	va_end(Arguments);
}


VOID MyOpenSSL_Format(LPOPENSSLPROGRESS lpProgress, LPSTR szFormat, ...)
{
	va_list	Arguments;

	va_start(Arguments, szFormat);
	FormatStringAVA(lpProgress->lpBuffer, szFormat, Arguments);
	va_end(Arguments);
}


int MyOpenSSL_Progress_Callback(int p, int n, BN_GENCB* bn_GenCB)
{
	LPOPENSSLPROGRESS lpProgress;
	LPBUFFER          lpBuffer;
	TCHAR             tc;
	VOID(*Out)(struct _OPENSSLPROGRESS* lpProgress, LPTSTR szFormat, ...);

	lpProgress = (LPOPENSSLPROGRESS)BN_GENCB_get_arg(bn_GenCB);
	lpBuffer = lpProgress->lpBuffer;
	Out = lpProgress->OutputFunc;

	if (lpBuffer->len == 0 && lpProgress->bShowDots)
	{
		(Out)(lpProgress, _T("%s"), lpProgress->tszPrefix);
	}

	if (p == 3)
	{
		// we're done...
		(Out)(lpProgress, _T("(DONE)\r\n"));
	}
	else
	{
		tc = _T('*');
		if (p == 0) tc = _T('.');
		if (p == 1) tc = _T('+');
		if (lpProgress->bShowDots)
		{
			(Out)(lpProgress, _T("%c"), tc);
		}
	}

	// now check to see if got 70 characters on the line so far and if we are finished.
	// If so flush the buffer and start a new line...
	if ((lpBuffer->len > 70) || (p == 3))
	{
		if (lpProgress->bShowDots && (p != 3))
		{
			(Out)(lpProgress, _T("\r\n"));
		}
		if (lpProgress->lpIoSocket)
		{
			SendQuick(lpProgress->lpIoSocket, lpBuffer->buf, lpBuffer->len);
			lpBuffer->len = 0;
		}
	}
	return 1;
}


static BOOL AddExtension(X509* cert, X509V3_CTX* ctx, int nid, const char* value)
{
	X509_EXTENSION* ex = X509V3_EXT_conf_nid(NULL, ctx, nid, (char*)value);
	if (!ex) return FALSE;
	if (!X509_add_ext(cert, ex, -1)) {
		X509_EXTENSION_free(ex);
		return FALSE;
	}
	X509_EXTENSION_free(ex);
	return TRUE;
}


static void MakeCert_LogOpenSSLErrors(LPOPENSSLPROGRESS lpProgress)
{
	unsigned long err;
	char  abuf[512];

	while ((err = ERR_get_error()) != 0) {
		ERR_error_string_n(err, abuf, sizeof(abuf));
#ifdef UNICODE
		{
			TCHAR tbuf[512];
			int nch = MultiByteToWideChar(CP_UTF8, 0, abuf, -1, tbuf, _countof(tbuf));
			if (nch <= 0) {
				MultiByteToWideChar(CP_ACP, 0, abuf, -1, tbuf, _countof(tbuf));
			}
			lpProgress->OutputFunc(lpProgress, _T("%sOpenSSL: %s\r\n"), lpProgress->tszPrefix, tbuf);
		}
#else
		lpProgress->OutputFunc(lpProgress, "%sOpenSSL: %s\r\n", lpProgress->tszPrefix, abuf);
#endif
	}
}

/*
* Generate a strong ECDSA certificate with the specified common name. The cert and key are returned in PEM format in the provided buffer.
* This certificate is not compatible with older ioFTPD versions that require RSA keys, but is more secure and faster to generate.
*/
BOOL MakeCertECDSA(LPTSTR szCertName, LPOPENSSLPROGRESS lpProgress)
{
	LPBUFFER   lpBuffer = lpProgress->lpBuffer;
	TCHAR      tszFileName[MAX_PATH + 1] = { 0 };
	EVP_PKEY* pKey = NULL;
	X509* pX509 = NULL;
	FILE* File = NULL;
	BOOL       bReturn = FALSE;
	errno_t    ferr;
	VOID(*Out)(struct _OPENSSLPROGRESS*, LPTSTR, ...) = lpProgress->OutputFunc;

	// Validate cert name length
	size_t sLen = _tcslen(szCertName);
	if (sLen + 5 > _countof(tszFileName)) {
		Out(lpProgress, _T("%sPath/Filename too long.\r\n"), lpProgress->tszPrefix);
		return FALSE;
	}

	// Generate EC key (prime256v1 = NIST P-256) using EVP_PKEY_CTX (OpenSSL 3.x)
	{
		OSSL_PARAM params[2];
		params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0);
		params[1] = OSSL_PARAM_construct_end();
		EVP_PKEY_CTX* pECCtx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
		if (!pECCtx) goto error;
		if (EVP_PKEY_keygen_init(pECCtx) <= 0 ||
			EVP_PKEY_CTX_set_params(pECCtx, params) <= 0 ||
			EVP_PKEY_keygen(pECCtx, &pKey) <= 0)
		{
			EVP_PKEY_CTX_free(pECCtx);
			goto error;
		}
		EVP_PKEY_CTX_free(pECCtx);
	}

	// Create X509 cert
	pX509 = X509_new();
	if (!pX509) goto error;
	if (!X509_set_version(pX509, 2)) goto error;

	// Secure random serial number
	{
		unsigned char serial[16];
		if (RAND_bytes(serial, sizeof(serial)) != 1) goto error;
		serial[0] &= 0x7F;
		if (serial[0] == 0) serial[0] = 1;

		BIGNUM* bn = BN_bin2bn(serial, sizeof(serial), NULL);
		if (!bn) goto error;
		if (!BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(pX509))) { BN_free(bn); goto error; }
		BN_free(bn);
	}

	// Validity period
	if (!X509_gmtime_adj(X509_getm_notBefore(pX509), -60 * 60 * 24)) goto error;
	if (!X509_gmtime_adj(X509_getm_notAfter(pX509), 60 * 60 * 24 * 397)) goto error;

	// Public key
	if (!X509_set_pubkey(pX509, pKey)) goto error;

	// Subject and issuer
	X509_NAME* xName = X509_get_subject_name(pX509);
#ifdef UNICODE
	char nameA[MAX_PATH + 1];
	int m = WideCharToMultiByte(CP_UTF8, 0, szCertName, -1, nameA, sizeof(nameA), NULL, NULL);
	if (m <= 0) goto error;
	if (!X509_NAME_add_entry_by_txt(xName, "CN", MBSTRING_UTF8, (unsigned char*)nameA, -1, -1, 0)) goto error;
#else
	if (!X509_NAME_add_entry_by_txt(xName, "CN", MBSTRING_ASC, (unsigned char*)szCertName, -1, -1, 0)) goto error;
#endif
	if (!X509_set_issuer_name(pX509, xName)) goto error;

	// X.509 v3 extensions
	{
		X509V3_CTX ctx;
		X509V3_set_ctx_nodb(&ctx);
		X509V3_set_ctx(&ctx, pX509, pX509, NULL, NULL, 0);

		if (!AddExtension(pX509, &ctx, NID_basic_constraints, "CA:FALSE")) goto error;
		if (!AddExtension(pX509, &ctx, NID_key_usage, "digitalSignature,keyEncipherment")) goto error;
		if (!AddExtension(pX509, &ctx, NID_ext_key_usage, "serverAuth")) goto error;

		char sanBuf[256];
#ifdef UNICODE
		_snprintf_s(sanBuf, sizeof(sanBuf), _TRUNCATE, "DNS:%s", nameA);
#else
		_snprintf_s(sanBuf, sizeof(sanBuf), _TRUNCATE, "DNS:%s", szCertName);
#endif
		if (!AddExtension(pX509, &ctx, NID_subject_alt_name, sanBuf)) goto error;

		if (!AddExtension(pX509, &ctx, NID_subject_key_identifier, "hash")) goto error;
		if (!AddExtension(pX509, &ctx, NID_authority_key_identifier, "keyid:always")) goto error;
	}

	// Sign with ECDSA
	if (!X509_sign(pX509, pKey, EVP_sha256())) goto error;
	if (!X509_verify(pX509, pKey)) {
		Out(lpProgress, _T("%sFailed to verify certificate.\r\n"), lpProgress->tszPrefix);
		goto error;
	}

	// Delete old cert/key
	Secure_Delete_Cert(szCertName);

	// Write private key (.key)
	_sntprintf_s(tszFileName, _countof(tszFileName), _TRUNCATE, _T("%s.key"), szCertName);
	ferr = _tfopen_s(&File, tszFileName, _T("wN"));
	if (ferr || !File) goto error;
	if (!PEM_write_PKCS8PrivateKey(File, pKey, NULL, NULL, 0, NULL, NULL)) goto error;
	fclose(File); File = NULL;

	// Write certificate (.pem)
	_sntprintf_s(tszFileName, _countof(tszFileName), _TRUNCATE, _T("%s.pem"), szCertName);
	ferr = _tfopen_s(&File, tszFileName, _T("wN"));
	if (ferr || !File) goto error;
	if (!PEM_write_X509(File, pX509)) goto error;
	fclose(File); File = NULL;

	bReturn = TRUE;

error:
	if (!bReturn) {
		unsigned long err;
		char abuf[512];
		while ((err = ERR_get_error()) != 0) {
			ERR_error_string_n(err, abuf, sizeof(abuf));
#ifdef UNICODE
			{
				TCHAR tbuf[512];
				MultiByteToWideChar(CP_UTF8, 0, abuf, -1, tbuf, _countof(tbuf));
				Out(lpProgress, _T("%sOpenSSL: %s\r\n"), lpProgress->tszPrefix, tbuf);
			}
#else
			Out(lpProgress, "%sOpenSSL: %s\r\n", lpProgress->tszPrefix, abuf);
#endif
		}
	}
	if (pKey) EVP_PKEY_free(pKey);
	if (pX509) X509_free(pX509);
	if (File) fclose(File);
	return bReturn;
}

/*
* This MakeCert generates an RSA certificate compatible with older ioFTPD versions, but is slower to generate and less secure than the ECDSA version.
* It is included for compatibility with older ioFTPD versions that require RSA keys, but the ECDSA version is recommended for new deployments.
*/
BOOL MakeCert(LPTSTR szCertName, LPOPENSSLPROGRESS lpProgress)
{
	LPBUFFER   lpBuffer = lpProgress->lpBuffer;
	TCHAR      tszFileName[MAX_PATH + 1] = { 0 };
	EVP_PKEY* pKey = NULL;
	X509* pX509 = NULL;
	FILE* File = NULL;
	BOOL       bReturn = FALSE;
	errno_t    ferr;
	VOID(*Out)(struct _OPENSSLPROGRESS*, LPTSTR, ...) = lpProgress->OutputFunc;

	size_t sLen = _tcslen(szCertName);
	if (sLen + 5 > _countof(tszFileName)) {
		Out(lpProgress, _T("%sPath/Filename too long.\r\n"), lpProgress->tszPrefix);
		return FALSE;
	}

	// ---------------------------------------------------------------------
	// Generate RSA key (2048-bit)
	// ---------------------------------------------------------------------
	{
		unsigned int uBits = 2048;
		OSSL_PARAM params[2];
		params[0] = OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_RSA_BITS, &uBits);
		params[1] = OSSL_PARAM_construct_end();
		EVP_PKEY_CTX* pRSACtx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
		if (!pRSACtx) goto error;

		if (EVP_PKEY_keygen_init(pRSACtx) <= 0 ||
			EVP_PKEY_CTX_set_params(pRSACtx, params) <= 0 ||
			EVP_PKEY_keygen(pRSACtx, &pKey) <= 0)
		{
			EVP_PKEY_CTX_free(pRSACtx);
			goto error;
		}

		EVP_PKEY_CTX_free(pRSACtx);
	}

	// ---------------------------------------------------------------------
	// Create X509 certificate
	// ---------------------------------------------------------------------
	pX509 = X509_new();
	if (!pX509) goto error;
	if (!X509_set_version(pX509, 2)) goto error;

	// Serial number
	{
		unsigned char serial[16];
		if (RAND_bytes(serial, sizeof(serial)) != 1) goto error;
		serial[0] &= 0x7F;
		if (serial[0] == 0) serial[0] = 1;

		BIGNUM* bn = BN_bin2bn(serial, sizeof(serial), NULL);
		if (!bn) goto error;
		if (!BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(pX509))) { BN_free(bn); goto error; }
		BN_free(bn);
	}

	// Validity
	if (!X509_gmtime_adj(X509_getm_notBefore(pX509), -60 * 60 * 24)) goto error;
	if (!X509_gmtime_adj(X509_getm_notAfter(pX509), 60 * 60 * 24 * 397)) goto error;

	// Public key
	if (!X509_set_pubkey(pX509, pKey)) goto error;

	// Subject / Issuer
	X509_NAME* xName = X509_get_subject_name(pX509);
#ifdef UNICODE
	char nameA[MAX_PATH + 1];
	int m = WideCharToMultiByte(CP_UTF8, 0, szCertName, -1, nameA, sizeof(nameA), NULL, NULL);
	if (m <= 0) goto error;
	if (!X509_NAME_add_entry_by_txt(xName, "CN", MBSTRING_UTF8, (unsigned char*)nameA, -1, -1, 0)) goto error;
#else
	if (!X509_NAME_add_entry_by_txt(xName, "CN", MBSTRING_ASC, (unsigned char*)szCertName, -1, -1, 0)) goto error;
#endif
	if (!X509_set_issuer_name(pX509, xName)) goto error;

	// Extensions
	{
		X509V3_CTX ctx;
		X509V3_set_ctx_nodb(&ctx);
		X509V3_set_ctx(&ctx, pX509, pX509, NULL, NULL, 0);

		if (!AddExtension(pX509, &ctx, NID_basic_constraints, "CA:FALSE")) goto error;
		if (!AddExtension(pX509, &ctx, NID_key_usage, "digitalSignature,keyEncipherment")) goto error;
		if (!AddExtension(pX509, &ctx, NID_ext_key_usage, "serverAuth")) goto error;

		char sanBuf[256];
#ifdef UNICODE
		_snprintf_s(sanBuf, sizeof(sanBuf), _TRUNCATE, "DNS:%s", nameA);
#else
		_snprintf_s(sanBuf, sizeof(sanBuf), _TRUNCATE, "DNS:%s", szCertName);
#endif
		if (!AddExtension(pX509, &ctx, NID_subject_alt_name, sanBuf)) goto error;

		if (!AddExtension(pX509, &ctx, NID_subject_key_identifier, "hash")) goto error;
		if (!AddExtension(pX509, &ctx, NID_authority_key_identifier, "keyid:always")) goto error;
	}

	// ---------------------------------------------------------------------
	// Sign with RSA + SHA256
	// ---------------------------------------------------------------------
	if (!X509_sign(pX509, pKey, EVP_sha256())) goto error;

	// ---------------------------------------------------------------------
	// Write private key
	// ---------------------------------------------------------------------
	_sntprintf_s(tszFileName, _countof(tszFileName), _TRUNCATE, _T("%s.key"), szCertName);
	ferr = _tfopen_s(&File, tszFileName, _T("wN"));
	if (ferr || !File) goto error;
	if (!PEM_write_PKCS8PrivateKey(File, pKey, NULL, NULL, 0, NULL, NULL)) goto error;
	fclose(File); File = NULL;

	// ---------------------------------------------------------------------
	// Write certificate
	// ---------------------------------------------------------------------
	_sntprintf_s(tszFileName, _countof(tszFileName), _TRUNCATE, _T("%s.pem"), szCertName);
	ferr = _tfopen_s(&File, tszFileName, _T("wN"));
	if (ferr || !File) goto error;
	if (!PEM_write_X509(File, pX509)) goto error;
	fclose(File); File = NULL;

	bReturn = TRUE;

error:
	if (!bReturn) {
		unsigned long err;
		char abuf[512];
		while ((err = ERR_get_error()) != 0) {
			ERR_error_string_n(err, abuf, sizeof(abuf));
#ifdef UNICODE
			TCHAR tbuf[512];
			MultiByteToWideChar(CP_UTF8, 0, abuf, -1, tbuf, _countof(tbuf));
			Out(lpProgress, _T("%sOpenSSL: %s\r\n"), lpProgress->tszPrefix, tbuf);
#else
			Out(lpProgress, "%sOpenSSL: %s\r\n", lpProgress->tszPrefix, abuf);
#endif
		}
	}

	if (pKey) EVP_PKEY_free(pKey);
	if (pX509) X509_free(pX509);
	if (File) fclose(File);

	return bReturn;
}


// TRUE if successful
BOOL Secure_MakeCert(LPSTR szCertName)
{
	OPENSSLPROGRESS OpenSslProgress;
	BUFFER          Buffer;
	BOOL            bReturn;

	ZeroMemory(&Buffer, sizeof(Buffer));

	OpenSslProgress.lpBuffer = &Buffer;
	OpenSslProgress.tszPrefix = _T("");
	OpenSslProgress.tszBlank = _T("");
	OpenSslProgress.lpIoSocket = NULL;
	OpenSslProgress.bShowDots = FALSE;
	OpenSslProgress.OutputFunc = MyOpenSSL_PutLog;

	bReturn = MakeCert(szCertName, &OpenSslProgress);

	if (Buffer.buf)
	{
		Free(Buffer.buf);
	}
	return bReturn;
}


LPTSTR Admin_MakeCert(LPFTPUSER lpUser, LPTSTR tszMultilinePrefix, LPIO_STRING Args)
{
	LPTSTR			tszUserName, tszCommand, tszCert;
	LPIOSERVICE     lpService;
	LPBUFFER        lpBuffer;
	DWORD           dwPrevious, dwError;
	OPENSSLPROGRESS OpenSslProgress;
	TCHAR           tszPrefix[64];


	//	Get arguments
	tszCommand = GetStringIndexStatic(Args, 0);
	if (GetStringItems(Args) != 1) ERROR_RETURN(ERROR_INVALID_ARGUMENTS, GetStringRange(Args, 1, STR_END));

	tszUserName = LookupUserName(lpUser->UserFile);
	lpBuffer = &lpUser->CommandChannel.Out;

	if (HasFlag(lpUser->UserFile, _TEXT("M")))
	{
		ERROR_RETURN(IO_NO_ACCESS, tszCommand);
	}

	lpService = lpUser->Connection.lpService;
	tszCert = 0;

	if (lpService->tszServiceValue)
	{
		tszCert = lpService->tszServiceValue;
		FormatString(lpBuffer, _TEXT("%sNAME=\"%s\" [%s (Certificate_Name)]\r\n"),
			tszMultilinePrefix, tszCert, lpService->tszName);
		if (lpService->dwFoundCredentials == 1)
		{
			ERROR_RETURN(CRYPT_E_EXISTS, tszCommand);
		}
	}
	else if (lpService->tszHostValue)
	{
		tszCert = lpService->tszHostValue;
		FormatString(lpBuffer, _TEXT("%sNAME=\"%s\" [%s Device (HOST=)]\r\n"),
			tszMultilinePrefix, tszCert, lpService->tszName);
		if (lpService->dwFoundCredentials == 2)
		{
			ERROR_RETURN(CRYPT_E_EXISTS, tszCommand);
		}
	}
	else
	{
		tszCert = _T("ioFTPD");
		FormatString(lpBuffer, _TEXT("%sNAME=\"%s\" [%s (default name)]\r\n"),
			tszMultilinePrefix, tszCert, lpService->tszName);
		if (lpService->dwFoundCredentials == 3)
		{
			ERROR_RETURN(CRYPT_E_EXISTS, tszCommand);
		}
	}

	_stprintf_s(tszPrefix, _countof(tszPrefix), _T("%s\r\n"), tszMultilinePrefix);

	OpenSslProgress.lpBuffer = lpBuffer;
	OpenSslProgress.tszPrefix = tszMultilinePrefix;
	OpenSslProgress.tszBlank = tszPrefix;
	OpenSslProgress.lpIoSocket = &lpUser->CommandChannel.Socket;
	OpenSslProgress.bShowDots = TRUE;
	OpenSslProgress.OutputFunc = MyOpenSSL_Format;

	if (!MakeCert(tszCert, &OpenSslProgress))
	{
		dwError = ERROR_COMMAND_FAILED;
		Putlog(LOG_ERROR, _TEXT("Failed to generate new SSL cert \"%s\". User=%s\r\n"),
			tszCert, tszUserName);
		ERROR_RETURN(dwError, tszCommand);
	}

	Putlog(LOG_GENERAL, _TEXT("SSL: \"Successfully generated new cert: %s\" \"User=%s\".\r\n"),
		tszCert, tszUserName);

	// force a reload
	AcquireExclusiveLock(&lpService->loLock);

	dwPrevious = lpService->dwFoundCredentials;

	Secure_Free_Ctx(lpService->pSecureCtx);
	lpService->pSecureCtx = NULL;
	lpService->dwFoundCredentials = 0;

	Service_GetCredentials(lpService, FALSE);

	ReleaseExclusiveLock(&lpService->loLock);

	if (lpService->dwFoundCredentials != 4 && lpService->dwFoundCredentials < dwPrevious)
	{
		FormatString(lpBuffer, _TEXT("\r\n%sSuccessfully loaded new cert!\r\n"), tszMultilinePrefix);
		return NULL;
	}
	else
	{
		dwError = ERROR_COMMAND_FAILED;
		FormatString(lpBuffer, _TEXT("\r\n%sFailed to load new cert.\r\n"), tszMultilinePrefix);
		ERROR_RETURN(dwError, tszCommand);
	}
}





BOOL
Secure_Init_Socket(LPIOSOCKET lpSocket,
	LPIOSERVICE lpService,
	DWORD dwCreationFlags)
{
	LPSECURITY  lpSecure;
	DWORD      dwBufSize;

	if (lpSocket->lpSecure || !lpService->pSecureCtx) return TRUE;
	//  Allocate memory for security buffers
	if (!(lpSecure = (LPSECURITY)Allocate("Socket:Secure:Structure", sizeof(SECURITY)))) return TRUE;
	ZeroMemory(lpSecure, sizeof(SECURITY));

	AcquireSharedLock(&lpService->loLock);
	if (lpService->pSecureCtx)
	{
		lpSecure->SSL = SSL_new(lpService->pSecureCtx);
	}
	ReleaseSharedLock(&lpService->loLock);

	if (!lpSecure->SSL)
	{
		Free(lpSecure);
		SetLastError(IO_SSL_FAIL);
		return TRUE;
	}

	(void)InitializeCriticalSectionAndSpinCount(&lpSecure->csLock, 1000);
	lpSecure->lRefCount = 1;   // socket owner holds the initial reference

	if (dwCreationFlags & SSL_ACCEPT)
	{
		SSL_set_accept_state(lpSecure->SSL);
	}
	else
	{
		SSL_set_connect_state(lpSecure->SSL);
	}

	//  Allocate decryption buffer
	if (dwCreationFlags & SSL_LARGE_BUFFER)
	{
		// making it the same size as the receive/send buffers just makes sense :)
		dwBufSize = FtpSettings.dwTransferBuffer;
	}
	else
	{
		// Not using DEFAULT_BUF_SIZE (2048) because supposedly the max TLS record is like 16k, so letting
		// openSSL choose the min default size to prevent multiple writes in a row during the handshake.
		dwBufSize = 0;
	}

	if (!BIO_new_bio_pair(&lpSecure->InternalBio, dwBufSize, &lpSecure->NetworkBio, dwBufSize))
	{
		Free(lpSecure);
		SetLastError(IO_SSL_FAIL);
		return TRUE;
	}

	SSL_set_bio(lpSecure->SSL, lpSecure->InternalBio, lpSecure->InternalBio);

	// Use the BIO_ctrl_pending(), to find out whether data is buffered in the BIO and must be transfered to the network.

	lpSocket->lpSecure = lpSecure;
	return FALSE;
}



LONG GetSslOptionBit(LPTSTR tszOption)
{
	if (!_tcsicmp(tszOption, _T("LEGACY_SERVER_CONNECT")))
	{
		return SSL_OP_LEGACY_SERVER_CONNECT;
	}
	if (!_tcsicmp(tszOption, _T("DONT_INSERT_EMPTY_FRAGMENTS")))
	{
		return SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;
	}
	if (!_tcsicmp(tszOption, _T("ALL")))
	{
		return SSL_OP_ALL;
	}
	if (!_tcsicmp(tszOption, _T("NO_QUERY_MTU")))
	{
		return SSL_OP_NO_QUERY_MTU;
	}
	if (!_tcsicmp(tszOption, _T("COOKIE_EXCHANGE")))
	{
		return SSL_OP_COOKIE_EXCHANGE;
	}
	if (!_tcsicmp(tszOption, _T("NO_TICKET")))
	{
		return SSL_OP_NO_TICKET;
	}
	if (!_tcsicmp(tszOption, _T("CISCO_ANYCONNECT")))
	{
		return SSL_OP_CISCO_ANYCONNECT;
	}
	if (!_tcsicmp(tszOption, _T("NO_SESSION_RESUMPTION_ON_RENEGOTIATION")))
	{
		return SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
	}
	if (!_tcsicmp(tszOption, _T("NO_COMPRESSION")))
	{
		return SSL_OP_NO_COMPRESSION;
	}
	if (!_tcsicmp(tszOption, _T("ALLOW_UNSAFE_LEGACY_RENEGOTIATION")))
	{
		return SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION;
	}
	if (!_tcsicmp(tszOption, _T("CIPHER_SERVER_PREFERENCE")))
	{
		return SSL_OP_CIPHER_SERVER_PREFERENCE;
	}
	if (!_tcsicmp(tszOption, _T("TLS_ROLLBACK_BUG")))
	{
		return SSL_OP_TLS_ROLLBACK_BUG;
	}
	if (!_tcsicmp(tszOption, _T("NO_SSLv3")))
	{
		return SSL_OP_NO_SSLv3;
	}
	if (!_tcsicmp(tszOption, _T("NO_TLSv1")))
	{
		return SSL_OP_NO_TLSv1;
	}
	if (!_tcsicmp(tszOption, _T("CRYPTOPRO_TLSEXT_BUG")))
	{
		return SSL_OP_CRYPTOPRO_TLSEXT_BUG;
	}
	return 0;
}



BOOL Secure_Create_Ctx(LPTSTR tszService, LPSTR szCertificateName, const SSL_METHOD* Method, SSL_CTX** ppCtx)
{
	char     szFileName[MAX_PATH + 1];
	SSL_CTX* pCtx;
	size_t   sLen;
	long     lOptionBits, lBit;
	LPTSTR   tszField, tszOption, tszSeparator;

	if (!szCertificateName) return TRUE;

	sLen = strlen(szCertificateName);
	if (sLen + 6 > sizeof(szFileName))
	{
		SetLastError(ERROR_FILENAME_EXCED_RANGE);
		return TRUE;
	}
	_snprintf_s(szFileName, sizeof(szFileName) / sizeof(*szFileName), _TRUNCATE, "%s.pem", szCertificateName);

	pCtx = SSL_CTX_new(Method);
	if (!pCtx) return TRUE;
	// Ensure TLSv1.2 and TLSv1.3 are enabled
	SSL_CTX_set_min_proto_version(pCtx, TLS1_VERSION);
	SSL_CTX_set_max_proto_version(pCtx, TLS1_3_VERSION);

	// Load legacy provider if requested for this service.
	// Default TRUE: DHE-RSA / AES-CBC / MD5 for FXP compat with older FTP servers.
	// OSSL_PROVIDER_load is idempotent — safe to call per-service; OpenSSL ref-counts it.
	{
		BOOL bLoadLegacy = TRUE;
		Config_Get_Bool(&IniConfigFile, tszService, _T("OpenSSL_LoadLegacyProvider"), &bLoadLegacy);

		if (bLoadLegacy)
		{
			if (!g_pLegacyProvider)
			{
				g_pLegacyProvider = OSSL_PROVIDER_load(NULL, "legacy");
				if (!g_pLegacyProvider)
				{
					Putlog(LOG_ERROR,
						_T("OpenSSL: Failed to load 'legacy' provider for service '%s'. ")
						_T("DHE-RSA / AES-CBC FXP compatibility may be reduced. ")
						_T("Ensure legacy.dll is present alongside libcrypto-3.dll.\r\n"),
						tszService);
				}
				else
				{
					Putlog(LOG_GENERAL,
						_T("OpenSSL: Loaded 'legacy' provider for service '%s' (DHE-RSA, AES-CBC, MD5 available).\r\n"),
						tszService);
				}
			}
		}
		else
		{
			Putlog(LOG_GENERAL,
				_T("OpenSSL: 'legacy' provider not loaded for service '%s' (OpenSSL_LoadLegacyProvider=False).\r\n"),
				tszService);
		}
	}

	// Explicitly offer ECDHE groups for TLS 1.3 and TLS 1.2
	// SSL_CTX_set1_groups_list(pCtx, "P-256:P-384:P-521:X25519");
	// Default curve list if ini value is missing or invalid
#define DEFAULT_GROUPS "P-256:P-384:P-521:X25519"

	tszField = Config_Get(&IniConfigFile, tszService, _TEXT("OpenSSL_Groups"), NULL, NULL);

	if (tszField && *tszField)
	{
#ifdef _UNICODE
		char szGroups[256];
		WideCharToMultiByte(CP_UTF8, 0, tszField, -1, szGroups, sizeof(szGroups), NULL, NULL);
		if (SSL_CTX_set1_groups_list(pCtx, szGroups) != 1) {
			Putlog(LOG_ERROR, _T("Invalid OpenSSL_Groups: '%hs'. Falling back to default: '%hs'.\r\n"), szGroups, DEFAULT_GROUPS);
			SSL_CTX_set1_groups_list(pCtx, DEFAULT_GROUPS);
		}
		else {
			Putlog(LOG_DEBUG, _T("Using OpenSSL_Groups: '%s' for service '%s'.\r\n"), tszField, tszService);
		}
#else
		if (SSL_CTX_set1_groups_list(pCtx, tszField) != 1) {
			Putlog(LOG_ERROR, _T("Invalid OpenSSL_Groups: '%s'. Falling back to default: '%s'.\r\n"), tszField, DEFAULT_GROUPS);
			SSL_CTX_set1_groups_list(pCtx, DEFAULT_GROUPS);
		}
		else {
			Putlog(LOG_DEBUG, _T("Using OpenSSL_Groups: '%s' for service '%s'.\r\n"), tszField, tszService);
		}
#endif
		Free(tszField);
	}
	else
	{
		SSL_CTX_set1_groups_list(pCtx, DEFAULT_GROUPS);
	}


	if (!pCtx) return TRUE;

	if (!SSL_CTX_use_certificate_chain_file(pCtx, szFileName))
	{
		SSL_CTX_free(pCtx);
		return TRUE;
	}

	strcpy_s(&szFileName[sLen], sizeof(szFileName) / sizeof(*szFileName) - sLen, ".key");

	if (!SSL_CTX_use_PrivateKey_file(pCtx, szFileName, SSL_FILETYPE_PEM))
	{
		SSL_CTX_free(pCtx);
		return TRUE;
	}

	if (!SSL_CTX_check_private_key(pCtx))
	{
		SSL_CTX_free(pCtx);
		return TRUE;
	}

	if (tszField = Config_Get(&IniConfigFile, tszService, _TEXT("OpenSSL_Options"), NULL, NULL))
	{
		lOptionBits = 0;
		tszOption = tszField;
		while (*tszOption)
		{
			if (tszSeparator = _tcschr(tszOption, _T('|')))
			{
				*tszSeparator = 0;
			}
			lBit = GetSslOptionBit(tszOption);
			if (!lBit)
			{
				Putlog(LOG_ERROR, _T("Unknown option (%s) in OpenSSL_Options for service '%s'.\r\n"), tszOption, tszService);
			}
			lOptionBits |= lBit;
			if (tszSeparator)
			{
				tszOption = tszSeparator + 1;
			}
			else
			{
				break;
			}
		}
		Free(tszField);

		SSL_CTX_set_options(pCtx, lOptionBits);
	}

	tszField = tszOption = Config_Get(&IniConfigFile, tszService, _TEXT("OpenSSL_Ciphers"), NULL, NULL);
	if (!tszOption)
	{
		tszOption = _T("DEFAULT:!LOW:!EXPORT");
	}

	// Read security level from ini; -1 means not configured (validated below)
	int secLevel = -1;
	Config_Get_Int(&IniConfigFile, tszService, _T("OpenSSL_SecurityLevel"), &secLevel);

	// Validate
	if (secLevel < 0 || secLevel > 2)
	{
		Putlog(LOG_DEBUG,
			_T("OpenSSL: Invalid OpenSSL_SecurityLevel=%d in [%s]. Using default=0 (compatibility mode).\r\n"),
			secLevel, tszService);

		secLevel = 0;
	}
	else
	{
		Putlog(LOG_DEBUG,
			_T("OpenSSL: Using OpenSSL_SecurityLevel=%d from [%s].\r\n"),
			secLevel, tszService);
	}

	// Put friendly log message about security level
	switch (secLevel)
	{
	case 0:
		Putlog(LOG_DEBUG, _T("OpenSSL: SecurityLevel=0 (maximum compatibility).\r\n"));
		break;
	case 1:
		Putlog(LOG_DEBUG, _T("OpenSSL: SecurityLevel=1 (OpenSSL default).\r\n"));
		break;
	case 2:
		Putlog(LOG_DEBUG, _T("OpenSSL: SecurityLevel=2 (strict modern TLS).\r\n"));
		break;
	}

	// Apply
	SSL_CTX_set_security_level(pCtx, secLevel);


	// TLS 1.0–1.2 cipher list  (OpenSSL_Ciphers in service section)
	if (!SSL_CTX_set_cipher_list(pCtx, tszOption))
	{
		Putlog(LOG_ERROR,
			_T("No valid TLS 1.2 ciphers selected via OpenSSL_Ciphers for service '%s'.\r\n"),
			tszService);
	}
	if (tszField) { Free(tszField); tszField = NULL; }

	// TLS 1.3 ciphersuites  (optional — uses a different string format than TLS 1.2)
	// e.g. "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"
	// If OpenSSL_Ciphers13 is absent, OpenSSL uses its built-in secure defaults.
	tszField = Config_Get(&IniConfigFile, tszService, _TEXT("OpenSSL_Ciphers13"), NULL, NULL);
	if (tszField && *tszField)
	{
#ifdef _UNICODE
		char szCiphers13[512];
		WideCharToMultiByte(CP_UTF8, 0, tszField, -1, szCiphers13, sizeof(szCiphers13), NULL, NULL);
		if (!SSL_CTX_set_ciphersuites(pCtx, szCiphers13))
#else
		if (!SSL_CTX_set_ciphersuites(pCtx, tszField))
#endif
		{
			Putlog(LOG_ERROR,
				_T("No valid TLS 1.3 ciphersuites in OpenSSL_Ciphers13 for service '%s'.\r\n"),
				tszService);
		}
		Free(tszField); tszField = NULL;
	}
	// OpenSSL_Ciphers13 absent: OpenSSL 3.x defaults apply (AES-GCM, ChaCha20).

	// Load DH parameters for DHE cipher support (OpenSSL 3.x OSSL_DECODER API).
	// If loading fails the server still runs, but DHE cipher suites will be unavailable.
	strcpy_s(&szFileName[sLen], sizeof(szFileName) - sLen, ".dhp");
	{
		FILE *dhFile = NULL;
		if (fopen_s(&dhFile, szFileName, "rN") == 0 && dhFile)
		{
			EVP_PKEY *pDHPKey = NULL;
			OSSL_DECODER_CTX *pDecCtx = OSSL_DECODER_CTX_new_for_pkey(
				&pDHPKey, "PEM", NULL, "DH",
				OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, NULL, NULL);

			if (pDecCtx && OSSL_DECODER_from_fp(pDecCtx, dhFile) && pDHPKey)
			{
				if (!SSL_CTX_set0_tmp_dh_pkey(pCtx, pDHPKey))
				{
					Putlog(LOG_ERROR,
						_T("SSL: Failed to apply DH params for cert '%hs'. DHE ciphers may be unavailable.\r\n"),
						szCertificateName);
					EVP_PKEY_free(pDHPKey);
				}
				else
				{
					Putlog(LOG_DEBUG, _T("SSL: Loaded DH params from '%hs'.\r\n"), szFileName);
					// Ownership of pDHPKey transferred to pCtx on success — do not free.
				}
			}
			else
			{
				Putlog(LOG_ERROR,
					_T("SSL: Invalid or unreadable DH param file '%hs'. DHE ciphers disabled.\r\n"),
					szFileName);
				if (pDHPKey) EVP_PKEY_free(pDHPKey);
			}

			OSSL_DECODER_CTX_free(pDecCtx);
			fclose(dhFile);
		}
		// .dhp absent is normal — DHE simply will not be offered to clients.
	}

	*ppCtx = pCtx;
	return FALSE;
}


VOID Secure_Free_Ctx(SSL_CTX* pCtx)
{
	if (!pCtx) return;

	SSL_CTX_free(pCtx);
}


BOOL Secure_Delete_Cert(LPTSTR tszCertificateName)
{
	TCHAR  File[MAX_PATH + 1];
	size_t sLen;
	DWORD  dwError, dwReturn;
	BOOL   bReturn, bDeleted;

	if (!tszCertificateName) return FALSE;

	bReturn = TRUE;
	bDeleted = FALSE;
	dwReturn = NO_ERROR;

	sLen = _tcslen(tszCertificateName);
	if (sLen + 6 > sizeof(File) / sizeof(*File))
	{
		SetLastError(ERROR_FILENAME_EXCED_RANGE);
		return FALSE;
	}
	_sntprintf_s(File, sizeof(File) / sizeof(*File), _TRUNCATE, _T("%s.pem"), tszCertificateName);

	dwError = NO_ERROR;

	if (!DeleteFile(File))
	{
		dwError = GetLastError();
		if (dwError != ERROR_FILE_NOT_FOUND)
		{
			bReturn = FALSE;
			dwReturn = dwError;
		}
	}
	else
	{
		bDeleted = TRUE;
	}

	_tcscpy_s(&File[sLen], sizeof(File) / sizeof(*File) - sLen, ".key");
	if (!DeleteFile(File))
	{
		dwError = GetLastError();
		if (dwError != ERROR_FILE_NOT_FOUND)
		{
			bReturn = FALSE;
			if (!dwReturn) dwReturn = dwError;
		}
	}
	else
	{
		bDeleted = TRUE;
	}

	_tcscpy_s(&File[sLen], sizeof(File) / sizeof(*File) - sLen, ".dhp");
	if (!DeleteFile(File))
	{
		dwError = GetLastError();
		if (dwError != ERROR_FILE_NOT_FOUND)
		{
			bReturn = FALSE;
			if (!dwReturn) dwReturn = dwError;
		}
	}
	else
	{
		bDeleted = TRUE;
	}

	if (!bReturn)
	{
		SetLastError(dwReturn);
		return FALSE;
	}

	if (!bDeleted)
	{
		SetLastError(ERROR_FILE_MISSING);
		return FALSE;
	}
	return TRUE;
}


LPTSTR Admin_Ciphers(LPFTPUSER lpUser, LPTSTR tszMultilinePrefix, LPIO_STRING Args)
{
	LPTSTR			tszCommand, tszArg;
	LPBUFFER        lpBuffer;
	LPIOSERVICE     lpService;
	SSL_CTX* pCtx;
	SSL* tempSSL;
	int             iCiphers, i;
	const STACK_OF(SSL_CIPHER)* CipherStack;
	const SSL_CIPHER* Cipher;
	CHAR            szBuf[129];

	// [name of service], or -all

	tszCommand = GetStringIndexStatic(Args, 0);
	lpBuffer = &lpUser->CommandChannel.Out;

	if (GetStringItems(Args) > 2) ERROR_RETURN(ERROR_INVALID_ARGUMENTS, tszCommand);

	tempSSL = NULL;
	if (GetStringItems(Args) == 2)
	{
		tszArg = GetStringIndexStatic(Args, 1);
		if (tszArg && !_tcsicmp(tszArg, _T("-all")))
		{
			pCtx = SSL_CTX_new(TLS_method());
			if (!pCtx)
			{
				ERROR_RETURN(IO_SSL_FAIL2, tszCommand);
			}
			tempSSL = SSL_new(pCtx);
			if (!tempSSL)
			{
				SSL_CTX_free(pCtx);
				ERROR_RETURN(IO_SSL_FAIL2, tszCommand);
			}
			if (!SSL_set_cipher_list(tempSSL, "ALL"))
			{
				SSL_free(tempSSL);
				SSL_CTX_free(pCtx);
				ERROR_RETURN(IO_SSL_FAIL2, tszCommand);
			}
		}
		else
		{
			ERROR_RETURN(ERROR_INVALID_ARGUMENTS, tszCommand);
		}
	}
	else
	{
		pCtx = NULL;
		lpService = lpUser->Connection.lpService;

		AcquireSharedLock(&lpService->loLock);
		if (!lpService->pSecureCtx)
		{
			ReleaseSharedLock(&lpService->loLock);
			FormatString(lpBuffer, _T("%sNo certificate loaded for service '%s'.\r\n"), tszMultilinePrefix, lpService->tszName);
			ERROR_RETURN(ERROR_COMMAND_FAILED, tszCommand);
		}
		tempSSL = SSL_new(lpService->pSecureCtx);
		ReleaseSharedLock(&lpService->loLock);
		if (!tempSSL)
		{
			ERROR_RETURN(IO_SSL_FAIL2, tszCommand);
		}
	}

	if (!(CipherStack = SSL_get_ciphers(tempSSL)))
	{
		SSL_free(tempSSL);
		if (pCtx) SSL_CTX_free(pCtx);
		ERROR_RETURN(IO_SSL_FAIL2, tszCommand);
	}

	iCiphers = sk_SSL_CIPHER_num(CipherStack);
	for (i = 0; (i < iCiphers) && (Cipher = sk_SSL_CIPHER_value(CipherStack, i)); i++)
	{
		// Could access the CIPHER structure directoy, and replicate the logic in SSL_CIPHER_description()
		// to get properly formatted output, or just accept it's not aligned correctly, but it's likely to
		// get updated with new algorithms which we might not catch in the future, or perhaps the structure
		// changes...
		SSL_CIPHER_description(Cipher, szBuf, sizeof(szBuf));
		//cszName   = SSL_CIPHER_get_name(Cipher);
		//iBits     = SSL_CIPHER_get_bits(Cipher, NULL);
		//szVersion = SSL_CIPHER_get_version(Cipher);
		//FormatString(lpBuffer, _T("%s#%2d: %s (%d bits) [%s]\r\n"), tszMultilinePrefix, i+1, cszName, iBits, szVersion);
		FormatString(lpBuffer, _T("%s#%2d: %s\r\n"), tszMultilinePrefix, i + 1, szBuf);
	}

	SSL_free(tempSSL);
	if (pCtx) SSL_CTX_free(pCtx);
	return NULL;
}


BOOL Security_Init(BOOL bFirstInitialization)
{
	if (!bFirstInitialization) return TRUE;

	// Override the compiled-in MODULESDIR with a path relative to this executable.
	// The build-time prefix (C:\Dev\Libs\...) is baked into libcrypto-3.dll and will
	// not exist on the production server, causing OSSL_PROVIDER_load("legacy") to
	// fail regardless of where legacy.dll is placed.  Setting the search path here
	// to <exedir>\lib\ossl-modules ensures providers are found at runtime.
	{
		char   szModulesDir[MAX_PATH];
		DWORD  dwLen = GetModuleFileNameA(NULL, szModulesDir, MAX_PATH);
		if (dwLen > 0 && dwLen < MAX_PATH)
		{
			char *pSlash = strrchr(szModulesDir, '\\');
			if (pSlash)
			{
				size_t remaining = sizeof(szModulesDir) - (size_t)(pSlash + 1 - szModulesDir);
				strcpy_s(pSlash + 1, remaining, "lib\\ossl-modules");
				OSSL_PROVIDER_set_default_search_path(NULL, szModulesDir);
				Putlog(LOG_DEBUG, _T("OpenSSL: Provider search path set to '%hs'.\r\n"), szModulesDir);
			}
		}
	}

	// Always load the default provider: AES-GCM, SHA-2, ECDHE, RSA, TLS 1.2/1.3, etc.
	// The legacy provider (DHE-RSA / AES-CBC / MD5) is loaded per-service in
	// Secure_Create_Ctx when OpenSSL_LoadLegacyProvider = True in the service section.
	g_pDefaultProvider = OSSL_PROVIDER_load(NULL, "default");
	if (!g_pDefaultProvider)
	{
		Putlog(LOG_ERROR, _T("OpenSSL: Failed to load 'default' provider. TLS will not work.\r\n"));
		return FALSE;
	}
	Putlog(LOG_GENERAL, _T("OpenSSL: Loaded 'default' provider.\r\n"));

	return TRUE;
}



VOID Security_DeInit(VOID)
{
	// Do NOT call OSSL_PROVIDER_unload() here.
	//
	// In OpenSSL 3.x, OSSL_PROVIDER_load() automatically registers OPENSSL_cleanup()
	// as a CRT atexit() handler. That handler safely frees all provider state — cipher
	// dispatch tables, algorithm name strings, error tables, etc. — after all other
	// atexit handlers and after all DLL_PROCESS_DETACH calls have completed.
	//
	// Calling OSSL_PROVIDER_unload() during ioFTPD's explicit shutdown sequence races
	// with FTP worker threads that are still executing TLS I/O (SSL_read / SSL_write).
	// Those threads reference the "default" provider's string and algorithm tables.
	// Freeing the provider under them causes use-after-free crashes in OpenSSL's
	// internal strnlen calls on freed string pointers, manifesting as:
	//   Access Violation (0xC0000005) at 0x004AC26C reading from 0x000001BC
	//
	// CONF_modules_unload(1) is similarly unsafe here and is also handled by
	// OPENSSL_cleanup(); omit it for the same reason.
	//
	// FTP worker threads (Thread_DeInit, pass 2) are still alive when Security_DeInit
	// runs (pass 0), making explicit provider teardown inherently racy.  Let the OS
	// and OpenSSL's atexit handler manage the final cleanup after all threads exit.

	// Clear our references. The atexit handler owns the actual unload.
	g_pLegacyProvider  = NULL;
	g_pDefaultProvider = NULL;
}
