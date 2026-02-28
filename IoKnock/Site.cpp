#include "stdafx.h"
#include "IoKnock.h"
#include "IoKnockDlg.h"
#include "Site.h"

#define ARRAY_SIZE(X)		 (sizeof(X)/sizeof(*X))

Site * Site::m_Knocking = 0;


Site::Site(LPCTSTR tszName, LPCTSTR tszHost)
    : m_Name(tszName)
	, m_Host(tszHost)
	, m_dwKnockCount(0)
	, m_dwCurrentKnock(0)
	, m_Status(SITE_UNTRIED)
	, m_bTimerActive(false)
	, m_bCloseNeeded(false)
{
	ZeroMemory(m_pdwKnocks, sizeof(m_pdwKnocks));
}


Site::~Site()
{
	// m_pASocket->Close();
}


void CALLBACK Site::TimerCB(HWND hWnd, UINT uMsg, UINT uTimerID, DWORD dwTime)
{
	if (!m_Knocking)
	{
		return;
	}

	m_Knocking->TimerEvent(dwTime);
}


BOOL
Site::DoKnock()
{
	CIoKnockDlg *pDlg = theApp.GetDialog();

	// m_Host.IsEmpty();
	// TODO: verify stuff here

	if (m_Status == SITE_CONNECTING)
	{
		return false;
	}

	for(int i=0 ; i<MAX_KNOCKS ; i++)
	{
		if (m_pdwKnocks[i] != 0)
		{
			pDlg->EnableKnock(i+1, true);
		}
		else
		{
			pDlg->EnableKnock(i+1, false);
		}

		pDlg->SetKnock(i+1, false, _T(""));
	}

	m_dwCurrentKnock = 0;
	m_Status = SITE_CONNECTING;
	NextKnock();
	return true;
}


BOOL
Site::CancelKnock()
{
	CIoKnockDlg *pDlg = theApp.GetDialog();

	if (m_Status != SITE_KNOCKED)
	{
		pDlg->SetKnock(m_dwCurrentKnock+1, false, _T("Aborted"));
		Failed(SITE_ABORTED);
	}
	pDlg->KnockDone();
	return TRUE;
}


void Site::NextKnock()
{
	CIoKnockDlg *pDlg = theApp.GetDialog();

	if (m_Status != SITE_CONNECTING)
	{
		return;
	}

	DWORD dwPort;

	for( ; m_dwCurrentKnock < MAX_KNOCKS ; m_dwCurrentKnock++ )
	{
		dwPort = m_pdwKnocks[m_dwCurrentKnock];
		if (dwPort > 0 && dwPort < 65535)
		{
			break;
		}
	}
	if (m_dwCurrentKnock >= MAX_KNOCKS)
	{
		m_Status = SITE_KNOCKED;
		if (m_bTimerActive)
		{
			m_bTimerActive = false;
			pDlg->KillTimer(1);
		}
		pDlg->KnockDone();
		return;
	}

	Create(0, SOCK_STREAM, FD_CONNECT | FD_CLOSE, 0);
	if (!Connect(m_Host, dwPort))
	{
		DWORD dwError;

		dwError = GetLastError();

		if (dwError == WSAEINVAL)
		{
			Close();
			Failed(SITE_ERROR);
			pDlg->MessageBox(_T("Host/IP is invalid"), _T("Error"), 0);
			pDlg->KnockDone();
			return;
		}

		if (dwError != WSAEWOULDBLOCK)
		{
			Close();
			Failed(SITE_ERROR);
			theApp.ErrorBox(_T("Socket->Connect"));
			pDlg->KnockDone();
			return;
		}
	}

	m_bCloseNeeded = TRUE;

	pDlg->SetKnock(m_dwCurrentKnock+1, false, _T("Connecting..."));

	if (!m_bTimerActive)
	{
		m_bTimerActive = true;
		pDlg->SetTimer(1, 1000, TimerCB);
	}
}


void Site::Failed(SITE_STATUS status)
{
	CIoKnockDlg *pDlg = theApp.GetDialog();

	if (m_bCloseNeeded)
	{
		m_bCloseNeeded = false;
		Close();
	}

	if (m_bTimerActive)
	{
		pDlg->KillTimer(1);
		m_bTimerActive = false;
	}

	for(int i=1 ; i<=MAX_KNOCKS ; i++)
	{
		pDlg->EnableKnock(i, false);
	}

	m_Status = status;
}



void Site::TimerEvent(DWORD dwTime)
{
	CIoKnockDlg *pDlg = theApp.GetDialog();

	if (m_dwTime > dwTime)
	{
		m_dwTime = -1 - m_dwTime;
	}

	if (m_dwTime + 10000 < dwTime)
	{
		return;
	}

	pDlg->SetKnock(m_dwCurrentKnock+1, true, _T("Timed out"));

	Failed(SITE_TIMEDOUT);
	pDlg->KnockDone();
}



void Site::OnConnect(int iErrorCode)
{
	CIoKnockDlg *pDlg = theApp.GetDialog();

	if (!iErrorCode)
	{
		Close();
		m_bCloseNeeded = false;

		pDlg->SetKnock(m_dwCurrentKnock+1, true, _T("Knocked"));
		m_dwCurrentKnock++;
		NextKnock();
		return;
	}

	CString err;
	switch(iErrorCode)
	{
	case WSAECONNREFUSED:
		err.Format(_T("Error: Rejected"));
		break;
	case WSAENETUNREACH:
		err.Format(_T("Error: Unreachable"));
		break;
	case WSAETIMEDOUT:
		err.Format(_T("Error: Timeout"));
		break;
	default:
		err.Format(_T("Error: #%d"), iErrorCode);
	}
	pDlg->SetKnock(m_dwCurrentKnock+1, false, err);

	Failed(SITE_TIMEDOUT);
	pDlg->KnockDone();
}
