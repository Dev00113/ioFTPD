// IoKnockDlg.h : header file
//

#pragma once
#include "afxwin.h"


class Site : public CAsyncSocket
{
public:
	Site(LPCTSTR tszName = 0, LPCTSTR tszHost = 0);
	~Site();

	enum { MAX_KNOCKS = 5 };

	typedef enum {
		SITE_ERROR,
		SITE_UNTRIED,
		SITE_CONNECTING,
		SITE_KNOCKED,
		SITE_TIMEDOUT,
		SITE_ABORTED
	} SITE_STATUS;

	LPCTSTR GetName()
	{
		return m_Name;
	}

	VOID SetName(LPCTSTR tszHost)
	{
		m_Host = tszHost;
	}

	LPCTSTR GetHost()
	{
		return m_Host;
	}

	VOID SetHost(LPCTSTR tszHost)
	{
		m_Host = tszHost;
	}

	DWORD GetMaxKnocks()
	{
		return MAX_KNOCKS;
	}

	DWORD GetKnockCount()
	{
		return m_dwKnockCount;
	}

	DWORD GetKnock(DWORD dwKnockNum)
	{
		if (dwKnockNum >= 1 && dwKnockNum <= MAX_KNOCKS )
		{
			return m_pdwKnocks[dwKnockNum-1];
		}
		return 0;
	}

	BOOL AddKnock(DWORD dwPort)
	{
		return SetKnock(m_dwKnockCount+1, dwPort);
	}

	BOOL SetKnock(DWORD dwKnockNum, DWORD dwPort)
	{
		if (dwKnockNum >= 1 && dwKnockNum <= MAX_KNOCKS)
		{
			if (dwPort >= 0 && dwPort <= 65535)
			{
				m_pdwKnocks[dwKnockNum-1] = dwPort;
				if (dwKnockNum > m_dwKnockCount)
				{
					m_dwKnockCount = dwKnockNum;
				}
				return TRUE;
			}
		}
		return FALSE;
	}

	BOOL DoKnock();
	BOOL CancelKnock();

	SITE_STATUS GetStatus(PDWORD pdwKnockNum = 0)
	{
		if (!pdwKnockNum)
		{
			return m_Status;
		}

		*pdwKnockNum = m_dwCurrentKnock;
		return m_Status;
	}

private:
	CString        m_Name;
	CString        m_Host;

	DWORD          m_pdwKnocks[MAX_KNOCKS];
	DWORD          m_dwKnockCount;
	DWORD          m_dwCurrentKnock;

	SITE_STATUS    m_Status;
	DWORD          m_dwTime;
	BOOL           m_bTimerActive;

	BOOL           m_bCloseNeeded;

	void OnConnect(int nErrorCode);

	void NextKnock();

	void TimerEvent(DWORD dwTime);

	void Failed(SITE_STATUS status);

	static void CALLBACK TimerCB(HWND hWnd, UINT uMsg, UINT uTimerID, DWORD dwTime);
	static Site *m_Knocking;
};
