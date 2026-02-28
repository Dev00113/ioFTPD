// IoKnock.h : main header file for the PROJECT_NAME application
//

#pragma once

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols

#define SAVE_FILENAME _T("ioKnock.ini")

// CIoKnockApp:
// See IoKnock.cpp for the implementation of this class
//
class CIoKnockDlg; 

class CIoKnockApp : public CWinApp
{
public:
	CIoKnockApp();

// Overrides
public:
	virtual BOOL InitInstance();

	CIoKnockDlg *GetDialog()
	{
		return m_pDlg;
	}

	CString GetSystemErrorMsg(DWORD dwError);

	void ErrorBox(LPTSTR tszFunction);

	// Implementation
	DECLARE_MESSAGE_MAP()

private:
	CIoKnockDlg *m_pDlg;
};

extern CIoKnockApp theApp;