// IoKnock.cpp : Defines the class behaviors for the application.
//

#include "stdafx.h"
#include "IoKnock.h"
#include "IoKnockDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CIoKnockApp

BEGIN_MESSAGE_MAP(CIoKnockApp, CWinApp)
	ON_COMMAND(ID_HELP, &CWinApp::OnHelp)
END_MESSAGE_MAP()


// CIoKnockApp construction

CIoKnockApp::CIoKnockApp()
{
	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
}


// The one and only CIoKnockApp object

CIoKnockApp theApp;


// CIoKnockApp initialization

BOOL CIoKnockApp::InitInstance()
{
	// InitCommonControlsEx() is required on Windows XP if an application
	// manifest specifies use of ComCtl32.dll version 6 or later to enable
	// visual styles.  Otherwise, any window creation will fail.
	INITCOMMONCONTROLSEX InitCtrls;
	InitCtrls.dwSize = sizeof(InitCtrls);
	// Set this to include all the common control classes you want to use
	// in your application.
	InitCtrls.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&InitCtrls);

	CWinApp::InitInstance();

	if (!AfxSocketInit())
	{
		AfxMessageBox(IDP_SOCKETS_INIT_FAILED);
		return FALSE;
	}

	// Standard initialization
	// If you are not using these features and wish to reduce the size
	// of your final executable, you should remove from the following
	// the specific initialization routines you do not need
	// Change the registry key under which our settings are stored
	// TODO: You should modify this string to be something appropriate
	// such as the name of your company or organization
	// SetRegistryKey(_T("ioKnock"));

	CIoKnockDlg dlg;
	m_pMainWnd = &dlg;
	m_pDlg     = &dlg;

	INT_PTR nResponse = dlg.DoModal();
	if (nResponse == IDOK)
	{
		// TODO: Place code here to handle when the dialog is
		//  dismissed with OK
	}
	else if (nResponse == IDCANCEL)
	{
		// TODO: Place code here to handle when the dialog is
		//  dismissed with Cancel
	}

	// Since the dialog has been closed, return FALSE so that we exit the
	//  application, rather than start the application's message pump.
	return FALSE;
}

CString
CIoKnockApp::GetSystemErrorMsg(DWORD dwError)
{
	CString Error;
    LPTSTR tszMsg;

	if (::FormatMessage((FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM),
		                NULL,
						dwError,
						MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
						(LPTSTR) &tszMsg,
						0, NULL ))
	{
		LPTSTR p = _tcsrchr(tszMsg, _T('\r'));
		if (p)
		{
			*p = 0;
		}
		Error = tszMsg;
		::LocalFree(tszMsg);
	}
	else
	{
		Error.Format(_T("[unknown error - %08x (%d)]"), dwError, dwError);
	}
	return Error;
}


void
CIoKnockApp::ErrorBox(LPTSTR tszFunction) 
{ 
	CString Error;
	CString Display;
	DWORD  dwErr;

	dwErr = GetLastError(); 
	Error = GetSystemErrorMsg(dwErr);

	if (!tszFunction)
	{
		tszFunction = _T("[unknown function]");
	}

	Display.Format(_T("%s\r\nError: %s"), tszFunction, (LPCTSTR) Error);
	if (m_pDlg)
	{
		m_pDlg->MessageBox(Display, _T("Error"), MB_OK|MB_ICONERROR);
	}
	else
	{
		MessageBox(NULL, Display, _T("Error"), MB_OK|MB_ICONERROR);
	}
}
