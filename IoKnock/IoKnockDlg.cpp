// IoKnockDlg.cpp : implementation file
//

#include "stdafx.h"
#include "IoKnock.h"
#include "IoKnockDlg.h"
#include "Site.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CIoKnockDlg dialog




CIoKnockDlg::CIoKnockDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CIoKnockDlg::IDD, pParent)
	, m_dwPort1(0)
	, m_dwPort2(0)
	, m_dwPort3(0)
	, m_dwPort4(0)
	, m_dwPort5(0)
	, m_Host(_T(""))
	, m_Group(_T("Site: "))
	, m_bModified(FALSE)
	, m_pSite(0)
	, m_iSite(-1)
	, m_bVerify(true)
	, m_bEnabled(true)
	, m_dwKnocking(0)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDI_ICON1);
}

void CIoKnockDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_PORT_1, m_dwPort1);
	if (m_bVerify) DDV_MinMaxUInt(pDX, m_dwPort1, 0, 65535);
	DDX_Text(pDX, IDC_PORT_2, m_dwPort2);
	if (m_bVerify) DDV_MinMaxUInt(pDX, m_dwPort2, 0, 65535);
	DDX_Text(pDX, IDC_PORT_3, m_dwPort3);
	if (m_bVerify) DDV_MinMaxUInt(pDX, m_dwPort3, 0, 65535);
	DDX_Text(pDX, IDC_PORT_4, m_dwPort4);
	if (m_bVerify) DDV_MinMaxUInt(pDX, m_dwPort4, 0, 65535);
	DDX_Text(pDX, IDC_PORT_5, m_dwPort5);
	if (m_bVerify) DDV_MinMaxUInt(pDX, m_dwPort5, 0, 65535);
	DDX_Control(pDX, IDC_CHECK1, m_Check1);
	DDX_Control(pDX, IDC_CHECK2, m_Check2);
	DDX_Control(pDX, IDC_CHECK3, m_Check3);
	DDX_Control(pDX, IDC_CHECK4, m_Check4);
	DDX_Control(pDX, IDC_CHECK5, m_Check5);
	DDX_Text(pDX, IDC_HOST, m_Host);
	if (m_bVerify) DDV_MaxChars(pDX, m_Host, 128);
	DDX_Control(pDX, IDC_SITE_COMBO, m_Sites);
	DDX_Text(pDX, IDC_GROUP, m_Group);
	if (m_bVerify) DDV_MaxChars(pDX, m_Group, 60);
}

BEGIN_MESSAGE_MAP(CIoKnockDlg, CDialog)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDC_BUTTON_ADD, &CIoKnockDlg::OnBnClickedButtonAdd)
	ON_BN_CLICKED(IDC_BUTTON_DELETE, &CIoKnockDlg::OnBnClickedButtonDelete)
	ON_BN_CLICKED(IDC_BUTTON_SAVE, &CIoKnockDlg::OnBnClickedButtonSave)
	ON_BN_CLICKED(IDC_BUTTON_KNOCK, &CIoKnockDlg::OnBnClickedButtonKnock)
	ON_CBN_SELCHANGE(IDC_SITE_COMBO, &CIoKnockDlg::OnCbnSelchangeSiteCombo)
	ON_WM_CLOSE()
END_MESSAGE_MAP()


// CIoKnockDlg message handlers

BOOL CIoKnockDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	m_pStatusText  = (CStatic *) GetDlgItem(IDC_STATUS);

	m_pSaveButton  = (CButton *) GetDlgItem(IDC_BUTTON_SAVE);
	m_pKnockButton = (CButton *) GetDlgItem(IDC_BUTTON_KNOCK);
	m_pAddButton   = (CButton *) GetDlgItem(IDC_BUTTON_ADD);
	m_pDelButton   = (CButton *) GetDlgItem(IDC_BUTTON_DELETE);

	m_pHostField   = (CEdit *)  GetDlgItem(IDC_HOST);

	m_pChecks[1] = &m_Check1;
	m_pChecks[2] = &m_Check2;
	m_pChecks[3] = &m_Check3;
	m_pChecks[4] = &m_Check4;
	m_pChecks[5] = &m_Check5;

	m_pPorts[1] = (CEdit *) GetDlgItem(IDC_PORT_1);
	m_pPorts[2] = (CEdit *) GetDlgItem(IDC_PORT_2);
	m_pPorts[3] = (CEdit *) GetDlgItem(IDC_PORT_3);
	m_pPorts[4] = (CEdit *) GetDlgItem(IDC_PORT_4);
	m_pPorts[5] = (CEdit *) GetDlgItem(IDC_PORT_5);

	CStdioFile      File;
	CFileException  ex;

	if (File.Open(SAVE_FILENAME, CFile::modeRead | CFile::shareDenyWrite, &ex))
	{
		CString  Line;
		CString  Name;
		CString  Host;
		CString  Knock;
		Site    *pSite;
		DWORD    dwPort;
		int      iPos;

		while(File.ReadString(Line))
		{
			iPos = 0;

			Name = Line.Tokenize(_T(" \t\n"), iPos);
			if (iPos == -1)
			{
				continue;
			}


			Host = Line.Tokenize(_T(" \t\n"), iPos);
			if (iPos == -1)
			{
				continue;
			}

		    pSite = new Site(Name, Host);

			for (int i=0 ; i<Site::MAX_KNOCKS ; i++)
			{
				Knock = Line.Tokenize(_T(" \t\n"), iPos);
				if (iPos == -1)
				{
					break;
				}
				if (_stscanf_s(Knock, _T("%d"), &dwPort) != 1)
				{
					break;
				}
				pSite->AddKnock(dwPort);
			}

			iPos = m_Sites.AddString(Name);
			if (iPos == CB_ERR || iPos == CB_ERRSPACE)
			{
				break;
			}
			m_Sites.SetItemDataPtr(iPos, pSite);
		}

		File.Close();

		iPos = m_Sites.GetCount();

		if (iPos != CB_ERR && iPos > 0)
		{
			m_Sites.SetCurSel(0);
			OnCbnSelchangeSiteCombo();
		}
	}

	if (theApp.m_lpCmdLine && *theApp.m_lpCmdLine)
	{
		CString Line(theApp.m_lpCmdLine);
		CString Name = Line.SpanExcluding(_T("\r\n ,\t"));

		if (!Name.IsEmpty())
		{
			int iPos = m_Sites.FindStringExact(-1, Name);
			if (iPos != CB_ERR)
			{
				m_Sites.SetCurSel(iPos);
				OnBnClickedButtonKnock();
			}
		}
	}

	return TRUE;  // return TRUE  unless you set the focus to a control
}


// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CIoKnockDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CIoKnockDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CIoKnockDlg::OnBnClickedButtonAdd()
{
	CString add;

	m_Sites.GetWindowText(add);
	if (add.IsEmpty())
	{
		return;
	}
	if (m_Sites.FindStringExact(-1, add) != CB_ERR)
	{
		return;
	}

	Site *pSite = new Site(add, m_Host);
	pSite->SetKnock(1, m_dwPort1);
	pSite->SetKnock(2, m_dwPort2);
	pSite->SetKnock(3, m_dwPort3);
	pSite->SetKnock(4, m_dwPort4);
	pSite->SetKnock(5, m_dwPort5);

	int iPos = m_Sites.AddString(add);
	if (iPos == CB_ERR || iPos == CB_ERRSPACE)
	{
		delete pSite;
		return;
	}
	m_Sites.SetItemDataPtr(iPos, pSite);
	m_bModified = TRUE;
}


void CIoKnockDlg::OnBnClickedButtonDelete()
{
	CString del;

	m_Sites.GetWindowText(del);
	if (del.IsEmpty())
	{
		return;
	}

	int iMatch = m_Sites.FindStringExact(-1, del);
	
	if (iMatch == CB_ERR)
	{
		return;
	}

	Site *pSite = (Site *) m_Sites.GetItemDataPtr(iMatch);

	if (pSite != 0 && pSite != (Site *) -1)
	{
		delete pSite;
	}

	m_Sites.DeleteString(iMatch);
	m_bModified = TRUE;
	m_pSite = 0;
	OnCbnSelchangeSiteCombo();
}


void CIoKnockDlg::OnBnClickedButtonSave()
{
	CStdioFile      File;
	CFileException  ex;

	OnCbnSelchangeSiteCombo();
	if (!m_bModified)
	{
		return;
	}

	int iMax = m_Sites.GetCount();

	if (iMax == CB_ERR)
	{
		return;
	}

	if (!File.Open(SAVE_FILENAME, CFile::modeCreate | CFile::modeWrite | CFile::shareExclusive, &ex))
	{
		return;
	}

	Site *pSite;
	CString line;
	LPCTSTR tcszHost;

	for(int i = 0; i < iMax ; i++)
	{
		pSite = (Site *) m_Sites.GetItemDataPtr(i);

		if (pSite != 0 && pSite != (Site *) -1)
		{
			if (!(tcszHost = pSite->GetHost()))
			{
				tcszHost = _T("localhost");
			}
			line.Format(_T("%s %s %d %d %d %d %d\n"),
				pSite->GetName(),
				tcszHost,
				pSite->GetKnock(1),
				pSite->GetKnock(2),
				pSite->GetKnock(3),
				pSite->GetKnock(4),
				pSite->GetKnock(5));
			File.WriteString(line);
		}
	}

	File.Close();
	m_bModified = FALSE;
}


void CIoKnockDlg::OnBnClickedButtonKnock()
{
	if (m_dwKnocking == 1)
	{
		// it's really an abort
		m_pSite->CancelKnock();
		return;
	}
	if (!VerifyData())
	{
		return;
	}

	if (!m_pSite)
	{
		return;
	}
	m_dwKnocking = 1;

	EnableDialog(false);

	m_pStatusText->SetWindowText(_T("Status: Knocking"));
	m_pStatusText->EnableWindow(true);

	m_pSite->DoKnock();
}


void CIoKnockDlg::OnCbnSelchangeSiteCombo()
{
	if (m_dwKnocking == 2)
	{
		m_pStatusText->SetWindowText(_T("Status: "));
		m_pStatusText->EnableWindow(false);

		for (int i=1 ; i<= 5 ; i++)
		{
			m_pChecks[i]->SetWindowText(_T(""));
			m_pChecks[i]->SetCheck(BST_UNCHECKED);
		}
		m_dwKnocking = 0;
	}
	VerifyData();
}


void
CIoKnockDlg::EnableDialog(BOOL bState)
{
	bState = (bState ? false : true);

	m_pHostField->SetReadOnly(bState);
	m_pPorts[1]->SetReadOnly(bState);
	m_pPorts[2]->SetReadOnly(bState);
	m_pPorts[3]->SetReadOnly(bState);
	m_pPorts[4]->SetReadOnly(bState);
	m_pPorts[5]->SetReadOnly(bState);

	bState = (bState ? false : true);

	m_pSaveButton->EnableWindow(bState);
	m_pAddButton->EnableWindow(bState);
	m_pDelButton->EnableWindow(bState);
	m_Sites.EnableWindow(bState);

	if (bState)
	{
		m_pKnockButton->SetWindowText(_T("Knock"));
	}
	else
	{
		m_pKnockButton->SetWindowText(_T("Abort"));
	}

	m_bEnabled = bState;
}


BOOL
CIoKnockDlg::VerifyData()
{
	if (m_pSite)
	{
		if (!UpdateData(TRUE))
		{
			m_Sites.SetCurSel(m_iSite);
			return false;
		}
		if (_tcscmp(m_Host, m_pSite->GetHost()) ||
			m_dwPort1 != m_pSite->GetKnock(1) ||
			m_dwPort2 != m_pSite->GetKnock(2) ||
			m_dwPort3 != m_pSite->GetKnock(3) ||
			m_dwPort4 != m_pSite->GetKnock(4) ||
			m_dwPort5 != m_pSite->GetKnock(5))
		{
			m_bModified = TRUE;
			m_pSite->SetHost(m_Host);
			m_pSite->SetKnock(1, m_dwPort1);
			m_pSite->SetKnock(2, m_dwPort2);
			m_pSite->SetKnock(3, m_dwPort3);
			m_pSite->SetKnock(4, m_dwPort4);
			m_pSite->SetKnock(5, m_dwPort5);
		}
	}

	int iSel = m_Sites.GetCurSel();

	if (iSel == CB_ERR)
	{
		m_Host  = _T("");
		m_Group = _T("Site: ");
		m_dwPort1 = 0;
		m_dwPort2 = 0;
		m_dwPort3 = 0;
		m_dwPort4 = 0;
		m_dwPort5 = 0;
		UpdateData(FALSE);
		m_pSite = 0;
		m_iSite = -1;
		m_Sites.SetCurSel(m_iSite);
		return false;
	}

	m_iSite = iSel;
	m_pSite = (Site *) m_Sites.GetItemDataPtr(iSel);

	if (m_pSite == 0 || m_pSite == (Site *) -1)
	{
		m_pSite = 0;
		return false;
	}

	m_Host = m_pSite->GetHost();

	m_Group = CString(_T("Site: ")) + m_pSite->GetName();

	m_dwPort1 = m_pSite->GetKnock(1);
	m_dwPort2 = m_pSite->GetKnock(2);
	m_dwPort3 = m_pSite->GetKnock(3);
	m_dwPort4 = m_pSite->GetKnock(4);
	m_dwPort5 = m_pSite->GetKnock(5);

	UpdateData(FALSE);
	return true;
}



void CIoKnockDlg::OnClose()
{
	m_bVerify = false;
	VerifyData();
	m_bVerify = true;
	if (m_bModified)
	{
		int iResult;
		iResult = MessageBox(_T("Save Changes?"),
			_T("Exit Confirmation"),
			(MB_YESNOCANCEL | MB_ICONEXCLAMATION));
		switch(iResult)
		{
		case IDYES:
			OnBnClickedButtonSave();
			break;
		case IDCANCEL:
			return;
		default: // IDNO
			break;
		}
	}

	CDialog::OnClose();
}


void
CIoKnockDlg::EnableKnock(DWORD dwNum, BOOL bEnable)
{
	if (dwNum > 0 && dwNum <= 5)
	{
		m_pChecks[dwNum]->EnableWindow(bEnable);
	}
}


void 
CIoKnockDlg::SetKnock(DWORD dwNum, BOOL bChecked, LPCTSTR tszString)
{
	if (dwNum > 0 && dwNum <= 5)
	{
		if (bChecked)
		{
			m_pChecks[dwNum]->SetCheck(BST_CHECKED);
		}
		else
		{
			m_pChecks[dwNum]->SetCheck(BST_UNCHECKED);
		}
		if (!tszString)
		{
			tszString = _T("");
		}
		m_pChecks[dwNum]->SetWindowText(tszString);
	}
}


void
CIoKnockDlg::KnockDone()
{
	Site::SITE_STATUS Status;

	Status = m_pSite->GetStatus();

	switch (Status)
	{
	case Site::SITE_KNOCKED:
		m_pStatusText->SetWindowText(_T("Status: KNOCKED!"));
		break;
	case Site::SITE_ABORTED:
		m_pStatusText->SetWindowText(_T("Status: Aborted"));
		break;
	default:
		m_pStatusText->SetWindowText(_T("Status: Failed"));
	}

	m_dwKnocking = 2;
	EnableDialog(true);
}
