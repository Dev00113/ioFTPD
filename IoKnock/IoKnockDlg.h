// IoKnockDlg.h : header file
//

#pragma once
#include "afxwin.h"
#include "Site.h"


// CIoKnockDlg dialog
class CIoKnockDlg : public CDialog
{
// Construction
public:
	CIoKnockDlg(CWnd* pParent = NULL);	// standard constructor

	void EnableKnock(DWORD dwNum, BOOL bEnable);
	void SetKnock(DWORD dwNum, BOOL bChecked, LPCTSTR tszString = NULL);

	void KnockDone();

	// Dialog Data
	enum { IDD = IDD_IOKNOCK_DIALOG };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support

// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()

private:
	CComboBox  m_Sites;
	CString    m_Host;
	CString    m_Group;

	DWORD      m_dwPort1;
	DWORD      m_dwPort2;
	DWORD      m_dwPort3;
	DWORD      m_dwPort4;
	DWORD      m_dwPort5;
	CEdit     *m_pPorts[6];

	CButton    m_Check1;
	CButton    m_Check2;
	CButton    m_Check3;
	CButton    m_Check4;
	CButton    m_Check5;
	CButton   *m_pChecks[6];

	CEdit     *m_pHostField;
	CStatic   *m_pStatusText;
	CButton   *m_pSaveButton;
	CButton   *m_pKnockButton;
	CButton   *m_pAddButton;
	CButton   *m_pDelButton;

	afx_msg void OnBnClickedButtonAdd();
	afx_msg void OnBnClickedButtonDelete();
	afx_msg void OnBnClickedButtonSave();
	afx_msg void OnBnClickedButtonKnock();
	afx_msg void OnCbnSelchangeSiteCombo();
	afx_msg void OnClose();

	BOOL VerifyData();
	void EnableDialog(BOOL bState);

	bool    m_bModified;
	Site   *m_pSite;
	int     m_iSite;
	bool    m_bVerify;
	BOOL    m_bEnabled;
	DWORD   m_dwKnocking;
};
