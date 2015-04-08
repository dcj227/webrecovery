
// webdiscoverDlg.h : header file
//

#pragma once

class CWebPageDiscover;

// CwebdiscoverDlg dialog
class CwebdiscoverDlg : public CDialogEx
{
// Construction
public:
	CwebdiscoverDlg(CWnd* pParent = NULL);	// standard constructor
	virtual ~CwebdiscoverDlg();

// Dialog Data
	enum { IDD = IDD_WEBDISCOVER_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()

public:
	afx_msg void OnBnClickedButtonLoadFile();
	afx_msg void OnBnClickedButtonFilter();
	afx_msg void OnBnClickedButtonSession();
	afx_msg void OnBnClickedButtonRequest();
	afx_msg void OnBnClickedButtonWebsite();

private:
	CString file_name_;
	CString protocol_;
	CString feedback_;
	CString output_path_;
	CString request_path_;
	CString website_path_;

	CWebPageDiscover* web_page_recovery_;
};
