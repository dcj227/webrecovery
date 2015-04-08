
// webdiscoverDlg.cpp : implementation file
//

#include "stdafx.h"
#include <direct.h>
#include "webdiscover.h"
#include "webdiscoverDlg.h"
#include "afxdialogex.h"
#include "WebPageDiscover.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CAboutDlg dialog used for App About

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// Dialog Data
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CwebdiscoverDlg dialog

CwebdiscoverDlg::CwebdiscoverDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CwebdiscoverDlg::IDD, pParent)
	, file_name_(_T(""))
	, web_page_recovery_(NULL)
	, protocol_(_T(""))
	, feedback_(_T(""))
	, output_path_(_T(""))
	, request_path_(_T(""))
	, website_path_(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	web_page_recovery_ = new CWebPageDiscover;
	file_name_ = _T("..\\csdn.pcap");
	protocol_ = _T("TCP");
	output_path_ = _T("..\\sessions\\");
	request_path_ = _T("..\\requests\\");
	website_path_ = _T("..\\websites\\");
}

CwebdiscoverDlg::~CwebdiscoverDlg() {
	if (web_page_recovery_) {
		delete web_page_recovery_;
		web_page_recovery_ = NULL;
	}
}


void CwebdiscoverDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT_PCAP_FILE, file_name_);
	DDX_Text(pDX, IDC_EDIT_PROTOCOL, protocol_);
	DDX_Text(pDX, IDC_EDIT_FEEDBACD, feedback_);
	DDX_Text(pDX, IDC_EDIT_OUTPUT_PATH, output_path_);
	DDX_Text(pDX, IDC_EDIT_REQUEST, request_path_);
	DDX_Text(pDX, IDC_EDIT_WEBSITE, website_path_);
}

BEGIN_MESSAGE_MAP(CwebdiscoverDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_LOAD_FILE, &CwebdiscoverDlg::OnBnClickedButtonLoadFile)
	ON_BN_CLICKED(IDC_BUTTON_FILTER, &CwebdiscoverDlg::OnBnClickedButtonFilter)
	ON_BN_CLICKED(IDC_BUTTON_SESSION, &CwebdiscoverDlg::OnBnClickedButtonSession)
	ON_BN_CLICKED(IDC_BUTTON_REQUEST, &CwebdiscoverDlg::OnBnClickedButtonRequest)
	ON_BN_CLICKED(IDC_BUTTON_WEBSITE, &CwebdiscoverDlg::OnBnClickedButtonWebsite)
END_MESSAGE_MAP()


// CwebdiscoverDlg message handlers

BOOL CwebdiscoverDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here

	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CwebdiscoverDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CwebdiscoverDlg::OnPaint()
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
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CwebdiscoverDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CwebdiscoverDlg::OnBnClickedButtonLoadFile()
{
	// TODO: Add your control notification handler code here
	UpdateData();
	error_no err_t;
	err_t = web_page_recovery_->LoadPacpFile(CT2A(file_name_));
	if (err_t == SUCCESS) {
		feedback_ += _T("Load file success.\r\n");
	} else {
		feedback_ += _T("Load file failed.\r\n");
	}
	UpdateData(false);
}

void CwebdiscoverDlg::OnBnClickedButtonFilter()
{
	// TODO: Add your control notification handler code here
	error_no err_t;
	err_t = web_page_recovery_->FitlerWithProtocolPort();
	if (err_t == SUCCESS) {
		feedback_ += _T("Filter protocol success.\r\n");
	} else {
		feedback_ += _T("Filter protocol failed.\r\n");
	}
	UpdateData(false);
}


void CwebdiscoverDlg::OnBnClickedButtonSession()
{
	// TODO: Add your control notification handler code here
	error_no err_t;
	err_t = web_page_recovery_->SeperateBySession();
	if (err_t == SUCCESS) {
		feedback_ += _T("Seperate session success.\r\n");
	} else {
		feedback_ += _T("Seperate session failed.\r\n");
	}
	if(!PathFileExists(_T("..\\sessions\\"))) {
		_mkdir("..\\sessions\\");
	}
	err_t = web_page_recovery_->OutputSessionToPcap(CT2A(output_path_));
	if (err_t == SUCCESS) {
		feedback_ += _T("Output session success.\r\n");
	} else {
		feedback_ += _T("Output session failed.\r\n");
	}
	UpdateData(false);
}


void CwebdiscoverDlg::OnBnClickedButtonRequest()
{
	// TODO: Add your control notification handler code here
	error_no err_t;
	err_t = web_page_recovery_->SeperateByRequest();
	if (err_t == SUCCESS) {
		feedback_ += _T("Seperate request success.\r\n");
	} else {
		feedback_ += _T("Seperate request failed.\r\n");
	}
	if(!PathFileExists(_T("..\\requests\\"))) {
		_mkdir("..\\requests\\");
	}
	err_t = web_page_recovery_->OutputRequetToPcap(CT2A(request_path_));
	if (err_t == SUCCESS) {
		feedback_ += _T("Output request success.\r\n");
	} else {
		feedback_ += _T("Output request failed.\r\n");
	}
	UpdateData(false);
}


void CwebdiscoverDlg::OnBnClickedButtonWebsite()
{
	// TODO: Add your control notification handler code here
	if(!PathFileExists(_T("..\\websites\\"))) {
		_mkdir("..\\websites\\");
	}
	error_no err_t;
	err_t = web_page_recovery_->GenerateWebFile(CT2A(website_path_));
	if (err_t == SUCCESS) {
		feedback_ += _T("Generate website success.\r\n");
	} else {
		feedback_ += _T("Generate website failed.\r\n");
	}
	UpdateData(false);
}
