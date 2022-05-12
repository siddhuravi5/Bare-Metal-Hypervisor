
// UserLevelMFCAppDlg.cpp : implementation file
//


#include "pch.h"
#include "framework.h"
#include "UserLevelMFCApp.h"
#include "UserLevelMFCAppDlg.h"
#include "afxdialogex.h"
#include <winioctl.h>
#include <iostream>
#include <string.h>
#define CURL_STATICLIB
#include <curl/curl.h>
#include <chrono>
#include <thread>
#include <functional>



#ifdef _DEBUG
#define new DEBUG_NEW
#endif

//#pragma comment(lib, "libcurl_a.lib")
// CAboutDlg dialog used for App About

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CUserLevelMFCAppDlg dialog



CUserLevelMFCAppDlg::CUserLevelMFCAppDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_USERLEVELMFCAPP_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CUserLevelMFCAppDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CUserLevelMFCAppDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CUserLevelMFCAppDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CUserLevelMFCAppDlg::OnBnClickedButton2)
	ON_BN_CLICKED(IDC_BUTTON3, &CUserLevelMFCAppDlg::OnBnClickedButton3)
	ON_BN_CLICKED(IDC_BUTTON5, &CUserLevelMFCAppDlg::OnBnClickedButton5)
	ON_BN_CLICKED(IDC_BUTTON3, &CUserLevelMFCAppDlg::OnBnClickedButton3)
	ON_BN_CLICKED(IDC_BUTTON4, &CUserLevelMFCAppDlg::OnBnClickedButton4)
	ON_BN_CLICKED(IDC_BUTTON6, &CUserLevelMFCAppDlg::OnBnClickedButton6)
	ON_BN_CLICKED(IDC_BUTTON7, &CUserLevelMFCAppDlg::OnBnClickedButton7)
END_MESSAGE_MAP()


// CUserLevelMFCAppDlg message handlers

BOOL CUserLevelMFCAppDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
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

void CUserLevelMFCAppDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

void CUserLevelMFCAppDlg::OnPaint()
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
HCURSOR CUserLevelMFCAppDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


#define SIOCTL_TYPE 30000

//
// The IOCTL function codes from 0x800 to 0xFFF are for customer use.
//
#define IOCTL_METHOD_IN_DIRECT \
    CTL_CODE( SIOCTL_TYPE, 0x950, METHOD_IN_DIRECT, FILE_ANY_ACCESS  )

#define IOCTL_METHOD_OUT_DIRECT \
    CTL_CODE( SIOCTL_TYPE, 0x951, METHOD_OUT_DIRECT , FILE_ANY_ACCESS  )

#define IOCTL_METHOD_BUFFERED \
    CTL_CODE( SIOCTL_TYPE, 0x952, METHOD_BUFFERED, FILE_ANY_ACCESS  )

#define IOCTL_METHOD_NEITHER \
    CTL_CODE( SIOCTL_TYPE, 0x953, METHOD_NEITHER , FILE_ANY_ACCESS  )

HANDLE handle = NULL;

void CUserLevelMFCAppDlg::OnBnClickedButton1()
{
	// TODO: Add your control notification handler code here
	handle = CreateFile(L"\\\\.\\MyBMHDevice",
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ |
		FILE_SHARE_WRITE,
		NULL, /// lpSecurityAttirbutes
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL |
		FILE_FLAG_OVERLAPPED,
		NULL); /// lpTemplateFile 

	if (handle == INVALID_HANDLE_VALUE) {
		MessageBox(L"error, invalid handle", 0, 0);
		return;
	}
	MessageBox(L"Device file is successfully created", 0, 0);
}

void CUserLevelMFCAppDlg::OnBnClickedButton2()
{
	// TODO: Add your control notification handler code here
	if (handle != INVALID_HANDLE_VALUE) {
		CloseHandle(handle);
		MessageBox(L"Device handle successfully closed", 0, 0);
	}
}


void timer_start(std::function<void(void)> func, unsigned int interval)
{
	std::thread([func, interval]() {
		while (true)
		{
			func();
			std::this_thread::sleep_for(std::chrono::milliseconds(interval));
		}
		}).detach();
}

void CUserLevelMFCAppDlg::OnBnClickedButton3()
{
	// Method Buffered
	BOOL status = FALSE;
	DWORD bytesReturned = 0;
	WCHAR inBuffer[120] = { 0 };
	WCHAR outBuffer[120] = { 0 };
	PCHAR data = "Hello, this is a message from the User.";
	size_t datalen = strlen(data) + 1;
	RtlCopyMemory(inBuffer, data, datalen);
	status = DeviceIoControl(handle, IOCTL_METHOD_BUFFERED, inBuffer, sizeof(inBuffer), outBuffer, sizeof(outBuffer), &bytesReturned, (LPOVERLAPPED)NULL);
	if (!status) {
		MessageBox(L"Something went wrong :( ", 0, 0);
		return;
	}
	MessageBox(outBuffer, L"Message received from Device Driver : ", 0);
}

void CUserLevelMFCAppDlg::OnBnClickedButton4()
{
	// Method IN_DIRECT
	BOOL status = FALSE;
	DWORD bytesReturned = 0;
	WCHAR inBuffer[120] = { 0 };
	WCHAR outBuffer[120] = { 0 };
	PCHAR data = "Hello, this is a message from the User.";
	size_t datalen = strlen(data) + 1;
	RtlCopyMemory(inBuffer, data, datalen);
	status = DeviceIoControl(handle, IOCTL_METHOD_IN_DIRECT, inBuffer, sizeof(inBuffer), outBuffer, sizeof(outBuffer), &bytesReturned, (LPOVERLAPPED)NULL);
	if (!status) {
		MessageBox(L"Something went wrong :( ", 0, 0);
		return;
	}
	MessageBox(outBuffer, L"Message received from Device Driver : ", 0);
}


void CUserLevelMFCAppDlg::OnBnClickedButton5()
{
	// Method OUT_DIRECT
	BOOL status = FALSE;
	DWORD bytesReturned = 0;
	WCHAR inBuffer[120] = { 0 };
	WCHAR outBuffer[120] = { 0 };
	PCHAR data = "Hello, this is a message from the User.";
	size_t datalen = strlen(data) + 1;
	RtlCopyMemory(inBuffer, data, datalen);
	status = DeviceIoControl(handle, IOCTL_METHOD_OUT_DIRECT, inBuffer, sizeof(inBuffer), outBuffer, sizeof(outBuffer), &bytesReturned, (LPOVERLAPPED)NULL);
	if (!status) {
		MessageBox(L"Something went wrong :( ", 0, 0);
		return;
	}
	MessageBox(outBuffer, L"Message received from Device Driver : ", 0);
}



void CUserLevelMFCAppDlg::OnBnClickedButton6()
{
	// Method Neither
	BOOL status = FALSE;
	DWORD bytesReturned = 0;
	WCHAR inBuffer[120] = { 0 };
	WCHAR outBuffer[120] = { 0 };
	PCHAR data = "Hello, this is a message from the User.";
	size_t datalen = strlen(data) + 1;
	RtlCopyMemory(inBuffer, data, datalen);
	status = DeviceIoControl(handle, IOCTL_METHOD_NEITHER, inBuffer, sizeof(inBuffer), outBuffer, sizeof(outBuffer), &bytesReturned, (LPOVERLAPPED)NULL);
	if (!status) {
		MessageBox(L"Something went wrong :( ", 0, 0);
		return;
	}
	MessageBox(outBuffer, L"Message received from Device Driver : ", 0);
}


static std::string payloadText[11];

std::string dateTimeNow();
std::string generateMessageId();

void setPayloadText(const std::string& to,
	const std::string& from,
	const std::string& cc,
	const std::string& nameFrom,
	const std::string& subject,
	const std::string& body)
{
	payloadText[0] = "Date: " + dateTimeNow();
	payloadText[1] = "To: <" + to + ">\r\n";
	payloadText[2] = "From: <" + from + "> (" + nameFrom + ")\r\n";
	payloadText[3] = "Cc: <" + cc + "> (" + nameFrom + ")\r\n";
	payloadText[4] = "Message-ID: <" + generateMessageId() + "@" + from.substr(from.find('@') + 1) + ">\r\n";
	payloadText[5] = "Subject: " + subject + "\r\n";
	payloadText[6] = "\r\n";
	payloadText[7] = body + "\r\n";
	payloadText[8] = "\r\n";
	payloadText[9] = "\r\n"; // "It could be a lot of lines, could be MIME encoded, whatever.\r\n";
	payloadText[10] = "\r\n"; // "Check RFC5322.\r\n";
}

std::string dateTimeNow()
{
	static const char* DAY_NAMES[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
	static const char* MONTH_NAMES[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

	const int RFC1123_TIME_LEN = 29;
	time_t t;
	struct tm tm;

	std::string ret;
	ret.resize(RFC1123_TIME_LEN);

	time(&t);
	gmtime_s(&tm, &t);

	strftime(&ret[0], RFC1123_TIME_LEN + 1, "---, %d --- %Y %H:%M:%S GMT", &tm);
	memcpy(&ret[0], DAY_NAMES[tm.tm_wday], 3);
	memcpy(&ret[8], MONTH_NAMES[tm.tm_mon], 3);

	return ret;
}

std::string generateMessageId()
{
	const int MESSAGE_ID_LEN = 37;
	time_t t;
	struct tm tm;

	std::string ret;
	ret.resize(15);

	time(&t);
	gmtime_s(&tm, &t);

	strftime(const_cast<char*>(ret.c_str()),
		MESSAGE_ID_LEN,
		"%Y%m%d%H%M%S.",
		&tm);

	ret.reserve(MESSAGE_ID_LEN);

	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	while (ret.size() < MESSAGE_ID_LEN) {
		ret += alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	return ret;
}

struct upload_status { int lines_read; };

static size_t payload_source(void* ptr, size_t size, size_t nmemb, void* userp)
{
	std::string s = generateMessageId();

	static const char* pt[12] = {};

	for (int i = 0; i < 11; ++i) {
		pt[i] = payloadText[i].c_str();
	}

	pt[11] = NULL;

	struct upload_status* upload_ctx = (struct upload_status*)userp;
	const char* data;

	if ((size == 0) || (nmemb == 0) || ((size * nmemb) < 1)) {
		return 0;
	}

	data = pt[upload_ctx->lines_read];

	if (data) {
		size_t len = strlen(data);
		memcpy(ptr, data, len);
		upload_ctx->lines_read++;

		return len;
	}

	return 0;
}

CURLcode sendEmail(const std::string& to,
	const std::string& from,
	const std::string& cc,
	const std::string& nameFrom,
	const std::string& subject,
	const std::string& body,
	const std::string& url,
	const std::string& password)
{
	CURLcode ret = CURLE_OK;

	struct curl_slist* recipients = NULL;
	struct upload_status upload_ctx;

	upload_ctx.lines_read = 0;

	CURL* curl = curl_easy_init();

	setPayloadText(to, from, cc, nameFrom, subject, body);

	if (curl) {
		curl_easy_setopt(curl, CURLOPT_USERNAME, from.c_str());
		curl_easy_setopt(curl, CURLOPT_PASSWORD, password.c_str());
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

		curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
		//curl_easy_setopt(curl, CURLOPT_CAINFO, "/path/to/certificate.pem");

		curl_easy_setopt(curl, CURLOPT_MAIL_FROM, ("<" + from + ">").c_str());
		recipients = curl_slist_append(recipients, ("<" + to + ">").c_str());
		recipients = curl_slist_append(recipients, ("<" + cc + ">").c_str());

		curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
		curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_source);
		curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
		curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

		ret = curl_easy_perform(curl);

		if (ret != CURLE_OK) {
			MessageBox(NULL, L"Mail couldn't be sent", L"Alert", 0);
		}

		curl_slist_free_all(recipients);
		curl_easy_cleanup(curl);
	}
	else {
		MessageBox(NULL, L"Curl failed", L"Alert", 0);
	}

	return ret;
}
void sendEmailFn(std::string body) {
	
	sendEmail("siddhudeveloper@gmail.com",
		"siddhudeveloper@gmail.com",
		"siddhudeveloper@gmail.com",
		"Developer",
		"Info Mail",
		body,
		"smtp://smtp.gmail.com:25",
		"Sid@123S");
}
void sendEmailHelper() {

	BOOL status = FALSE;
	DWORD bytesReturned = 0;
	WCHAR inBuffer[1000] = { 0 };
	WCHAR outBuffer[1000] = { 0 };
	PCHAR data = "Hello, this is a message from the User.";
	size_t datalen = strlen(data) + 1;
	RtlCopyMemory(inBuffer, data, datalen);
	status = DeviceIoControl(handle, IOCTL_METHOD_OUT_DIRECT, inBuffer, sizeof(inBuffer), outBuffer, 1000, &bytesReturned, (LPOVERLAPPED)NULL);
	if (!status) {
		MessageBox(NULL,L"Message Not Received", L"Alert", 0);
		return;
	}
	//MessageBox(NULL,outBuffer, L"size:", 0);
	std::string msgBody = "";
	for (int i = 0; i < bytesReturned; i++) {
		msgBody = msgBody + (CHAR)outBuffer[i];
	}
	sendEmailFn(msgBody);

	
}

void CUserLevelMFCAppDlg::OnBnClickedButton7()
{
	//send email every 20 seconds
	timer_start(sendEmailHelper, 20000);

	while (true);

	
}

void apiFn() {
	//send email every 20 seconds
	timer_start(sendEmailHelper, 20000);

	while (true);
}

