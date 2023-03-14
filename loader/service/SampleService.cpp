/****************************** Module Header ******************************\
* Module Name:  SampleService.cpp
* Project:      sample-service
* Copyright (c) Microsoft Corporation.
* Copyright (c) Tromgy (tromgy@yahoo.com)
*
* Provides a sample service class that derives from the service base class -
* CServiceBase. The sample service logs the service start and stop
* information to the Application event log, and shows how to run the main
* function of the service in a thread pool worker thread.
*
* This source is subject to the Microsoft Public License.
* See http://www.microsoft.com/en-us/openness/resources/licenses.aspx#MPL.
* All other rights reserved.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
* EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
\***************************************************************************/


#include "stdafx.h"
#include "SampleService.h"
#include "event_ids.h"
#include <iostream>
#include <windows.h>
#include <Lmcons.h>
#include <windows.h>
#include <tchar.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <string>
#include <fstream>
#include <vector>
#include <AtlConv.h>
#include <strsafe.h>
#include "Wtsapi32.h"
#include <sstream>
#include "resource.h"
#include "resource1.h"
#include <UserEnv.h>
#include <Iphlpapi.h>
#include <Tlhelp32.h>
#include <Psapi.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "Wtsapi32.lib")

#define fs std::filesystem

CSampleService::CSampleService(PCWSTR pszServiceName,
                               BOOL fCanStop,
                               BOOL fCanShutdown,
                               BOOL fCanPauseContinue) :
    CServiceBase(pszServiceName, fCanStop, fCanShutdown, fCanPauseContinue, MSG_SVC_FAILURE, CATEGORY_SERVICE)
{
    m_bIsStopping = FALSE;

    m_hHasStoppedEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    if (m_hHasStoppedEvent == NULL)
    {
        throw GetLastError();
    }
}

void CSampleService::OnStart(DWORD /* useleses */, PWSTR* /* useless */)
{
    const wchar_t* wsConfigFullPath = SERVICE_CONFIG_FILE;
    bool bRunAsService = true;

    // Log a service start message to the Application log.
    WriteLogEntry(L"Sample Service is starting...", EVENTLOG_INFORMATION_TYPE, MSG_STARTUP, CATEGORY_SERVICE);

    if (m_argc > 1)
    {
        bRunAsService = (_wcsicmp(SERVICE_CMD, m_argv[1]) == 0);

        // Check if the config file was specified on the service command line
        if (m_argc > 2) // the argument at 1 should be "run mode", so we start at 2
        {
            if (_wcsicmp(L"-config", m_argv[2]) == 0)
            {
                if (m_argc > 3)
                {
                    wsConfigFullPath = m_argv[3];
                }
                else
                {
                    throw exception("no configuration file name");
                }
            }
        }
    }
    else
    {
        WriteLogEntry(L"Sample Service:\nNo run mode specified.", EVENTLOG_ERROR_TYPE, MSG_STARTUP, CATEGORY_SERVICE);
        throw exception("no run mode specified");
    }

    try
    {
        // Here we would load configuration file
        // but instead we're just writing to event log the configuration file name
        wstring infoMsg = L"Sample Service\n The service is pretending to read configuration from ";
        infoMsg += wsConfigFullPath;
        WriteLogEntry(infoMsg.c_str(), EVENTLOG_INFORMATION_TYPE, MSG_STARTUP, CATEGORY_SERVICE);
    }
    catch (exception const& e)
    {
        WCHAR wszMsg[MAX_PATH];

        _snwprintf_s(wszMsg, _countof(wszMsg), _TRUNCATE, L"Sample Service\nError reading configuration %S", e.what());

        WriteLogEntry(wszMsg, EVENTLOG_ERROR_TYPE, MSG_STARTUP, CATEGORY_SERVICE);
    }

    if (bRunAsService)
    {
        WriteLogEntry(L"Sample Service will run as a service.", EVENTLOG_INFORMATION_TYPE, MSG_STARTUP, CATEGORY_SERVICE);

        // Add the main service function for execution in a worker thread.
        if (!CreateThread(NULL, 0, ServiceRunner, this, 0, NULL))
        {
            WriteLogEntry(L"Sample Service couldn't create worker thread.", EVENTLOG_ERROR_TYPE, MSG_STARTUP, CATEGORY_SERVICE);
        }
    }
    else
    {
        wprintf(L"Sample Service is running as a regular process.\n");

        CSampleService::ServiceRunner(this);
    }
}

CSampleService::~CSampleService()
{
}

void CSampleService::Run()
{
    OnStart(0, NULL);
}
BOOL EnableDebugPrivilege()
{
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
    {
        return FALSE;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL))
    {
        return FALSE;
    }

    if (!CloseHandle(hToken))
    {
        return FALSE;
    }

    return TRUE;
}
BOOL ReleaseLibrary(UINT uResourceId, const CHAR* szResourceType, const CHAR* szFileName)
{
    HRSRC hRsrc = FindResourceA(NULL, MAKEINTRESOURCEA(uResourceId), szResourceType);
    if (hRsrc == NULL)
    {
        return FALSE;
    }
    DWORD dwSize = SizeofResource(NULL, hRsrc);
    if (dwSize <= 0)
    {
        return FALSE;
    }
    HGLOBAL hGlobal = LoadResource(NULL, hRsrc);
    if (hGlobal == NULL)
    {
        return FALSE;
    }
    LPVOID lpRes = LockResource(hGlobal);
    if (lpRes == NULL)
    {
        return FALSE;
    }
    HANDLE hFile = CreateFileA(szFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == NULL)
    {
        return FALSE;
    }
    DWORD dwWriten = 0;
    BOOL bRes = WriteFile(hFile, lpRes, dwSize, &dwWriten, NULL);
    if (bRes == FALSE || dwWriten <= 0)
    {
        return FALSE;
    }
    CloseHandle(hFile);
    return TRUE;
}
void ReleaseFileToSysDir(UINT uResourceId, const CHAR* szResourceType, const CHAR* szFileName)
{
    CHAR szDLLFile[MAX_PATH] = { 0 };

    GetSystemDirectoryA(szDLLFile, MAX_PATH);

    StringCbPrintfA(szDLLFile, sizeof(szDLLFile), "%s\\%s", szDLLFile, szFileName);
    //fs::path path = fs::path(szDLLFile) / szFileName;

    ReleaseLibrary(uResourceId, szResourceType, szDLLFile);
}
bool CheckUserLogined()
{
    bool bRet = false;

    PWTS_SESSION_INFO pSessions = NULL;
    DWORD dwCount = 0;
    DWORD dwError;
    if (!WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessions, &dwCount))
    {
        dwError = GetLastError();
    
    }
    else if (dwCount == 0)
    {

    }
    else
    {
        for (DWORD i = 0; i < dwCount; ++i)
        {
            if (pSessions[i].State == WTSActive) // has a logged in user
            {
                bRet = true;
                break;
            }
        }
    }
    if (pSessions)
        WTSFreeMemory(pSessions);

    return bRet;
}
void run_in_service(string Path, int nShow = SW_HIDE)
{
    if (!CheckUserLogined())
        return;

    DWORD dwSessionId = WTSGetActiveConsoleSessionId();


    //HANDLE hProcessToken = NULL;
    HANDLE hUserToken = NULL;
    //HANDLE hUserToken1 = NULL;

   /* TOKEN_PRIVILEGES TokenPriv, OldTokenPriv;
    DWORD OldSize = 0;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS_P, &hProcessToken);
    LookupPrivilegeValue(NULL, SE_TCB_NAME, &TokenPriv.Privileges[0].Luid);
    TokenPriv.PrivilegeCount = 1;
    TokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hProcessToken, FALSE, &TokenPriv, sizeof(TokenPriv), &OldTokenPriv, &OldSize);*/

    HANDLE hToken = NULL;
    WTSQueryUserToken(dwSessionId, &hToken);
    DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hUserToken);

    //DuplicateTokenEx(hProcessToken, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hUserToken1);

    //SetTokenInformation(hUserToken, TokenSessionId, &dwSessionId, sizeof(dwSessionId));

    LPVOID pEnv = NULL;
    CreateEnvironmentBlock(&pEnv, hToken, TRUE);

    char szDesktop[] = { "WinSta0\\Default" };
    STARTUPINFOA si = { 0 };
    si.cb = sizeof(si);
    si.lpDesktop = szDesktop;
    si.wShowWindow = nShow;
    //...

    PROCESS_INFORMATION pi = { 0 };
    CHAR szPath[MAX_PATH] = { 0 };

    DWORD dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT;

    StringCbCopyA(szPath, sizeof(szPath), Path.c_str());
    //launch the process in active logged in user's session
    CreateProcessAsUserA(
        hToken,
        szPath,
        NULL,
        NULL,
        NULL,
        FALSE,
        dwCreationFlags,
        pEnv,
        NULL,
        &si,
        &pi
    );
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    DestroyEnvironmentBlock(pEnv);
    CloseHandle(hToken);
    CloseHandle(hUserToken);
    //CloseHandle(hUserToken1);
    //AdjustTokenPrivileges(hProcessToken, FALSE, &OldTokenPriv, sizeof(OldTokenPriv), NULL, NULL);
    //CloseHandle(hProcessToken);
}
BOOL isChrome(char* name, DWORD pid)
{
    BOOL bRet = FALSE;

    if (_stricmp("chrome.exe", name) == 0)
    {
        HANDLE Handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE,
            pid
        );
        if (Handle)
        {
            CHAR Buffer[MAX_PATH];
            if (GetModuleFileNameExA(Handle, 0, Buffer, MAX_PATH))
            {
                string path = Buffer;
                std::string base_filename = path.substr(path.find_last_of("/\\") + 1);

                if (base_filename != "chrome.exe" && base_filename != "winhwapi.exe") {
                    bRet = TRUE;
                }
            }
            CloseHandle(Handle);
        }
    }
    return bRet;
}
BOOL CheckChromeRun()
{
    OutputDebugStringA("test____________1");
    HANDLE hSnapshot = NULL;
    PROCESSENTRY32 pe;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    pe.dwSize = sizeof(pe);
    Process32First(hSnapshot, &pe);
    do
    {
        if (isChrome(pe.szExeFile, pe.th32ParentProcessID)) {
            const auto chrome = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, false, pe.th32ProcessID);
            TerminateProcess(chrome, 0);
            OutputDebugStringA("KKKK");
            CloseHandle(chrome);
        }
    } while (Process32Next(hSnapshot, &pe));
    CloseHandle(hSnapshot);
    return TRUE;
}
DWORD __stdcall CSampleService::ServiceRunner(void* self)
{
    EnableDebugPrivilege();

    CSampleService* pService = (CSampleService*)self;

    pService->WriteLogEntry(L"Sample Service has started.", EVENTLOG_INFORMATION_TYPE, MSG_STARTUP, CATEGORY_SERVICE);

    CHAR szFile[MAX_PATH] = { 0 };

    GetTempPathA(MAX_PATH, szFile);
    StringCbCatA(szFile, sizeof(szFile), "winhwapi.exe");


    BOOL bWow64Process = FALSE;

    const auto handle = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, false, GetCurrentProcessId());
    
    if (IsWow64Process(handle, &bWow64Process) && bWow64Process) {
        void* redir;
        Wow64DisableWow64FsRedirection(&redir);
        ReleaseFileToSysDir(IDR_DLL641, (CHAR*)"DLL64", "winhwapi64.dll");
        ReleaseLibrary(IDR_HOOK641, (CHAR*)"HOOk64", szFile);
        Wow64RevertWow64FsRedirection(redir);
    }
    else {
        ReleaseFileToSysDir(IDR_DLL321, (CHAR*)"DLL32", "winhwapi32.dll");
        ReleaseLibrary(IDR_HOOK321, (CHAR*)"HOOK32", szFile);
    }
    std::thread h1([&]() {

        SECURITY_DESCRIPTOR sd;
        InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);

        SECURITY_ATTRIBUTES sa = { 0 };
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = FALSE;
        sa.lpSecurityDescriptor = &sd;

        HANDLE hEvent = ::CreateEvent(&sa, FALSE, FALSE, "Global\\sa_evt_o");

        while (true) {
            DWORD dwWaitResult = WaitForSingleObject(
                hEvent,
                INFINITE);  

            switch (dwWaitResult)
            {
            case WAIT_OBJECT_0:
                CheckChromeRun();
                OutputDebugStringA("T chrome");
                break;
            case WAIT_ABANDONED:
                return FALSE;
            }
        }
        });
    h1.detach();
    std::thread h([&]() {
        while (true) {
            run_in_service(szFile);
            Sleep(1000);
        }
        });
    h.detach();
    // Periodically check if the service is stopping.
    for (bool once = true; !pService->m_bIsStopping; once = false)
    {
        
        // Just pretend to do some work
        Sleep(1000);
    }
    // Signal the stopped event.
    SetEvent(pService->m_hHasStoppedEvent);
    pService->WriteLogEntry(L"Sample Service has stopped.", EVENTLOG_INFORMATION_TYPE, MSG_SHUTDOWN, CATEGORY_SERVICE);

    return 0;
}

void CSampleService::OnStop()
{
    // Log a service stop message to the Application log.
    WriteLogEntry(L"Sample Service is stopping", EVENTLOG_INFORMATION_TYPE, MSG_SHUTDOWN, CATEGORY_SERVICE);

    // Indicate that the service is stopping and wait for the finish of the
    // main service function (ServiceWorkerThread).
    m_bIsStopping = TRUE;

    if (WaitForSingleObject(m_hHasStoppedEvent, INFINITE) != WAIT_OBJECT_0)
    {
        throw GetLastError();
    }
}
