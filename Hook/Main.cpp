#define WIN32_LEAN_AND_MEAN 

#include <windows.h>
#include <stdio.h>
#include <string>
#include <stdlib.h>
#include <winuser.h>
#include <Shlwapi.h>
#include <string>
#include <winternl.h>
#include <tchar.h>
#include <strsafe.h>
#include "detours.h"
#include <fstream>
#include <filesystem>

#pragma comment(lib,"shlwapi.lib")

using namespace std;
#define fs std::filesystem


typedef BOOL(WINAPI* CREATEPROCESSW)(IN LPCWSTR lpApplicationName,
    IN LPWSTR lpCommandLine,
    IN LPSECURITY_ATTRIBUTES lpProcessAttributes,
    IN LPSECURITY_ATTRIBUTES lpThreadAttributes,
    IN BOOL bInheritHandles,
    IN DWORD dwCreationFlags,
    IN LPVOID lpEnvironment,
    IN LPCWSTR lpCurrentDirectory,
    IN LPSTARTUPINFOW lpStartupInfo,
    OUT LPPROCESS_INFORMATION lpProcessInformation
    );

typedef BOOL(NTAPI* GETVERSIONEXW) (
    LPOSVERSIONINFOW lpVersionInformation
    );

typedef BOOL(NTAPI* GETPRODUCTINFO)(
    DWORD  dwOSMajorVersion,
     DWORD  dwOSMinorVersion,
      DWORD  dwSpMajorVersion,
     DWORD  dwSpMinorVersion,
     PDWORD pdwReturnedProductType
);
typedef BOOL(NTAPI* ISOS)(
    DWORD dwOS
);

GETPRODUCTINFO OriginalGetProductInfo = NULL;
GETVERSIONEXW OriginalGetVersionExW = NULL;
ISOS OriginalIsOS = NULL;
CREATEPROCESSW OriginalCreateProcessW = NULL;

BOOL NTAPI HookedGetVersionExW(
    LPOSVERSIONINFOW lpVersionInformation
)
{
    BOOL bRet = OriginalGetVersionExW(lpVersionInformation);

    if (bRet && lpVersionInformation) {
        ///lpVersionInformation->dwMajorVersion = 10;
        //lpVersionInformation->dwBuildNumber = 10000;
    }
    return bRet;
}

BOOL NTAPI HookedGetProductInfo(
    DWORD  dwOSMajorVersion,
    DWORD  dwOSMinorVersion,
    DWORD  dwSpMajorVersion,
    DWORD  dwSpMinorVersion,
    PDWORD pdwReturnedProductType
)
{
    BOOL bRet = OriginalGetProductInfo(dwOSMajorVersion, dwOSMinorVersion, dwSpMajorVersion, dwSpMinorVersion, pdwReturnedProductType);

    if (bRet) {
        *pdwReturnedProductType = PRODUCT_PROFESSIONAL;
    }
    return bRet;
}
BOOL NTAPI HookedIsOS(DWORD dwOS)
{
    if (dwOS == OS_DOMAINMEMBER)
        return TRUE;
    else
        return OriginalIsOS(dwOS);
}
void InstallHook(LPCSTR dll, LPCSTR function, LPVOID* originalFunction, LPVOID hookedFunction)
{
	HMODULE module = GetModuleHandleA(dll);
    if (module == NULL) {
        module = LoadLibraryA(dll);
    }
    *originalFunction = (LPVOID)GetProcAddress(module, function);

    if (*originalFunction) {
        DetourAttach(originalFunction, hookedFunction);
    }
}

BOOL WINAPI HookedCreateProcessW(LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    if (lpApplicationName) {
        wstring name = fs::path(lpApplicationName).stem().wstring();
        transform(name.begin(), name.end(), name.begin(), ::tolower);
        if (name == L"chrome") {
            return DetourCreateProcessWithDllExW(lpApplicationName,
                lpCommandLine,
                lpProcessAttributes,
                lpThreadAttributes,
                bInheritHandles,
                dwCreationFlags,
                lpEnvironment,
                lpCurrentDirectory,
                lpStartupInfo,
                lpProcessInformation,
                "TestHook64.dll",
                OriginalCreateProcessW
            );
        }
    }
    return OriginalCreateProcessW(lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation
    );
}
DWORD WINAPI InstallHooks()
{
    //CHAR szFile[MAX_PATH] = { 0 };

   // GetModuleFileNameA(NULL, szFile, MAX_PATH);
   // string name = fs::path(szFile).stem().string();
   // transform(name.begin(), name.end(), name.begin(), ::tolower);

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    //InstallHook("kernel32.dll", "CreateProcessW", (LPVOID*)&OriginalCreateProcessW, HookedCreateProcessW);

    //if (name == "chrome") {
        InstallHook("Kernel32.dll", "GetVersionExW", (LPVOID*)&OriginalGetVersionExW, HookedGetVersionExW);
        InstallHook("Kernel32.dll", "GetProductInfo", (LPVOID*)&OriginalGetProductInfo, HookedGetProductInfo);
        InstallHook("shlwapi.dll", "IsOS", (LPVOID*)&OriginalIsOS, HookedIsOS);
   // }
    DetourTransactionCommit();

    return 0;
}

extern "C" __declspec(dllexport) VOID xx()
{
    return;
}
BOOL APIENTRY DllMain(HANDLE hMoudle, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        InstallHooks();
        break;
    case DLL_PROCESS_DETACH:
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:

        break;
    }
    return TRUE;
}