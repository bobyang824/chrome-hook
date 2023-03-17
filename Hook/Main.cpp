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

DWORD WINAPI InstallHooks()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    InstallHook("Kernel32.dll", "GetVersionExW", (LPVOID*)&OriginalGetVersionExW, HookedGetVersionExW);
    InstallHook("Kernel32.dll", "GetProductInfo", (LPVOID*)&OriginalGetProductInfo, HookedGetProductInfo);
    InstallHook("shlwapi.dll", "IsOS", (LPVOID*)&OriginalIsOS, HookedIsOS);

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