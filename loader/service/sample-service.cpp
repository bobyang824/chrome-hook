/****************************** Module Header ******************************\
* Module Name:  sample-service.cpp
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


// sample-service.cpp : Defines the entry point for the console application.
//

#pragma region "Includes"
#include "stdafx.h"
#include <regex>
#include "SampleService.h"
#include <ServiceInstaller.h>
#include <Shlwapi.h>
#include <strsafe.h>

#pragma endregion

using namespace std;

void startService(PCWSTR pszServiceName)
{
    SC_HANDLE schSCManager = NULL;
    SC_HANDLE schService = NULL;
    SERVICE_STATUS ssSvcStatus = {};

    // Open the local default service control manager database
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (schSCManager == NULL)
    {

        goto Cleanup;
    }

    // Open the service with delete, stop, and query status permissions
    schService = OpenServiceW(schSCManager, pszServiceName, SERVICE_START |
        SERVICE_QUERY_STATUS | DELETE);
    if (schService == NULL)
    {

        goto Cleanup;
    }
    SERVICE_STATUS status;

    if (::QueryServiceStatus(schService, &status) == FALSE)
    {

        goto Cleanup;
    }
    if (status.dwCurrentState == SERVICE_RUNNING)
    {

        goto Cleanup;
    }
    else {
        // Try to stop the service
        if (StartService(schService, NULL, NULL))
        {

            Sleep(1000);

            while (QueryServiceStatus(schService, &ssSvcStatus))
            {
                if (ssSvcStatus.dwCurrentState == SERVICE_START_PENDING)
                {
                    wprintf(L".");
                    Sleep(1000);
                }
                else break;
            }

            if (ssSvcStatus.dwCurrentState == SERVICE_RUNNING)
            {

            }
            else
            {

            }
        }
    }
Cleanup:
    // Centralized cleanup for all allocated resources.
    if (schSCManager)
    {
        CloseServiceHandle(schSCManager);
        schSCManager = NULL;
    }
    if (schService)
    {
        CloseServiceHandle(schService);
        schService = NULL;
    }
}
int wmain(int argc, wchar_t *argv[])
{
   // Service parameters
   DWORD dwSvcStartType = SERVICE_START_TYPE;
   PCWSTR wsSvcAccount = SERVICE_ACCOUNT;
   PCWSTR wsSvcPwd = SERVICE_PASSWORD;
   PCWSTR wsConfigFullPath = SERVICE_CONFIG_FILE;
   WCHAR wsServiceParams[MAX_PATH] = SERVICE_CMD;

   if (argc > 1)
   {
      if (_wcsicmp(L"install", argv[1]) == 0)
      {
         try
         {
            InstallService(
               SERVICE_NAME,               // Name of service
               SERVICE_DISP_NAME,          // Display name
               SERVICE_DESC,               // Description
               wsServiceParams,            // Command-line parameters to pass to the service
               dwSvcStartType,             // Service start type
               SERVICE_DEPENDENCIES,       // Dependencies
               wsSvcAccount,               // Service running account
               wsSvcPwd,                   // Password of the account
               TRUE,                       // Register with Windows Event Log, so our log messages will be found in Event Viewer
               1,                          // We have only one event category, "Service"
               NULL                        // No separate resource file, use resources in main executable for messages (default)
            );
            startService(SERVICE_NAME);
         }
         catch (exception const& ex)
         {
            wprintf(L"Couldn't install service: %S", ex.what());
            return 1;
         }
         catch (...)
         {
            wprintf(L"Couldn't install service: unexpected error");
            return 2;
         }
      }
      else if (_wcsicmp(L"uninstall", argv[1]) == 0)
      {
         UninstallService(SERVICE_NAME);
      }
      else if (_wcsicmp(SERVICE_CMD, argv[1]) == 0)
      {
         CSampleService service(SERVICE_NAME);

         service.SetCommandLine(argc, argv);

         if (!CServiceBase::Run(service))
         {
            DWORD dwErr = GetLastError();

            wprintf(L"Service failed to run with error code: 0x%08lx\n", dwErr);

            return dwErr;
         }
      }
      else if (_wcsicmp(PROCESS_CMD, argv[1]) == 0)
      {
         CSampleService service(SERVICE_NAME);

         service.SetCommandLine(argc, argv);

         service.Run();
      }
      else
      {
         wprintf(L"Unknown parameter: %s\n", argv[1]);
      }
   }
   else
   {
      wprintf(L"\nSample Windows Service\n\n");
      wprintf(L"Parameters:\n\n");
      wprintf(L" install [-start-type <2..4> -account <account-name> -password <account-password> -config <configuration-file-path>]\n  - to install the service.\n");
      wprintf(L"    service start types are:\n");
      wprintf(L"     2 - service started automatically by the service control manager during system startup.\n");
      wprintf(L"     3 - service started manually or by calling StartService function from another process.\n");
      wprintf(L"     4 - service installed in the \"disabled\" state, and cannot be started until enabled.\n");
      wprintf(L" run [-config <configuration-file-path>]\n  - to start as a regular process (not a service)\n");
      wprintf(L" uninstall\n  - to remove the service.\n");
   }

   return 0;
}


