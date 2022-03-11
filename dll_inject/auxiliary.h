#pragma once

VOID displayHelp();
DWORD GetProcPID(wchar_t* procname);
BOOL SetPrivilege();
LPCTSTR GetProcName(DWORD dwPID);
BOOL CheckDllInProcess(DWORD dwPID, LPCTSTR szDllPath);
BOOL IsVistaLater();
DWORD GetThreadID(DWORD dwPID);

