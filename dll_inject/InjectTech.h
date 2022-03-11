#pragma once

BOOL MyCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pThreadProc, LPVOID pRemoteBuf,int nMod);
BOOL MyQueueUserAPC(HANDLE hProcess, LPTHREAD_START_ROUTINE hThreadProc, LPVOID pRemoteBuf, DWORD dwPID);
BOOL MySetWindowsHookEx(LPCTSTR szDllPath, DWORD dwPID, LPCTSTR ProcName);
BOOL MyRtlCreateUserThread(HANDLE hProcess, LPTHREAD_START_ROUTINE hThreadProc, LPVOID pRemoteBuf);
//BOOL MysuspendThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pThreadProc, LPVOID pRemoteBuf, DWORD dwPID);
BOOL ReflectiveDllInjection(PCWSTR cpDllFile, DWORD dwPID);