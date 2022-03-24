#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include "auxiliary.h"
#include "InjectTech.h"
#include <TlHelp32.h>

enum { INJECTION_MOD = 0, EJECTION_MOD };

BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath, int tech,int nMod)
{
	HANDLE hProcess = NULL;
	LPTHREAD_START_ROUTINE hThreadProc = NULL;
	LPVOID pRemoteBuf = NULL;
	DWORD dwBuffSize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);
	BOOL Result = FALSE;
	HMODULE hMod = NULL;
	DWORD dwDesireAccess = 0;
	TCHAR szProcName[MAX_PATH] = { 0, };
	BOOL IsReflective = FALSE;

	dwDesireAccess = PROCESS_ALL_ACCESS;
	hProcess = OpenProcess(dwDesireAccess, FALSE, dwPID);
	if (hProcess == NULL)
	{
		wprintf(TEXT("[-] Error: Inject(): OpenProcess() Failed! [%d]\n"), GetLastError());
		goto INJECTDLL_EXIT;
	}

	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBuffSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pRemoteBuf == NULL)
	{
		wprintf(TEXT("[-] Error: Inject(): VirtualAllocEx() Failed! [%d]\n"), GetLastError());
		goto INJECTDLL_EXIT;
	}

	if ( !WriteProcessMemory(hProcess, pRemoteBuf, (LPCVOID)szDllPath, dwBuffSize, NULL))
	{
		wprintf(TEXT("[-] Error: Inject(): WriteProcessMemory() Failed! [%d]\n"), GetLastError());
		goto INJECTDLL_EXIT;
	}

	hMod = GetModuleHandle(L"kernel32.dll");
	if (hMod == NULL)
	{
		wprintf(TEXT("[-] Error: Inject(): GetModuleHandle(\"kernel32.dll\") Failed! [%d]\n"), GetLastError());
		goto INJECTDLL_EXIT;
	}

	hThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryW");
	if (hThreadProc == NULL)
	{
		wprintf(TEXT("[-] Error: Inject(): GetProcAddress(\"LoadLibrary\") Failed! [%d]\n"), GetLastError());
		goto INJECTDLL_EXIT;
	}

	switch (tech)
	{
	case 1:
		if (!MyCreateRemoteThread(hProcess, hThreadProc, pRemoteBuf,nMod))
		{
			wprintf(TEXT("[-] Error: Inject(): MyCreateRemoteThread() Failed! [%d]\n"), GetLastError());
			goto INJECTDLL_EXIT;
		}
		break;
	case 2:
		if (!MyQueueUserAPC(hProcess, hThreadProc, pRemoteBuf, dwPID))
		{
			wprintf(TEXT("[-] Error: Inject(): MyQueueUserAPC() Failed! [%d]\n"), GetLastError());
			goto INJECTDLL_EXIT;
		}
		break;
	case 3:
		if (!MySetWindowsHookEx(szDllPath,dwPID,GetProcName(dwPID)))
		{
			wprintf(TEXT("[-] Error: Inject(): MySetWindowsHookEx() Failed! [%d]\n"), GetLastError());
			goto INJECTDLL_EXIT;
		}
		break;
	case 4:
		if (!MyRtlCreateUserThread(hProcess, hThreadProc, pRemoteBuf))
		{
			wprintf(TEXT("[-] Error: Inject(): MyRtlCreateUserThread() Failed! [%d]\n"), GetLastError());
			goto INJECTDLL_EXIT;
		}
		break;
	
	case 5:
		if (!(Result = ReflectiveDllInjection(szDllPath, dwPID)))
		{
			wprintf(TEXT("[-] Error: Inject(): ReflectiveDllInjection() Failed! [%d]\n"), GetLastError());
			goto INJECTDLL_EXIT;
		}
		IsReflective = TRUE;
		break;
	/*case 6:
		if (!(Result = MysuspendThread(hProcess, hThreadProc, pRemoteBuf,dwPID)))
		{
			wprintf(TEXT("[-] Error: Inject(): MysuspendThread() Failed! [%d]\n"), GetLastError());
			goto INJECTDLL_EXIT;
		}
		break;
		*/
	}
	
	if (!IsReflective)
		// 反射式DLL注入因没有注册DLL所以无法查找DLL是否在进程里面
		Result = CheckDllInProcess(dwPID, szDllPath);
	else
		Result = TRUE;

INJECTDLL_EXIT:
	wsprintf(szProcName, L"%s", GetProcName(dwPID));
	if (szProcName[0] == '\0')
		_tcscpy_s(szProcName, L"No_Process");
	wprintf(TEXT("%s[%d] Inject %s!!! [%d]\n"), szProcName, dwPID, Result ? L"Success" : L"-->>Failure", GetLastError());

	if (pRemoteBuf)
		VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
	if (hProcess)
		CloseHandle(hProcess);
	return Result;

}


BOOL EjectDll(DWORD dwPID, LPCTSTR szDllPath,int nMod)
{
	BOOL ModuleEnd = FALSE, FoundDll = FALSE, Result = FALSE;
	HANDLE hSnapShot = INVALID_HANDLE_VALUE;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	MODULEENTRY32 me = { sizeof(me), };
	LPTHREAD_START_ROUTINE pThreadProc = NULL;
	HMODULE hMod = NULL;
	DWORD dwDesireAccess = 0;
	TCHAR szProcName[MAX_PATH] = { 0, };

	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if (hSnapShot == INVALID_HANDLE_VALUE)
	{
		wprintf(TEXT("[-] Error: Eject(): CreateToolHelp32SnapShot() Failed! [%d]\n"), GetLastError());
		goto EJECT_EXIT;
	}

	ModuleEnd = Module32First(hSnapShot, &me);
	for (; ModuleEnd; ModuleEnd = Module32Next(hSnapShot, &me))
	{
		if (!_tcsicmp(me.szModule, szDllPath) ||
			!_tcsicmp(me.szExePath, szDllPath))
		{
			FoundDll = TRUE;
			break;
		}
	}

	if (!FoundDll)
	{
		wprintf(TEXT("[-] Error: Eject(): Could not find %s module in the process[%d]\n"), szDllPath, dwPID);
		goto EJECT_EXIT;
	}

	dwDesireAccess = PROCESS_ALL_ACCESS;
	hProcess = OpenProcess(dwDesireAccess, FALSE, dwPID);
	if (hProcess == NULL)
	{
		wprintf(TEXT("[-] Error: Eject(): OpenProcess() Failed! [%d]\n"), GetLastError());
		goto EJECT_EXIT;
	}

	hMod = GetModuleHandle(L"kernel32.dll");
	if (hMod == NULL)
	{
		wprintf(TEXT("[-] Error: Eject(): GetModuleHandle(\"Kernel32.dll\") Failed! [%d]\n"), GetLastError());
		goto EJECT_EXIT;
	}

	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "FreeLibrary");
	if (pThreadProc == NULL)
	{
		wprintf(TEXT("[-] Error: Eject(): GetProcAddress(\"FreeLibrary\") Failed! [%d]\n"), GetLastError());
		goto EJECT_EXIT;
	}

	if (!MyCreateRemoteThread(hProcess, pThreadProc, me.modBaseAddr,nMod))
	{
		wprintf(TEXT("[-] Error: Eject(): xx Failed! \n"));
		goto EJECT_EXIT;
	}

	Result = TRUE;

EJECT_EXIT:
	_tcscpy_s(szProcName, GetProcName(dwPID));
	_tprintf(L"%s(%d) Ejects %s!!! [%d]\n", szProcName, dwPID, Result ? L"SUCCESS" : L"-->> FAILURE", GetLastError());

	if (hThread)
		CloseHandle(hThread);
	if (hProcess)
		CloseHandle(hProcess);
	if (hSnapShot)
		CloseHandle(hSnapShot);

	return Result;
}

BOOL InjectOrEjectDllToOne(LPCTSTR szProc, int nMod, LPCTSTR szDllPath, TCHAR* tech)
{
	int i = 0, nLen = (int)_tcsclen(szProc);
	DWORD dwPID = 0;
	HANDLE hSnapShot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 pe;
	BOOL SnapShotEnd = FALSE;

	// 检查传入的是进程名还是PID
	for (i = 0; i < nLen; i++)
		// 如果不是十进制数字就返回0，循环就会中断，因此 i!=nLen
		if (!_istdigit(szProc[i]))
			break;

	// 如果传入的是PID
	if (i == nLen)
	{
		dwPID = (DWORD)_tstol(szProc);
		if (nMod == INJECTION_MOD)
			InjectDll(dwPID, szDllPath, _wtoi(tech), nMod);
		else
			EjectDll(dwPID, szDllPath, nMod);
	}
	// 如果是进程名
	else
	{
		// 获取系统所有进程快照
		pe.dwSize = sizeof(PROCESSENTRY32);
		hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
		if (hSnapShot == INVALID_HANDLE_VALUE)
		{
			wprintf(TEXT("[-] Error: InjectOrEjectDllToOne(): CreateToolHelp32SnapShot() Failed! [%d]\n"), GetLastError());
			return FALSE;
		}

		SnapShotEnd = Process32First(hSnapShot, &pe);
		for (; SnapShotEnd; SnapShotEnd = Process32Next(hSnapShot, &pe))
		{
			dwPID = pe.th32ProcessID;
			
			// PID小于100多为系统进程，为保证DLL注入不影响系统我们需要跳过
			if (dwPID <= 100)
				continue;

			if (!_tcsicmp(pe.szExeFile, szProc))
			{
				if (nMod == INJECTION_MOD)
					InjectDll(dwPID, szDllPath, _wtoi(tech),nMod);
				else
					EjectDll(dwPID, szDllPath, nMod);
			}
		}
		CloseHandle(hSnapShot);
	}
	return TRUE; 
}

BOOL InjectOrEjectDllToAll(int nMod, LPCTSTR szDllPath,TCHAR* tech)
{
	DWORD dwPID = 0;
	HANDLE hSnapShot = INVALID_HANDLE_VALUE;
	BOOL SnapShotEnd = FALSE;
	PROCESSENTRY32 pe;

	pe.dwSize = sizeof(PROCESSENTRY32);
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE)
	{
		wprintf(TEXT("[-] Error: InjectOrEjectDllToAll(): CreateToolHelp32SnapShot() Failed! [%d]\n"), GetLastError());
		return FALSE;
	}
	
	SnapShotEnd = Process32First(hSnapShot, &pe);
	for (; SnapShotEnd; SnapShotEnd = Process32Next(hSnapShot, &pe))
	{
		dwPID = pe.th32ProcessID;
		if (dwPID <= 100 ||
			!_wcsicmp(pe.szExeFile,L"smss.exe") ||
			!_wcsicmp(pe.szExeFile,L"csrss.exe"))
		{
			wprintf(TEXT("%s(%d) is System Process... DLL %s is Refused!\n"),
				pe.szExeFile, dwPID, nMod == INJECTION_MOD ? L"Injection" : L"Ejection");
			continue;
		}

		if (nMod == INJECTION_MOD)

			InjectDll(dwPID, szDllPath,_wtoi(tech), nMod);
		else
			EjectDll(dwPID, szDllPath, nMod);

	}
	CloseHandle(hSnapShot);
	return TRUE;
}

