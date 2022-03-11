#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include "auxiliary.h"

BOOL MySetWindowsHookEx(LPCTSTR szDllPath, DWORD dwPID, LPCTSTR ProcName)
{
	DWORD ThreadID = GetThreadID(dwPID);
	if (ThreadID == (DWORD)0)
	{
		wprintf(L"[-] Error: MySetWindowsHookEx(): GetThreadID() failed!\n");
		return FALSE;
	}

	HMODULE dll = LoadLibraryEx(szDllPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (dll == NULL)
	{
		wprintf(L"[-] Error: MySetWindowsHookEx(): LoadLibraryEx() failed!\n");
		return FALSE;
	}

	// DLL文件中导出函数名称必须为Poc
	HOOKPROC addr = (HOOKPROC)GetProcAddress(dll, "Poc");
	if (addr == NULL)
	{
		wprintf(L"[-] Error: MySetWindowsHookEx(): GetProcAddress() failed!\n");
		return FALSE;
	}

	HWND targetWnd = FindWindow(NULL, ProcName);
	GetWindowThreadProcessId(targetWnd, &dwPID);

	HHOOK handle = SetWindowsHookEx(WH_KEYBOARD, addr, dll, ThreadID);
	if (handle == NULL)
	{
		wprintf(L"[-] Error: MySetWindowsHookEx(): SetWindowsHookEx() failed!\n");
		return FALSE;
	}
	else
	{
		wprintf(TEXT("[+] Program successfully hooked.\nPress enter to unhook the function and stop the program.\n"));
		getchar();
		UnhookWindowsHookEx(handle);
	}

	return TRUE;

}