#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include "auxiliary.h"

BOOL MySetWindowsHookEx(LPCTSTR szDllPath, DWORD dwPID, LPCTSTR ProcName)
{
	// 获得目标进程当前的线程ID
	DWORD ThreadID = GetThreadID(dwPID);
	if (ThreadID == (DWORD)0)
	{
		wprintf(L"[-] Error: MySetWindowsHookEx(): GetThreadID() failed!\n");
		return FALSE;
	}
	// 加载目标DLL，但不在加载以及卸载的时候执行DllMain函数
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
	// 返回目标进程的窗口句柄
	//HWND targetWnd = FindWindow(NULL, ProcName);
	// 获取获取目标进程的PID
	//GetWindowThreadProcessId(targetWnd, &dwPID);

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