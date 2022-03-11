#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>

VOID displayHelp() {
	wprintf(TEXT("\nUsage: dll_inject.exe <procname|pid|*> <mod:-i|-e> <Injection technique> <dll path>\n"));

	wprintf(TEXT("\nprocname|pid|*:\n"));
	wprintf(TEXT("  procname|pid: Dll Injecting to procename|pid\n"));
	wprintf(TEXT("  *: Dll Injecting to all process\n"));
	wprintf(TEXT("mod:\n"));
	wprintf(TEXT("  -i: Dll Injection\n"));
	wprintf(TEXT("  -e: Dll Ejection\n"));

	wprintf(TEXT("Injection technique:\n"));
	wprintf(TEXT("  [for \"-e\"mod, this parameter is not limited, it can be a number or letter.] \n"));
	wprintf(TEXT("  [for \"-i\"mod, this parameter is limited to 5,not including 0.] \n"));
	wprintf(TEXT("  1. DLL injection via CreatRemoteThread() or via NtCreateThreadEx() if OS version is vista or later \n"));
	wprintf(TEXT("  2. DLL injection via QueueUserAPC()\n"));
	wprintf(TEXT("  3. DLL injection via SetWindowsHookEx(),The Expot Function of Dll should own \"Poc\" Function  \n"));
	wprintf(TEXT("  4. DLL injection via RtlCreateUserThread()\n"));
	wprintf(TEXT("  5. DLL injection via ReflectiveInjection()\n"));
}

DWORD GetProcPID(wchar_t* procname) {
	HANDLE phandle;
	PROCESSENTRY32 procSnapshot;
	// 获取系统中所有进程的快照
	phandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	procSnapshot.dwSize = sizeof(PROCESSENTRY32);

	// 遍历所有进程查找进程名称与procname相同的进程的pid号
	do {
		if (!_wcsicmp(procSnapshot.szExeFile, procname)) {
			DWORD pid = procSnapshot.th32ProcessID;
			CloseHandle(phandle);
			wprintf(TEXT("[+] PID of %s is: %ld\n"),procname, pid);
			return pid;
		}
	} while (Process32Next(phandle, &procSnapshot));

	CloseHandle(phandle);
	return 0;
}


LPCTSTR GetProcName(DWORD dwPID)
{
	HANDLE hSnapShot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 pe;
	BOOL SnapShotEnd = FALSE;

	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE)
	{
		wprintf(TEXT("[-] Error: GetProcName(): CreateToolhelp32Snapshot() Failed! \n"));
		return NULL;
	}
	
	pe.dwSize = sizeof(PROCESSENTRY32);
	SnapShotEnd = Process32First(hSnapShot, &pe);
	for (; SnapShotEnd; SnapShotEnd = Process32Next(hSnapShot, &pe))
	{
		if (dwPID == pe.th32ProcessID)
		{
			CloseHandle(hSnapShot);
			return pe.szExeFile;
		}
	}
	CloseHandle(hSnapShot);
	return NULL;
}

DWORD GetThreadID(DWORD dwPID)
{
	HANDLE hSnapShot = INVALID_HANDLE_VALUE;
	HANDLE hThread = NULL;
	BOOL ThreadEnd = FALSE;
	THREADENTRY32 te = { 0, };
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapShot != INVALID_HANDLE_VALUE)
	{
		te.dwSize = sizeof(THREADENTRY32);
		ThreadEnd = Thread32First(hSnapShot, &te);
		for (; ThreadEnd; Thread32Next(hSnapShot, &te))
		{
			if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID))
			{
				if (te.th32OwnerProcessID == dwPID)
				{
					hThread = OpenThread(READ_CONTROL, FALSE, te.th32ThreadID);
					if (!hThread)
						wprintf(TEXT("[-] Error: Couldn't get thread handle\n"));
					else
						return te.th32ThreadID;
				}
			}
		}
	}
	CloseHandle(hSnapShot);
	return DWORD(0);

}

BOOL SetPrivilege() 
{
	TOKEN_PRIVILEGES tp = { 0 };
	HANDLE hToken = NULL;
	// 获取该进程的access Token,允许更改access token的特权并允许查询该access token的特权
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) 
	{
		// TOKEN_PRIVILEGES结构体中第二个成员特权数组的个数
		tp.PrivilegeCount = 1;
		// 启用的特权属性,luid(本地唯一标识)代表各种不同的特权类型，用来保存要获得的权限
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		// NULL表示从本地系统的获取权限特权值 ,需要获取的特权信息的名称为SE_DEBUG_NAME，
		// 将获取的的特权信息(也就是获取SE_DEBUG_NAME这个特权)，存入tp.Privileges[0].Luid中,
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) 
		{
			// 第一个参数为要修改特权的access token的句柄
			// 第二个参数FALSE表示不禁用htoken所有的特权
			// 第三个参数为新的特权信息的指针(也就是需要让token获得的特权),新的特权信息就保存在tp.Privileges[0].Luid中
			if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL) == 0) 
			{
				wprintf(TEXT("[-] Error: AdjustTokenPrivilege Failed！ %u. \n"), GetLastError());
				if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) 
				{
					wprintf(TEXT("[*] Warning: The token does not set the specified privilege.\n"));
						return FALSE;
				}
			}
			else
				wprintf(TEXT("[+] SeDebugPrivilege Enabled.\n"));
		}
		CloseHandle(hToken);
	}
	else
	{
		wprintf(TEXT("[-] Error: OpenProcessToken() failed %u.\n"),GetLastError());
		return FALSE;
	}
	return TRUE;
}

BOOL CheckDllInProcess(DWORD dwPID,LPCTSTR szDllPath)
{
	BOOL ModuleEnd = FALSE;
	HANDLE hSnapShot = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me = { sizeof(me), };

	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if (hSnapShot == INVALID_HANDLE_VALUE)
	{
		wprintf(TEXT("[-] Error: CheckDllInProcess(): CreateToolhelp32Snapshot() failed %d.\n"), GetLastError());
		return FALSE;
	}

	ModuleEnd = Module32First(hSnapShot, &me);
	for (; ModuleEnd; ModuleEnd = Module32Next(hSnapShot, &me))
	{
		if (!_tcsicmp(me.szModule, szDllPath) ||
			!_tcsicmp(me.szExePath, szDllPath))
		{
			CloseHandle(hSnapShot);
			return TRUE;
		}
	}
	CloseHandle(hSnapShot);
	return FALSE;
}

BOOL IsVistaLater()
{
	OSVERSIONINFO osvi;

	ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

	GetVersionEx(&osvi);

	if (osvi.dwMajorVersion >= 6)
		return TRUE;
	return FALSE;
}