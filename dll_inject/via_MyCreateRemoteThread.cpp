#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include "auxiliary.h"

// 定义NtCreateThreadEx函数
// 32位和64位的NtCreateThreadEx函数的参数不同
#ifdef _WIN64

// 64位用
typedef NTSTATUS(WINAPI* LPFUN_NtCreateThreadEx)(
	PHANDLE hThread,
	ACCESS_MASK DesireAccess,
	LPVOID ObjectAttributes,
	HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE lpstartAddress,
	LPVOID lpParameter,
	ULONG CreateThreadFlags,
	SIZE_T ZeroBits,
	SIZE_T StackSize,
	SIZE_T MaximumStackSize,
	LPVOID lpBytesBuffer
	);
#else

// 32位用
typedef NTSTATUS(WINAPI* LPFUN_NtCreateThreadEx)(
	PHANDLE hThread,
	ACCESS_MASK DesireAccess,
	LPVOID ObjectAttributes,
	HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE lpstartAddress,
	LPVOID lpParameter,
	BOOL CreateSuspended,
	ULONG StackZeroBits,
	ULONG SizeOfStackCommit,
	ULONG SizeOfStackReserve,
	LPVOID lpBytesBuffer
	);

#endif // __WIN64



BOOL MyCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pThreadProc, LPVOID pRemoteBuf,int nMod)
{
	HANDLE hThread = NULL;
	FARPROC pFunc = NULL;

	if (IsVistaLater())
	{
		pFunc = GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateThreadEx");
		if (pFunc == NULL)
		{
			wprintf(TEXT("[-] Error: MyCreateRemoteThread(): GetProcAddress(\"NtCreateThreadEx\") Failed! [%d]\n"), GetLastError());
			return FALSE;
		}

		((LPFUN_NtCreateThreadEx)pFunc)
			(&hThread,
			0x1FFFFF,
			NULL,
			hProcess,
			pThreadProc,
			pRemoteBuf,
			FALSE,
			NULL,
			NULL,
			NULL,
			NULL);
		
		if (hThread == NULL)
		{
			wprintf(TEXT("[-] Error: MyCreateRemoteThread(): NtCreateThreadEx() Failed! [%d]\n"), GetLastError());
			return FALSE;
		}
	}
	else
	{
		hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
		if (hThread == NULL)
		{
			wprintf(TEXT("[-] Error: MyCreateRemoteThread(): CreateRemoteThread() Failed! [%d]\n"), GetLastError());
			return FALSE;
		}
	}
	
	if (WaitForSingleObject(hThread, INFINITE) == WAIT_FAILED)
	{
		wprintf(TEXT("[-] Error: MyCreateRemoteThread(): WaitForSingleObject() Failed! [%d]\n"), GetLastError());
		return FALSE;
	}

	if(nMod == 0)
		wprintf(TEXT("[+] Success: DLL injected via CreateRemoteThread().\n"));
	else
		wprintf(TEXT("[+] Success: DLL Ejected via CreateRemoteThread().\n"));

	return TRUE;
}
