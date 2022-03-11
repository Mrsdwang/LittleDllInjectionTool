#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include "auxiliary.h"

typedef DWORD(WINAPI* pRtlCreateUserThread)(
	IN HANDLE 					ProcessHandle,
	IN PSECURITY_DESCRIPTOR 	SecurityDescriptor,
	IN BOOL 					CreateSuspended,
	IN ULONG					StackZeroBits,
	IN OUT PULONG				StackReserved,
	IN OUT PULONG				StackCommit,
	IN LPVOID					StartAddress,
	IN LPVOID					StartParameter,
	OUT HANDLE 					ThreadHandle,
	OUT LPVOID					ClientID
	);


BOOL MyRtlCreateUserThread(HANDLE hProcess, LPTHREAD_START_ROUTINE hThreadProc, LPVOID pRemoteBuf)
{
	pRtlCreateUserThread RtlCreateUserThread = NULL;
	HANDLE hRemoteThread = NULL;
	BOOL Result = FALSE, Status = FALSE;

	RtlCreateUserThread = (pRtlCreateUserThread)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlCreateUserThread");
	if (RtlCreateUserThread == NULL)
	{
		wprintf(L"[-] Error: MyRtlCreateUserThread(): GetProcAddress(GetModuleHandle(\"ntdll.dll\"), \"RtlCreateUserThread\") failed! \n");
		return Result;
	}

	Status = (BOOL)RtlCreateUserThread(
		hProcess,
		NULL,
		0,
		0,
		0,
		0,
		hThreadProc,
		pRemoteBuf,
		&hRemoteThread,
		NULL);
	if (Status < 0)
	{
		wprintf(TEXT("[-] Error: MyRtlCreateUserThread(): RtlCreateUserThread() failed\n"));
	}
	else
	{
		wprintf(TEXT("[+] Success: DLL injected via RtlCreateUserThread().\n"));
		WaitForSingleObject(hRemoteThread, INFINITE);
		CloseHandle(hProcess);
		Result = TRUE;
	}
	return Result;
	
}