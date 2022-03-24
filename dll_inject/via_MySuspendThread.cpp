#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include "auxiliary.h"


#ifdef _WIN64
unsigned char ShellCode [] =
{
	0x49,0xBD,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
	0x41,0x55,
    0x50, // push rax (save rax)
	//0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // mov rax, 0CCCCCCCCCCCCCCCCh (place holder for return address)
	0x9c,                                                                   // pushfq
	0x51,                                                                   // push rcx
	0x52,                                                                   // push rdx
	0x53,                                                                   // push rbx
	0x55,                                                                   // push rbp
	0x56,                                                                   // push rsi
	0x57,                                                                   // push rdi
	0x41, 0x50,                                                             // push r8
	0x41, 0x51,                                                             // push r9
	0x41, 0x52,                                                             // push r10
	0x41, 0x53,                                                             // push r11
	0x41, 0x54,                                                             // push r12
	0x41, 0x55,                                                             // push r13
	0x41, 0x56,                                                             // push r14
	0x41, 0x57,                                                             // push r15
	0x68, 0xef,0xbe,0xad,0xde,
	0x48, 0xB9, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // mov rcx, 0CCCCCCCCCCCCCCCCh (place holder for DLL path name)
	0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // mov rax, 0CCCCCCCCCCCCCCCCh (place holder for LoadLibrary)
	0xFF, 0xD0,                // call rax (call LoadLibrary)
	0x58, // pop dummy
	0x41, 0x5F,                                                             // pop r15
	0x41, 0x5E,                                                             // pop r14
	0x41, 0x5D,                                                             // pop r13
	0x41, 0x5C,                                                             // pop r12
	0x41, 0x5B,                                                             // pop r11
	0x41, 0x5A,                                                             // pop r10
	0x41, 0x59,                                                             // pop r9
	0x41, 0x58,                                                             // pop r8
	0x5F,                                                                   // pop rdi
	0x5E,                                                                   // pop rsi
	0x5D,                                                                   // pop rbp
	0x5B,                                                                   // pop rbx
	0x5A,                                                                   // pop rdx
	0x59,                                                                   // pop rcx
	0x9D,                                                                   // popfq
	0x58,                                                                   // pop rax
	0xC3                                                                    // ret
	/*
0x48,0x83,0xEC,0x28,
0x48,0x89,0x44,0x24,0x18,
0x48,0x89,0x4C,0x24,0x10,
0x48,0xB9,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
0x48,0xB8,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,
0xFF,0xD0,
0x48,0x8B,0x4C,0x24,0x10,
0x48,0x8B,0x44,0x24,0x18,
0x48,0x83,0xC4,0x28,
0x49,0xBB,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,
0x41,0xFF,0xE3
*/

};

BOOL MysuspendThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pThreadProc, LPVOID pRemoteBuf,DWORD dwPID)
{
	LPVOID ShellCodeAddr;
	DWORD64 ScSize;
	DWORD ThreadID;
	HANDLE hThread;
	CONTEXT ctx;
	ULONG_PTR OldRip = 0;

	ScSize = sizeof(ShellCode);
	wprintf(TEXT("[+] Shellcode Length is: %lld\n"), ScSize);

	ShellCodeAddr = VirtualAllocEx(hProcess, NULL, ScSize, MEM_COMMIT , PAGE_EXECUTE_READWRITE);
	printf("%I64x\n", ShellCodeAddr);
	if (ShellCodeAddr == NULL)
	{
		wprintf(TEXT("[-] Error: Inject(): MysuspendThread() Failed! [%d]\n"), GetLastError());
		return FALSE;
	}

	ThreadID = GetThreadID(dwPID);
	hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadID);
	if (hThread == NULL)
	{
		wprintf(L"[-] Error: MysuspendThread(): OpenThread() failed!\n");
		return FALSE;
	}
	
	if (SuspendThread(hThread) == -1)
	{
		wprintf(L"[-] Error: MysuspendThread(): SuspendThread() failed!\n");
		return FALSE;
	}
	ctx.ContextFlags = CONTEXT_CONTROL;
	if (!GetThreadContext(hThread, &ctx))
	{
		wprintf(L"[-] Error: MysuspendThread(): SuspendThread() failed!\n");
		return FALSE;
	}
	OldRip = ctx.Rip;
	ctx.Rip = (DWORD64)ShellCodeAddr;
	ctx.ContextFlags = CONTEXT_CONTROL;
	//memcpy(ShellCode + 52, &OldRip, sizeof(OldRip));
	//memcpy(ShellCode + 16, &pRemoteBuf, sizeof(pRemoteBuf));
	//memcpy(ShellCode + 26, &pThreadProc, sizeof(pThreadProc));
	
	memcpy(ShellCode + 2, &OldRip, sizeof(OldRip));
	memcpy(ShellCode + 43, &pRemoteBuf, sizeof(pRemoteBuf));
	memcpy(ShellCode + 53, &pThreadProc, sizeof(pThreadProc));
	wprintf(L"[-] Check point1\n");
	if (!WriteProcessMemory(hProcess, ShellCodeAddr, &ShellCode, ScSize, NULL))
	{
		wprintf(L"[-] Error: MysuspendThread(): WriteProcessMemory() failed!\n");
		return FALSE;
	}

	wprintf(L"[-] Check point2\n");
	if (!SetThreadContext(hThread, &ctx))
	{
		wprintf(L"[-] Error: MysuspendThread(): SetThreadContext() failed!\n");
		return FALSE;
	}
	wprintf(L"[-] Check point3\n");
	ResumeThread(hThread);

	Sleep(800);

	VirtualFreeEx(hProcess, ShellCodeAddr, ScSize, MEM_DECOMMIT);
	CloseHandle(hThread);

	return TRUE;
}

#else

#endif

