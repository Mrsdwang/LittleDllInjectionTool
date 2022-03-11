#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include "auxiliary.h"

BOOL MyQueueUserAPC(HANDLE hProcess, LPTHREAD_START_ROUTINE hThreadProc, LPVOID pRemoteBuf,DWORD dwPID)
{
	BOOL Result = FALSE, ThreadEnd = FALSE;
	HANDLE hThread = NULL, hSnapShot = NULL;
	DWORD ThreadID = 0;
	THREADENTRY32 te = { 0, };
	int Counter = 0;

	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE)
	{
		wprintf(TEXT("[-] Error: MyQueueUserAPC(): CreateToolHelp32SnapShot() Failed! [%d]\n"), GetLastError());
		return FALSE;
	}

	te.dwSize = sizeof(THREADENTRY32);
	ThreadEnd = Thread32First(hSnapShot, &te);
	for (; ThreadEnd; ThreadEnd = Thread32Next(hSnapShot, &te))
	{
		if (te.th32OwnerProcessID == dwPID)
		{
			ThreadID = te.th32ThreadID;
			wprintf(TEXT("[+] Using thread: %i\n"), ThreadID);
			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
			if (hThread == NULL)
				wprintf(TEXT("[-] Error: MyQueueUserAPC(): OpenThread() failed > Continuing to try other threads...\n"));
			else
			{
				DWORD APCResult = QueueUserAPC((PAPCFUNC)hThreadProc, hThread, (ULONG_PTR)pRemoteBuf);
				if (APCResult == 0)
				{
					wprintf(TEXT("[-] Error: MyQueueUserAPC(): Couldn't call QueueUserAPC() on thread > Continuing to try othrt threads...\n"));
				}
				else
				{
					Counter++;
					wprintf(TEXT("[+] Success: DLL injected via QueueUserAPC().\n"));
					Result = TRUE;
				}
				CloseHandle(hThread);
			}
		}
	}
	
	if (!ThreadID)
		wprintf(TEXT("[-] Error: MyQueueUserAPC: No threads found in thr target process\n"));

	CloseHandle(hSnapShot);
	wprintf(TEXT("[-] Injected %d times,you should Eject %d times if you need to Eject\n"),Counter,Counter);
	return Result;
}