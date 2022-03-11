//===============================================================================================//
// Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are permitted 
// provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice, this list of 
// conditions and the following disclaimer.
// 
//     * Redistributions in binary form must reproduce the above copyright notice, this list of 
// conditions and the following disclaimer in the documentation and/or other materials provided 
// with the distribution.
// 
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR 
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR 
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <tchar.h>
#include <ntsecapi.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>
#include "LoadLibraryR.h"

#pragma comment(lib,"Advapi32.lib")

extern HANDLE __stdcall LoadRemoteLibraryR(HANDLE process, LPVOID lpBuffer, DWORD dwLength, LPVOID plParameter);


BOOL ReflectiveDllInjection(PCWSTR cpDllFile, DWORD dwPID)
{
	HANDLE hFile = NULL;
	HANDLE hModule = NULL;
	HANDLE hProcess = NULL;
	LPVOID lpBuffer = NULL;
	DWORD dwLength = 0;
	DWORD dwBytesRead = 0;
	BOOL Result = FALSE;

	// 这里的 do-while(0)可以提供很多优化功能
	// 例如避免宏展开缺少花括号或者多了分号造成的语法错误
	// 可以更结构化的处理错误跳转，以及可以在中途通过break结束这段代码
	do
	{
		hFile = CreateFileW(cpDllFile, GENERIC_READ, 0, NULL, OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL, NULL);
		// 这里的BREAK_WITH_ERROR后面跟了分号，是因为没有else,否则else将丢失if
		if (hFile == INVALID_HANDLE_VALUE)
		{
			wprintf(TEXT("[-] Error: Inject(): CreateFileW() Failed! [%d]\n"), GetLastError());
			break;
		}
		dwLength = GetFileSize(hFile, NULL);
		if (dwLength == INVALID_FILE_SIZE || dwLength == 0)
		{
			wprintf(TEXT("[-] Error: Inject(): GetFileSize() Failed! [%d]\n"), GetLastError());
			break;
		}
		
		lpBuffer = HeapAlloc(GetProcessHeap(), 0, dwLength);
		if (!lpBuffer) 
		{
			wprintf(TEXT("[-] Error: Inject(): HeapAlloc() Failed! [%d]\n"), GetLastError());
			break;
		}

		if (ReadFile(hFile, lpBuffer, dwLength, &dwBytesRead, NULL) == FALSE) 
		{
			wprintf(TEXT("[-] Error: Inject(): ReadFile() Failed! [%d]\n"), GetLastError());
			break;
		}

		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
		if(!hProcess) 
		{
			wprintf(TEXT("[-] Error: Inject(): OpenProcess() Failed! [%d]\n"), GetLastError());
			break;
		}

		hModule = LoadRemoteLibraryR(hProcess, lpBuffer, dwLength, NULL);
		if(!hModule)
		{
			wprintf(TEXT("[-] Error: Inject(): LoadRemoteLibraryR() Failed! [%d]\n"), GetLastError());
			break;
		}
		
		wprintf(TEXT("[+] Injected '%s' into process ID %d!\n"), cpDllFile, dwPID);

		WaitForSingleObject(hModule, -1);

		Result = TRUE;
	} while (0);

	if (lpBuffer) HeapFree(GetProcessHeap(), 0, lpBuffer);
	if (hProcess) CloseHandle(hProcess);
	return Result;
}