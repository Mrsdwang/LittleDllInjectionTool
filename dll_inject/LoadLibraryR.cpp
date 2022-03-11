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

#include "LoadLibraryR.h"
#include <stdio.h>
#include <Windows.h>
//#include <ntstatus.h>

//===============================================================================================//
DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress)
{
	WORD wIndex = 0;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	// ��ȡNTͷ�ĵ�ַ��Ҳ����PEǩ����ʼ�ĵ�ַ
	pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);
	// ��ȡ����ͷ��ʼ�ĵ�ַ�����㷽��Ϊ addr(OptionHeader) + sizeof(OptionHeader)����������OpitionHeader���򣬻�ý���ͷ��ַ
	pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);
	// �����Ҫ����RVAת����Offset��RVAС�ڵ�һ���������ļ���ʼ��ַ���ͷ��ء���ΪRVAС�ڣ���ô�Ͳ������ǽ��������ݣ�����Ҫת����
	if (dwRva < pSectionHeader[0].PointerToRawData)
		return dwRva;

	//���Ͼ��ǻ�ȡ������ַ
	// �ж��ٽ�����ѭ�����ٴ�
	for (wIndex = 0; wIndex < pNtHeaders->FileHeader.NumberOfSections; wIndex++)
	{
		// ���Ҫת����RVA���ڵ��ڸý������ڴ��е���ʼ��ַ,������Ҫת����RVAС�ڽ������ڴ��е���ʼ��ַ���ϸý����ڴ����еĴ�С�ͷ���ת��ֵ
		// �ڶ�������������ΪVirtualSizeҪС��SizeofRawData���ܱ���ת������������������������Ǽ���ý���Image�Ĵ�С�������ļ��Ĵ�С�����̶�ȷ��ת����RVA����������ĵ�ַ����
		if (dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData))
			// ���ݼ��㹫ʽ Offset = RVA - VirtualAddress + PointerToRawData
			return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData);
	}

	return 0;
}

//===============================================================================================//
DWORD GetReflectiveLoaderOffset(VOID* lpReflectiveDllBuffer)
{
	UINT_PTR uiBaseAddress = 0;
	UINT_PTR uiExportDir = 0;
	UINT_PTR uiNameArray = 0;
	UINT_PTR uiAddressArray = 0;
	UINT_PTR uiNameOrdinals = 0;
	DWORD dwCounter = 0;
#ifdef _WIN64
	DWORD dwCompiledArch = 2;
#else
	// This will catch Win32 and WinRT.
	DWORD dwCompiledArch = 1;
#endif
	// ��DLL�ļ�д��Ķѵ�ַ��Ҳ����д���ڴ�ѵ�DLL�ļ�����ʼ��ַ
	uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;

	// get the File Offset of the modules NT Header
	// ��ȡDLL�ļ���NT Header ���ļ�ƫ�ƣ�Ҳ����PEǩ����ͷ�ĵ�ַ
	uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

	// currenlty we can only process a PE file which is the same type as the one this fuction has  
	// been compiled as, due to various offset in the PE structures being defined at compile time.

	// ͨ��NTͷ�Ŀ�ѡͷ��Magic�ֶ��ж���Ϊ32����64
	if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x010B) // PE32
	{
		if (dwCompiledArch != 1)
			return 0;
	}
	else if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x020B) // PE64
	{
		if (dwCompiledArch != 2)
			return 0;
	}
	else
	{
		return 0;
	}
	// ��Ϊ��ֱ�����ļ���ʽ������DLL�ļ����ص��ڴ棬������Ȼ���ļ��ṹ��������DLLͨ�����ص��ڴ���image�ṹ������Ҫ�����ļ�ƫ��
	// uiNameArray = the address of the modules export directory entry
	// ��ȡ��ѡͷ�еĵ������ַ
	uiNameArray = (UINT_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	// get the File Offset of the export directory
	// ��ȡIMAGE_EXPORT_DIRECTORY�ṹ��ĵ�ַ
	uiExportDir = uiBaseAddress + Rva2Offset(((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress);

	// get the File Offset for the array of name pointers
	// ��ȡ��DLL�����������Ƶ������ļ�ƫ��
	uiNameArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames, uiBaseAddress);

	// get the File Offset for the array of addresses
	// ��ȡDLL����������ַ������ļ�ƫ��
	uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);

	// get the File Offset for the array of name ordinals
	// ��ȡDLL��������Ordinals������ļ�ƫ��
	uiNameOrdinals = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals, uiBaseAddress);

	// get a counter for the number of exported functions...
	// ��ȡ��������������
	dwCounter = ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->NumberOfNames;

	// loop through all the exported functions to find the ReflectiveLoader
	// �������е�������Ѱ�ҷ������������
	while (dwCounter--)
	{
		// ��ȡ�����������ƣ����������������鱣����Ǻ��������ַ�������ĵ�ַ����˻���Ҫ�ڶ���ת���ַ�������ĵ�ַΪ�ļ�ƫ��
		char* cpExportedFunctionName = (char*)(uiBaseAddress + Rva2Offset(DEREF_32(uiNameArray), uiBaseAddress));
		// ������������������������ҵ��ַ���"ReflectiveLoader"
		if (strstr(cpExportedFunctionName, "ReflectiveLoader") != NULL)
		{
			// get the File Offset for the array of addresses
			// ���ҵ���������������󣬾ͻ�ȡ������ַ���ļ�ƫ��(ǰ�治��������Ϊʲô��дһ�Σ�)
			uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);

			// use the functions name ordinal as an index into the array of name pointers
			// ��Orinal��ֵ��Ϊ�������Ӻ�����ַ����ȡ����������������ĵ�ַ
			uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

			// return the File Offset to the ReflectiveLoader() functions code...
			// ����������������ĵ�ַתΪ�ļ�ƫ�Ƶ�ַ
			return Rva2Offset(DEREF_32(uiAddressArray), uiBaseAddress);
		}
		// get the next exported function name
		// ���û�ҵ�����������ĺ������ƶ�����һ��������������Ԫ��
		uiNameArray += sizeof(DWORD);

		// get the next exported function name ordinal
		// ����Ordinal����� Ordinal = index ����ʽͬ���������������ƶ����ҵ��󼴿ɴ���Ordinal�����Ӻ�����ַ����ȡ����Ӧ�����ĵ�ַ
		uiNameOrdinals += sizeof(WORD);
	}

	return 0;
}

// Loads a PE image from memory into the address space of a host process via the image's exported ReflectiveLoader function
// Note: You must compile whatever you are injecting with REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR 
//       defined in order to use the correct RDI prototypes.
// Note: The hProcess handle must have these access rights: PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
//       PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
// Note: If you are passing in an lpParameter value, if it is a pointer, remember it is for a different address space.
// Note: This function currently cant inject accross architectures, but only to architectures which are the 
//       same as the arch this function is compiled as, e.g. x86->x86 and x64->x64 but not x64->x86 or x86->x64.
HANDLE WINAPI LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter)
{
	BOOL bSuccess = FALSE;
	LPVOID lpRemoteLibraryBuffer = NULL;
	LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;
	HANDLE hThread = NULL;
	DWORD dwReflectiveLoaderOffset = 0;
	DWORD dwThreadId = 0;
	PRTL_CREATE_USER_THREAD RtlCreateUserThread = NULL;

	__try
	{
		do
		{
			if (!hProcess || !lpBuffer || !dwLength)
				break;

			// check if the library has a ReflectiveLoader...
			// ��ȡDLL�з���������������ļ�ƫ�Ƶ�ַ
			dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer);
			if (!dwReflectiveLoaderOffset)
			{
				//OutputDebugString("GetReflectiveLoaderOffset FAILED!");
				wprintf(TEXT("[-] Error: LoadRemoteLibraryR(): GetReflectiveLoaderOffset() Failed! [%d]\n"), GetLastError());
				break;
			}

			// alloc memory (RWX) in the host process for the image...
			// ��Ŀ���������DLL�ļ���С���ڴ�ռ�
			lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, dwLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!lpRemoteLibraryBuffer)
			{
				//OutputDebugString("VirtualAllocEx FAILED!");
				wprintf(TEXT("[-] Error: LoadRemoteLibraryR(): VirtualAllocEx() Failed! [%d]\n"), GetLastError());
				break;
			}

			// write the image into the host process...
			// ��DLL�ļ�д��Ŀ�����������ڴ�ռ���
			if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL))
			{
				//OutputDebugString("WriteProcessMemory FAILED!");
				wprintf(TEXT("[-] Error: LoadRemoteLibraryR(): WriteProcessMemory() Failed! [%d]\n"), GetLastError());
				break;
			}

			// add the offset to ReflectiveLoader() to the remote library address...
			// ��ȡDLL��д��Ŀ������ڴ�ռ����������ĵ�ַ ��Ȼ���ļ�ƫ��
			// ��Ϊ��ֱ�Ӱ�DLLû���ص��ڴ�Ľṹ������д�룬������Ȼ���ļ�ƫ��
			lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset);

			// create a remote thread in the host process to call the ReflectiveLoader!
			//OutputDebugString("INJECTING DLL!");
			// ����Զ���߳������÷������������
			RtlCreateUserThread = (PRTL_CREATE_USER_THREAD)(GetProcAddress(GetModuleHandle(TEXT("ntdll")), "RtlCreateUserThread"));
			RtlCreateUserThread(hProcess, NULL, 0, 0, 0, 0, lpReflectiveLoader, lpParameter, &hThread, NULL);

			if (hThread == NULL)
			{
				//OutputDebugString("Injection FAILED!");
				wprintf(TEXT("[-] Error: LoadRemoteLibraryR(): RtlCreateUserThread() Failed! [%d]\n"), GetLastError());
				break;
			}

			WaitForSingleObject(hThread, INFINITE);

			VirtualFreeEx(hProcess, lpRemoteLibraryBuffer, dwLength, MEM_RELEASE);

		} while (0);

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

		hThread = NULL;
	}

	return hThread;
}
