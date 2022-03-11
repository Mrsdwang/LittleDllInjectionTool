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
	// 获取NT头的地址，也就是PE签名开始的地址
	pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);
	// 获取节区头开始的地址。计算方法为 addr(OptionHeader) + sizeof(OptionHeader)，就能跳过OpitionHeader区域，获得节区头地址
	pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);
	// 如果需要进行RVA转化成Offset的RVA小于第一个节区的文件起始地址，就返回。因为RVA小于，那么就不可能是节区的数据，不需要转换。
	if (dwRva < pSectionHeader[0].PointerToRawData)
		return dwRva;

	//以上就是获取节区地址
	// 有多少节区就循环多少次
	for (wIndex = 0; wIndex < pNtHeaders->FileHeader.NumberOfSections; wIndex++)
	{
		// 如果要转换的RVA大于等于该节区在内存中的起始地址,并且需要转换的RVA小于节区在内存中的起始地址加上该节区在磁盘中的大小就返回转化值
		// 第二个条件，是因为VirtualSize要小于SizeofRawData才能避免转换到错误节区，因此这个条件是假设该节区Image的大小等于在文件的大小，最大程度确保转换的RVA在这个节区的地址里面
		if (dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData))
			// 根据计算公式 Offset = RVA - VirtualAddress + PointerToRawData
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
	// 将DLL文件写入的堆地址，也就是写入内存堆的DLL文件的起始地址
	uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;

	// get the File Offset of the modules NT Header
	// 获取DLL文件的NT Header 的文件偏移，也就是PE签名开头的地址
	uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

	// currenlty we can only process a PE file which is the same type as the one this fuction has  
	// been compiled as, due to various offset in the PE structures being defined at compile time.

	// 通过NT头的可选头的Magic字段判断是为32还是64
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
	// 因为是直接以文件形式把整个DLL文件加载到内存，所以仍然是文件结构，而不是DLL通过加载到内存后的image结构，所以要计算文件偏移
	// uiNameArray = the address of the modules export directory entry
	// 获取可选头中的导出表地址
	uiNameArray = (UINT_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	// get the File Offset of the export directory
	// 获取IMAGE_EXPORT_DIRECTORY结构体的地址
	uiExportDir = uiBaseAddress + Rva2Offset(((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress);

	// get the File Offset for the array of name pointers
	// 获取着DLL导出函数名称的数组文件偏移
	uiNameArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames, uiBaseAddress);

	// get the File Offset for the array of addresses
	// 获取DLL导出函数地址数组的文件偏移
	uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);

	// get the File Offset for the array of name ordinals
	// 获取DLL导出函数Ordinals数组的文件偏移
	uiNameOrdinals = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals, uiBaseAddress);

	// get a counter for the number of exported functions...
	// 获取导出函数的数量
	dwCounter = ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->NumberOfNames;

	// loop through all the exported functions to find the ReflectiveLoader
	// 遍历所有导出函数寻找反射加载器函数
	while (dwCounter--)
	{
		// 获取导出函数名称，导出函数名称数组保存的是函数名称字符串保存的地址，因此还需要第二次转换字符串保存的地址为文件偏移
		char* cpExportedFunctionName = (char*)(uiBaseAddress + Rva2Offset(DEREF_32(uiNameArray), uiBaseAddress));
		// 如果导出函数名称数组中能找到字符串"ReflectiveLoader"
		if (strstr(cpExportedFunctionName, "ReflectiveLoader") != NULL)
		{
			// get the File Offset for the array of addresses
			// 当找到反射加载器函数后，就获取函数地址表文件偏移(前面不是求了吗，为什么在写一次？)
			uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);

			// use the functions name ordinal as an index into the array of name pointers
			// 以Orinal的值作为索引，从函数地址数组取出反射加载器函数的地址
			uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

			// return the File Offset to the ReflectiveLoader() functions code...
			// 将反射加载器函数的地址转为文件偏移地址
			return Rva2Offset(DEREF_32(uiAddressArray), uiBaseAddress);
		}
		// get the next exported function name
		// 如果没找到反射加载器的函数就移动到下一个函数名称数组元素
		uiNameArray += sizeof(DWORD);

		// get the next exported function name ordinal
		// 根绝Ordinal数组的 Ordinal = index 的形式同步函数名称数组移动，找到后即可从以Ordinal索引从函数地址数组取出相应函数的地址
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
			// 获取DLL中反射加载器函数的文件偏移地址
			dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer);
			if (!dwReflectiveLoaderOffset)
			{
				//OutputDebugString("GetReflectiveLoaderOffset FAILED!");
				wprintf(TEXT("[-] Error: LoadRemoteLibraryR(): GetReflectiveLoaderOffset() Failed! [%d]\n"), GetLastError());
				break;
			}

			// alloc memory (RWX) in the host process for the image...
			// 在目标进程申请DLL文件大小的内存空间
			lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, dwLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!lpRemoteLibraryBuffer)
			{
				//OutputDebugString("VirtualAllocEx FAILED!");
				wprintf(TEXT("[-] Error: LoadRemoteLibraryR(): VirtualAllocEx() Failed! [%d]\n"), GetLastError());
				break;
			}

			// write the image into the host process...
			// 将DLL文件写入目标进程申请的内存空间中
			if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL))
			{
				//OutputDebugString("WriteProcessMemory FAILED!");
				wprintf(TEXT("[-] Error: LoadRemoteLibraryR(): WriteProcessMemory() Failed! [%d]\n"), GetLastError());
				break;
			}

			// add the offset to ReflectiveLoader() to the remote library address...
			// 获取DLL被写入目标进程内存空间后反射加载器的地址 仍然是文件偏移
			// 因为是直接把DLL没加载到内存的结构和内容写入，所以仍然是文件偏移
			lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset);

			// create a remote thread in the host process to call the ReflectiveLoader!
			//OutputDebugString("INJECTING DLL!");
			// 创建远程线程来调用反射加载器函数
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
