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
#include "pch.h"
//===============================================================================================//
// Our loader will set this to a pseudo correct HINSTANCE/HMODULE value
HINSTANCE hAppInstance = NULL;
//===============================================================================================//
#pragma intrinsic( _ReturnAddress )
// This function can not be inlined by the compiler or we will not get the address we expect. Ideally 
// this code will be compiled with the /O2 and /Ob1 switches. Bonus points if we could take advantage of 
// RIP relative addressing in this instance but I dont believe we can do so with the compiler intrinsics 
// available (and no inline asm available under x64).
// ���ⱻ�����������Ż���
//_ReturnAddress���� ���ظú������ں����ķ��ص�ַ��Ҳ���Ƿ���caller�����ķ��ص�ַ��Ҳ���ǵ���caller����ָ�����ڵ�ַ����һ��ָ���ַ
__declspec(noinline) ULONG_PTR caller(VOID) { return (ULONG_PTR)_ReturnAddress(); }
//===============================================================================================//

// Note 1: If you want to have your own DllMain, define REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN,  
//         otherwise the DllMain at the end of this file will be used.
// �������������Լ���DllMain,����Ҫ����REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN
// �����ִ������ļ�������DllMain
// 
// Note 2: If you are injecting the DLL via LoadRemoteLibraryR, define REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR,
//         otherwise it is assumed you are calling the ReflectiveLoader via a stub.
// �������ͨ��LoadRemoteLibraryRע��DLL������REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
// ��������������ͨ��Shellcode����ReflectiveLoader
// �������� �궼�Ѿ�����Ŀ->C/C++->Ԥ������->Ԥ���������������

// This is our position independent reflective DLL loader/injector
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpParameter)
#else
DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(VOID)
#endif
{
	// the functions we need
	// ��������ĺ���
	LOADLIBRARYA pLoadLibraryA = NULL;
	GETPROCADDRESS pGetProcAddress = NULL;
	VIRTUALALLOC pVirtualAlloc = NULL;
	NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = NULL;

	USHORT usCounter;

	// the initial location of this image in memory
	ULONG_PTR uiLibraryAddress;
	// the kernels base address and later this images newly loaded base address
	ULONG_PTR uiBaseAddress;

	// variables for processing the kernels export table
	ULONG_PTR uiAddressArray;
	ULONG_PTR uiNameArray;
	ULONG_PTR uiExportDir;
	ULONG_PTR uiNameOrdinals;
	DWORD dwHashValue;

	// variables for loading this image
	ULONG_PTR uiHeaderValue;
	ULONG_PTR uiValueA;
	ULONG_PTR uiValueB;
	ULONG_PTR uiValueC;
	ULONG_PTR uiValueD;
	ULONG_PTR uiValueE;

	// STEP 0: calculate our images current base address
	// ���� 0: ����Images��ǰ�Ļ�ַ
	// we will start searching backwards from our callers return address.
	// ͨ������_ReturnAddress ���ص�ǰָ�����һ��ָ���ַ
	uiLibraryAddress = caller();

	// loop through memory backwards searching for our images base address
	// we dont need SEH style search as we shouldnt generate any access violations with this
	// ���ǲ���Ҫ�쳣������Ʒ�����������Ϊ���ǲ�Ӧ��ͨ��������������κη����쳣
	while (TRUE)
	{
		// ���������ַ�ҵ���DLL�ļ��Ļ�ַ��Ҳ����MZǩ����
		if (((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_magic == IMAGE_DOS_SIGNATURE)
		{
			// ��ȡDLL�ļ���NTͷ��ʼ��ַ��PEǩ��
			uiHeaderValue = ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;
			// some x64 dll's can trigger a bogus signature (IMAGE_DOS_SIGNATURE == 'POP r10'),
			// һЩx64��dll���ܴ�����ٵ�ǩ������Ϊpop r10�Ķ����Ʊ�ʾΪ4D5AҲ��(MZ�ַ�)��ASIIC���룬������;�����pop r10�������������ж�ΪMZǩ��
			// we sanity check the e_lfanew with an upper threshold value of 1024 to avoid problems.

			// �����ȡ��NTͷ��ʼ��ַ����DOSͷ�Ĵ�С�����ҵ�ַС��1024(D)=400(h)��Ӧ����С�ڵ�һ��������ʼ�ĵ�ַ
			if (uiHeaderValue >= sizeof(IMAGE_DOS_HEADER) && uiHeaderValue < 1024)
			{
				// ����ҵ�����ȷ�����Ǽӵ�MZǩ������ô��ʱuiHeaderValueΪPEǩ����RVA����uiLibraryAddressΪ��ַ
				// ���ǩ����ȷ���������������if��������˳���uiLibraryAddress����������ַ
				uiHeaderValue += uiLibraryAddress;
				// break if we have found a valid MZ/PE header
				if (((PIMAGE_NT_HEADERS)uiHeaderValue)->Signature == IMAGE_NT_SIGNATURE)
					break;
			}
		}
		// û���ҵ�MZǩ���Ǿͼ���������ַ
		uiLibraryAddress--;
	}

	// STEP 1: process the kernels exports for the functions our loader needs...
	// ���� 1: �������Ǽ�������Ҫ�ĺ��ĵ�������
	// get the Process Enviroment Block
	// ��ȡPEB��ͨ����ȡGS�Ĵ�����0X60ƫ��(X64���� FS�Ĵ�����0X30ƫ��(X86)��Ҳ����PEB�ṹ���ָ��
#ifdef _WIN64
	uiBaseAddress = __readgsqword(0x60);
#else
#ifdef _WIN32
	uiBaseAddress = __readfsdword(0x30);

#endif
#endif

	// get the processes loaded modules. ref: http://msdn.microsoft.com/en-us/library/aa813708(VS.85).aspx
	// ��ȡ���̼��ص�DLL����Ϣ
	uiBaseAddress = (ULONG_PTR)((_PPEB)uiBaseAddress)->pLdr;

	// get the first entry of the InMemoryOrder module list
	// ��ȡInMemoryOrder ����ĵ�һ��ģ������
	uiValueA = (ULONG_PTR)((PPEB_LDR_DATA)uiBaseAddress)->InMemoryOrderModuleList.Flink;
	while (uiValueA)
	{
		// get pointer to current modules name (unicode string)
		// �����uiValueA����ע�͵��˵�һ����Ա����ΪʲôBaseDllName����ԭ��ַ������ǰһ����Ա�ı����أ�
		// �ѵ�ת�����ͺ�Ӧ���Զ� �İѽṹ���һ����Ա��������ʼ��ַ��������Ҳ����InMemoryOrderModule�ĳ�Ա�����InLoadLinks������
		// ��ȡ��ǰDLL������
		uiValueB = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->BaseDllName.pBuffer;
		// set bCounter to the length for the loop
		// ��ȡDLL���Ƶĳ���
		usCounter = ((PLDR_DATA_TABLE_ENTRY)uiValueA)->BaseDllName.Length;
		// clear uiValueC which will store the hash of the module name
		// DLL���Ʊ�����uiValueC��
		uiValueC = 0;

		// compute the hash of the module name...
		// ����DLL��Hash�������do-while���ڽ���Hashֵ�ļ���
		do
		{
			// ��uiValueCѭ������13λ
			uiValueC = ror((DWORD)uiValueC);
			// normalize to uppercase if the madule name is in lowercase
			// ��DLL���е�Сд��ĸ���д��Ȼ����uiValueC������ЩUNICODE��
			if (*((BYTE*)uiValueB) >= 'a')
				uiValueC += *((BYTE*)uiValueB) - 0x20;
			else
				uiValueC += *((BYTE*)uiValueB);
			uiValueB++;
		} while (--usCounter);

		// compare the hash with that of kernel32.dll
		// �����DLL��Hashֵ��KERNEL32.DLL����ͬ
		if ((DWORD)uiValueC == KERNEL32DLL_HASH)
		{
			// get this modules base address
			// ��ȡDLL�Ļ�ַ
			uiBaseAddress = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->DllBase;

			// get the VA of the modules NT Header
			// ��ȡDLL��NTͷ
			uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

			// uiNameArray = the address of the modules export directory entry
			// ��ȡDLL�ĵ�������ڵ�ַ
			uiNameArray = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

			// get the VA of the export directory
			// ��ȡ�������VA
			uiExportDir = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

			// get the VA for the array of name pointers
			// ��ȡ�������������������ʼ��ַ
			uiNameArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames);

			// get the VA for the array of name ordinals
			// ��ȡ��������Ordinals�������ʼ��ַ
			uiNameOrdinals = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals);
			// ���3����������KERNEL32.DLL����Ҫ�ĺ���������
			usCounter = 3;

			// loop while we still have imports to find
			while (usCounter > 0)
			{
				// compute the hash values for this function name
				// ���㺯�����ַ����ĵ�ַ��Hashֵ
				dwHashValue = hash((char*)(uiBaseAddress + DEREF_32(uiNameArray)));

				// if we have found a function we want we get its virtual address
				// ����ҵ���������Ҫ�ĺ�������ô�ͻ�ȡ���ǵ�VA
				// ��Ҫ�ĺ�����LoadLibraryA,GetProcAddress,VirtualAlloc
				if (dwHashValue == LOADLIBRARYA_HASH || dwHashValue == GETPROCADDRESS_HASH || dwHashValue == VIRTUALALLOC_HASH)
				{
					// get the VA for the array of addresses
					// ��õ���������ַ����ĵ�ַ
					uiAddressArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

					// use this functions name ordinal as an index into the array of name pointers
					// ʹ��ordinal��Ϊ������ȡ���躯���ĵ�ַ
					uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

					// store this functions VA
					// �������躯���ĵ�ַ
					if (dwHashValue == LOADLIBRARYA_HASH)
						pLoadLibraryA = (LOADLIBRARYA)(uiBaseAddress + DEREF_32(uiAddressArray));
					else if (dwHashValue == GETPROCADDRESS_HASH)
						pGetProcAddress = (GETPROCADDRESS)(uiBaseAddress + DEREF_32(uiAddressArray));
					else if (dwHashValue == VIRTUALALLOC_HASH)
						pVirtualAlloc = (VIRTUALALLOC)(uiBaseAddress + DEREF_32(uiAddressArray));

					// decrement our counter
					// �ҵ���Ҫ�ĺ����ͽ�������һ
					usCounter--;
				}

				// get the next exported function name
				// ȡ����һ��������������
				uiNameArray += sizeof(DWORD);

				// get the next exported function name ordinal
				// ordinalsͬ�������Ա�����ȡ��������ַ������
				uiNameOrdinals += sizeof(WORD);
			}
		}
		// ���DLL��Hashֵ��ntdll.dll����ͬ
		// ����Ĳ�����kernel32.dll����ͬ�Ͳ���׸��
		else if ((DWORD)uiValueC == NTDLLDLL_HASH)
		{
			// get this modules base address
			uiBaseAddress = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->DllBase;

			// get the VA of the modules NT Header
			uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

			// uiNameArray = the address of the modules export directory entry
			uiNameArray = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

			// get the VA of the export directory
			uiExportDir = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

			// get the VA for the array of name pointers
			uiNameArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames);

			// get the VA for the array of name ordinals
			uiNameOrdinals = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals);

			usCounter = 1;

			// loop while we still have imports to find
			while (usCounter > 0)
			{
				// compute the hash values for this function name
				dwHashValue = hash((char*)(uiBaseAddress + DEREF_32(uiNameArray)));

				// if we have found a function we want we get its virtual address
				// �ҵ�����NtFlushInStructionCache��ͻ�ȡ���ĵ�ַ
				if (dwHashValue == NTFLUSHINSTRUCTIONCACHE_HASH)
				{
					// get the VA for the array of addresses
					uiAddressArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

					// use this functions name ordinal as an index into the array of name pointers
					uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

					// store this functions VA
					if (dwHashValue == NTFLUSHINSTRUCTIONCACHE_HASH)
						pNtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE)(uiBaseAddress + DEREF_32(uiAddressArray));

					// decrement our counter
					usCounter--;
				}

				// get the next exported function name
				uiNameArray += sizeof(DWORD);

				// get the next exported function name ordinal
				uiNameOrdinals += sizeof(WORD);
			}
		}

		// we stop searching when we have found everything we need.
		// ���ҵ�������Ҫ�ĺ�����ֹͣ
		if (pLoadLibraryA && pGetProcAddress && pVirtualAlloc && pNtFlushInstructionCache)
			break;

		// get the next entry
		// ˫������FlinkΪ��һ���ڵ�ĵ�ַ����DEREFΪ*(UINT_PTR*)ȡFlinkָ��ָ��ĵ�ַ��ֵ��Ҳ������һ���ڵ�ĵ�ַ
		uiValueA = DEREF(uiValueA);
	}

	// STEP 2: load our image into a new permanent location in memory...
	// ���� 2: ��Image���ص��ڴ������ʱ����
	// get the VA of the NT Header for the PE to be loaded
	// ��ȡDLL�ļ���NTͷ��ַ
	// ��ʱuiLibraryAddress��������DLL�ļ��Ļ�ַ
	// uiHeaderValue ΪҪ����DLL��NTͷ��ַ
	uiHeaderValue = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

	// allocate all the memory for the DLL to be loaded into. we can load at any address because we will  
	// relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
	//���ǿ������κε�ַ�����㹻��DLL�ڴ�������DLL�ļ�����Ϊ���ǽ���Image�ض�λ���������ڴ����㲢���ÿɶ�дִ�е�Ȩ�ޱ�����ܵ�����
	//ͨ����ȡDLL�ļ���SizeOfImage�������㹻���ڴ�
	uiBaseAddress = (ULONG_PTR)pVirtualAlloc(NULL, ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// we must now copy over the headers
	uiValueA = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders;
	uiValueB = uiLibraryAddress; //��ʱΪDLL�ļ���ַ
	uiValueC = uiBaseAddress; //ΪDLL�ļ�Image������ڴ�Ļ�ַ
	// ��ΪImage������ڴ��ַ��ʼ����DLL��PE�ļ�ͷ
	while (uiValueA--)
		*(BYTE*)uiValueC++ = *(BYTE*)uiValueB++;

	// STEP 3: load in all of our sections...
	// ���� 3: ����DLL���еĽ��� 
	// uiValueA = the VA of the first section
	// ��ȡ��һ������ͷ����ʼ��ַ
	uiValueA = ((ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader + ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader);

	// itterate through all sections, loading them into memory.
	// ��ȡ��������
	uiValueE = ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections;
	while (uiValueE--)
	{
		// uiValueB is the VA for this section
		// ��λ��ΪDLL�ļ�������ڴ�ռ��еĸý����ĵ�ַ
		uiValueB = (uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress);

		// uiValueC if the VA for this sections data
		// ��ȡ�ý������ļ�ƫ��
		uiValueC = (uiLibraryAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->PointerToRawData);

		// copy the section over
		// ��ȡ�����������ļ�ʱ�Ĵ�С
		uiValueD = ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData;
		// ���������ݸ��Ƶ�ΪDLL�ļ�������ڴ��иý������ڴ�
		while (uiValueD--)
			*(BYTE*)uiValueB++ = *(BYTE*)uiValueC++;

		// get the VA of the next section
		// ��ȡ��һ������ͷ����ʼ��ַ
		uiValueA += sizeof(IMAGE_SECTION_HEADER);
	}

	// STEP 4: process our images import table...
	// ���� 4: ����Image�ĵ�������޸�IAT
	// uiValueB = the address of the import directory
	//��ñ��浼�����Ϣ�ĵ�ַ
	uiValueB = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	// we assume their is an import table to process
	// uiValueC is the first entry in the import table
	// ������ڵ����
	// ��ȡ�������ʼ��ַ(IDT�ĵ�ַ)
	uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

	// itterate through all imports
	// ��������IDT��IID�ṹ��
	while (((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name)
	{
		// use LoadLibraryA to load the imported module into memory
		// ��ȡDLL�����ַ����ı����ַ��ͨ��LoadLibraryA�������DLL���ص��ڴ�
		// uiLibraryAddress ���ǵ����DLL���ص��ڴ��ĵ�ַ
		uiLibraryAddress = (ULONG_PTR)pLoadLibraryA((LPCSTR)(uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name));

		// uiValueD = VA of the OriginalFirstThunk
		// ��ȡ����INT�����ַ�ĵ�ַ
		uiValueD = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->OriginalFirstThunk);

		// uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
		// ��ȡ����IAT�����ַ�ĵ�ַ
		uiValueA = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->FirstThunk);

		// itterate through all imported functions, importing by ordinal if no name present
		// �������е��뺯�����������û��������ͨ��Ordinal����
		while (DEREF(uiValueA))
		{
			// sanity check uiValueD as some compilers only import by FirstThunk
			// ��ΪһЩ��������ͨ��IAT���룬���Ҫ��uiValueD���н�׳�Լ��
			// uiValueD��Ϊ��
			// IMAGE_ORDINAL_FLAGE = 0x80000000 ,���û��ڴ�ռ�Ϊ0x0 - 0x7FFFFFFF��
			//�涨���PIMAGE_THUNK_DATA��ԱΪOrdinalʱ�����λΪ1�ҵ�16λΪOrdinal�����ΪAddressOfData�����λΪ0
			// ��������Ordinal��0x80000000���벻Ϊ0˵����Ordinal��Ϊ0˵����AddressOfData
			// ������ú�����ͨ��Ordinal������������Ƶ���
			if (uiValueD && ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// get the VA of the modules NT Header
				// ��ȡ�������ڴ��DLL�ļ���NTͷ��ַ
				uiExportDir = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

				// uiNameArray = the address of the modules export directory entry
				// ���DLL�������ַ
				uiNameArray = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

				// get the VA of the export directory
				// ��ȡDLL���������ڵ�ַ
				uiExportDir = (uiLibraryAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

				// get the VA for the array of addresses
				// ��ȡ����������ַ�����ַ
				uiAddressArray = (uiLibraryAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

				// use the import ordinal (- export ordinal base) as an index into the array of addresses
				// ͨ��Ordinal��ȡDLL����������ַ,����INT��Ordinal�������е��뺯������ţ�Ҫ�任����������DLL����������Ҫ��Ordinal��Base
				uiAddressArray += ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal) - ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->Base) * sizeof(DWORD));

				// patch in the address for this imported function
				// ��ȡ������ַ��д��IAT��
				DEREF(uiValueA) = (uiLibraryAddress + DEREF_32(uiAddressArray));
			}
			// ���������ͨ�����Ƶ���
			else
			{
				// get the VA of this functions import by name struct
				// ��ȡIAT���������ʼλ��
				uiValueB = (uiBaseAddress + DEREF(uiValueA));

				// use GetProcAddress and patch in the address for this imported function
				// ʹ��GetProcAddress���������뵽uiLibraryAddress��ַ��DLL�л�ȡ�ú����ĵ�ַ����д��IAT��
				DEREF(uiValueA) = (ULONG_PTR)pGetProcAddress((HMODULE)uiLibraryAddress, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name);
			}
			// get the next imported function
			// IATָ�����
			uiValueA += sizeof(ULONG_PTR);
			// INTָ�����
			if (uiValueD)
				uiValueD += sizeof(ULONG_PTR);
			// ��Ϊ��PE�ļ�δ�����ص��ڴ�ǰIAT��INT��ͬ����PE�ļ������ڴ�����������INT��IAT����һ��,IAT���浼�뺯����ַ��INT��Ȼ��Ordinal��IIBN�ṹ��
		}

		// get the next import
		// ָ��ָ����һ��IID�ṹ�壬ÿ����һ��DLL�ļ��ͻ���һ��IID�ṹ�壬���Ҳ��ָ����һ��DLL
		uiValueC += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}

	// STEP 5: process all of our images relocations...
	// ���� 5: ����Images���ض�λ
	// calculate the base address delta and perform relocations (even if we load at desired image base)
	// �����ַ������ִ���ض�λ(��ʹ���ص���������Image��ַ
	// ΪĿ��DLL�ļ�������ڴ�ռ�Ļ�ַ - Ŀ��DLL�ļ���ImageBase(ָ��DLL�ļ����ȼ��صĵ�ַ,ΪRVA)
	// Ϊʲô���������ΪImageBaseΪRVA�����������ض�λ������µ�RVA
	// ��Ҳ�Ǽ��������ض�λʱ��Ҫ���ģ������������ض�λ��,�ҵ�Ҫ���������ݣ�
	// Ȼ����(ʵ��Image��ַ - DLLĬ��ImageBase) + �ض�λ���ݵ�ַ(�ں�����)�����ʽ�����ض�λ
	uiLibraryAddress = uiBaseAddress - ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;

	// uiValueB = the address of the relocation directory
	// ��ȡ�ض�λ���ַ
	uiValueB = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	// check if their are any relocations present
	// ����ض�λ����ڣ�Size�Ͳ�Ϊ0
	if (((PIMAGE_DATA_DIRECTORY)uiValueB)->Size)
	{
		// uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
		// ��ȡ�ض�λ�����ʼ��ַ
		uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

		// and we itterate through all entries...
		// �����ض�λ��
		while (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock)
		{
			// uiValueA = the VA for this relocation block
			// ��ȡ���ض�λ��������ַ
			uiValueA = (uiBaseAddress + ((PIMAGE_BASE_RELOCATION)uiValueC)->VirtualAddress);

			// uiValueB = number of entries in this relocation block
			// SizeOfBlock �Ǹ��ض�λ��Ĵ�С������IMAGE_BASE_RELOCATION�ṹ�� + ��¼ƫ��������ƫ�Ƶ�ַ��TypeOffSet����
			// TypeOffset Ϊ2�ֽڣ���4λ�����ض�λ���ͣ���12λ����ƫ�Ƶ�ַ��ƫ�Ƶ�ַ+VirtualAddress��Ϊ�ض�λ�ĵ�ַ
			// [SizeOfBlock - �ṹ��Ĵ�Сsizeof(IMAGE_BASE_RELOCATION)] / ���ֽ� = TypeOffset����Ԫ�ص�����
			uiValueB = (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

			// uiValueD is now the first entry in the current relocation block
			// ��ȡ��ǰ�ض�λ���TypeOffset����ĵ�һ��Ԫ�صĵ�ַ
			uiValueD = uiValueC + sizeof(IMAGE_BASE_RELOCATION);

			// we itterate through all the entries in the current block...
			// ������ǰ�ض�λ�������TypeOffset����Ԫ��
			while (uiValueB--)
			{
				// perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
				// we dont use a switch statement to avoid the compiler building a jump table
				// which would not be very position independent!
				// ִ���ض�λ���������� IMAGE_REL_BASED_ABSOLUTE(�ض�λ����,���ر����壬ֻ��Ϊ����ÿ����4�ֽڶ��룬����������ã����沢û������)
				// ��ʹ��switch���ʽ���������������һ��λ�ò�����ô��������ת��?????

				//IMAGE_REL_BASED_DIR64(�ض�λ����,��ָ���������ַ��������
				//(ʵ��Image��ַ - DLLĬ��ImageBase) + �ض�λ���ݵ�ַ(RVA)
				// ����uiLibraryAddress Ϊ(ʵ��Image��ַ - DLLĬ��ImageBase),
				// �ض�λ���ݵ�ַ(RVA) = uiValueA + uiValueD->offset = VirtualAddress + offset
				if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_DIR64)
					//���� IMAGE_BASE_RELOCATION + offset = �ض�λ���RVA��ַ��Ȼ���RVA��ַ��ֵ + uiLibraryAddress = �ض�λ�����ڴ��VA
					*(ULONG_PTR*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += uiLibraryAddress;
				// ͬ�ϣ��������ض�λ���Ͷ��Ƕ�ָ���������ַ������������һ��x64һ��x86
				// Ҳ����ע�⵽��ͬ���ض�λ����ֻ��Ӱ���ַȡ����λ
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGHLOW)
					*(DWORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += (DWORD)uiLibraryAddress;
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGH)
					*(WORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += HIWORD(uiLibraryAddress);
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_LOW)
					*(WORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += LOWORD(uiLibraryAddress);

				// get the next entry in the current relocation block
				// ��ȡ���ض�λ�����һ��TypeOffset����Ԫ��
				uiValueD += sizeof(IMAGE_RELOC);
			}

			// get the next entry in the relocation directory
			// ��ȡ��һ���ض�λ��
			uiValueC = uiValueC + ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock;
		}
	}

	// STEP 6: call our images entry point
	// ���� 6: ����Images����ڵ�
	// uiValueA = the VA of our newly loaded DLL/EXE's entry point
	// uiValueA Ϊ DLL�ļ�PEͷ��¼����ڵ��ַ
	uiValueA = (uiBaseAddress + ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.AddressOfEntryPoint);

	// We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
	// ����ˢ��ָ���������ʹ�ñ��������ض�λ���̸��µľɴ���
	// ���ǳ����ָ���ڱ����Ͳ���ı䣬�������������������µ�DLL�󣬳���ͻ������µ�ָ��
	// �������ָ����ĺ�ͨ���ú�������ˢ��CPU����CPU���Զ�ȡ��ִ���µ�ָ��
	pNtFlushInstructionCache((HANDLE)-1, NULL, 0);

	// call our respective entry point, fudging our hInstance value
	// ���ø��Ե���ڵ㣬����hInstance��ֵ��
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
	// if we are injecting a DLL via LoadRemoteLibraryR we call DllMain and pass in our parameter (via the DllMain lpReserved parameter)
	// ���ͨ��LoadRemoteLibraryR����ע��DLL�����Ե���DllMain��ͨ��DllMain��lpReserved�����������ǵĲ���
	((DLLMAIN)uiValueA)((HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, lpParameter);
#else
	// if we are injecting an DLL via a stub we call DllMain with no parameter
	((DLLMAIN)uiValueA)((HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, NULL);
#endif

	// STEP 8: return our new entry point address so whatever called us can call DllMain() if needed.
	// ���÷�������������µ�DLL��ڵ�ַ�Ա��ܵ���DllMain()
	return uiValueA;
}
//===============================================================================================//
#ifndef REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	BOOL bReturnValue = TRUE;
	switch (dwReason)
	{
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
			*(HMODULE*)lpReserved = hAppInstance;
		break;
	case DLL_PROCESS_ATTACH:
		hAppInstance = hinstDLL;
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}

#endif
//===============================================================================================//