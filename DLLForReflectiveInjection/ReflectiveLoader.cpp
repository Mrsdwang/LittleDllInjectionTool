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
// 避免被编译器内联优化，
//_ReturnAddress函数 返回该函数所在函数的返回地址，也就是返回caller函数的返回地址，也就是调用caller函数指令所在地址的下一条指令地址
__declspec(noinline) ULONG_PTR caller(VOID) { return (ULONG_PTR)_ReturnAddress(); }
//===============================================================================================//

// Note 1: If you want to have your own DllMain, define REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN,  
//         otherwise the DllMain at the end of this file will be used.
// 如果你想调用你自己的DllMain,就需要定义REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN
// 否则会执行这个文件最后面的DllMain
// 
// Note 2: If you are injecting the DLL via LoadRemoteLibraryR, define REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR,
//         otherwise it is assumed you are calling the ReflectiveLoader via a stub.
// 如果你想通过LoadRemoteLibraryR注入DLL，定义REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
// 否则程序会假设你会通过Shellcode调用ReflectiveLoader
// 以上两个 宏都已经在项目->C/C++->预处理器->预处理器定义中添加

// This is our position independent reflective DLL loader/injector
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpParameter)
#else
DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(VOID)
#endif
{
	// the functions we need
	// 定义所需的函数
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
	// 步骤 0: 计算Images当前的基址
	// we will start searching backwards from our callers return address.
	// 通过函数_ReturnAddress 返回当前指令的下一条指令地址
	uiLibraryAddress = caller();

	// loop through memory backwards searching for our images base address
	// we dont need SEH style search as we shouldnt generate any access violations with this
	// 我们不需要异常处理机制风格的搜索，因为我们不应该通过这个方法产生任何访问异常
	while (TRUE)
	{
		// 如果遍历地址找到了DLL文件的基址，也就是MZ签名处
		if (((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_magic == IMAGE_DOS_SIGNATURE)
		{
			// 获取DLL文件的NT头起始地址，PE签名
			uiHeaderValue = ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;
			// some x64 dll's can trigger a bogus signature (IMAGE_DOS_SIGNATURE == 'POP r10'),
			// 一些x64的dll可能触发虚假的签名，因为pop r10的二进制表示为4D5A也即(MZ字符)的ASIIC编码，所以中途如果有pop r10则可能引起错误判断为MZ签名
			// we sanity check the e_lfanew with an upper threshold value of 1024 to avoid problems.

			// 如果获取的NT头起始地址大于DOS头的大小，并且地址小于1024(D)=400(h)，应该是小于第一个节区开始的地址
			if (uiHeaderValue >= sizeof(IMAGE_DOS_HEADER) && uiHeaderValue < 1024)
			{
				// 如果找到了正确而不是加的MZ签名，那么此时uiHeaderValue为PE签名的RVA，而uiLibraryAddress为基址
				// 因此签名正确，则则满足下面的if，否则就退出，uiLibraryAddress继续减至基址
				uiHeaderValue += uiLibraryAddress;
				// break if we have found a valid MZ/PE header
				if (((PIMAGE_NT_HEADERS)uiHeaderValue)->Signature == IMAGE_NT_SIGNATURE)
					break;
			}
		}
		// 没有找到MZ签名那就继续遍历地址
		uiLibraryAddress--;
	}

	// STEP 1: process the kernels exports for the functions our loader needs...
	// 步骤 1: 处理我们加载器需要的核心导出函数
	// get the Process Enviroment Block
	// 获取PEB，通过读取GS寄存器的0X60偏移(X64）或 FS寄存器的0X30偏移(X86)，也就是PEB结构体的指针
#ifdef _WIN64
	uiBaseAddress = __readgsqword(0x60);
#else
#ifdef _WIN32
	uiBaseAddress = __readfsdword(0x30);

#endif
#endif

	// get the processes loaded modules. ref: http://msdn.microsoft.com/en-us/library/aa813708(VS.85).aspx
	// 获取进程加载的DLL的信息
	uiBaseAddress = (ULONG_PTR)((_PPEB)uiBaseAddress)->pLdr;

	// get the first entry of the InMemoryOrder module list
	// 获取InMemoryOrder 链表的第一个模块的入口
	uiValueA = (ULONG_PTR)((PPEB_LDR_DATA)uiBaseAddress)->InMemoryOrderModuleList.Flink;
	while (uiValueA)
	{
		// get pointer to current modules name (unicode string)
		// 这里的uiValueA不是注释掉了第一个成员，那为什么BaseDllName还是原地址而不是前一个成员的变量呢？
		// 难道转换类型后不应该自动 的把结构体第一个成员保存着起始地址的数据吗，也就是InMemoryOrderModule的成员存的是InLoadLinks的数据
		// 获取当前DLL的名称
		uiValueB = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->BaseDllName.pBuffer;
		// set bCounter to the length for the loop
		// 获取DLL名称的长度
		usCounter = ((PLDR_DATA_TABLE_ENTRY)uiValueA)->BaseDllName.Length;
		// clear uiValueC which will store the hash of the module name
		// DLL名称保存在uiValueC中
		uiValueC = 0;

		// compute the hash of the module name...
		// 计算DLL的Hash，下面的do-while就在进行Hash值的计算
		do
		{
			// 将uiValueC循环右移13位
			uiValueC = ror((DWORD)uiValueC);
			// normalize to uppercase if the madule name is in lowercase
			// 把DLL名中的小写字母变大写，然后用uiValueC加上这些UNICODE码
			if (*((BYTE*)uiValueB) >= 'a')
				uiValueC += *((BYTE*)uiValueB) - 0x20;
			else
				uiValueC += *((BYTE*)uiValueB);
			uiValueB++;
		} while (--usCounter);

		// compare the hash with that of kernel32.dll
		// 如果该DLL的Hash值与KERNEL32.DLL的相同
		if ((DWORD)uiValueC == KERNEL32DLL_HASH)
		{
			// get this modules base address
			// 获取DLL的基址
			uiBaseAddress = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->DllBase;

			// get the VA of the modules NT Header
			// 获取DLL的NT头
			uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

			// uiNameArray = the address of the modules export directory entry
			// 获取DLL的导出表入口地址
			uiNameArray = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

			// get the VA of the export directory
			// 获取导出表的VA
			uiExportDir = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

			// get the VA for the array of name pointers
			// 获取导出函数名称数组的起始地址
			uiNameArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames);

			// get the VA for the array of name ordinals
			// 获取导出函数Ordinals数组的起始地址
			uiNameOrdinals = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals);
			// 这个3的是我们在KERNEL32.DLL中需要的函数的数量
			usCounter = 3;

			// loop while we still have imports to find
			while (usCounter > 0)
			{
				// compute the hash values for this function name
				// 计算函数名字符串的地址的Hash值
				dwHashValue = hash((char*)(uiBaseAddress + DEREF_32(uiNameArray)));

				// if we have found a function we want we get its virtual address
				// 如果找到了我们需要的函数，那么就获取他们的VA
				// 需要的函数有LoadLibraryA,GetProcAddress,VirtualAlloc
				if (dwHashValue == LOADLIBRARYA_HASH || dwHashValue == GETPROCADDRESS_HASH || dwHashValue == VIRTUALALLOC_HASH)
				{
					// get the VA for the array of addresses
					// 获得导出函数地址数组的地址
					uiAddressArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

					// use this functions name ordinal as an index into the array of name pointers
					// 使用ordinal作为索引获取所需函数的地址
					uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

					// store this functions VA
					// 保存所需函数的地址
					if (dwHashValue == LOADLIBRARYA_HASH)
						pLoadLibraryA = (LOADLIBRARYA)(uiBaseAddress + DEREF_32(uiAddressArray));
					else if (dwHashValue == GETPROCADDRESS_HASH)
						pGetProcAddress = (GETPROCADDRESS)(uiBaseAddress + DEREF_32(uiAddressArray));
					else if (dwHashValue == VIRTUALALLOC_HASH)
						pVirtualAlloc = (VIRTUALALLOC)(uiBaseAddress + DEREF_32(uiAddressArray));

					// decrement our counter
					// 找到需要的函数就将数量减一
					usCounter--;
				}

				// get the next exported function name
				// 取出下一个函数名称数组
				uiNameArray += sizeof(DWORD);

				// get the next exported function name ordinal
				// ordinals同步增长以便用作取出函数地址的索引
				uiNameOrdinals += sizeof(WORD);
			}
		}
		// 如果DLL的Hash值与ntdll.dll的相同
		// 下面的操作与kernel32.dll的相同就不再赘述
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
				// 找到函数NtFlushInStructionCache后就获取它的地址
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
		// 当找到所有需要的函数就停止
		if (pLoadLibraryA && pGetProcAddress && pVirtualAlloc && pNtFlushInstructionCache)
			break;

		// get the next entry
		// 双向链表，Flink为下一个节点的地址，而DEREF为*(UINT_PTR*)取Flink指针指向的地址的值，也就是下一个节点的地址
		uiValueA = DEREF(uiValueA);
	}

	// STEP 2: load our image into a new permanent location in memory...
	// 步骤 2: 将Image加载到内存的新临时区域
	// get the VA of the NT Header for the PE to be loaded
	// 获取DLL文件的NT头地址
	// 此时uiLibraryAddress被减到了DLL文件的基址
	// uiHeaderValue 为要加载DLL的NT头地址
	uiHeaderValue = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

	// allocate all the memory for the DLL to be loaded into. we can load at any address because we will  
	// relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
	//我们可以在任何地址申请足够的DLL内存来加载DLL文件，因为我们将对Image重定位。将所有内存置零并设置可读写执行的权限避免可能的问题
	//通过获取DLL文件的SizeOfImage来申请足够的内存
	uiBaseAddress = (ULONG_PTR)pVirtualAlloc(NULL, ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// we must now copy over the headers
	uiValueA = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders;
	uiValueB = uiLibraryAddress; //此时为DLL文件基址
	uiValueC = uiBaseAddress; //为DLL文件Image申请的内存的基址
	// 从为Image申请的内存基址开始复制DLL的PE文件头
	while (uiValueA--)
		*(BYTE*)uiValueC++ = *(BYTE*)uiValueB++;

	// STEP 3: load in all of our sections...
	// 步骤 3: 加载DLL所有的节区 
	// uiValueA = the VA of the first section
	// 获取第一个节区头的起始地址
	uiValueA = ((ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader + ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader);

	// itterate through all sections, loading them into memory.
	// 获取节区数量
	uiValueE = ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections;
	while (uiValueE--)
	{
		// uiValueB is the VA for this section
		// 定位到为DLL文件申请的内存空间中的该节区的地址
		uiValueB = (uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress);

		// uiValueC if the VA for this sections data
		// 获取该节区的文件偏移
		uiValueC = (uiLibraryAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->PointerToRawData);

		// copy the section over
		// 获取节区保存在文件时的大小
		uiValueD = ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData;
		// 将节区数据复制到为DLL文件申请的内存中该节区的内存
		while (uiValueD--)
			*(BYTE*)uiValueB++ = *(BYTE*)uiValueC++;

		// get the VA of the next section
		// 获取下一个节区头的起始地址
		uiValueA += sizeof(IMAGE_SECTION_HEADER);
	}

	// STEP 4: process our images import table...
	// 步骤 4: 处理Image的导入表，即修复IAT
	// uiValueB = the address of the import directory
	//获得保存导入表信息的地址
	uiValueB = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	// we assume their is an import table to process
	// uiValueC is the first entry in the import table
	// 假设存在导入表
	// 获取导入表起始地址(IDT的地址)
	uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

	// itterate through all imports
	// 遍历所有IDT的IID结构体
	while (((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name)
	{
		// use LoadLibraryA to load the imported module into memory
		// 获取DLL名称字符串的保存地址，通过LoadLibraryA将导入的DLL加载到内存
		// uiLibraryAddress 就是导入的DLL加载到内存后的地址
		uiLibraryAddress = (ULONG_PTR)pLoadLibraryA((LPCSTR)(uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name));

		// uiValueD = VA of the OriginalFirstThunk
		// 获取保存INT数组地址的地址
		uiValueD = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->OriginalFirstThunk);

		// uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
		// 获取保存IAT数组地址的地址
		uiValueA = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->FirstThunk);

		// itterate through all imported functions, importing by ordinal if no name present
		// 遍历所有导入函数，如果函数没有名称则通过Ordinal导入
		while (DEREF(uiValueA))
		{
			// sanity check uiValueD as some compilers only import by FirstThunk
			// 因为一些编译器仅通过IAT导入，因此要对uiValueD进行健壮性检查
			// uiValueD不为空
			// IMAGE_ORDINAL_FLAGE = 0x80000000 ,而用户内存空间为0x0 - 0x7FFFFFFF，
			//规定如果PIMAGE_THUNK_DATA成员为Ordinal时，最高位为1且低16位为Ordinal，如果为AddressOfData，最高位为0
			// 因此如果用Ordinal与0x80000000相与不为0说明是Ordinal，为0说明是AddressOfData
			// 即如果该函数是通过Ordinal导入而不是名称导入
			if (uiValueD && ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// get the VA of the modules NT Header
				// 获取加载至内存的DLL文件的NT头地址
				uiExportDir = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

				// uiNameArray = the address of the modules export directory entry
				// 获得DLL导出表地址
				uiNameArray = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

				// get the VA of the export directory
				// 获取DLL导出表的入口地址
				uiExportDir = (uiLibraryAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

				// get the VA for the array of addresses
				// 获取导出函数地址数组地址
				uiAddressArray = (uiLibraryAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

				// use the import ordinal (- export ordinal base) as an index into the array of addresses
				// 通过Ordinal获取DLL导出函数地址,这里INT的Ordinal是在所有导入函数的序号，要变换到函数所在DLL的序号因此需要减Ordinal的Base
				uiAddressArray += ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal) - ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->Base) * sizeof(DWORD));

				// patch in the address for this imported function
				// 获取函数地址并写入IAT中
				DEREF(uiValueA) = (uiLibraryAddress + DEREF_32(uiAddressArray));
			}
			// 如果函数是通过名称导入
			else
			{
				// get the VA of this functions import by name struct
				// 获取IAT的数组的起始位置
				uiValueB = (uiBaseAddress + DEREF(uiValueA));

				// use GetProcAddress and patch in the address for this imported function
				// 使用GetProcAddress函数从载入到uiLibraryAddress地址的DLL中获取该函数的地址，并写入IAT中
				DEREF(uiValueA) = (ULONG_PTR)pGetProcAddress((HMODULE)uiLibraryAddress, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name);
			}
			// get the next imported function
			// IAT指针后移
			uiValueA += sizeof(ULONG_PTR);
			// INT指针后移
			if (uiValueD)
				uiValueD += sizeof(ULONG_PTR);
			// 因为在PE文件未被加载到内存前IAT和INT相同，当PE文件载入内存运行起来后INT和IAT不再一样,IAT保存导入函数地址，INT仍然是Ordinal或IIBN结构体
		}

		// get the next import
		// 指针指向下一个IID结构体，每导入一个DLL文件就会有一个IID结构体，因此也是指向下一个DLL
		uiValueC += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}

	// STEP 5: process all of our images relocations...
	// 步骤 5: 处理Images的重定位
	// calculate the base address delta and perform relocations (even if we load at desired image base)
	// 计算基址增量并执行重定位(即使加载到了期望的Image基址
	// 为目标DLL文件申请的内存空间的基址 - 目标DLL文件的ImageBase(指出DLL文件优先加载的地址,为RVA)
	// 为什么是相减？因为ImageBase为RVA，减掉好再重定位后加上新的RVA
	// 这也是加载器的重定位时需要做的，加载器遍历重定位表,找到要修正的数据，
	// 然后用(实际Image地址 - DLL默认ImageBase) + 重定位数据地址(在后面会加)这个公式进行重定位
	uiLibraryAddress = uiBaseAddress - ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;

	// uiValueB = the address of the relocation directory
	// 获取重定位表地址
	uiValueB = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	// check if their are any relocations present
	// 如果重定位表存在，Size就不为0
	if (((PIMAGE_DATA_DIRECTORY)uiValueB)->Size)
	{
		// uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
		// 获取重定位块表起始地址
		uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

		// and we itterate through all entries...
		// 遍历重定位块
		while (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock)
		{
			// uiValueA = the VA for this relocation block
			// 获取该重定位块的虚拟地址
			uiValueA = (uiBaseAddress + ((PIMAGE_BASE_RELOCATION)uiValueC)->VirtualAddress);

			// uiValueB = number of entries in this relocation block
			// SizeOfBlock 是该重定位块的大小，包括IMAGE_BASE_RELOCATION结构体 + 记录偏移类型与偏移地址的TypeOffSet数组
			// TypeOffset 为2字节，高4位代表重定位类型，低12位代表偏移地址，偏移地址+VirtualAddress就为重定位的地址
			// [SizeOfBlock - 结构体的大小sizeof(IMAGE_BASE_RELOCATION)] / 两字节 = TypeOffset数组元素的数量
			uiValueB = (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

			// uiValueD is now the first entry in the current relocation block
			// 获取当前重定位块的TypeOffset数组的第一个元素的地址
			uiValueD = uiValueC + sizeof(IMAGE_BASE_RELOCATION);

			// we itterate through all the entries in the current block...
			// 遍历当前重定位块的所有TypeOffset数组元素
			while (uiValueB--)
			{
				// perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
				// we dont use a switch statement to avoid the compiler building a jump table
				// which would not be very position independent!
				// 执行重定位，可以跳过 IMAGE_REL_BASED_ABSOLUTE(重定位类型,无特别意义，只是为了让每个段4字节对齐，就是填充作用，里面并没有数据)
				// 不使用switch表达式来避免编译器构建一个位置不是那么独立的跳转表?????

				//IMAGE_REL_BASED_DIR64(重定位类型,对指向的整个地址进行修正
				//(实际Image地址 - DLL默认ImageBase) + 重定位数据地址(RVA)
				// 这里uiLibraryAddress 为(实际Image地址 - DLL默认ImageBase),
				// 重定位数据地址(RVA) = uiValueA + uiValueD->offset = VirtualAddress + offset
				if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_DIR64)
					//就是 IMAGE_BASE_RELOCATION + offset = 重定位后的RVA地址，然后该RVA地址的值 + uiLibraryAddress = 重定位后在内存的VA
					*(ULONG_PTR*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += uiLibraryAddress;
				// 同上，这两个重定位类型都是对指向的整个地址修正，好像是一个x64一个x86
				// 也可以注意到不同的重定位类型只是影响地址取多少位
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGHLOW)
					*(DWORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += (DWORD)uiLibraryAddress;
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGH)
					*(WORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += HIWORD(uiLibraryAddress);
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_LOW)
					*(WORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += LOWORD(uiLibraryAddress);

				// get the next entry in the current relocation block
				// 获取该重定位块的下一个TypeOffset数组元素
				uiValueD += sizeof(IMAGE_RELOC);
			}

			// get the next entry in the relocation directory
			// 获取下一个重定位块
			uiValueC = uiValueC + ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock;
		}
	}

	// STEP 6: call our images entry point
	// 步骤 6: 调用Images的入口点
	// uiValueA = the VA of our newly loaded DLL/EXE's entry point
	// uiValueA 为 DLL文件PE头记录的入口点地址
	uiValueA = (uiBaseAddress + ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.AddressOfEntryPoint);

	// We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
	// 必须刷新指令缓存来避免使用被我们在重定位过程更新的旧代码
	// 就是程序的指令在编译后就不会改变，当我们向程序里面添加新的DLL后，程序就会增加新的指令
	// 当程序的指令被更改后通过该函数可以刷新CPU，让CPU可以读取并执行新的指令
	pNtFlushInstructionCache((HANDLE)-1, NULL, 0);

	// call our respective entry point, fudging our hInstance value
	// 调用各自的入口点，捏造hInstance的值？
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
	// if we are injecting a DLL via LoadRemoteLibraryR we call DllMain and pass in our parameter (via the DllMain lpReserved parameter)
	// 如果通过LoadRemoteLibraryR函数注入DLL，可以调用DllMain并通过DllMain的lpReserved参数传递我们的参数
	((DLLMAIN)uiValueA)((HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, lpParameter);
#else
	// if we are injecting an DLL via a stub we call DllMain with no parameter
	((DLLMAIN)uiValueA)((HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, NULL);
#endif

	// STEP 8: return our new entry point address so whatever called us can call DllMain() if needed.
	// 调用反射加载器返回新的DLL入口地址以便能调用DllMain()
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