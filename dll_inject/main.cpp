#include <Windows.h>
#include <stdio.h>
#include "tchar.h"
#include "auxiliary.h"
#include "InjectionAndEjectionTool.h"

#define BufSize (1024)
enum { INJECTION_MOD = 0, EJECTION_MOD };

int _tmain(int argc, TCHAR *argv[])
{
	int nMod = INJECTION_MOD;
	TCHAR szPath[BufSize] = L"";

	// 若输入不满足要求则提示
	if ((argc != 5) ||
		// 因为wcsicmp相等返回0，因此需要相与，如果为或则会一直返回1
		(_wcsicmp(argv[2], L"-i") && _wcsicmp(argv[2],L"-e")) ||
		// 如果是注入模式，必须要在1-5之间选择
		(!_wcsicmp(argv[2], L"-i") && (_wtoi(argv[3]) <= 0 && _wtoi(argv[3]) >= 6 )))
	{
		displayHelp();
		return 1;
	}

	// 讲DLL路径读入szPath
	if (!GetFullPathName(argv[4], BufSize, szPath, NULL))
	{
		wprintf(TEXT("GetFullPathName() failed! [%d]\n"), GetLastError());
		return 1;
	}

	// 检查该路径下是否有该dll文件
	if (_taccess(szPath, 0) == -1)
	{
		wprintf(TEXT("Could not find \"%s\" file!\n "), szPath);
		return 1;
	}

	// 提高权限
	if (!SetPrivilege())
	{
		return 1;
	}

	// 判断是注入或卸载DLL
	if (!_wcsicmp(argv[2], L"-e"))
	{
		nMod = EJECTION_MOD;
	}
	// 根据nMod来判断注入或是卸载Dll
	if (!_wcsicmp(argv[1], L"*"))
		InjectOrEjectDllToAll(nMod, szPath, argv[3]);
	else
		// argv[1]可能是PID也可能是进程名
		InjectOrEjectDllToOne(argv[1], nMod, szPath, argv[3]);

	return 0;
}