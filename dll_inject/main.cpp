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

	// �����벻����Ҫ������ʾ
	if ((argc != 5) ||
		// ��Ϊwcsicmp��ȷ���0�������Ҫ���룬���Ϊ�����һֱ����1
		(_wcsicmp(argv[2], L"-i") && _wcsicmp(argv[2],L"-e")) ||
		// �����ע��ģʽ������Ҫ��1-5֮��ѡ��
		(!_wcsicmp(argv[2], L"-i") && (_wtoi(argv[3]) <= 0 && _wtoi(argv[3]) >= 6 )))
	{
		displayHelp();
		return 1;
	}

	// ��DLL·������szPath
	if (!GetFullPathName(argv[4], BufSize, szPath, NULL))
	{
		wprintf(TEXT("GetFullPathName() failed! [%d]\n"), GetLastError());
		return 1;
	}

	// ����·�����Ƿ��и�dll�ļ�
	if (_taccess(szPath, 0) == -1)
	{
		wprintf(TEXT("Could not find \"%s\" file!\n "), szPath);
		return 1;
	}

	// ���Ȩ��
	if (!SetPrivilege())
	{
		return 1;
	}

	// �ж���ע���ж��DLL
	if (!_wcsicmp(argv[2], L"-e"))
	{
		nMod = EJECTION_MOD;
	}
	// ����nMod���ж�ע�����ж��Dll
	if (!_wcsicmp(argv[1], L"*"))
		InjectOrEjectDllToAll(nMod, szPath, argv[3]);
	else
		// argv[1]������PIDҲ�����ǽ�����
		InjectOrEjectDllToOne(argv[1], nMod, szPath, argv[3]);

	return 0;
}