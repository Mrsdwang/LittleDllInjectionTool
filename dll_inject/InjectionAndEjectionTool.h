#pragma once

BOOL InjectOrEjectDllToOne(LPCTSTR szProc, int nMod, LPCTSTR szDllPath, TCHAR* tech);
BOOL InjectOrEjectDllToAll(int nMod, LPCTSTR szDllPath, TCHAR* tech);