# LittleDllInjectionTool
Dll injection tool, For learning Windows reverse technique
Support x86 and x64
Injection technique will keep updating

	Usage: dll_inject.exe <procname|pid|*> <mod:-i|-e> <Injection technique> <dll path>
	procname|pid|*:
  	procname|pid: Dll Injecting to procename|pid
	*: Dll Injecting to all process
	mod:
	-i: Dll Injection
	-e: Dll Ejection

	Injection technique:
	[for \"-e\"mod, this parameter is not limited, it can be a number or letter.]
	[for \"-i\"mod, this parameter is limited to 5,not including 0.]
	1. DLL injection via CreatRemoteThread() or via NtCreateThreadEx() if OS version is vista or later
	2. DLL injection via QueueUserAPC()\n"));
	3. DLL injection via SetWindowsHookEx(),The Expot Function of Dll should own \"Poc\" Function
	4. DLL injection via RtlCreateUserThread()
	5. DLL injection via ReflectiveInjection()
  
  Reference :
  [injectAllTheThings](https://github.com/DanielRTeixeira/injectAllTheThings)
  
  [ReflectiveDLLInjection](https://github.com/stephenfewer/ReflectiveDLLInjection)
  
