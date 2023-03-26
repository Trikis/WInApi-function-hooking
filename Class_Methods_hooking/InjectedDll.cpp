#include <windows.h>
#include <psapi.h>
#include <iostream>

typedef void (__stdcall* TrampolineFunc)(LPVOID self);

class HookPrintInfo {
private:
	static LPVOID lpPrintInfoFunc;
	static TrampolineFunc trampoline;
	static char PreviousBuffer[10];
	static char Patch[10];
	static DWORD dwOldProtection;

public:
	static void GetPrintInfoAddress() {
		MODULEINFO ExeModuleInfo;
		GetModuleInformation(GetCurrentProcess(),
			GetModuleHandle(NULL), &ExeModuleInfo, sizeof(MODULEINFO));

		LPVOID lpBaseAddress = ExeModuleInfo.lpBaseOfDll;
		while (TRUE) {
			// in my case this - start of PrintInfo function
			if (memcmp(lpBaseAddress, "\x55\x8b\xec\x83\xe4", 5) == 0) break;
			lpBaseAddress = (BYTE*)lpBaseAddress + 1;
		}
		lpPrintInfoFunc = lpBaseAddress;
	}

	static void ProxyFunc(LPVOID* self){
		std::wcout << L"PrintInfo hooked\n";
		DWORD* curr_points = (DWORD*)self;
		DWORD cabababe = 0xcabebabe;
		std::wcout << "\tOriginal Points : " << std::hex << *curr_points << "\t------>";
		std::wcout << L"  Change to 0xcabebabe" << std::endl;
		memcpy(self, &cabababe, 4);
		return trampoline(self);
	}

	static void PatchPrintInfoFunction() {
		GetPrintInfoAddress();
		DWORD ProxyFunc_Address = (DWORD)ProxyFunc;
		/*
		* Patch:
		*	xchg ecx , dword [esp]
		*	push ecx
		*	push ProxyFunc_Address
		*	pop
		*/
		memcpy(Patch, "\x87\x0c\x24\x51\x68\xaa\xaa\xaa\xaa\xc3", 10);
		memcpy(Patch + 5, &ProxyFunc_Address, 4);

		VirtualProtect(lpPrintInfoFunc, 10, PAGE_EXECUTE_READWRITE, &dwOldProtection);
		memcpy(PreviousBuffer, lpPrintInfoFunc, 10);
		memcpy(lpPrintInfoFunc, Patch, 10);
		VirtualProtect(lpPrintInfoFunc, 10, dwOldProtection, &dwOldProtection);


		/*
		* Trampoline:
		*	pop ecx
		*	xchg ecx , dword [esp]
		*	exec PreviousBuffer
		*	push ContinueAddress
		*	ret
		*/

		LPVOID trampoline_address = VirtualAlloc(
			NULL, 20, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
		);
		DWORD ContinueAddress = (DWORD)lpPrintInfoFunc + 10;
		memcpy(trampoline_address, "\x59\x87\x0c\x24", 4);
		memcpy((BYTE*)trampoline_address + 4, PreviousBuffer, 10);
		memcpy((BYTE*)trampoline_address + 14, "\x68", 1);
		memcpy((BYTE*)trampoline_address + 15, &ContinueAddress, 4);
		memcpy((BYTE*)trampoline_address + 19, "\xc3", 1);
		trampoline = (TrampolineFunc)trampoline_address;
	}
};

LPVOID HookPrintInfo::lpPrintInfoFunc;
TrampolineFunc HookPrintInfo::trampoline;
char HookPrintInfo::PreviousBuffer[10];
char HookPrintInfo::Patch[10];
DWORD HookPrintInfo::dwOldProtection;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
	if (dwReason == DLL_PROCESS_ATTACH) {
		HANDLE hThread = CreateThread(NULL , 0 , (LPTHREAD_START_ROUTINE)HookPrintInfo::PatchPrintInfoFunction , NULL  , 0 , NULL);
	}
	return TRUE;
}