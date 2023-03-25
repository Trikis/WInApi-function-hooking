#include <windows.h>
#include <iostream>

typedef  int(__stdcall* TrampolineFunc)(HWND, LPCSTR, LPCSTR, UINT);

class HookMessageBoxA {
private:
	static char PreviousBuffer[5];
	static char Patch[5];
	static DWORD dwOldProtection;
	static LPVOID lpOriginFunc;
	static TrampolineFunc trampoline;
public:

	static int __stdcall ProxyFunc(HWND hwnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
		std::wcout << L"MessageBoxA hooked\n";
		std::wcout << L"\tlpText : " << lpText << std::endl;
		std::wcout << L"\tlpCaption : " << lpCaption << std::endl;

		return trampoline(hwnd, lpText, lpCaption, uType);
	}

	static void ModifyFuncStart() {
		ZeroMemory(Patch, sizeof(Patch));

		HMODULE hModule = LoadLibraryW(L"user32.dll");
		lpOriginFunc = GetProcAddress(hModule, "MessageBoxA");

		DWORD src = (DWORD)lpOriginFunc;
		DWORD dst = (DWORD)(&ProxyFunc);
		DWORD offset = (dst - src - 5);

		memcpy(Patch, "\xe9", 1); memcpy(Patch + 1, &offset, 4);

		VirtualProtect(lpOriginFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtection);
		memcpy(PreviousBuffer, lpOriginFunc, 5);
		memcpy(lpOriginFunc, Patch, 5);
		VirtualProtect(lpOriginFunc, 20, dwOldProtection, &dwOldProtection);

		DWORD ContinationAddress = ((DWORD)lpOriginFunc + 5);
		LPVOID trampoline_address = VirtualAlloc(NULL, 11, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		memcpy(trampoline_address, &PreviousBuffer, 5);
		memcpy((BYTE*)trampoline_address + 5, "\x68", 1);
		memcpy((BYTE*)trampoline_address + 6, &ContinationAddress, 4);
		memcpy((BYTE*)trampoline_address + 10, "\xc3", 1);
		trampoline = (TrampolineFunc)trampoline_address;
		
	}

};

char HookMessageBoxA::PreviousBuffer[5];
char HookMessageBoxA::Patch[5];
DWORD HookMessageBoxA::dwOldProtection;
LPVOID HookMessageBoxA::lpOriginFunc;
TrampolineFunc HookMessageBoxA::trampoline;


BOOL WINAPI DllMain(HINSTANCE hInstDll, DWORD dwReason, LPVOID lpReserved) {
	if (dwReason == DLL_PROCESS_ATTACH) {
		HookMessageBoxA::ModifyFuncStart();
	}
	return TRUE;
}