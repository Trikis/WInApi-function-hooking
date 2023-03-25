#include <windows.h>
#include <iostream>

typedef int(__stdcall* TrampolineFunc)(HWND, LPCSTR, LPCSTR, UINT);

class HookMessageBoxA {
private:
	static char PreviousBuffer[12];
	static char Patch[12];
	static DWORD dwOldProtection;
	static LPVOID lpOriginalFunc;
	static TrampolineFunc trampoline;

public:

	static int __stdcall ProxyFunc(HWND hwnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
		std::wcout << L"MessageBoxA hooked\n";
		std::wcout << L"\tlpText : " << lpText << std::endl;
		std::wcout << L"\tlpCaption : " << lpCaption << std::endl;

		return trampoline(hwnd, lpText, lpCaption, uType);
	}

	static void ModifyFuncStart() {

		HMODULE hModule = LoadLibraryW(L"user32.dll");
		lpOriginalFunc = GetProcAddress(hModule, "MessageBoxA");

		DWORD proxy_func_address = (DWORD)&ProxyFunc;
		memcpy(Patch, "\x90\x90\x90", 3);
		memcpy(Patch + 3, "\x068", 1);
		memcpy(Patch + 4, &proxy_func_address, 4);
		memcpy(Patch + 8, "\x90\x90\x90", 3);
		memcpy(Patch + 11, "\xc3", 1);

		VirtualProtect(lpOriginalFunc, 12, PAGE_EXECUTE_READWRITE, &dwOldProtection);
		memcpy(PreviousBuffer, lpOriginalFunc, 12);
		memcpy(lpOriginalFunc, Patch, 12);
		VirtualProtect(lpOriginalFunc, 12, dwOldProtection, &dwOldProtection);

		LPVOID trampoline_address = VirtualAlloc(NULL, 12, MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE);
		DWORD ContinueAddress = (DWORD)lpOriginalFunc + 12;
		memcpy(trampoline_address, PreviousBuffer, 12);
		memcpy((BYTE*)trampoline_address + 12, "\x68", 1);
		memcpy((BYTE*)trampoline_address + 13, &ContinueAddress, 4);
		memcpy((BYTE*)trampoline_address + 17, "\xc3", 1);
		trampoline = (TrampolineFunc)trampoline_address;

	}
};

char HookMessageBoxA::PreviousBuffer[12];
char HookMessageBoxA::Patch[12];
DWORD HookMessageBoxA::dwOldProtection;
LPVOID HookMessageBoxA::lpOriginalFunc;
TrampolineFunc HookMessageBoxA::trampoline;

BOOL APIENTRY DllMain(HINSTANCE hInstDll, DWORD dwReason, LPVOID lpReserved) {
	if (dwReason == DLL_PROCESS_ATTACH) {
		HookMessageBoxA::ModifyFuncStart();
	}
	return TRUE;
}