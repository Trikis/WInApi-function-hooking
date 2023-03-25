#include <windows.h>
#include <iostream>

typedef int (WINAPI* TrampolineFunc)(HWND, LPCSTR, LPCSTR, UINT);


double ProxyFunc_Address;
double* pProxyFunc_Address;

class HookMessageBoxA {
private:
	static char PreviousBuffer[12];
	static char Patch[12];
	static DWORD dwOldProtection;
	static LPVOID lpOriginalFunc;
	static TrampolineFunc trampoline;
public:
	static int WINAPI ProxyFunc(HWND hwnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
		std::wcout << L"MessageBoxA hooked\n";
		std::wcout << L"\tlpText : " << lpText << std::endl;
		std::wcout << L"\tlpCaption : " << lpCaption << std::endl;

		return trampoline(hwnd, lpText, lpCaption, uType);
	}

	static void ModifyFuncStart() {
		HMODULE hModule = LoadLibraryW(L"user32.dll");
		lpOriginalFunc = GetProcAddress(hModule, "MessageBoxA");

		ProxyFunc_Address = (double)((DWORD)&ProxyFunc);
		pProxyFunc_Address = &ProxyFunc_Address;
		/*
		* Patch:
		*	push eax
		*	fld qword ptr [pProxyFunc_Address]
		*	fistp dword ptr [esp]
		*	ret
		*/
		memcpy(Patch, "\x90\x50\xdd\x05\xaa\xaa\xaa\xaa\xdb\x1c\x24\xc3", 12);
		memcpy(Patch + 4, &pProxyFunc_Address, 4);

		VirtualProtect(lpOriginalFunc, 12, PAGE_EXECUTE_READWRITE, &dwOldProtection);
		memcpy(PreviousBuffer, lpOriginalFunc, 12);
		memcpy(lpOriginalFunc, Patch, 12);
		VirtualProtect(lpOriginalFunc, 12, dwOldProtection, &dwOldProtection);

		LPVOID trampoline_address = VirtualAlloc(NULL, 18, MEM_COMMIT |
			MEM_RESERVE, PAGE_EXECUTE_READWRITE);
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

BOOL APIENTRY DllMain(HINSTANCE hInstDll, DWORD dwReason, UINT uType) {
	if (dwReason == DLL_PROCESS_ATTACH) {
		HookMessageBoxA::ModifyFuncStart();
	}
	return TRUE;
}