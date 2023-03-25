#include <windows.h>
#include <iostream>


typedef int (WINAPI* TrampolineFunc)(HWND, LPCSTR, LPCSTR, UINT);

class HookMessageBoxA {
private:
	static char PreviousBuffer[2];
	static char Patch1[2];
	static char Patch2[6];
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

		memcpy(Patch1, "\xeb\xf8", 2);
		DWORD ProxyFunc_Address = (DWORD)&ProxyFunc;
		memcpy(Patch2, "\x68\xAA\xAA\xAA\xAA\xc3", 6);
		memcpy(Patch2 + 1, &ProxyFunc_Address, 4);

		VirtualProtect((BYTE*)lpOriginalFunc - 6, 8, PAGE_EXECUTE_READWRITE, &dwOldProtection);
		memcpy(PreviousBuffer, lpOriginalFunc, 2);
		memcpy((BYTE*)lpOriginalFunc - 6, Patch2, 6);
		memcpy(lpOriginalFunc, Patch1, 2);
		VirtualProtect((BYTE*)lpOriginalFunc - 6, 8, dwOldProtection, &dwOldProtection);

		LPVOID trampoline_address = VirtualAlloc(NULL, 8, MEM_COMMIT |
			MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		DWORD ContinueAddress = (DWORD)lpOriginalFunc + 2;
		memcpy(trampoline_address, PreviousBuffer, 2);
		memcpy((BYTE*)trampoline_address + 2, "\x68", 1);
		memcpy((BYTE*)trampoline_address + 3, &ContinueAddress, 4);
		memcpy((BYTE*)trampoline_address + 7, "\xc3", 1);
		trampoline = (TrampolineFunc)trampoline_address;
	}
};

char HookMessageBoxA::PreviousBuffer[2];
char HookMessageBoxA::Patch1[2];
char HookMessageBoxA::Patch2[6];
DWORD HookMessageBoxA::dwOldProtection;
LPVOID HookMessageBoxA::lpOriginalFunc;
TrampolineFunc HookMessageBoxA::trampoline;


BOOL APIENTRY DllMain(HINSTANCE hInstDll, DWORD dwReason, LPVOID lpReserved) {
	if (dwReason == DLL_PROCESS_ATTACH) {
		HookMessageBoxA::ModifyFuncStart();
	}
	return TRUE;
}