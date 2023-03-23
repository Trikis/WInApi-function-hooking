#include <windows.h>
#include <iostream>

class HookMessageBoxA {
private:
	static char PriviousBuffer[5];
	static char Patch[5];
	static DWORD dwPreviousProtection;
	static LPVOID OriginFuncAddress;
public:

	static int __stdcall ProxyFunc(HWND hwnd, LPCSTR lpText, LPCSTR lpCaption ,  UINT uType) {
		std::wcout << "MessageBox hooked\n";
		std::wcout << "lpText : " << lpText << std::endl;
		std::wcout << "lpCaption : " << lpCaption << std::endl;
		
		WriteProcessMemory(GetCurrentProcess(), OriginFuncAddress, PriviousBuffer, 5, NULL);
		VirtualProtect(OriginFuncAddress, 5, dwPreviousProtection, &dwPreviousProtection);
		return MessageBoxA(hwnd, lpText, lpCaption, uType);
	}

	static void ModifyFuncStart() {
		ZeroMemory(Patch, sizeof(Patch));

		HMODULE hModule = LoadLibraryW(L"user32.dll");
		OriginFuncAddress = GetProcAddress(hModule, "MessageBoxA");

		DWORD Src = (DWORD)OriginFuncAddress;
		DWORD Dst = (DWORD)(&ProxyFunc);
		DWORD* relative_offset = (DWORD*)(Dst - Src - 5);

		memcpy(Patch, "\xe9", 1); memcpy(Patch + 1, &relative_offset, 4);

		VirtualProtect(OriginFuncAddress, 5, PAGE_EXECUTE_READWRITE, &dwPreviousProtection);
		memcpy(PriviousBuffer, OriginFuncAddress, 5);
		memcpy(OriginFuncAddress, Patch, 5);
	}
};

char HookMessageBoxA::PriviousBuffer[5];
char HookMessageBoxA::Patch[5];
DWORD HookMessageBoxA::dwPreviousProtection;
LPVOID HookMessageBoxA::OriginFuncAddress;


BOOL WINAPI DllMain(HINSTANCE hInsDll, DWORD dwReason, LPVOID lpReserved) {
	if (dwReason == DLL_PROCESS_ATTACH) {
		HookMessageBoxA::ModifyFuncStart();
	}
	return TRUE;
}