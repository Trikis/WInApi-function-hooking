#include <windows.h>
#include <TlHelp32.h>
#include <iostream>


BOOL SetPrivilegeToCurrProcess(
	LPCWSTR lpszPrivilegeName , 
	BOOL bEnablePrivilege
) {
	HANDLE hProcess = GetCurrentProcess();
	HANDLE hToken;
	if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES , &hToken)) {
		std::wcout << L"[ERROR] OpenProcessToken failed\tError code: " << GetLastError() << std::endl;
		return FALSE;
	}
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL, lpszPrivilegeName, &luid
	)) {
		std::wcout << L"[ERROR] LookupPrivivlegeVa;ue failed\tError code : " << GetLastError() << std::endl;
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : 0;

	if (!AdjustTokenPrivileges(
		hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL
	)) {
		std::wcout << L"[ERROR] AdjustTokenPrivileges failed\tError code : " << GetLastError() << std::endl;
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		std::wcout << L"[ERROR] Required SID that can give Privilege = " << lpszPrivilegeName << std::endl;
		return FALSE;
	}
	CloseHandle(hToken);
	CloseHandle(hProcess);
	return TRUE;
}

DWORD GetPidByProcessName(LPCWSTR lpProcessName) {
	HANDLE hSnapshot;
	PROCESSENTRY32 Pe32;
	Pe32.dwSize = sizeof(PROCESSENTRY32);

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS , NULL);
	
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		throw std::exception("Can't create Process Snapshot");
	}

	if (Process32First(hSnapshot, &Pe32)) {
		do {
			if (wcscmp(Pe32.szExeFile, lpProcessName) == 0) {
				return Pe32.th32ProcessID;
			}
		} while (Process32Next(hSnapshot, &Pe32));
	}

	throw std::exception("Can't find Process");
}

int wmain(int argc, wchar_t** argv) {

	if (argc != 3) {
		std::wcout << L"Usage: program_name.exe file1.exe file2.dll\n";
		return -1;
	}

	//if (!SetPrivilegeToCurrProcess(SE_DEBUG_NAME, TRUE)) {
		//return -1;
	//}

	DWORD dwSizeOfDllName = lstrlenW(argv[2]) * 2 + 2;
	DWORD dwProcessId;

	try {
		dwProcessId = GetPidByProcessName(argv[1]);
	}
	catch (std::exception& e) {
		std::wcout << L"[ERROR] " << e.what() << std::endl;
		getchar();
		return -1;
	}

	HANDLE hProcess = OpenProcess(
		PROCESS_ALL_ACCESS,
		FALSE,
		dwProcessId
	);
	if (hProcess == NULL) {
		std::wcout << L"[ERROR] Can't Open Target Process\tError code : " << GetLastError() << std::endl;
		CloseHandle(hProcess);
		getchar();
		return -1;
	}

	LPVOID lpDllName = VirtualAllocEx(hProcess, NULL, dwSizeOfDllName, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (lpDllName == NULL) {
		std::wcout << L"[ERROR] Can't allocate memory in Target Process\tError code:" << GetLastError() << std::endl;
		CloseHandle(hProcess);
		getchar();
		return -1;
	}

	BOOL bRes = WriteProcessMemory(hProcess, lpDllName, argv[2], dwSizeOfDllName, NULL);
	if (!bRes) {
		std::wcout << L"[ERROR]Can't write in target Process\tError code: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, lpDllName, dwSizeOfDllName, MEM_RELEASE);
		CloseHandle(hProcess);
		getchar();
		return -1;
	}

	HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
	if (hKernel32 == NULL) {
		std::wcout << L"[ERROR] Can't find kernel32.dll\tError code: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, lpDllName, dwSizeOfDllName, MEM_RELEASE);
		CloseHandle(hProcess);
		getchar();
		return -1;
	}

	LPVOID lpLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryW");
	if (lpLoadLibrary == NULL) {
		std::wcout << L"[ERROR]Can't find LoadLibraryW in kernel32.dll\tError code: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, lpDllName, dwSizeOfDllName, MEM_RELEASE);
		CloseHandle(hProcess);
		getchar();
		return -1;
	}

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
		(LPTHREAD_START_ROUTINE)lpLoadLibrary, lpDllName, 0, 0);

	if (hThread == NULL) {
		std::wcout << L"[ERROR] Can't Create Remote Thread\tError code: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, lpDllName, dwSizeOfDllName, MEM_RELEASE);
		CloseHandle(hProcess);
		getchar();
		return -1;
	}

	std::wcout << L"[+] Dll Injected!\n";

	VirtualFreeEx(hProcess, lpDllName, dwSizeOfDllName, MEM_RELEASE);
	CloseHandle(hThread);
	CloseHandle(hProcess);
	getchar();
	return 0;
}