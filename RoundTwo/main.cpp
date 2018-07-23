#include <windows.h>
#include <winternl.h>
#include <tchar.h>
#include <string.h>
#include <stdio.h>

BOOL
LoggedSetLockPagesPrivilege(HANDLE hProcess,
	BOOL bEnable)
{
	struct {
		DWORD Count;
		LUID_AND_ATTRIBUTES Privilege[1];
	} Info;

	HANDLE Token;
	BOOL Result;

	// Open the token.

	Result = OpenProcessToken(hProcess,
		TOKEN_ADJUST_PRIVILEGES,
		&Token);

	if (Result != TRUE)
	{
		_tprintf(_T("Cannot open process token.\n"));
		return FALSE;
	}

	// Enable or disable?

	Info.Count = 1;
	if (bEnable)
	{
		Info.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	else
	{
		Info.Privilege[0].Attributes = 0;
	}

	// Get the LUID.

	Result = LookupPrivilegeValue(NULL,
		SE_LOCK_MEMORY_NAME,
		&(Info.Privilege[0].Luid));

	if (Result != TRUE)
	{
		_tprintf(_T("Cannot get privilege for %s.\n"), SE_LOCK_MEMORY_NAME);
		return FALSE;
	}

	// Adjust the privilege.

	Result = AdjustTokenPrivileges(Token, FALSE,
		(PTOKEN_PRIVILEGES)&Info,
		0, NULL, NULL);

	// Check the result.

	if (Result != TRUE)
	{
		_tprintf(_T("Cannot adjust token privileges (%u)\n"), GetLastError());
		return FALSE;
	}
	else
	{
		if (GetLastError() != ERROR_SUCCESS)
		{
			_tprintf(_T("Cannot enable the SE_LOCK_MEMORY_NAME privilege; "));
			_tprintf(_T("please check the local policy.\n"));
			return FALSE;
		}
	}

	CloseHandle(Token);

	return TRUE;
}


int main(int argc, char** argv)
{
	LPVOID lpvMemoryWindowOne = nullptr;
	LPVOID lpvMemoryWindowTwo = nullptr;
	SYSTEM_INFO sysInfo = { 0 };

	ULONG_PTR ulNumPages, ulNumOriginalPages = 0;
	ULONG_PTR * ulPfnArray = nullptr;
	ULONG ulPfnArraySize = 0;
	ULONG ulRequestedMemory = 1024 * 50;  // 50 MB

										  // Ensure correct privileges are set
	if (!LoggedSetLockPagesPrivilege(GetCurrentProcess(), TRUE))
	{
		_tprintf(_T("Failed to set proper privs\n"));
		return 0;
	}

	GetSystemInfo(&sysInfo);
	_tprintf(_T("System Page size: %d\n"), sysInfo.dwPageSize);

	// Determine number of physical pages we're going to request. 
	ulNumPages = ulRequestedMemory / sysInfo.dwPageSize;
	_tprintf(_T("Number of pages being requested: %d\n"), ulNumPages);

	ulPfnArraySize = ulNumPages * sizeof(ULONG_PTR);
	_tprintf(_T("PfnArraySize: %d\n"), ulPfnArraySize);

	ulPfnArray = (ULONG_PTR*)HeapAlloc(GetProcessHeap(), 0, ulPfnArraySize);

	ulNumOriginalPages = ulNumPages;
	if (!AllocateUserPhysicalPages(GetCurrentProcess(), &ulNumPages, ulPfnArray))
	{
		_tprintf(_T("Failed to Allocate Physical Pages, Error: %X\n"), GetLastError());
		getchar();
		return 0;
	}

	_tprintf(_T("Allocated Pages: %d\n"), ulNumPages);

	// Create the window
	lpvMemoryWindowOne = VirtualAlloc(NULL, ulRequestedMemory,
		MEM_RESERVE | MEM_PHYSICAL | MEM_TOP_DOWN, PAGE_READWRITE);
	if (lpvMemoryWindowOne == NULL)
	{
		_tprintf(_T("Failed to allocate memory!\n"));
		getchar();
		return 0;
	}

	lpvMemoryWindowTwo = VirtualAlloc(NULL, ulRequestedMemory, 
		MEM_RESERVE | MEM_PHYSICAL | MEM_TOP_DOWN, PAGE_READWRITE);
	if (lpvMemoryWindowTwo == NULL)
	{
		_tprintf(_T("Failed to allocate second window\n"));
		getchar();
		goto done;
	}

	// Map the physical pages for this window region
	if (!MapUserPhysicalPages(lpvMemoryWindowOne, ulNumPages, ulPfnArray))
	{
		_tprintf(_T("Failed to map physical pages: Error = %X\n"), GetLastError());
		getchar();
		goto done;
	}

	// This should fail according to docs
	if (!MapUserPhysicalPages(lpvMemoryWindowTwo, ulNumPages, ulPfnArray))
	{
		_tprintf(_T("Could not map second window!: Error: %X\n"), GetLastError());
		getchar();
		goto done;
	}


done:
	if (lpvMemoryWindowTwo)
		VirtualFree(lpvMemoryWindowTwo, 0, MEM_RELEASE);
	if (lpvMemoryWindowOne)
		VirtualFree(lpvMemoryWindowOne, 0, MEM_RELEASE);

	getchar();
	return 0;
}