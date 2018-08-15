#include <windows.h>
#include <winternl.h>
#include <tchar.h>
#include <string.h>
#include <stdio.h>


void PrintError(const char *szMsg, DWORD ddMsgId)
{
	char *szError;

	FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		ddMsgId,
		0,
		(LPSTR)&szError,
		0,
		NULL
	);
	_tprintf(_T("[E] %hs: %hs"), szMsg, szError);
	LocalFree(szError);
	return;
}

BOOL LoggedSetLockPagesPrivilege(HANDLE hProcess,
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

void PrintPFNs(ULONG_PTR* ulpNums, ULONG_PTR szNumLen)
{
	if (!*ulpNums || szNumLen == 0)
		return;
	_tprintf(_T("Printing Page Frame Numbers:\n"));
	for (ULONG_PTR i = 0; i < szNumLen; i++)
	{
		_tprintf(_T("%X\n"), ulpNums[i]);
	}
}

BOOL WriteData(PVOID pMemory, size_t szMemLen)
{
	BOOL bRet = TRUE;
	char *data = malloc(1024);
	memset(data, 0x41, 1024);

	if (!pMemory || szMemLen == 0)
		return FALSE;

	VirtualProtect(pMemory, szMemLen, PAGE_READWRITE, NULL);

	__try
	{
		WriteProcessMemory(GetCurrentProcess(), pMemory, (LPCVOID)data, 1024, NULL);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		_tprintf(_T("Failed to write to memory!\n"));
		return FALSE;
	}
	
	return bRet;
}

void PrintData(PVOID pMemory, ULONG_PTR szMemLen)
{
	if (!pMemory || szMemLen == 0)
		return;
	//print the buffer
	for (unsigned int i = 0; i < 64; i++)
	{
		if ((i % 16) == 0 && (i != 0))
			_tprintf(_T("\n"));
		_tprintf(_T("%02x"), ((char*)pMemory)[i]);
	}
	_tprintf(_T("\n"));
}

int main(int argc, char** argv)
{
	LPVOID lpvMemoryWindowOne = NULL;
	LPVOID lpvMemoryWindowTwo = NULL;
	SYSTEM_INFO sysInfo = { 0 };

	ULONG_PTR ulNumPages, ulNumOriginalPages = 0;
	ULONG_PTR * ulPfnArray = NULL;
	ULONG ulPfnArraySize = 0;
	ULONG ulRequestedMemory = 1024 * 50;  // 50 MB

										  // Ensure correct privileges are set
	if (!LoggedSetLockPagesPrivilege(GetCurrentProcess(), TRUE))
	{
		_tprintf(_T("Failed to set proper privs\n"));
		goto done;
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
		goto done;
	}

	_tprintf(_T("Allocated Pages: %d\n"), ulNumPages);
	_tprintf(_T("Memory Size Requested: %X\n"), ulRequestedMemory);
	PrintPFNs(ulPfnArray, ulNumPages);
	_tprintf(_T("Creating Window 1\n"));

	// Create the window
	lpvMemoryWindowOne = VirtualAlloc(NULL, ulRequestedMemory,
		MEM_RESERVE | MEM_PHYSICAL, PAGE_READWRITE);
	if (lpvMemoryWindowOne == NULL)
	{
		_tprintf(_T("Failed to allocate memory!\n"));
		getchar();
		goto done;
	}

	// Second Window
	lpvMemoryWindowTwo = VirtualAlloc(NULL, ulRequestedMemory,
		MEM_RESERVE | MEM_PHYSICAL, PAGE_READWRITE);
	if (lpvMemoryWindowTwo == NULL)
	{
		_tprintf(_T("Failed to allocate second window\n"));
		getchar();
		goto done;
	}

	_tprintf(_T("Window One Address: 0x%X\n", lpvMemoryWindowOne));
	_tprintf(_T("Windows Two Address: 0x%X\n", lpvMemoryWindowTwo));

	_tprintf(_T("Created Windows, Press any key to cont...\n"));
	getchar();

	
	// Map the physical pages for this window region
	if (!MapUserPhysicalPages(lpvMemoryWindowOne, ulNumPages, ulPfnArray))
	{
		PrintError("Error", GetLastError());
		//_tprintf(_T("Failed to map physical pages: Error = %X\n"), GetLastError());
		getchar();
		goto done;
	}

	_tprintf(_T("Writing Data to VA\n"));
	if (!WriteData(lpvMemoryWindowOne, ulRequestedMemory))
	{
		PrintError("Write Error:", GetLastError());
	}

	_tprintf(_T("Printing Data\n"));
	PrintData(lpvMemoryWindowOne, ulRequestedMemory);

	//Unmap the first Window
	_tprintf(_T("Umap first Window\n"));
	if (!MapUserPhysicalPages(lpvMemoryWindowOne, ulNumOriginalPages, NULL))
	{
		PrintError("Error Unmapping:", GetLastError());
		getchar();
		goto done;
	}

	
	// Now map the physical pages to the new window
	_tprintf(_T("Mapping second window\n"));
	if (!MapUserPhysicalPages(lpvMemoryWindowTwo, ulNumPages, ulPfnArray))
	{
		PrintError("Error", GetLastError());
		_tprintf(_T("Could not map second window!: Error: %X\n"), GetLastError());
		getchar();
		goto done;
	}

	_tprintf(_T("print second window\n"));
	PrintData(lpvMemoryWindowTwo, ulRequestedMemory);

done:
	if (lpvMemoryWindowTwo)
		VirtualFree(lpvMemoryWindowTwo, 0, MEM_RELEASE);
	if (lpvMemoryWindowOne)
		VirtualFree(lpvMemoryWindowOne, 0, MEM_RELEASE);
	if (ulPfnArray)
	{
		FreeUserPhysicalPages(GetCurrentProcess(), &ulNumPages, ulPfnArray);
		HeapFree(GetProcessHeap(), 0, ulPfnArray);
	}
	getchar();
	return 0;
}