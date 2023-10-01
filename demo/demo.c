#include<stdio.h>
#include<windows.h>

/*循环右移*/
DWORD fROR(DWORD data, int length)
{
    DWORD result = 0;
    result = (data >> length) | (data << (32 - length));
    return result;
}
VOID dllHash(WCHAR* dllname) {
    DWORD hash1;
    WORD wtmp;
    int i;

    hash1 = 0;
    for (i = 0; dllname[i]; i++) {
        wtmp = dllname[i];
        if (wtmp >= 'A' && wtmp <= 'Z') {
            wtmp = wtmp | 0b100000; //我希望在这里来一个大小写的统一
        }
        hash1 = wtmp + fROR(hash1, 17);
    }
    wprintf(L"%s: = %08X\n", dllname, hash1);
    return;

}
VOID funHash(char* APIname) {
    DWORD  hash2;
    BYTE btmp;
    int i;

    hash2 = 0;
    for (i = 0; APIname[i]; i++) {
        btmp = APIname[i];
        if (btmp >= 'A' && btmp <= 'Z') {
            btmp = btmp | 0b100000; //我希望在这里来一个大小写的统一
        }
        hash2 = btmp + fROR(hash2, 17);
    }
    //printf("%s: = %08X\n", APIname, hash2);
    printf("0x%08X,\n", hash2);
    return;
}
int main() {
    char** arr[] = {
    "LoadLibraryA",
    "GetModuleHandleA",
    "FreeLibrary",
    "CreateFileA",
    "CloseHandle",
    "GetCurrentDirectoryA",
    "ReadFile",
    "WriteFile",
    "DeleteFileA",
    "SetFilePointer",
    "GetFileSize",
    "FindFirstFileA",
    "FindNextFileA",
    "FindClose",
    "GlobalAlloc",
    "GlobalFree",
    "Sleep",
    "URLDownloadToFileA",
    "mciSendStringA",
    };
    int i;
    for (i = 0; i < sizeof(arr) / sizeof(PVOID); i++) {
        funHash(arr[i]);
    }
    return 0;

}