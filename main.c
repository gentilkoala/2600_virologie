#include <stdio.h>
#include "libproc.h"

typedef HMODULE(*loadlib_call)(LPCSTR);

typedef int (*msgbox_call)(
    HWND   hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT   uType
    );

int main()
{
    list_dll();
    PVOID dll = get_dll(L"C:\\WINDOWS\\System32\\KERNEL32.DLL");
    LOG("KERNEL32 at %p\n", dll);
    list_func(dll);
    PVOID loadlib = get_func("LoadLibraryA", dll);
    LOG("loadlib at %p\n", loadlib);
    HMODULE hM = ((loadlib_call)loadlib)("user32.dll");
    LOG("hmod at %p\n", hM);
    LOG("what %s\n", (PCHAR)hM);
    PVOID msgbox = get_func("MessageBoxA", hM);
    LOG("msgbox at %p\n", msgbox);
    ((msgbox_call)msgbox)(NULL, "Yeah! Hacked!!!", "HackBox", 0);
    return 0;
}