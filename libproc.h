#ifndef __LIBPROC_H
#define __LIBPROC_H

#ifdef DEBUG
#   define LOG(...) printf(__VA_ARGS__);
#else
#   define LOG(...) /**/
#endif

#include <windows.h>

#ifdef DEBUG
void        list_dll();
void        list_func(PVOID dllBase);
#endif

#pragma section("injected", read, execute)

__declspec(code_seg("injected"))
PVOID       get_dll(PWSTR name);

__declspec(code_seg("injected"))
PVOID       get_func(PCHAR name, PVOID dllBase);

__declspec(code_seg("injected"))
void inj_code_c();

#endif