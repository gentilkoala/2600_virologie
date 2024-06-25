/*
 * Ce programme contient des fonctions pour lister les DLL chargées dans un processus
 * et pour obtenir un pointeur vers une fonction spécifique dans une DLL chargée.
 * Il utilise des segments de code et de données spécifiques pour l'injection.
 */

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include "libproc.h"

#ifdef DEBUG
void    list_dll()
{
    //The Thread Environment Block (TEB) structure describes the state of a thread.
    PTEB pTeb = NtCurrentTeb();

    //Ptr to the PEB structure; contient des innfo sur l'ensemble du processus
    PPEB pPeb = pTeb->ProcessEnvironmentBlock;

    LOG("Teb %p\n", pTeb);
    LOG("Peb %p\n", pPeb);

    //Ptr to PEB_LDR_DATA (loader_data) structure; contient info sur les modules load par le process
    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    LOG("LDR %p\n", pLdr);

    //ptr vers l'addr d'un élément de type LIST_ENTRY utilisé pour suivre les modules chargés en mémoire dans un certain ordre
    PLIST_ENTRY pList = &pLdr->InMemoryOrderModuleList;
    for (PLIST_ENTRY pNode = pList->Flink; pNode != pList; pNode = pNode->Flink) //Flink = Forward Link
    {
        LOG("node %p\n", pNode);
        //CONTAINING_RECORD = macro pour ((LDR_DATA_TABLE_ENTRY *)((char *)(ptr_vers_pNode) - (unsigned long)(&((LDR_DATA_TABLE_ENTRY *)0)->InMemoryOrderLinks)))
        //Appelé pour déterminer l’adresse de base d’une structure dont le type est connu lorsque l’appelant a un pointeur vers un champ à l’intérieur d’une telle structure
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pNode, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        LOG("entry %ls\n", pEntry->FullDllName.Buffer);
        LOG("base %p\n", pEntry->DllBase);
    }
}
#endif

void    list_func(PVOID dllBase)
{
    //PIMAGE_DOS_HEADER = ptr vers struc DOS header IMAGE_DOS_HEADER, qui est la 1ere struc dans un fichier PE 
    //Ici Dll base est un ptr vers le début de l'image en mémoire du fichier PE
    PIMAGE_DOS_HEADER   pDosHeader = (PIMAGE_DOS_HEADER)dllBase;

    //IMAGE_NT_HEADERS64 Represents the PE header format.
    //en-tête PE = NT header
    //e_lfanew est un champ de la structure IMAGE_DOS_HEADER qui contient l'offset du PE header
    PIMAGE_NT_HEADERS64 pNtHeader = (PIMAGE_NT_HEADERS64)((PUCHAR)dllBase + pDosHeader->e_lfanew);
    LOG("NtHead %p\n", pNtHeader);
    

    //DataDirectory est un tableau de structures IMAGE_DATA_DIRECTORY.
    //IMAGE_DIRECTORY_ENTRY_EXPORT est une constante qui donne l'index du repertoire des données exportées, ici index = 0
    //Ptr vers l'entrée du repertoire des exportations, qui est aussi le début du tableau DATA_DIRECTORY car index = 0 
    PIMAGE_DATA_DIRECTORY pDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    LOG("pDir %p\n", pDir);
    LOG("pVirt %x\n", pDir->VirtualAddress);

    //Récupération de l'adrr de la table des exportations
    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)dllBase + pDir->VirtualAddress);
    LOG("pExp %p\n", pExp);

    // NumberOfFunctions spécifie le nombre de fonctions que le module exporte
    for (int i = 0; i < pExp->NumberOfFunctions; i += 1)
    {
        PDWORD rvaNames = (PDWORD)((PUCHAR)dllBase + pExp->AddressOfNames);     // Adresse RVA de la table des noms des fonctions exportées
        
        //contient les indices dans la table des adresses des fonctions correspondant à chaque nom
        PWORD aryOrds = (PWORD)((PUCHAR)dllBase + pExp->AddressOfNameOrdinals); // Adresse RVA de la table des ordinals des fonctions.

        PDWORD rvaFuncs = (PDWORD)((PUCHAR)dllBase + pExp->AddressOfFunctions); // Adresse RVA de la table des adresses des fonctions (contient des RVA)
        
        // Affichage du nom de la fonction
        LOG("rvaName %d\n", rvaNames[i]);
        LOG("Name %s\n", (PCHAR)((PCHAR)dllBase + rvaNames[i]));
        
        // Ordinal ==  index de la fonction dans la table des adresses des fonctions
        WORD ord = aryOrds[i];
        LOG("ord %d\n", ord);


        // Convertit la RVA de l'adresse de la fonction en une adresse réelle en mémoire en utilisant l'ordinal.
        PVOID pFunc = (PVOID)((PUCHAR)dllBase + rvaFuncs[ord]);
        LOG("pFunc %p\n", pFunc);
    }
}



__declspec(code_seg("injected"))
int my_wstrcmp(PWSTR src1, PWSTR src2) //src1 et src2 sont des pointeurs vers des chaînes de caractères larges (wchar_t) == Unicode car codé sur plusieurs octets
{
    for (int i = 0; src1[i]; i += 1)
        if (src1[i] != src2[i])
            return src1[i] - src2[i];
    return 0;
}

__declspec(code_seg("injected"))
int my_strcmp(PCHAR src1, PCHAR src2) //PCHAR src1 et PCHAR src2 sont des pointeurs vers des chaînes de caractères ASCII (codé sur 1 octet).
{
    for (int i = 0; src1[i]; i += 1)
        if (src1[i] != src2[i])
            return src1[i] - src2[i];
    return 0;
}

__declspec(code_seg("injected"))
PVOID    get_dll(PWSTR name)
{
    //The Thread Environment Block (TEB) structure describes the state of a thread.
    PTEB pTeb = NtCurrentTeb();
    LOG("Teb %p\n", pTeb);

    //Ptr to the PEB structure; contient des info sur l'ensemble du processus
    PPEB pPeb = pTeb->ProcessEnvironmentBlock;
    LOG("Peb %p\n", pPeb);
    
    // Ptr to PEB_LDR_DATA(loader_data) structure; contient info sur les modules load par le process
    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    LOG("LDR %p\n", pLdr);

    ////ptr vers l'addr d'un élément de type LIST_ENTRY utilisé pour suivre les modules chargés en mémoire dans un certain ordre
    PLIST_ENTRY pList = &pLdr->InMemoryOrderModuleList;

    //Boucle de recherche du module spécifique "name" chargé en mémoire
    for (PLIST_ENTRY pNode = pList->Flink; pNode != pList; pNode = pNode->Flink)
    {
        LOG("node %p\n", pNode);

        PLDR_DATA_TABLE_ENTRY pEntry = (PLDR_DATA_TABLE_ENTRY)(pNode - 1);
        LOG("entry %ls\n", pEntry->FullDllName.Buffer);
        LOG("base %p\n", pEntry->DllBase);

        if (!my_wstrcmp(name, pEntry->FullDllName.Buffer)) // Si NULL return NULL 
            return pEntry->DllBase;
    }
    return NULL;
}

__declspec(code_seg("injected"))
PVOID    get_func(PCHAR name, PVOID dllBase)
{
    PIMAGE_DOS_HEADER   pDosHeader = (PIMAGE_DOS_HEADER)dllBase;
    PIMAGE_NT_HEADERS64 pNtHeader = (PIMAGE_NT_HEADERS64)((PUCHAR)dllBase + pDosHeader->e_lfanew);
    LOG("NtHead %p\n", pNtHeader);

    PIMAGE_DATA_DIRECTORY pDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    LOG("pDir %p\n", pDir);
    LOG("pVirt %x\n", pDir->VirtualAddress);

    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)dllBase + pDir->VirtualAddress);
    LOG("pExp %p\n", pExp);

    for (int i = 0; i < pExp->NumberOfFunctions; i += 1)
    {
        PDWORD rvaNames = (PDWORD)((PUCHAR)dllBase + pExp->AddressOfNames);
        PWORD aryOrds = (PWORD)((PUCHAR)dllBase + pExp->AddressOfNameOrdinals);
        PDWORD rvaFuncs = (PDWORD)((PUCHAR)dllBase + pExp->AddressOfFunctions);
        LOG("rvaName %d\n", rvaNames[i]);

        //on récupère le ptr du nom de la fonction chargée en mémoire
        PCHAR pName = (PCHAR)((PCHAR)dllBase + rvaNames[i]);
        LOG("Name %s\n", pName);
        //on compare avec le nom en argument soit "name"
        if (!my_strcmp(name, pName))// Si NULL return NULL 
        {
            WORD ord = aryOrds[i];
            LOG("ord %d\n", ord);
            PVOID pFunc = (PVOID)((PUCHAR)dllBase + rvaFuncs[ord]);
            LOG("pFunc %p\n", pFunc);
            return pFunc;
        }
    }
    return NULL;
}