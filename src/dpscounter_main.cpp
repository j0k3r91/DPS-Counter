/**
 * dpscounter_main.cpp
 * Launcher DPS Counter — injecte dpscounter_dll.dll dans SFrame.exe
 *
 * Mécanisme identique à BuffGuild.exe :
 *   1. Cherche le processus SFrame.exe
 *   2. Vérifie le mutex "Local\DPSCounterRunning" (une seule instance)
 *   3. Crée l'événement "Local\DPSCounterExit"
 *   4. Écrit la DLL (embarquée en tableau C) dans un fichier temp
 *   5. Injecte via CreateRemoteThread + LoadLibraryA
 *   6. Attend l'événement DPSCounterExit pour libérer le fichier temp
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstring>

// DLL embarquée (générée par CMake cible dll_header)
#include "dll_data.h"

// ============================================================
// Configuration
// ============================================================
static const char* TARGET_EXE      = "SFrame.exe";
static const char* MUTEX_NAME      = "Local\\DPSCounterRunning";
static const char* EVENT_EXIT_NAME = "Local\\DPSCounterExit";
// Nom unique a chaque lancement (timestamp) pour forcer LoadLibraryA a recharger
static char s_dllTmpName[64] = {};
static const char* GetDllTmpName() {
    if (!s_dllTmpName[0])
        _snprintf_s(s_dllTmpName, sizeof(s_dllTmpName), _TRUNCATE,
                    "\\dpscounter_%lu.dll", GetTickCount());
    return s_dllTmpName;
}

// ============================================================
// Utilitaires
// ============================================================
static void ShowError(const char* msg)
{
    MessageBoxA(nullptr, msg, "DPS Counter -- Erreur", MB_OK | MB_ICONERROR);
}

static DWORD FindProcessByName(const char* name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = { sizeof(pe) };
    DWORD pid = 0;
    for (BOOL ok = Process32First(snap, &pe); ok; ok = Process32Next(snap, &pe)) {
        if (_stricmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
    }
    CloseHandle(snap);
    return pid;
}

// ============================================================
// Injection CreateRemoteThread + LoadLibraryA
// ============================================================
static bool InjectDLL(DWORD pid, const char* dllPath)
{
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        ShowError("Impossible d'ouvrir le processus SFrame.exe (droits insuffisants ?)");
        return false;
    }

    size_t pathLen = strlen(dllPath) + 1;
    void* pRemote = VirtualAllocEx(hProc, nullptr, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemote) {
        CloseHandle(hProc);
        ShowError("VirtualAllocEx a echoue.");
        return false;
    }

    if (!WriteProcessMemory(hProc, pRemote, dllPath, pathLen, nullptr)) {
        VirtualFreeEx(hProc, pRemote, 0, MEM_RELEASE);
        CloseHandle(hProc);
        ShowError("WriteProcessMemory a echoue.");
        return false;
    }

    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLib =
        (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel, "LoadLibraryA");

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, pLoadLib, pRemote, 0, nullptr);
    if (!hThread || hThread == INVALID_HANDLE_VALUE) {
        VirtualFreeEx(hProc, pRemote, 0, MEM_RELEASE);
        CloseHandle(hProc);
        ShowError("CreateRemoteThread a echoue. La DLL n'a pas pu etre injectee.");
        return false;
    }

    DWORD waitRes = WaitForSingleObject(hThread, 30000);
    CloseHandle(hThread);
    VirtualFreeEx(hProc, pRemote, 0, MEM_RELEASE);
    CloseHandle(hProc);

    if (waitRes != WAIT_OBJECT_0) {
        ShowError("Timeout lors de l'injection de la DLL.");
        return false;
    }
    return true;
}

// ============================================================
// Extraction de la DLL embarquée dans un fichier temporaire
// ============================================================
static bool ExtractDLL(char* outPath, int outLen)
{
    char tmpDir[MAX_PATH];
    if (!GetTempPathA(MAX_PATH, tmpDir))
        GetSystemDirectoryA(tmpDir, MAX_PATH);

    _snprintf_s(outPath, outLen, _TRUNCATE, "%s%s", tmpDir, GetDllTmpName());

    HANDLE hFile = CreateFileA(outPath, GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD written = 0;
    BOOL ok = WriteFile(hFile, kEmbeddedDll, kEmbeddedDllSize, &written, nullptr);
    CloseHandle(hFile);
    return ok && (written == kEmbeddedDllSize);
}

// ============================================================
// Point d'entree
// ============================================================
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
    // Une seule instance du launcher
    HANDLE hMutex = CreateMutexA(nullptr, TRUE, MUTEX_NAME);
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        if (hMutex) CloseHandle(hMutex);
        MessageBoxA(nullptr,
            "DPS Counter est deja actif.",
            "DPS Counter", MB_OK | MB_ICONINFORMATION);
        return 0;
    }

    // Chercher SFrame.exe
    DWORD pid = 0;
    for (int i = 0; i < 60 && pid == 0; ++i) {
        pid = FindProcessByName(TARGET_EXE);
        if (pid == 0) {
            if (i == 0) {
                int r = MessageBoxA(nullptr,
                    "SFrame.exe n'est pas detecte.\n"
                    "Lancez le jeu puis cliquez OK, ou Annuler pour quitter.",
                    "DPS Counter", MB_OKCANCEL | MB_ICONQUESTION);
                if (r != IDOK) { CloseHandle(hMutex); return 0; }
            }
        }
        if (pid == 0) Sleep(1000);
    }

    if (pid == 0) {
        CloseHandle(hMutex);
        ShowError("SFrame.exe introuvable apres attente. Abandon.");
        return 1;
    }

    // Creer l'evenement de synchronisation de dechargement
    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE hExitEvent = CreateEventA(&sa, TRUE, FALSE, EVENT_EXIT_NAME);
    if (!hExitEvent) {
        CloseHandle(hMutex);
        ShowError("Impossible de creer l'evenement DPSCounterExit.");
        return 1;
    }

    // Extraire la DLL
    char dllPath[MAX_PATH];
    if (!ExtractDLL(dllPath, MAX_PATH)) {
        CloseHandle(hExitEvent);
        CloseHandle(hMutex);
        ShowError("Impossible d'extraire la DLL vers le repertoire temporaire.");
        return 1;
    }

    // Injecter
    if (!InjectDLL(pid, dllPath)) {
        CloseHandle(hExitEvent);
        CloseHandle(hMutex);
        DeleteFileA(dllPath);
        return 1;
    }

    // Attendre que la DLL demande le dechargement (bouton X dans l'overlay)
    WaitForSingleObject(hExitEvent, INFINITE);
    CloseHandle(hExitEvent);

    Sleep(500);
    DeleteFileA(dllPath);
    CloseHandle(hMutex);
    return 0;
}
