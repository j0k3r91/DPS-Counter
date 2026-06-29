/**
 * dpscounter_dll.cpp - v2.0  (x86, Win32, Rappelz / SFrame.exe)
 *
 * NOUVELLE APPROCHE : hook post-cipher, pre-dispatch
 * ===================================================
 * Au lieu de hooker recv et dechiffrer manuellement, on hooke
 * APRES que XBasicCipher::Decode a tourne, juste avant OnReceive.
 * A ce stade [ebp-0x3010] contient les donnees en clair.
 *
 * Pattern unique dans SFrame.exe (stable, RVA 0x47CB90) :
 *   8D 8D F0 CF FF FF   lea  ecx,[ebp-0x3010]
 *   51                  push ecx              <- hook ici (5 bytes)
 *   8B CE               mov  ecx,esi
 *   FF D2               call edx   (-> OnReceive)
 *
 * Hook type : JMP (E9, pas CALL) -> pas d'adresse de retour extra.
 *
 * Contexte au moment du JMP vers notre stub :
 *   ecx = ptr buffer decrypte
 *   [esp+0] = size  (ebx pousse par "push ebx" avant notre hook)
 *   esi = dispatcher object
 *   edx = OnReceive vtable fn
 *
 * Pourquoi JMP (E9) et pas CALL (E8) ?
 *   - Un CALL pousserait une adresse de retour supplementaire sur la pile.
 *   - A notre site de hook, push ebx (size) est deja sur la pile.
 *   - Si on ajoute un ret_addr, OnReceive verrait [buf_ptr][ret_addr]
 *     au lieu de [buf_ptr][size] -> crash garanti.
 *   - Avec JMP, on entre dans le stub sans modifier la pile.
 *
 * Stack au moment du JMP vers le stub :
 *   [esp+0] = size
 *   ecx = buf_ptr, esi = dispatcher, edx = OnReceive
 *
 * Le stub appelle ProcessDecryptedBuffer(buf_ptr, size), puis execute
 * les bytes voles (push ecx; mov ecx,esi; call edx) et JMP retour.
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <windowsx.h>
#include <psapi.h>
#include <d3d9.h>
#include <d3dx9.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <io.h>
#include <fcntl.h>

#pragma comment(lib, "psapi.lib")

// ============================================================
// DEBUG: active les dumps hexa des paquets bruts (desactiver en release)
// ============================================================
#define DPS_DEBUG

// ============================================================
// Logger
// ============================================================
static CRITICAL_SECTION g_logCS;
static FILE*            g_logFile = nullptr;

static void LogInit()
{
    InitializeCriticalSection(&g_logCS);
    char path[MAX_PATH] = {};
    HMODULE hSelf = nullptr;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCSTR)(void*)LogInit, &hSelf);
    if (hSelf)
    {
        GetModuleFileNameA(hSelf, path, MAX_PATH);
        char* sl = strrchr(path, '\\');
        if (sl) *(sl + 1) = '\0'; else path[0] = '\0';
    }
    else GetTempPathA(MAX_PATH, path);
    strncat_s(path, MAX_PATH, "dpscounter.log", _TRUNCATE);
    // Ouverture avec FILE_SHARE_READ pour permettre la lecture en live
    HANDLE hLog = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ,
                              nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hLog != INVALID_HANDLE_VALUE)
    {
        int fd = _open_osfhandle((intptr_t)hLog, 0);
        if (fd != -1) g_logFile = _fdopen(fd, "w");
        else CloseHandle(hLog);
    }
    if (g_logFile)
    {
        fprintf(g_logFile, "=== DPS Counter v2.0 (post-cipher hook) tick=%lu ===\n",
                GetTickCount());
        fflush(g_logFile);
    }
}
static void LogClose()
{
    if (!g_logFile) return;
    EnterCriticalSection(&g_logCS);
    fclose(g_logFile); g_logFile = nullptr;
    LeaveCriticalSection(&g_logCS);
    DeleteCriticalSection(&g_logCS);
}
static void Log(const char* fmt, ...)
{
    if (!g_logFile) return;
    EnterCriticalSection(&g_logCS);
    fprintf(g_logFile, "[%8lu] ", GetTickCount());
    va_list va; va_start(va, fmt);
    vfprintf(g_logFile, fmt, va);
    va_end(va);
    fputc('\n', g_logFile);
    fflush(g_logFile);
    LeaveCriticalSection(&g_logCS);
}

// ============================================================
// Prototypes forward
// ============================================================
static DWORD WINAPI UnloadThread(LPVOID);
static DWORD WINAPI ScanNameByHandleThread(LPVOID pArg);

// ============================================================
// Constantes opcodes Rappelz
// ============================================================
static const unsigned short TM_SC_ENTER           = 3;
static const unsigned short TM_SC_LEAVE           = 9;
static const unsigned short TM_SC_ATTACK_EVENT    = 101;
static const unsigned short TM_SC_ADD_SUMMON_INFO = 301;
static const unsigned short TM_SC_ADD_PET_INFO    = 351;
static const unsigned short TM_SC_SKILL           = 401;
static const unsigned short TM_SC_STATE_RESULT    = 406; // DoT ticks

static const unsigned char GAME_PLAYER = 0;
static const unsigned char GAME_SUMMON = 4;
static const unsigned char GAME_PET    = 7;

static const unsigned char ATK_FLAG_MISS  = (1 << 2);

static const unsigned char SR_DAMAGE       = 0;
static const unsigned char SR_MAGIC_DAMAGE = 1;
static const unsigned char SR_DAMAGE_KB    = 2;
static const unsigned char SR_RESULT       = 10; // state/buff/debuff effect
static const unsigned char SR_ADD_HP       = 20;
static const unsigned char SR_ADD_MP       = 21;
static const unsigned char SR_ADD_HP_MP_SP = 22;
static const unsigned char SR_REBIRTH      = 23;
static const unsigned char SR_RUSH         = 30;
static const unsigned char SR_CHAIN_DAMAGE = 40;
static const unsigned char SR_CHAIN_MAGIC  = 41;
static const unsigned char SR_CHAIN_HEAL   = 42;

// Detecte a l'attache DLL selon SizeOfImage du module principal :
//   < 9 000 000 bytes (~8.5 MB) --> Sframe.exe nouveau client (7 types elementaux)
//   >= 9 000 000 bytes (~9.5 MB) --> SFrame.exe ancien client (17 types elementaux)
static bool g_clientV7 = false;
// 12.6 MB+ clients : skill_id passe de 4→3 bytes, skill_level supprime (shift -2)
static bool g_clientShiftedSkill = false;

// Declarations avancees (defini plus bas dans le fichier)
static HMODULE g_hMod = nullptr;  // initialise dans DllMain
static int     g_scrollOffset = 0;
// Vrai si localNameCache a ete renseigne depuis un packet reseau (source autoritaire).
// Empeche le scan heap d'ecraser un nom deja correct.
static bool    g_localNameFromPacket = false;

static int SkillResultSize(unsigned char t)
{
    // DamageType = 1+4+4+1+4+4 + N*2 bytes (N = nombre de types elementaux)
    //   Ancien client (~9.9 MB, SFrame.exe) : N=17 -> 52 bytes
    //   Nouveau client (~8.9 MB, Sframe.exe) : N=7  -> 32 bytes
    const int dmgSz = g_clientV7 ? (1+4+4+1+4+4 + 7*2)   // 32
                                 : (1+4+4+1+4+4 + 17*2);  // 52
    switch (t)
    {
    case SR_DAMAGE: case SR_MAGIC_DAMAGE:      return dmgSz;
    case SR_DAMAGE_KB:                         return dmgSz + 13;
    case SR_RESULT:                            return 10; // 1+4+1+4 (pas d'elemental)
    case SR_ADD_HP: case SR_ADD_MP:            return 13; // 1+4+4+4
    case SR_ADD_HP_MP_SP:                      return 25; // 1+4+4+4+4+4+4
    case SR_REBIRTH:                           return 23; // 1+4+4+4+4+4+2
    case SR_RUSH:                              return 19; // 1+4+1+4+4+4+1
    case SR_CHAIN_DAMAGE: case SR_CHAIN_MAGIC: return dmgSz + 4;
    case SR_CHAIN_HEAL:                        return 17; // 1+4+4+4+4 (pas d'elemental)
    default: return 0;
    }
}

// ============================================================
// Compteurs de diagnostic (visibles sur l'overlay)
// ============================================================
static volatile LONG g_debugBufCalls = 0;
static volatile LONG g_debugPkt101   = 0;
static volatile LONG g_debugPkt401   = 0;
static volatile LONG g_debugHits     = 0;

// ============================================================
// Stream accumulator
// ============================================================
#define STREAM_BUF_SIZE 131072

static unsigned char    g_streamBuf[STREAM_BUF_SIZE];
static int              g_streamUsed = 0;
static CRITICAL_SECTION g_streamCS;

static void StreamCS_Init() { InitializeCriticalSection(&g_streamCS); }

static bool ValidateHeader(const unsigned char* p, int avail)
{
    if (avail < 7) return false;
    unsigned int sz; memcpy(&sz, p, 4);
    if (sz < 7 || sz > 32768) return false;
    unsigned char cs = 0;
    for (int i = 0; i < 6; ++i) cs += p[i];
    return cs == p[6];
}

// ============================================================
// Entites
// ============================================================
#define MAX_ENTITIES 512

struct EntityInfo {
    unsigned int handle;
    unsigned int master_handle;
    char         name[24];
    bool         active;
};

static EntityInfo       g_entities[MAX_ENTITIES];
static CRITICAL_SECTION g_entCS;

static void EntCS_Init()  { InitializeCriticalSection(&g_entCS); }
static void EntCS_Enter() { EnterCriticalSection(&g_entCS); }
static void EntCS_Leave() { LeaveCriticalSection(&g_entCS); }

static EntityInfo* FindEntity(unsigned int h)
{
    for (int i = 0; i < MAX_ENTITIES; ++i)
        if (g_entities[i].active && g_entities[i].handle == h)
            return &g_entities[i];
    return nullptr;
}
static EntityInfo* AllocEntity(unsigned int h)
{
    EntityInfo* e = FindEntity(h);
    if (e) return e;
    for (int i = 0; i < MAX_ENTITIES; ++i)
        if (!g_entities[i].active)
        {
            memset(&g_entities[i], 0, sizeof(EntityInfo));
            g_entities[i].handle = h;
            g_entities[i].active = true;
            return &g_entities[i];
        }
    return nullptr;
}
static unsigned int ResolveOwner(unsigned int h)
{
    EntCS_Enter();
    EntityInfo* e = FindEntity(h);
    unsigned int ow = (e && e->master_handle) ? e->master_handle : h;
    EntCS_Leave();
    return ow;
}
static volatile unsigned int g_localHandle = 0;
static char g_localNameCache[24] = {};
static volatile LONG g_handleScanDone = 0;

// Evite de lancer plusieurs scans concurents pour le meme handle.
static CRITICAL_SECTION g_nameScanCS;
static unsigned int     g_nameScanHandles[256] = {};
static int              g_nameScanCount = 0;

static void NameScanCS_Init() { InitializeCriticalSection(&g_nameScanCS); }

static bool TryQueueNameScan(unsigned int h)
{
    if (!h) return false;
    EnterCriticalSection(&g_nameScanCS);
    for (int i = 0; i < g_nameScanCount; ++i)
    {
        if (g_nameScanHandles[i] == h)
        {
            LeaveCriticalSection(&g_nameScanCS);
            return false;
        }
    }
    if (g_nameScanCount < (int)(sizeof(g_nameScanHandles) / sizeof(g_nameScanHandles[0])))
        g_nameScanHandles[g_nameScanCount++] = h;
    LeaveCriticalSection(&g_nameScanCS);
    return true;
}

static void MarkNameScanDone(unsigned int h)
{
    EnterCriticalSection(&g_nameScanCS);
    for (int i = 0; i < g_nameScanCount; ++i)
    {
        if (g_nameScanHandles[i] == h)
        {
            g_nameScanHandles[i] = g_nameScanHandles[g_nameScanCount - 1];
            g_nameScanCount--;
            break;
        }
    }
    LeaveCriticalSection(&g_nameScanCS);
}

// Scan le heap en background pour trouver le handle du local player.
// Strategie 1 : cherche le pointeur vers la string statique du nom (const char*) sur le heap.
// Strategie 2 : cherche la string du nom en ligne sur le heap (fallback).
static DWORD WINAPI ScanLocalHandleThread(LPVOID)
{
    Sleep(2000); // laisser le jeu se stabiliser
    if (g_localHandle != 0 || !g_localNameCache[0]) { InterlockedExchange(&g_handleScanDone,1); return 0; }

    int nameLen = (int)strlen(g_localNameCache);
    if (nameLen < 2 || nameLen > 20) { InterlockedExchange(&g_handleScanDone,1); return 0; }

    // Adresse statique de la string du nom (pointeur que le jeu stocke probablement)
    // LOCAL_NAME_RVA = 0x00855168 (valide uniquement sur l'ancien client 17-elem)
    // Sur le client 7-elem (g_clientV7), cette RVA est inconnue -> on ne fait que la strategie 2
    HMODULE hSFrame2     = GetModuleHandleA("SFrame.exe");
    BYTE*   staticNameAddr = (!g_clientV7 && hSFrame2) ? ((BYTE*)hSFrame2 + 0x00855168u) : nullptr;
    DWORD   staticNamePtr  = staticNameAddr ? (DWORD)staticNameAddr : 0;

    const BYTE fb  = (BYTE)g_localNameCache[0];
    BYTE ptrBytes[4]; memcpy(ptrBytes, &staticNamePtr, 4);

    unsigned int foundH = 0;
    int          foundCount = 0;

    BYTE* addr = (BYTE*)0x10000;
    LONGLONG scanned = 0;
    const LONGLONG SCAN_LIMIT = 128LL * 1024 * 1024; // reduit : heap privee ~64-128 MB suffit

    Log("ScanHandle: start namePtr=0x%08X name=[%s]", staticNamePtr, g_localNameCache);

    while (addr < (BYTE*)0x7FF00000 && scanned < SCAN_LIMIT)
    {
        if (g_localHandle != 0) break;
        MEMORY_BASIC_INFORMATION mbi = {};
        if (!VirtualQuery(addr, &mbi, sizeof(mbi)) || mbi.RegionSize == 0) break;

        // Scanne uniquement les pages read/write privees commitees (heap, stacks)
        if (mbi.State == MEM_COMMIT &&
            mbi.Type  == MEM_PRIVATE &&
            !(mbi.Protect & (PAGE_GUARD|PAGE_NOACCESS)) &&
            (mbi.Protect & (PAGE_READWRITE|PAGE_WRITECOPY|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY)))
        {
            BYTE* b = (BYTE*)mbi.BaseAddress;
            SIZE_T s = mbi.RegionSize;
            __try {
                for (SIZE_T off = 0; off + 4 <= s; ++off)
                {
                    // Strategie 1 : pointeur vers la string statique
                    if (staticNamePtr && off + 4 <= s &&
                        b[off] == ptrBytes[0] && b[off+1] == ptrBytes[1] &&
                        b[off+2] == ptrBytes[2] && b[off+3] == ptrBytes[3])
                    {
                        for (int d = -256; d <= 256; d += 4)
                        {
                            ptrdiff_t p2 = (ptrdiff_t)off + d;
                            if (p2 < 0 || p2 + 4 > (ptrdiff_t)s) continue;
                            unsigned int v;
                            memcpy(&v, b + p2, 4);
                            // Filtre strict : high byte doit etre exactement 0x80 (handles joueur Rappelz)
                            if ((v & 0xFF000000u) == 0x80000000u && v > 0x80000100u && v < 0x80FFFFFFu)
                            {
                                if (foundCount == 0 || v == foundH) {
                                    foundH = v; foundCount++;
                                    Log("ScanHandle[ptr]: ptr at %p d=%d h=0x%08X", b+off, d, v);
                                } else {
                                    Log("ScanHandle[ptr]: ambig h=0x%08X vs 0x%08X", foundH, v);
                                }
                            }
                        }
                    }
                    // Strategie 2 : string inline, uniquement si pas encore trouve
                    if (!foundH && off + (SIZE_T)nameLen + 1 <= s &&
                        b[off] == fb &&
                        memcmp(b + off, g_localNameCache, (size_t)nameLen) == 0 &&
                        b[off + nameLen] == 0)
                    {
                        // Filtre strict : high byte exactement 0x80 (handles Rappelz joueur)
                        auto okHandle = [](unsigned int v) -> bool {
                            return (v & 0xFF000000u) == 0x80000000u && v > 0x80000100u && v < 0x80FFFFFFu;
                        };
                        // Offset exact -4 en priorite (confirme par analyse CE : handle = name[-4])
                        if (off >= 4) {
                            unsigned int v; memcpy(&v, b + off - 4, 4);
                            if (okHandle(v)) {
                                if (foundCount == 0 || v == foundH) {
                                    foundH = v; foundCount++;
                                    Log("ScanHandle[str-4]: str at %p h=0x%08X", b+off, v);
                                }
                            }
                        }
                        // Fallback +-64 si -4 n'a rien donne
                        if (!foundH) {
                            for (int d = -64; d <= 64; d += 4)
                            {
                                ptrdiff_t p2 = (ptrdiff_t)off + d;
                                if (p2 < 0 || p2 + 4 > (ptrdiff_t)s) continue;
                                unsigned int v;
                                memcpy(&v, b + p2, 4);
                                if (okHandle(v))
                                {
                                    if (foundCount == 0 || v == foundH) {
                                        foundH = v; foundCount++;
                                        Log("ScanHandle[str]: str at %p d=%d h=0x%08X", b+off, d, v);
                                    }
                                }
                            }
                        }
                    }
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
            scanned += (LONGLONG)s;
        }
        BYTE* nx = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if (nx <= addr) break;
        addr = nx;
    }

    if (foundH && g_localHandle == 0)
    {
        g_localHandle = foundH;
        EntCS_Enter();
        EntityInfo* e = AllocEntity(foundH);
        if (e && !e->name[0])
            _snprintf_s(e->name, sizeof(e->name), _TRUNCATE, "%s", g_localNameCache);
        EntCS_Leave();
        // Les CombatEntry seront mis a jour par le refresh dans DrawDPSPanel
        Log("ScanHandle: local player h=%u name=[%s]", foundH, g_localNameCache);
    }
    else if (!foundH)
        Log("ScanHandle: aucun handle trouve pour [%s]", g_localNameCache);

    InterlockedExchange(&g_handleScanDone, 1);
    return 0;
}

static void GetEntityName(unsigned int h, char* out, int outLen)
{
    EntCS_Enter();
    EntityInfo* e = FindEntity(h);
    if (e && e->name[0])
        _snprintf_s(out, outLen, outLen-1, "%s", e->name);
    // Fallback local: affiche le nom local meme s'il vient du scan memoire.
    else if (h == g_localHandle && g_localNameCache[0])
        _snprintf_s(out, outLen, outLen-1, "%s", g_localNameCache);
    else
        _snprintf_s(out, outLen, outLen-1, "#%u", h);
    EntCS_Leave();
}

// Lit le nom et le handle du joueur local depuis des adresses statiques de SFrame.exe
// Verifiees sur 2 sessions (base variable, RVA fixe) :
//   RVA 0x855168 = buffer char nom (max 16 chars)     [VALIDE uniquement sur client 17-elem]
//   RVA 0x8452F4 = uint32 handle du joueur local      [non fiable dans les deux versions]
//   RVA 0x8932BC = buffer char nom V7 (client 7-elem) [VALIDE sur V7 ~8.9 MB]
static const unsigned int LOCAL_NAME_RVA    = 0x00855168;
static const unsigned int LOCAL_HANDLE_RVA  = 0x008452F4;
static const unsigned int LOCAL_NAME_RVA_V7 = 0x008932BC;
static const int          LOCAL_NAME_LEN    = 16;

// Filtre anti-faux-positifs : rejette les chaines internes du jeu
static bool IsValidPlayerName(const char* s, int len)
{
    if (!s || len < 2 || len > 20) return false;
    // Doit commencer par une majuscule
    if (s[0] < 'A' || s[0] > 'Z') return false;
    // Ne doit contenir que des caracteres valides
    for (int i = 0; i < len; ++i) {
        char c = s[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-'))
            return false;
    }
    // Blacklist : prefixes internes du jeu
    if (len >= 5) {
        if (strncmp(s, "state_", 6) == 0) return false;
        if (strncmp(s, "set_",   4) == 0) return false;
        if (strncmp(s, "monster", 7) == 0) return false;
        if (strncmp(s, "skill_", 6) == 0) return false;
        if (strncmp(s, "effect_",7) == 0) return false;
        if (strncmp(s, "item_",  5) == 0) return false;
        if (strncmp(s, "npc_",   4) == 0) return false;
    }
    // Rejette les noms qui sont en majuscules pures (souvent des constantes internes)
    bool hasLower = false;
    for (int i = 0; i < len; ++i) if (s[i] >= 'a' && s[i] <= 'z') { hasLower = true; break; }
    if (!hasLower && len > 3) return false;
    return true;
}

static void ReadLocalPlayerFromMemory()
{
    HMODULE hSFrame = GetModuleHandleA("SFrame.exe");
    if (!hSFrame) return;
    ULONG_PTR base = (ULONG_PTR)hSFrame;

    unsigned int h = 0;
    const char* pName = nullptr;
    unsigned int nameRVA = 0;

    if (g_clientV7) {
        // V7 : lire le nom a l'adresse statique connue
        nameRVA = LOCAL_NAME_RVA_V7;
        pName = (const char*)(base + nameRVA);
        // Le handle n'est pas fiable en statique sur V7 ; ParseEnter completera
    } else {
        nameRVA = LOCAL_NAME_RVA;
        pName = (const char*)(base + nameRVA);
        h = *(volatile unsigned int*)(base + LOCAL_HANDLE_RVA);
        if ((h & 0x80000000) == 0) h = 0;
    }

    int len = 0;
    __try {
        while (len < LOCAL_NAME_LEN && pName[len] >= 0x20 && pName[len] < 0x7F) len++;
    } __except(EXCEPTION_EXECUTE_HANDLER) { len = 0; }

    if (len > 0 && IsValidPlayerName(pName, len))
    {
        _snprintf_s(g_localNameCache, sizeof(g_localNameCache), _TRUNCATE, "%.*s", len, pName);
        Log("ReadLocalPlayerMemory: V7=%d RVA=0x%X name=[%s]", (int)g_clientV7, nameRVA, g_localNameCache);
    }
    else
        Log("ReadLocalPlayerMemory: V7=%d RVA=0x%X len=%d invalid", (int)g_clientV7, nameRVA, len);

    if (h && g_localNameCache[0])
    {
        g_localHandle = h;
        EntCS_Enter();
        EntityInfo* e = AllocEntity(h);
        if (e && !e->name[0])
            _snprintf_s(e->name, sizeof(e->name), _TRUNCATE, "%s", g_localNameCache);
        EntCS_Leave();
        Log("LocalPlayer: handle=%u name=[%s]", h, g_localNameCache);
    }
    else if (!h)
        Log("LocalPlayer: handle read failed (h=%u len=%d)", h, len);
}

static bool IsPlayerEntity(unsigned int h)
{
    // Bit 31 set = joueur/pet/ally. Bit 31 clear = mob.
    if (h & 0x80000000) return true;
    EntCS_Enter();
    bool known = (FindEntity(h) != nullptr);
    EntCS_Leave();
    return known;
}

// ============================================================
// Statistiques de combat
// ============================================================
#define MAX_COMBATANTS 64

struct CombatEntry {
    unsigned int handle;
    unsigned int ownerHandle;
    char         name[24];
    bool         isPet;
    LONGLONG     dmgOut;
    LONGLONG     healOut;
    LONGLONG     dmgIn;
    int          maxHit;   // plus grand coup sorti
    int          maxHeal;  // plus grande valeur de soin
    int          maxRcvd;  // plus grand coup recu
};

static CombatEntry    g_combat[MAX_COMBATANTS];
static int            g_combatCount = 0;
static DWORD          g_fightStart  = 0;
static DWORD          g_fightEnd    = 0;
static DWORD          g_lastHit     = 0;  // max des trois — pour timeout global
static DWORD          g_lastDmgOut  = 0;  // dernier evenement TAB_DPS
static DWORD          g_lastHeal    = 0;  // dernier evenement TAB_HEAL
static DWORD          g_lastDmgIn   = 0;  // dernier evenement TAB_RCVD
static DWORD          g_fightTimeout = 20000;  // charge depuis INI

static CRITICAL_SECTION g_statsCS;
static void StatsCS_Init()  { InitializeCriticalSection(&g_statsCS); }
static void StatsCS_Enter() { EnterCriticalSection(&g_statsCS); }
static void StatsCS_Leave() { LeaveCriticalSection(&g_statsCS); }

enum MetricTab { TAB_DPS = 0, TAB_HEAL = 1, TAB_RCVD = 2, TAB_MAXHIT = 3 };
static MetricTab g_tab = TAB_DPS;

static CombatEntry* FindOrCreateCombat(unsigned int h)
{
    for (int i = 0; i < g_combatCount; ++i)
        if (g_combat[i].handle == h) return &g_combat[i];
    if (g_combatCount >= MAX_COMBATANTS) return nullptr;
    CombatEntry* e = &g_combat[g_combatCount++];
    memset(e, 0, sizeof(CombatEntry));
    e->handle      = h;
    e->ownerHandle = ResolveOwner(h);
    GetEntityName(h, e->name, sizeof(e->name));
    EntCS_Enter();
    EntityInfo* ei = FindEntity(h);
    e->isPet = (ei && ei->master_handle != 0);
    EntCS_Leave();

    // Fallback 6.3: si le nom n'est pas encore connu (#handle), tenter un scan memoire
    // pour mapper [handle]->name meme sans packet ENTER exploitable.
    if (e->name[0] == '#' && (h & 0x80000000u) && TryQueueNameScan(h))
        CloseHandle(CreateThread(nullptr, 0, ScanNameByHandleThread,
                                 (LPVOID)(uintptr_t)h, 0, nullptr));

    // Heuristique injection tardive : en Rappelz V7, les pets/invocations ont des handles
    // de la forme 0xCxxxxxxx (bit31+bit30), les joueurs 0x8xxxxxxx (bit31 seul).
    // Si l'entite est inconnue et ressemble a un pet, on l'attribue directement au
    // joueur local en attendant le ParseEnter qui confirmera le vrai master.
    if (!e->isPet && e->ownerHandle == h && (h >> 30) == 3u && g_localHandle != 0) {
        e->ownerHandle = g_localHandle;
        e->isPet       = true;
        Log("PetDetect(0xC): h=0x%08X -> owner=0x%08X (temp, avant ParseEnter)", h, g_localHandle);
    }
    Log("NewCombatant: h=%u owner=%u name=[%s] isPet=%d isPlayer=%d",
        h, e->ownerHandle, e->name, (int)e->isPet, (int)IsPlayerEntity(h));
    return e;
}
static void ResetCombat()
{
    StatsCS_Enter();
    memset(g_combat, 0, sizeof(CombatEntry) * g_combatCount);
    g_combatCount = 0;
    g_fightStart = g_fightEnd = g_lastHit = 0;
    g_lastDmgOut = g_lastHeal = g_lastDmgIn = 0;
    g_scrollOffset = 0;
    StatsCS_Leave();
}
static void OnCombatEvent(int tab)
{
    DWORD now = GetTickCount();
    if      (tab == TAB_DPS)  g_lastDmgOut = now;
    else if (tab == TAB_HEAL) g_lastHeal   = now;
    else                       g_lastDmgIn  = now;
    g_lastHit = g_lastDmgOut;
    if (g_lastHeal  > g_lastHit) g_lastHit = g_lastHeal;
    if (g_lastDmgIn > g_lastHit) g_lastHit = g_lastDmgIn;
    if (g_fightStart == 0) {
        g_fightStart = now; g_fightEnd = 0;
    } else if (g_fightEnd != 0) {
        // Nouveau combat apres une pause : reset des donnees
        memset(g_combat, 0, sizeof(CombatEntry) * g_combatCount);
        g_combatCount = 0;
        g_fightStart = now; g_fightEnd = 0;
        g_scrollOffset = 0;
        g_lastDmgOut = g_lastHeal = g_lastDmgIn = 0;
        if      (tab == TAB_DPS)  g_lastDmgOut = now;
        else if (tab == TAB_HEAL) g_lastHeal   = now;
        else                       g_lastDmgIn  = now;
        g_lastHit = now;
    }
}
static void RecordDamageOut(unsigned int atk, int dmg)
{
    if (dmg <= 0) return;
    InterlockedIncrement(&g_debugHits);
    StatsCS_Enter();
    OnCombatEvent(TAB_DPS);
    CombatEntry* e = FindOrCreateCombat(atk);
    if (e) {
        e->dmgOut += dmg;
        if (dmg > e->maxHit) e->maxHit = dmg;
        // Log throttle : 1 log tous les 10 hits par combattant
        if ((g_debugHits % 10) == 1)
            Log("DmgOut: h=%u name=[%s] +%d total=%lld max=%d", atk, e->name, dmg, e->dmgOut, e->maxHit);
    }
    StatsCS_Leave();
}
static void RecordHeal(unsigned int caster, int amount)
{
    if (amount <= 0) return;
    StatsCS_Enter();
    OnCombatEvent(TAB_HEAL);
    CombatEntry* e = FindOrCreateCombat(caster);
    if (e) {
        e->healOut += amount;
        if (amount > e->maxHeal) e->maxHeal = amount;
    }
    StatsCS_Leave();
}
static void RecordDamageIn(unsigned int tgt, int dmg)
{
    if (dmg <= 0) return;
    StatsCS_Enter();
    OnCombatEvent(TAB_RCVD);
    CombatEntry* e = FindOrCreateCombat(tgt);
    if (e) {
        e->dmgIn += dmg;
        if (dmg > e->maxRcvd) e->maxRcvd = dmg;
    }
    StatsCS_Leave();
}
static void CheckFightTimeout()
{
    if (g_fightStart == 0 || g_fightEnd != 0) return;
    if (GetTickCount() - g_lastHit > g_fightTimeout) g_fightEnd = GetTickCount();
}

// ============================================================
// Helpers lecture memoire
// ============================================================
static unsigned int   ReadU32(const unsigned char* p) { unsigned int   v; memcpy(&v, p, 4); return v; }
static int            ReadI32(const unsigned char* p) { int            v; memcpy(&v, p, 4); return v; }
static unsigned short ReadU16(const unsigned char* p) { unsigned short v; memcpy(&v, p, 2); return v; }

// ============================================================
// Scan memoire pour trouver le nom du joueur local quand seul le handle est connu
// (injection mi-session sur client V7, pas de ParseEnter recu pour soi-meme).
// ============================================================
static DWORD WINAPI ScanNameByHandleThread(LPVOID pArg)
{
    unsigned int localH = (unsigned int)(uintptr_t)pArg;
    if (!localH) return 0;
    const bool isLocalTarget = (localH == g_localHandle);
    Sleep(1000);
    // Ne pas ecraser un nom deja fourni par un packet reseau (source autoritaire)
    if (isLocalTarget && g_localNameCache[0] && g_localNameFromPacket) { MarkNameScanDone(localH); return 0; }

    BYTE hBytes[4];
    memcpy(hBytes, &localH, 4);

    struct NC { char name[24]; int count; };
    NC cands[64] = {}; int nCands = 0;

    auto isNameChar = [](BYTE c) -> bool {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') || c == '_' || c == '-';
    };

    auto isNameStart = [](BYTE c) -> bool {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
    };

    auto addCandidate = [&](const char* cand, int len)
    {
        if (!cand || len < 2 || len > 20) return;
        char tmp[24] = {};
        memcpy(tmp, cand, len);
        // Filtre anti-faux-positifs
        if (!IsValidPlayerName(tmp, len)) return;
        bool found = false;
        for (int k = 0; k < nCands; ++k)
            if (strcmp(cands[k].name, tmp) == 0) { cands[k].count++; found = true; break; }
        if (!found && nCands < 64)
            { memcpy(cands[nCands].name, tmp, len+1); cands[nCands].count = 1; nCands++; }
    };

    auto readAsciiAt = [&](const BYTE* b, SIZE_T s, SIZE_T pos, char* out, int outSz) -> int
    {
        if (!b || !out || outSz < 2 || pos >= s) return 0;
        if (!isNameStart(b[pos])) return 0;
        int len = 0;
        while (len < outSz - 1 && pos + (SIZE_T)len < s && isNameChar(b[pos + len])) ++len;
        if (len < 2 || len > 20) return 0;
        if (pos + (SIZE_T)len >= s || b[pos + len] != 0) return 0;
        memcpy(out, b + pos, len);
        out[len] = 0;
        return len;
    };

    auto readUtf16At = [&](const BYTE* b, SIZE_T s, SIZE_T pos, char* out, int outSz) -> int
    {
        if (!b || !out || outSz < 2 || pos + 1 >= s) return 0;
        BYTE c0 = b[pos];
        BYTE z0 = b[pos + 1];
        if (z0 != 0 || !isNameStart(c0)) return 0;
        int len = 0;
        while (len < outSz - 1)
        {
            SIZE_T idx = pos + (SIZE_T)len * 2;
            if (idx + 1 >= s) return 0;
            BYTE c = b[idx];
            BYTE z = b[idx + 1];
            if (z != 0) return 0;
            if (c == 0) break;
            if (!isNameChar(c)) return 0;
            out[len++] = (char)c;
        }
        if (len < 2 || len > 20) return 0;
        SIZE_T endIdx = pos + (SIZE_T)len * 2;
        if (endIdx + 1 >= s || b[endIdx] != 0 || b[endIdx + 1] != 0) return 0;
        out[len] = 0;
        return len;
    };

    // Sur V7 : fenetre ultra-serree handle+4 a handle+24 uniquement.
    // La struct joueur en memoire a la forme [handle(4)][name(<=20)][nul].
    // En utilisant l'offset exact, "Erzate" (ancien perso, handle different)
    // n'apparait JAMAIS a handle+4 pour le handle courant -> plus de faux positif.
    //
    // Sur l'ancien client : fenetre large [-80,+80] avec vote (comme avant).
    const bool tightScan = g_clientV7;

    BYTE* addr = (BYTE*)0x10000;
    const LONGLONG SCAN_LIMIT = 384LL * 1024 * 1024;
    LONGLONG scanned = 0;

    while (addr < (BYTE*)0x7FF00000 && scanned < SCAN_LIMIT)
    {
        if (isLocalTarget && g_localNameCache[0] && g_localNameFromPacket) break;
        MEMORY_BASIC_INFORMATION mbi = {};
        if (!VirtualQuery(addr, &mbi, sizeof(mbi)) || mbi.RegionSize == 0) break;

        bool regionOk = (mbi.State == MEM_COMMIT) &&
                (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED || mbi.Type == MEM_IMAGE) &&
                        !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
                        (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_READONLY |
                                        PAGE_READWRITE | PAGE_WRITECOPY |
                                        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));

        if (regionOk)
        {
            BYTE*  b = (BYTE*)mbi.BaseAddress;
            SIZE_T s = mbi.RegionSize;
            __try {
                for (SIZE_T off = 0; off + 4 <= s; ++off)
                {
                    if (b[off]   != hBytes[0] || b[off+1] != hBytes[1] ||
                        b[off+2] != hBytes[2] || b[off+3] != hBytes[3]) continue;

                    if (tightScan)
                    {
                        // 6.3: le nom peut etre inline ASCII/UTF-16 a plusieurs offsets,
                        // ou indirect via pointeur proche de la structure contenant le handle.
                        static const int kNameOffsets[] = {4,8,12,16,20,24,28,32,36,40,44,48};
                        for (int oi = 0; oi < (int)(sizeof(kNameOffsets)/sizeof(kNameOffsets[0])); ++oi)
                        {
                            SIZE_T n = off + (SIZE_T)kNameOffsets[oi];
                            if (n >= s) continue;
                            char cand[24] = {};
                            int lenA = readAsciiAt(b, s, n, cand, (int)sizeof(cand));
                            if (lenA > 0) addCandidate(cand, lenA);
                            int lenU = readUtf16At(b, s, n, cand, (int)sizeof(cand));
                            if (lenU > 0) addCandidate(cand, lenU);
                        }

                        for (int pd = -16; pd <= 48; pd += 4)
                        {
                            ptrdiff_t p2 = (ptrdiff_t)off + pd;
                            if (p2 < 0 || p2 + 4 > (ptrdiff_t)s) continue;
                            unsigned int pv = 0;
                            memcpy(&pv, b + p2, 4);
                            if (pv < 0x10000u || pv > 0x7FF00000u) continue;
                            __try {
                                const BYTE* pb = (const BYTE*)(uintptr_t)pv;
                                char cand[24] = {};
                                int lenA = 0;
                                if (isNameStart(pb[0])) {
                                    while (lenA < 20 && isNameChar(pb[lenA])) ++lenA;
                                    if (lenA >= 2 && lenA <= 20 && pb[lenA] == 0) {
                                        memcpy(cand, pb, lenA);
                                        cand[lenA] = 0;
                                        addCandidate(cand, lenA);
                                    }
                                }
                                if (pb[1] == 0 && isNameStart(pb[0])) {
                                    int lenU = 0;
                                    while (lenU < 20) {
                                        BYTE c = pb[lenU * 2];
                                        BYTE z = pb[lenU * 2 + 1];
                                        if (z != 0) { lenU = 0; break; }
                                        if (c == 0) break;
                                        if (!isNameChar(c)) { lenU = 0; break; }
                                        cand[lenU++] = (char)c;
                                    }
                                    if (lenU >= 2 && lenU <= 20 && pb[lenU * 2] == 0 && pb[lenU * 2 + 1] == 0) {
                                        cand[lenU] = 0;
                                        addCandidate(cand, lenU);
                                    }
                                }
                            } __except(EXCEPTION_EXECUTE_HANDLER) {}
                        }
                    }
                    else
                    {
                        // Ancien client : fenetre large avec vote
                        int wStart = (int)off - 80; if (wStart < 0) wStart = 0;
                        int wEnd   = (int)off + 80; if ((SIZE_T)wEnd > s) wEnd = (int)s;
                        for (int d = wStart; d < wEnd; )
                        {
                            if (!isNameChar(b[d])) { ++d; continue; }
                            if (d > 0 && isNameChar(b[d-1])) { ++d; continue; }
                            int len = 0;
                            while (len <= 20 && d+len < wEnd && isNameChar(b[d+len])) ++len;
                            if (len < 4 || len > 20) { d += (len>0?len:1); continue; }
                            if (d+len >= (int)s || b[d+len] != 0) { d += len; continue; }
                            if (!(b[d] >= 'A' && b[d] <= 'Z')) { d += len+1; continue; }
                            char cand[24] = {};
                            memcpy(cand, b+d, len);
                            if (!IsValidPlayerName(cand, len)) { d += len+1; continue; }
                            bool found = false;
                            for (int k=0;k<nCands;++k)
                                if (strcmp(cands[k].name,cand)==0){ cands[k].count++; found=true; break; }
                            if (!found && nCands<64)
                                { memcpy(cands[nCands].name,cand,len+1); cands[nCands].count=1; nCands++; }
                            d += len+1;
                        }
                    }
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
            scanned += (LONGLONG)s;
        }
        BYTE* nx = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if (nx <= addr) break;
        addr = nx;
    }

    NC* best = nullptr;
    for (int k = 0; k < nCands; ++k)
        if (!best || cands[k].count > best->count) best = &cands[k];

    // Log TOUS les candidats pour le diagnostic
    Log("ScanNameByHandle: h=0x%08X nCands=%d scanned=%lldMB tight=%d",
        localH, nCands, scanned >> 20, (int)tightScan);
    for (int k = 0; k < nCands; ++k)
        Log("  cand[%d]: [%s] count=%d%s", k, cands[k].name, cands[k].count,
            (best == &cands[k]) ? " <-- WINNER" : "");

    if (best && best->count >= 1)
    {
        EntCS_Enter();
        EntityInfo* mei = AllocEntity(localH);
        if (mei && (!mei->name[0] || isLocalTarget))
            _snprintf_s(mei->name, sizeof(mei->name), _TRUNCATE, "%s", best->name);
        EntCS_Leave();

        if (isLocalTarget && !(g_localNameCache[0] && g_localNameFromPacket))
            _snprintf_s(g_localNameCache, sizeof(g_localNameCache), _TRUNCATE, "%s", best->name);

        StatsCS_Enter();
        for (int ci = 0; ci < g_combatCount; ++ci)
            if (g_combat[ci].handle == localH)
                _snprintf_s(g_combat[ci].name, sizeof(g_combat[ci].name), _TRUNCATE, "%s", best->name);
        StatsCS_Leave();
        Log("ScanNameByHandle: -> using [%s] count=%d", best->name, best->count);
    }
    else
        Log("ScanNameByHandle: aucun nom pour h=0x%08X nCands=%d", localH, nCands);

    MarkNameScanDone(localH);
    return 0;
}

// ============================================================
// Parsers de paquets (donnees deja dechiffrees)
// ============================================================
static void ParseEnter(const unsigned char* p, unsigned int sz)
{
    if (sz < 26) return;
    unsigned int  handle  = ReadU32(p + 8);
    unsigned char objType = p[25];
    if (objType == GAME_PLAYER)
    {
        // isFirstEnter : le client marque le propre personnage local avec ce flag.
        // Offset 59 valide pour l'ancien client ; en V7 on s'appuie aussi sur la
        // detection par nom (ci-dessous) pour etre robuste aux deux versions.
        bool isFirstEnter = (sz > 59) ? (p[59] != 0) : false;
        if (sz >= 89 + 19)
        {
            EntCS_Enter();
            EntityInfo* e = AllocEntity(handle);
            if (e) {
                e->master_handle = 0;
                _snprintf_s(e->name, sizeof(e->name), _TRUNCATE, "%.*s", 19, (const char*)(p + 89));
            }
            EntCS_Leave();
            // Mettre a jour le nom dans les CombatEntry existants (nom recu tardivement)
            if (e && e->name[0]) {
                StatsCS_Enter();
                for (int ci = 0; ci < g_combatCount; ++ci)
                    if (g_combat[ci].handle == handle)
                        _snprintf_s(g_combat[ci].name, sizeof(g_combat[ci].name), _TRUNCATE, "%s", e->name);
                StatsCS_Leave();
            }
            if (isFirstEnter)
            {
                // isFirstEnter est vrai uniquement pour le personnage local qui entre en jeu.
                // On met TOUJOURS a jour l'identite locale, meme si g_localHandle etait deja connu
                // (gere le cas changement de personnage sans relancer l'EXE).
                if (g_localHandle != handle)
                {
                    Log("CharacterChange: ancien h=%u -> nouveau h=%u name=[%s]",
                        g_localHandle, handle, (e && e->name[0]) ? e->name : "?");
                    g_localHandle        = handle;
                    g_localNameCache[0]  = '\0';
                    g_localNameFromPacket = false;
                    if (e && e->name[0])
                    {
                        _snprintf_s(g_localNameCache, sizeof(g_localNameCache), _TRUNCATE, "%s", e->name);
                        g_localNameFromPacket = true;
                    }
                    ResetCombat(); // nouveau personnage = nouveau combat
                }
                else if (g_localHandle == 0)
                {
                    g_localHandle = handle;
                    if (!g_localNameCache[0] && e && e->name[0])
                    {
                        _snprintf_s(g_localNameCache, sizeof(g_localNameCache), _TRUNCATE, "%s", e->name);
                        g_localNameFromPacket = true;
                    }
                }
            }
            // Detecter le local par nom si g_localNameCache est connu et handle pas encore defini
            if (g_localHandle == 0 && g_localNameCache[0] && e && e->name[0] &&
                strncmp(e->name, g_localNameCache, LOCAL_NAME_LEN) == 0)
            {
                g_localHandle = handle;
                Log("LocalPlayer detected via ParseEnter name-match: h=%u", handle);
            }
            // Si on avait deja ce handle (via OPC1000 ou autre), mettre a jour le nom cache.
            // On ecrase TOUJOURS : le packet reseau est plus fiable que le scan heap.
            else if (g_localHandle == handle) {
                if (e && e->name[0]) {
                    if (!g_localNameCache[0])
                        Log("ParseEnter: localNameCache late-set=[%s]", e->name);
                    else if (strcmp(g_localNameCache, e->name) != 0)
                        Log("ParseEnter: localNameCache corrige [%s] -> [%s]", g_localNameCache, e->name);
                    _snprintf_s(g_localNameCache, sizeof(g_localNameCache), _TRUNCATE, "%s", e->name);
                    g_localNameFromPacket = true;
                }
            }
        }
    }
    else if (objType == GAME_SUMMON || objType == GAME_PET)
    {
        if (sz >= 76 + 19)
        {
            unsigned int master = ReadU32(p + 64);
            EntCS_Enter();
            EntityInfo* e = AllocEntity(handle);
            if (e) {
                e->master_handle = master;
                _snprintf_s(e->name, sizeof(e->name), _TRUNCATE, "%.*s", 19, (const char*)(p + 76));
            }
            EntCS_Leave();
            // Mettre a jour ownerHandle dans les CombatEntries existants pour ce pet
            // (le pet peut avoir tire avant que son ParseEnter arrive)
            if (master) {
                StatsCS_Enter();
                for (int ci = 0; ci < g_combatCount; ++ci) {
                    if (g_combat[ci].handle == handle) {
                        g_combat[ci].ownerHandle = master;
                        g_combat[ci].isPet       = true;
                        if (e && e->name[0])
                            _snprintf_s(g_combat[ci].name, sizeof(g_combat[ci].name), _TRUNCATE, "%s", e->name);
                    }
                }
                StatsCS_Leave();

                // Propagation du nom au master si injection tardive (pas de ParseEnter joueur).
                // On ne le fait que si le master a deja des degats en combat (c'est le joueur local)
                // et n'a pas encore de nom dans EntityInfo.
                if (IsPlayerEntity(master)) {
                    // Verifier si master est dans g_combat (injection tardive : on connait son handle)
                    bool masterInCombat = false;
                    StatsCS_Enter();
                    for (int ci = 0; ci < g_combatCount; ++ci)
                        if (g_combat[ci].handle == master)
                            { masterInCombat = true; break; }
                    StatsCS_Leave();

                    if (masterInCombat) {
                        // Identifier le joueur local via le handle du master.
                        // NE PAS propager le nom du pet vers le master (ils ont des noms differents).
                        if (g_localHandle == 0)
                            g_localHandle = master;
                        if (g_localHandle == master && !g_localNameFromPacket) {
                            Log("LocalPlayer from summon: h=0x%08X (scanning for name)", master);
                            if (TryQueueNameScan(master))
                                CloseHandle(CreateThread(nullptr, 0, ScanNameByHandleThread,
                                                         (LPVOID)(uintptr_t)master, 0, nullptr));
                        }
                    }
                }
            }
        }
    }
}

static void ParseAttackEvent(const unsigned char* p, unsigned int sz)
{
    // header[7] + attacker[4] + target[4] + speed[2] + delay[2] + action[1] + flag[1] + count[1] = 22
    if (sz < 22) return;
    unsigned int attacker = ReadU32(p + 7);
    unsigned int target   = ReadU32(p + 11);
    unsigned char count   = p[21];
    Log("ATTACK_EVENT atk=%u tgt=%u count=%d sz=%u", attacker, target, (int)count, sz);
    if (count == 0) return;
    if (sz < (unsigned)(22 + count)) return;

    // Calcul dynamique de la taille d'un ATTACK_INFO
    unsigned int infoStride = (sz - 22) / count;
#ifdef DPS_DEBUG
    // Hex-dump du premier ATTACK_INFO pour les joueurs (max 5 fois, pour identifier le champ heal)
    static int s_atkDumpCount = 0;
    if (s_atkDumpCount < 5 && IsPlayerEntity(attacker) && infoStride >= 8) {
        s_atkDumpCount++;
        char hex[600] = {}; int hx = 0;
        unsigned int dumpSz = (infoStride < 120) ? infoStride : 120;
        for (unsigned int di = 0; di < dumpSz && hx < 590; ++di)
            hx += snprintf(hex+hx, 598-hx, "%02X ", p[22+di]);
        Log("RAWATK stride=%u atk=%u tgt=%u hex: %s", infoStride, attacker, target, hex);
    }
#endif

    // Detecter le joueur local depuis le premier paquet d'attaque recu
    // (necessaire sur V7 et tout client sans static RVAs valides).
    // 0x8... = joueur, 0xC... = pet.
    if (g_localHandle == 0 &&
        attacker != 0 && (attacker & 0xC0000000) == 0x80000000)
    {
        g_localHandle = attacker;
        Log("ParseAttack V7: g_localHandle <- 0x%08X", attacker);
        if (TryQueueNameScan(attacker))
            CloseHandle(CreateThread(nullptr, 0, ScanNameByHandleThread,
                                     (LPVOID)(uintptr_t)attacker, 0, nullptr));
    }

    const unsigned char* info = p + 22;
    int totalDmg = 0;
    for (unsigned int i = 0; i < count; ++i, info += infoStride)
    {
        if (info + infoStride > p + sz) break;
        int dmg = ReadI32(info);
        unsigned char flag = (infoStride > 8) ? info[8] : info[4];
        if (dmg <= 0 || (flag & ATK_FLAG_MISS)) continue;
        totalDmg += dmg;
        RecordDamageOut(attacker, dmg);
        RecordDamageIn(target, dmg);
    }
#ifdef DPS_DEBUG
    if (totalDmg > 0)
        Log("  -> recorded dmg=%d atk_isPlayer=%d", totalDmg, (int)IsPlayerEntity(attacker));
#endif
}

static void ParseSkill(const unsigned char* p, unsigned int sz)
{
    // Layout TS_SC_SKILL (packet 1) :
    //   Standard (V7, ancien, RappelzClassic) :
    //     TS_MSG(7) + skill_id(4) + skill_level(1) + caster(4) + target(4) + xyz(12)
    //     + layer(1) + type(1) + hp_cost(4) + mp_cost(4) + caster_hp(4) + caster_mp(4)
    //     = 50 octets (static) + FireType (9) = 59 minimum
    //     srCount a p+57, SR data a p+59, caster a p+12, type a p+33
    //   12.6 MB+ (g_clientShiftedSkill) :
    //     skill_id 4→3 bytes, skill_level supprime → shift -2 bytes
    //     srCount a p+55, SR data a p+57, caster a p+10, type a p+31
    const unsigned int hdrSz    = g_clientShiftedSkill ? 57u : 59u;
    const unsigned int cntOff   = g_clientShiftedSkill ? 55u : 57u;

    if (sz < hdrSz) return;
    unsigned int  caster = ReadU32(p + (g_clientShiftedSkill ? 10 : 12));
    unsigned char type   = p[g_clientShiftedSkill ? 31 : 33];

    // Diagnostic: dump des offsets cles pour identifier le bon layout
    {
        unsigned int c10 = ReadU32(p+10), c11=ReadU32(p+11), c12=ReadU32(p+12);
        unsigned short cnt55=ReadU16(p+55), cnt56=ReadU16(p+56), cnt57=ReadU16(p+57);
        Log("SKILL_DIAG: sz=%u shifted=%d c10=0x%08X c11=0x%08X c12=0x%08X cnt55=%u cnt56=%u cnt57=%u",
            sz, (int)g_clientShiftedSkill, c10, c11, c12, (unsigned)cnt55, (unsigned)cnt56, (unsigned)cnt57);
        Log("SKILL_DIAG: type33=%d type32=%d type31=%d hdrSz=%u cntOff=%u",
            (int)p[33], (int)p[32], (int)p[31], hdrSz, cntOff);
    }

    static const unsigned char FIRE           = 0;
    static const unsigned char CASTING        = 1;
    static const unsigned char CASTING_UPDATE = 2;
    static const unsigned char CANCEL         = 3;
    static const unsigned char REGION_FIRE    = 4;
    static const unsigned char COMPLETE       = 5;
    // Detecter le joueur local depuis le premier paquet de skill recu
    // (necessaire sur V7 et tout client sans static RVAs valides).
    if (g_localHandle == 0 &&
        caster != 0 && (caster & 0xC0000000) == 0x80000000)
    {
        g_localHandle = caster;
        Log("ParseSkill V7: g_localHandle <- 0x%08X", caster);
        if (TryQueueNameScan(caster))
            CloseHandle(CreateThread(nullptr, 0, ScanNameByHandleThread,
                                     (LPVOID)(uintptr_t)caster, 0, nullptr));
    }

    if (type != FIRE && type != REGION_FIRE) {
        Log("SKILL: type=%d ignored (not FIRE/REGION_FIRE) caster=%u sz=%u", (int)type, caster, sz);
        return;
    }

    unsigned short srCount = ReadU16(p + cntOff);
    if (srCount == 0 || srCount > 256) {
        Log("SKILL: srCount=%u out of range (cntOff=%u) — returning", (unsigned)srCount, cntOff);
        return;
    }
    Log("SKILL: caster=%u type=%d srCount=%d isPlayer=%d hdrSz=%u remaining=%u",
        caster, (int)type, (int)srCount, (int)IsPlayerEntity(caster), hdrSz, sz - hdrSz);

    const unsigned char* sr = p + hdrSz;
    unsigned int remaining  = sz - hdrSz;

    bool casterKnown = IsPlayerEntity(caster);

    for (int i = 0; i < srCount; ++i)
    {
        if (remaining < 1) break;
        unsigned char srType = sr[0];
        int srSz = SkillResultSize(srType);
        if (srSz == 0) {
            Log("SKILL: unknown srType=%d at i=%d srCount=%d remaining=%u, stopping", (int)srType, i, (int)srCount, remaining);
#ifdef DPS_DEBUG
            char hexU[300]={}; int hxU=0;
            unsigned int dumpU = remaining < 64 ? remaining : 64;
            for(unsigned int _d=0;_d<dumpU&&hxU<296;++_d)
                hxU+=snprintf(hexU+hxU,296-hxU,"%02X ",sr[_d]);
            Log("SKILL: unknown SR hex: %s", hexU);
#endif
            break;
        }
#ifdef DPS_DEBUG
        // Dump SR_RESULT pour reverse-engineer le layout reel
        if (srType == SR_RESULT) {
            char hexR[300]={}; int hxR=0;
            unsigned int dumpR = remaining < 64 ? remaining : 64;
            for(unsigned int _d=0;_d<dumpR&&hxR<296;++_d)
                hxR+=snprintf(hexR+hxR,296-hxR,"%02X ",sr[_d]);
            Log("SKILL SR_RESULT: caster=%u srSz=%d remaining=%u hex: %s", caster, srSz, remaining, hexR);
        }
#endif
        if ((unsigned)srSz > remaining) break;

        if ((srType == SR_DAMAGE || srType == SR_MAGIC_DAMAGE ||
             srType == SR_DAMAGE_KB) && srSz >= 14)
        {
            unsigned int tgt = ReadU32(sr + 1);
            int dmg  = ReadI32(sr + 10);
            int flag = ReadI32(sr + 14);
            if (dmg > 0 && !(flag & 0x02)) {
                RecordDamageOut(caster, dmg);
                RecordDamageIn(tgt, dmg);
            }
        }
        else if ((srType == SR_CHAIN_DAMAGE || srType == SR_CHAIN_MAGIC) && srSz >= 14)
        {
            unsigned int tgt = ReadU32(sr + 1);
            int dmg  = ReadI32(sr + 10);
            int flag = ReadI32(sr + 14);
            if (dmg > 0 && !(flag & 0x02)) {
                RecordDamageOut(caster, dmg);
                RecordDamageIn(tgt, dmg);
            }
        }
        else if ((srType == SR_ADD_HP || srType == SR_ADD_MP ||
                  srType == SR_ADD_HP_MP_SP) && srSz >= 13)
        {
            // Structure SR_ADD_HP (13 bytes) :
            // [0]=type [1..4]=hTarget [5..8]=target_hp [9..12]=nIncHP
            // nIncHP est le montant effectivement soigne (capped a HP max)
            int heal = ReadI32(sr + 9);
            if (heal > 0) {
                RecordHeal(caster, heal);
                unsigned int srTarget = ReadU32(sr + 1);
                if (srTarget != caster && IsPlayerEntity(srTarget))
                    Log("SKILL SR_ADD_HP: caster=%u srTarget=%u heal=%d", caster, srTarget, heal);
            }
        }
        else if (srType == SR_CHAIN_HEAL && srSz >= 13)
        {
            // [0]=type [1..4]=hTarget [5..8]=target_hp [9..12]=nIncHP [13..16]=hFrom
            int heal = ReadI32(sr + 9);
            if (heal > 0) RecordHeal(caster, heal);
        }

        sr        += srSz;
        remaining -= srSz;
    }
}

// Packet DoT : TS_SC_STATE_RESULT (opcode 406)
// Layout (offsets depuis debut packet) :
//   [0..3]  size (uint32)
//   [4..5]  opcode = 406 (uint16)
//   [6]     checksum (uint8)
//   [7..10] caster_handle (uint32)
//   [11..14] target_handle (uint32)
//   [15..18] code (int)
//   [19..20] level (uint16)
//   [21..22] result_type (uint16) : 1=DMG_HP 2=DMG_MP 3=DMG_SP 4=HEAL_HP 5=HEAL_MP 6=HEAL_SP
//   [23..26] value (int)          = montant dégâts/soin
//   [27..30] target_value (int)
//   [31]    final (bool)
//   [32..35] total_amount (int)
static void ParseStateResult(const unsigned char* p, unsigned int sz)
{
    if (sz < 36) return;
#ifdef DPS_DEBUG
    {
        unsigned short opc = ReadU16(p + 4);
        static int s_dumpSR406 = 0;
        if ((opc == 406 || opc == 1406) && s_dumpSR406 < 10) {
            s_dumpSR406++;
            char hexSR[300]={}; int hxSR=0;
            unsigned int dumpSR = sz < 64 ? sz : 64;
            for(unsigned int _d=0;_d<dumpSR&&hxSR<296;++_d)
                hxSR+=snprintf(hexSR+hxSR,296-hxSR,"%02X ",p[_d]);
            Log("STATERESULT_RAW: opc=%u sz=%u hex: %s", (unsigned)opc, sz, hexSR);
        }
    }
#endif
    unsigned int   caster = ReadU32(p + 7);
    unsigned int   target = ReadU32(p + 11);
    unsigned short rtype  = ReadU16(p + 21);
    int            value  = ReadI32(p + 23);
    if (value <= 0) return;
    Log("DOT: caster=%u tgt=%u rtype=%u val=%d isPlayerCaster=%d isPlayerTarget=%d",
        caster, target, (unsigned)rtype, value,
        (int)IsPlayerEntity(caster), (int)IsPlayerEntity(target));
    if (rtype == 1) // STATE_DAMAGE_HP : degats sur HP
    {
        RecordDamageOut(caster, value);
        RecordDamageIn(target, value);
    }
    else if (rtype == 4) // STATE_HEAL_HP : soin HP
    {
        // Pour les HoT (caster=lanceur du sort, target=soigne)
        // Pour le vol de vie passif (life steal), caster peut etre le mob attaque ou 0.
        // On utilise le caster si c'est un joueur, sinon le target.
        unsigned int healer = IsPlayerEntity(caster) ? caster : target;
        if (IsPlayerEntity(healer))
            RecordHeal(healer, value);
    }
}

// Opcode 1000 = TS_SC_RESULT V7 (stat summary, ~110 bytes) - pas un packet de degats
static void ParseOpcode1000(const unsigned char* p, unsigned int sz)
{
#ifdef DPS_DEBUG
    static int s_dump1000 = 0;
    if (s_dump1000 < 8) {
        s_dump1000++;
        char hex[768] = {}; int hx = 0;
        unsigned int dumpSz = sz < 256 ? sz : 256;
        for (unsigned int _i = 0; _i < dumpSz && hx < 750; ++_i)
            hx += snprintf(hex+hx, 760-hx, "%02X ", p[_i]);
        unsigned int caster = (sz>=11) ? ReadU32(p+7) : 0;
        unsigned int target = (sz>=15) ? ReadU32(p+11) : 0;
        Log("OPC1000[%d] sz=%u caster=%u tgt=%u isPlayer=%d hex: %s",
            s_dump1000, sz, caster, target, (int)IsPlayerEntity(caster), hex);
    }
#endif
    // OPC1000 = stat update periodique envoye uniquement pour le joueur local
    // -> on recupere le handle local si pas encore connu (missed le TM_SC_ENTER)
    if (sz >= 11) {
        unsigned int h = ReadU32(p + 7);
        if (IsPlayerEntity(h) && g_localHandle == 0) {
            g_localHandle = h;
            Log("OPC1000: g_localHandle <- %u (0x%08X)", h, h);
            if (!g_localNameFromPacket)
            {
                if (TryQueueNameScan(h))
                    CloseHandle(CreateThread(nullptr, 0, ScanNameByHandleThread, (LPVOID)(uintptr_t)h, 0, nullptr));
            }
        }
    }
}

static void DispatchPacket(const unsigned char* p, unsigned int sz)
{
    if (sz < 7) return;
    unsigned short id = ReadU16(p + 4);
    switch (id)
    {
    case TM_SC_ENTER:
    case 1003: // TM_SC_ENTER V7
        ParseEnter(p, sz);
        break;
    case TM_SC_LEAVE:
    case 1009: // TM_SC_LEAVE V7
        // Supprimer l'entite qui quitte la zone (evite d'accumuler des entrees mortes)
        if (sz >= 11) {
            unsigned int h = ReadU32(p + 7);
            EntCS_Enter();
            EntityInfo* e = FindEntity(h);
            if (e) e->active = false;
            EntCS_Leave();
            // Si le joueur local quitte (changement de personnage / deconnexion),
            // on remet g_localHandle a 0 pour que le prochain ENTER le detecte a nouveau.
            if (h == g_localHandle) {
                Log("LocalPlayer LEAVE h=%u -> reset localHandle", h);
                g_localHandle        = 0;
                g_localNameCache[0]  = '\0';
                g_localNameFromPacket = false;
            }
        }
        break;
    case TM_SC_ATTACK_EVENT:
    case 1101: // TM_SC_ATTACK_EVENT V7
        InterlockedIncrement(&g_debugPkt101);
        ParseAttackEvent(p, sz);
        break;
    case TM_SC_STATE_RESULT:
    case 1406: // TM_SC_STATE_RESULT V7
        ParseStateResult(p, sz);
        break;
    case 1000: // TM_SC_RESULT — magic result joueur (layout a determiner)
        ParseOpcode1000(p, sz);
        break;
    case TM_SC_SKILL:
    case 1401: // TM_SC_SKILL V7
        InterlockedIncrement(&g_debugPkt401);
#ifdef DPS_DEBUG
        if (sz >= 32) {
            char hex[512] = {}; int hx = 0;
            int dump = (sz < 128) ? sz : 128;
            for (int _i = 0; _i < dump && hx < 500; ++_i)
                hx += snprintf(hex+hx, 510-hx, "%02X ", p[_i]);
            {
                unsigned int _cntOff = g_clientShiftedSkill ? 55u : 57u;
                unsigned int _minSz  = g_clientShiftedSkill ? 57u : 59u;
                Log("RAWSKILL type=%d sz=%u srCount=%u hex: %s",
                    (int)(g_clientShiftedSkill ? p[31] : p[33]), sz, (sz>=_minSz?ReadU16(p+_cntOff):0), hex);
            }
        }
#endif
        ParseSkill(p, sz);
        break;
    default:
        // Log jusqu'a 3 fois par opcode inconnu, dump 64 bytes depuis le debut
        {
            struct OpcSeen { unsigned short opc; int count; };
            static OpcSeen s_seenOpc[128] = {}; static int s_seenN = 0;
            int idx = -1;
            for (int _k = 0; _k < s_seenN; ++_k) if (s_seenOpc[_k].opc == id) { idx=_k; break; }
            if (idx < 0 && s_seenN < 128) { idx = s_seenN++; s_seenOpc[idx].opc = id; }
            bool doLog = (idx >= 0 && s_seenOpc[idx].count < 3);
            // Toujours logguer si le packet contient un handle joueur (bit31=1)
            if (sz >= 11) {
                unsigned int h7  = ReadU32(p + 7);
                unsigned int h10 = (sz>=14) ? ReadU32(p + 10) : 0;
                if ((h7 & 0x80000000) || (h10 & 0x80000000)) doLog = true;
            }
            if (doLog) {
                if (idx >= 0) s_seenOpc[idx].count++;
                char hex2[500]={}; int hx2=0;
                unsigned int dumpN = sz < 64 ? sz : 64;
                for(unsigned int _j=0;_j<dumpN&&hx2<496;++_j) hx2+=snprintf(hex2+hx2,496-hx2,"%02X ",p[_j]);
                Log("UnknownOpcode id=%u sz=%u hex: %s", (unsigned)id, sz, hex2);
            }
        }
        break;
    }
}

// ============================================================
// Traitement du stream accumule
// ============================================================
static void ProcessStreamBuffer()
{
    int safety = 0;
    while (g_streamUsed >= 7 && safety++ < 4096)
    {
        if (!ValidateHeader(g_streamBuf, g_streamUsed))
        {
            bool found = false;
            for (int skip = 1; skip <= g_streamUsed - 7; ++skip)
            {
                if (ValidateHeader(g_streamBuf + skip, g_streamUsed - skip))
                {
                    unsigned short chk = ReadU16(g_streamBuf + skip + 4);
                    if (chk == 0 || chk > 2048) continue;
                    memmove(g_streamBuf, g_streamBuf + skip, g_streamUsed - skip);
                    g_streamUsed -= skip;
                    found = true;
                    break;
                }
            }
            if (!found)
            {
                if (g_streamUsed > 6)
                {
                    memmove(g_streamBuf, g_streamBuf + g_streamUsed - 6, 6);
                    g_streamUsed = 6;
                }
                return;
            }
        }

        unsigned int pktSize = ReadU32(g_streamBuf);
        if ((int)pktSize > g_streamUsed) return;

        unsigned short id = ReadU16(g_streamBuf + 4);
        if (id == 0 || id > 2048)
        {
            memmove(g_streamBuf, g_streamBuf + 1, --g_streamUsed);
            continue;
        }

        DispatchPacket(g_streamBuf, pktSize);

        int rem = g_streamUsed - (int)pktSize;
        if (rem > 0) memmove(g_streamBuf, g_streamBuf + pktSize, rem);
        g_streamUsed = rem;
    }
}

// ============================================================
// ProcessDecryptedBuffer  (appelee depuis le stub JMP)
// buf  = ptr buffer de reception deja dechiffre
// size = nombre de bytes recus ce tour
// ============================================================
extern "C" void __cdecl ProcessDecryptedBuffer(const unsigned char* buf, int size)
{
    if (!buf || size <= 0 || size > 65536) return;

    InterlockedIncrement(&g_debugBufCalls);

    // Log les premiers appels + periodiquement pour debug
    {
        LONG n = g_debugBufCalls;
        if (n <= 5 || (n % 200) == 0)
        {
            char hex[49] = {};
            for (int i = 0; i < 16 && i < size; ++i)
                _snprintf_s(hex + i * 3, (int)sizeof(hex) - i * 3, _TRUNCATE, "%02x ", buf[i]);
            Log("ProcessBuf #%ld size=%d hex=[%s]", n, size, hex);
        }
    }

    EnterCriticalSection(&g_streamCS);
    int avail = STREAM_BUF_SIZE - g_streamUsed;
    int copy  = (size < avail) ? size : avail;
    if (copy > 0)
    {
        memcpy(g_streamBuf + g_streamUsed, buf, copy);
        g_streamUsed += copy;
    }
    ProcessStreamBuffer();
    LeaveCriticalSection(&g_streamCS);
}

// ============================================================
// Pattern scanner (memoire executee de SFrame.exe)
// ============================================================
static void* ScanPattern(const unsigned char* pat, int patLen)
{
    HMODULE hMod = GetModuleHandleA("SFrame.exe");
    if (!hMod) return nullptr;

    MODULEINFO mi = {};
    GetModuleInformation(GetCurrentProcess(), hMod, &mi, sizeof(mi));

    BYTE* p   = (BYTE*)mi.lpBaseOfDll;
    BYTE* end = p + mi.SizeOfImage;

    MEMORY_BASIC_INFORMATION mbi;
    while (p < end)
    {
        if (!VirtualQuery(p, &mbi, sizeof(mbi)) || mbi.RegionSize == 0) break;

        if (mbi.State    == MEM_COMMIT &&
            !(mbi.Protect & PAGE_GUARD) &&
            !(mbi.Protect & PAGE_NOACCESS) &&
            (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                            PAGE_EXECUTE_WRITECOPY | PAGE_READONLY | PAGE_READWRITE)))
        {
            BYTE*  base = (BYTE*)mbi.BaseAddress;
            SIZE_T sz   = mbi.RegionSize;
            if (base + sz > end) sz = (SIZE_T)(end - base);

            __try
            {
                for (SIZE_T i = 0; i + (SIZE_T)patLen <= sz; ++i)
                    if (memcmp(base + i, pat, patLen) == 0)
                        return base + i;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }

        BYTE* next = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if (next <= p) break;
        p = next;
    }
    return nullptr;
}

// ============================================================
// JMP Hook post-cipher
// ============================================================
static const unsigned char NET_HOOK_PATTERN[] = {
    0x8D, 0x8D, 0xF0, 0xCF, 0xFF, 0xFF,  // lea ecx,[ebp-0x3010]
    0x51,                                  // push ecx           <- remplace ici
    0x8B, 0xCE,                            // mov ecx,esi
    0xFF, 0xD2                             // call edx
};
static const int NET_HOOK_OFFSET = 6; // on JMP au 7e byte (51 8B CE FF D2)

// V7 (Sframe.exe ~8.9 MB) : hook au moment de la lecture du packet ID
//   edi = TS_MESSAGE* (packet complet, valide)
//   [edi+0] = uint32 size, [edi+4] = uint16 id
//
// Pattern : cmp [edi],eax; ja erreur; movzx ecx,[edi+4]
// Hook site = offset 8 (sur movzx ecx,[edi+4])
// Bytes voles (6) : 0F B7 4F 04  (movzx ecx,[edi+4])
//                   8B C1         (mov eax,ecx)
// Orphan byte a hookSite+5 : 0xC1 (partie de mov eax,ecx, jamais atteint)
// JMP retour -> hookSite+6
static const unsigned char NET_HOOK_PATTERN_V7[] = {
    0x39, 0x07,                           // cmp [edi],eax
    0x0F, 0x87, 0xC4, 0x08, 0x00, 0x00,  // ja +0x8C4 (vers handler erreur)
    0x0F, 0xB7, 0x4F, 0x04               // movzx ecx,word ptr [edi+04]  <- hook ici
};
static const int NET_HOOK_OFFSET_V7 = 8; // offset du pattern vers le hook site

// Client 6.3 observe (SFrame.exe ~12.6 MB) :
//   cmp [ebp],eax ; ja erreur ; movzx ecx,[ebp+4]
// Hook site = offset 9 (sur movzx ecx,[ebp+4])
static const unsigned char NET_HOOK_PATTERN_63[] = {
    0x39, 0x45, 0x00,                     // cmp [ebp+00],eax
    0x0F, 0x87, 0xE4, 0x11, 0x00, 0x00,  // ja +0x11E4
    0x0F, 0xB7, 0x4D, 0x04               // movzx ecx,word ptr [ebp+04]  <- hook ici
};
static const int NET_HOOK_OFFSET_63 = 9;

// RappelzClassic / client 10.1 MB (Rappelz Classic) :
//   cmp esi,eax ; ja erreur ; movzx ecx,[edi+4]
// Dispatch via jump table 2 niveaux (0-0xFA et 0xFF-0x1F4).
// Hook site = offset 0 (sur movzx ecx,[edi+4])
// Bytes voles (4) : 0F B7 4F 04  (movzx ecx,[edi+4])
// JMP retour -> hookSite+4
// Pattern 12 octets sans offsets relatifs - stable entre builds.
static const unsigned char NET_HOOK_PATTERN_RC[] = {
    0x0F, 0xB7, 0x4F, 0x04,              // movzx ecx,word ptr [edi+04]  <- hook ici
    0x8B, 0xC1,                           // mov eax,ecx
    0x81, 0xF9, 0xFE, 0x00, 0x00, 0x00  // cmp ecx,000000FE
};
static const int NET_HOOK_OFFSET_RC = 0; // hook sur le 1er byte du pattern

enum NetHookKind {
    NET_HOOK_NONE = 0,
    NET_HOOK_OLD  = 1,
    NET_HOOK_V7   = 2,
    NET_HOOK_63   = 3,
    NET_HOOK_RC   = 4
};

struct JmpHook { void* pSite; void* pStub; bool installed; int kind; };
static JmpHook g_netHook = {};

// Callback V7 : appele depuis le stub avec edi = TS_MESSAGE*.
// Le packet est complet et valide (taille verifiee par le client).
extern "C" void __cdecl V7PacketCallback(const unsigned char* pkt)
{
    if (!pkt) return;
    unsigned int sz = ReadU32(pkt);
    if (sz < 7 || sz > 65536) return;
    InterlockedIncrement(&g_debugBufCalls);
    EnterCriticalSection(&g_streamCS);
    DispatchPacket(pkt, sz);
    LeaveCriticalSection(&g_streamCS);
}

static bool InstallNetworkHook()
{
    // --- Tentative 1 : RappelzClassic (~10.1 MB) — pattern le plus specifique ---
    void* patAddr = ScanPattern(NET_HOOK_PATTERN_RC, sizeof(NET_HOOK_PATTERN_RC));
    if (patAddr)
    {
        BYTE* hookSite = (BYTE*)patAddr + NET_HOOK_OFFSET_RC;
        Log("Pattern RC @ %p, hookSite @ %p", patAddr, hookSite);

        BYTE* stub = (BYTE*)VirtualAlloc(nullptr, 128,
                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!stub) { Log("VirtualAlloc stub RC FAIL err=%lu", GetLastError()); return false; }

        // --------------------------------------------------------
        // Stub RC (RappelzClassic 10.1 MB)
        // Entree via JMP : edi = TS_MESSAGE* (packet complet, valide)
        // Meme principe que V7 : on appelle V7PacketCallback(edi)
        // Bytes voles (6) : 0F B7 4F 04 (movzx ecx,[edi+4]) + 8B C1 (mov eax,ecx)
        // JMP retour -> hookSite+6 (saute l'orphan byte 0xC1 a hookSite+5)
        // --------------------------------------------------------
        BYTE* s = stub;

        *s++ = 0x50; // push eax
        *s++ = 0x51; // push ecx
        *s++ = 0x52; // push edx
        *s++ = 0x56; // push esi

        *s++ = 0x57; // push edi   <- arg : TS_MESSAGE*
        {
            DWORD ct = (DWORD)(uintptr_t)V7PacketCallback;
            DWORD cf = (DWORD)(uintptr_t)(s + 5);
            *s++ = 0xE8;
            *(DWORD*)s = ct - cf;
            s += 4;
        }
        *s++ = 0x83; *s++ = 0xC4; *s++ = 0x04; // add esp,4

        *s++ = 0x5E; // pop esi
        *s++ = 0x5A; // pop edx
        *s++ = 0x59; // pop ecx
        *s++ = 0x58; // pop eax

        // Bytes voles (instructions completes) :
        *s++ = 0x0F; *s++ = 0xB7; *s++ = 0x4F; *s++ = 0x04; // movzx ecx,[edi+4]
        *s++ = 0x8B; *s++ = 0xC1;                             // mov eax,ecx

        // JMP vers hookSite+6 (saute l'orphan byte a hookSite+5)
        BYTE* jmpBack = hookSite + 6;
        DWORD jmpRel  = (DWORD)(uintptr_t)jmpBack - (DWORD)(uintptr_t)(s + 5);
        *s++ = 0xE9;
        *(DWORD*)s = jmpRel;
        s += 4;

        Log("Stub RC %d bytes @ %p", (int)(s - stub), stub);

        DWORD old = 0;
        if (!VirtualProtect(hookSite, 5, PAGE_EXECUTE_READWRITE, &old)) {
            Log("VirtualProtect RC FAIL err=%lu", GetLastError());
            VirtualFree(stub, 0, MEM_RELEASE);
            return false;
        }
        DWORD rel = (DWORD)(uintptr_t)stub - (DWORD)(uintptr_t)(hookSite + 5);
        hookSite[0] = 0xE9;
        *(DWORD*)(hookSite + 1) = rel;
        FlushInstructionCache(GetCurrentProcess(), hookSite, 5);
        VirtualProtect(hookSite, 5, old, &old);

        g_netHook.pSite     = hookSite;
        g_netHook.pStub     = stub;
        g_netHook.installed = true;
        g_netHook.kind      = NET_HOOK_RC;
        Log("Hook reseau RC OK : site=%p stub=%p", hookSite, stub);
        return true;
    }

    // --- Tentative 2 : client V7 ---
    patAddr = ScanPattern(NET_HOOK_PATTERN_V7, sizeof(NET_HOOK_PATTERN_V7));
    if (patAddr)
    {
        BYTE* hookSite = (BYTE*)patAddr + NET_HOOK_OFFSET_V7;
        Log("Pattern V7 @ %p, hookSite @ %p", patAddr, hookSite);

        BYTE* stub = (BYTE*)VirtualAlloc(nullptr, 128,
                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!stub) { Log("VirtualAlloc stub V7 FAIL err=%lu", GetLastError()); return false; }

        // --------------------------------------------------------
        // Stub V7
        // Entree via JMP : edi = TS_MESSAGE* (packet complet, valide)
        // On appelle V7PacketCallback(edi) en cdecl puis on restaure eax,ecx,edx,esi.
        // edi doit rester intact (utilise apres le retour).
        // Bytes voles (6) : 0F B7 4F 04 (movzx ecx,[edi+4]) + 8B C1 (mov eax,ecx)
        // Orphan byte a hookSite+5 = 0xC1 (jamais execute)
        // JMP retour -> hookSite+6
        // --------------------------------------------------------
        BYTE* s = stub;

        *s++ = 0x50; // push eax
        *s++ = 0x51; // push ecx
        *s++ = 0x52; // push edx
        *s++ = 0x56; // push esi

        *s++ = 0x57; // push edi   <- arg : TS_MESSAGE*
        {
            DWORD ct = (DWORD)(uintptr_t)V7PacketCallback;
            DWORD cf = (DWORD)(uintptr_t)(s + 5);
            *s++ = 0xE8;
            *(DWORD*)s = ct - cf;
            s += 4;
        }
        *s++ = 0x83; *s++ = 0xC4; *s++ = 0x04; // add esp,4  (cleanup 1 arg)

        *s++ = 0x5E; // pop esi
        *s++ = 0x5A; // pop edx
        *s++ = 0x59; // pop ecx
        *s++ = 0x58; // pop eax

        // Bytes voles (instructions completes) :
        *s++ = 0x0F; *s++ = 0xB7; *s++ = 0x4F; *s++ = 0x04; // movzx ecx,[edi+4]
        *s++ = 0x8B; *s++ = 0xC1;                             // mov eax,ecx

        // JMP vers hookSite+6 (saute l'orphan byte 0xC1 a hookSite+5)
        BYTE* jmpBack = hookSite + 6;
        DWORD jmpRel  = (DWORD)(uintptr_t)jmpBack - (DWORD)(uintptr_t)(s + 5);
        *s++ = 0xE9;
        *(DWORD*)s = jmpRel;
        s += 4;

        Log("Stub V7 %d bytes @ %p", (int)(s - stub), stub);

        DWORD old = 0;
        if (!VirtualProtect(hookSite, 5, PAGE_EXECUTE_READWRITE, &old)) {
            Log("VirtualProtect V7 FAIL err=%lu", GetLastError());
            VirtualFree(stub, 0, MEM_RELEASE);
            return false;
        }
        DWORD rel = (DWORD)(uintptr_t)stub - (DWORD)(uintptr_t)(hookSite + 5);
        hookSite[0] = 0xE9;
        *(DWORD*)(hookSite + 1) = rel;
        FlushInstructionCache(GetCurrentProcess(), hookSite, 5);
        VirtualProtect(hookSite, 5, old, &old);

        g_netHook.pSite     = hookSite;
        g_netHook.pStub     = stub;
        g_netHook.installed = true;
        g_netHook.kind      = NET_HOOK_V7;
        Log("Hook reseau V7 OK : site=%p stub=%p", hookSite, stub);
        return true;
    }

    // --- Tentative 3 : client 6.3 ---
    patAddr = ScanPattern(NET_HOOK_PATTERN_63, sizeof(NET_HOOK_PATTERN_63));
    if (patAddr)
    {
        BYTE* hookSite = (BYTE*)patAddr + NET_HOOK_OFFSET_63;
        Log("Pattern 6.3 @ %p, hookSite @ %p", patAddr, hookSite);

        BYTE* stub = (BYTE*)VirtualAlloc(nullptr, 128,
                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!stub) { Log("VirtualAlloc stub 6.3 FAIL err=%lu", GetLastError()); return false; }

        // --------------------------------------------------------
        // Stub 6.3
        // Entree via JMP : ebp = TS_MESSAGE* (packet complet, valide)
        // Bytes voles (6) : 0F B7 4D 04 (movzx ecx,[ebp+4]) + 8B C1
        // --------------------------------------------------------
        BYTE* s = stub;

        *s++ = 0x50; // push eax
        *s++ = 0x51; // push ecx
        *s++ = 0x52; // push edx
        *s++ = 0x56; // push esi

        *s++ = 0x55; // push ebp   <- arg : TS_MESSAGE*
        {
            DWORD ct = (DWORD)(uintptr_t)V7PacketCallback;
            DWORD cf = (DWORD)(uintptr_t)(s + 5);
            *s++ = 0xE8;
            *(DWORD*)s = ct - cf;
            s += 4;
        }
        *s++ = 0x83; *s++ = 0xC4; *s++ = 0x04; // add esp,4

        *s++ = 0x5E; // pop esi
        *s++ = 0x5A; // pop edx
        *s++ = 0x59; // pop ecx
        *s++ = 0x58; // pop eax

        *s++ = 0x0F; *s++ = 0xB7; *s++ = 0x4D; *s++ = 0x04; // movzx ecx,[ebp+4]
        *s++ = 0x8B; *s++ = 0xC1;                             // mov eax,ecx

        BYTE* jmpBack = hookSite + 6;
        DWORD jmpRel  = (DWORD)(uintptr_t)jmpBack - (DWORD)(uintptr_t)(s + 5);
        *s++ = 0xE9;
        *(DWORD*)s = jmpRel;
        s += 4;

        Log("Stub 6.3 %d bytes @ %p", (int)(s - stub), stub);

        DWORD old = 0;
        if (!VirtualProtect(hookSite, 5, PAGE_EXECUTE_READWRITE, &old)) {
            Log("VirtualProtect 6.3 FAIL err=%lu", GetLastError());
            VirtualFree(stub, 0, MEM_RELEASE);
            return false;
        }
        DWORD rel = (DWORD)(uintptr_t)stub - (DWORD)(uintptr_t)(hookSite + 5);
        hookSite[0] = 0xE9;
        *(DWORD*)(hookSite + 1) = rel;
        FlushInstructionCache(GetCurrentProcess(), hookSite, 5);
        VirtualProtect(hookSite, 5, old, &old);

        g_netHook.pSite     = hookSite;
        g_netHook.pStub     = stub;
        g_netHook.installed = true;
        g_netHook.kind      = NET_HOOK_63;
        Log("Hook reseau 6.3 OK : site=%p stub=%p", hookSite, stub);
        return true;
    }

    // --- Tentative 4 : ancien client (SFrame.exe 17-elem, fallback) ---
    patAddr = ScanPattern(NET_HOOK_PATTERN, sizeof(NET_HOOK_PATTERN));
    if (patAddr)
    {
        BYTE* hookSite = (BYTE*)patAddr + NET_HOOK_OFFSET;
        Log("Pattern ancien client @ %p, hookSite @ %p", patAddr, hookSite);

        BYTE* stub = (BYTE*)VirtualAlloc(nullptr, 128,
                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!stub) { Log("VirtualAlloc stub FAIL err=%lu", GetLastError()); return false; }

        // --------------------------------------------------------
        // Stub ancien client
        // Entree via JMP : ecx=buf, [esp+0]=size, esi=disp, edx=OnRecv
        // --------------------------------------------------------
        BYTE* s = stub;

        *s++ = 0x50;  // push eax
        *s++ = 0x51;  // push ecx  (buf_ptr)
        *s++ = 0x52;  // push edx  (OnRecv fn)
        *s++ = 0x56;  // push esi  (dispatcher)
        // [esp]=esi [esp+4]=edx [esp+8]=buf [esp+12]=eax [esp+16]=size

        *s++ = 0xFF; *s++ = 0x74; *s++ = 0x24; *s++ = 0x10; // push size [esp+16]
        *s++ = 0xFF; *s++ = 0x74; *s++ = 0x24; *s++ = 0x0C; // push buf  [esp+12]

        DWORD callTarget = (DWORD)(uintptr_t)ProcessDecryptedBuffer;
        DWORD callFrom   = (DWORD)(uintptr_t)(s + 5);
        *s++ = 0xE8;
        *(DWORD*)s = callTarget - callFrom;
        s += 4;

        *s++ = 0x83; *s++ = 0xC4; *s++ = 0x08; // add esp,8
        *s++ = 0x5E; // pop esi
        *s++ = 0x5A; // pop edx
        *s++ = 0x59; // pop ecx
        *s++ = 0x58; // pop eax

        // Bytes voles : 51 8B CE FF D2
        *s++ = 0x51;               // push ecx
        *s++ = 0x8B; *s++ = 0xCE; // mov ecx, esi
        *s++ = 0xFF; *s++ = 0xD2; // call edx

        // JMP vers hookSite+5
        BYTE* jmpBack = hookSite + 5;
        DWORD jmpRel  = (DWORD)(uintptr_t)jmpBack - (DWORD)(uintptr_t)(s + 5);
        *s++ = 0xE9;
        *(DWORD*)s = jmpRel;
        s += 4;

        Log("Stub ancien %d bytes @ %p", (int)(s - stub), stub);

        DWORD old = 0;
        if (!VirtualProtect(hookSite, 5, PAGE_EXECUTE_READWRITE, &old)) {
            Log("VirtualProtect FAIL err=%lu", GetLastError());
            VirtualFree(stub, 0, MEM_RELEASE);
            return false;
        }
        DWORD rel = (DWORD)(uintptr_t)stub - (DWORD)(uintptr_t)(hookSite + 5);
        hookSite[0] = 0xE9;
        *(DWORD*)(hookSite + 1) = rel;
        FlushInstructionCache(GetCurrentProcess(), hookSite, 5);
        VirtualProtect(hookSite, 5, old, &old);

        g_netHook.pSite     = hookSite;
        g_netHook.pStub     = stub;
        g_netHook.installed = true;
        g_netHook.kind      = NET_HOOK_OLD;
        Log("Hook reseau (ancien) OK : site=%p stub=%p", hookSite, stub);
        return true;
    }

    Log("Aucun pattern de hook reseau trouve (OLD/V7/63/RC)");
    return false;
}

static void RemoveNetworkHook()
{
    if (!g_netHook.installed) return;
    BYTE kOrig[5];
    if (g_netHook.kind == NET_HOOK_V7 || g_netHook.kind == NET_HOOK_RC)
    {   // movzx ecx,[edi+4] (4 bytes) + premier byte de mov eax,ecx (1 byte)
        kOrig[0]=0x0F; kOrig[1]=0xB7; kOrig[2]=0x4F; kOrig[3]=0x04; kOrig[4]=0x8B;
    }
    else if (g_netHook.kind == NET_HOOK_63)
    {   // movzx ecx,[ebp+4] (4 bytes) + premier byte de mov eax,ecx (1 byte)
        kOrig[0]=0x0F; kOrig[1]=0xB7; kOrig[2]=0x4D; kOrig[3]=0x04; kOrig[4]=0x8B;
    }
    else
    {   // push ecx + mov ecx,esi + call edx (5 bytes)
        kOrig[0]=0x51; kOrig[1]=0x8B; kOrig[2]=0xCE; kOrig[3]=0xFF; kOrig[4]=0xD2;
    }
    BYTE* site = (BYTE*)g_netHook.pSite;
    DWORD old = 0;
    VirtualProtect(site, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(site, kOrig, 5);
    FlushInstructionCache(GetCurrentProcess(), site, 5);
    VirtualProtect(site, 5, old, &old);
    if (g_netHook.pStub) VirtualFree(g_netHook.pStub, 0, MEM_RELEASE);
    g_netHook = {};
    Log("Hook reseau retire");
}

// ============================================================
// D3D9 hook
// ============================================================
typedef HRESULT(WINAPI* fn_EndScene)(IDirect3DDevice9*);
typedef HRESULT(WINAPI* fn_Reset   )(IDirect3DDevice9*, D3DPRESENT_PARAMETERS*);

static const int VTIDX_RESET    = 16;
static const int VTIDX_ENDSCENE = 42;

struct DetourD3D {
    BYTE  stolen[32];
    int   stolenLen;
    void* pTrampoline;
    void* pOrigFunc;
    bool  installed;
};
static DetourD3D   g_detourES    = {};
static DetourD3D   g_detourReset = {};
static fn_EndScene g_trampolineES    = nullptr;
static fn_Reset    g_trampolineReset = nullptr;

static int X86InstrLen(const BYTE* p)
{
    if (p[0]==0x66||p[0]==0x67||p[0]==0xF2||p[0]==0xF3||
        p[0]==0x64||p[0]==0x65||p[0]==0x2E||p[0]==0x3E) return 1+X86InstrLen(p+1);
    if (p[0]==0x0F){
        if(p[1]>=0x80&&p[1]<=0x8F) return 6;
        auto mrm=[](const BYTE* q,int b)->int{BYTE m=q[1];int mo=(m>>6)&3,rm=m&7;
            if(mo==0&&rm==5)b+=4; else if(mo==1)b+=1; else if(mo==2)b+=4;
            if(rm==4&&mo!=3)b+=1; return b;};
        if(p[1]==0xAF||p[1]==0xB6||p[1]==0xB7||p[1]==0xBE||p[1]==0xBF) return mrm(p,2);
        return 2;
    }
    auto modrm=[](const BYTE* q,int b)->int{BYTE m=q[1];int mo=(m>>6)&3,rm=m&7;
        if(mo==0&&rm==5)b+=4; else if(mo==1)b+=1; else if(mo==2)b+=4;
        if(rm==4&&mo!=3)b+=1; return b;};
    switch(p[0]){
    case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57:
    case 0x58: case 0x59: case 0x5A: case 0x5B: case 0x5C: case 0x5D: case 0x5E: case 0x5F:
    case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45: case 0x46: case 0x47:
    case 0x48: case 0x49: case 0x4A: case 0x4B: case 0x4C: case 0x4D: case 0x4E: case 0x4F:
    case 0x90: case 0xC3: case 0xCC: case 0xC9: case 0x98: case 0x99: return 1;
    case 0x6A: case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75:
    case 0x76: case 0x77: case 0x78: case 0x79: case 0x7A: case 0x7B:
    case 0x7C: case 0x7D: case 0x7E: case 0x7F: case 0xEB:
    case 0xB0: case 0xB1: case 0xB2: case 0xB3: case 0xB4: case 0xB5: case 0xB6: case 0xB7:
        return 2;
    case 0x01: case 0x03: case 0x09: case 0x0B: case 0x11: case 0x13:
    case 0x19: case 0x1B: case 0x21: case 0x23: case 0x29: case 0x2B:
    case 0x31: case 0x33: case 0x39: case 0x3B:
    case 0x85: case 0x87: case 0x88: case 0x89: case 0x8A: case 0x8B: case 0x8D:
        return modrm(p,2);
    case 0x6B: return modrm(p,2)+1;
    case 0x69: return modrm(p,2)+4;
    case 0x83: case 0xC1: return modrm(p,2)+1;
    case 0x81: return modrm(p,2)+4;
    case 0xC7: return modrm(p,2)+4;
    case 0xFF: case 0xFE: return modrm(p,2);
    case 0x68: case 0xA1: case 0xA3:
    case 0xB8: case 0xB9: case 0xBA: case 0xBB: case 0xBC: case 0xBD: case 0xBE: case 0xBF:
    case 0xE8: case 0xE9: return 5;
    case 0xC6: return modrm(p,2)+1;
    case 0xC2: return 3;
    default: return 0;
    }
}

static bool DetourD3DInstall(DetourD3D& d, void* pTarget, void* pHook)
{
    if (d.installed) return true;
    d.pOrigFunc = pTarget;
    const BYTE* pc = (const BYTE*)pTarget;
    int stolen = 0;
    while (stolen < 5) {
        int l = X86InstrLen(pc + stolen);
        if (l == 0 || stolen + l > 28) return false;
        stolen += l;
    }
    d.stolenLen = stolen;
    DWORD old = 0;
    if (!VirtualProtect(pTarget, stolen, PAGE_EXECUTE_READWRITE, &old)) return false;
    memcpy(d.stolen, pTarget, stolen);
    d.pTrampoline = VirtualAlloc(nullptr, stolen + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!d.pTrampoline) { VirtualProtect(pTarget, stolen, old, &old); return false; }
    BYTE* pT = (BYTE*)d.pTrampoline;
    memcpy(pT, d.stolen, stolen);
    for (int off = 0; off < stolen;) {
        int l = X86InstrLen(pT + off); if (l == 0) break;
        if ((pT[off] == 0xE8 || pT[off] == 0xE9) && l == 5) {
            INT32 rel; memcpy(&rel, pT + off + 1, 4);
            BYTE* origTgt = (BYTE*)pTarget + off + 5 + rel;
            INT32 nr = (INT32)(origTgt - (pT + off + 5));
            memcpy(pT + off + 1, &nr, 4);
        }
        off += l;
    }
    BYTE* jb = pT + stolen;
    INT32 rb  = (INT32)((BYTE*)pTarget + stolen - (jb + 5));
    jb[0] = 0xE9; memcpy(jb + 1, &rb, 4);
    BYTE*  dst = (BYTE*)pTarget;
    INT32  rh  = (INT32)((BYTE*)pHook - (dst + 5));
    dst[0] = 0xE9; memcpy(dst + 1, &rh, 4);
    for (int i = 5; i < stolen; ++i) dst[i] = 0x90;
    FlushInstructionCache(GetCurrentProcess(), pTarget, stolen);
    VirtualProtect(pTarget, stolen, old, &old);
    d.installed = true;
    return true;
}
static void DetourD3DRemove(DetourD3D& d)
{
    if (!d.installed || !d.pOrigFunc) return;
    DWORD old = 0;
    VirtualProtect(d.pOrigFunc, d.stolenLen, PAGE_EXECUTE_READWRITE, &old);
    memcpy(d.pOrigFunc, d.stolen, d.stolenLen);
    FlushInstructionCache(GetCurrentProcess(), d.pOrigFunc, d.stolenLen);
    VirtualProtect(d.pOrigFunc, d.stolenLen, old, &old);
    VirtualFree(d.pTrampoline, 0, MEM_RELEASE);
    d.pTrampoline = nullptr;
    d.installed   = false;
}

// ============================================================
// Viewport / Fenetre
// ============================================================
static int     g_vpW = 0, g_vpH = 0;
static HWND    g_hWnd     = nullptr;
static WNDPROC g_origProc = nullptr;

// ============================================================
// Panel UI
// ============================================================
#define PANEL_MIN_W   280
#define PANEL_MAX_W   600
#define PANEL_HEADER  66
#define ROW_H         20
#define MAX_ROWS      20  // cap absolu

static int  g_panelW = 360;  // charge depuis INI
static int  g_panelX = -1, g_panelY = -1;
static int  g_maxVisibleRows = 12;  // charge depuis INI, ajustable par resize bas
static bool g_panelVisible = true;
static bool g_dragging = false, g_dragMoved = false;
static int  g_dragOffX = 0, g_dragOffY = 0;
static bool g_closeHover = false, g_resetHover = false, g_settingsHover = false;
static bool g_settingsOpen = false;
static bool g_resizing = false, g_resizeMoved = false;
static int  g_resizeOffX = 0;
static bool g_resizingH = false;      // resize hauteur (nombre de lignes)
static int  g_resizeOffY = 0;
static bool g_resizingCorner = false; // resize coin -> largeur + hauteur
static int  g_cornerInitW = 0, g_cornerInitRows = 0;
static int  g_cornerInitX = 0, g_cornerInitY = 0;
static bool g_tab0Hover = false, g_tab1Hover = false, g_tab2Hover = false, g_tab3Hover = false;
static int  g_panelH = PANEL_HEADER + 14 + MAX_ROWS * ROW_H + 4;
static float g_panelScale = 1.0f;      // scale proportionnel largeur -> contenu
static float g_lastFontScale = 0.0f;   // pour recreation polices si changement
// g_scrollOffset declare en avant de fichier

// ============================================================
// Persistence position panneau (INI)
// ============================================================
static void GetIniPath(char* out, int sz)
{
    GetModuleFileNameA(g_hMod, out, sz);
    char* p = strrchr(out, '\\');
    if (p) { p[1] = '\0'; strcat_s(out, sz, "dpscounter.ini"); }
}
static void LoadPanelPos()
{
    char ini[MAX_PATH] = {};
    GetIniPath(ini, sizeof(ini));
    int x = (int)GetPrivateProfileIntA("Panel", "X", -1, ini);
    int y = (int)GetPrivateProfileIntA("Panel", "Y", -1, ini);
    int w = (int)GetPrivateProfileIntA("Panel", "W", 360, ini);
    int t = (int)GetPrivateProfileIntA("Panel", "Timeout", 20, ini);
    int r = (int)GetPrivateProfileIntA("Panel", "Rows", 12, ini);
    if (x >= 0) g_panelX = x;
    if (y >= 0) g_panelY = y;
    if (w >= PANEL_MIN_W && w <= PANEL_MAX_W) g_panelW = w;
    if (t >= 1 && t <= 120) g_fightTimeout = (DWORD)t * 1000;
    if (r >= 4 && r <= MAX_ROWS) g_maxVisibleRows = r;
    Log("LoadPanelPos: x=%d y=%d w=%d timeout=%ds rows=%d (ini=%s)", g_panelX, g_panelY, g_panelW, (int)(g_fightTimeout/1000), g_maxVisibleRows, ini);
}
static void SavePanelPos()
{
    char ini[MAX_PATH] = {}; char buf[16];
    GetIniPath(ini, sizeof(ini));
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%d", g_panelX);
    WritePrivateProfileStringA("Panel", "X", buf, ini);
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%d", g_panelY);
    WritePrivateProfileStringA("Panel", "Y", buf, ini);
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%d", g_panelW);
    WritePrivateProfileStringA("Panel", "W", buf, ini);
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%d", (int)(g_fightTimeout / 1000));
    WritePrivateProfileStringA("Panel", "Timeout", buf, ini);
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%d", g_maxVisibleRows);
    WritePrivateProfileStringA("Panel", "Rows", buf, ini);
}

static void EnsurePanelPos() {
    if (g_panelX < 0) g_panelX = 10;
    if (g_panelY < 0) g_panelY = 10;
    // Taille initiale responsive : ~25% de la largeur ecran (une seule fois)
    static bool s_firstSize = true;
    if (s_firstSize && g_vpW > 0) {
        s_firstSize = false;
        int autoW = g_vpW / 4;
        if (autoW < PANEL_MIN_W) autoW = PANEL_MIN_W;
        if (autoW > PANEL_MAX_W) autoW = PANEL_MAX_W;
        // Ne pas ecraser une valeur INI explicite (sauf si c'est le defaut 360)
        if (g_panelW == 360 && autoW != 360) g_panelW = autoW;
    }
}

// ============================================================
// D3D9 helpers
// ============================================================
static ID3DXFont* g_fontRow   = nullptr;
static ID3DXFont* g_fontSmall = nullptr;
static void ReleaseFonts() {
    if (g_fontRow)   { g_fontRow->Release();   g_fontRow   = nullptr; }
    if (g_fontSmall) { g_fontSmall->Release(); g_fontSmall = nullptr; }
}
static void EnsureFonts(IDirect3DDevice9* dev) {
    // Recreer les polices si l'echelle a change
    if (g_lastFontScale != g_panelScale) {
        ReleaseFonts();
        g_lastFontScale = g_panelScale;
    }
    if (!g_fontRow)
        D3DXCreateFontA(dev,(int)(14*g_panelScale+0.5f),0,FW_BOLD,1,FALSE,DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH|FF_DONTCARE,"Tahoma",&g_fontRow);
    if (!g_fontSmall)
        D3DXCreateFontA(dev,(int)(11*g_panelScale+0.5f),0,FW_NORMAL,1,FALSE,DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH|FF_DONTCARE,"Tahoma",&g_fontSmall);
}
static void FillRect2D(IDirect3DDevice9* dev, int x, int y, int w, int h, DWORD col) {
    struct V { float x,y,z,rhw; DWORD color; };
    V v[4] = {{(float)x,(float)(y+h),0.f,1.f,col},{(float)x,(float)y,0.f,1.f,col},
              {(float)(x+w),(float)(y+h),0.f,1.f,col},{(float)(x+w),(float)y,0.f,1.f,col}};
    dev->SetFVF(D3DFVF_XYZRHW|D3DFVF_DIFFUSE);
    dev->DrawPrimitiveUP(D3DPT_TRIANGLESTRIP,2,v,sizeof(V));
}
static void DrawText2(ID3DXFont* fnt, const char* txt, RECT r, DWORD fmt, DWORD col) {
    if (!fnt||!txt||!txt[0]) return;
    RECT rs={r.left+1,r.top+1,r.right+1,r.bottom+1};
    fnt->DrawTextA(nullptr,txt,-1,&rs,fmt,D3DCOLOR_ARGB(180,0,0,0));
    fnt->DrawTextA(nullptr,txt,-1,&r, fmt,col);
}

// ============================================================
// DrawDPSPanel
// ============================================================
// Palette : 8 couleurs cyclee par owner
static const DWORD kOwnerBg[8] = {
    D3DCOLOR_ARGB(195,18,28,52),  // bleu
    D3DCOLOR_ARGB(195,16,46,18),  // vert
    D3DCOLOR_ARGB(195,50,18,16),  // rouge
    D3DCOLOR_ARGB(195,38,18,54),  // violet
    D3DCOLOR_ARGB(195,50,38,10),  // or
    D3DCOLOR_ARGB(195,12,44,44),  // teal
    D3DCOLOR_ARGB(195,46,16,46),  // magenta
    D3DCOLOR_ARGB(195,40,40,12),  // jaune
};
static const DWORD kPetBg[8] = {
    D3DCOLOR_ARGB(155,14,22,42),
    D3DCOLOR_ARGB(155,12,36,14),
    D3DCOLOR_ARGB(155,40,14,12),
    D3DCOLOR_ARGB(155,30,14,44),
    D3DCOLOR_ARGB(155,40,30, 8),
    D3DCOLOR_ARGB(155, 8,34,34),
    D3DCOLOR_ARGB(155,36,12,36),
    D3DCOLOR_ARGB(155,32,32, 8),
};
static const DWORD kOwnerBar[8] = {
    D3DCOLOR_ARGB(110, 70,130,255),
    D3DCOLOR_ARGB(110, 70,210, 70),
    D3DCOLOR_ARGB(110,220, 65, 35),
    D3DCOLOR_ARGB(110,150, 70,255),
    D3DCOLOR_ARGB(110,255,175, 35),
    D3DCOLOR_ARGB(110, 35,195,195),
    D3DCOLOR_ARGB(110,215, 55,215),
    D3DCOLOR_ARGB(110,195,195, 35),
};

struct SortRow {
    unsigned int ownerHandle, selfHandle;
    char         name[24];
    LONGLONG     value;
    int          maxValue;  // max hit / max heal / max rcvd
    bool         isPet;
    int          colorIdx;
};

static void DrawDPSPanel(IDirect3DDevice9* dev)
{
    if (!g_panelVisible || g_vpW < 200 || g_vpH < 200) return;

    IDirect3DStateBlock9* pSB = nullptr;
    if (FAILED(dev->CreateStateBlock(D3DSBT_ALL, &pSB))) return;

    dev->SetVertexShader(nullptr); dev->SetPixelShader(nullptr);
    dev->SetVertexDeclaration(nullptr);
    for (int i = 0; i < 8; ++i) dev->SetTexture(i, nullptr);
    dev->SetRenderState(D3DRS_ALPHABLENDENABLE,  TRUE);
    dev->SetRenderState(D3DRS_SRCBLEND,          D3DBLEND_SRCALPHA);
    dev->SetRenderState(D3DRS_DESTBLEND,         D3DBLEND_INVSRCALPHA);
    dev->SetRenderState(D3DRS_ZENABLE,           FALSE);
    dev->SetRenderState(D3DRS_ZWRITEENABLE,      FALSE);
    dev->SetRenderState(D3DRS_LIGHTING,          FALSE);
    dev->SetRenderState(D3DRS_CULLMODE,          D3DCULL_NONE);
    dev->SetRenderState(D3DRS_SCISSORTESTENABLE, FALSE);
    dev->SetRenderState(D3DRS_ALPHATESTENABLE,   FALSE);
    dev->SetRenderState(D3DRS_COLORWRITEENABLE,  0xF);
    dev->SetRenderState(D3DRS_STENCILENABLE,     FALSE);
    dev->SetRenderState(D3DRS_FILLMODE,          D3DFILL_SOLID);
    dev->SetRenderState(D3DRS_FOGENABLE,         FALSE);
    dev->SetTextureStageState(0,D3DTSS_COLOROP,  D3DTOP_SELECTARG1);
    dev->SetTextureStageState(0,D3DTSS_COLORARG1,D3DTA_DIFFUSE);
    dev->SetTextureStageState(0,D3DTSS_ALPHAOP,  D3DTOP_SELECTARG1);
    dev->SetTextureStageState(0,D3DTSS_ALPHAARG1,D3DTA_DIFFUSE);
    dev->SetTextureStageState(1,D3DTSS_COLOROP,  D3DTOP_DISABLE);
    dev->SetTextureStageState(1,D3DTSS_ALPHAOP,  D3DTOP_DISABLE);

    // Echelle proportionnelle : contenu suit la largeur (base 360px = 1.0)
    g_panelScale = (float)g_panelW / 360.0f;
    if (g_panelScale < 0.7f) g_panelScale = 0.7f;
    if (g_panelScale > 1.5f) g_panelScale = 1.5f;

    EnsureFonts(dev);
    EnsurePanelPos();
    CheckFightTimeout();

    StatsCS_Enter();
    DWORD fightStart = g_fightStart, fightEnd = g_fightEnd, lastHit = g_lastHit;
    DWORD lastDmgOut = g_lastDmgOut, lastHeal = g_lastHeal, lastDmgIn = g_lastDmgIn;
    int   count = g_combatCount;

    SortRow rows[MAX_COMBATANTS * 2]; int rowCount = 0;
    unsigned int seenOwners[MAX_COMBATANTS]; int seenCount = 0;

    // Refresh noms : corrige les entrees creees avant que les noms soient connus
    // (joueur local, pets, joueurs arrives avant le 1er ParseEnter)
    for (int i = 0; i < count; ++i) {
        char fresh[24];
        GetEntityName(g_combat[i].handle, fresh, sizeof(fresh));
        if (fresh[0] && fresh[0] != '#')
            _snprintf_s(g_combat[i].name, sizeof(g_combat[i].name), _TRUNCATE, "%s", fresh);
    }

    for (int i = 0; i < count; ++i) {
        unsigned int ow = g_combat[i].ownerHandle; bool f2 = false;
        for (int j = 0; j < seenCount; ++j) if (seenOwners[j]==ow){f2=true;break;}
        if (!f2 && seenCount < MAX_COMBATANTS) seenOwners[seenCount++] = ow;
    }
    int colorCount = 0;
    for (int oi = 0; oi < seenCount && rowCount < MAX_COMBATANTS*2; ++oi) {
        unsigned int ow = seenOwners[oi];
        // Filtrer les mobs : bit31 = 0 -> mob, bit31 = 1 -> joueur/pet/ally
        if (!IsPlayerEntity(ow)) continue;
        LONGLONG total = 0; int owMax = 0; char owName[24]={};
        for (int i = 0; i < count; ++i) {
            CombatEntry* e = &g_combat[i]; if (e->ownerHandle != ow) continue;
            LONGLONG v=(g_tab==TAB_DPS)?e->dmgOut:(g_tab==TAB_HEAL)?e->healOut:(g_tab==TAB_RCVD)?e->dmgIn:(LONGLONG)e->maxHit;
            int vm=(g_tab==TAB_DPS)?e->maxHit:(g_tab==TAB_HEAL)?e->maxHeal:(g_tab==TAB_RCVD)?e->maxRcvd:e->maxHit;
            total += v;
            if (vm > owMax) owMax = vm;
            if (e->handle == ow && e->name[0]) _snprintf_s(owName,sizeof(owName),_TRUNCATE,"%s",e->name);
        }
        if (total == 0) continue;
        if (!owName[0]) GetEntityName(ow, owName, sizeof(owName));
        int ci = colorCount++ % 8;
        SortRow& r = rows[rowCount++]; memset(&r,0,sizeof(r));
        r.ownerHandle=ow; r.selfHandle=ow; r.value=total; r.maxValue=owMax; r.isPet=false; r.colorIdx=ci;
        _snprintf_s(r.name,sizeof(r.name),_TRUNCATE,"%s",owName);
        for (int i = 0; i < count && rowCount < MAX_COMBATANTS*2; ++i) {
            CombatEntry* e = &g_combat[i];
            if (e->ownerHandle!=ow || e->handle==ow) continue;
            LONGLONG v=(g_tab==TAB_DPS)?e->dmgOut:(g_tab==TAB_HEAL)?e->healOut:(g_tab==TAB_RCVD)?e->dmgIn:(LONGLONG)e->maxHit;
            int vm=(g_tab==TAB_DPS)?e->maxHit:(g_tab==TAB_HEAL)?e->maxHeal:(g_tab==TAB_RCVD)?e->maxRcvd:e->maxHit;
            if (v==0) continue;
            SortRow& rp = rows[rowCount++]; memset(&rp,0,sizeof(rp));
            rp.ownerHandle=ow; rp.selfHandle=e->handle; rp.value=v; rp.maxValue=vm; rp.isPet=true; rp.colorIdx=ci;
            GetEntityName(e->handle, rp.name, sizeof(rp.name));
        }
    }
    // Tri dynamique par groupes (owner + ses pets) selon la valeur owner, decroissant
    struct GroupInfo { int start; int len; LONGLONG ownerVal; };
    GroupInfo groups[MAX_COMBATANTS]; int nGroups = 0;
    for (int i = 0; i < rowCount; ) {
        if (!rows[i].isPet) {
            int gStart = i; LONGLONG ov = rows[i].value; ++i;
            while (i < rowCount && rows[i].isPet) ++i;
            if (nGroups < MAX_COMBATANTS) { groups[nGroups].start=gStart; groups[nGroups].len=i-gStart; groups[nGroups].ownerVal=ov; ++nGroups; }
        } else ++i;
    }
    // Insertion sort groupes par ownerVal decroissant
    for (int gi = 1; gi < nGroups; ++gi) {
        GroupInfo kg = groups[gi]; int gj = gi - 1;
        while (gj >= 0 && groups[gj].ownerVal < kg.ownerVal) { groups[gj+1]=groups[gj]; --gj; }
        groups[gj+1] = kg;
    }
    // Reconstruire rows dans le nouvel ordre
    {
        SortRow sorted[MAX_COMBATANTS * 2]; int si2 = 0;
        for (int gi = 0; gi < nGroups; ++gi)
            for (int k = 0; k < groups[gi].len && si2 < MAX_COMBATANTS*2; ++k)
                sorted[si2++] = rows[groups[gi].start + k];
        memcpy(rows, sorted, si2 * sizeof(SortRow));
    }
    LONGLONG groupTotal = 0;
    LONGLONG maxVal = 1;
    for (int i = 0; i < rowCount; ++i)
        if (!rows[i].isPet) { groupTotal += rows[i].value; if (rows[i].value > maxVal) maxVal = rows[i].value; }
    if (groupTotal < 1) groupTotal = 1;
    DWORD now = GetTickCount();
    // Timer independant par onglet :
    //   DPS tab  -> lastDmgOut  /  HEAL tab -> lastHeal  /  TANK tab -> lastDmgIn
    //   Max tab  -> lastDmgOut (meme temporalite que DPS)
    DWORD tabLastHit = (g_tab == TAB_HEAL) ? lastHeal :
                       (g_tab == TAB_RCVD) ? lastDmgIn : lastDmgOut;
    // Onglet actif = fight en cours ET cet onglet a eu une activite recente
    bool  tabIsActive = fightStart && !fightEnd && tabLastHit &&
                        (now - tabLastHit <= g_fightTimeout);
    // Timer d'affichage : defileait tant qu'actif, gele sur tabLastHit sinon
    DWORD timerEnd  = tabIsActive ? now : (tabLastHit ? tabLastHit : fightStart);
    DWORD timerMs   = (fightStart && timerEnd >= fightStart) ? (timerEnd - fightStart) : 0;
    // Diviseur /s : gele sur tabLastHit -> le score ne descend plus si l'onglet est inactif
    DWORD durationMs  = (fightStart && tabLastHit && tabLastHit >= fightStart)
                        ? (tabLastHit - fightStart) : 0;
    float durationSec = durationMs / 1000.0f;
    float timerSec    = timerMs   / 1000.0f;
    LONGLONG topDmg   = (rowCount>0&&!rows[0].isPet) ? rows[0].value : 0;
    float effSec      = (durationSec > 1.0f) ? durationSec : 1.0f;
    float topDps      = (topDmg > 0 && g_tab == TAB_DPS) ? (float)(topDmg / effSec) : 0.f;
    StatsCS_Leave();

    // Retry scan name si nom local toujours inconnu (toutes les 5s).
    {
        static DWORD s_lastScanRetry = 0;
        if (g_localHandle && !g_localNameCache[0] && now - s_lastScanRetry > 5000) {
            s_lastScanRetry = now;
            if (TryQueueNameScan(g_localHandle))
                CloseHandle(CreateThread(nullptr, 0, ScanNameByHandleThread,
                                         (LPVOID)(uintptr_t)(unsigned int)g_localHandle, 0, nullptr));
        }
    }

    // Log periodique du panel toutes les 5s
    static DWORD s_lastPanelDump = 0;
    if (fightStart && now - s_lastPanelDump > 5000) {
        s_lastPanelDump = now;
        Log("=PANEL= localH=%u localName=[%s] combatants=%d rows=%d dur=%.1fs",
            g_localHandle, g_localNameCache, count, rowCount, durationSec);
        for (int ri = 0; ri < rowCount && ri < g_maxVisibleRows; ++ri)
            Log("  [%d] owner=%u name=[%s] val=%lld pet=%d player=%d",
                ri, rows[ri].ownerHandle, rows[ri].name, rows[ri].value,
                (int)rows[ri].isPet, (int)IsPlayerEntity(rows[ri].ownerHandle));
    }

    // Clamp scroll offset
    if (g_scrollOffset < 0) g_scrollOffset = 0;
    if (g_scrollOffset > rowCount - 1) g_scrollOffset = (rowCount > 0) ? rowCount - 1 : 0;

    int visRows = 0;
    for (int i = g_scrollOffset; i < rowCount && visRows < g_maxVisibleRows; ++i) ++visRows;
    int settingsH = g_settingsOpen ? 48 : 0;
    int rowH = (int)(ROW_H * g_panelScale + 0.5f);
    int panelH = PANEL_HEADER + settingsH + 14 + visRows*rowH + 4;
    if (panelH < PANEL_HEADER + 30) panelH = PANEL_HEADER + 30;  // hauteur min pour poignee
    g_panelH = panelH;
    int px=g_panelX, py=g_panelY, pw=g_panelW;
    int listY = py + PANEL_HEADER + settingsH; // debut zone liste (sous header + settings)
    // Colonnes responsives (en % de la largeur depuis le bord droit)
    int colGrpL = px + pw - (int)(pw * 0.12f);  // Grp% : 12%
    int colGrpR = px + pw - 4;
    int colTotL = px + pw - (int)(pw * 0.30f);  // Total : 18%
    int colTotR = colGrpL - 4;
    int colDpsL = px + pw - (int)(pw * 0.48f);  // DPS/s : 18%
    int colDpsR = colTotL - 4;
    int colNameR = colDpsL - 6;                 // Nom : le reste

    FillRect2D(dev,px,py,pw,panelH,D3DCOLOR_ARGB(210,15,15,20));
    DWORD border = D3DCOLOR_ARGB(210,60,120,200);
    FillRect2D(dev,px,py,pw,1,border); FillRect2D(dev,px,py+panelH-1,pw,1,border);
    FillRect2D(dev,px,py,1,panelH,border); FillRect2D(dev,px+pw-1,py,1,panelH,border);

    FillRect2D(dev,px+1,py+1,pw-2,20,D3DCOLOR_ARGB(230,20,40,80));
    {RECT tr={px+4,py+3,px+pw-40,py+20};
     DrawText2(g_fontRow,"DPS Counter",tr,DT_LEFT|DT_VCENTER,D3DCOLOR_ARGB(255,180,210,255));}

    // Compteurs diagnostics
    {char dbg[64];
     _snprintf_s(dbg,sizeof(dbg),_TRUNCATE,"buf:%ld a:%ld s:%ld h:%ld",
                 g_debugBufCalls,g_debugPkt101,g_debugPkt401,g_debugHits);
     RECT dr={px+4,py+20,px+pw-4,py+35};
     DrawText2(g_fontSmall,dbg,dr,DT_LEFT|DT_VCENTER,D3DCOLOR_ARGB(160,140,180,255));}

    // Bouton X
    int bx=px+pw-18, by2=py+1;
    FillRect2D(dev,bx,by2,17,18,g_closeHover?D3DCOLOR_ARGB(230,180,30,30):D3DCOLOR_ARGB(200,80,15,15));
    {RECT cr={bx,by2,bx+17,by2+18};DrawText2(g_fontRow,"X",cr,DT_CENTER|DT_VCENTER,D3DCOLOR_ARGB(255,255,200,200));}

    // Bouton R
    int rx=bx-19, ry3=by2;
    FillRect2D(dev,rx,ry3,17,18,g_resetHover?D3DCOLOR_ARGB(230,30,130,30):D3DCOLOR_ARGB(200,15,60,15));
    {RECT rr2={rx,ry3,rx+17,ry3+18};DrawText2(g_fontSmall,"R",rr2,DT_CENTER|DT_VCENTER,D3DCOLOR_ARGB(255,150,255,150));}

    // Bouton Settings (engrenage)
    int sx=rx-19, sy2=by2;
    FillRect2D(dev,sx,sy2,17,18,g_settingsHover||g_settingsOpen?D3DCOLOR_ARGB(230,60,60,140):D3DCOLOR_ARGB(200,30,30,70));
    {RECT sr={sx,sy2,sx+17,sy2+18};DrawText2(g_fontSmall,"+",sr,DT_CENTER|DT_VCENTER,D3DCOLOR_ARGB(255,200,200,255));}

    // Panneau settings
    if(g_settingsOpen){
        int setY=py+PANEL_HEADER+4, setH=44;
        FillRect2D(dev,px+1,setY,pw-2,setH,D3DCOLOR_ARGB(225,18,20,35));
        FillRect2D(dev,px+1,setY,pw-2,1,D3DCOLOR_ARGB(180,80,100,180));
        FillRect2D(dev,px+1,setY+setH-1,pw-2,1,D3DCOLOR_ARGB(180,80,100,180));
        {char tbuf[48]; _snprintf_s(tbuf,sizeof(tbuf),_TRUNCATE,"Timeout reset: %ds",(int)(g_fightTimeout/1000));
         RECT trs={px+6,setY+2,px+pw-6,setY+20};
         DrawText2(g_fontSmall,tbuf,trs,DT_CENTER|DT_VCENTER,D3DCOLOR_ARGB(255,200,210,255));}
        int midX=px+pw/2;
        // Bouton "-"
        FillRect2D(dev,midX-60,setY+22,36,16,D3DCOLOR_ARGB(200,80,40,40));
        {RECT mr={midX-60,setY+22,midX-24,setY+38};DrawText2(g_fontSmall,"-1s",mr,DT_CENTER|DT_VCENTER,D3DCOLOR_ARGB(255,255,180,180));}
        // Bouton "+"
        FillRect2D(dev,midX+24,setY+22,36,16,D3DCOLOR_ARGB(200,40,120,40));
        {RECT prs={midX+24,setY+22,midX+60,setY+38};DrawText2(g_fontSmall,"+1s",prs,DT_CENTER|DT_VCENTER,D3DCOLOR_ARGB(255,180,255,180));}
    }

    // Onglets (responsifs : ~11% de largeur par onglet)
    static const char* tl[4]={"DPS","HEAL","TANK","Max"};
    int tabW=(int)(pw*0.11f); if(tabW<32)tabW=32; if(tabW>72)tabW=72;
    int tabGap=(int)(pw*0.005f); if(tabGap<1)tabGap=1;
    int tabY=py+36;
    for (int t=0;t<4;++t){
        int tx=px+1+t*(tabW+tabGap); bool active=(g_tab==(MetricTab)t);
        bool hov=(t==0?g_tab0Hover:t==1?g_tab1Hover:t==2?g_tab2Hover:g_tab3Hover);
        DWORD tbg=active?D3DCOLOR_ARGB(230,40,80,160):hov?D3DCOLOR_ARGB(200,30,60,120):D3DCOLOR_ARGB(180,20,35,70);
        FillRect2D(dev,tx,tabY,tabW,16,tbg);
        if(active)FillRect2D(dev,tx,tabY+15,tabW,1,D3DCOLOR_ARGB(255,120,180,255));
        RECT tr2={tx,tabY,tx+tabW,tabY+16};
        DrawText2(g_fontSmall,tl[t],tr2,DT_CENTER|DT_VCENTER,
                  active?D3DCOLOR_ARGB(255,220,240,255):D3DCOLOR_ARGB(200,140,160,200));
    }

    // Infos combat
    {char info[80];
     if (!fightStart || !tabLastHit) _snprintf_s(info,sizeof(info),_TRUNCATE,"En attente...");
     else{int sec=(int)(timerMs/1000),mn=sec/60;sec%=60;
          const char* st=tabIsActive?"[ACT]":"[FIN]";
          if(g_tab==TAB_DPS&&topDps>0)
              _snprintf_s(info,sizeof(info),_TRUNCATE,"%d:%02d  Top: %.0f/s  %s",mn,sec,topDps,st);
          else _snprintf_s(info,sizeof(info),_TRUNCATE,"%d:%02d  %s",mn,sec,st);}
     RECT ir={px+4,py+53,px+pw-4,py+PANEL_HEADER-1};
     DrawText2(g_fontSmall,info,ir,DT_LEFT|DT_VCENTER,D3DCOLOR_ARGB(220,180,200,255));}

    FillRect2D(dev,px+1,py+PANEL_HEADER-1,pw-2,1,D3DCOLOR_ARGB(120,60,120,200));
    // En-tetes de colonnes
    FillRect2D(dev,px+1,listY,pw-2,14,D3DCOLOR_ARGB(190,10,14,24));
    {const char* colLbl=(g_tab==TAB_HEAL)?"HPS/s":(g_tab==TAB_RCVD)?"Tank/s":(g_tab==TAB_MAXHIT)?"Max":"DPS/s";
     RECT ch={colDpsL,listY,colDpsR,listY+14};
     DrawText2(g_fontSmall,colLbl,ch,DT_RIGHT|DT_VCENTER,D3DCOLOR_ARGB(140,150,180,220));}
    {RECT ch={colTotL,listY,colTotR,listY+14};
     DrawText2(g_fontSmall,"Total",ch,DT_RIGHT|DT_VCENTER,D3DCOLOR_ARGB(140,150,180,220));}
    {RECT ch={colGrpL,listY,colGrpR,listY+14};
     DrawText2(g_fontSmall,"Grp%",ch,DT_RIGHT|DT_VCENTER,D3DCOLOR_ARGB(140,150,180,220));}
    FillRect2D(dev,px+1,listY+13,pw-2,1,D3DCOLOR_ARGB(80,60,120,200));

    int shown = 0;
    for (int i = g_scrollOffset; i < rowCount && shown < g_maxVisibleRows; ++i, ++shown)
    {
        SortRow& row = rows[i];
        int ry4 = listY+14+shown*rowH;
        DWORD rbg = row.isPet ? kPetBg[row.colorIdx & 7] : kOwnerBg[row.colorIdx & 7];
        FillRect2D(dev,px+1,ry4,pw-2,rowH,rbg);

        if (!row.isPet) {
            // Barre : relative au top joueur (comparaison visuelle)
            float pctMax=maxVal>0?(float)row.value/(float)maxVal:0.f;
            int bw=(int)(pctMax*(pw-2));
            if(bw>0) FillRect2D(dev,px+1,ry4,bw,rowH,kOwnerBar[row.colorIdx & 7]);
            // Nom
            {RECT nr={px+6,ry4,colNameR,ry4+rowH};
             DrawText2(g_fontRow,row.name,nr,DT_LEFT|DT_VCENTER,D3DCOLOR_ARGB(255,230,230,230));}
            // DPS/val par seconde (ou max hit pour l'onglet Max)
            char dpsStr[32]="--";
            if(g_tab==TAB_MAXHIT){
                if(row.maxValue>0){
                    if(row.maxValue>=1000000) _snprintf_s(dpsStr,sizeof(dpsStr),_TRUNCATE,"%.2fM",(float)row.maxValue/1000000.f);
                    else if(row.maxValue>=10000) _snprintf_s(dpsStr,sizeof(dpsStr),_TRUNCATE,"%.1fk",(float)row.maxValue/1000.f);
                    else _snprintf_s(dpsStr,sizeof(dpsStr),_TRUNCATE,"%d",row.maxValue);
                }
            } else if(row.value > 0){
                float dps=(float)row.value / ((durationSec>1.0f)?durationSec:1.0f);
                if(dps>=1000000.f) _snprintf_s(dpsStr,sizeof(dpsStr),_TRUNCATE,"%.2fM",dps/1000000.f);
                else if(dps>=10000.f) _snprintf_s(dpsStr,sizeof(dpsStr),_TRUNCATE,"%.1fk",dps/1000.f);
                else if(dps>=1000.f) _snprintf_s(dpsStr,sizeof(dpsStr),_TRUNCATE,"%.1fk",dps/1000.f);
                else _snprintf_s(dpsStr,sizeof(dpsStr),_TRUNCATE,"%.0f",dps);
            }
            {RECT dr={colDpsL,ry4,colDpsR,ry4+rowH};
             DrawText2(g_fontRow,dpsStr,dr,DT_RIGHT|DT_VCENTER,D3DCOLOR_ARGB(255,255,220,100));}
            // Total
            char totStr[32];
            if(row.value>=1000000LL) _snprintf_s(totStr,sizeof(totStr),_TRUNCATE,"%.2fM",row.value/1000000.0);
            else if(row.value>=10000LL) _snprintf_s(totStr,sizeof(totStr),_TRUNCATE,"%.1fk",row.value/1000.0);
            else if(row.value>=1000LL) _snprintf_s(totStr,sizeof(totStr),_TRUNCATE,"%.1fk",row.value/1000.0);
            else _snprintf_s(totStr,sizeof(totStr),_TRUNCATE,"%lld",row.value);
            {RECT tr3={colTotL,ry4,colTotR,ry4+rowH};
             DrawText2(g_fontSmall,totStr,tr3,DT_RIGHT|DT_VCENTER,D3DCOLOR_ARGB(220,180,210,255));}
            // Pourcentage du groupe
            char ps[16];
            {int pct=(groupTotal>0)?(int)((row.value*100LL)/groupTotal):0;
             _snprintf_s(ps,sizeof(ps),_TRUNCATE,"%d%%",pct);}
            {RECT pr={colGrpL,ry4,colGrpR,ry4+rowH};
             DrawText2(g_fontSmall,ps,pr,DT_RIGHT|DT_VCENTER,D3DCOLOR_ARGB(220,255,180,80));}
        } else {
            // Ligne pet - indentee
            {RECT nr={px+18,ry4,colNameR,ry4+rowH};
             DrawText2(g_fontSmall,row.name,nr,DT_LEFT|DT_VCENTER,D3DCOLOR_ARGB(210,180,200,140));}
            // DPS pet
            char dpsStr[32]="--";
            if(g_tab==TAB_MAXHIT){
                if(row.maxValue>0){
                    if(row.maxValue>=10000) _snprintf_s(dpsStr,sizeof(dpsStr),_TRUNCATE,"%.1fk",(float)row.maxValue/1000.f);
                    else _snprintf_s(dpsStr,sizeof(dpsStr),_TRUNCATE,"%d",row.maxValue);
                }
            } else if(row.value > 0){
                float dps=(float)row.value / ((durationSec>1.0f)?durationSec:1.0f);
                if(dps>=1000000.f) _snprintf_s(dpsStr,sizeof(dpsStr),_TRUNCATE,"%.2fM",dps/1000000.f);
                else if(dps>=10000.f) _snprintf_s(dpsStr,sizeof(dpsStr),_TRUNCATE,"%.1fk",dps/1000.f);
                else if(dps>=1000.f) _snprintf_s(dpsStr,sizeof(dpsStr),_TRUNCATE,"%.1fk",dps/1000.f);
                else _snprintf_s(dpsStr,sizeof(dpsStr),_TRUNCATE,"%.0f",dps);
            }
            {RECT dr={colDpsL,ry4,colDpsR,ry4+rowH};
             DrawText2(g_fontSmall,dpsStr,dr,DT_RIGHT|DT_VCENTER,D3DCOLOR_ARGB(200,200,180,80));}
            // Total
            char totStr[32];
            if(row.value>=1000000LL) _snprintf_s(totStr,sizeof(totStr),_TRUNCATE,"%.2fM",row.value/1000000.0);
            else if(row.value>=10000LL) _snprintf_s(totStr,sizeof(totStr),_TRUNCATE,"%.1fk",row.value/1000.0);
            else if(row.value>=1000LL) _snprintf_s(totStr,sizeof(totStr),_TRUNCATE,"%.0fk",row.value/1000.0);
            else _snprintf_s(totStr,sizeof(totStr),_TRUNCATE,"%lld",row.value);
            {RECT tr3={colTotL,ry4,colTotR,ry4+rowH};
             DrawText2(g_fontSmall,totStr,tr3,DT_RIGHT|DT_VCENTER,D3DCOLOR_ARGB(180,155,175,115));}
            // Pourcentage du groupe (pet)
            char ps[16];
            {int pct=(groupTotal>0)?(int)((row.value*100LL)/groupTotal):0;
             _snprintf_s(ps,sizeof(ps),_TRUNCATE,"%d%%",pct);}
            {RECT pr={colGrpL,ry4,colGrpR,ry4+rowH};
             DrawText2(g_fontSmall,ps,pr,DT_RIGHT|DT_VCENTER,D3DCOLOR_ARGB(180,210,160,60));}
        }
    }
    // Barre de defilement verticale (visible seulement si plus de g_maxVisibleRows entrees)
    if (rowCount > g_maxVisibleRows)
    {
        int sbX     = px + pw - 5;
        int sbTrackY = listY + 14;
        int sbTrackH = visRows * rowH;
        FillRect2D(dev, sbX, sbTrackY, 4, sbTrackH, D3DCOLOR_ARGB(100, 40, 40, 50));
        float thumbFrac   = (float)g_maxVisibleRows  / (float)rowCount;
        float offsetFrac  = (float)g_scrollOffset / (float)rowCount;
        int   thumbH = (int)(sbTrackH * thumbFrac); if (thumbH < 6) thumbH = 6;
        int   thumbY = sbTrackY + (int)(sbTrackH * offsetFrac);
        if (thumbY + thumbH > sbTrackY + sbTrackH) thumbY = sbTrackY + sbTrackH - thumbH;
        FillRect2D(dev, sbX, thumbY, 4, thumbH, D3DCOLOR_ARGB(200, 100, 150, 255));
    }
    // Poignees de redimensionnement
    if(!g_settingsOpen){
        // Coin bas-droit (largeur + hauteur)
        int cx=px+pw-16, cy=py+panelH-16;
        FillRect2D(dev,cx+10,cy+10,6,2,D3DCOLOR_ARGB(180,160,180,220));
        FillRect2D(dev,cx+8,cy+12,8,2,D3DCOLOR_ARGB(160,140,160,200));
        FillRect2D(dev,cx+6,cy+14,10,2,D3DCOLOR_ARGB(140,120,140,180));
        // Bord droit (largeur)
        int rhx=px+pw-10, rhy=py+panelH-4;
        FillRect2D(dev,rhx,rhy,8,2,D3DCOLOR_ARGB(100,100,120,140));
        FillRect2D(dev,rhx+2,rhy-3,6,2,D3DCOLOR_ARGB(100,100,120,140));
        FillRect2D(dev,rhx+4,rhy-6,4,2,D3DCOLOR_ARGB(100,100,120,140));
        // Bord bas (hauteur)
        int bbx=px+pw-4, bby=py+panelH-10;
        FillRect2D(dev,bbx,bby,2,8,D3DCOLOR_ARGB(100,100,120,140));
        FillRect2D(dev,bbx-3,bby+2,2,6,D3DCOLOR_ARGB(100,100,120,140));
        FillRect2D(dev,bbx-6,bby+4,2,4,D3DCOLOR_ARGB(100,100,120,140));
    }

    pSB->Apply(); pSB->Release();
}

// ============================================================
// D3D9 hook callbacks
// ============================================================
static HRESULT WINAPI HookedReset(IDirect3DDevice9* dev, D3DPRESENT_PARAMETERS* pp)
{
    ReleaseFonts();
    return g_trampolineReset(dev, pp);
}
static HRESULT WINAPI HookedEndScene(IDirect3DDevice9* dev)
{
    static int s_frame = 0; ++s_frame;
    if (s_frame <= 30) return g_trampolineES(dev);
    __try {
        D3DVIEWPORT9 vp={}; dev->GetViewport(&vp);
        g_vpW=(int)vp.Width; g_vpH=(int)vp.Height;
        if(g_vpW>=640&&g_vpH>=480) DrawDPSPanel(dev);
    } __except(EXCEPTION_EXECUTE_HANDLER) { ReleaseFonts(); }
    return g_trampolineES(dev);
}

// ============================================================
// WndProc hook
// ============================================================
static bool PtInPanelHeader(int mx,int my){
    if(!g_panelVisible)return false;
    return mx>=g_panelX&&mx<g_panelX+g_panelW&&my>=g_panelY&&my<g_panelY+PANEL_HEADER;}
static bool PtInClose(int mx,int my){int bx=g_panelX+g_panelW-18,by=g_panelY+1;return mx>=bx&&mx<bx+17&&my>=by&&my<by+18;}
static bool PtInReset(int mx,int my){int bx=g_panelX+g_panelW-37,by=g_panelY+1;return mx>=bx&&mx<bx+17&&my>=by&&my<by+18;}
static bool PtInSettings(int mx,int my){int bx=g_panelX+g_panelW-55,by=g_panelY+1;return mx>=bx&&mx<bx+17&&my>=by&&my<by+18;}
static bool PtInResizeCorner(int mx,int my){
    if(!g_panelVisible||g_settingsOpen)return false;
    // Coin bas-droit : 30x30px -> largeur + hauteur simultanes
    return (mx >= g_panelX + g_panelW - 30 && mx < g_panelX + g_panelW + 6 &&
            my >= g_panelY + g_panelH - 30 && my < g_panelY + g_panelH + 6);
}
static bool PtInResizeEdge(int mx,int my){
    if(!g_panelVisible||g_settingsOpen)return false;
    // Bord droit -> largeur seule (pas le coin)
    return (mx>=g_panelX+g_panelW-8&&mx<g_panelX+g_panelW+4 &&
            my>=g_panelY&&my<g_panelY+g_panelH-30);
}
static bool PtInResizeBottom(int mx,int my){
    if(!g_panelVisible||g_settingsOpen)return false;
    // Bord bas -> hauteur seule (pas le coin)
    int gripTop = g_panelY + g_panelH - 12;
    if (gripTop < g_panelY + PANEL_HEADER) gripTop = g_panelY + PANEL_HEADER;
    return (my >= gripTop && my < g_panelY + g_panelH + 6 &&
            mx >= g_panelX && mx < g_panelX + g_panelW - 30);
}
static int PtInTab(int mx,int my){
    int ty=g_panelY+36;if(my<ty||my>=ty+16)return -1;
    int tabW=(int)(g_panelW*0.11f); if(tabW<32)tabW=32; if(tabW>72)tabW=72;
    int tabGap=(int)(g_panelW*0.005f); if(tabGap<1)tabGap=1;
    for(int t=0;t<4;++t){int tx=g_panelX+1+t*(tabW+tabGap);if(mx>=tx&&mx<tx+tabW)return t;}return -1;
}
static bool HandlePanelMouse(UINT msg,LPARAM lp){
    if(!g_panelVisible||g_vpW<=0)return false;
    int mx=GET_X_LPARAM(lp),my=GET_Y_LPARAM(lp);

    // Gestion du panneau settings (prioritaire)
    if(g_settingsOpen){
        int sy=g_panelY+PANEL_HEADER+4, sh=44; // hauteur du mini-panneau
        bool inSettings=mx>=g_panelX&&mx<g_panelX+g_panelW&&my>=sy&&my<sy+sh;
        if(msg==WM_LBUTTONDOWN){
            // Boutons +/- timeout
            int midX=g_panelX+g_panelW/2;
            if(my>=sy+20&&my<sy+40){
                if(mx>=midX-60&&mx<midX-20){ // bouton "-"
                    if(g_fightTimeout>1000) g_fightTimeout-=1000;
                    SavePanelPos(); return true;
                }
                if(mx>=midX+20&&mx<midX+60){ // bouton "+"
                    if(g_fightTimeout<120000) g_fightTimeout+=1000;
                    SavePanelPos(); return true;
                }
            }
            // Clic hors settings -> fermer
            if(!inSettings){g_settingsOpen=false;return true;}
            return true;
        }
        // Bloquer autres interactions quand settings ouvert
        return (msg==WM_MOUSEMOVE) ? false : inSettings;
    }

    if(msg==WM_MOUSEMOVE){
        g_closeHover=PtInClose(mx,my); g_resetHover=PtInReset(mx,my);
        g_settingsHover=PtInSettings(mx,my);
        int t=PtInTab(mx,my);g_tab0Hover=(t==0);g_tab1Hover=(t==1);g_tab2Hover=(t==2);g_tab3Hover=(t==3);
    }
    if(msg==WM_LBUTTONDOWN&&PtInClose(mx,my)){SetCapture(g_hWnd);return true;}
    if(msg==WM_LBUTTONUP&&g_closeHover&&PtInClose(mx,my)){ReleaseCapture();g_panelVisible=false;CloseHandle(CreateThread(nullptr,0,UnloadThread,nullptr,0,nullptr));return true;}
    if(msg==WM_LBUTTONDOWN&&PtInReset(mx,my)){SetCapture(g_hWnd);return true;}
    if(msg==WM_LBUTTONUP&&g_resetHover&&PtInReset(mx,my)){ReleaseCapture();ResetCombat();return true;}
    if(msg==WM_LBUTTONDOWN&&PtInSettings(mx,my)){g_settingsOpen=!g_settingsOpen;return true;}
    if(msg==WM_LBUTTONDOWN){int t=PtInTab(mx,my);if(t>=0&&t<=3){g_tab=(MetricTab)t;return true;}}
    // Redimensionnement largeur (bord droit)
    if(msg==WM_LBUTTONDOWN&&PtInResizeEdge(mx,my)&&!PtInClose(mx,my)&&!PtInReset(mx,my)&&!PtInSettings(mx,my)&&!PtInResizeCorner(mx,my)&&!PtInResizeBottom(mx,my)){
        g_resizing=true;g_resizeMoved=false;g_resizeOffX=mx-g_panelW;SetCapture(g_hWnd);return true;
    }
    if(msg==WM_MOUSEMOVE&&g_resizing){
        int nw=mx-g_resizeOffX;
        if(nw<PANEL_MIN_W)nw=PANEL_MIN_W;if(nw>PANEL_MAX_W)nw=PANEL_MAX_W;
        if(g_panelX+nw>g_vpW)nw=g_vpW-g_panelX;
        g_panelW=nw;g_resizeMoved=true;return true;
    }
    if(msg==WM_LBUTTONUP&&g_resizing){g_resizing=false;ReleaseCapture();if(g_resizeMoved)SavePanelPos();return g_resizeMoved;}
    // Redimensionnement hauteur (bord bas)
    if(msg==WM_LBUTTONDOWN&&PtInResizeBottom(mx,my)&&!PtInClose(mx,my)&&!PtInReset(mx,my)&&!PtInSettings(mx,my)&&!PtInResizeEdge(mx,my)&&!PtInResizeCorner(mx,my)){
        g_resizingH=true;g_resizeMoved=false;g_resizeOffY=my-g_panelH;SetCapture(g_hWnd);return true;
    }
    if(msg==WM_MOUSEMOVE&&g_resizingH){
        int newH = my - g_resizeOffY;
        int settingsH2 = g_settingsOpen ? 48 : 0;
        int rowH2 = (int)(ROW_H * g_panelScale + 0.5f);
        if (rowH2 < 10) rowH2 = 10;
        int contentH = newH - PANEL_HEADER - settingsH2 - 14 - 4;
        int newRows = contentH / rowH2;
        if(newRows<4)newRows=4; if(newRows>MAX_ROWS)newRows=MAX_ROWS;
        g_maxVisibleRows=newRows;g_resizeMoved=true;return true;
    }
    if(msg==WM_LBUTTONUP&&g_resizingH){g_resizingH=false;ReleaseCapture();if(g_resizeMoved)SavePanelPos();return g_resizeMoved;}
    // Redimensionnement coin (largeur + hauteur en meme temps)
    if(msg==WM_LBUTTONDOWN&&PtInResizeCorner(mx,my)&&!PtInClose(mx,my)&&!PtInReset(mx,my)&&!PtInSettings(mx,my)){
        g_resizingCorner=true;g_resizeMoved=false;
        g_cornerInitW=g_panelW; g_cornerInitRows=g_maxVisibleRows;
        g_cornerInitX=mx; g_cornerInitY=my;
        SetCapture(g_hWnd);return true;
    }
    if(msg==WM_MOUSEMOVE&&g_resizingCorner){
        int dX=mx-g_cornerInitX, dY=my-g_cornerInitY;
        int nw=g_cornerInitW+dX;
        if(nw<PANEL_MIN_W)nw=PANEL_MIN_W; if(nw>PANEL_MAX_W)nw=PANEL_MAX_W;
        if(g_panelX+nw>g_vpW)nw=g_vpW-g_panelX;
        g_panelW=nw;
        int settingsH2 = g_settingsOpen ? 48 : 0;
        int rowH2 = (int)(ROW_H * g_panelScale + 0.5f);
        if (rowH2 < 10) rowH2 = 10;
        int panelH2 = PANEL_HEADER + settingsH2 + 14 + g_cornerInitRows*rowH2 + 4;
        int newH = panelH2 + dY;
        int contentH = newH - PANEL_HEADER - settingsH2 - 14 - 4;
        int newRows = contentH / rowH2;
        if(newRows<4)newRows=4; if(newRows>MAX_ROWS)newRows=MAX_ROWS;
        g_maxVisibleRows=newRows;
        g_resizeMoved=true;return true;
    }
    if(msg==WM_LBUTTONUP&&g_resizingCorner){g_resizingCorner=false;ReleaseCapture();if(g_resizeMoved)SavePanelPos();return g_resizeMoved;}
    // Drag panel
    if(msg==WM_LBUTTONDOWN&&PtInPanelHeader(mx,my)&&!PtInClose(mx,my)&&!PtInReset(mx,my)&&!PtInSettings(mx,my)&&!PtInResizeEdge(mx,my)&&!PtInResizeBottom(mx,my)&&!PtInResizeCorner(mx,my)){
        g_dragging=true;g_dragMoved=false;g_dragOffX=mx-g_panelX;g_dragOffY=my-g_panelY;SetCapture(g_hWnd);return true;}
    if(msg==WM_MOUSEMOVE&&g_dragging){g_panelX=mx-g_dragOffX;g_panelY=my-g_dragOffY;if(g_panelX<0)g_panelX=0;if(g_panelY<0)g_panelY=0;if(g_panelX+g_panelW>g_vpW)g_panelX=g_vpW-g_panelW;g_dragMoved=true;return true;}
    if(msg==WM_LBUTTONUP&&g_dragging){g_dragging=false;ReleaseCapture();if(g_dragMoved)SavePanelPos();return g_dragMoved;}
    return false;
}
static LRESULT CALLBACK CustomWndProc(HWND hwnd,UINT msg,WPARAM wp,LPARAM lp){
    if(msg==WM_MOUSEMOVE||msg==WM_LBUTTONDOWN||msg==WM_LBUTTONUP)
        if(HandlePanelMouse(msg,lp))return 0;
    if(msg==WM_MOUSEWHEEL&&g_panelVisible&&g_vpW>0){
        // WM_MOUSEWHEEL : lParam = coordonnees ecran.
        // Ne traiter que si la souris est vraiment sur notre fenetre.
        POINT pt={GET_X_LPARAM(lp),GET_Y_LPARAM(lp)};
        HWND hover=WindowFromPoint(pt);
        if(hover!=hwnd&&!IsChild(hwnd,hover))
            return CallWindowProcA(g_origProc,hwnd,msg,wp,lp);

        // Convertir ensuite en client pour test hitbox panneau.
        ScreenToClient(hwnd,&pt);
        if(pt.x>=g_panelX&&pt.x<g_panelX+g_panelW&&pt.y>=g_panelY&&pt.y<g_panelY+g_panelH)
        {   int delta=GET_WHEEL_DELTA_WPARAM(wp);
            if(delta>0&&g_scrollOffset>0) --g_scrollOffset;
            else if(delta<0) ++g_scrollOffset;
            return 0;
        }
    }
    return CallWindowProcA(g_origProc,hwnd,msg,wp,lp);
}
static BOOL CALLBACK FindGameWnd(HWND hwnd,LPARAM){
    DWORD pid; GetWindowThreadProcessId(hwnd,&pid);
    if(pid!=GetCurrentProcessId()||!IsWindowVisible(hwnd))return TRUE;
    RECT r; GetClientRect(hwnd,&r);
    if(r.right>400&&r.bottom>300){g_hWnd=hwnd;return FALSE;}
    return TRUE;
}

// ============================================================
// Dechargement
// ============================================================
// g_hMod declare en avant de fichier
static volatile LONG g_unloading = 0;

static void DoCleanup()
{
    Log("DoCleanup");
    if(g_origProc&&g_hWnd) SetWindowLongPtrA(g_hWnd,GWLP_WNDPROC,(LONG_PTR)g_origProc);
    ReleaseFonts();
    RemoveNetworkHook();
    DetourD3DRemove(g_detourES);
    DetourD3DRemove(g_detourReset);
    LogClose();
}
static DWORD WINAPI UnloadThread(LPVOID)
{
    if(InterlockedCompareExchange(&g_unloading,1,0)!=0)return 0;
    HANDLE hEv=OpenEventA(EVENT_MODIFY_STATE,FALSE,"Local\\DPSCounterExit");
    if(hEv){SetEvent(hEv);CloseHandle(hEv);}
    DoCleanup(); Sleep(80);
    FreeLibraryAndExitThread(g_hMod,0); return 0;
}
static DWORD WINAPI KillWatcher(LPVOID)
{
    HANDLE hEv=nullptr;
    for(int i=0;i<100&&!hEv;++i){hEv=OpenEventA(SYNCHRONIZE,FALSE,"Local\\DPSCounterExit");if(!hEv)Sleep(100);}
    if(!hEv)return 1;
    WaitForSingleObject(hEv,INFINITE); CloseHandle(hEv);
    CloseHandle(CreateThread(nullptr,0,UnloadThread,nullptr,0,nullptr)); return 0;
}

// ============================================================
// HookThread
// ============================================================
static DWORD WINAPI HookThread(LPVOID)
{
    Sleep(800);
    LogInit();
    Log("HookThread demarre");
    LoadPanelPos();

    EnumWindows(FindGameWnd,0);
    if(g_hWnd) g_origProc=(WNDPROC)SetWindowLongPtrA(g_hWnd,GWLP_WNDPROC,(LONG_PTR)CustomWndProc);
    Log("WndProc: %s (hWnd=%p)", g_origProc?"OK":"FAIL", g_hWnd);

    if(!InstallNetworkHook())
        Log("AVERTISSEMENT: hook reseau non installe");

    HMODULE hD3D=GetModuleHandleA("d3d9.dll");
    if(!hD3D){Log("d3d9.dll absent");return 1;}
    typedef IDirect3D9*(WINAPI* pfn9)(UINT);
    pfn9 fn=(pfn9)GetProcAddress(hD3D,"Direct3DCreate9");
    if(!fn){Log("Direct3DCreate9 absent");return 1;}

    for(int attempt=0;attempt<15;++attempt)
    {
        if(attempt>0)Sleep(2000);
        HWND hw=CreateWindowExA(0,"STATIC","D3DTmp",WS_POPUP,0,0,1,1,nullptr,nullptr,nullptr,nullptr);
        if(!hw)continue;
        IDirect3D9* pD3D=fn(D3D_SDK_VERSION);
        if(!pD3D){DestroyWindow(hw);continue;}
        D3DPRESENT_PARAMETERS pp={};
        pp.Windowed=TRUE;pp.SwapEffect=D3DSWAPEFFECT_DISCARD;
        pp.BackBufferFormat=D3DFMT_UNKNOWN;pp.hDeviceWindow=hw;
        IDirect3DDevice9* pTmp=nullptr;
        HRESULT hr=pD3D->CreateDevice(D3DADAPTER_DEFAULT,D3DDEVTYPE_HAL,hw,
            D3DCREATE_SOFTWARE_VERTEXPROCESSING,&pp,&pTmp);
        if(FAILED(hr)){pD3D->Release();DestroyWindow(hw);continue;}
        void** vt=*reinterpret_cast<void***>(pTmp);
        void* fnES=vt[VTIDX_ENDSCENE]; void* fnRst=vt[VTIDX_RESET];
        pTmp->Release();pD3D->Release();DestroyWindow(hw);
        bool ok=true;
        if(DetourD3DInstall(g_detourES,fnES,(void*)HookedEndScene)) g_trampolineES=(fn_EndScene)g_detourES.pTrampoline;
        else ok=false;
        if(DetourD3DInstall(g_detourReset,fnRst,(void*)HookedReset)) g_trampolineReset=(fn_Reset)g_detourReset.pTrampoline;
        else ok=false;
        if(ok){Log("D3D9 hooks OK (ES=%p RST=%p)",fnES,fnRst);return 0;}
    }
    Log("D3D9 hook FAIL apres 15 tentatives");
    return 1;
}

// ============================================================
// DllMain
// ============================================================
BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID)
{
    switch(reason)
    {
    case DLL_PROCESS_ATTACH:
        g_hMod=hMod;
        DisableThreadLibraryCalls(hMod);
        StreamCS_Init();
        EntCS_Init();
        StatsCS_Init();
        NameScanCS_Init();
        memset(g_entities,0,sizeof(g_entities));
        memset(g_combat,  0,sizeof(g_combat));
        // Detecter le type de client en priorisant les signatures reseau.
        // Fallback taille: historique (<9 MB = V7, ~9.9 MB = ancien, >=12 MB = 6.3 observe).
        {
            HMODULE hSFr = GetModuleHandleA("SFrame.exe");
            if (hSFr) {
                MODULEINFO mi = {};
                GetModuleInformation(GetCurrentProcess(), hSFr, &mi, sizeof(mi));
                const bool hasOld = (ScanPattern(NET_HOOK_PATTERN, sizeof(NET_HOOK_PATTERN)) != nullptr);
                const bool hasV7  = (ScanPattern(NET_HOOK_PATTERN_V7, sizeof(NET_HOOK_PATTERN_V7)) != nullptr);
                const bool has63  = (ScanPattern(NET_HOOK_PATTERN_63, sizeof(NET_HOOK_PATTERN_63)) != nullptr);
                const bool hasRC  = (ScanPattern(NET_HOOK_PATTERN_RC, sizeof(NET_HOOK_PATTERN_RC)) != nullptr);

                // hasOld → 17 elementaux, layout standard
                // hasV7/has63/hasRC → 7 elementaux (RappelzClassic ~10.1 MB aussi en 7 elem)
                if (hasOld) g_clientV7 = false;
                else if (hasV7 || has63 || hasRC) g_clientV7 = true;
                else g_clientV7 = (mi.SizeOfImage < 9000000u) || (mi.SizeOfImage >= 12000000u);

                // Format 12.6 MB+ ET RappelzClassic (~10.1 MB) : skill_id 3 bytes, skill_level supprime
                g_clientShiftedSkill = has63 || hasRC || (mi.SizeOfImage >= 12000000u);

                Log("Client detect: size=%lu old=%d v7=%d v63=%d rc=%d => g_clientV7=%d shiftedSkill=%d",
                    (unsigned long)mi.SizeOfImage,
                    hasOld ? 1 : 0,
                    hasV7 ? 1 : 0,
                    has63 ? 1 : 0,
                    hasRC ? 1 : 0,
                    g_clientV7 ? 1 : 0,
                    g_clientShiftedSkill ? 1 : 0);
            }
        }
        ReadLocalPlayerFromMemory(); // lit le nom local depuis la memoire statique de SFrame.exe
        // Lance le scan heap en background pour trouver le handle local (si le RVA statique echoue)
        CloseHandle(CreateThread(nullptr,0,ScanLocalHandleThread,nullptr,0,nullptr));
        CloseHandle(CreateThread(nullptr,0,HookThread, nullptr,0,nullptr));
        CloseHandle(CreateThread(nullptr,0,KillWatcher,nullptr,0,nullptr));
        break;
    case DLL_PROCESS_DETACH:
        DoCleanup();
        // Signaler le launcher pour qu'il se termine proprement quand le jeu ferme
        {
            HANDLE hEv = OpenEventA(EVENT_MODIFY_STATE, FALSE, "Local\\DPSCounterExit");
            if (hEv) { SetEvent(hEv); CloseHandle(hEv); }
        }
        break;
    }
    return TRUE;
}
