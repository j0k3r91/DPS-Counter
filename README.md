# DPS Counter

Overlay DPS/Heal/Tank en temps réel pour **SFrame.exe** (Rappelz / V7).  
Injecte une DLL dans le process client, capture les paquets réseau après déchiffrement, et affiche un panel DirectX superposé au jeu.

---

## Fonctionnalités

- **Trois onglets** : DPS/s · Heal/s · Tank/s (dégâts reçus)
- **Chrono temps réel** : le timer défile en continu, s'arrête exactement au dernier coup (sans délai de timeout)
- **Pet / Invocations** : les dégâts des familiers sont attribués à leur propriétaire (ligne indentée)
- **Colonne Total** : dégâts cumulés par combattant
- **Colonne %** : part de chaque joueur dans le groupe
- **Top DPS/s** affiché dans l'en-tête
- **Barre de progression** par joueur (proportionnelle au top)
- **Glissable** à la souris
- **Double-clic** → reset manuel
- **Ctrl+Clic** → changement d'onglet
- Fonctionne sur **client V7** (~8.5 MB) et **ancien client 17-elem** (~9.5 MB)

---

## Architecture

```
DPSCounter.exe  (launcher)
    │
    └── injecte dpscounter.dll dans SFrame.exe
                │
                ├── Hook JMP (E9) à RVA 0x47CB90 (post-cipher, pré-dispatch)
                │   ↓ post-déchiffrement, avant OnReceive
                ├── Décodage des opcodes réseau :
                │     3   SC_ENTER       (création entité)
                │     9   SC_LEAVE       (suppression entité)
                │   101   SC_ATTACK_EVENT
                │   301   SC_ADD_SUMMON_INFO
                │   351   SC_ADD_PET_INFO
                │   401   SC_SKILL       (dégâts / soins détaillés)
                │   406   SC_STATE_RESULT (DoT ticks)
                │  1000   stat update    → détection joueur local
                └── Overlay DirectX 9 (IDirect3DDevice9::Present hooké via vftable)
```

---

## Compatibilité

| Cible | Client | SizeOfImage | Status |
|---|---|---|---|
| Rappelz V7 (nouveau) | `Sframe.exe` | < 9 000 000 | ✅ Testé |
| Rappelz (ancien 17-elem) | `SFrame.exe` | ≥ 9 000 000 | ✅ Supporté |

---

## Prérequis build

| Outil | Version requise |
|---|---|
| Visual Studio / Build Tools | 2017, 2019 ou **2022** (MSVC x86) |
| CMake | ≥ 3.15 |
| DirectX SDK | June 2010 |

La variable d'environnement `DXSDK_DIR` doit pointer vers le dossier racine du DirectX SDK.

---

## Build

**Option 1 — Script automatique** (détecte MSVC et DXSDK) :

```bat
build.bat
```

**Option 2 — Depuis le dossier build_x86** (environnement MSVC déjà configuré) :

```bat
cd build_x86
do_build.bat
```

**Option 3 — CMake manuel** :

```bat
mkdir build_x86
cd build_x86
cmake -A Win32 -DDXSDK_DIR="C:\DXSDK" ..
cmake --build . --config Release
```

Sorties :
- `build_x86/dpscounter.dll` — DLL injectée
- `build_x86/DPSCounter.exe` — Launcher

---

## Utilisation

**1.** Lancer Rappelz (`SFrame.exe` ou `Sframe.exe`) et entrer dans le jeu.

**2.** Lancer `DPSCounter.exe` — la DLL s'injecte automatiquement.

**3.** L'overlay apparaît en haut à gauche.

| Geste | Action |
|---|---|
| Clic + glisser | Déplacer le panel |
| Double-clic | Reset du combat |
| Ctrl + Clic gauche | Onglet suivant (DPS → Heal → Tank) |
| Fermer le launcher | Décharge la DLL |

---

## Fichiers du projet

```
DPS Counter/
├── src/
│   ├── dpscounter_dll.cpp   — DLL principale (hook + parsing + overlay)
│   └── dpscounter_main.cpp  — Launcher (injection via CreateRemoteThread)
├── cmake/
│   └── dll_to_header.cmake  — Convertit la DLL en tableau C embarqué
├── CMakeLists.txt
├── build.bat                — Script de build tout-en-un
└── build_x86/               — Dossier de build généré par CMake
    ├── dpscounter.dll
    └── DPSCounter.exe
```

---

## Logs

La DLL crée `dpscounter.log` dans son dossier d'injection.  
Utile pour diagnostiquer les noms de joueurs manquants, les opcodes non reconnus, etc.

---

## Notes techniques

- **Hook type JMP E9** (pas CALL) — évite d'altérer la pile avant `OnReceive`
- **CRT statique `/MT`** — aucune dépendance sur `msvcrt.dll` externe
- **`/GS-`** — buffer security checks désactivés (zones critique pour les hooks inline)
- **Handle V7** : `0x8xxxxxxx` = joueur · `0xCxxxxxxx` = pet/invocation
- **Timeout combat** : 8 secondes sans coup → combat terminé (`[FIN]`)

---

## Licence

Usage privé — code source non distribué publiquement.
