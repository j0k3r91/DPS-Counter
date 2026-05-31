# DPS Counter — Bug nom joueur V7 (reprise)

## Repo
- Source : `src/dpscounter_dll.cpp`
- Git remote : https://github.com/j0k3r91/DPS-Counter.git
- Dernier commit : `fd2f64f`

## Symptôme
- Overlay affiche `#2147485193` pendant ~5s, puis "Erzate" (ancien perso) au lieu de "GodSlayers" (perso actuel)
- Client V7 (`g_clientV7 = true` quand `SizeOfImage < 9 000 000`)

## Cause racine identifiée
Sur V7 il n'y a pas d'opcode 1000 (TM_SC_RESULT). `g_localHandle` restait à 0 → scan jamais lancé → `#handle`.

`g_localHandle` est maintenant détecté depuis `ParseAttackEvent` / `ParseSkill` (premier paquet `0x8xxxxxxx`) — fix `6efe325`.

Le scan V7 cherche le nom à `handle+4` (offset confirmé CE). Mais "Erzate" apparaît ENCORE à handle+4 → scan retourne le mauvais nom.

## Hypothèses restantes
1. La struct de GodSlayers est dans une région `MEM_MAPPED` (pas `MEM_PRIVATE`) → scan la rate
2. L'offset exact n'est pas +4 sur V7
3. Handles de deux persos partagent des octets → faux match

## Historique commits
| Commit | Description |
|--------|-------------|
| `102f31b` | v1.1.0 — 5 features |
| `59925df` | CharacterChange detection in ParseEnter |
| `103304f` | LEAVE handler reset localHandle |
| `cb9d2de` | g_localNameFromPacket flag |
| `fb3a371` | Disable ScanNameByHandle on V7 |
| `25f76fe` | Early return V7 in ScanNameByHandleThread |
| `0ff7048` | V7 tight-window scan handle+4 (mais scan jamais lancé) |
| `6efe325` | Detect g_localHandle from ParseAttack/ParseSkill on V7 |
| `fd2f64f` | Strict +4 only + log all cands |

## Etat actuel du code
- `ScanNameByHandleThread` (~line 610) : `tightScan = g_clientV7`, cherche nom à offset **strictement +4**, MEM_PRIVATE uniquement
- Log TOUS les candidats avec leur count
- `GetEntityName` (~line 399) : cherche `EntityInfo.name` d'abord, puis `g_localNameCache` si `g_localNameFromPacket`

## Prochaine étape
Tester `fd2f64f` en jeu — attaquer quelque chose — puis partager `%TEMP%\dpscounter.log` (section `ScanNameByHandle`).

Cas possibles :
- `nCands=0` → GodSlayers pas en MEM_PRIVATE → essayer MEM_MAPPED aussi
- "Erzate" gagne → comparer les handles (collision de bytes ?)
- "GodSlayers" gagne → bug ailleurs (GetEntityName ou DrawDPSPanel)
