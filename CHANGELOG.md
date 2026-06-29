# Changelog

Toutes les modifications notables sont documentées ici.  
Format basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/).

---

## [1.1.6-RappelzClassic] — 2026-06-29

### Ajouté
- **Timeout configurable** : réglable de 1s à 120s via le bouton `+` et le mini-panneau (±1s)
- **Redimensionnement responsive** : bord droit (largeur), bord bas (hauteur/lignes), coin (les deux)
- **Polices et lignes proportionnelles** : le contenu scale automatiquement avec la largeur
- **Colonnes en pourcentages** : DPS/s 18%, Total 18%, Grp% 12% — plus de pixels en dur
- **Onglets responsifs** : taille adaptative (~11% de la largeur)
- **Poignées visuelles** de redimensionnement (coin, bord droit, bord bas)
- **Taille initiale adaptative** : ~25% de la largeur écran au premier lancement
- **Sauvegarde INI** : largeur (W), timeout, nombre de lignes (Rows)

### Corrigé
- **Nom du joueur local sur V7** : adresse statique `SFrame.exe + 0x8932BC`
- **Filtre anti-faux-positifs** (`IsValidPlayerName`) : rejette `state_*`, `set_*`, `monster*`, etc.
- **Timeout minimum** abaissé de 3s → 1s
- **Virgule de précision** pour les valeurs >10k (18.2k au lieu de 18k)
- **Hauteur minimale** du panneau (96px) pour toujours pouvoir saisir le bord bas
- **Zone de saisie élargie** : 12px au bord bas, 30x30px dans le coin

---

## [1.0.0] — 2026-05-25

### Ajouté
- **Overlay DirectX 9** affiché en temps réel dans SFrame.exe
- **Trois onglets** : DPS/s, Heal/s, Tank/s (dégâts reçus)
- **Chrono temps réel** qui défile chaque seconde même sans dégâts
- **Détection automatique** du joueur local via opcode 1000
- **Détection pets / invocations** par heuristique handle V7 (`0xCxxxxxxx`),  
  confirmée par `SC_ADD_PET_INFO` / `SC_ADD_SUMMON_INFO`
- **Scan mémoire** du nom du joueur local avec système de vote (64 candidats)
- **Colonnes** : DPS/s · Total · % du groupe · barre de progression
- **Top DPS/s** dans l'en-tête avec timer `M:SS [ACT/FIN]`
- **Glisser-déposer** du panel à la souris
- **Double-clic** pour reset manuel du combat
- **Ctrl+Clic** pour changer d'onglet
- Support **client V7** (7 élémentaux, ~8.5 MB) et **ancien client** (17 élémentaux, ~9.5 MB)
- Launcher `DPSCounter.exe` avec injection via `CreateRemoteThread` + `LoadLibraryA`
- DLL embarquée en tableau C dans l'EXE (pas de fichier externe nécessaire)
- Log `dpscounter.log` en temps réel (partagé en lecture)

### Architecture technique
- Hook **JMP E9** à RVA `0x47CB90` (post-cipher, pré-dispatch) — pile intacte
- Décodage opcodes : 3, 9, 101, 301, 351, 401, 406, 1000
- Handle format V7 : `0x8xxxxxxx` joueur / `0xCxxxxxxx` pet
- Build MSVC x86, CRT statique (`/MT`), DirectX SDK June 2010
- Timeout combat : 8 s sans coup → `[FIN]`

### Corrections
- Nom joueur affiché `#numéro` → scan mémoire + vote avec filtre majuscule
- Parasite `max_stamina` dans le scan → retrait du caractère `_` des noms valides
- Pet affiché comme 2ème joueur → détection immédiate par préfixe handle `0xC`
- Valeur gonflée au 1er coup → reset complet des dégâts au nouveau combat
- DPS/s doublé pendant < 1 s → diviseur minimum `1.0 s`
- DPS/s qui descend à l'arrêt → DPS/s figé sur le dernier coup
- Timer figé entre les coups → `now` utilisé pour le chrono pendant le combat
- Timer incluait 8 s de FIGHT_TIMEOUT → timer s'arrête sur `lastHit`
- Affichage `--` au premier coup → suppression des seuils de durée, `max(1 s, durée)`

---

## [1.1.0] — 2026-05-25

### Ajouté
- **Hook réseau V7** : nouveau pattern `NET_HOOK_PATTERN_V7` (12 octets) hookant  
  `movzx ecx,[edi+04]` (RVA `0x21E5D8`). Callback `V7PacketCallback` appelle  
  `DispatchPacket` directement (pas de réassemblage stream, packet déjà complet dans `edi`).  
  `InstallNetworkHook` tente d'abord l'ancien pattern, puis le pattern V7 si `g_clientV7`.  
  `RemoveNetworkHook` restaure les bytes corrects selon `g_netHook.isV7`.
- **Onglet "Max"** (4ème tab `TAB_MAXHIT`) : affiche le plus grand coup sorti / soin /  
  dégât reçu (valeur brute, sans division par le temps).
- **Persistence position du panneau** : la position est sauvegardée dans `dpscounter.ini`  
  (même dossier que la DLL) après chaque déplacement et rechargée au démarrage.
- **Défilement (scrollbar)** : molette de la souris sur le panneau scrolle la liste quand  
  elle dépasse `MAX_ROWS` entrées. Indicateur visuel (barre bleue côté droit). Offset remis  
  à zéro au reset combat.

### Amélioré
- **Scan heap optimisé** : limite réduite de 512 / 384 MB à **128 MB** sur les deux threads  
  (`ScanLocalHandleThread`, `ScanNameByHandleThread`). Filtre `MEM_PRIVATE` ajouté pour  
  ignorer les sections image/mappées et accélérer le scan.

---

## [1.1.1] — 2026-05-31

### Corrections (détection nom joueur V7)

- **`g_localHandle` depuis paquet** : sur le client V7 l'opcode 1000 (`TM_SC_RESULT`) est absent ;
  `g_localHandle` est maintenant initialisé dès le premier paquet `ATTACK` ou `SKILL` portant
  un handle `0x8xxxxxxx` (`ParseAttackEvent` / `ParseSkill`).
- **Scan V7 offset strict `+4`** : `ScanNameByHandleThread` cherche le nom à l'offset
  **exactement `+4`** (offset confirmé par Cheat Engine) — les offsets adjacents ne sont
  plus testés, éliminant le faux-positif "Erzate".
- **`ScanNameByHandleThread` désactivé sur V7** : sur le client V7 le nom du joueur local
  arrive uniquement par scan direct à `handle+4` ; l'ancien chemin `ScanNameByHandle` est
  court-circuité (early return) pour éviter les faux matches.
- **Protection `g_localNameFromPacket`** : le scan heap ne peut plus écraser un nom
  déjà reçu via paquet réseau (flag `g_localNameFromPacket` vérifié avant écriture).
- **Détection changement de personnage robuste** : réception d'un `LEAVE` correspondant
  au nom actuel remet `g_localHandle` à 0 et force un nouveau scan sur V7 ; test du nom
  ajouté dans `ParseEnter` pour traiter les reconnexions rapides.
- **Candidats loggés** : le scan V7 journalise tous les candidats avec leur score de vote
  dans `dpscounter.log` (section `ScanNameByHandle`) pour faciliter le diagnostic.

---

## [1.1.2] — 2026-06-09

### Corrections

- **Relancement robuste** : si une instance précédente du DPS meter est encore active,
  elle est fermée automatiquement avant nouveau chargement.
- **Stabilité des timers par onglet** : les timers DPS/Heal/Tank sont désormais
  indépendants par onglet, avec reprise/gel cohérents selon l'activité.
- **Molette limitée au panneau** : le scroll du DPS meter ne s'applique plus si le
  curseur n'est pas sur la fenêtre/panneau du compteur, tout en laissant la molette
  fonctionner normalement dans le jeu.

---

## [1.1.3-RappelzClassic] — 2026-06-14

### Ajouté

- **Support client 6.3** : nouveau pattern réseau `NET_HOOK_PATTERN_63` basé sur
  `cmp [ebp],eax ; ja ; movzx ecx,[ebp+4]`, avec stub dédié.

### Amélioré

- **Détection de variante client plus robuste** : priorité aux signatures de hook
  (ancien / V7 / 6.3), puis fallback sur `SizeOfImage`.
- **Launcher** : recherche du process étendue à `sfram.exe` en fallback.

---

## [1.1.4-RappelzClassic] — 2026-06-28

### Ajouté

- **Support client 12.6 MB (v2026)** : adaptation du layout `TS_SC_SKILL` pour les
  clients récents où `skill_id` passe de 4→3 octets et `skill_level` est supprimé
  (shift de -2 octets sur tous les offsets de la structure).
- **Détection handle local universelle** : la détection du joueur local depuis le
  premier paquet d'attaque/skill n'est plus conditionnée à `g_clientV7`, ce qui
  permet de supporter tout client sans RVA statiques valides.

### Technique

- Debug : activation de `DPS_DEBUG` pour les dumps hexa des paquets bruts.
- Correction des offsets dans `DispatchPacket` (debug log `RAWSKILL`) pour le
  nouveau format client.

---

## [1.1.5-RappelzClassic] — 2026-06-28

### Ajouté

- **Support client RappelzClassic (~10.1 MB)** : nouveau pattern réseau
  `NET_HOOK_PATTERN_RC` (12 octets, sans offsets relatifs) hookant le dispatch
  principal à `movzx ecx,[edi+04]`. Pattern unique dans le module, testé en
  première position pour éviter les faux positifs.
- **Détection auto du layout TS_SC_SKILL** : le flag `g_clientShiftedSkill`
  est activé pour les patterns RC et 63 (skill_id 3 octets, sans skill_level).

### Corrections

- **Nombre d'élémentaux** : le client RappelzClassic utilise 7 élémentaux
  (dmgSz=32), comme V7, et non 17. Le calcul `SkillResultSize` était incorrect
  et empêchait le parsing des SR entries (52 > 45 bytes disponibles).
- **Faux positif pattern OLD** : le pattern ancien client matchait dans du heap
  hors module SFrame.exe. Réordonnancement des tentatives : RC d'abord, OLD en
  dernier (fallback).
- **Stub RC JMP return** : correction du retour stub à hookSite+6 (au lieu de +4)
  pour éviter d'exécuter les bytes de l'offset JMP comme code.
- **Détection handle local** : le parsing skill utilisait un mauvais offset caster,
  initialisant `g_localHandle` avec une valeur incorrecte et empêchant la
  détection du joueur local.
