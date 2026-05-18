# Analyse Forensique Mobile — MVT & Surface d'Attaque

> Audit de sécurité de smartphones Android avec le **Mobile Verification Toolkit (MVT)** d'Amnesty International, incluant la détection d'indicateurs de compromission (IoC) et la cartographie des surfaces d'attaque.

**Auteur :** Senghor VLAVONOU  
**Date :** 17 avril 2026

---

## Table des matières

- [Objectif](#objectif)
- [Appareils analysés](#appareils-analysés)
- [Environnement & outils](#environnement--outils)
- [Méthodologie](#méthodologie)
- [Résultats des scans MVT](#résultats-des-scans-mvt)
- [Cartographie de la surface d'attaque](#cartographie-de-la-surface-dattaque)
- [Fichiers générés](#fichiers-générés)
- [Conclusion](#conclusion)

---

## Objectif

Ce projet réalise une **analyse forensique de trois smartphones Android** afin de :

- Détecter des **indicateurs de compromission (IoC)** à l'aide de MVT
- Identifier les **permissions applicatives critiques ou abusives**
- Cartographier les **vecteurs de persistance** potentiels d'un spyware
- Évaluer la **surface d'attaque globale** de chaque terminal

---

## Appareils analysés

| Appareil | SoC | Packages scannés | Fichiers indexés |
|---|---|---|---|
| Infinix Note 12i | MediaTek Helio G85 | 303 | 247 912 |
| Redmi 13C | MediaTek | 454 | 589 252 |
| Samsung Galaxy S9 | Qualcomm Snapdragon 845 | 470 | 349 849 |

---

## Environnement & outils

| Outil | Rôle |
|---|---|
| **MVT (Mobile Verification Toolkit)** v2.7.0 | Extraction et analyse forensique |
| **ADB (Android Debug Bridge)** | Communication avec les terminaux Android |
| **pipx** | Gestion isolée des dépendances Python |
| **Bases IoC STIX2** (Amnesty International) | Référentiel de menaces connues (Pegasus, Predator, etc.) |

### Installation rapide

```bash
# 1. Installer pipx
sudo apt install pipx

# 2. Installer MVT
pipx install mvt

# 3. Télécharger les IoCs
mvt-android download-iocs

# 4. Installer ADB
sudo apt install android-tools-adb

# 5. Lancer le scan sur un appareil connecté
mvt-android check-adb --iocs ~/.local/share/mvt/iocs/ --output ./output/
```

---

## Méthodologie

L'analyse suit le pipeline suivant :

```
Connexion ADB
     │
     ▼
Extraction MVT (check-adb)
     │
     ├── Module Packages   → inventaire des applications
     ├── Module Logcat     → journaux système
     ├── Module RootBinaries → détection de binaires root
     └── Module Files      → analyse du système de fichiers
          │
          ▼
     Comparaison avec les bases IoC STIX2
          │
          ▼
     Génération des fichiers JSON de résultats
```

---

## Résultats des scans MVT

### Infinix Note 12i

Aucun IoC détecté. Les **warnings générés** portent sur des fichiers SUID dans `/proc/sparta/` et `/proc/tran_gc_debug/` — il s'agit de **faux positifs** liés aux drivers propriétaires MediaTek (sous-système SPARTA de gestion NAND/eMMC), non de menaces réelles.

### Redmi 13C

Aucune détection. Scan sans anomalie sur les quatre modules (Packages, Logcat, RootBinaries, Files). L'appareil ne présente aucune trace de spyware référencé dans la base MVT.

### Samsung Galaxy S9

Aucun IoC relevé. On note la présence d'applications tierces légitimes (Snapchat, Instagram Lite, Xender, VPN Lat) ainsi qu'une entrée Knox datée du 31/12/2008, probablement un artefact de date système.

---

## Cartographie de la surface d'attaque

### Infinix Note 12i

**Permissions critiques identifiées :**
- WhatsApp & WhatsApp Business : accès simultané au microphone, à la caméra, aux contacts, au stockage externe et aux comptes utilisateur
- Gozem & Yango : géolocalisation précise en continu, y compris hors sessions actives
- `CHANGE_WIFI_STATE` accordée à 6 applications (WhatsApp, Boomplay, Yango, Facebook Lite, Xender) — permet de rejoindre un réseau Wi-Fi arbitraire
- 20/23 applications détiennent `WAKE_LOCK` (activité réseau permanente en arrière-plan)

**Vecteurs de persistance potentiels :**

| Composant | Risque |
|---|---|
| `init` (PID 1) | Modification de `init.rc` → relance automatique au reboot |
| `watchdogd` | Détournable pour relancer un composant malveillant stoppé |
| `jbd2/mmcblk0p8` | Persistance des modifications au-delà des redémarrages |
| `kverityd` | Neutralisation des mécanismes de vérification d'intégrité |
| Threads kernel (`kthreadd`, `ksoftirqd`, `kswapd0`) | Camouflage efficace par nature permanente et discrète |

---

### Redmi 13C *(surface d'attaque la plus large)*

**Permissions critiques identifiées :**
- 8 applications accèdent au microphone (Snapchat, WhatsApp, Teams, Instagram, Facebook Lite, Shazam…)
- WhatsApp cumule 5 permissions critiques simultanées : `READ_PHONE_STATE`, `ACCESS_FINE_LOCATION`, `READ_CONTACTS`, `GET_ACCOUNTS`, `CHANGE_WIFI_STATE`
- Instagram détient `READ_CALL_LOG` — sans justification fonctionnelle
- `CHANGE_WIFI_STATE` accordée à **28 applications** (Binance, DeepSeek, AppBlock…)
- 70 applications autorisées à démarrer au boot (`RECEIVE_BOOT_COMPLETED`)
- 4 applications installées en dehors du Play Store (sideload)

**Vecteurs de persistance potentiels :**

| Composant | Risque |
|---|---|
| `com.miui.daemon` | Droits system + redémarrage automatique → cible idéale pour firmware spyware |
| `com.miui.securitycenter.remote` | Consommation RAM anormale (228 Mo), accès aux permissions et processus |
| `ueventd` | Contrôle des permissions `/dev` → accès caché micro/caméra/stockage |
| `kworker/R-netns`, `kworker/R-ipv6_` | Maintien de communications C2 et exfiltration réseau |
| `kauditd` | Détournement → aveugler la journalisation système |

---

### Samsung Galaxy S9

**Permissions critiques identifiées :**
- Accès microphone : WhatsApp, WhatsApp Business, Snapchat, Shazam
- Accès caméra : WhatsApp, WhatsApp Business, Xender, Snapchat
- `READ_PHONE_STATE` (accès à l'IMEI) : Facebook, Snapchat
- Duolingo détient `READ_CONTACTS` — sans justification fonctionnelle
- Facebook détient `SYSTEM_ALERT_WINDOW` → risque d'overlay attack (phishing par superposition d'interface)
- Xender détient `DELETE_PACKAGES` → désinstallation silencieuse d'applications
- 33 applications avec `RECEIVE_BOOT_COMPLETED`

**Vecteurs de persistance potentiels :**

| Composant | Risque |
|---|---|
| `init` (PID 1) | Vecteur de persistance ultime |
| Threads `kworker` (multiples) | Camouflage idéal par multiplicité et activité générique |
| `ksoftirqd` | Interception trafic réseau / communication serveur C2 |
| `watchdogd` / `msm_watchdog` | Relance de malware ou neutralisation de la détection |
| Composants GPU `kgsl_*` | Vecteur émergent pour stockage/exécution furtive de code |

---

## Fichiers générés

MVT produit automatiquement les fichiers JSON suivants dans le dossier `output/` :

| Fichier | Contenu |
|---|---|
| `files.json` | Inventaire complet du système de fichiers (chemins, permissions, bits SUID/SGID, tailles) |
| `getprop.json` | Propriétés système Android (`getprop`) : kernel, Bluetooth, JVM Dalvik… |
| `info.json` | Métadonnées de l'analyse : version MVT, date, bases IoC chargées |
| `packages.json` | Applications installées : nom, chemin APK, installeur, statut (système/tierce partie) |
| `processes.json` | Snapshot des processus actifs : PID, PPID, utilisateur, RAM, label SELinux |
| `selinux_status.json` | État SELinux du terminal (mode `enforcing` sur les appareils audités) |
| `settings.json` | Paramètres système exportés depuis `settings.db` |
| `logcat.txt` | Journaux système bruts |
| `sms.json` | Inventaire des SMS (si extraction autorisée) |
| `timeline.csv` | Chronologie des événements système |

---

## Conclusion

L'analyse forensique confirme l'**absence d'IoC connus** sur les trois terminaux au moment de l'audit. Cependant, plusieurs enseignements ressortent :

- ❗ **La surface d'attaque est significative** sur les trois appareils, en particulier le Redmi 13C (101 apps tierces, 70 avec boot automatique)
- ❗ **Les permissions excessives** constituent le risque principal en cas de compromission applicative
- ❗ **Les composants constructeurs** (MIUI, MediaTek, Qualcomm) introduisent des vecteurs de persistance spécifiques difficilement détectables par MVT seul
- ✅ MVT reste pertinent en investigation, mais doit être **complété par une analyse comportementale** et une surveillance en temps réel pour faire face à des menaces inconnues ou évolutives

> La sécurité mobile ne se résume pas à l'absence d'IoC : elle repose sur une gestion rigoureuse des permissions, une surveillance des processus critiques et une compréhension fine de l'architecture système.

---

## Références

- [Mobile Verification Toolkit (MVT)](https://github.com/mvt-project/mvt) — Amnesty International
- [Bases IoC MVT](https://github.com/mvt-project/mvt-indicators)
- [Pegasus Project — Amnesty Tech](https://www.amnesty.org/en/tech/)
- [Android Debug Bridge (ADB)](https://developer.android.com/studio/command-line/adb)
