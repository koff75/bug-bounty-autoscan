# Outil automatisé de reconnaissance & scan de vulnérabilités en Bash

**Attention :** Cet ensemble de scripts a été développé à des fins de tests de sécurité et de bug bounty dans un cadre légal et contrôlé. **Utilisez ces outils uniquement sur des cibles pour lesquelles vous disposez d’une autorisation explicite.**

## Table des matières

- [Introduction](#introduction)
- [Fonctionnalités](#fonctionnalités)
- [Structure du dépôt](#structure-du-dépôt)
- [Installation & Dépendances](#installation--dépendances)
- [Utilisation](#utilisation)
  - [Lancement de l’outil principal](#lancement-de-loutil-principal)
  - [Menu interactif](#menu-interactif)
  - [Scan WordPress](#scan-wordpress)
- [Fonctionnalités détaillées](#fonctionnalités-détaillées)
  - [core_scan.sh](#corescansh)
  - [Bash_menu.sh](#bash_menush)
  - [bash_draw.sh](#bash_drawsh)
  - [wordpress.sh](#wordpresssh)
- [Contribuer](#contribuer)
- [Avertissement légal](#avertissement-légal)
- [Licence](#licence)

---

## Introduction

Ce dépôt regroupe une suite d’outils écrits en bash visant à automatiser les phases de reconnaissance et de tests de vulnérabilités lors d’un audit de sécurité. Les scripts couvrent de nombreux aspects du pentest web, allant de l’énumération de sous-domaines et la découverte de contenu à l’analyse de paramètres et au scan de vulnérabilités (XSS, SQLi, SSRF, etc.). L’ensemble s’appuie sur des outils externes (Recon-ng, Amass, Sublist3r, Waybackurls, ffuf, nuclei, sqlmap, etc.) pour enrichir les analyses.

---

## Fonctionnalités

- **Reconnaissance & Énumération :**  
  - Utilisation de Recon-ng, Amass, Sublist3r et Waybackurls pour collecter des sous-domaines et des URL en vue d’une analyse.
  - Conversion d’URL en adresses IP, vérification de l’accessibilité et détection de domaines vulnérables.
  
- **Content Discovery & Fuzzing :**  
  - Lancement de fuzzing avec ffuf sur des répertoires et sous-domaines en s’appuyant sur des dictionnaires téléchargeables (ex. AssetNote, SecLists).
  
- **Analyse de paramètres :**  
  - Exécution de ParamSpider, GF, Arjun et JSScanner pour extraire et tester les paramètres des URL.
  - Lancement de tests automatisés avec sqlmap pour détecter d’éventuelles injections SQL.
  
- **Scan de vulnérabilités :**  
  - Lancement de scans Nuclei (simple et complet) avec filtrage par sévérité.
  - Tests via Dalfox, Gitleaks/Trufflehog pour détecter des failles XSS, fuites de secrets, takeover de domaines, etc.
  
- **Scan de ports & Détection de CVE :**  
  - Intégration de RustScan, Nmap et outils de reporting pour la découverte des ports ouverts et la recherche de vulnérabilités connues (CVEs).
  
- **Interface interactive :**  
  - Un menu en mode texte permet de sélectionner facilement les actions à exécuter.
  
- **Scan WordPress dédié :**  
  - Un script dédié permettant d’identifier et de vérifier les pages critiques et configurations de sites WordPress.

---

## Structure du dépôt

```
.
├── core_scan.sh         # Script principal regroupant les fonctions de reconnaissance, fuzzing et scan vulnérabilités
├── Bash_menu.sh         # Système de menu interactif (navigation avec les touches fléchées et entrée)
├── bash_draw.sh         # Fonctions utilitaires pour l’affichage coloré et le dessin dans le terminal (utilisé par le menu)
└── wordpress.sh         # Script de scan dédié aux sites WordPress (vérification de robots.txt, pages sensibles, version, utilisateurs, etc.)
```

---

## Installation & Dépendances

### Prérequis

Pour faire fonctionner ces scripts, vous devez disposer de bash (version 4+ de préférence) et installer les outils suivants :

- **Outils systèmes et utilitaires :**
  - `curl`, `wget`, `jq`, `git`
- **Reconnaissance et énumération :**
  - Recon-ng
  - Amass
  - Sublist3r
  - Waybackurls
- **Fuzzing et content discovery :**
  - ffuf
  - Dictionnaires issus d’AssetNote ou SecLists (vous pouvez configurer les liens de téléchargement dans le script)
- **Analyse de paramètres & vulnérabilités :**
  - ParamSpider (Python)
  - GF, Arjun, JSScanner
  - sqlmap
- **Scan de vulnérabilités :**
  - nuclei
  - dalfox
- **Scan de ports :**
  - RustScan, Nmap
- **Divers :**
  - gitleaks, trufflehog
  - outils spécifiques pour takeover de domaines, etc.

### Installation

1. **Cloner le dépôt :**

2. **Installer les dépendances via votre gestionnaire de paquets ou en suivant les documentations officielles :**

   Par exemple, sous Debian/Ubuntu :
   ```bash
   sudo apt update
   sudo apt install curl wget jq git nmap python3-pip
   # Installer d’autres outils (Amass, ffuf, nuclei, sqlmap, etc.) selon les instructions de leurs repos respectifs.
   ```

3. **Configurer les outils externes :**

   Assurez-vous que chaque outil externe (Recon-ng, Amass, etc.) est accessible via le PATH et fonctionne correctement. Certains scripts appellent directement des commandes comme `amass enum`, `sublist3r`, etc.

---

## Utilisation

### Lancement de l’outil principal

Pour démarrer le **core_scan.sh** qui regroupe toutes les fonctions de reconnaissance et de scan, exécutez :

```bash
bash core_scan.sh
```

Selon la configuration et les fonctions activées, le script pourra lancer tour à tour :

- La vérification des dépendances (fonction `Check-dependencies`)
- L’énumération (via Recon-ng, Amass, Sublist3r, Waybackurls)
- Le content discovery et fuzzing (fonction `Content-discovery`)
- L’analyse de paramètres (fonction `Params_analysis`)
- Les scans de vulnérabilités (nuclei, sqlmap, Dalfox, etc.)
- La recherche de fuites de secrets

Certains tests nécessitent une interaction (confirmation ou appui sur une touche pour continuer).

### Menu interactif

Le fichier **Bash_menu.sh** propose une interface textuelle interactive. Lancez-le par :

```bash
bash Bash_menu.sh
```

Le menu utilise les fonctions de **bash_draw.sh** pour afficher un cadre coloré et permet la navigation avec :

- **Flèche haut / Flèche bas :** pour sélectionner l’option
- **Touche entrée :** pour lancer l’action associée

Les actions du menu sont définies via un tableau de fonctions (`menuActions`) qui peuvent appeler par exemple des fonctions de `core_scan.sh`.

### Scan WordPress

Le script **wordpress.sh** est conçu pour analyser une cible WordPress.  
Avant de le lancer, modifiez la variable `url` (définie au début du script) pour pointer vers le site à analyser.  
Ensuite, lancez :

```bash
bash wordpress.sh
```

Le script :

- Vérifie la présence d’un fichier `robots.txt` pour tenter de localiser le répertoire WordPress.
- Teste l’existence de fichiers sensibles et de pages critiques (ex. `wp-config.php`, `wp-login.php`, etc.).
- Extrait des informations telles que la version de WordPress, PHP, le serveur, la liste des utilisateurs via l’API REST, et d’autres métadonnées.
- Rassemble les informations dans un fichier JSON (`output_wordpress.json`).

---

## Fonctionnalités détaillées

### core_scan.sh

Ce script est le cœur de la suite de scan. Il définit de nombreuses fonctions :

- **SendDiscord :** Envoi des notifications (par exemple vers Discord) lors de l’exécution des actions.
- **progress-bar :** Affichage d’une barre de progression.
- **Check-dependencies :** Vérifie que les outils requis sont installés et, le cas échéant, les installe ou avertit l’utilisateur.
- **Recon-ng :** Génère un fichier de commandes pour Recon-ng afin d’énumérer des sous-domaines via divers modules.
- **Fuzzing :** Lance ffuf avec des dictionnaires adaptés (téléchargement automatique si nécessaire).
- **Content-discovery :** Utilise webanalyze pour détecter la technologie d’un site et adapte les dictionnaires pour lancer des fuzzings spécifiques (API, Wordpress, répertoires, etc.).
- **Enumeration :** Regroupe l’énumération via Recon-ng, Amass, Sublist3r, Waybackurls, Waymore et xnLinkFinder, puis procède à la conversion des URL en IP et à la validation.
- **Params_analysis :** Lance ParamSpider, GF, Arjun, JSScanner et sqlmap pour analyser les paramètres et détecter des vulnérabilités (XSS, SQLi, IDOR, etc.).
- **Vuln_web_analysis & Vuln_web_analysis_one_liner :** Fonctions pour lancer Dalfox, sqlmap et d’autres outils de scan de vulnérabilités en one-liner.
- **Port-scanning :** Utilise RustScan et Nmap (via l’outil das) pour détecter les ports ouverts et réaliser des scans de versions.
- **Finding_CVES :** Recherche des CVEs à partir des rapports Nmap et lance nuclei pour détecter des vulnérabilités connues.
- **Nuclei_simple_scan & Nuclei_full_scan :** Lance nuclei en mode simple (scan des CVEs) ou complet (possibilité d’utiliser proxychains / Tor).
- **GitLeaks_Trufflehog :** Lance les outils Gitleaks et Trufflehog pour détecter des fuites de secrets dans des dépôts Git.
- **XSS_detection, High_known_CVES, Check_SQL, Check_secrets_quick, Check_secrets_full :** Fonctions complémentaires pour détecter divers types de vulnérabilités (XSS, SSRF, LFI, RCE, exfiltration de secrets, etc.).

Chaque fonction effectue des traitements en chaîne et enregistre les résultats dans des fichiers (par exemple dans des dossiers `subdomains/`, `vuln/`, `params/` ou `secret/`).

### Bash_menu.sh

Ce script gère l’interface de menu interactif :

- Définit des variables globales pour positionner et colorer le menu.
- Utilise les fonctions issues de **bash_draw.sh** pour afficher les bordures, l’en-tête, le pied de page et les items.
- La fonction `menuLoop` attend la saisie de l’utilisateur et, en fonction des touches (flèches haut/bas ou touche entrée), exécute la fonction associée à l’item sélectionné.
- Par défaut, le dernier item est « Exit », qui quitte le menu.

### bash_draw.sh

Fournit un ensemble de fonctions pour dessiner sur le terminal :

- **drawClear :** Efface l’écran.
- **drawColour :** Définit la couleur du texte et du fond.
- **drawPlain / drawSpecial / drawHighlight :** Affichent du texte en mode normal ou avec mise en évidence.
- **drawPlainAt / drawHighlightAt :** Permettent d’afficher du texte à des coordonnées précises dans le terminal.
- Contient également la définition des codes de couleur (par exemple, DRAW_COL_RED, DRAW_COL_GREEN, etc.).

Ces fonctions sont utilisées par le menu pour créer une interface utilisateur conviviale.

### wordpress.sh

Ce script se concentre sur l’analyse de sites WordPress :

- Il commence par vérifier la présence d’un fichier `robots.txt` pour tenter d’identifier un répertoire personnalisé pour WordPress.
- Il effectue ensuite des tests sur des pages et fichiers critiques (ex. `wp-config.php`, `wp-admin/login.php`, etc.) afin d’identifier d’éventuelles failles (fichiers accessibles alors qu’ils ne devraient pas l’être).
- Le script extrait des informations telles que la version de WordPress, la version de PHP, le type de serveur, et tente d’extraire la liste des utilisateurs via l’API REST.
- Les résultats sont agrégés dans un fichier JSON (`output_wordpress.json`) et des messages d’information sont affichés au fur et à mesure.

---

## Contribuer

Si vous souhaitez contribuer à ce projet :

1. **Forkez** le dépôt.
2. **Créez** une branche pour vos modifications (`git checkout -b feature/ma-nouvelle-fonction`).
3. **Validez** vos changements (`git commit -m "Ajout de ma nouvelle fonction"`).
4. **Poussez** votre branche (`git push origin feature/ma-nouvelle-fonction`).
5. Ouvrez une **pull request** pour que vos modifications soient examinées.

Merci de respecter le [Code de Conduite](CONTRIBUTING.md) du projet.

---

## Avertissement légal

Ces outils ont été conçus pour être utilisés dans un cadre légal et contrôlé. L’utilisation non autorisée sur des systèmes tiers est strictement interdite et peut entraîner des poursuites judiciaires. Assurez-vous de disposer des autorisations nécessaires avant de réaliser tout test de sécurité.


---

Vous pouvez maintenant cloner ce dépôt, installer les dépendances et commencer vos tests de reconnaissance et de scan de vulnérabilités. N’hésitez pas à adapter ou étendre ces scripts selon vos besoins !

---
