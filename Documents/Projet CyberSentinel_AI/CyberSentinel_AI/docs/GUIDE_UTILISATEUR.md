# Guide Utilisateur et Manuel Opérateur — CyberSentinel AI

> **Application** : CyberSentinel AI Desktop  
> **Version** : 1.0.0 LTS  
> **Système requis** : Windows 10 (21H2+) ou Windows 11 (64-bit)  

---

## 1. Prérequis et Installation

### 1.1 Configuration Minimale Requise
- **Système d'exploitation** : Windows 10 (x64) ou Windows 11 (x64).
- **Processeur** : Architecture x86_64, 2 cœurs minimum (support des instructions AVX recommandé pour les inférences d'IA).
- **Mémoire vive (RAM)** : 4 Go minimum (8 Go recommandés lors de scans volumineux).
- **Espace disque libre** : 500 Mo d'espace disque disponible pour l'application, les modèles d'IA et la base de données SQLite.
- **Composant runtime** : [.NET 10.0 Desktop Runtime (x64)](https://dotnet.microsoft.com/download/dotnet/10.0).
- **Composants optionnels recommandés** :
  - **WinGet** (*Windows Package Manager*, préinstallé sous Windows 11 / App Installer).
  - **ClamAV Windows** (service local `clamd` pour l'analyse antivirale de signatures).

### 1.2 Procédure d'Installation
1. **Téléchargement** : Récupérez l'archive de déploiement `CyberSentinel_AI_v1.0_x64.zip` ou l'exécutable d'installation.
2. **Extraction** : Extrayez le contenu dans un répertoire protégé (ex: `C:\Program Files\CyberSentinel_AI` ou un dossier utilisateur dédié).
3. **Privilèges d'exécution** :
   - L'analyse de fichiers, la consultation de l'inventaire et la lecture des vulnérabilités fonctionnent avec les droits d'un utilisateur standard.
   - La mise en quarantaine de fichiers système protégés et le déploiement de mises à jour applicatives via WinGet nécessitent un lancement avec des privilèges administrateur (**Clic droit > Exécuter en tant qu'administrateur**).

---

## 2. Premier Démarrage

Lors du lancement initial de `CyberSentinel.Desktop.exe` :
1. **Initialisation de la base SQLite** : L'application crée automatiquement la base de données locale sécurisée dans `%LocalAppData%\CyberSentinel\cyber_sentinel.db`.
2. **Vérification d'intégrité des moteurs** :
   - Le moteur YARA interne compile ses règles heuristiques embarquées.
   - Le modèle d'intelligence artificielle EMBER2024 vérifie son empreinte cryptographique SHA-256.
   - La présence de WinGet et du démon ClamAV est détectée.
3. **Tableau de Bord Initial** : L'écran d'accueil affiche l'état global de sécurité de l'ordinateur, les statistiques de scans antérieurs et les alertes prioritaires.

```text
+----------------------------------------------------------------------------------+
|  🛡️ CYBERSENTINEL AI                                           [ _ ] [ 口 ] [ X ] |
+----------------------------------------------------------------------------------+
|  [🏠 Dashboard]          | ÉTAT GLOBAL DE SÉCURITÉ : VULNÉRABLE (3 alertes)     |
|  [🔍 Analyse Fichiers]   | ---------------------------------------------------  |
|  [📦 Inventaire Système] | 📁 Fichiers scannés : 1 240   ⚠️ Menaces actives : 2   |
|  [⚡ Vulnérabilités]     | 🛡️ Vulnérabilités : 5 (2 Critiques)  🔄 Mises à jour : 3 |
|  [🔄 Mises à jour]       | ---------------------------------------------------  |
|  [🔒 Quarantaine]        | Dernier scan complet : Aujourd'hui à 14h30           |
|  [📊 Rapports d'audit]   | [ Lancer une analyse rapide ]  [ Télécharger PDF ]   |
+----------------------------------------------------------------------------------+
```

---

## 3. Analyse de Fichiers et de Dossiers

### 3.1 Analyse d'un Fichier Unitaire
1. Cliquez sur l'onglet **Analyse Fichiers** dans la barre latérale.
2. Cliquez sur le bouton **Parcourir un fichier...** ou glissez-déposez un fichier directement dans la zone d'analyse.
3. Cliquez sur **Lancer l'analyse**.
4. L'application sollicite simultanément :
   - Le moteur de signatures certifiées (ClamAV).
   - Le scanner heuristique de règles (YARA).
   - Le modèle de Machine Learning (EMBER2024 / ONNX).
5. Le résultat s'affiche instantanément : score de risque global ($0.0$ à $1.0$), verdict catégorisé (*Clean*, *Suspicious*, *Malware*) et détail de chaque moteur.

### 3.2 Analyse Récursive d'un Dossier
1. Dans l'onglet **Analyse Fichiers**, sélectionnez **Analyser un dossier...**.
2. Choisissez le répertoire cible (ex: dossier de téléchargements ou répertoire applicatif).
3. L'arborescence est parcourue de manière asynchrone sans bloquer l'interface.
4. Une barre de progression affiche le taux d'avancement et le fichier en cours d'évaluation.
5. Vous pouvez interrompre l'opération à tout moment en cliquant sur **Annuler** (l'arrêt s'effectue proprement en moins de 10 millisecondes).

---

## 4. Consultation des Menaces et Actions de Remédiation

Lorsqu'un exécutable est identifié comme suspect ou malveillant :
1. La ligne correspondante s'affiche en surbrillance rouge (`Critique`) ou orange (`Élevé`).
2. En cliquant sur l'élément, le volet de détails expose :
   - **Empreinte SHA-256** du binaire.
   - **Nom de la menace** détectée par ClamAV.
   - **Règles YARA** déclenchées (ex: détection de pattern d'injection mémoire ou de note de rançongiciel).
   - **Indice de suspicion EMBER** (ex: distribution anormale d'entropie des sections).
3. **Actions disponibles** :
   - **Mettre en quarantaine** : Neutralise immédiatement le fichier (voir Section 7).
   - **Ignorer (Faux positif)** : Ajoute le fichier à la liste blanche locale.
   - **Ouvrir l'emplacement** : Ouvre l'Explorateur Windows sur le dossier contenant le fichier.

---

## 5. Inventaire Système et Détection des Vulnérabilités (CVE)

### 5.1 Réalisation d'un Inventaire Logiciel
1. Accédez à l'onglet **Inventaire Système**.
2. Cliquez sur **Actualiser l'inventaire**.
3. CyberSentinel AI inspecte le Registre Windows (64-bit et 32-bit WoW64) ainsi que le gestionnaire de paquets WinGet pour extraire la liste certifiée de vos logiciels installés.
4. La liste réconciliée affiche : Nom de l'application, Éditeur, Version installée, Architecture (x64/x86) et Identifiant WinGet.

### 5.2 Analyse des Vulnérabilités Connectée (NVD & OSV)
1. Rendez-vous dans l'onglet **Vulnérabilités**.
2. Cliquez sur **Rechercher les vulnérabilités**.
3. Pour chaque logiciel inventorié, l'application résout son identifiant CPE et interroge la base de données du **NIST (NVD)** et le référentiel **OSV**.
4. Les vulnérabilités identifiées sont classées par sévérité CVSS v3.1 :
   - 🔴 **Critique (CVSS 9.0 - 10.0)** : Exécution de code à distance (RCE), élévation de privilèges sans interaction.
   - 🟠 **Élevée (CVSS 7.0 - 8.9)** : Compromission importante des données ou du système.
   - 🟡 **Moyenne (CVSS 4.0 - 6.9)** : Déni de service local ou fuite d'informations partielles.
   - 🟢 **Faible (CVSS 0.1 - 3.9)** : Risque résiduel mineur.
5. Cliquez sur une CVE pour afficher le résumé technique, le score CVSS, les plages de versions impactées et le lien vers le bulletin de sécurité officiel.

---

## 6. Recherche et Déploiement des Mises à Jour

1. Ouvrez l'onglet **Mises à jour**.
2. Cliquez sur **Vérifier les mises à jour disponibles**.
3. CyberSentinel interroge les sources officielles de dépôts de logiciels.
4. Pour chaque mise à jour détectée, l'écran indique la **version installée** et la **version cible disponible**.
5. **Mise à jour sécurisée avec confirmation** :
   - Sélectionnez le logiciel à mettre à jour.
   - Cliquez sur **Mettre à jour le logiciel**.
   - Une boîte de dialogue de confirmation vous demande validation.
   - L'utilitaire WinGet procède au téléchargement du package certifié, vérifie son hachage officiel et applique le correctif.

---

## 7. Gestion de la Quarantaine Sécurisée

### 7.1 Mise en Quarantaine d'un Fichier Suspect
Lorsqu'un fichier est placé en quarantaine :
1. Le fichier original est verrouillé et extrait de son dossier hôte.
2. Il est chiffré selon l'algorithme militaire **AES-256-GCM** avec une clé dérivée de l'hôte.
3. Un hachage d'intégrité **HMAC-SHA256** est apposé pour empêcher toute corruption ou falsification.
4. L'archive sécurisée résultante reçoit l'extension `.qfile` et est reléguée dans le coffre-fort isolé `%ProgramData%\CyberSentinel\Quarantine`.

### 7.2 Restauration ou Suppression Définitive
1. Ouvrez l'onglet **Quarantaine**.
2. Vous visualisez la liste des fichiers isolés, leur date de mise en quarantaine, leur chemin d'origine et la raison de la mise à l'écart.
3. Pour restaurer un fichier :
   - Cliquez sur **Restaurer**.
   - Le système vérifie l'intégrité HMAC-SHA256.
   - Si l'intégrité est parfaite et que le chemin de destination est sûr (non système), le fichier est déchiffré à son emplacement d'origine et l'archive `.qfile` est effacée.
4. Pour purger définitivement une menace :
   - Cliquez sur **Supprimer définitivement**. Le fichier `.qfile` fait l'objet d'un écrasement sécurisé de ses blocs disque.

---

## 8. Génération et Exportation de Rapports d'Audit (PDF)

1. Rendez-vous dans l'onglet **Rapports d'audit**.
2. Sélectionnez la période d'analyse ou la session d'audit souhaitée.
3. Cliquez sur **Générer le rapport PDF**.
4. Un rapport professionnel vectoriel conforme à la norme **PDF-1.7** est généré de manière native sans passer par un navigateur ni aucun outil tiers.
5. Le document généré intègre :
   - La date et l'horodatage précis de l'audit.
   - L'empreinte de la machine auditée et version du système.
   - La synthèse des menaces détectées et des fichiers analysés.
   - Le tableau détaillé des vulnérabilités CVE actives avec scores CVSS.
   - L'état de déploiement des mises à jour correctives.
   - Les recommandations prioritaires de durcissement.

