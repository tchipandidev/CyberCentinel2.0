# Scénario de Démonstration en Direct (Live Demo) — CyberSentinel AI

> **Contexte** : Démonstration technique devant le Jury de Fin d'Études  
> **Durée estimée** : 7 minutes  
> **Principe déontologique absolu** : **Zéro malware réel**. Les tests exploitent des binaires inoffensifs de test intégrant des signatures heuristiques et des en-têtes PE conformes aux spécifications validées en QA.  
> **Prérequis machine** : Windows 10/11 x64, exécutable de release compilé, connexion Internet pour l'interrogation de l'inventaire WinGet.  

---

## Tableau Synoptique du Déroulement

| Étape | Temps | Action Opérateur | Ce qui se passe sous le capot | Ce qu'il faut dire au Jury |
| :---: | :---: | :--- | :--- | :--- |
| **01** | 0:00 - 0:45 | Lancement de `CyberSentinel.Desktop.exe` | Initialisation SQLite, compilation YARA, vérification SHA-256 du modèle ONNX | *"L'application démarre en vérifiant l'intégrité de ses composants et charge le tableau de bord consolidé."* |
| **02** | 0:45 - 1:30 | Analyse d'un binaire sain (`notepad.exe` ou équivalent PE) | Extraction des 2381 features, inférence ONNX ($12\text{ ms}$), arbitrage multi-moteurs | *"Le moteur EMBER analyse la structure interne du PE en 12 ms sans jamais exécuter le binaire."* |
| **03** | 1:30 - 2:30 | Détection d'un fichier de test heuristique | Déclenchement de la règle YARA (Ransomware/Injection), arbitrage $S = 0.94$ | *"Le système détecte le pattern malveillant, élève l'alerte au niveau Critique et propose la mise en quarantaine."* |
| **04** | 2:30 - 3:15 | Mise en quarantaine et vérification cryptographique | Chiffrement AES-256-GCM + signature HMAC-SHA256, isolation sous `.qfile` | *"Le binaire est neutralisé dans un conteneur hermétique préservant l'intégrité forensique de la preuve."* |
| **05** | 3:15 - 4:15 | Actualisation de l'inventaire système | Inspection Registry (64/32 bits) + WinGet, dédoublonnage par clé canonique | *"Le moteur de réconciliation consolide 150+ logiciels en éliminant les redondances WoW64."* |
| **06** | 4:15 - 5:15 | Détection des vulnérabilités CVE / CVSS | Résolution CPE 2.3, requêtage NVD/OSV, matching de version | *"CyberSentinel identifie les failles connues (CVE-2022-41325) et leur sévérité CVSS v3.1."* |
| **07** | 5:15 - 6:00 | Détection et proposition de mise à jour WinGet | Détection package obsolète, validation regex de sécurité | *"Une mise à jour corrective est prête. Par mesure de sécurité, aucune action n'est engagée sans confirmation."* |
| **08** | 6:00 - 7:00 | Génération et ouverture du rapport PDF | Composition du document ISO PDF-1.7 natif vectoriel en mémoire | *"En un clic, nous exportons un rapport d'audit exécutif complet conforme au standard PDF."* |

---

## Guide Pas-à-Pas Détaillé pour le Présentateur

### Étape 1 : Démarrage et Accueil (0:00 - 0:45)
1. **Action** : Double-cliquez sur l'exécutable `CyberSentinel.Desktop.exe` (ou lancez-le depuis le terminal).
2. **Constat à l'écran** :
   - L'interface sombre s'ouvre instantanément.
   - Le **Dashboard** affiche les cartes statistiques : Fichiers analysés, Menaces détectées, Vulnérabilités actives, Mises à jour en attente.
3. **Discours au Jury** :
   > "Au démarrage, CyberSentinel AI initialise sa base SQLite locale et effectue un contrôle d'intégrité SHA-256 sur le modèle d'intelligence artificielle ONNX pour s'assurer qu'aucun empoisonnement local n'a eu lieu. L'écran d'accueil présente la vue synthétique de la sécurité du poste."

---

### Étape 2 : Analyse d'un Exécutable Sain (0:45 - 1:30)
1. **Action** : 
   - Cliquez sur l'onglet **Analyse Fichiers** dans la barre latérale.
   - Cliquez sur **Parcourir** et sélectionnez un binaire légitime (ex: `C:\Windows\System32\notepad.exe` ou un binaire de test compilé sain).
   - Cliquez sur **Lancer l'analyse**.
2. **Constat à l'écran** :
   - En moins de 15 millisecondes, le statut passe au vert : **Sain (Clean)**.
   - Score global : `0.00 / 1.00`.
   - Détail des 3 moteurs : ClamAV: `Clean`, YARA: `Clean`, EMBER IA: `0.03 (Sain)`.
3. **Discours au Jury** :
   > "Nous venons d'analyser un exécutable standard. Les 2381 caractéristiques de l'en-tête PE, des sections et de la table d'importation ont été extraites statiquement par notre moteur sans exécuter le fichier. L'inférence du modèle d'apprentissage supervisé confirme que le profil structurel est parfaitement sain."

---

### Étape 3 : Détection Heuristique et Arbitrage Multi-Moteurs (1:30 - 2:30)
1. **Action** :
   - Sélectionnez l'échantillon de test inoffensif préparé (`test_sample_heuristic.exe`).
   - *(Note : Ce binaire de démonstration intègre des chaînes d'injection mémoire et une fausse note de rançon pour stimuler les règles YARA et le vecteur d'entropie EMBER, sans aucun comportement dangereux).*
   - Cliquez sur **Lancer l'analyse**.
2. **Constat à l'écran** :
   - Alerte visuelle immédiate en rouge vif : **MENACE CRITIQUE DÉTECTÉE**.
   - Score calculé : `0.94 / 1.00` (Niveau de Risque : `Critical`).
   - Le volet détail affiche la règle YARA déclenchée : `SUSPICIOUS_MEMORY_INJECTION_AND_RANSOM`.
   - L'arbitre de décision (`VerdictArbitrator`) a automatiquement surclassé le verdict au niveau maximal.
3. **Discours au Jury** :
   > "Ici, l'arbitre multi-moteurs entre en action. La signature comportementale a été interceptée par le moteur YARA et corrélée avec les anomalies structurelles détectées par l'IA. Conformément à notre politique de sécurité stricte, le score s'élève à 0.94 et l'alerte passe en Critique."

---

### Étape 4 : Mise en Quarantaine Cryptographique (2:30 - 3:15)
1. **Action** :
   - Cliquez sur le bouton rouge **Mettre en quarantaine**.
   - Naviguez vers l'onglet **Quarantaine** dans le volet latéral.
2. **Constat à l'écran** :
   - Le fichier a disparu de son répertoire d'origine.
   - Il apparaît dans le registre de quarantaine avec son ID unique, son horodatage et son hachage SHA-256.
   - Sur le disque, un conteneur chiffré `.qfile` est présent dans le coffre-fort.
3. **Discours au Jury** :
   > "Le fichier a été retiré du système de fichiers et placé dans un coffre-fort chiffré en AES-256-GCM avec une signature d'intégrité HMAC-SHA256. Même si un attaquant tentait de modifier le conteneur sur le disque, l'intégrité cryptographique rejetterait immédiatement la restauration."

---

### Étape 5 : Inventaire Système Réconcilié (3:15 - 4:15)
1. **Action** :
   - Cliquez sur l'onglet **Inventaire Système**.
   - Cliquez sur **Actualiser l'inventaire**.
2. **Constat à l'écran** :
   - La liste de tous les logiciels installés s'affiche en moins d'une seconde.
   - Un tableau paginé et filtrable expose : Nom, Éditeur, Version, Architecture (x64/x86), et l'identifiant WinGet associé.
3. **Discours au Jury** :
   > "Notre moteur d'inventaire interroge simultanément les ruches 64 bits et 32 bits du Registre Windows et le catalogue WinGet. L'algorithme de réconciliation fusionne les doublons et déduit automatiquement la chaîne CPE 2.3 standardisée pour chaque logiciel."

---

### Étape 6 : Détection des Vulnérabilités (CVE / CVSS) (4:15 - 5:15)
1. **Action** :
   - Cliquez sur l'onglet **Vulnérabilités**.
   - Cliquez sur **Rechercher les vulnérabilités**.
2. **Constat à l'écran** :
   - Les logiciels présentant des versions vulnérables sont mis en exergue (ex: composant Git, VLC ou Python d'une version cible).
   - Les CVE associées apparaissent avec leur sévérité CVSS v3.1 (badges colorés : Critique en rouge, Élevée en orange).
   - En cliquant sur une CVE, le résumé officiel de la faille et les versions impactées s'affichent.
3. **Discours au Jury** :
   > "Le système effectue la corrélation entre les identifiants CPE de l'inventaire et les bases du NIST (NVD) et d'OSV. Grâce à notre composant de comparaison SemVer, seules les vulnérabilités affectant formellement la plage de version installée sont signalées, évitant ainsi le bruit des faux positifs."

---

### Étape 7 : Recherche de Mises à Jour & Déploiement Sécurisé (5:15 - 6:00)
1. **Action** :
   - Cliquez sur l'onglet **Mises à jour**.
   - Cliquez sur **Vérifier les mises à jour**.
2. **Constat à l'écran** :
   - La liste des logiciels obsolètes s'affiche avec la version installée et la nouvelle version disponible sur les dépôts officiels.
   - En sélectionnant un logiciel et en cliquant sur **Mettre à jour**, une boîte de dialogue de confirmation sécurisée s'affiche.
3. **Discours au Jury** :
   > "CyberSentinel AI fait le pont entre la vulnérabilité détectée et sa remédiation. Conformément à notre politique de développement sécurisé (SSDLC), aucune mise à jour n'est jamais exécutée sans la validation formelle de l'administrateur, et l'identifiant du package fait l'objet d'une validation stricte par expression régulière pour interdire toute injection de commande."

---

### Étape 8 : Génération et Exportation du Rapport PDF (6:00 - 7:00)
1. **Action** :
   - Rendez-vous sur l'onglet **Rapports d'audit**.
   - Cliquez sur **Générer le rapport PDF**.
   - Ouvrez le fichier PDF généré sur le bureau.
2. **Constat à l'écran** :
   - Un document PDF vectoriel de haute qualité s'affiche dans le lecteur PDF.
   - Il présente le récapitulatif complet de la session, les scores de menace, la liste des CVE et les recommandations d'action.
3. **Discours au Jury** :
   > "Pour clore la démonstration, voici le rapport d'audit exécutif généré de manière 100% native par notre moteur PDF-1.7, sans aucune dépendance externe. En 7 minutes, nous avons démontré l'intégralité du cycle de vie de la sécurité d'un terminal : de la détection prédictive par IA jusqu'à la remédiation et la traçabilité réglementaire. Je vous remercie pour votre attention."

