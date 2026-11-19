# Diaporama de Soutenance PFE — CyberSentinel AI

> **Titre du Projet** : CyberSentinel AI — Plateforme Intégrée de Détection des Menaces par Intelligence Artificielle et de Gestion des Vulnérabilités sous Windows  
> **Diplôme** : Diplôme d'Ingénieur / Master 2 Cybersécurité & Génie Logiciel  
> **Durée conseillée** : 20 minutes d'exposé + 15 minutes de questions-réponses  
> **Support** : 20 diapositives professionnelles structurées  

---

## Sommaire du Diaporama

| N° | Titre de la Diapositive | Minutage suggéré | Objectif de la Diapositive |
| :---: | :--- | :---: | :--- |
| **01** | Introduction & Page de Garde | 0:00 – 1:00 | Cadrage du sujet, identité des candidats et des encadrants |
| **02** | Contexte de la Cybersécurité des Postes de Travail | 1:00 – 2:00 | Explosion des ransomwares, malwares polymorphes et failles applicatives |
| **03** | Problématique : La Fracture Détection vs Remédiation | 2:00 – 3:00 | Limites des antivirus statiques et isolement de la gestion des vulnérabilités |
| **04** | Objectifs Académiques et Industriels | 3:00 – 4:00 | Modèle prédictif local, Clean Architecture, remédiation continue |
| **05** | Étude de l'Existant : EDR vs Antivirus Traditionnels | 4:00 – 5:00 | Benchmark comparatif (Cloud, latence, vie privée, coûts) |
| **06** | Cahier des Charges & Spécification des Besoins | 5:00 – 6:00 | Besoins fonctionnels et non-fonctionnels (FURPS+) |
| **07** | Architecture Logicielle : Clean Architecture en Oignon | 6:00 – 7:30 | Découplage strict, inversion de dépendances, principes SOLID |
| **08** | Stack Technologique : .NET 10 LTS & C# 14 | 7:30 – 8:30 | RyuJIT, `ReadOnlySpan<T>`, WPF MVVM, SQLite/EF Core, ONNX Runtime |
| **09** | Modélisation des Données : Merise (MCD/MLD) | 8:30 – 9:30 | Persistance de l'inventaire, schéma 3NF, indexation, sécurité ACID |
| **10** | Module 1 : Moteur Malware Scanner Multi-Moteurs | 9:30 – 10:30 | Fusion ClamAV + YARA + EMBER, formule d'arbitrage pondéré |
| **11** | Module 2 : Intégration de l'IA (Modèle EMBER2024 & ONNX) | 10:30 – 12:00 | Vecteur 2381-D, analyse statique PE, entropie de Shannon, Fast-Path |
| **12** | Module 3 : Scanner d'Inventaire Système Réconcilié | 12:00 – 13:00 | Extraction croisée Registre (64/32) + WinGet, dédoublonnage |
| **13** | Module 4 : Détection des Vulnérabilités (NVD API 2.0 & OSV) | 13:00 – 14:00 | Résolution CPE 2.3, parsing SemVer, scoring CVSS v3.1, rate limiter |
| **14** | Module 5 : Update Management & Quarantaine Cryptographique | 14:00 – 15:00 | Déploiement assisté WinGet, conteneur AES-256-GCM + HMAC (.qfile) |
| **15** | Interface Graphique Utilisateur (WPF MVVM) | 15:00 – 16:00 | Ergonomie EDR/SIEM, thème sombre, zéro gel d'UI (asynchronisme) |
| **16** | Stratégie de Qualification & Tests (TDD / SSDLC) | 16:00 – 17:00 | Approche à 3 niveaux : Unitaires, Intégration, Audit Sécurité |
| **17** | Résultats Expérimentaux & Métriques Réelles | 17:00 – 18:00 | **115/115 tests réussis**, latence 12 ms, débit 1 080 fichiers/s |
| **18** | Limites Techniques Actuelles | 18:00 – 18:45 | Exécution en User-Mode, absence d'interception mémoire temps réel |
| **19** | Perspectives & Travaux Futurs | 18:45 – 19:30 | Driver Minifilter noyau, SLM local pour remédiation assistée |
| **20** | Conclusion Générale | 19:30 – 20:00 | Bilan scientifique, conformité industrielle et ouverture aux questions |

---

## Détail des 20 Diapositives

---

### Diapositive 01 : Introduction & Page de Garde
- **Titre** : CYBERSENTINEL AI
- **Sous-titre** : Conception et Réalisation d'une Plateforme Intégrée d'Analyse des Menaces par Intelligence Artificielle et de Gestion des Vulnérabilités sous Windows
- **Contenu** :
  - Candidat(s) : Équipe d'Ingénierie CyberSentinel AI
  - Encadrement : Ingénieur Senior & Superviseur Académique
  - Établissement / Spécialité : Diplôme d'Ingénieur / Master 2 Cybersécurité & Génie Logiciel
  - Année Académique : 2025 – 2026
- **Notes de l'orateur (1 min)** :
  > "Monsieur le Président, mesdames et messieurs les membres du jury, bonjour. J'ai l'honneur de vous présenter aujourd'hui les travaux de fin d'études portant sur le projet CyberSentinel AI, une solution modulaire conçue pour unifier l'analyse prédictive des menaces par apprentissage automatique et la remédiation continue des vulnérabilités applicatives sous environnement Windows."

---

### Diapositive 02 : Contexte de la Cybersécurité des Postes Clients
- **Points clés** :
  - Le terminal (*Endpoint*) : cible privilégiée de plus de 70 % des compromissions en entreprise.
  - Multiplication des ransomwares et des charges utiles obfusquées (*Crypters*, *Packers*).
  - Industrialisation du cybercrime : kits de malwares as a Service (MaaS) générant des milliers de variantes uniques chaque jour.
  - La dette de sécurité applicative : accumulation de logiciels tiers non maintenus hébergeant des failles documentées.
- **Illustration** : Schéma d'une chaîne d'attaque typique (Phishing $\rightarrow$ Exécution binaire $\rightarrow$ Exploitation CVE locale $\rightarrow$ Élévation de privilèges).
- **Notes de l'orateur (1 min)** :
  > "Le poste de travail Windows demeure la porte d'entrée maîtresse des attaquants. Deux réalités s'affrontent : d'un côté, des malwares conçus pour muter en permanence et échapper aux analyses traditionnelles ; de l'autre, des applications d'usage courant dont les correctifs de sécurité critiques ne sont jamais appliqués sur les postes."

---

### Diapositive 03 : Problématique : La Fracture Détection vs Remédiation
- **Constat d'échec des approches silotées** :
  - **Antivirus traditionnels** : Réactivité différée face aux signatures inédites (fenêtre d'exposition Zero-Day de plusieurs jours).
  - **Outils de gestion de vulnérabilités isolés** : Scanners de vulnérabilités périodiques lourds, déconnectés de la réalité du binaire suspect présent sur le disque.
  - **Dépendance Cloud excessive des EDR** : Fuite de métadonnées, facture de bande passante, inopérance totale sur les réseaux industriels ou militaires fermés (*air-gapped*).
- **Question de Recherche** :
  *Comment concevoir une solution de sécurité pour Windows capable de prédire localement la malveillance d'exécutables inconnus sans déport dans le Cloud, tout en intégrant dans le même cycle de vie l'audit et la remédiation des vulnérabilités logicielles ?*

---

### Diapositive 04 : Objectifs du Projet
- **Objectifs Académiques** :
  - Mettre en œuvre le modèle de pointe **EMBER2024** (Gradient Boosted Trees) en inférence locale via **ONNX Runtime**.
  - Valider l'application rigoureuse des principes de génie logiciel : **Clean Architecture**, **SOLID**, **TDD**.
  - Démontrer formellement l'absence de failles d'implémentation par un audit SSDLC complet.
- **Objectifs Industriels** :
  - Développer une application Desktop Windows 10/11 réactive, ergonomique et légère.
  - Zéro dépendance tierce superflue en production (100% BCL natif pour la cryptographie, le parsing et le reporting).
  - Fournir un coffre-fort de quarantaine cryptographique inviolable sous **AES-256-GCM**.

---

### Diapositive 05 : Étude de l'Existant : EDR Cloud vs Antivirus Classiques
- **Tableau Comparatif** :

| Critères d'Évaluation | Antivirus Classique (ex: ClamAV) | EDR Entreprise Cloud (ex: CrowdStrike) | CyberSentinel AI (Notre Solution) |
| :--- | :---: | :---: | :---: |
| **Détection Zero-Day** | ❌ Très Faible (Signatures) | ✔️ Élevée (IA / Cloud) | ✔️ **Élevée (Modèle EMBER local)** |
| **Fonctionnement Hors-Ligne** | ✔️ Oui (Base locale) | ❌ Non (Dépendance Cloud) | ✔️ **100% Autonome (Air-gapped)** |
| **Gestion des Vulnérabilités** | ❌ Aucune | ⚠️ Option payante lourde | ✔️ **Native (NVD + WinGet)** |
| **Souveraineté des Données** | ✔️ Totale | ❌ Télémétrie externe | ✔️ **Données strictement locales** |
| **Empreinte Système** | Légère | Lourde (Agents multiples) | **Ultra-légère ($< 15\text{ ms}$)** |

---

### Diapositive 06 : Cahier des Charges & Spécifications (FURPS+)
- **Exigences Fonctionnelles (F)** :
  1. Analyse multi-moteurs simultanée : ClamAV (signatures), YARA (règles heuristiques), EMBER (IA).
  2. Inventaire logiciel réconcilié à partir des registres 32/64 bits et de WinGet.
  3. Détection des CVE par résolution CPE 2.3 et interrogation résiliente de la NVD et d'OSV.
  4. Mise à niveau applicative automatisée et sécurisée via WinGet.
  5. Quarantaine chiffrée AES-GCM et export PDF autonome.
- **Exigences Non-Fonctionnelles (URPS)** :
  - **Performance** : Analyse unitaire $< 50\text{ ms}$, scan de dossiers multithreadé non bloquant.
  - **Fiabilité & Sécurité** : Immunité aux injections de commandes, path traversal, et empoisonnement de modèles.

---

### Diapositive 07 : Architecture Logicielle : Clean Architecture en Oignon
- **Présentation du Diagramme d'Architecture** :
  - Couche 1 : **Domain** (Zéro dépendance, règles pures, entités, calcul de score).
  - Couche 2 : **Application** (Contrats, interfaces, DTOs, validateurs).
  - Couche 3 : **Infrastructure** (SQLite, ClamAV, YARA, WinGet, NVD, Quarantaine).
  - Couche 4 : **AI** (Extraction PE 2381-D, moteur ONNX).
  - Couche 5 : **Desktop** (Interface WPF, ViewModels MVVM réactifs).
- **Règle de Dépendance** : Unidirectionnelle vers l'intérieur. Inversion de dépendances via IoC.

---

### Diapositive 08 : Stack Technologique : .NET 10 LTS & C# 14
- **Pourquoi .NET 10 LTS ?**
  - Performance du compilateur RyuJIT et accélération matérielle SIMD/AVX.
  - Utilisation poussée de `ReadOnlySpan<byte>` pour l'analyse binaire sans allocation mémoire sur le tas.
- **Pourquoi C# 14 ?**
  - Syntaxe expressive : Record structs, collection expressions, pattern matching avancé.
  - Sécurité des types : Nullable reference types stricts activés sur 100 % de la base de code.
- **Composants Clés** :
  - WPF (.NET 10 Desktop) pour le rendu graphique vectoriel accéléré par GPU.
  - Microsoft.ML.OnnxRuntime pour l'exécution ultra-rapide des graphes d'IA.
  - SQLite + EF Core 10 pour la persistance locale relationnelle ACID.

---

### Diapositive 09 : Modélisation des Données : Merise (MCD/MLD)
- **Modèle Conceptuel (MCD)** :
  - Entité `SESSION_INVENTAIRE` liée par `CONTENIR (1,N)` à `LOGICIEL_INSTALLE`.
  - Entités d'audit : `ScanSession`, `ThreatFinding`, `QuarantineRecord`.
- **Modèle Logique (MLD 3NF)** :
  - Dédoublonnage strict des logiciels recensés.
  - Index composites sur `SessionId`, `PackageIdentifier`, et `CanonicalCpe`.
  - Sécurité des données : Requêtes LINQ compilées paramétrées éliminant toute injection SQL.

---

### Diapositive 10 : Module 1 : Moteur Malware Scanner Multi-Moteurs
- **Synergie Tripartite** :
  - **ClamAV** : Spécialiste des signatures antivirales historiques certifiées ($S = 1.0$).
  - **YARA** : Spécialiste des patterns comportementaux (injection mémoire, note de rançon, $S = 0.90$).
  - **EMBER IA** : Spécialiste de la détection de structure anormale sur exécutables inconnus ($S = 0.85$).
- **Algorithme d'Arbitrage Pondéré (`VerdictArbitrator`)** :

$$\text{ThreatScore} = \max\left(S_{\text{ClamAV}} \times 1.0, \; S_{\text{YARA}} \times 0.90, \; S_{\text{EMBER}} \times 0.85\right)$$

- Seuil critique : Score $\ge 0.85 \implies$ `Malware` / `RiskLevel.Critical`.

---

### Diapositive 11 : Module 2 : Intégration de l'IA (EMBER2024 & ONNX)
- **Extraction des 2381 Caractéristiques Statiques (Sans exécution)** :
  1. Histogramme d'octets (256) : Distribution globale des fréquences.
  2. Histogramme d'entropie locale (256) : Mesure de Shannon sur fenêtres coulissantes.
  3. Caractéristiques de chaînes (104) : Longueur, URLs, registres, chemins.
  4. En-têtes PE & Sections (327) : Tailles virtuelles vs physiques, flags mémoire.
  5. Tables IAT & EAT (1408) : Fonctions système importées/exportées.
- **Inférence ONNX & Fast-Path** :
  - Évaluation par Gradient Boosted Trees en **$12\text{ ms}$**.
  - Court-circuit immédiat des fichiers non-PE (`MZ` absent) en **$0\text{ ms}$**.
  - Vérification cryptographique de l'intégrité SHA-256 du modèle avant tout chargement.

---

### Diapositive 12 : Module 3 : Scanner d'Inventaire Système Réconcilié
- **Le Problème** : Les registres Windows contiennent des noms hétérogènes, des doublons 32/64 bits et manquent d'identifiants standardisés.
- **La Solution CyberSentinel** :
  - Scrutateur multi-ruches : Registre 64-bit, WoW64 32-bit, Registre Utilisateur HKCU.
  - Interrogation parallèle de WinGet CLI.
  - **Moteur de Réconciliation** : Dédoublonnage par clé canonique, assignation de l'ID WinGet officiel et génération du CPE 2.3 normalisé.

---

### Diapositive 13 : Module 4 : Détection des Vulnérabilités (NVD API 2.0 & OSV)
- **Pipeline de Corrélation** :
  1. Résolution de la chaîne CPE (ex: `cpe:2.3:a:videolan:vlc_media_player:3.0.11:*:*:*:*:*:*:*`).
  2. Interrogation résiliente de la **NVD REST API 2.0** et du référentiel **OSV**.
  3. Gestion adaptative des quotas par `NvdRateLimiter` (fenêtre glissante anti-HTTP 429).
  4. Comparaison des plages de versions affectées par `VersionRangeMatcher` (règles SemVer).
- **Classification CVSS v3.1** : Identification immédiate des sévérités Critiques (CVSS 9.0 - 10.0) et Élevées.

---

### Diapositive 14 : Module 5 : Update Management & Quarantaine Cryptographique
- **Gestion Sécurisée des Mises à Jour (WinGet)** :
  - Identification des packages obsolètes.
  - Contrôle strict par expression régulière des identifiants (`^[a-zA-Z0-9_\-\.]+$`).
  - Blocage impératif sans confirmation explicite de l'utilisateur.
- **Quarantaine Authentifiée (`.qfile`)** :
  - Chiffrement symétrique **AES-256-GCM** (vecteur d'initialisation aléatoire 96 bits, tag 128 bits).
  - Empreinte **HMAC-SHA256** garantissant l'intégrité absolue de la preuve numérique.
  - Restauration atomique avec contrôle anti-path traversal.

---

### Diapositive 15 : Interface Graphique Utilisateur (WPF MVVM)
- **Principes de Design** :
  - Thème sombre professionnel inspiré des consoles EDR/SIEM de référence.
  - Navigation ergonomique par volet latéral : Dashboard, Scans, Inventaire, Vulnérabilités, Mises à jour, Quarantaine, Rapports.
  - Liaison de données (*Data Binding*) bidirectionnelle et commandes réactives (`RelayCommand`).
  - Threading asynchrone évitant tout blocage de l'interface (*UI Thread fluid à 60 FPS*).

---

### Diapositive 16 : Stratégie de Qualification & Tests (TDD / SSDLC)
- **Pyramide des Tests** :
  - **87 Tests Unitaires** : Services, parseurs, mathématiques d'entropie, règles de fusion.
  - **19 Tests d'Intégration & Scénarios** : 7 moteurs réels, Scénarios A à I de bout en bout, benchmarks de charge.
  - **9 Tests de Sécurité & Robustesse** : Injections de commandes, traversée de répertoires, altération de quarantaine, fuite de secrets.
- **Règle Déontologique** : Zéro test simulé ou complaisant. Tous les tests sont exécutés par ligne de commande hôte.

---

### Diapositive 17 : Résultats Expérimentaux & Métriques Réelles
- **Bilan Global** : **115 tests exécutés, 115 tests validés avec succès (100 %)**.
- **Performances Mesurées** :
  - Latence d'analyse unitaire : **$12\text{ ms}$** par binaire PE.
  - Débit batch massif : **50 fichiers en $46\text{ ms}$** ($> 1\,080\text{ fichiers/seconde}$).
  - Consommation mémoire : **$0.0\text{ MB}$** de fuite mémoire résiduelle après Garbage Collection.
  - Réactivité d'annulation : Prise en compte du `CancellationToken` en **$2\text{ ms}$**.

---

### Diapositive 18 : Limites Techniques Identifiées
- **Exécution en Espace Utilisateur (*User-Mode*)** :
  - Analyse statique ultra-rapide mais incapable d'intercepter les attaques sans fichier (*Fileless Malware*) ou les injections de DLL à chaud exécutées exclusivement en RAM.
- **Dépendance aux Privilèges Hôte (UAC)** :
  - La remédiation système et la mise en quarantaine de binaires protégés exigent l'élévation administrateur.
- **Quotas de l'API NVD sans clé** :
  - Débit de requêtage limité à 5 requêtes par fenêtre de 30 secondes sans clé personnelle NIST.

---

### Diapositive 19 : Perspectives & Travaux Futurs
1. **Pilote Noyau Système (*Kernel Minifilter Driver*)** :
   - Interception synchrone à l'ouverture de fichier (*On-Access Scanning*) avant tout accès disque.
2. **Surveillance Dynamique par ETW (*Event Tracing for Windows*)** :
   - Corrélation comportementale temps réel des appels API et connexions réseau via des réseaux récurrents (LSTM).
3. **Assistance à la Remédiation par Modèle de Langage Local (SLM)** :
   - Déploiement d'un modèle type Phi-3 / Gemma local pour générer des scripts de remédiation adaptés aux CVE détectées.

---

### Diapositive 20 : Conclusion Générale
- **Synthèse** :
  - Objectifs académiques et industriels 100 % atteints.
  - Démonstration de l'efficience de l'IA (EMBER2024 / ONNX) pour la cybersécurité des terminaux.
  - Architecture Clean Architecture et SSDLC éprouvée par 115 tests automatisés.
- **Remerciements** :
  - À l'encadrement académique et aux membres du jury pour leur écoute attentive.
- **Ouverture** : "Nous sommes désormais à votre entière disposition pour répondre à vos questions et procéder à la démonstration en direct."

