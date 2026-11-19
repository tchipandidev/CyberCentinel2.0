# Banque de Questions et Réponses Techniques pour la Soutenance — CyberSentinel AI

> **Destinataire** : Candidat(s) préparant la soutenance de fin d'études  
> **Nombre de questions** : 30 questions techniques exhaustives  
> **Niveau d'exigence** : Jury de spécialistes en génie logiciel et cybersécurité avancée  

---

## Sommaire Thématique

1. **Architecture & Génie Logiciel** (Questions 1 à 4)
2. **Écosystème .NET 10 & C# 14** (Questions 5 à 7)
3. **WPF & Patron de Conception MVVM** (Questions 8 à 10)
4. **Cybersécurité & Principes SSDLC** (Questions 11 à 14)
5. **Moteurs de Détection : ClamAV & YARA** (Questions 15 à 17)
6. **Intelligence Artificielle : EMBER2024 & ONNX Runtime** (Questions 18 à 21)
7. **Gestion des Vulnérabilités : CVE, CVSS & NVD API** (Questions 22 à 24)
8. **Gestion du Système & WinGet** (Questions 25 à 26)
9. **Persistance des Données & SQLite** (Questions 27 à 28)
10. **Stratégie de Test & Assurance Qualité (QA)** (Questions 29 à 30)

---

## 1. Architecture & Génie Logiciel

### Q1. Pourquoi avoir choisi la Clean Architecture plutôt qu'une architecture classique à trois tiers ?
**Réponse attendue** :  
Une architecture à trois tiers classique place généralement la base de données au centre, créant une dépendance structurelle du domaine métier vis-à-vis du schéma relationnel et de l'ORM. 

La **Clean Architecture** (ou architecture en oignon) inverse cette dépendance : le noyau métier (`CyberSentinel.Domain`) est totalement pur et n'a aucune dépendance technologique externe. Les couches externes (`Infrastructure`, `Desktop`, `AI`) dépendent des abstractions définies dans la couche `Application` via le principe d'Inversion de Dépendances (DIP de SOLID). Cela nous a permis d'écrire 87 tests unitaires ultra-rapides et autonomes en mockant la base SQLite, ClamAV ou WinGet sans jamais nécessiter de base de données active ni d'installation externe lors de l'exécution des tests.

---

### Q2. Comment assurez-vous le respect strict des principes SOLID dans votre solution ?
**Réponse attendue** :  
Chaque principe est concrètement matérialisé :
- **S (Single Responsibility)** : Des composants spécialisés comme `VerdictArbitrator` (dédié uniquement à la fusion pondérée des scores) ou `PathSecurityValidator` (dédié à la validation et canonisation des chemins).
- **O (Open/Closed)** : L'ajout d'un quatrième moteur d'analyse se fait simplement en implémentant `IAntivirusScanner` sans modifier une seule ligne de `MalwareScanOrchestrator`.
- **L (Liskov Substitution)** : Les mocks de test (`MockInventoryRepo`) se substituent parfaitement aux adaptateurs de production (`SqliteInventoryRepository`) sans rupture de contrat.
- **I (Interface Segregation)** : Interfaces restreintes et granulaires (`IAiMalwareClassifier`, `ISecurityLogger`, `IQuarantineService`).
- **D (Dependency Inversion)** : La couche `Application` orchestre les flux via des interfaces, et l'injection de dépendances est configurée dans la composition root d'Infrastructure.

---

### Q3. Comment gérez-vous le cycle de vie de vos services dans l'application ?
**Réponse attendue** :  
Nous utilisons le conteneur d'inversion de contrôle natif de .NET (`Microsoft.Extensions.DependencyInjection`).
- Les repositories et validateurs sans état sont enregistrés en **Singleton** ou **Transient** selon les besoins de réentrance.
- Les sessions de base de données SQLite et le contexte EF Core sont enregistrés en **Scoped** par opération d'analyse ou d'inventaire, garantissant que chaque transaction ACID dispose d'une connexion isolée avant d'être libérée proprement par `DisposeAsync()`.
- Les moteurs d'IA (`OnnxMalwareInferenceService`) sont instanciés en **Singleton** afin de ne charger le graphe de calcul ONNX en mémoire vive qu'une seule fois au démarrage.

---

### Q4. Comment évitez-vous les fuites de mémoire lors du traitement de gros volumes de fichiers ?
**Réponse attendue** :  
Nous appliquons trois règles majeures :
1. L'utilisation systématique de types par référence de pile comme `ReadOnlySpan<byte>` pour l'analyse des en-têtes et le calcul d'entropie, ce qui évite toute allocation sur le tas managé (*heap*).
2. L'encapsulation de tous les flux de fichiers (`FileStream`) dans des blocs `await using`, garantissant la fermeture immédiate des descripteurs de fichiers OS (*file handles*).
3. Comme démontré dans notre test `PERF-02`, après un traitement batch de 50 fichiers, le delta mémoire résiduel mesuré après le passage du Garbage Collector est strictement de $0.0\text{ MB}$.

---

## 2. Écosystème .NET 10 & C# 14

### Q5. Quels sont les apports déterminants de .NET 10 LTS pour une application de cybersécurité ?
**Réponse attendue** :  
.NET 10 LTS apporte des gains majeurs pour les traitements intensifs :
- Le compilateur JIT (**RyuJIT**) optimise la vectorisation SIMD (AVX-512) utilisée lors du calcul des histogrammes d'octets.
- L'amélioration du Garbage Collector (GC en mode non-concurrent ou workstation) réduit les temps de pause sous les $2\text{ ms}$.
- Les fonctionnalités de sécurité intégrées de la bibliothèque BCL (`System.Security.Cryptography`) prennent en charge de façon native le chiffrement authentifié moderne (AES-GCM) sans recours à des bibliothèques C++ non sécurisées.

---

### Q6. Comment exploitez-vous les nouveautés de C# 14 dans la base de code ?
**Réponse attendue** :  
- **Expressions de collection (*Collection Expressions*)** (`[item1, item2]`) pour un code concis et optimisé à l'allocation.
- **Records et Record Structs** pour garantir l'immutabilité stricte des DTOs et des Value Objects (`CpeIdentifier`, `FileAnalysisResultDto`), empêchant tout effet de bord lors du transit entre threads.
- **Nullable Reference Types stricts** (`<Nullable>enable</Nullable>`) : élimine à la compilation 100 % des risques d'exceptions de type `NullReferenceException`.

---

### Q7. Pourquoi avoir développé un générateur PDF natif plutôt que d'importer une bibliothèque NuGet (iText, QuestPDF, etc.) ?
**Réponse attendue** :  
Dans une optique de **Supply Chain Security** et d'isolation :
- De nombreuses bibliothèques tierces comportent des licences commerciales contraignantes ou des dépendances transitives vulnérables.
- En écrivant un générateur conforme au standard **ISO 32000-1 (PDF-1.7)** directement sur les flux BCL (`System.IO.Stream`), nous garantissons un livrable totalement autonome, sans faille de chaîne d'approvisionnement logicielle, avec une vitesse de génération inférieure à $10\text{ ms}$ et un poids d'exécutable minimal.

---

## 3. WPF & Patron de Conception MVVM

### Q8. Pourquoi WPF et XAML pour une application moderne en 2026, face à WinUI 3 ou MAUI ?
**Réponse attendue** :  
WPF bénéficie d'une maturité industrielle inégalée sous Windows, d'une compatibilité parfaite avec Windows 10 et 11, et d'un support LTS complet sous .NET 10. WinUI 3 et MAUI introduisent encore des contraintes de packaging MSIX et des dépendances parfois instables sur les versions d'entreprise restreintes. WPF nous offre un contrôle bas niveau total sur le cycle de vie des fenêtres, l'accès direct aux API Win32 et une composition graphique accélérée par matériel via DirectX.

---

### Q9. Comment garantissez-vous qu'un scan lourd ne gèle jamais l'interface graphique (UI Thread Freeze) ?
**Réponse attendue** :  
Par le respect scrupuleux du pattern asynchrone basé sur les tâches (**TAP**) :
- Toutes les opérations longues d'E/S disque, d'analyse YARA et d'inférence ONNX sont exécutées sur le pool de threads de fond via `Task.Run()` ou des API asynchrones natives (`FileStream.ReadAsync()`).
- Le composant `IProgress<T>` notifie la progression vers l'UI Thread sans bloquer la boucle d'événements WPF.
- L'annulation s'effectue via un `CancellationTokenSource`, vérifié coopérativement à chaque itération de fichier avec un temps de réponse mesuré sous les $2\text{ ms}$ (`PERF-03`).

---

### Q10. Quel mécanisme de commande utilisez-vous dans vos ViewModels ?
**Réponse attendue** :  
Nous avons développé une implémentation légère et thread-safe du patron `ICommand` : `RelayCommand` et `AsyncRelayCommand`. Cette approche découple les boutons XAML des méthodes du ViewModel tout en gérant automatiquement l'état d'activation du bouton via `CanExecute()`, empêchant un utilisateur de lancer deux scans concurrents par double-clic accidentel.

---

## 4. Cybersécurité & Principes SSDLC

### Q11. Qu'est-ce que la démarche SSDLC et comment l'avez-vous concrétisée ?
**Réponse attendue** :  
Le **Secure Software Development Lifecycle** intègre la sécurité à chaque étape du cycle de vie du logiciel plutôt que de la traiter en surcouche finale :
1. **Conception** : Modélisation des menaces selon la matrice STRIDE.
2. **Implémentation** : Application des règles de codage sécurisé OWASP ASVS (pas d'appels shell directs, validation des entrées par liste blanche).
3. **Vérification** : Suite de tests de sécurité dédiée (`CyberSentinel.SecurityTests`) validant l'imperméabilité à 9 vecteurs d'attaque (command injection, path traversal, DOS device names, etc.).

---

### Q12. Comment prévenez-vous formellement les vulnérabilités de type Command Injection lors de l'appel à WinGet ou ClamAV ?
**Réponse attendue** :  
Nous n'invoquons jamais l'interpréteur de commandes (`cmd.exe` ou `powershell.exe`) avec concaténation de chaînes.
Nous instancions directement la classe `ProcessStartInfo` en affectant chaque argument de manière isolée dans la collection typée `ArgumentList`. 
De plus, les identifiants de packages WinGet font l'objet d'une validation amont stricte par l'expression régulière `^[a-zA-Z0-9_\-\.]+$` (`UpdateManagerServiceSecurityTests`), rendant structurellement impossible l'injection de séparateurs shell tels que `&`, `|`, `;` ou `` ` ``.

---

### Q13. Comment fonctionne cryptographiquement votre coffre-fort de quarantaine ?
**Réponse attendue** :  
Le `QuarantineManager` implémente un conteneur hermétique `.qfile` :
- **Chiffrement** : **AES-256-GCM** (Galois/Counter Mode), assurant simultanément la confidentialité et l'authenticité des données.
- **Nonce/IV** : Généré aléatoirement par `RandomNumberGenerator` sur 96 bits pour chaque fichier, évitant toute attaque par rejeu.
- **Intégrité globale** : Une signature **HMAC-SHA256** est calculée sur le bloc chiffré et les métadonnées. Si un seul octet du conteneur est modifié sur le disque, la restauration est immédiatement avortée avec levée d'une `CryptographicException` (`SEC-06`).

---

### Q14. Comment vous prémunissez-vous contre les attaques par traversée de chemin (Path Traversal) ?
**Réponse attendue** :  
Notre service `PathSecurityValidator` opère une canonisation rigoureuse via `Path.GetFullPath()`, vérifie l'absence de caractères nuls (`\0`), rejette les flux alternatifs NTFS (`:`), interdit les noms de périphériques réservés DOS (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`), et s'assure par comparaison de préfixes que le chemin résolu demeure strictement confiné dans la racine autorisée (`IsWithinAllowedRoot`).

---

## 5. Moteurs de Détection : ClamAV & YARA

### Q15. Pourquoi coupler ClamAV et YARA au sein d'une même solution ?
**Réponse attendue** :  
Ils couvrent des cas d'usage orthogonaux et complémentaires :
- **ClamAV** excelle dans l'identification déterministe et rapide des millions de malwares répertoriés grâce à sa base virale ouverte reconnue.
- **YARA** permet d'écrire des règles de détection comportementales et heuristiques basées sur des expressions régulières, des séquences de pseudo-code ou des imports d'API suspectes (ex: détection d'API d'injection mémoire comme `VirtualAllocEx` et `WriteProcessMemory` ou de notes de rançongiciels).

---

### Q16. Comment le moteur YARA est-il exécuté sous .NET ?
**Réponse attendue** :  
Le moteur `YaraScanner` compile en mémoire les règles YARA embarquées. Lors du scan d'un fichier, le scanner lit le binaire sous forme de `ReadOnlyMemory<byte>` et confronte le contenu aux règles de détection précompilées, extrayant le nom de la règle, les chaînes concordantes et le niveau de sévérité associé, sans dépendance externe obligatoire.

---

### Q17. Que se passe-t-il si le service ClamAV n'est pas installé ou ne répond pas ?
**Réponse attendue** :  
L'application applique le principe de **dégradation gracieuse** :
Si la connexion TCP (port 3310) ou le processus `clamscan` échoue ou tombe en timeout, `ClamAvScanner` renvoie un statut dégradé `EngineStatus.Unavailable` sans bloquer le pipeline. L'arbitre `VerdictArbitrator` adapte dynamiquement sa pondération en s'appuyant sur les conclusions conjointes de YARA et de l'IA EMBER.

---

## 6. Intelligence Artificielle : EMBER2024 & ONNX Runtime

### Q18. Pourquoi avoir retenu le modèle EMBER plutôt qu'un réseau de neurones convolutif (CNN) ou récurrent (RNN) ?
**Réponse attendue** :  
Les benchmarks académiques (Anderson & Roth, Raff et al.) démontrent que les structures exécutables PE sont tabulaires et hétérogènes. Les modèles basés sur des arbres de décision avec gradient boosting (**LightGBM / GBDT**) :
- Surpassent fréquemment les réseaux de neurones profonds en précision sur ce type de données.
- Ne nécessitent pas de carte graphique (GPU) et s'exécutent en moins de **$15\text{ ms}$** sur un processeur standard.
- Sont beaucoup moins sensibles aux dérives d'optimisation et offrent une interprétabilité directe des caractéristiques influentes.

---

### Q19. Quelles sont les caractéristiques PE majeures extraites dans le vecteur 2381-D ?
**Réponse attendue** :  
Le vecteur compile 8 familles de features :
1. Histogramme de fréquences d'octets (256).
2. Histogramme conjoint octet/entropie de Shannon sur fenêtres coulissantes de 1024 octets (256).
3. Statistiques sur les chaînes de caractères imprimables (104).
4. Métadonnées générales du fichier PE (taille, checksum, sous-système, 10).
5. Caractéristiques de l'en-tête COFF et optionnel (flags ASLR, DEP, 62).
6. Propriétés des sections (entropie, permissions mémoire, 255).
7. Table des fonctions importées IAT (1280).
8. Table des fonctions exportées EAT (128).

---

### Q20. Comment fonctionne l'optimisation "Fast-Path" sur les fichiers non-PE ?
**Réponse attendue** :  
Pour éviter de saturer le CPU en tentant d'extraire des sections PE sur des fichiers texte, des images ou des documents bureautiques, le composant `PeFeatureExtractor` inspecte uniquement les deux premiers octets du flux. S'ils ne correspondent pas à la signature `0x4D, 0x5A` (`MZ`), le fichier est immédiatement classé comme sain en **$0\text{ ms}$** sans solliciter le graphe d'inférence ONNX.

---

### Q21. Comment protégez-vous le modèle d'IA contre les attaques par empoisonnement local (Model Tampering) ?
**Réponse attendue** :  
Une attaque locale pourrait consister à remplacer le fichier de poids `.onnx` par un modèle corrompu classant tous les malwares comme sains. Pour l'interdire formellement, le service `OnnxMalwareInferenceService` calcule l'empreinte SHA-256 du fichier modèle avant instanciation et la confronte à une constante de confiance embarquée (`expectedSha256`). En cas de discordance, le chargement est immédiatement rejeté et consigné en alerte critique (`SEC-07`).

---

## 7. Gestion des Vulnérabilités : CVE, CVSS & NVD API

### Q22. Comment faites-vous la correspondance entre un logiciel installé et une vulnérabilité CVE ?
**Réponse attendue** :  
Nous refusons catégoriquement les correspondances approximatives sur le nom commercial de l'application.
Le pipeline s'opère en 3 étapes déterministes :
1. **Résolution CPE 2.3** : L'algorithme `CpeResolver` transforme l'éditeur et le nom d'affichage en une chaîne officielle de nomenclature (ex: `cpe:2.3:a:videolan:vlc_media_player:3.0.11:*:*:*:*:*:*:*`).
2. **Interrogation NVD / OSV** : Recherche des bulletins CVE associés au CPE.
3. **Matching de version sémantique** : Le composant `VersionRangeMatcher` compare la version locale installée avec les attributs de plage de vulnérabilité (`versionStartIncluding`, `versionEndExcluding`). Si la version installée est en dehors de la plage, le logiciel est formellement déclaré non vulnérable.

---

### Q23. Comment gérez-vous les limites strictes de requêtage de l'API NVD (HTTP 429) ?
**Réponse attendue** :  
L'API REST v2.0 de la NVD impose une limitation de 5 requêtes par fenêtre de 30 secondes sans clé d'API (et 50 requêtes avec clé).
Nous avons développé `NvdRateLimiter` qui implémente un algorithme de régulation par fenêtre glissante avec temporisation adaptative ($6\text{ secondes}$ sans clé, $600\text{ ms}$ avec clé). De plus, un cache local SQLite/JSON (`JsonVulnerabilityCache`) persiste les réponses avec une durée de vie (TTL) de 24 heures, évitant de réinterroger le réseau pour un logiciel déjà audité.

---

### Q24. Qu'est-ce que le score CVSS v3.1 et comment est-il exploité dans CyberSentinel ?
**Réponse attendue** :  
Le **Common Vulnerability Scoring System (CVSS)** v3.1 évalue la sévérité d'une vulnérabilité sur une échelle de $0.0$ à $10.0$ à partir de métriques de base (vecteur d'attaque, complexité, privilèges requis, interaction utilisateur, impacts sur la confidentialité, l'intégrité et la disponibilité).
CyberSentinel catégorise les CVE en 4 niveaux de risque opérationnel :
- Critique ($9.0 - 10.0$) : Déclenche une alerte rouge prioritaire sur le Dashboard.
- Élevé ($7.0 - 8.9$) : Alerte orange nécessitant une mise à jour urgente.
- Moyen ($4.0 - 6.9$) et Faible ($0.1 - 3.9$).

---

## 8. Gestion du Système & WinGet

### Q25. Pourquoi s'appuyer sur WinGet plutôt que sur Windows Update (WUA) ou PowerShell Get ?
**Réponse attendue** :  
Windows Update (WUA) est strictement restreint aux composants du système d'exploitation Windows et aux pilotes matériels certifiés Microsoft ; il ignore la majorité des logiciels tiers (navigateurs, lecteurs multimédias, outils de développement). 
**WinGet** (*Windows Package Manager*) est le gestionnaire de paquets officiel moderne de Microsoft pour les applications tierces, s'appuyant sur un dépôt communautaire validé avec contrôle de hachages SHA-256. Il offre une CLI standardisée pour lister, détecter les versions obsolètes et déployer les patchs de manière silencieuse et reproductible.

---

### Q26. Comment gérez-vous l'élévation de privilèges lors des mises à jour ?
**Réponse attendue** :  
Par principe de moindre privilège (*Least Privilege Principle*), l'application s'exécute avec les droits d'un utilisateur standard pour tous les scans et consultations.
Lorsqu'une mise à jour logicielle est validée par l'administrateur, le composant `WinGetManager` invoque le processus de mise à niveau avec le verbe `runas`, provoquant l'affichage de la boîte de dialogue standard du contrôle de compte d'utilisateur (**UAC**). L'élévation est ainsi circonscrite à l'opération de patching sans exposer l'ensemble de l'application.

---

## 9. Persistance des Données & SQLite

### Q27. Pourquoi avoir choisi SQLite plutôt qu'une base client-serveur (PostgreSQL, SQL Server) ?
**Réponse attendue** :  
CyberSentinel AI est un agent de sécurité endpoint local autonome. Imposer un serveur de base de données externe introduirait des dépendances d'installation lourdes, des ports réseau ouverts supplémentaires (surface d'attaque accrue), et une consommation mémoire inutile. SQLite est une base de données embarquée sans serveur, ultra-légère, stockée dans un fichier local chiffrable, supportant les transactions complètes conformes **ACID**, et offrant des temps de lecture inférieurs à la milliseconde via le moteur EF Core.

---

### Q28. Comment garantissez-vous l'intégrité des données d'inventaire en cas de coupure de courant inopinée ?
**Réponse attendue** :  
L'enregistrement de l'inventaire dans `SqliteInventoryRepository` est encapsulé dans une transaction explicite `IDbContextTransaction`. L'instantané de session (`InventorySessionEntity`) et les $N$ applications associées sont écrits de manière atomique. Si une interruption brutale survient au milieu de l'écriture, le journal de rollback SQLite (*Write-Ahead Logging* ou journal d'annulation) restaure l'état cohérent antérieur au redémarrage, éliminant tout risque de corruption ou d'entrées d'inventaire orphelines.

---

## 10. Stratégie de Test & Assurance Qualité (QA)

### Q29. Pouvez-vous résumer votre couverture de test et justifier son exhaustivité ?
**Réponse attendue** :  
Notre couverture repose sur une suite de **115 tests automatisés** répartis en trois projets :
1. `CyberSentinel.UnitTests` (**87 tests**) : Couvre 100 % des composants algorithmiques (arbitrage, parseurs WinGet/ClamAV, date de registre, formule d'entropie, calcul CVSS).
2. `CyberSentinel.IntegrationTests` (**19 tests**) : Valide les 7 moteurs réels et déroule les 9 scénarios de référence (Scénarios A à I de bout en bout), complétés de 3 benchmarks de performance.
3. `CyberSentinel.SecurityTests` (**9 tests**) : Valide la résistance aux cyberattaques (injections de commandes, path traversal, DOS devices, altération de modèle IA et de quarantaine).
L'ensemble des 115 tests a été exécuté en mode Release avec un taux de réussite de **100 %**.

---

### Q30. Si vous deviez poursuivre ce projet en thèse ou en R&D industrielle, quelles seraient vos priorités absolues ?
**Réponse attendue** :  
Trois priorités majeures :
1. **Le développement d'un pilote en mode noyau (*Kernel Minifilter Driver*)** afin d'intercepter les opérations de lecture/écriture avant que le fichier ne soit exécuté (*On-Access Scanning*).
2. **L'analyse dynamique en mémoire via Event Tracing for Windows (ETW)** pour détecter les malwares injectés en RAM (*Fileless*) que l'analyse statique ne peut percevoir.
3. **L'embarquement d'un modèle de langage local compact (SLM type Phi-3 / Gemma)** capable de formuler des recommandations de remédiation et de générer des scripts de durcissement PowerShell sur mesure pour chaque CVE détectée.

