# Bibliographie et Annexes Techniques — CyberSentinel AI

---

## 1. Bibliographie et Références Normatives

### 1.1 Articles de Recherche et Publications Scientifiques
1. **Anderson, H. S., & Roth, P.** (2018). *EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models*. arXiv preprint arXiv:1804.04169.
2. **Raff, E., Barker, J., Sylvester, J., Brandon, R., Sell, R., & Nicholas, C.** (2018). *Malware Detection by Eating a Whole EXE*. Workshops at the Thirty-Second AAAI Conference on Artificial Intelligence.
3. **Saxe, J., & Berlin, K.** (2015). *Deep neural network based malware detection using two dimensional binary program features*. 10th International Conference on Malicious and Unwanted Software (MALWARE), IEEE, pp. 11-20.
4. **Ke, G., Meng, Q., Finley, T., Wang, T., Chen, W., Ma, W., Ye, Q., & Liu, T. Y.** (2017). *LightGBM: A Highly Efficient Gradient Boosting Decision Tree*. Advances in Neural Information Processing Systems (NeurIPS 30), pp. 3146-3154.
5. **Shannon, C. E.** (1948). *A Mathematical Theory of Communication*. Bell System Technical Journal, 27(3), pp. 379-423. *(Fondement du calcul d'entropie locale des sections PE)*.

### 1.2 Normes, Standards et Publications Institutionnelles
6. **NIST SP 800-115** (2008). *Technical Guide to Information Security Testing and Assessment*. National Institute of Standards and Technology.
7. **NIST IR 7695** (2011). *Common Platform Enumeration: Naming Specification Version 2.3*. NIST Specification.
8. **FIRST** (2019). *Common Vulnerability Scoring System v3.1: Specification Document*. Forum of Incident Response and Security Teams.
9. **ISO/IEC 32000-1:2008** (2008). *Document management — Portable document format — Part 1: PDF 1.7*. International Organization for Standardization.
10. **RFC 5424** (2009). *The Syslog Protocol*. Internet Engineering Task Force (IETF).
11. **OWASP Foundation** (2021). *OWASP Application Security Verification Standard (ASVS) 4.0.3*.
12. **Microsoft Corporation** (2023). *Microsoft Portable Executable and Common Object File Format Specification*. Revision 11.0.

---

## 2. Annexe A : Spécification Complète du Vecteur EMBER 2381-D

Le vecteur $\mathbf{x} \in \mathbb{R}^{2381}$ est structuré en 8 sous-ensembles de caractéristiques normalisées :

| Index Début | Index Fin | Nb Dims | Nom du Groupe | Description et Normalisation |
| :---: | :---: | :---: | :--- | :--- |
| `0` | `255` | 256 | `ByteHistogram` | Fréquence relative de chaque octet $b \in [0, 255]$ divisée par la taille totale du binaire. |
| `256` | `511` | 256 | `ByteEntropyHistogram` | Distribution conjointe octet/entropie sur fenêtres coulissantes de 1024 octets. |
| `512` | `615` | 104 | `StringExtractor` | Statistiques sur chaînes ASCII/Unicode : nombre, longueur moyenne, ratio d'octets, distribution des longueurs, chemins Windows, clés de registre, URLs. |
| `616` | `625` | 10 | `GeneralFileInfo` | Taille du fichier, taille virtuelle, nombre de sections, nombre de symboles, présence de signature authentifiée, checksum, sous-système. |
| `626` | `687` | 62 | `HeaderFileInfo` | Heuristiques de l'en-tête COFF : caractéristiques binaire (DLL, EXE), flags machine, caractéristiques optionnelles (ASLR, DEP, SafeSEH, NoSEH). |
| `688` | `942` | 255 | `SectionInfo` | Propriétés des sections (jusqu'à 10 sections principales) : entropie de section, taille brute vs virtuelle, flags de mémoire (lecture, écriture, exécution). |
| `943` | `2222` | 1280 | `ImportsInfo` | Hachages 2D des fonctions importées via la table IAT (hachage des noms de DLL et noms d'API Win32 via MurmurHash3 / 2D trick). |
| `2223` | `2380` | 128 | `ExportsInfo` | Nombre de fonctions exportées et hachages des symboles exposés par la table EAT. |

---

## 3. Annexe B : Spécification du Format de Quarantaine Cryptographique (.qfile)

Le format binaire `.qfile` est un conteneur chiffré hermétique conçu pour empêcher toute exécution accidentelle sur la machine hôte :

```text
+--------------------------------------------------------------------------------+
| OFFSET (Octets) | TAILLE (Octets) | CHAMP          | DESCRIPTION               |
+--------------------------------------------------------------------------------+
| 0x00 - 0x07     | 8               | Magic Header   | "CS_QFILE\0" (Identifiant) |
| 0x08 - 0x0B     | 4               | Format Version | 0x00000001 (Version 1.0)  |
| 0x0C - 0x1B     | 16              | Record ID      | GUID unique de quarantaine|
| 0x1C - 0x27     | 12              | GCM IV (Nonce) | 96 bits aléatoires        |
| 0x28 - 0x37     | 16              | GCM Auth Tag   | 128 bits d'authentification|
| 0x38 - 0x3F     | 8               | Original Size  | Taille en octets du binaire|
| 0x40 - 0x5F     | 32              | Original SHA256| Hachage du fichier d'origine|
| 0x60 - 0x7F     | 32              | HMAC-SHA256    | Signature d'intégrité     |
| 0x80 - ...      | Variable        | Encrypted Blob | Fichier chiffré AES-256   |
+--------------------------------------------------------------------------------+
```

---

## 4. Annexe C : Matrice des Commandes WinGet Intégrées

| Commande WinGet | Arguments Typiques | Utilisation dans CyberSentinel AI | Précautions de Sécurité |
| :--- | :--- | :--- | :--- |
| `winget list` | `--accept-source-agreements` | Énumération des logiciels installés avec identifiants officiels. | Exécution en lecture seule, droits standards. |
| `winget list` | `--upgrade-available` | Identification des logiciels disposant d'une version plus récente. | Découpage des colonnes avec tolérance de langue. |
| `winget upgrade`| `--id <ID> --exact -h --accept-package-agreements` | Application d'une mise à jour logicielle spécifique en mode silencieux. | Validation regex stricte de l'identifiant `<ID>`, confirmation explicite de l'utilisateur, élévation UAC. |

---

## 5. Annexe D : Matrice de Correspondance et Sévérités CVSS v3.1

| Plage de Score CVSS v3.1 | Niveau de Sévérité | Impact Opérationnel Type | Délai de Remédiation Recommandé (SLA) |
| :---: | :---: | :--- | :---: |
| **9.0 – 10.0** | 🔴 **Critique** | Exécution de code à distance (RCE) non authentifiée, prise de contrôle totale. | Immédiat ($\le 24\text{ heures}$) |
| **7.0 – 8.9** | 🟠 **Élevé** | Élévation locale de privilèges, compromission de la confidentialité de données critiques. | Urgent ($\le 7\text{ jours}$) |
| **4.0 – 6.9** | 🟡 **Moyen** | Déni de service local, contournement partiel de mécanismes de sécurité. | Planifié ($\le 30\text{ jours}$) |
| **0.1 – 3.9** | 🟢 **Faible** | Fuite d'informations mineure, prérequis d'accès physique ou scénario très contraint. | Au fil de l'eau |
| **0.0** | ⚪ **Aucun** | Absence de vulnérabilité identifiée dans le catalogue NVD. | N/A |

