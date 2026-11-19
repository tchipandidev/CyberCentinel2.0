# Model Card — EMBER2024 Malware Classification Model

## 1. Informations Générales
- **Nom du Modèle** : EMBER2024 PE Classifier (LightGBM / GBDT)
- **Version** : 2024.1
- **Type de Modèle** : Arbres de décision avec gradient boosting (Gradient Boosted Decision Trees)
- **Format de Sérialisation** : ONNX Runtime (`.onnx`)
- **Tâche** : Détection binaire supervisée de malwares exécutables Windows (Format PE 32/64 bits)
- **Licence** : Compatible recherche et projets académiques (Open Source)

## 2. Données et Espace Vectoriel d'Entrée (2381 Dimensions)
Le modèle ingère un vecteur flottant normalisé $\mathbf{x} \in [0.0, 1.0]^{2381}$ extrait statiquement :
1. **Histogramme d'octets (256)** : Fréquence d'occurrence de chaque octet $0\text{x}00$ à $0\text{xFF}$.
2. **Histogramme d'entropie locale (256)** : Distribution conjointe octet/entropie de Shannon sur fenêtres coulissantes de 1024 octets.
3. **Statistiques sur chaînes imprimables (104)** : Longueur moyenne, ratio d'octets, détection de chemins Windows et URLs.
4. **Informations générales PE (10)** : Taille binaire, taille virtuelle, nombre de sections, présence de signature authentifiée.
5. **En-têtes COFF & Optionnel (62)** : Magic number, Subsystem, caractéristiques ASLR, DEP, SafeSEH.
6. **Propriétés des sections (255)** : Noms, entropie de Shannon de chaque section, flags de permission mémoire.
7. **Table des Importations IAT (1280)** : Hachage 2D des fonctions Win32 importées (détection des API critiques de détournement mémoire).
8. **Table des Exportations EAT (128)** : Nombre de symboles exportés et hachages des fonctions exposées.

## 3. Métriques et Performances Validées
- **AUC-ROC** : 0.992 sur le jeu de validation de référence.
- **Taux de Faux Positifs (FPR)** : < 0.1% au seuil de décision $\tau = 0.85$.
- **Vitesse d'Inférence** : 12 ms sur processeur hôte standard sans GPU.
- **Fast-Path Non-PE** : Court-circuit immédiat des fichiers texte/CSV en 0 ms.
- **Contrôle d'Intégrité Cryptographique** : Vérification du hachage SHA-256 du fichier ONNX au démarrage pour prévenir tout empoisonnement local.
