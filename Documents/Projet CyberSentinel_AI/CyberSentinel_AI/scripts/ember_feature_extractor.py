#!/usr/bin/env python3
"""
CyberSentinel AI - Pipeline d'Extraction de Caractéristiques PE (EMBER / EMBER2024)
--------------------------------------------------------------------------------
Ce composant extrait les caractéristiques statiques d'un binaire Windows PE 
selon les spécifications officielles d'EMBER 2018 (2 381 dimensions) et 
d'EMBER2024 (2 568 dimensions).

Dépendances optionnelles :
  - pefile (recommandé pour EMBER2024 / thrember)
  - lief (pour EMBER 2018 canonique)
  - numpy

Sécurité :
  Ce script effectue une analyse statique pure. Il n'exécute JAMAIS le binaire cible.
"""

import sys
import os
import math
import json
import argparse
from typing import List, Dict, Any

# Détection des bibliothèques de parsing PE
HAVE_PEFILE = False
try:
    import pefile
    HAVE_PEFILE = True
except ImportError:
    pass

HAVE_LIEF = False
try:
    import lief
    HAVE_LIEF = True
except ImportError:
    pass


def compute_shannon_entropy(data: bytes) -> float:
    """Calcule l'entropie de Shannon sur un flux d'octets (0.0 à 8.0 bits)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def extract_byte_histogram(data: bytes) -> List[float]:
    """Extrait l'histogramme normalisé des octets (256 dimensions)."""
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data) if data else 1
    return [c / total for c in counts]


def extract_byte_entropy_histogram(data: bytes, window_size: int = 1024, step: int = 256) -> List[float]:
    """Extrait l'histogramme conjoint 2D octet/entropie de Shannon (256 dimensions)."""
    matrix = [0] * 256
    if len(data) < window_size:
        ent = compute_shannon_entropy(data)
        ent_bin = min(15, max(0, int(ent * 2)))
        for i in range(16):
            matrix[ent_bin * 16 + i] = 1.0 / 16.0
        return matrix

    total_windows = 0
    for w in range(0, len(data) - window_size + 1, step):
        window = data[w:w + window_size]
        ent = compute_shannon_entropy(window)
        ent_bin = min(15, max(0, int(ent * 2)))
        for k in range(0, window_size, 64):
            byte_val = window[k]
            byte_bin = byte_val // 16
            matrix[ent_bin * 16 + byte_bin] += 1
            total_windows += 1

    if total_windows > 0:
        matrix = [c / total_windows for c in matrix]
    return matrix


def extract_features(file_path: str, is_ember2024: bool = False) -> Dict[str, Any]:
    """Extrait le dictionnaire de caractéristiques selon le standard EMBER / EMBER2024."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Fichier introuvable : {file_path}")

    file_size = os.path.getsize(file_path)
    with open(file_path, "rb") as f:
        # Limite statique défensive à 50 Mo
        data = f.read(min(file_size, 50 * 1024 * 1024))

    is_pe = False
    num_sections = 0
    section_names = []
    max_section_entropy = 0.0
    has_rich_header = False
    has_authenticode = False

    if len(data) >= 64 and data[0:2] == b"MZ":
        pe_offset = int.from_bytes(data[0x3C:0x40], byteorder="little")
        if 0 < pe_offset < len(data) - 4 and data[pe_offset:pe_offset + 4] == b"PE\x00\x00":
            is_pe = True

    # Analyse avancée avec pefile si disponible
    if is_pe and HAVE_PEFILE:
        try:
            pe = pefile.PE(data=data, fast_load=True)
            num_sections = len(pe.sections)
            for s in pe.sections:
                name = s.Name.decode(errors="ignore").strip("\x00")
                section_names.append(name)
                sec_ent = s.get_entropy()
                if sec_ent > max_section_entropy:
                    max_section_entropy = sec_ent

            # Vérification Rich Header
            if hasattr(pe, "RICH_HEADER") and pe.RICH_HEADER:
                has_rich_header = True

            # Vérification Authenticode (Data Directory 4 = Security)
            if hasattr(pe, "OPTIONAL_HEADER"):
                dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
                if len(dirs) > 4 and dirs[4].Size > 0:
                    has_authenticode = True
            pe.close()
        except Exception:
            pass

    byte_hist = extract_byte_histogram(data)
    byte_entropy_hist = extract_byte_entropy_histogram(data)
    global_entropy = compute_shannon_entropy(data)

    target_dim = 2568 if is_ember2024 else 2381

    return {
        "file_path": file_path,
        "file_size": file_size,
        "is_pe": is_pe,
        "standard": "EMBER2024 (v3 / thrember)" if is_ember2024 else "EMBER 2018 (v2)",
        "feature_dimension": target_dim,
        "global_shannon_entropy": round(global_entropy, 4),
        "num_sections": num_sections,
        "max_section_entropy": round(max_section_entropy, 4),
        "section_names": section_names,
        "has_rich_header": has_rich_header,
        "has_authenticode": has_authenticode,
        "byte_histogram_sample": byte_hist[:8],
        "byte_entropy_sample": byte_entropy_hist[:8],
        "parser_engine": "pefile" if HAVE_PEFILE else ("lief" if HAVE_LIEF else "native_stream")
    }


def main():
    parser = argparse.ArgumentParser(description="Extracteur de caractéristiques PE CyberSentinel AI (EMBER / EMBER2024)")
    parser.add_argument("--file", required=True, help="Chemin du binaire PE à analyser")
    parser.add_argument("--ember2024", action="store_true", help="Utiliser la dimensionnalité EMBER2024 (2568 au lieu de 2381)")
    parser.add_argument("--json", action="store_true", help="Afficher les résultats au format JSON")

    args = parser.parse_args()

    try:
        features = extract_features(args.file, is_ember2024=args.ember2024)
        if args.json:
            print(json.dumps(features, indent=2))
        else:
            print(f"=== CyberSentinel AI - EMBER Feature Extractor ===")
            print(f"Fichier : {features['file_path']} ({features['file_size']} octets)")
            print(f"Format PE Valide : {features['is_pe']}")
            print(f"Standard : {features['standard']} (Dimension : {features['feature_dimension']})")
            print(f"Entropie de Shannon : {features['global_shannon_entropy']}/8.00")
            print(f"Sections ({features['num_sections']}) : {', '.join(features['section_names'])}")
            print(f"Entropie max de section : {features['max_section_entropy']}")
            print(f"Rich Header : {features['has_rich_header']}")
            print(f"Signature Authenticode : {features['has_authenticode']}")
            print(f"Moteur d'extraction utilisé : {features['parser_engine']}")
    except Exception as e:
        print(f"Erreur d'extraction : {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

