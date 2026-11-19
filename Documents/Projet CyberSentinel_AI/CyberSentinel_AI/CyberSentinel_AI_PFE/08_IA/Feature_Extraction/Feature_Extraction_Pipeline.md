# Pipeline d'Extraction Statique PE (2381 Dimensions)

L'implémentation C# native sans crash mémoire est localisée dans :
- `src/CyberSentinel.AI/Features/PeFeatureExtractor.cs`
- `src/CyberSentinel.AI/Features/EmberFeatureExtractor.cs`
- `src/CyberSentinel.AI/Features/EmberFeatureVector.cs`

L'extraction s'opère en mode lecture seule stricte sur des flux `ReadOnlySpan<byte>`, garantissant zéro exécution dynamique et zéro allocation sur le tas managé.
