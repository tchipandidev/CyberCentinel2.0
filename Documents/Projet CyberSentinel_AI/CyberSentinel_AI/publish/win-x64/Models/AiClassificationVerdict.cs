namespace CyberSentinel.AI.Models;

public enum AiClassificationVerdict
{
    /// <summary>
    /// Binaire présentant des caractéristiques et structures alignées avec les exécutables légitimes.
    /// Probabilité de malveillance P &lt; 0.30.
    /// </summary>
    Benign = 0,

    /// <summary>
    /// Binaire présentant des anomalies structurelles ou heuristiques notables nécessitant une surveillance.
    /// Plage d'incertitude 0.30 &lt;= P &lt; 0.70.
    /// </summary>
    Suspicious = 1,

    /// <summary>
    /// Binaire présentant une forte concordance statistique avec des familles de logiciels malveillants.
    /// Probabilité de malveillance P &gt;= 0.70.
    /// </summary>
    Malicious = 2,

    /// <summary>
    /// Fichier non supporté (non-PE), corrompu, inaccessible ou taille hors limites.
    /// </summary>
    UnknownOrUnsupported = 3
}

