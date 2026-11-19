-- ============================================================================
-- CYBERSENTINEL AI - MODÈLE PHYSIQUE DE DONNÉES (MPD SQL)
-- ============================================================================
-- SGBD Cible        : SQLite 3.x / Entity Framework Core 10 (Compatible ANSI SQL)
-- Auteur            : Équipe d'Ingénierie CyberSentinel AI
-- Date de Référence : Novembre 2026
-- Description       : Script DDL complet de création des tables, contraintes,
--                     index de performance B-Tree, triggers et vues analytiques.
-- ============================================================================

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

-- ----------------------------------------------------------------------------
-- 1. TABLE : InventorySessions
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS InventorySessions (
    Id                          TEXT PRIMARY KEY NOT NULL, -- GUID au format texte standard
    SnapshotDate                TEXT NOT NULL,             -- Horodatage ISO 8601 UTC
    TotalApplicationsCount      INTEGER NOT NULL DEFAULT 0 CHECK (TotalApplicationsCount >= 0),
    X64ApplicationsCount        INTEGER NOT NULL DEFAULT 0 CHECK (X64ApplicationsCount >= 0),
    X86ApplicationsCount        INTEGER NOT NULL DEFAULT 0 CHECK (X86ApplicationsCount >= 0),
    OtherArchCount              INTEGER NOT NULL DEFAULT 0 CHECK (OtherArchCount >= 0),
    MachineName                 TEXT NOT NULL,
    OsVersion                   TEXT NOT NULL
);

-- ----------------------------------------------------------------------------
-- 2. TABLE : InstalledSoftware
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS InstalledSoftware (
    Id                          TEXT PRIMARY KEY NOT NULL, -- GUID
    SessionId                   TEXT NOT NULL,
    DisplayName                 TEXT NOT NULL,
    Publisher                   TEXT NOT NULL DEFAULT 'Éditeur inconnu',
    DisplayVersion              TEXT NOT NULL DEFAULT 'Non spécifiée',
    Architecture                TEXT NOT NULL DEFAULT 'Unknown' CHECK (Architecture IN ('x64', 'x86', 'ARM64', 'Unknown')),
    InstallDate                 TEXT,
    InstallLocation             TEXT,
    IdentificationSource        TEXT NOT NULL,
    PackageIdentifier           TEXT,                      -- Identifiant WinGet officiel (ex: Git.Git)
    CanonicalCpe                TEXT,                      -- Chaîne CPE 2.3 normalisée
    IsSystemComponent           INTEGER NOT NULL DEFAULT 0 CHECK (IsSystemComponent IN (0, 1)),
    DiscoveredAt                TEXT NOT NULL,
    FOREIGN KEY (SessionId) REFERENCES InventorySessions(Id) ON DELETE CASCADE
);

-- ----------------------------------------------------------------------------
-- 3. TABLE : Vulnerabilities
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS Vulnerabilities (
    CveId                       TEXT PRIMARY KEY NOT NULL, -- Ex: CVE-2022-41325
    CvssScore                   REAL NOT NULL DEFAULT 0.0 CHECK (CvssScore >= 0.0 AND CvssScore <= 10.0),
    Severity                    TEXT NOT NULL CHECK (Severity IN ('None', 'Low', 'Medium', 'High', 'Critical')),
    Description                 TEXT NOT NULL,
    RemediationUrl              TEXT,
    PublishedDate               TEXT
);

-- ----------------------------------------------------------------------------
-- 4. TABLE DE LIAISON : SoftwareVulnerabilities (Association N:N)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS SoftwareVulnerabilities (
    SoftwareId                  TEXT NOT NULL,
    CveId                       TEXT NOT NULL,
    MatchStatus                 TEXT NOT NULL CHECK (MatchStatus IN ('Confirmed', 'Potential', 'Patched', 'InsufficientInfo')),
    DetectedAt                  TEXT NOT NULL,
    PRIMARY KEY (SoftwareId, CveId),
    FOREIGN KEY (SoftwareId) REFERENCES InstalledSoftware(Id) ON DELETE CASCADE,
    FOREIGN KEY (CveId) REFERENCES Vulnerabilities(CveId) ON DELETE RESTRICT
);

-- ----------------------------------------------------------------------------
-- 5. TABLE : SoftwareUpdates
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS SoftwareUpdates (
    Id                          TEXT PRIMARY KEY NOT NULL,
    SoftwareId                  TEXT NOT NULL UNIQUE,
    PackageIdentifier           TEXT NOT NULL,
    CurrentVersion              TEXT NOT NULL,
    AvailableVersion            TEXT NOT NULL,
    UpdateSource                TEXT NOT NULL,
    DiscoveredAt                TEXT NOT NULL,
    Status                      TEXT NOT NULL DEFAULT 'Available' CHECK (Status IN ('Available', 'PendingConfirmation', 'Installing', 'Installed', 'Failed')),
    FOREIGN KEY (SoftwareId) REFERENCES InstalledSoftware(Id) ON DELETE CASCADE
);

-- ----------------------------------------------------------------------------
-- 6. TABLE : ScanSessions
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ScanSessions (
    Id                          TEXT PRIMARY KEY NOT NULL,
    ScanType                    TEXT NOT NULL CHECK (ScanType IN ('SingleFile', 'Directory', 'FullSystem')),
    StartedAt                   TEXT NOT NULL,
    CompletedAt                 TEXT,
    TotalFilesScanned           INTEGER NOT NULL DEFAULT 0 CHECK (TotalFilesScanned >= 0),
    ThreatsDetectedCount        INTEGER NOT NULL DEFAULT 0 CHECK (ThreatsDetectedCount >= 0),
    DurationMs                  INTEGER NOT NULL DEFAULT 0 CHECK (DurationMs >= 0),
    Status                      TEXT NOT NULL CHECK (Status IN ('Running', 'Completed', 'Cancelled', 'Failed'))
);

-- ----------------------------------------------------------------------------
-- 7. TABLE : ScannedFiles
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ScannedFiles (
    Id                          TEXT PRIMARY KEY NOT NULL,
    ScanSessionId               TEXT NOT NULL,
    FilePath                    TEXT NOT NULL,
    Sha256Hash                  TEXT NOT NULL,
    FileSizeBytes               INTEGER NOT NULL CHECK (FileSizeBytes >= 0),
    Verdict                     TEXT NOT NULL CHECK (Verdict IN ('Clean', 'Suspicious', 'Malware', 'Error', 'BypassedNonPe')),
    CompositeThreatScore        REAL NOT NULL DEFAULT 0.0 CHECK (CompositeThreatScore >= 0.0 AND CompositeThreatScore <= 1.0),
    ClamAvScore                 REAL NOT NULL DEFAULT 0.0 CHECK (ClamAvScore >= 0.0 AND ClamAvScore <= 1.0),
    YaraScore                   REAL NOT NULL DEFAULT 0.0 CHECK (YaraScore >= 0.0 AND YaraScore <= 1.0),
    EmberAiScore                REAL NOT NULL DEFAULT 0.0 CHECK (EmberAiScore >= 0.0 AND EmberAiScore <= 1.0),
    ScannedAt                   TEXT NOT NULL,
    FOREIGN KEY (ScanSessionId) REFERENCES ScanSessions(Id) ON DELETE CASCADE
);

-- ----------------------------------------------------------------------------
-- 8. TABLE : QuarantineRecords
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS QuarantineRecords (
    Id                          TEXT PRIMARY KEY NOT NULL,
    ScannedFileId               TEXT NOT NULL UNIQUE,
    OriginalFilePath            TEXT NOT NULL,
    QuarantineBlobPath          TEXT NOT NULL,             -- Chemin du conteneur .qfile
    Sha256Hash                  TEXT NOT NULL,
    HmacSignature               BLOB NOT NULL,             -- 32 octets (HMAC-SHA256)
    AesIv                       BLOB NOT NULL,             -- 12 octets (Nonce GCM 96-bit)
    AesAuthTag                  BLOB NOT NULL,             -- 16 octets (Tag GCM 128-bit)
    Status                      TEXT NOT NULL CHECK (Status IN ('Quarantined', 'Restored', 'Purged')),
    QuarantinedAt               TEXT NOT NULL,
    RestoredAt                  TEXT,
    FOREIGN KEY (ScannedFileId) REFERENCES ScannedFiles(Id) ON DELETE RESTRICT
);

-- ----------------------------------------------------------------------------
-- 9. TABLE : SecurityReports
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS SecurityReports (
    Id                          TEXT PRIMARY KEY NOT NULL,
    GeneratedAt                 TEXT NOT NULL,
    ReportTitle                 TEXT NOT NULL,
    MachineName                 TEXT NOT NULL,
    TotalScannedFiles           INTEGER NOT NULL DEFAULT 0,
    TotalThreatsFound           INTEGER NOT NULL DEFAULT 0,
    TotalVulnerabilitiesFound   INTEGER NOT NULL DEFAULT 0,
    TotalUpdatesAvailable       INTEGER NOT NULL DEFAULT 0,
    PdfFilePath                 TEXT NOT NULL
);

-- ============================================================================
-- INDEX DE PERFORMANCE (B-TREE INDEXING)
-- ============================================================================
CREATE INDEX IF NOT EXISTS IX_InstalledSoftware_SessionId ON InstalledSoftware(SessionId);
CREATE INDEX IF NOT EXISTS IX_InstalledSoftware_PackageId ON InstalledSoftware(PackageIdentifier);
CREATE INDEX IF NOT EXISTS IX_InstalledSoftware_Cpe ON InstalledSoftware(CanonicalCpe);
CREATE INDEX IF NOT EXISTS IX_InstalledSoftware_DisplayName ON InstalledSoftware(DisplayName);

CREATE INDEX IF NOT EXISTS IX_SoftwareVulnerabilities_CveId ON SoftwareVulnerabilities(CveId);
CREATE INDEX IF NOT EXISTS IX_SoftwareVulnerabilities_MatchStatus ON SoftwareVulnerabilities(MatchStatus);

CREATE INDEX IF NOT EXISTS IX_ScannedFiles_SessionId ON ScannedFiles(ScanSessionId);
CREATE INDEX IF NOT EXISTS IX_ScannedFiles_Sha256 ON ScannedFiles(Sha256Hash);
CREATE INDEX IF NOT EXISTS IX_ScannedFiles_Verdict ON ScannedFiles(Verdict);

CREATE INDEX IF NOT EXISTS IX_QuarantineRecords_Sha256 ON QuarantineRecords(Sha256Hash);
CREATE INDEX IF NOT EXISTS IX_QuarantineRecords_Status ON QuarantineRecords(Status);

-- ============================================================================
-- VUES ANALYTIQUES POUR LE DASHBOARD (OPTIMISATIONS DE CONSULTATION)
-- ============================================================================

-- Vue 1 : Vulnérabilités Critiques Actives non encore corrigées
CREATE VIEW IF NOT EXISTS v_ActiveCriticalVulnerabilities AS
SELECT 
    s.DisplayName AS ApplicationName,
    s.DisplayVersion AS InstalledVersion,
    v.CveId,
    v.CvssScore,
    v.Severity,
    v.Description,
    sv.MatchStatus,
    sv.DetectedAt
FROM SoftwareVulnerabilities sv
JOIN InstalledSoftware s ON sv.SoftwareId = s.Id
JOIN Vulnerabilities v ON sv.CveId = v.CveId
WHERE v.Severity = 'Critical' AND sv.MatchStatus = 'Confirmed';

-- Vue 2 : Synthèse Globale du Dernier État de Sécurité
CREATE VIEW IF NOT EXISTS v_LatestSecuritySummary AS
SELECT 
    (SELECT COUNT(*) FROM ScannedFiles) AS TotalFilesScanned,
    (SELECT COUNT(*) FROM ScannedFiles WHERE Verdict = 'Malware') AS TotalMalwareFound,
    (SELECT COUNT(*) FROM ScannedFiles WHERE Verdict = 'Suspicious') AS TotalSuspiciousFound,
    (SELECT COUNT(*) FROM SoftwareVulnerabilities WHERE MatchStatus = 'Confirmed') AS ConfirmedVulnerabilitiesCount,
    (SELECT COUNT(*) FROM SoftwareUpdates WHERE Status = 'Available') AS PendingUpdatesCount,
    (SELECT COUNT(*) FROM QuarantineRecords WHERE Status = 'Quarantined') AS ActiveQuarantinedCount;

