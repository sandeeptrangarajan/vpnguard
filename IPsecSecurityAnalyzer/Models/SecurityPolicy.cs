namespace IPsecSecurityAnalyzer.Models;

/// <summary>
/// Configurable security policy defining algorithm classifications, thresholds, and risk score weights.
/// Prevents hardcoded security thresholds across the codebase and allows policy evolution.
/// </summary>
public class SecurityPolicy
{
    public string PolicyName { get; set; } = "NIST / BSI IPsec Security Baseline";
    public string PolicyVersion { get; set; } = "1.0.0";

    // IKE Version Policy
    public HashSet<string> WeakIkeVersions { get; set; } = new(StringComparer.OrdinalIgnoreCase)
    {
        "IKEv1", "ISAKMP"
    };

    // Encryption Algorithm Policy
    public HashSet<string> PreferredEncryptionAlgorithms { get; set; } = new(StringComparer.OrdinalIgnoreCase)
    {
        "AES-GCM", "AES-256-GCM", "AES-128-GCM", "AES-GCM-256", "AES-GCM-128", "ChaCha20-Poly1305"
    };

    public HashSet<string> AcceptableEncryptionAlgorithms { get; set; } = new(StringComparer.OrdinalIgnoreCase)
    {
        "AES-CBC", "AES-CBC-256", "AES-CBC-128", "AES-CBC-192", "AES-256", "AES-128", "AES-192", "AES-CTR", "Camellia"
    };

    public HashSet<string> WeakEncryptionAlgorithms { get; set; } = new(StringComparer.OrdinalIgnoreCase)
    {
        "3DES", "3DES-CBC", "DES", "DES-CBC", "RC4", "IDEA", "Blowfish", "NULL", "None"
    };

    // Integrity / Authentication Algorithm Policy
    public HashSet<string> PreferredIntegrityAlgorithms { get; set; } = new(StringComparer.OrdinalIgnoreCase)
    {
        "HMAC-SHA256", "HMAC-SHA256-128", "HMAC-SHA384", "HMAC-SHA384-192", "HMAC-SHA512", "HMAC-SHA512-256",
        "SHA256", "SHA384", "SHA512", "AES-GMAC", "None (AEAD Combined)", "AEAD"
    };

    public HashSet<string> AcceptableIntegrityAlgorithms { get; set; } = new(StringComparer.OrdinalIgnoreCase)
    {
        "HMAC-SHA1", "HMAC-SHA1-96", "SHA1"
    };

    public HashSet<string> WeakIntegrityAlgorithms { get; set; } = new(StringComparer.OrdinalIgnoreCase)
    {
        "MD5", "HMAC-MD5", "HMAC-MD5-96", "NULL", "None"
    };

    // Diffie-Hellman Group Policy
    public HashSet<int> PreferredDhGroups { get; set; } = new()
    {
        14, 15, 16, 17, 18, 19, 20, 21, 27, 28, 29, 30, 31, 32
    };

    public HashSet<int> AcceptableDhGroups { get; set; } = new()
    {
        5, 14
    };

    public HashSet<int> WeakDhGroups { get; set; } = new()
    {
        1, 2
    };

    // Configuration Requirements
    public bool RequirePfs { get; set; } = true;
    public bool RequireReplayProtection { get; set; } = true;
    public long MaxRecommendedKeyLifetimeSeconds { get; set; } = 28800; // 8 hours
    public long MaxAcceptableKeyLifetimeSeconds { get; set; } = 86400; // 24 hours

    // Risk Scoring Weights
    public double CriticalWeight { get; set; } = 10.0;
    public double HighWeight { get; set; } = 7.0;
    public double MediumWeight { get; set; } = 4.0;
    public double LowWeight { get; set; } = 2.0;
    public double InformationalWeight { get; set; } = 0.0;

    // Normalization scale factor
    public double MaxExpectedRawScore { get; set; } = 30.0;

    // Risk Classification Thresholds (Application-Defined Model)
    public double LowThresholdMax { get; set; } = 19.0;
    public double ModerateThresholdMax { get; set; } = 39.0;
    public double ElevatedThresholdMax { get; set; } = 59.0;
    public double HighThresholdMax { get; set; } = 79.0;
}
