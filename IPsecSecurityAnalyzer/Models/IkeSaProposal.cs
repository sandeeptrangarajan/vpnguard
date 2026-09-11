namespace IPsecSecurityAnalyzer.Models;

/// <summary>
/// Represents an observed IKEv1 or IKEv2 Security Association proposal transform suite.
/// </summary>
public class IkeSaProposal
{
    public int ProposalNumber { get; set; } = 1;
    public string Protocol { get; set; } = "IKE";
    public string Spi { get; set; } = "Unknown";
    public string EncryptionAlgorithm { get; set; } = "Unknown";
    public string IntegrityAlgorithm { get; set; } = "Unknown";
    public string DhGroup { get; set; } = "Unknown";
    public string PrfAlgorithm { get; set; } = "Unknown";
    public string AuthenticationMethod { get; set; } = "Unknown";
    public string KeyLength { get; set; } = "Default";
    public string LifeDuration { get; set; } = "Default / Unspecified";
    public bool IsWeak { get; set; } = false;
    public string SecurityRating => IsWeak ? "Legacy / Insecure" : "Compliant / Strong";
}
