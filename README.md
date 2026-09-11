# IPsec Security Analyzer (VPNGuard)

**AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework**  
**Smart India Hackathon 2026 — Problem Statement:** `SIH26160`  
**Current Status:** `Phase 7 Complete — Final Integration, Verification & SIH Demo Readiness`

### Completed Phases:
- ✅ **Phase 1:** WPF Base Desktop Application & SOC MVVM Architecture
- ✅ **Phase 2:** Real PCAP / TShark Packet Dissection Engine
- ✅ **Phase 3:** Deep IPsec / IKEv1 / IKEv2 / ESP / AH Protocol Analysis
- ✅ **Phase 4:** Deterministic Security Assessment & Modular Rules Engine
- ✅ **Phase 5:** AI-Based Traffic Classification & Behavioral Anomaly Detection
- ✅ **Phase 6:** Reports, History & SQLite Database Integration
- ✅ **Phase 7:** Final Integration, End-to-End Testing & SIH Demonstration Readiness

---

## 🛡️ Project Overview

The **IPsec Security Analyzer (VPNGuard)** is a Windows desktop cybersecurity analysis platform designed for security analysts, network engineers, and compliance auditors to inspect, decode, and evaluate IPsec VPN tunnels, IKE (Internet Key Exchange) handshakes, and Encapsulating Security Payload (ESP) parameters against modern cryptographic standards (e.g., NIST SP 800-77 Rev. 1, CNSA, RFC 7321, RFC 7296).

### Problem Statement (SIH26160)
> *"AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework"*

Modern VPN deployments often suffer from legacy cipher suites (3DES, MD5, SHA-1, DH groups < 14), missing Perfect Forward Secrecy (PFS), aggressive mode identity leaks, or unmonitored ESP replay attacks. This framework provides automated, non-invasive protocol analysis and deterministic security posture scoring.

---

## 🏗️ Architecture & Pipeline

```
Traffic Capture / PCAP (.pcap / .pcapng)
        ↓
Phase 2: TShark Packet Extraction Engine (Non-GUI, Process-Safe)
        ↓
Phase 3: Deep IKEv1/v2 Handshake & ESP Dissection (IpsecAnalysisResult)
        ↓
Phase 4: Security Assessment Engine (ISecurityAssessmentService)
        ├── Modular Security Rules (ISecurityRule)
        ├── Rule Evaluation & Deduplication
        ├── Deterministic Risk Scoring (0–100) & Risk Level Classification
        ├── Assessment Parameter Coverage Calculation (%)
        └── Actionable Remediation Guidance (SecurityRecommendation)
        ↓
WPF Security Operations Center (SOC) Desktop Dashboard
```

---

## ⚙️ Phase 4: Security Assessment Engine

Phase 4 introduces a deterministic, modular, evidence-based security evaluation engine that analyzes real [`IpsecAnalysisResult`](IPsecSecurityAnalyzer/Models/IpsecAnalysisResult.cs) data from Phase 3 without using artificial intelligence hallucinations or mock data.

### 1. Modular Security Rules

| Rule ID | Category | Severity | Description | Recommendation Summary |
|---|---|---|---|---|
| `IPSEC-IKE-001` | IKE Version | **Medium** | Detects deprecated IKEv1 protocol usage (RFC 2409). | Migrate to IKEv2 (RFC 7296) for enhanced DoS mitigation and native NAT-T. |
| `IPSEC-IKE-002` | IKE Version | **High** | Detects IKEv1 Aggressive Mode cleartext identity disclosure. | Disable Aggressive Mode immediately; use Main Mode or IKEv2. |
| `IPSEC-CRYPTO-001` | Encryption | **High / Critical** | Detects weak ciphers (3DES, DES) or unencrypted NULL transforms. | Replace with AES-256-GCM, AES-128-GCM, or AES-256-CBC. |
| `IPSEC-CRYPTO-002` | Integrity | **High / Low** | Identifies deprecated hashes (MD5, HMAC-MD5, SHA-1). | Upgrade to HMAC-SHA256, HMAC-SHA384, or use AEAD ciphers. |
| `IPSEC-CRYPTO-003` | Diffie-Hellman | **High** | Flags sub-2048-bit MODP DH groups (Group 1: 768-bit, Group 2: 1024-bit). | Upgrade DH group to at least Group 14 (2048-bit) or Group 19 (256-bit ECP). |
| `IPSEC-CONFIG-001` | PFS | **Medium** | Flags disabled Perfect Forward Secrecy on Child / Phase 2 SAs. | Enable PFS with DH Group 14+ to prevent retrospective session decryption. |
| `IPSEC-CONFIG-002` | Replay Protection | **High** | Detects duplicate sequence numbers or disabled Anti-Replay window. | Enforce IPsec ESP Anti-Replay protection and sliding window verification. |
| `IPSEC-CONFIG-003` | Key Lifetime | **Medium** | Flags excessively long SA lifetimes (> 24 hours). | Configure SA lifetime to <= 8 hours (28,800s) to limit key exposure. |
| `IPSEC-CONFIG-004` | SA Consistency | **Medium** | Flags mixed proposals offering weak fallback suites alongside modern ones. | Remove weak fallback proposals to eliminate downgrade attacks. |
| `IPSEC-COV-001` | Coverage | **Informational** | Reports unobserved parameters without generating false vulnerabilities. | Capture initial negotiation frames to achieve 100% parameter coverage. |

---

### 2. Deterministic Risk Scoring Methodology

> [!NOTE]
> **Disclaimer:** The risk score is an application-defined assessment model and is not itself an industry-standard vulnerability score (such as CVSS).

1. **Rule Weights:**
   - **Critical:** 10.0 points
   - **High:** 7.0 points
   - **Medium:** 4.0 points
   - **Low:** 2.0 points
   - **Informational:** 0.0 points
2. **Deduplication:** Findings with identical `RuleId` and `ObservedValue` are deduplicated to prevent repeated network packet frames from artificially inflating the score.
3. **Score Normalization:**
   $$\text{Raw Risk Score} = \sum \text{Finding Weights}$$
   $$\text{Overall Risk Score} = \min\left(100.0, \text{Round}\left(\frac{\text{Raw Risk Score}}{\text{Max Expected Raw Score (30.0)}} \times 100.0\right)\right)$$
   *(If all assessed parameters are clean and compliant, score is strictly 0 / 100)*.
4. **Risk Level Classification Bands:**
   - **0 – 19:** `Low`
   - **20 – 39:** `Moderate`
   - **40 – 59:** `Elevated`
   - **60 – 79:** `High`
   - **80 – 100:** `Critical`

---

### 3. Unknown Data & Assessment Coverage Handling

- **Strict No-Guessing Rule:** If a security parameter (e.g. DH Group, Encryption Cipher, PFS) cannot be observed from the packet capture (e.g. negotiation occurred prior to capture start), it is marked as `Unknown` / `Not assessable`.
- **Zero False Positives:** Unknown parameters **never** trigger false vulnerability alerts.
- **Coverage Calculation:**
  $$\text{Assessment Coverage} = \left(\frac{\text{Assessed Core Parameters}}{8}\right) \times 100\%$$
  Core parameters tracked: IKE Version, Exchange Mode, Encryption Cipher, Integrity Hash, DH Group, PFS, Replay Protection, Key Lifetime.

---

### 4. Configurable Security Policy (`SecurityPolicy`)

All cryptographic classification sets, algorithm baselines, lifetime thresholds, and risk weights are encapsulated in [`SecurityPolicy.cs`](IPsecSecurityAnalyzer/Models/SecurityPolicy.cs) to allow compliance standards (NIST, BSI, CNSA) to evolve without code changes.

---

## 🤖 Phase 5: AI-Based Traffic Classification & Anomaly Analysis

Phase 5 introduces an intelligent machine learning analysis layer for encrypted IPsec VPN traffic, extracting multi-dimensional statistical metadata features to classify traffic types and identify potential behavioral anomalies—**without decrypting ESP payloads**.

### 1. Architecture & Privacy Principles
- **Zero Payload Inspection:** Operates strictly on observable network traffic metadata (packet sizes, timing deltas, direction ratios, burst patterns, protocol headers).
- **Clear Separation of Concerns:** Direct observations (from Phase 2/3) and AI inferences are distinctly labeled. The UI always flags inferred results with `AI-Inferred Traffic Type` and `AI Confidence`.
- **Defensive Anomaly Terminology:** Potential anomalies flagged by the Isolation Forest are termed `"Potentially unusual traffic pattern"`, never labeled as definitive security incidents or attacks.
- **Fail-Safe Operation:** If Python or ML dependencies are unavailable, the application degrades gracefully and informs the user (`"Python AI environment is not configured."`) without application instability.

### 2. Extracted Traffic Features (23 Dimensions)
From packet bursts and stream sessions, `ai_engine/features.py` calculates statistical indicators:
- **Volume & Sizing:** `packet_count`, `total_bytes`, `duration_seconds`, `avg_packet_size`, `min_packet_size`, `max_packet_size`, `packet_size_std`.
- **Temporal & Rates:** `avg_inter_arrival_time`, `inter_arrival_time_std`, `packets_per_second`, `bytes_per_second`.
- **Flow & Symmetry:** `forward_packet_count`, `reverse_packet_count`, `forward_reverse_ratio`.
- **Burst Metrics:** `burst_count`, `avg_burst_size`.
- **Encapsulated Protocol Footprint:** `esp_packet_count`, `ike_packet_count`, `ah_packet_count`, `tcp_packet_count`, `udp_packet_count`.
- **Session Identity:** `unique_endpoints_count`, `unique_spi_count`.

### 3. Machine Learning Models
- **Traffic Classifier:** `RandomForestClassifier` (100 estimators, max depth 12) trained on controlled network behavior profiles:
  - *Web browsing* (asymmetric TCP bursts)
  - *VoIP* (symmetric, ~20ms interval, ~200B frames)
  - *Video streaming* (high-throughput, near-MTU download bursts)
  - *File transfer* (high bulk frame upload/download)
  - *Messaging* (infrequent, small payload exchanges)
  - *ICMP/ping* (periodic low-volume symmetric tests)
  - *Tunnel keep-alive / DPD* (periodic NAT-T keepalives)
- **Anomaly Detector:** `IsolationForest` (unsupervised outlier detection) identifying anomalous packet rate floods, severe burst variance, or unusual protocol combinations.
- **Explainability (XAI):** Gini feature importances are packaged into `model_metadata.json` and surfaced in the UI alongside confidence metrics to justify classifications.

### 4. Running the AI Engine & Tests
```powershell
# Install Python dependencies
pip install -r ai_engine/requirements.txt

# Train models on dataset
python -m ai_engine.train

# Execute Python test suite
python -m unittest discover -s ai_engine/tests
```

---

## 💾 Phase 6: Reports, History & SQLite Database Integration

Phase 6 introduces enterprise-grade persistence, audit log querying, interactive snapshot inspection, professional PDF compliance report generation, and structured JSON export.

### 1. Unified Analysis Snapshot (`AnalysisReportData`)
A single, complete, unified data model captures the entire analysis lifecycle across Phase 2, 3, 4, and 5:
- **Metadata:** Unique `AnalysisId` (GUID), analysis timestamp, application version, user notes.
- **PCAP Overview:** File name, file path, file size, capture duration, packet/byte counts.
- **Protocol Footprint:** IPsec detection flag, packet breakdown (ESP, IKE, AH, TCP, UDP, ICMP), full protocol distribution list.
- **IPsec Dissection:** IKE version, exchange type, authentication method, encryption/integrity transforms, DH group, PFS, replay protection status, SPI, SA proposals, handshakes, ESP sessions.
- **Security Assessment:** Deterministic risk score (0–100), risk level (Low to Critical), parameter coverage percentage, finding counts by severity, full findings list with evidence and remediation, prioritized recommendations.
- **AI Classification:** AI-inferred traffic type, inference confidence, behavioral anomaly status, explainability feature importance metrics.

### 2. Local SQLite Persistence (`Data/vpnguard.db`)
- **Engine:** Built with `Microsoft.EntityFrameworkCore.Sqlite` for asynchronous non-blocking I/O.
- **Database Location:** Automatically initialized at `Data/vpnguard.db` relative to the application base directory upon first launch.
- **Resilience:** Automatic database schema creation (`EnsureCreatedAsync()`), schema migration safety, zero raw PCAP payload storage (stores structured summaries and JSON snapshots).
- **Audit Logging:** Every completed PCAP analysis is automatically persisted as an audit history record without requiring manual user intervention.

### 3. Audit History & Interactive Snapshot Inspector
- **DataGrid Audit View:** Displays chronological audit records with date, PCAP name, IPsec status, IKE version, risk score, risk level, findings count, AI classification, and pattern status.
- **Search & Filtering:** Real-time multi-parameter query engine supporting text search (by file name or Analysis ID), risk level filtering (Low, Moderate, Elevated, High, Critical), IPsec traffic filter, and behavioral pattern filter.
- **Snapshot Inspection:** Click "View" on any historical record to open the detailed snapshot inspector panel—displaying complete stored findings, security coverage, and AI inferences **without re-running the PCAP capture**.
- **Management Actions:**
  - `View`: Open detailed historical analysis in the inspector panel.
  - `PDF`: Export an official PDF audit report directly from the stored snapshot.
  - `JSON`: Export the full raw JSON audit snapshot.
  - `Delete`: Remove a specific analysis record from SQLite (with user confirmation dialog; never touches original PCAP files).
  - `Purge History`: Clear all history records from SQLite database.

### 4. Professional Cybersecurity Reporting Engine (`ReportService`)
- **ISO 32000-1 (PDF 1.4) Compliant:** Generates standalone, auditor-grade PDF documents with Courier typography, formal headers, pagination, and cross-reference tables without requiring heavy external dependencies.
- **Standard 8-Section PDF Report:**
  1. *Executive Summary:* Overall risk score, risk classification, assessment coverage, IPsec status, finding counts, AI classification.
  2. *Analysis Scope & Methodology:* Clear distinction between Observed, Inferred, and Unknown parameters. Explicit notice that encrypted payloads were not decrypted.
  3. *PCAP & Traffic Overview:* Capture duration, total volume, protocol distribution footprint.
  4. *IPsec & IKE Dissection:* Observable cryptographic parameters, key lifetimes, SPIs.
  5. *Security Findings & Vulnerability Audit:* Itemized findings with rule IDs, observed values, remediation instructions, and verifiable capture evidence.
  6. *Prioritized Remediation Actions:* Ordered action items directly linked to observed findings.
  7. *AI Traffic Classification & Anomalies:* AI-inferred traffic type, confidence percentage, anomaly status, and top contributing explainability features.
  8. *Assessment Limitations & Ethical Notice:* Defensive tool boundaries and probabilistic classification disclosures.
- **JSON Audit Snapshot Export:** Exports human-readable, formatted JSON snapshots using `System.Text.Json` for SIEM integration or compliance archiving.

---

## 💻 Technology Stack

- **Platform:** Windows Desktop Application (WPF / XAML)
- **Language & Runtime:** C# 12 / .NET 8 LTS (`net8.0-windows`)
- **Architecture Pattern:** MVVM (Model-View-ViewModel) with Dependency Injection
- **Packet Dissector Engine:** TShark (Wireshark 4.x) direct process execution with safe argument handling
- **Database & ORM:** SQLite via Microsoft.EntityFrameworkCore.Sqlite 8.0.11
- **Report Engine:** Built-in ISO 32000-1 PDF document generator & System.Text.Json exporter
- **AI / ML Runtime:** Python 3.x, Scikit-learn, Pandas, NumPy, Joblib via JSON-IPC
- **Testing Framework:** Built-in Regression Test Runner (`IPsecSecurityAnalyzer.Tests`) & Python `unittest`

---

## 🚀 How to Build & Run

### Prerequisites
- Windows 10/11 (64-bit)
- .NET 8.0 SDK (`net8.0-windows`)
- Python 3.9+ with `scikit-learn`, `pandas`, `numpy`, `joblib`
- Optional: Wireshark / TShark installed (for live `.pcap` analysis)

### Build & Run Steps
1. Restore dependencies:
   ```powershell
   dotnet restore
   ```
2. Build solution in Release mode:
   ```powershell
   dotnet build -c Release IPsecSecurityAnalyzer.sln
   ```
3. Run the automated test suite (104 verification scenarios):
   ```powershell
   dotnet run --project IPsecSecurityAnalyzer.Tests/IPsecSecurityAnalyzer.Tests.csproj -c Release
   ```
4. Launch the desktop application:
   ```powershell
   dotnet run --project IPsecSecurityAnalyzer/IPsecSecurityAnalyzer.csproj -c Release
   ```

---

## 🔒 Security, Ethical Boundaries & Non-Decryption Notice

The IPsec Security Analyzer is built exclusively as a **defensive network security assessment and compliance tool**.
- **No Decryption / Cracking:** In accordance with ethical standards, the application does NOT attempt to crack, break, or decrypt encrypted ESP payloads or negotiate keys unlawfully.
- **No Fake Data:** Every metric, finding, and recommendation derives directly from verifiable packet data or rigorous statistical inference.
- **Explainable AI:** Machine learning classifications are probabilistic inferences based on traffic metadata (packet sizing, inter-arrival timing, burst rates), clearly marked with confidence metrics and feature importance.

---

## 👥 Smart India Hackathon (SIH 2026) Deliverable Summary

- **Problem Statement Code:** `SIH26160`
- **Application Version:** `v1.0.0 (SIH26160)`
- **Solution Verification:** 104 Passing Unit & Integration Tests (0 Failures, 0 Warnings)
- **Production Readiness:** Complete, self-contained, and verified for live demonstration.

