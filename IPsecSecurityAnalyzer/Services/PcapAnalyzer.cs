using System.Globalization;
using System.IO;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Services;

/// <summary>
/// Real PCAP / PCAPNG packet analysis engine powered by TShark packet dissection.
/// Dissects packets, parses deep IKEv1/v2 handshakes, cryptographic proposals, Nonces, DH exchanges, and ESP session streams.
/// </summary>
public class PcapAnalyzer : IPcapAnalyzer
{
    private readonly ITsharkService _tsharkService;
    private PcapFileInfo? _currentFile;
    private PcapAnalysisResult? _lastAnalysisResult;

    public PcapFileInfo? CurrentFile => _currentFile;
    public PcapAnalysisResult? LastAnalysisResult => _lastAnalysisResult;

    public event EventHandler<PcapFileInfo?>? FileChanged;
    public event EventHandler<PcapAnalysisResult?>? AnalysisCompleted;

    public PcapAnalyzer(ITsharkService tsharkService)
    {
        _tsharkService = tsharkService;
    }

    public Task<PcapFileInfo> LoadPcapFileAsync(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            throw new ArgumentException("File path cannot be empty.", nameof(filePath));
        }

        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException("The specified PCAP capture file does not exist.", filePath);
        }

        var ext = Path.GetExtension(filePath).ToLowerInvariant();
        if (ext != ".pcap" && ext != ".pcapng")
        {
            throw new NotSupportedException($"Unsupported capture file format '{ext}'. Only .pcap and .pcapng files are supported.");
        }

        var fileInfo = new FileInfo(filePath);

        _currentFile = new PcapFileInfo
        {
            FileName = fileInfo.Name,
            FilePath = fileInfo.FullName,
            FileSize = fileInfo.Length,
            FileExtension = fileInfo.Extension.ToLowerInvariant(),
            CreatedDate = fileInfo.CreationTime,
            LastModifiedDate = fileInfo.LastWriteTime
        };

        FileChanged?.Invoke(this, _currentFile);

        return Task.FromResult(_currentFile);
    }

    public async Task<PcapAnalysisResult> AnalyzeAsync(string filePath, CancellationToken cancellationToken = default)
    {
        // 1. Validation
        if (string.IsNullOrWhiteSpace(filePath))
        {
            throw new ArgumentException("Capture file path cannot be empty.", nameof(filePath));
        }

        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException("The specified PCAP capture file does not exist.", filePath);
        }

        var ext = Path.GetExtension(filePath).ToLowerInvariant();
        if (ext != ".pcap" && ext != ".pcapng")
        {
            throw new NotSupportedException($"Unsupported capture file format '{ext}'. Only .pcap and .pcapng files are supported.");
        }

        var fileInfo = new FileInfo(filePath);
        if (fileInfo.Length == 0)
        {
            throw new InvalidOperationException("The capture file is empty (0 bytes).");
        }

        // 2. Verify TShark availability
        if (!_tsharkService.IsTsharkAvailable())
        {
            throw new InvalidOperationException("TShark was not found. Install Wireshark or configure the TShark path in Settings.");
        }

        // 3. Build TShark arguments for direct extraction
        // Field extraction query using -T fields
        var arguments = new List<string>
        {
            "-r", filePath,
            "-T", "fields",
            "-E", "header=y",
            "-E", "separator=\t",
            "-E", "occurrence=f",
            "-e", "frame.number",
            "-e", "frame.time_epoch",
            "-e", "frame.len",
            "-e", "frame.protocols",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "ipv6.src",
            "-e", "ipv6.dst",
            "-e", "ip.proto",
            "-e", "ipv6.nxt",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "udp.srcport",
            "-e", "udp.dstport",
            "-e", "esp.spi",
            "-e", "esp.sequence",
            "-e", "ah.spi",
            "-e", "ah.sequence",
            "-e", "isakmp.version",
            "-e", "isakmp.exchangetype",
            "-e", "isakmp.ispi",
            "-e", "isakmp.rspi",
            "-e", "isakmp.msgid",
            "-e", "_ws.col.Protocol",
            "-e", "_ws.col.Info",
            "-e", "isakmp.payload",
            "-e", "isakmp.sa.transform.enc",
            "-e", "isakmp.sa.transform.auth",
            "-e", "isakmp.sa.transform.hash",
            "-e", "isakmp.sa.transform.dh",
            "-e", "isakmp.sa.transform.attr.keylen",
            "-e", "isakmp.sa.transform.attr.lifeduration",
            "-e", "ikev2.payload",
            "-e", "ikev2.transform.enc",
            "-e", "ikev2.transform.integ",
            "-e", "ikev2.transform.dh",
            "-e", "ikev2.transform.prf",
            "-e", "ikev2.nonce",
            "-e", "ikev2.ke.dh_group",
            "-e", "ikev2.ke.data",
            "-e", "ikev2.auth.method"
        };

        var execResult = await _tsharkService.ExecuteAsync(arguments, null, TimeSpan.FromSeconds(90), cancellationToken);

        if (execResult.IsCancelled)
        {
            throw new OperationCanceledException("Analysis cancelled by user.");
        }

        if (execResult.IsTimeout)
        {
            throw new TimeoutException("TShark execution timed out while analyzing the capture file.");
        }

        // Wireshark/TShark field names can vary slightly between releases. If the
        // deep-dissector query is rejected, retry with a conservative field set so
        // the application can still produce real packet statistics instead of failing
        // the entire analysis. IPsec-specific fields are then simply marked unknown.
        if (!execResult.IsSuccess && string.IsNullOrWhiteSpace(execResult.StandardOutput))
        {
            var fallbackArguments = new List<string>
            {
                "-r", filePath,
                "-T", "fields",
                "-E", "header=y",
                "-E", "separator=\t",
                "-E", "occurrence=f",
                "-e", "frame.number",
                "-e", "frame.time_epoch",
                "-e", "frame.len",
                "-e", "frame.protocols",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "ipv6.src",
                "-e", "ipv6.dst",
                "-e", "ip.proto",
                "-e", "ipv6.nxt",
                "-e", "udp.srcport",
                "-e", "udp.dstport",
                "-e", "tcp.srcport",
                "-e", "tcp.dstport",
                "-e", "_ws.col.Protocol",
                "-e", "_ws.col.Info"
            };

            var fallbackResult = await _tsharkService.ExecuteAsync(fallbackArguments, null, TimeSpan.FromSeconds(90), cancellationToken);
            if (fallbackResult.IsCancelled)
                throw new OperationCanceledException("Analysis cancelled by user.");
            if (fallbackResult.IsTimeout)
                throw new TimeoutException("TShark execution timed out while analyzing the capture file.");
            if (fallbackResult.IsSuccess && !string.IsNullOrWhiteSpace(fallbackResult.StandardOutput))
            {
                execResult = fallbackResult;
            }
            else
            {
                var details = string.IsNullOrWhiteSpace(fallbackResult.StandardError)
                    ? execResult.StandardError
                    : fallbackResult.StandardError;
                throw new InvalidOperationException($"TShark analysis failed. {details}".Trim());
            }
        }

        // 4. Parse extracted fields into structured result
        var result = ParseTsharkOutput(execResult.StandardOutput, fileInfo);

        _lastAnalysisResult = result;
        AnalysisCompleted?.Invoke(this, result);

        return result;
    }

    public Task<TrafficStatistics> GetTrafficStatisticsAsync()
    {
        if (_lastAnalysisResult == null)
        {
            return Task.FromResult(new TrafficStatistics());
        }

        var stats = new TrafficStatistics
        {
            TotalPackets = _lastAnalysisResult.PacketCount,
            TotalBytes = _lastAnalysisResult.TotalBytes,
            Duration = _lastAnalysisResult.Duration,
            SourceCount = _lastAnalysisResult.SourceAddresses.Count,
            DestinationCount = _lastAnalysisResult.DestinationAddresses.Count
        };

        return Task.FromResult(stats);
    }

    public static PcapAnalysisResult ParseTsharkOutput(string tsharkStdout, FileInfo fileInfo)
    {
        var result = new PcapAnalysisResult
        {
            FileName = fileInfo.Name,
            FilePath = fileInfo.FullName,
            FileSize = fileInfo.Length
        };

        if (string.IsNullOrWhiteSpace(tsharkStdout))
        {
            return result;
        }

        using var reader = new StringReader(tsharkStdout);
        var headerLine = reader.ReadLine();
        if (string.IsNullOrWhiteSpace(headerLine))
        {
            return result;
        }

        var headers = headerLine.Split('\t');
        var colMap = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < headers.Length; i++)
        {
            colMap[headers[i].Trim()] = i;
        }

        // Validate that this is indeed valid TShark field output containing known frame/packet columns
        if (!colMap.ContainsKey("frame.number") && !colMap.ContainsKey("frame.len") && !colMap.ContainsKey("ip.src"))
        {
            return result;
        }

        string GetCol(string[] cols, string colName)
        {
            if (colMap.TryGetValue(colName, out var idx) && idx < cols.Length)
            {
                return cols[idx].Trim();
            }
            return string.Empty;
        }

        double minEpoch = double.MaxValue;
        double maxEpoch = double.MinValue;
        var sourceSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var destSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Protocol counters (Name -> (Packets, Bytes))
        var protocolMap = new Dictionary<string, (long packets, long bytes)>(StringComparer.OrdinalIgnoreCase);

        // ESP Sessions Tracker (Spi -> Session Tracker)
        var espTrackerMap = new Dictionary<string, (string src, string dst, long count, long bytes, long firstSeq, long lastSeq, HashSet<long> seqSet, int dupCount)>(StringComparer.OrdinalIgnoreCase);

        void AccumulateProto(string protoName, long bytes)
        {
            if (string.IsNullOrWhiteSpace(protoName)) return;
            if (protocolMap.TryGetValue(protoName, out var val))
            {
                protocolMap[protoName] = (val.packets + 1, val.bytes + bytes);
            }
            else
            {
                protocolMap[protoName] = (1, bytes);
            }
        }

        string? line;
        long packetCount = 0;
        long totalBytes = 0;
        int proposalIndex = 1;

        while ((line = reader.ReadLine()) != null)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;

            var cols = line.Split('\t');
            packetCount++;

            // Packet number
            long.TryParse(GetCol(cols, "frame.number"), out var frameNum);
            if (frameNum <= 0) frameNum = packetCount;

            // Frame length & bytes
            long.TryParse(GetCol(cols, "frame.len"), out var frameLen);
            totalBytes += frameLen;

            // Epoch & Timestamp
            var epochStr = GetCol(cols, "frame.time_epoch");
            var timestampFormatted = "Unknown";
            if (double.TryParse(epochStr, NumberStyles.Float, CultureInfo.InvariantCulture, out var epoch))
            {
                if (epoch < minEpoch) minEpoch = epoch;
                if (epoch > maxEpoch) maxEpoch = epoch;

                try
                {
                    var dto = DateTimeOffset.FromUnixTimeMilliseconds((long)(epoch * 1000));
                    timestampFormatted = dto.ToString("yyyy-MM-dd HH:mm:ss.fff");
                }
                catch
                {
                    timestampFormatted = epoch.ToString("F3", CultureInfo.InvariantCulture);
                }
            }

            // IPs
            var ipSrc = GetCol(cols, "ip.src");
            var ipDst = GetCol(cols, "ip.dst");
            var ipv6Src = GetCol(cols, "ipv6.src");
            var ipv6Dst = GetCol(cols, "ipv6.dst");

            var srcIp = !string.IsNullOrEmpty(ipSrc) ? ipSrc : (!string.IsNullOrEmpty(ipv6Src) ? ipv6Src : "Unknown");
            var dstIp = !string.IsNullOrEmpty(ipDst) ? ipDst : (!string.IsNullOrEmpty(ipv6Dst) ? ipv6Dst : "Unknown");

            if (!string.IsNullOrEmpty(ipSrc)) sourceSet.Add(ipSrc);
            else if (!string.IsNullOrEmpty(ipv6Src)) sourceSet.Add(ipv6Src);

            if (!string.IsNullOrEmpty(ipDst)) destSet.Add(ipDst);
            else if (!string.IsNullOrEmpty(ipv6Dst)) destSet.Add(ipv6Dst);

            // Protocol tree & dissectors
            var frameProtocols = GetCol(cols, "frame.protocols").ToLowerInvariant();
            var colProto = GetCol(cols, "_ws.col.Protocol");
            var colInfo = GetCol(cols, "_ws.col.Info");
            var ipProto = GetCol(cols, "ip.proto");
            var ipv6Nxt = GetCol(cols, "ipv6.nxt");
            var udpSrc = GetCol(cols, "udp.srcport");
            var udpDst = GetCol(cols, "udp.dstport");

            // IPsec indicators
            var espSpi = GetCol(cols, "esp.spi");
            var espSeq = GetCol(cols, "esp.sequence");
            var ahSpi = GetCol(cols, "ah.spi");
            var ahSeq = GetCol(cols, "ah.sequence");

            var isakmpVer = GetCol(cols, "isakmp.version");
            var isakmpEx = GetCol(cols, "isakmp.exchangetype");
            var isakmpIspi = GetCol(cols, "isakmp.ispi");
            var isakmpRspi = GetCol(cols, "isakmp.rspi");
            var isakmpMsgid = GetCol(cols, "isakmp.msgid");

            // Phase 3 Deep fields
            var isakmpPayload = GetCol(cols, "isakmp.payload");
            var isakmpEnc = GetCol(cols, "isakmp.sa.transform.enc");
            var isakmpAuth = GetCol(cols, "isakmp.sa.transform.auth");
            var isakmpHash = GetCol(cols, "isakmp.sa.transform.hash");
            var isakmpDh = GetCol(cols, "isakmp.sa.transform.dh");
            var isakmpKeyLen = GetCol(cols, "isakmp.sa.transform.attr.keylen");
            var isakmpLife = GetCol(cols, "isakmp.sa.transform.attr.lifeduration");

            var ikev2Payload = GetCol(cols, "ikev2.payload");
            var ikev2Enc = GetCol(cols, "ikev2.transform.enc");
            var ikev2Integ = GetCol(cols, "ikev2.transform.integ");
            var ikev2Dh = GetCol(cols, "ikev2.transform.dh");
            var ikev2Prf = GetCol(cols, "ikev2.transform.prf");
            var ikev2Nonce = GetCol(cols, "ikev2.nonce");
            var ikev2KeDh = GetCol(cols, "ikev2.ke.dh_group");
            var ikev2KeData = GetCol(cols, "ikev2.ke.data");
            var ikev2Auth = GetCol(cols, "ikev2.auth.method");

            // Detect layers
            bool isIpv4 = frameProtocols.Contains("ip:") || frameProtocols.EndsWith(":ip") || !string.IsNullOrEmpty(ipSrc);
            bool isIpv6 = frameProtocols.Contains("ipv6:") || frameProtocols.EndsWith(":ipv6") || !string.IsNullOrEmpty(ipv6Src);

            if (isIpv4)
            {
                result.Ipv4PacketCount++;
                AccumulateProto("IPv4", frameLen);
            }
            if (isIpv6)
            {
                result.Ipv6PacketCount++;
                AccumulateProto("IPv6", frameLen);
            }

            bool isTcp = frameProtocols.Contains(":tcp") || colProto.Equals("TCP", StringComparison.OrdinalIgnoreCase) || ipProto == "6" || ipv6Nxt == "6";
            if (isTcp)
            {
                result.TcpPacketCount++;
                AccumulateProto("TCP", frameLen);
            }

            bool isUdp = frameProtocols.Contains(":udp") || colProto.Equals("UDP", StringComparison.OrdinalIgnoreCase) || ipProto == "17" || ipv6Nxt == "17";
            if (isUdp)
            {
                result.UdpPacketCount++;
                AccumulateProto("UDP", frameLen);
            }

            bool isIcmp = frameProtocols.Contains(":icmp") || frameProtocols.Contains(":icmpv6") || colProto.StartsWith("ICMP", StringComparison.OrdinalIgnoreCase) || ipProto == "1" || ipProto == "58" || ipv6Nxt == "58";
            if (isIcmp)
            {
                AccumulateProto("ICMP", frameLen);
            }

            // IPsec Detection
            bool isIke = frameProtocols.Contains("isakmp") || frameProtocols.Contains("ikev2") || frameProtocols.Contains("ike") ||
                         colProto.StartsWith("IKE", StringComparison.OrdinalIgnoreCase) || colProto.Equals("ISAKMP", StringComparison.OrdinalIgnoreCase) ||
                         udpSrc == "500" || udpDst == "500" || udpSrc == "4500" || udpDst == "4500" ||
                         !string.IsNullOrEmpty(isakmpVer) || !string.IsNullOrEmpty(isakmpIspi);

            bool isEsp = frameProtocols.Contains(":esp") || colProto.Equals("ESP", StringComparison.OrdinalIgnoreCase) || ipProto == "50" || ipv6Nxt == "50" || !string.IsNullOrEmpty(espSpi);
            bool isAh = frameProtocols.Contains(":ah") || colProto.Equals("AH", StringComparison.OrdinalIgnoreCase) || ipProto == "51" || ipv6Nxt == "51" || !string.IsNullOrEmpty(ahSpi);

            string primaryProtocol = !string.IsNullOrEmpty(colProto) ? colProto : "Unknown";

            if (isIke)
            {
                result.IkePacketCount++;
                result.IpsecPacketCount++;
                AccumulateProto("IKE", frameLen);

                primaryProtocol = !string.IsNullOrEmpty(colProto) ? colProto : "IKE";

                // Parse IKE parameters if observable
                if (result.IkeVersion == "Unknown" && !string.IsNullOrEmpty(isakmpVer))
                {
                    result.IkeVersion = FormatIkeVersion(isakmpVer);
                }
                else if (result.IkeVersion == "Unknown" && (colProto.Contains("IKEv2", StringComparison.OrdinalIgnoreCase) || frameProtocols.Contains("ikev2")))
                {
                    result.IkeVersion = "IKEv2";
                }
                else if (result.IkeVersion == "Unknown" && (colProto.Contains("ISAKMP", StringComparison.OrdinalIgnoreCase) || colProto.Contains("IKEv1", StringComparison.OrdinalIgnoreCase)))
                {
                    result.IkeVersion = "IKEv1";
                }

                if (result.IkeExchangeType == "Unknown" && !string.IsNullOrEmpty(isakmpEx))
                {
                    result.IkeExchangeType = FormatIkeExchangeType(isakmpEx);
                }

                if (result.IkeInitiatorSpi == "Unknown" && !string.IsNullOrEmpty(isakmpIspi))
                {
                    result.IkeInitiatorSpi = isakmpIspi;
                }

                if ((result.IkeResponderSpi == "Unknown" || result.IkeResponderSpi == "0000000000000000" || result.IkeResponderSpi == "0x0000000000000000") &&
                    !string.IsNullOrEmpty(isakmpRspi) &&
                    isakmpRspi != "0000000000000000" &&
                    isakmpRspi != "0x0000000000000000")
                {
                    result.IkeResponderSpi = isakmpRspi;
                }
                else if (result.IkeResponderSpi == "Unknown" && !string.IsNullOrEmpty(isakmpRspi))
                {
                    result.IkeResponderSpi = isakmpRspi;
                }

                if (result.IkeMessageId == "Unknown" && !string.IsNullOrEmpty(isakmpMsgid))
                {
                    result.IkeMessageId = isakmpMsgid;
                }

                // Phase 3: Aggressive Mode check
                if (isakmpEx == "4" || colInfo.Contains("Aggressive", StringComparison.OrdinalIgnoreCase))
                {
                    result.AggressiveModeDetected = true;
                }

                // Phase 3: Nonce & Key Exchange observation
                bool hasNonce = !string.IsNullOrEmpty(ikev2Nonce) || colInfo.Contains("Nonce", StringComparison.OrdinalIgnoreCase) || colInfo.Contains("Ni", StringComparison.OrdinalIgnoreCase) || colInfo.Contains("Nr", StringComparison.OrdinalIgnoreCase);
                if (hasNonce) result.NonceObserved = true;

                bool hasKe = !string.IsNullOrEmpty(ikev2KeDh) || !string.IsNullOrEmpty(ikev2KeData) || colInfo.Contains("Key Exchange", StringComparison.OrdinalIgnoreCase) || colInfo.Contains("KE", StringComparison.OrdinalIgnoreCase);
                if (hasKe) result.KeyExchangePayloadObserved = true;

                var observedDh = !string.IsNullOrEmpty(ikev2KeDh) ? FormatDhGroup(ikev2KeDh) : (!string.IsNullOrEmpty(isakmpDh) ? FormatDhGroup(isakmpDh) : (!string.IsNullOrEmpty(ikev2Dh) ? FormatDhGroup(ikev2Dh) : "None"));

                // Phase 3: Perfect Forward Secrecy (PFS) Detection in Child SA / Quick Mode
                bool isChildSaOrQuickMode = isakmpEx == "32" || isakmpEx == "36" || colInfo.Contains("Quick Mode", StringComparison.OrdinalIgnoreCase) || colInfo.Contains("CREATE_CHILD_SA", StringComparison.OrdinalIgnoreCase);
                if (isChildSaOrQuickMode)
                {
                    if (hasKe || observedDh != "None")
                    {
                        result.PfsEnabled = true;
                    }
                    else if (!result.PfsEnabled.HasValue)
                    {
                        result.PfsEnabled = false;
                    }
                }

                // Add Handshake record
                var exchangeTypeName = !string.IsNullOrEmpty(isakmpEx) ? FormatIkeExchangeType(isakmpEx) : (!string.IsNullOrEmpty(colInfo) ? colInfo : "IKE Exchange");
                var payloadsSummary = FormatPayloads(!string.IsNullOrEmpty(ikev2Payload) ? ikev2Payload : isakmpPayload, colInfo);

                result.Handshakes.Add(new IkeExchangeInfo
                {
                    PacketNumber = frameNum,
                    Timestamp = timestampFormatted,
                    Source = srcIp,
                    Destination = dstIp,
                    Version = result.IkeVersion != "Unknown" ? result.IkeVersion : "IKE",
                    ExchangeType = exchangeTypeName,
                    InitiatorSpi = !string.IsNullOrEmpty(isakmpIspi) ? isakmpIspi : "Unknown",
                    ResponderSpi = !string.IsNullOrEmpty(isakmpRspi) ? isakmpRspi : "0000000000000000",
                    MessageId = !string.IsNullOrEmpty(isakmpMsgid) ? isakmpMsgid : "0",
                    PayloadsSummary = payloadsSummary,
                    HasKeyExchange = hasKe,
                    DhGroup = observedDh,
                    HasNonce = hasNonce,
                    IsAggressiveMode = isakmpEx == "4" || colInfo.Contains("Aggressive", StringComparison.OrdinalIgnoreCase),
                    PfsDetected = result.PfsEnabled == true
                });

                // Phase 3: Extract SA Proposal & Transforms
                var encVal = !string.IsNullOrEmpty(ikev2Enc) ? ikev2Enc : isakmpEnc;
                var integVal = !string.IsNullOrEmpty(ikev2Integ) ? ikev2Integ : isakmpHash;
                var authVal = !string.IsNullOrEmpty(ikev2Auth) ? ikev2Auth : isakmpAuth;
                var dhVal = !string.IsNullOrEmpty(ikev2Dh) ? ikev2Dh : (!string.IsNullOrEmpty(ikev2KeDh) ? ikev2KeDh : isakmpDh);
                var prfVal = !string.IsNullOrEmpty(ikev2Prf) ? ikev2Prf : "";

                if (!string.IsNullOrEmpty(encVal) || !string.IsNullOrEmpty(integVal) || !string.IsNullOrEmpty(dhVal) || !string.IsNullOrEmpty(authVal))
                {
                    var parsedEnc = FormatEncryption(encVal, isakmpKeyLen);
                    var parsedInteg = FormatIntegrity(integVal);
                    var parsedDh = FormatDhGroup(dhVal);
                    var parsedAuth = FormatAuthMethod(authVal);
                    var parsedPrf = FormatPrf(prfVal);

                    bool isWeakSuite = parsedEnc.Contains("DES") || parsedInteg.Contains("MD5") || parsedInteg.Contains("SHA1") || parsedDh.Contains("Insecure") || parsedDh.Contains("Weak");

                    result.SaProposals.Add(new IkeSaProposal
                    {
                        ProposalNumber = proposalIndex++,
                        Protocol = result.IkeVersion != "Unknown" ? result.IkeVersion : "IKE",
                        Spi = !string.IsNullOrEmpty(isakmpIspi) ? isakmpIspi : "Unknown",
                        EncryptionAlgorithm = parsedEnc,
                        IntegrityAlgorithm = parsedInteg,
                        DhGroup = parsedDh,
                        PrfAlgorithm = parsedPrf,
                        AuthenticationMethod = parsedAuth,
                        KeyLength = !string.IsNullOrEmpty(isakmpKeyLen) ? $"{isakmpKeyLen} bits" : "Default",
                        LifeDuration = !string.IsNullOrEmpty(isakmpLife) ? $"{isakmpLife} seconds" : "Default / Unspecified",
                        IsWeak = isWeakSuite
                    });

                    if (result.EncryptionAlgorithm == "Unknown" && parsedEnc != "Unknown") result.EncryptionAlgorithm = parsedEnc;
                    if (result.IntegrityAlgorithm == "Unknown" && parsedInteg != "Unknown") result.IntegrityAlgorithm = parsedInteg;
                    if (result.DhGroup == "Unknown" && parsedDh != "Unknown") result.DhGroup = parsedDh;
                    if (result.AuthenticationMethod == "Unknown" && parsedAuth != "Unknown") result.AuthenticationMethod = parsedAuth;
                    if (result.PrfAlgorithm == "Unknown" && parsedPrf != "Unknown") result.PrfAlgorithm = parsedPrf;
                }

                result.IpsecPackets.Add(new IpsecPacketInfo
                {
                    PacketNumber = frameNum,
                    Timestamp = timestampFormatted,
                    Source = srcIp,
                    Destination = dstIp,
                    Protocol = primaryProtocol,
                    Spi = !string.IsNullOrEmpty(isakmpIspi) ? isakmpIspi : "Unknown",
                    SequenceNumber = !string.IsNullOrEmpty(isakmpMsgid) ? isakmpMsgid : "Unknown",
                    Length = frameLen,
                    Info = !string.IsNullOrEmpty(colInfo) ? colInfo : "IKE Handshake / Message"
                });
            }
            else if (isEsp)
            {
                result.EspPacketCount++;
                result.IpsecPacketCount++;
                AccumulateProto("ESP", frameLen);

                primaryProtocol = "ESP";

                if (result.EspSpi == "Unknown" && !string.IsNullOrEmpty(espSpi))
                {
                    result.EspSpi = espSpi;
                }

                // Phase 3: Track ESP session and sequence numbers
                long.TryParse(espSeq, out var seqNum);
                var sessionKey = !string.IsNullOrEmpty(espSpi) ? espSpi : $"{srcIp}->{dstIp}";

                if (espTrackerMap.TryGetValue(sessionKey, out var sess))
                {
                    int dups = sess.dupCount;
                    if (sess.seqSet.Contains(seqNum) && seqNum > 0)
                    {
                        dups++;
                    }
                    else if (seqNum > 0)
                    {
                        sess.seqSet.Add(seqNum);
                    }

                    long first = sess.firstSeq;
                    long last = seqNum > sess.lastSeq ? seqNum : sess.lastSeq;

                    espTrackerMap[sessionKey] = (srcIp, dstIp, sess.count + 1, sess.bytes + frameLen, first, last, sess.seqSet, dups);
                }
                else
                {
                    var set = new HashSet<long>();
                    if (seqNum > 0) set.Add(seqNum);
                    espTrackerMap[sessionKey] = (srcIp, dstIp, 1, frameLen, seqNum > 0 ? seqNum : 1, seqNum > 0 ? seqNum : 1, set, 0);
                }

                result.IpsecPackets.Add(new IpsecPacketInfo
                {
                    PacketNumber = frameNum,
                    Timestamp = timestampFormatted,
                    Source = srcIp,
                    Destination = dstIp,
                    Protocol = "ESP",
                    Spi = !string.IsNullOrEmpty(espSpi) ? espSpi : "Unknown",
                    SequenceNumber = !string.IsNullOrEmpty(espSeq) ? espSeq : "Unknown",
                    Length = frameLen,
                    Info = !string.IsNullOrEmpty(colInfo) ? colInfo : $"ESP Packet (SPI={espSpi}, SEQ={espSeq})"
                });
            }
            else if (isAh)
            {
                result.AhPacketCount++;
                result.IpsecPacketCount++;
                AccumulateProto("AH", frameLen);

                primaryProtocol = "AH";

                result.IpsecPackets.Add(new IpsecPacketInfo
                {
                    PacketNumber = frameNum,
                    Timestamp = timestampFormatted,
                    Source = srcIp,
                    Destination = dstIp,
                    Protocol = "AH",
                    Spi = !string.IsNullOrEmpty(ahSpi) ? ahSpi : "Unknown",
                    SequenceNumber = !string.IsNullOrEmpty(ahSeq) ? ahSeq : "Unknown",
                    Length = frameLen,
                    Info = !string.IsNullOrEmpty(colInfo) ? colInfo : $"AH Packet (SPI={ahSpi}, SEQ={ahSeq})"
                });
            }
            else if (!string.IsNullOrEmpty(colProto) && !colProto.Equals("TCP", StringComparison.OrdinalIgnoreCase) && !colProto.Equals("UDP", StringComparison.OrdinalIgnoreCase) && !colProto.Equals("IPv4", StringComparison.OrdinalIgnoreCase) && !colProto.Equals("IPv6", StringComparison.OrdinalIgnoreCase))
            {
                AccumulateProto(colProto, frameLen);
            }

            result.PacketDetails.Add(new PacketInfo
            {
                PacketNumber = frameNum,
                Timestamp = timestampFormatted,
                Epoch = epoch,
                Source = srcIp,
                Destination = dstIp,
                Protocol = primaryProtocol,
                Length = frameLen,
                Info = !string.IsNullOrEmpty(colInfo) ? colInfo : $"{primaryProtocol} traffic",
                Spi = !string.IsNullOrEmpty(espSpi) ? espSpi : (!string.IsNullOrEmpty(ahSpi) ? ahSpi : isakmpIspi)
            });
        }

        // Build Phase 3 ESP Sessions list
        foreach (var kvp in espTrackerMap)
        {
            var val = kvp.Value;
            int totalExpected = (int)(val.lastSeq - val.firstSeq + 1);
            int gaps = totalExpected > val.seqSet.Count && totalExpected > 0 ? totalExpected - val.seqSet.Count : 0;

            result.EspSessions.Add(new EspSessionInfo
            {
                Spi = kvp.Key,
                Source = val.src,
                Destination = val.dst,
                PacketCount = val.count,
                TotalBytes = val.bytes,
                FirstSequence = val.firstSeq,
                LastSequence = val.lastSeq,
                DuplicateSequences = val.dupCount,
                SequenceGaps = gaps,
                Mode = "Tunnel (ESP)"
            });
        }

        if (result.EspSessions.Count > 0)
        {
            result.ReplayProtectionEnabled = !result.EspSessions.Any(s => s.DuplicateSequences > 0);
        }

        result.PacketCount = packetCount;
        result.TotalBytes = totalBytes;
        result.SourceAddresses = sourceSet.OrderBy(x => x).ToList();
        result.DestinationAddresses = destSet.OrderBy(x => x).ToList();

        if (minEpoch != double.MaxValue && maxEpoch != double.MinValue && maxEpoch >= minEpoch)
        {
            result.Duration = TimeSpan.FromSeconds(maxEpoch - minEpoch);
            try
            {
                result.FirstPacketTimestamp = DateTimeOffset.FromUnixTimeMilliseconds((long)(minEpoch * 1000)).ToString("yyyy-MM-dd HH:mm:ss.fff");
                result.LastPacketTimestamp = DateTimeOffset.FromUnixTimeMilliseconds((long)(maxEpoch * 1000)).ToString("yyyy-MM-dd HH:mm:ss.fff");
            }
            catch
            {
                result.FirstPacketTimestamp = minEpoch.ToString(CultureInfo.InvariantCulture);
                result.LastPacketTimestamp = maxEpoch.ToString(CultureInfo.InvariantCulture);
            }
        }

        // Calculate protocol statistics
        var statsList = new List<ProtocolStatistics>();
        foreach (var kvp in protocolMap.OrderByDescending(p => p.Value.packets))
        {
            statsList.Add(new ProtocolStatistics
            {
                ProtocolName = kvp.Key,
                PacketCount = kvp.Value.packets,
                ByteCount = kvp.Value.bytes,
                Percentage = packetCount > 0 ? (double)kvp.Value.packets / packetCount * 100.0 : 0.0
            });
        }
        result.Protocols = statsList;

        return result;
    }

    public static string FormatIkeVersion(string ver)
    {
        var trimmed = ver.Trim();
        if (trimmed.Equals("0x10", StringComparison.OrdinalIgnoreCase) || trimmed.Equals("16") || trimmed.Equals("1.0") || trimmed.Equals("1"))
            return "IKEv1";
        if (trimmed.Equals("0x20", StringComparison.OrdinalIgnoreCase) || trimmed.Equals("32") || trimmed.Equals("2.0") || trimmed.Equals("2"))
            return "IKEv2";
        return trimmed;
    }

    public static string FormatIkeExchangeType(string ex)
    {
        var trimmed = ex.Trim();
        return trimmed switch
        {
            "34" or "0x22" => "IKE_SA_INIT (34)",
            "35" or "0x23" => "IKE_AUTH (35)",
            "36" or "0x24" => "CREATE_CHILD_SA (36)",
            "37" or "0x25" => "INFORMATIONAL (37)",
            "2" => "Identity Protection / Main Mode (2)",
            "4" => "Aggressive Mode (4)",
            "5" => "Informational (5)",
            "32" => "Quick Mode (32)",
            _ => trimmed
        };
    }

    public static string FormatEncryption(string enc, string? keyLen)
    {
        var trimmed = enc.Trim();
        var lenStr = !string.IsNullOrWhiteSpace(keyLen) ? $" ({keyLen}-bit)" : "";

        return trimmed.ToLowerInvariant() switch
        {
            "1" or "0x0001" or "des" or "des-cbc" => "DES-CBC (56-bit - Insecure)",
            "5" or "0x0005" or "3des" or "3des-cbc" or "tripledes-cbc" => "3DES-CBC (192-bit - Legacy)",
            "7" or "0x0007" or "aes" or "aes-cbc" => $"AES-CBC{(string.IsNullOrEmpty(lenStr) ? " (256/128-bit)" : lenStr)}",
            "12" or "0x000c" or "aes-ctr" => $"AES-CTR{lenStr}",
            "20" or "0x0014" or "aes-gcm" or "aes-gcm-16" => $"AES-GCM-16{(string.IsNullOrEmpty(lenStr) ? " (256/128-bit)" : lenStr)}",
            "28" or "chacha20-poly1305" => "ChaCha20-Poly1305 (256-bit)",
            "" => "Unknown",
            _ => !string.IsNullOrEmpty(lenStr) ? $"{trimmed}{lenStr}" : trimmed
        };
    }

    public static string FormatIntegrity(string integ)
    {
        var trimmed = integ.Trim();
        return trimmed.ToLowerInvariant() switch
        {
            "1" or "md5" or "hmac-md5" => "HMAC-MD5-96 (Insecure)",
            "2" or "sha1" or "hmac-sha1" or "sha-1" => "HMAC-SHA1-96 (Weak)",
            "12" or "sha256" or "sha2-256" or "hmac-sha256" => "HMAC-SHA256-128 (Strong)",
            "13" or "sha384" or "sha2-384" or "hmac-sha384" => "HMAC-SHA384-192 (Strong)",
            "14" or "sha512" or "sha2-512" or "hmac-sha512" => "HMAC-SHA512-256 (Strong)",
            "" => "Unknown",
            _ => trimmed
        };
    }

    public static string FormatDhGroup(string dh)
    {
        var trimmed = dh.Trim();
        return trimmed.ToLowerInvariant() switch
        {
            "1" or "group 1" or "modp-768" => "Group 1 (768-bit MODP - Insecure)",
            "2" or "group 2" or "modp-1024" => "Group 2 (1024-bit MODP - Insecure)",
            "5" or "group 5" or "modp-1536" => "Group 5 (1536-bit MODP - Insecure)",
            "14" or "group 14" or "modp-2048" => "Group 14 (2048-bit MODP - NIST Compliant)",
            "15" or "group 15" or "modp-3072" => "Group 15 (3072-bit MODP - Strong)",
            "16" or "group 16" or "modp-4096" => "Group 16 (4096-bit MODP - Strong)",
            "19" or "group 19" or "ecp-256" => "Group 19 (256-bit ECP - Strong)",
            "20" or "group 20" or "ecp-384" => "Group 20 (384-bit ECP - Strong)",
            "21" or "group 21" or "ecp-521" => "Group 21 (521-bit ECP - Strong)",
            "31" or "curve25519" => "Group 31 (Curve25519 - Strong)",
            "" or "0" or "none" => "None",
            _ => trimmed
        };
    }

    public static string FormatAuthMethod(string auth)
    {
        var trimmed = auth.Trim();
        return trimmed.ToLowerInvariant() switch
        {
            "1" or "psk" or "pre-shared" => "Pre-Shared Key (PSK)",
            "2" or "dss" => "DSS Signatures",
            "3" or "rsa" or "rsa-sig" => "RSA Digital Signature",
            "9" or "ecdsa-256" => "ECDSA (P-256)",
            "10" or "ecdsa-384" => "ECDSA (P-384)",
            "11" or "ecdsa-521" => "ECDSA (P-521)",
            "" => "Unknown",
            _ => trimmed
        };
    }

    public static string FormatPrf(string prf)
    {
        var trimmed = prf.Trim();
        return trimmed.ToLowerInvariant() switch
        {
            "1" => "PRF-HMAC-MD5 (Weak)",
            "2" => "PRF-HMAC-SHA1 (Weak)",
            "4" => "PRF-HMAC-SHA2-256 (Strong)",
            "5" => "PRF-HMAC-SHA2-384 (Strong)",
            "6" => "PRF-HMAC-SHA2-512 (Strong)",
            "" => "Unknown",
            _ => trimmed
        };
    }

    public static string FormatPayloads(string rawPayloads, string info)
    {
        if (!string.IsNullOrWhiteSpace(rawPayloads))
        {
            var items = rawPayloads.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries);
            var names = new List<string>();
            foreach (var item in items)
            {
                var t = item.Trim();
                var friendly = t switch
                {
                    "1" or "sa" => "SA",
                    "2" => "Proposal",
                    "3" => "Transform",
                    "4" or "ke" => "Key Exchange (KE)",
                    "5" or "id" or "idi" or "idr" => "Identification (ID)",
                    "6" or "cert" => "Certificate (CERT)",
                    "7" or "cr" => "Cert Request (CR)",
                    "8" or "hash" => "Hash (HASH)",
                    "9" or "sig" => "Signature (SIG)",
                    "10" or "nonce" or "ni" or "nr" => "Nonce (Ni/Nr)",
                    "11" or "notify" or "notification" => "Notify (N)",
                    "12" or "delete" => "Delete (D)",
                    "13" or "vid" => "Vendor ID (VID)",
                    "33" or "sk" or "encrypted" => "Encrypted (SK)",
                    "43" or "eap" => "EAP",
                    _ => t
                };
                if (!names.Contains(friendly)) names.Add(friendly);
            }
            if (names.Count > 0) return string.Join(", ", names);
        }

        if (!string.IsNullOrWhiteSpace(info))
        {
            var parts = new List<string>();
            if (info.Contains("SA", StringComparison.OrdinalIgnoreCase)) parts.Add("SA");
            if (info.Contains("KE", StringComparison.OrdinalIgnoreCase) || info.Contains("Key Exchange", StringComparison.OrdinalIgnoreCase)) parts.Add("KE");
            if (info.Contains("Nonce", StringComparison.OrdinalIgnoreCase) || info.Contains("Ni", StringComparison.OrdinalIgnoreCase) || info.Contains("Nr", StringComparison.OrdinalIgnoreCase)) parts.Add("Nonce");
            if (info.Contains("AUTH", StringComparison.OrdinalIgnoreCase)) parts.Add("AUTH");
            if (info.Contains("ID", StringComparison.OrdinalIgnoreCase)) parts.Add("ID");
            if (info.Contains("CERT", StringComparison.OrdinalIgnoreCase)) parts.Add("CERT");
            if (info.Contains("Notify", StringComparison.OrdinalIgnoreCase)) parts.Add("Notify");
            if (parts.Count > 0) return string.Join(", ", parts);
        }

        return "Header";
    }
}
