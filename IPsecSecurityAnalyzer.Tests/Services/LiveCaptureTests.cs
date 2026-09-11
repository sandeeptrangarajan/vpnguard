using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;
using IPsecSecurityAnalyzer.Services;
using IPsecSecurityAnalyzer.ViewModels;

namespace IPsecSecurityAnalyzer.Tests.Services;

/// <summary>
/// Verifies the Live Capture & Stream Analysis subsystem:
/// Interface discovery, streaming packet generation, standard PCAP binary formatting,
/// and ViewModel telemetry binding.
/// </summary>
public static class LiveCaptureTests
{
    public static async Task<(int passed, int failed)> RunAllAsync()
    {
        int passed = 0;
        int failed = 0;

        void Assert(bool condition, string testName, string? details = null)
        {
            if (condition)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("[PASS] ");
                Console.ResetColor();
                Console.WriteLine(testName);
                if (!string.IsNullOrEmpty(details))
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine($"       └─ {details}");
                    Console.ResetColor();
                }
                passed++;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write("[FAIL] ");
                Console.ResetColor();
                Console.WriteLine(testName);
                if (!string.IsNullOrEmpty(details))
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"       └─ Failure detail: {details}");
                    Console.ResetColor();
                }
                failed++;
            }
        }

        Console.WriteLine();
        Console.WriteLine("================================================================================");
        Console.WriteLine("   Live Capture & Real-Time Stream Analyzer Test Suite");
        Console.WriteLine("================================================================================");

        var liveCaptureService = new LiveCaptureService();

        // Test 1: Interface Discovery
        var ifaces = await liveCaptureService.GetAvailableInterfacesAsync();
        Assert(ifaces.Count >= 3, "LiveCapture: Interfaces discovery returns physical adapters and testbed streams", $"Count: {ifaces.Count}");
        Assert(ifaces.Any(i => i.Contains("strongSwan", StringComparison.OrdinalIgnoreCase)), "LiveCapture: strongSwan IPsec testbed stream is available");

        // Test 2: Live Stream Session Execution
        int receivedPacketsCount = 0;
        liveCaptureService.PacketReceived += (s, p) => receivedPacketsCount++;
        liveCaptureService.StatusChanged += (s, msg) => Console.WriteLine($"       [Engine Status] {msg}");

        // Run brief 1.5s stream
        var streamInterface = ifaces.First(i => i.Contains("strongSwan"));
        await liveCaptureService.StartCaptureAsync(streamInterface, TimeSpan.FromSeconds(2));
        
        // Wait 1.2 seconds while streaming
        await Task.Delay(1200);
        Assert(liveCaptureService.IsCapturing, "LiveCapture: Capture engine state is active during streaming");
        Assert(liveCaptureService.CapturedPacketsCount > 0, "LiveCapture: Packets streamed dynamically to event listeners", $"Packets: {liveCaptureService.CapturedPacketsCount}");

        // Test 3: Stop Capture & PCAP File Generation
        await liveCaptureService.StopCaptureAsync();
        Assert(!liveCaptureService.IsCapturing, "LiveCapture: Capture engine halts cleanly upon StopCaptureAsync");
        
        var pcapPath = liveCaptureService.LastCapturedPcapPath;
        Assert(!string.IsNullOrEmpty(pcapPath) && File.Exists(pcapPath), "LiveCapture: Authentic PCAP file created on disk", $"Path: {pcapPath}");

        if (File.Exists(pcapPath))
        {
            var pcapBytes = await File.ReadAllBytesAsync(pcapPath);
            Assert(pcapBytes.Length >= 24, "LiveCapture: PCAP file contains valid header size", $"Size: {pcapBytes.Length} bytes");

            // Verify Libpcap magic number 0xa1b2c3d4 (little endian: d4 c3 b2 a1)
            bool validMagic = pcapBytes[0] == 0xd4 && pcapBytes[1] == 0xc3 && pcapBytes[2] == 0xb2 && pcapBytes[3] == 0xa1;
            Assert(validMagic, "LiveCapture: Binary PCAP header conforms to libpcap 2.4 specification (Magic 0xa1b2c3d4)");
        }

        // Test 4: LiveCaptureViewModel State & Command Integration
        var vm = new LiveCaptureViewModel(liveCaptureService);
        await Task.Delay(50); // allow async LoadInterfaces
        Assert(vm.AvailableInterfaces.Count > 0, "LiveCaptureViewModel: Interfaces collection populated automatically");
        Assert(!string.IsNullOrEmpty(vm.SelectedInterface), "LiveCaptureViewModel: Initial interface selected by default");
        Assert(vm.CanStartCapture, "LiveCaptureViewModel: StartCaptureCommand is enabled for execution");
        Assert(!vm.IsCapturing, "LiveCaptureViewModel: Initial capture state is idle");

        Console.WriteLine();
        Console.WriteLine($"Live Capture Tests: {passed} passed, {failed} failed");
        return (passed, failed);
    }
}
