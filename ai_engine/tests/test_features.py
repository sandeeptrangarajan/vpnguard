import unittest
from ai_engine.features import extract_features_from_packets, FEATURE_NAMES, dict_to_feature_vector

class TestFeatures(unittest.TestCase):
    def test_empty_packets(self):
        feat = extract_features_from_packets([])
        self.assertIsInstance(feat, dict)
        for name in FEATURE_NAMES:
            self.assertIn(name, feat)
            self.assertEqual(feat[name], 0.0)

    def test_sample_packets(self):
        packets = [
            {"length": 100, "timestamp_epoch": 1000.0, "source": "192.168.1.1", "destination": "10.0.0.1", "protocol": "ESP", "spi": "0x12345678"},
            {"length": 200, "timestamp_epoch": 1000.02, "source": "10.0.0.1", "destination": "192.168.1.1", "protocol": "ESP", "spi": "0x87654321"},
            {"length": 150, "timestamp_epoch": 1000.04, "source": "192.168.1.1", "destination": "10.0.0.1", "protocol": "ESP", "spi": "0x12345678"}
        ]
        feat = extract_features_from_packets(packets)
        self.assertEqual(feat["packet_count"], 3.0)
        self.assertEqual(feat["total_bytes"], 450.0)
        self.assertEqual(feat["esp_packet_count"], 3.0)
        self.assertEqual(feat["min_packet_size"], 100.0)
        self.assertEqual(feat["max_packet_size"], 200.0)
        self.assertAlmostEqual(feat["avg_packet_size"], 150.0)
        self.assertEqual(feat["unique_spi_count"], 2.0)

    def test_dict_to_feature_vector(self):
        feat = extract_features_from_packets([])
        vec = dict_to_feature_vector(feat)
        self.assertEqual(len(vec), len(FEATURE_NAMES))

if __name__ == "__main__":
    unittest.main()
