import unittest
from ai_engine.infer import run_inference

class TestInference(unittest.TestCase):
    def test_run_inference_empty(self):
        res = run_inference([])
        self.assertTrue(res["IsModelConnected"])
        self.assertIn("TrafficType", res)
        self.assertIn("Prediction", res)
        self.assertIn("Confidence", res)
        self.assertIn("Features", res)
        self.assertIn("Explanation", res)
        self.assertIn("TopFeatures", res)
        self.assertGreater(len(res["TopFeatures"]), 0)

    def test_run_inference_with_packets(self):
        packets = [
            {"length": 200, "timestamp_epoch": 1000.0, "source": "192.168.1.1", "destination": "10.0.0.1", "protocol": "ESP", "spi": "0x11111111"},
            {"length": 200, "timestamp_epoch": 1000.02, "source": "10.0.0.1", "destination": "192.168.1.1", "protocol": "ESP", "spi": "0x22222222"},
        ]
        res = run_inference(packets)
        self.assertTrue(res["IsModelConnected"])
        self.assertIsInstance(res["Confidence"], float)
        self.assertGreaterEqual(res["Confidence"], 0.0)
        self.assertLessEqual(res["Confidence"], 1.0)

if __name__ == "__main__":
    unittest.main()
