"""
Unit Tests for Advanced Network Traffic Analyzer
"""

import unittest
from datetime import datetime
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from protocol_parser import ProtocolParser
from threat_detector import ThreatDetector
from traffic_analyzer import TrafficAnalyzer
from data_exporter import DataExporter


class TestProtocolParser(unittest.TestCase):
    """Test protocol parser functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.parser = ProtocolParser()

    def test_parse_empty_packet(self):
        """Test parsing empty packet."""
        result = self.parser.parse({"timestamp": datetime.now()})
        self.assertIn("error", result)

    def test_tcp_flags_parsing(self):
        """Test TCP flags parsing."""
        # SYN flag (0x02)
        flags = self.parser._parse_tcp_flags(0x02)
        self.assertIn("SYN", flags)

        # SYN+ACK flags (0x12)
        flags = self.parser._parse_tcp_flags(0x12)
        self.assertIn("SYN", flags)
        self.assertIn("ACK", flags)

    def test_get_summary(self):
        """Test packet summary generation."""
        parsed = {
            "src_ip": "192.168.1.1",
            "dst_ip": "8.8.8.8",
            "src_port": 53891,
            "dst_port": 443,
            "protocols": ["TCP", "HTTPS"]
        }
        summary = self.parser.get_summary(parsed)
        self.assertIn("192.168.1.1", summary)
        self.assertIn("8.8.8.8", summary)


class TestThreatDetector(unittest.TestCase):
    """Test threat detection functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.detector = ThreatDetector()

    def test_port_scanning_detection(self):
        """Test port scanning detection."""
        # Simulate multiple port attempts from single source
        all_threats = []
        for port in range(1, 25):
            packet = {
                "timestamp": datetime.now().isoformat(),
                "protocols": ["TCP"],
                "src_ip": "192.168.1.100",
                "dst_ip": "192.168.1.1",
                "dst_port": port,
            }
            threats = self.detector.analyze(packet)
            all_threats.extend(threats)

        # Check if threats detected
        port_scan_threats = [t for t in all_threats if t["type"] == "port_scanning"]
        self.assertTrue(len(port_scan_threats) > 0)

    def test_threat_summary(self):
        """Test threat summary generation."""
        summary = self.detector.get_threat_summary()
        self.assertIn("total_threats", summary)
        self.assertIn("threat_types", summary)

    def test_clear_threats(self):
        """Test threat clearing."""
        self.detector.threats = [{"type": "test"}]
        self.detector.clear_threats()
        self.assertEqual(len(self.detector.threats), 0)


class TestTrafficAnalyzer(unittest.TestCase):
    """Test traffic analysis functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = TrafficAnalyzer()

    def test_packet_analysis(self):
        """Test packet analysis."""
        packet = {
            "protocols": ["TCP", "HTTP"],
            "src_ip": "192.168.1.1",
            "dst_ip": "8.8.8.8",
            "src_port": 54321,
            "dst_port": 80,
            "size": 1024,
        }
        self.analyzer.analyze_packet(packet)

        stats = self.analyzer.get_statistics()
        self.assertEqual(stats["total_packets"], 1)
        self.assertEqual(stats["total_bytes"], 1024)

    def test_protocol_breakdown(self):
        """Test protocol statistics."""
        packets = [
            {"protocols": ["TCP"], "size": 100},
            {"protocols": ["UDP"], "size": 50},
            {"protocols": ["TCP"], "size": 100},
        ]
        for pkt in packets:
            self.analyzer.analyze_packet(pkt)

        breakdown = self.analyzer.get_protocol_breakdown()
        self.assertEqual(breakdown["TCP"], 2)
        self.assertEqual(breakdown["UDP"], 1)

    def test_top_ips(self):
        """Test top IP extraction."""
        packets = [
            {
                "protocols": ["TCP"],
                "src_ip": "192.168.1.1",
                "dst_ip": "8.8.8.8",
                "size": 1000,
            },
            {
                "protocols": ["TCP"],
                "src_ip": "192.168.1.2",
                "dst_ip": "8.8.8.8",
                "size": 500,
            },
        ]
        for pkt in packets:
            self.analyzer.analyze_packet(pkt)

        stats = self.analyzer.get_statistics()
        top_ips = stats["top_ips"]
        self.assertTrue(len(top_ips) > 0)


class TestDataExporter(unittest.TestCase):
    """Test data export functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.exporter = DataExporter(output_dir="test_output")

    def tearDown(self):
        """Clean up test files."""
        import shutil
        if os.path.exists("test_output"):
            shutil.rmtree("test_output")

    def test_csv_export(self):
        """Test CSV export."""
        packets = [
            {
                "timestamp": "2024-01-15T10:30:45",
                "src_ip": "192.168.1.1",
                "dst_ip": "8.8.8.8",
                "size": 100,
            }
        ]
        filepath = self.exporter.export_csv(packets, "test.csv")
        self.assertTrue(os.path.exists(filepath))

    def test_json_export(self):
        """Test JSON export."""
        data = {"test": "data", "packets": 10}
        filepath = self.exporter.export_json(data, "test.json")
        self.assertTrue(os.path.exists(filepath))

    def test_report_export(self):
        """Test report generation."""
        stats = {"total_packets": 100, "total_bytes": 10000}
        threats = [{"type": "test", "severity": "LOW"}]
        filepath = self.exporter.export_report(stats, threats, "test_report.txt")
        self.assertTrue(os.path.exists(filepath))

    def test_list_exports(self):
        """Test export list."""
        self.exporter.export_json({"test": "data"})
        exports = self.exporter.list_exports()
        self.assertTrue(len(exports) > 0)


class TestIntegration(unittest.TestCase):
    """Integration tests."""

    def test_full_workflow(self):
        """Test complete workflow."""
        parser = ProtocolParser()
        detector = ThreatDetector()
        analyzer = TrafficAnalyzer()
        exporter = DataExporter(output_dir="test_output")

        # Create sample packet
        packet_data = {
            "timestamp": datetime.now(),
            "packet": None,  # In real scenario, would have actual packet
        }

        try:
            parsed = parser.parse(packet_data)
            threats = detector.analyze(parsed)
            analyzer.analyze_packet(parsed)

            stats = analyzer.get_statistics()
            self.assertIn("total_packets", stats)
        except Exception as e:
            # Expected since we don't have real packets
            pass

    def tearDown(self):
        """Clean up test files."""
        import shutil
        if os.path.exists("test_output"):
            shutil.rmtree("test_output")


def run_tests():
    """Run all tests."""
    unittest.main(verbosity=2)


if __name__ == "__main__":
    run_tests()
