import tempfile
import unittest
from pathlib import Path

from endpoint_security.network import (
    decode_socket_address,
    collect_network_connections,
)


class TestNetworkInspection(unittest.TestCase):

    def test_decode_valid_socket_address(self):
        result = decode_socket_address("0100007F:1538")
        self.assertEqual(
            result,
            {"ip": "127.0.0.1", "port": 5432},
        )

    def test_decode_invalid_socket_address(self):
        result = decode_socket_address("invalid-address")
        self.assertIsNone(result)

    def test_collect_tcp_and_udp_connections(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tcp_file = root / "tcp"
            udp_file = root / "udp"

            tcp_file.write_text(
                "header\n"
                "0: 0100007F:1538 00000000:0000 0A\n"
            )

            udp_file.write_text(
                "header\n"
                "0: 00000000:0035 00000000:0000 07\n"
            )

            results = collect_network_connections(
                tcp_file, udp_file
            )

            self.assertEqual(len(results), 2)
            self.assertEqual(results[0]["protocol"], "TCP")
            self.assertEqual(results[0]["local_ip"], "127.0.0.1")
            self.assertEqual(results[0]["local_port"], 5432)
            self.assertEqual(results[0]["state"], "LISTEN")
            self.assertEqual(results[1]["protocol"], "UDP")
            self.assertEqual(results[1]["local_port"], 53)
            self.assertEqual(results[1]["state"], "UNCONNECTED")

    def test_missing_network_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            results = collect_network_connections(
                root / "missing_tcp",
                root / "missing_udp",
            )
            self.assertEqual(results, [])

    def test_malformed_network_records_are_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tcp_file = root / "tcp"
            udp_file = root / "udp"

            tcp_file.write_text(
                "header\n"
                "malformed record\n"
                "0: 0100007F:1538 00000000:0000 0A\n"
            )
            udp_file.write_text("header\n")

            results = collect_network_connections(
                tcp_file, udp_file
            )
            self.assertEqual(len(results), 1)


if __name__ == "__main__":
    unittest.main()
