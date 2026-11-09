import unittest
import tempfile
from pathlib import Path

from endpoint_security.processes import (
    inspect_process,
    collect_running_processes,
)

from endpoint_security.main import (
    get_system_information,
    get_linux_distribution,
    get_system_uptime,
    get_memory_information,
    collect_all_system_information,
)


class TestSystemInformation(unittest.TestCase):

    def test_system_information_contains_required_fields(self):
        information = get_system_information()

        required_fields = [
            "hostname",
            "operating_system",
            "kernel_version",
            "architecture",
            "python_version",
            "collection_time",
        ]

        for field in required_fields:
            with self.subTest(field=field):
                self.assertIn(field, information)
                self.assertTrue(information[field])

    def test_operating_system_is_linux(self):
        information = get_system_information()
        self.assertEqual(information["operating_system"], "Linux")

    def test_distribution_returns_text(self):
        distribution = get_linux_distribution()
        self.assertIsInstance(distribution, str)
        self.assertTrue(distribution)

    def test_uptime_is_valid(self):
        uptime = get_system_uptime()

        if uptime is not None:
            self.assertIsInstance(uptime, int)
            self.assertGreaterEqual(uptime, 0)

    def test_memory_information(self):
        memory = get_memory_information()

        self.assertIsInstance(memory, dict)

        if memory:
            self.assertIn("MemTotal", memory)
            self.assertIn("MemAvailable", memory)
            self.assertGreater(memory["MemTotal"], 0)

    def test_complete_collection(self):
        information = collect_all_system_information()

        self.assertIn("distribution", information)
        self.assertIn("uptime_seconds", information)
        self.assertIn("memory_kb", information)
        self.assertIn("process_count", information)
        self.assertIn("processes", information)
        self.assertIn("network_connection_count", information)
        self.assertIn("network_connections", information)

        self.assertEqual(
            information["process_count"],
            len(information["processes"]),
        )

        self.assertEqual(
            information["network_connection_count"],
            len(information["network_connections"]),
        )

    def test_missing_distribution_file(self):
        with tempfile.TemporaryDirectory() as directory:
            missing_file = Path(directory) / "missing-os-release"
            result = get_linux_distribution(missing_file)
            self.assertEqual(result, "Unknown")

    def test_missing_uptime_file(self):
        with tempfile.TemporaryDirectory() as directory:
            missing_file = Path(directory) / "missing-uptime"
            result = get_system_uptime(missing_file)
            self.assertIsNone(result)

    def test_invalid_uptime_value(self):
        with tempfile.TemporaryDirectory() as directory:
            invalid_file = Path(directory) / "uptime"
            invalid_file.write_text("invalid-data")
            result = get_system_uptime(invalid_file)
            self.assertIsNone(result)

    def test_missing_memory_file(self):
        with tempfile.TemporaryDirectory() as directory:
            missing_file = Path(directory) / "missing-meminfo"
            result = get_memory_information(missing_file)
            self.assertEqual(result, {})

    def test_malformed_memory_information(self):
        with tempfile.TemporaryDirectory() as directory:
            memory_file = Path(directory) / "meminfo"

            memory_file.write_text(
                "MemTotal: invalid kB\n"
                "MemAvailable: 1024 kB\n"
            )

            result = get_memory_information(memory_file)

            self.assertNotIn("MemTotal", result)
            self.assertEqual(result["MemAvailable"], 1024)

    def test_inspect_process(self):
        with tempfile.TemporaryDirectory() as directory:
            proc_root = Path(directory)
            process_directory = proc_root / "1234"
            process_directory.mkdir()

            (process_directory / "stat").write_text(
                "1234 (test process) S 1 0 0 0\n"
            )

            (process_directory / "status").write_text(
                "Name: test process\n"
                "Uid: 1000 1000 1000 1000\n"
            )

            result = inspect_process(1234, proc_root)

            self.assertEqual(result["pid"], 1234)
            self.assertEqual(result["name"], "test process")
            self.assertEqual(result["uid"], 1000)
            self.assertEqual(result["state"], "S")

    def test_missing_process_returns_none(self):
        with tempfile.TemporaryDirectory() as directory:
            result = inspect_process(9999, Path(directory))
            self.assertIsNone(result)

    def test_collect_processes_returns_sorted_results(self):
        with tempfile.TemporaryDirectory() as directory:
            proc_root = Path(directory)

            for pid in ("200", "100"):
                process_directory = proc_root / pid
                process_directory.mkdir()

                (process_directory / "stat").write_text(
                    f"{pid} (test process) S 1 0 0 0\n"
                )

                (process_directory / "status").write_text(
                    "Uid: 1000 1000 1000 1000\n"
                )

            results = collect_running_processes(proc_root)

            self.assertEqual(
                [process["pid"] for process in results],
                [100, 200],
            )


if __name__ == "__main__":
    unittest.main()
