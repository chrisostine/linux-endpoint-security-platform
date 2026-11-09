import unittest

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


if __name__ == "__main__":
    unittest.main()