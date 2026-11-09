import platform
import socket
import datetime
from pathlib import Path


def get_system_information():
    """Collect basic Linux system information."""

    information = {
        "hostname": socket.gethostname(),
        "operating_system": platform.system(),
        "kernel_version": platform.release(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "collection_time": datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat(),
    }

    return information


def get_linux_distribution():
    """Read Linux distribution information."""

    os_release = Path("/etc/os-release")

    if not os_release.exists():
        return "Unknown"

    for line in os_release.read_text().splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip('"')

    return "Unknown"


def get_system_uptime():
    """Read system uptime from the Linux proc filesystem."""

    uptime_file = Path("/proc/uptime")

    if not uptime_file.exists():
        return None

    uptime_seconds = float(uptime_file.read_text().split()[0])

    return int(uptime_seconds)


def get_memory_information():
    """Collect total and available system memory."""

    memory_file = Path("/proc/meminfo")

    if not memory_file.exists():
        return {}

    memory = {}

    for line in memory_file.read_text().splitlines():
        if line.startswith(("MemTotal:", "MemAvailable:")):
            key, value = line.split(":", 1)
            memory[key] = int(value.strip().split()[0])

    return memory


def collect_all_system_information():
    """Combine all system information into one result."""

    information = get_system_information()

    information["distribution"] = get_linux_distribution()
    information["uptime_seconds"] = get_system_uptime()
    information["memory_kb"] = get_memory_information()

    return information


if __name__ == "__main__":
    import json

    results = collect_all_system_information()

    print(json.dumps(results, indent=4))