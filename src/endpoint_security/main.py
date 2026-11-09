
import platform
import socket
import datetime
import json
from pathlib import Path
from endpoint_security.processes import collect_running_processes
from endpoint_security.network import collect_network_connections


def get_system_information():
    """Collect basic Linux system information."""

    return {
        "hostname": socket.gethostname(),
        "operating_system": platform.system(),
        "kernel_version": platform.release(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "collection_time": datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat(),
    }


def get_linux_distribution(os_release_path=Path("/etc/os-release")):
    """Read Linux distribution information safely."""

    try:
        content = os_release_path.read_text(encoding="utf-8")

        for line in content.splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')

    except (OSError, UnicodeError):
        pass

    return "Unknown"


def get_system_uptime(uptime_path=Path("/proc/uptime")):
    """Read system uptime safely."""

    try:
        content = uptime_path.read_text(encoding="utf-8")
        uptime_seconds = float(content.split()[0])

        return int(uptime_seconds)

    except (OSError, UnicodeError, ValueError, IndexError):
        return None


def get_memory_information(memory_path=Path("/proc/meminfo")):
    """Collect total and available memory safely."""

    memory = {}

    try:
        lines = memory_path.read_text(encoding="utf-8").splitlines()

        for line in lines:
            if line.startswith(("MemTotal:", "MemAvailable:")):
                key, value = line.split(":", 1)

                try:
                    memory[key] = int(value.strip().split()[0])
                except (ValueError, IndexError):
                    continue

    except (OSError, UnicodeError):
        return {}

    return memory


def collect_all_system_information():
    """Collect system, process, and network information."""

    information = get_system_information()

    information["distribution"] = get_linux_distribution()
    information["uptime_seconds"] = get_system_uptime()
    information["memory_kb"] = get_memory_information()

    # Collect running processes.
    processes = collect_running_processes()

    information["process_count"] = len(processes)
    information["processes"] = processes

    # Collect network connections.
    network_connections = collect_network_connections()

    information["network_connection_count"] = len(network_connections)
    information["network_connections"] = network_connections

    return information



if __name__ == "__main__":
    results = collect_all_system_information()
    print(json.dumps(results, indent=4))
