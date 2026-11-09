
import os
from pathlib import Path


def inspect_process(pid, proc_root=Path("/proc")):
    """Collect basic information about one Linux process."""

    process_directory = proc_root / str(pid)

    try:
        stat_content = (
            process_directory / "stat"
        ).read_text(encoding="utf-8")

        # The process name is enclosed in parentheses.
        # rsplit handles spaces and closing parentheses in names.
        stat_parts = stat_content.rsplit(")", 1)

        if len(stat_parts) != 2:
            return None

        process_name = stat_parts[0].split("(", 1)[-1]
        remaining_fields = stat_parts[1].split()

        if len(remaining_fields) < 1:
            return None

        process_state = remaining_fields[0]

        # Read the process user ID.
        uid = None
        status_file = process_directory / "status"

        try:
            for line in status_file.read_text(
                encoding="utf-8"
            ).splitlines():
                if line.startswith("Uid:"):
                    uid = int(line.split()[1])
                    break
        except (OSError, ValueError, IndexError):
            pass

        # Read the executable path where permissions allow.
        executable = None

        try:
            executable = os.readlink(
                process_directory / "exe"
            )
        except OSError:
            pass

        return {
            "pid": int(pid),
            "name": process_name,
            "executable": executable,
            "uid": uid,
            "state": process_state,
        }

    except (OSError, ValueError, IndexError):
        # A process may exit while we are inspecting it.
        return None


def collect_running_processes(proc_root=Path("/proc")):
    """Collect information about accessible running processes."""

    processes = []

    try:
        for entry in proc_root.iterdir():
            if entry.name.isdigit():
                process = inspect_process(
                    entry.name,
                    proc_root
                )

                if process is not None:
                    processes.append(process)

    except OSError:
        return []

    return sorted(processes, key=lambda item: item["pid"])
