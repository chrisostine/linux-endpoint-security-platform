import socket
import struct
from pathlib import Path


TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
    "0C": "NEW_SYN_RECV",
}


def decode_socket_address(address):
    """Convert a Linux hexadecimal IPv4 socket address."""

    try:
        ip_hex, port_hex = address.split(":")

        if len(ip_hex) != 8:
            return None

        if len(port_hex) != 4:
            return None

        ip_address = socket.inet_ntoa(
            struct.pack("<I", int(ip_hex, 16))
        )

        port = int(port_hex, 16)

        return {
            "ip": ip_address,
            "port": port,
        }

    except (ValueError, struct.error, OSError):
        return None


def collect_network_connections(
    tcp_path=Path("/proc/net/tcp"),
    udp_path=Path("/proc/net/udp"),
):
    """Collect and decode basic TCP and UDP socket information."""

    connections = []

    protocol_files = {
        "TCP": tcp_path,
        "UDP": udp_path,
    }

    for protocol, file_path in protocol_files.items():

        try:
            lines = file_path.read_text(
                encoding="utf-8"
            ).splitlines()

        except (OSError, UnicodeError):
            continue

        for line in lines[1:]:

            fields = line.split()

            if len(fields) < 4:
                continue

            local = decode_socket_address(fields[1])
            remote = decode_socket_address(fields[2])

            if local is None or remote is None:
                continue

            state_code = fields[3]

            if protocol == "TCP":
                state_name = TCP_STATES.get(
                    state_code,
                    "UNKNOWN",
                )
            else:
                state_name = (
                    "UNCONNECTED"
                    if state_code == "07"
                    else "UNKNOWN"
                )

            connections.append({
                "protocol": protocol,
                "local_ip": local["ip"],
                "local_port": local["port"],
                "remote_ip": remote["ip"],
                "remote_port": remote["port"],
                "state_code": state_code,
                "state": state_name,
            })

    return connections
