from pathlib import Path

from eduid.userdb.testing.temp_instance import INSTANCE_PORT_MAX, INSTANCE_PORT_MIN, random_instance_port

IANA_EPHEMERAL_PORT_MIN = 49152  # also what macOS uses


def _os_ephemeral_port_min() -> int:
    """The lowest port the OS hands out to outgoing connections."""
    proc_file = Path("/proc/sys/net/ipv4/ip_local_port_range")
    if proc_file.exists():
        return int(proc_file.read_text().split()[0])
    return IANA_EPHEMERAL_PORT_MIN


def test_instance_ports_are_in_range() -> None:
    for _ in range(500):
        port = random_instance_port()
        assert port >= INSTANCE_PORT_MIN
        assert port <= INSTANCE_PORT_MAX


def test_instance_ports_are_not_reused() -> None:
    ports = [random_instance_port() for _ in range(500)]
    assert len(set(ports)) == len(ports)


def test_instance_ports_are_below_the_ephemeral_port_range() -> None:
    """Ports in the ephemeral range collide with outgoing connections still in TIME_WAIT, see temp_instance.py."""
    assert _os_ephemeral_port_min() > INSTANCE_PORT_MAX
