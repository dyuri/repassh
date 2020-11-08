import select
import socket
import time


def knock(host=None, ports=[], delay=0, use_udp=False, timeout=100, config=None):
    """Knocks the sequence of ports.

    Args:
        host: string, host to knock
        ports: iterable of ints, sequence of port numbers to knock
        delay: int, delay between each knock, ms
        timeout: int, timeout for knocks
        config: Config instance, for printing
    """
    prnt = getattr(config, "print", print)
    prnt(f"KNOCK host: {host}, ports: {ports}, delay: {delay}")

    address_family, _, _, _, (ip_addr, _) = socket.getaddrinfo(
        host=host,
        port=None,
        flags=socket.AI_ADDRCONFIG
    )[0]

    for i, port in enumerate(ports):
        prnt(f"Knocking {host}:{port} [{'udp' if use_udp else 'tcp'}].")

        s = socket.socket(address_family, socket.SOCK_DGRAM if use_udp else socket.SOCK_STREAM)
        s.setblocking(False)

        socket_address = (ip_addr, int(port))
        if use_udp:
            s.sendto(b'', socket_address)
        else:
            s.connect_ex(socket_address)
            select.select([s], [s], [s], timeout / 1000)

        s.close()

        if delay and i < len(ports) - 1:
            time.sleep(delay / 1000)
