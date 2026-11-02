import socket
import sys

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.settimeout(5)
    client.connect('/run/security-center/status.sock')
    client.sendall(b'GET\n')
    payload = bytearray()
    while True:
        part = client.recv(65536)
        if not part:
            break
        payload.extend(part)
        if len(payload) > 2097152:
            raise ValueError('Response exceeds limit')
    sys.stdout.write(payload.decode())
