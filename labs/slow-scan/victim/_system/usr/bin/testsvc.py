#!/usr/bin/env python3
"""
slow-scan test service: a minimal TCP banner service.

    testsvc.py <port> <name>

Each connection completes the TCP handshake (so a scan probe sees the port as
open and the monitor sees a SYN-ACK), receives one banner line and is closed:

    220 slow-scan <name> service ready

The victim runs two instances, testsvc1.service (8081 inventory) and
testsvc2.service (9090 backup). They give the scanner open ports to find
besides 22 and 80, and give the client's health check targets. Each
connection is logged to stdout, i.e. `journalctl -u testsvc1`.
"""
import socketserver
import sys
import time


def make_handler(name):
    banner = ('220 slow-scan %s service ready\r\n' % name).encode('ascii')

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            src, sport = self.client_address[:2]
            print('%s %s connection from %s:%d' % (time.strftime('%Y-%m-%dT%H:%M:%S'), name, src, sport),
                  flush=True)
            try:
                self.request.sendall(banner)
            except OSError:
                pass  # client already gone (e.g. a connect scan that closes at once)

    return Handler


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def parse_args(argv):
    if len(argv) != 2:
        sys.exit('usage: testsvc.py <port> <name>')
    try:
        port = int(argv[0])
    except ValueError:
        sys.exit('testsvc.py: port must be a number, got %r' % argv[0])
    if not 0 <= port <= 65535:  # 0 = pick a free port (tests only)
        sys.exit('testsvc.py: port out of range: %d' % port)
    name = argv[1].strip()
    if not name or not name.isprintable() or not name.isascii():
        sys.exit('testsvc.py: name must be printable ASCII')
    return port, name


def main(argv=None):
    port, name = parse_args(sys.argv[1:] if argv is None else argv)
    with Server(('', port), make_handler(name)) as srv:
        print('%s listening on port %d' % (name, srv.server_address[1]), flush=True)
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == '__main__':
    main()
