#!/usr/bin/env python3
"""
slow-scan victim web server (port 80).

Python 3 port of MyHTTPServer.py from scripts/designer/services/web-server.tar.
Serves /var/www/html and writes one line per request to
/var/log/myhttplogfile.txt in the Apache common log format:

    172.20.0.20 - - [20/Nov/2026:10:15:03 +0000] "GET / HTTP/1.1" 200 -

That bracketed timestamp is what the httpd branch of Labtainers' getTS
(scripts/labtainer-instructor/assess_bin/ResultParser.py) parses.

Run by httpserver.service as root (port 80 is privileged). The options exist
so the server can also be tested on a laptop without root:

    MyHTTPServer.py --port 8000 --root ./www --log ./http.log
"""
import argparse
import functools
import http.server
import os
import sys
import threading
import time


def make_handler(root, log_path):
    log_file = open(log_path, 'a', buffering=1)  # append: keep history across restarts
    lock = threading.Lock()

    class Handler(http.server.SimpleHTTPRequestHandler):
        server_version = 'MyHTTPServer/2.0'

        def log_message(self, format, *args):  # noqa: A002 (name fixed by the base class)
            line = '%s - - [%s] %s\n' % (self.client_address[0],
                                         time.strftime('%d/%b/%Y:%H:%M:%S %z'),
                                         format % args)
            with lock:
                log_file.write(line)
                log_file.flush()

    return functools.partial(Handler, directory=root)


def main(argv=None):
    ap = argparse.ArgumentParser(description='slow-scan victim web server')
    ap.add_argument('--port', type=int, default=80)
    ap.add_argument('--bind', default='')
    ap.add_argument('--root', default='/var/www/html')
    ap.add_argument('--log', default='/var/log/myhttplogfile.txt')
    args = ap.parse_args(argv)

    if not os.path.isdir(args.root):
        sys.exit('MyHTTPServer: document root %s does not exist' % args.root)
    handler = make_handler(args.root, args.log)
    http.server.ThreadingHTTPServer.allow_reuse_address = True
    httpd = http.server.ThreadingHTTPServer((args.bind, args.port), handler)
    httpd.daemon_threads = True
    print('serving %s on port %d, logging to %s' % (args.root, httpd.server_address[1], args.log),
          flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == '__main__':
    main()
