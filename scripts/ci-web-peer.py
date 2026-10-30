#!/usr/bin/env python3
"""A web server that answers every GET with the address the request came from, one line of plain text.

The Android emulator test fetches it before and after the tunnel is up: the first answer is the emulator's own path
to the runner, the second is the SoftEther container's SecureNAT address, so the difference proves the traffic went
through the server. Usage: ci-web-peer.py PORT"""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Peer(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        body = (self.client_address[0] + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.client_address[0], fmt % args))


HTTPServer(("0.0.0.0", int(sys.argv[1])), Peer).serve_forever()
