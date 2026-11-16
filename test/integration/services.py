# Copyright 2026 davenonymous
"""Stand-ins for the services the test plugins talk to.

Each service listens on 127.0.0.1 on a free port, runs on threads of the test
process and records what it received, so a test can assert on it:

- HttpService: the HTTP endpoints (a Discord webhook, demos.tf's upload, the
  ETF2L API, a fast download server, a signed webhook, PUT uploads).
- SocketService: a TCP and a UDP echo on the same port number.
- WebSocketService: a WebSocket echo.
"""

import asyncio
import email.parser
import email.policy
import hashlib
import hmac
import json
import socket
import socketserver
import sys
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import websockets

HOST = "127.0.0.1"

# What the plugins and the stand-ins agree on.
DEMOSTF_API_KEY = "goodkey"
DEMOSTF_LINK = "https://demos.tf/123456"
SIGNING_SECRET = "topsecret"
ETF2L_PLAYER_NAME = "Nace"
MAP_BYTES = bytes(range(256)) * 12000
BANNED_ITEMS = ["The Reserve Shooter", "Bonk! Atomic Punch", "Crit-a-Cola", "Mad Milk", "Soda Popper", "Wrap Assassin"]
BIG_TEXT = "".join("line %06d of the big file\n" % number for number in range(8000)).encode()
# How long /slow keeps a request open without answering it.
SLOW_SECONDS = 60


def whitelist_text():
    """An item whitelist in the format of whitelist.tf."""
    lines = ["// Whitelist: stand-in", '"item_whitelist"', "{", '\t"unlisted_items_default_to"\t"1"']
    lines += ['\t"%s"\t\t"0"' % item for item in BANNED_ITEMS]
    lines += ['\t"The Allowed Hat"\t\t"1"', "}"]
    return "\n".join(lines) + "\n"


@dataclass
class Request:
    """One HTTP request as a stand-in received it."""

    method: str
    path: str
    headers: dict
    body: bytes
    fields: dict = field(default_factory=dict)


@dataclass
class FormField:
    """One section of a multipart/form-data body."""

    filename: str
    content_type: str
    content: bytes


def _wait_for_close(connection, seconds):
    """Blocks until the peer closes the connection or the time is over; returns whether it closed."""
    connection.settimeout(seconds)
    try:
        return connection.recv(1) == b""
    except socket.timeout:
        return False
    except OSError:
        return True


class _HttpHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *arguments):
        pass

    def _record(self, body=b"", fields=None):
        headers = {name.lower(): value for name, value in self.headers.items()}
        request = Request(self.command, self.path, headers, body, fields or {})
        self.server.service.requests.append(request)
        return request

    def _answer(self, status, body=b"", content_type="text/plain", headers=()):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        if content_type:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _read_body(self):
        if self.headers.get("Transfer-Encoding", "").lower() != "chunked":
            return self.rfile.read(int(self.headers.get("Content-Length", 0)))

        body = b""
        while True:
            size = int(self.rfile.readline().split(b";")[0], 16)
            if size == 0:
                self.rfile.readline()
                return body
            body += self.rfile.read(size)
            self.rfile.readline()

    def _read_form(self, body):
        message = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
            b"Content-Type: " + self.headers["Content-Type"].encode() + b"\r\n\r\n" + body
        )
        fields = {}
        for part in message.iter_parts():
            name = part.get_param("name", header="content-disposition")
            content = part.get_payload(decode=True) or b""
            fields[name] = FormField(part.get_filename(), part.get_content_type(), content)
        return fields

    def do_GET(self):
        self._record()
        path = self.path.split("?")[0]

        if path == "/redirect":
            return self._answer(302, headers=[("Location", "/index.html")])
        if path == "/index.html":
            return self._answer(200, "hello\n", "application/octet-stream")
        if path == "/big.txt":
            return self._answer(200, BIG_TEXT)
        if path == "/whitelist.txt":
            return self._answer(200, whitelist_text())
        if path == "/maps/cp_test.bsp":
            return self._answer(200, MAP_BYTES, "application/octet-stream")
        if path == "/slow":
            return self._hold_open()
        if path.startswith("/player/"):
            return self._answer_player(path.split("/")[2])
        return self._answer(404, "not found")

    do_HEAD = do_GET

    def _hold_open(self):
        """Answers nothing; records how long the client stayed."""
        started = time.monotonic()
        closed = _wait_for_close(self.connection, SLOW_SECONDS)
        self.server.service.slow_requests.append(time.monotonic() - started if closed else None)
        self.close_connection = True

    def _answer_player(self, identifier):
        if identifier == "0":
            body = {"status": {"code": 404, "message": "No player was found for 0."}}
            return self._answer(404, json.dumps(body), "application/json")
        body = {
            "player": {"bans": None, "classes": ["Demoman", "Scout"], "country": "Sweden", "id": 100,
                       "name": ETF2L_PLAYER_NAME, "steam": {"id64": identifier}, "teams": []},
            "status": {"code": 200, "message": "OK"},
        }
        return self._answer(200, json.dumps(body, separators=(",", ":")), "application/json")

    def do_PUT(self):
        body = self._read_body()
        self._record(body)
        self._answer(201, "stored %d bytes" % len(body))

    def do_POST(self):
        body = self._read_body()
        path = self.path.split("?")[0]

        if path.startswith("/api/webhooks/"):
            self._record(body)
            return self._answer_discord(body)
        if path == "/upload":
            fields = self._read_form(body)
            self._record(fields=fields)
            return self._answer_demostf(fields)
        if path == "/hook":
            self._record(body)
            return self._answer_signed(body)
        self._record(body)
        return self._answer(404, "not found")

    def _answer_discord(self, body):
        try:
            has_content = isinstance(json.loads(body).get("content"), str)
        except (ValueError, AttributeError):
            has_content = False
        if not has_content:
            error = {"message": "Cannot send an empty message", "code": 50006}
            return self._answer(400, json.dumps(error), "application/json")
        return self._answer(204, content_type=None)

    def _answer_demostf(self, fields):
        if "demo" not in fields:
            return self._answer(200, "No demo uploaded")
        if fields.get("key") is None or fields["key"].content.decode() != DEMOSTF_API_KEY:
            return self._answer(200, "Invalid key")
        return self._answer(200, "STV available at: " + DEMOSTF_LINK)

    def _answer_signed(self, body):
        expected = "sha256=" + hmac.new(SIGNING_SECRET.encode(), body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, self.headers.get("X-Hub-Signature-256", "")):
            return self._answer(401, "bad signature")
        return self._answer(200, "ok")


class _HttpServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        """Clients that go away in the middle of a request are part of the tests; anything else is reported."""
        if isinstance(sys.exc_info()[1], ConnectionError):
            return
        super().handle_error(request, client_address)


class HttpService:
    """The HTTP stand-ins. `requests` has every request received, oldest first."""

    def __init__(self):
        self.requests = []
        # Seconds each /slow request stayed open until its client closed it; None for one that never closed.
        self.slow_requests = []
        self._server = _HttpServer((HOST, 0), _HttpHandler)
        self._server.service = self
        self.port = self._server.server_address[1]
        self.url = "http://%s:%d" % (HOST, self.port)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def requests_to(self, path_prefix):
        return [request for request in self.requests if request.path.startswith(path_prefix)]

    def close(self):
        self._server.shutdown()
        self._server.server_close()


class _TcpHandler(socketserver.StreamRequestHandler):
    """Answers the first line in upper case; records how long a client that sends nothing stays."""

    def handle(self):
        started = time.monotonic()
        try:
            line = self.rfile.readline()
        except OSError:
            line = b""
        if line:
            self.wfile.write(b"echo: " + line.upper())
            return
        self.server.service.silent_clients.append(time.monotonic() - started)


class _TcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class SocketService:
    """A TCP echo and a UDP echo on the same port number."""

    def __init__(self):
        # Seconds each TCP client stayed connected that closed without sending a line.
        self.silent_clients = []
        self._tcp = _TcpServer((HOST, 0), _TcpHandler)
        self._tcp.service = self
        self.port = self._tcp.server_address[1]
        self.address = "%s:%d" % (HOST, self.port)
        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.bind((HOST, self.port))
        threading.Thread(target=self._tcp.serve_forever, daemon=True).start()
        threading.Thread(target=self._serve_udp, daemon=True).start()

    def _serve_udp(self):
        while True:
            try:
                data, sender = self._udp.recvfrom(2048)
            except OSError:
                return
            self._udp.sendto(b"udp echo: " + data, sender)

    def close(self):
        self._tcp.shutdown()
        self._tcp.server_close()
        self._udp.close()


class WebSocketService:
    """A WebSocket echo.

    `connections` has the path and the Authorization header of every handshake, `messages` every message received.
    A text message containing "!close" makes the server close the connection, one containing "!drop" makes it
    abort the connection without a closing handshake.
    """

    def __init__(self):
        self.connections = []
        self.messages = []
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self.port = 0
        threading.Thread(target=self._run, daemon=True).start()
        if not self._ready.wait(10):
            raise RuntimeError("The WebSocket stand-in did not start")
        self.url = "ws://%s:%d" % (HOST, self.port)

    def _run(self):
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._serve())

    async def _serve(self):
        self._stop = asyncio.Event()
        async with websockets.serve(self._handle, HOST, 0, max_size=None) as server:
            self.port = server.sockets[0].getsockname()[1]
            self._ready.set()
            await self._stop.wait()

    async def _handle(self, connection):
        self.connections.append((connection.request.path, connection.request.headers.get("Authorization")))
        async for message in connection:
            self.messages.append(message)
            is_text = isinstance(message, str)
            if is_text and "!close" in message:
                await connection.close(1000, "bye from the server")
                return
            if is_text and "!drop" in message:
                connection.transport.abort()
                return
            await connection.send(message)

    def text_messages(self):
        return [message for message in self.messages if isinstance(message, str)]

    def close(self):
        self._loop.call_soon_threadsafe(self._stop.set)
