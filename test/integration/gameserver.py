# Copyright 2026 davenonymous
"""A TF2 server in a Docker container, for the integration tests.

The container is the public image of a complete server with SourceMod. This module compiles the test plugins with
the image's own compiler, puts them and the built extension into a container, starts it and talks to it over RCON.
"""

import secrets
import socket
import struct
import subprocess
import time
from pathlib import Path

CONTAINER_NAME = "sm-neocurl-integration"
RCON_PORT = 27015
SERVER_DIR = "/home/tf2/server"
GAME_DIR = SERVER_DIR + "/tf"
SOURCEMOD_DIR = GAME_DIR + "/addons/sourcemod"
# Seconds the server may take until its plugins are loaded: it loads the game and a map first.
START_TIMEOUT = 600

_SERVERDATA_AUTH = 3
_SERVERDATA_EXECCOMMAND = 2


class ServerError(Exception):
    """The server or one of the tools around it did not do what the tests need."""


def _run(arguments, **options):
    """Runs a command and returns its output; raises ServerError with the output when it fails."""
    result = subprocess.run(arguments, capture_output=True, text=True, errors="replace", **options)
    if result.returncode != 0:
        raise ServerError("%s failed:\n%s%s" % (" ".join(arguments[:3]), result.stdout, result.stderr))
    return result.stdout


def compile_plugins(image, sources, include_dir, output_dir):
    """Compiles SourcePawn files with the compiler of the server image; returns the .smx paths."""
    output_dir.mkdir(parents=True, exist_ok=True)
    mounts = []
    commands = []
    for number, source in enumerate(sources):
        mounts += ["-v", "%s:/sources/%d/%s:ro" % (source, number, source.name)]
        commands.append(
            "./spcomp -i /include -o /output/%s.smx /sources/%d/%s || exit 1" % (source.stem, number, source.name)
        )
    _run(
        ["docker", "run", "--rm", "--user", "root", "--entrypoint", "sh",
         "-v", "%s:/include:ro" % include_dir, "-v", "%s:/output" % output_dir, *mounts,
         "-w", SOURCEMOD_DIR + "/scripting", image,
         "-c", "\n".join(commands) + "\nchmod -R a+rwX /output"]
    )
    compiled = [output_dir / (source.stem + ".smx") for source in sources]
    missing = [path.name for path in compiled if not path.is_file()]
    if missing:
        raise ServerError("The compiler wrote no %s" % ", ".join(missing))
    return compiled


class GameServer:
    """One running server container."""

    def __init__(self, image):
        self.image = image
        self.rcon_password = secrets.token_hex(8)
        self._log_offset = 0

    def start(self, extension, plugins, game_files):
        """Creates and starts the container.

        extension: the curl.ext.so to load.
        plugins: compiled plugins for addons/sourcemod/plugins/.
        game_files: a directory whose content is copied into the game directory and made writable for the server.
        """
        self.remove()
        _run(["docker", "create", "--name", CONTAINER_NAME, "--network", "host",
              "-e", "RCON_PASSWORD=" + self.rcon_password, self.image])

        self._copy_in(extension, SOURCEMOD_DIR + "/extensions/curl.ext.so")
        for plugin in plugins:
            self._copy_in(plugin, "%s/plugins/%s" % (SOURCEMOD_DIR, plugin.name))
        self._copy_in("%s/." % game_files, GAME_DIR + "/")

        _run(["docker", "start", CONTAINER_NAME])
        # docker cp creates files owned by root; the server deletes and renames some of them.
        owned = " ".join("'%s/%s'" % (GAME_DIR, entry.name) for entry in sorted(Path(game_files).iterdir()))
        if owned:
            _run(["docker", "exec", "--user", "root", CONTAINER_NAME, "sh", "-c", "chown -R tf2:tf2 " + owned])

    def _copy_in(self, source, target):
        _run(["docker", "cp", str(source), "%s:%s" % (CONTAINER_NAME, target)])

    def wait_until_loaded(self, plugin_file):
        """Waits until SourceMod has loaded the plugin, e.g. "curl_ext_test.smx"."""
        deadline = time.monotonic() + START_TIMEOUT
        while time.monotonic() < deadline:
            if not self.is_running():
                raise ServerError("The server stopped while starting:\n" + self.log()[-4000:])
            try:
                # "sm plugins list" prints titles; only "info" tells a plugin by its file.
                if "Filename: " + plugin_file in self.rcon("sm plugins info " + plugin_file):
                    return
            except OSError:
                pass
            time.sleep(3)
        raise ServerError("The server did not load %s within %d seconds:\n%s"
                          % (plugin_file, START_TIMEOUT, self.log()[-4000:]))

    def is_running(self):
        result = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER_NAME],
                                capture_output=True, text=True)
        return result.returncode == 0 and result.stdout.strip() == "true"

    def rcon(self, command):
        """Runs one console command and returns what the server answered."""
        with socket.create_connection(("127.0.0.1", RCON_PORT), timeout=10) as connection:
            _send_packet(connection, 1, _SERVERDATA_AUTH, self.rcon_password)
            # The server answers an auth request with an empty response packet and then the auth result.
            _receive_packet(connection)
            request_id, _ = _receive_packet(connection)
            if request_id == -1:
                raise ServerError("The server refused the RCON password")

            _send_packet(connection, 2, _SERVERDATA_EXECCOMMAND, command)
            connection.settimeout(1.5)
            answer = ""
            try:
                while True:
                    answer += _receive_packet(connection)[1]
            except socket.timeout:
                return answer

    def log(self):
        """Everything the server console printed so far."""
        result = subprocess.run(["docker", "logs", CONTAINER_NAME], capture_output=True, text=True, errors="replace")
        return result.stdout + result.stderr

    def mark_log(self):
        """Forgets the log so far: new_log() returns only what is printed from now on."""
        self._log_offset = len(self.log())

    def new_log(self):
        return self.log()[self._log_offset:]

    def wait_for_log(self, text, timeout=30):
        """Waits until the console printed `text` after the last mark_log(); returns the new log."""
        deadline = time.monotonic() + timeout
        while True:
            log = self.new_log()
            if text in log:
                return log
            if time.monotonic() >= deadline:
                raise AssertionError("The server did not print %r within %d seconds. It printed:\n%s"
                                     % (text, timeout, log[-3000:]))
            if not self.is_running():
                raise AssertionError("The server stopped while waiting for %r. Its last output:\n%s"
                                     % (text, log[-3000:]))
            time.sleep(0.3)

    def read_file(self, path):
        """The content of a file below the game directory."""
        result = subprocess.run(["docker", "exec", CONTAINER_NAME, "cat", "%s/%s" % (GAME_DIR, path)],
                                capture_output=True)
        if result.returncode != 0:
            raise ServerError("Cannot read %s: %s" % (path, result.stderr.decode(errors="replace")))
        return result.stdout

    def file_exists(self, path):
        result = subprocess.run(["docker", "exec", CONTAINER_NAME, "test", "-e", "%s/%s" % (GAME_DIR, path)])
        return result.returncode == 0

    def remove(self):
        subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True)


def _send_packet(connection, request_id, kind, body):
    payload = struct.pack("<ii", request_id, kind) + body.encode() + b"\x00\x00"
    connection.sendall(struct.pack("<i", len(payload)) + payload)


def _receive_exactly(connection, size):
    data = b""
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise ConnectionError("The server closed the RCON connection")
        data += chunk
    return data


def _receive_packet(connection):
    size = struct.unpack("<i", _receive_exactly(connection, 4))[0]
    payload = _receive_exactly(connection, size)
    request_id = struct.unpack("<i", payload[:4])[0]
    return request_id, payload[8:-2].decode(errors="replace")


def default_image():
    return "ghcr.io/melkortf/tf2-sourcemod/i386:latest"


def find_extension(package):
    """The 32-bit extension in a package directory (the addons/ tree of a build or of a release archive)."""
    candidates = [Path(package) / "addons/sourcemod/extensions/curl.ext.so",
                  Path(package) / "sourcemod/extensions/curl.ext.so"]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise ServerError("No addons/sourcemod/extensions/curl.ext.so below %s; build the extension first" % package)
