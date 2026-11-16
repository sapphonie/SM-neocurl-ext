# Copyright 2026 davenonymous
"""Fixtures of the integration tests: the stand-in services and one game server for the whole run."""

import os
from pathlib import Path

import pytest

import gameserver
import services
from helpers import SERVER_FILES

REPOSITORY = Path(__file__).resolve().parents[2]
SCRIPTING = REPOSITORY / "pawn" / "scripting"
INCLUDE = SCRIPTING / "include"
TEST_PLUGINS = Path(__file__).resolve().parent / "plugins"



def pytest_addoption(parser):
    parser.addoption("--package", default=str(REPOSITORY / "build" / "package"),
                     help="Directory with the addons/ tree of a build or of an extracted release archive")
    parser.addoption("--image", default=os.environ.get("TF2_SERVER_IMAGE", gameserver.default_image()),
                     help="Docker image of a TF2 server with SourceMod")
    parser.addoption("--keep-server", action="store_true", help="Leave the server container running after the tests")
    parser.addoption("--server-log", default=None, help="File to write the server's console output to at the end")


def pytest_collection_modifyitems(items):
    """The lifetime tests run last: if one of them crashes the server, the other tests have run already."""
    items.sort(key=lambda item: item.module.__name__ == "test_lifetime")


def plugin_sources():
    """The test plugin of the plugin API, every example plugin and the lifetime test plugin."""
    sources = [SCRIPTING / "curl_ext_test.sp"]
    sources += sorted((SCRIPTING / "examples").glob("*.sp"))
    sources += sorted(TEST_PLUGINS.glob("*.sp"))
    return sources


@pytest.fixture(scope="session")
def http():
    service = services.HttpService()
    yield service
    service.close()


@pytest.fixture(scope="session")
def sockets():
    service = services.SocketService()
    yield service
    service.close()


@pytest.fixture(scope="session")
def websocket():
    service = services.WebSocketService()
    yield service
    service.close()


@pytest.fixture(scope="session")
def server(request, tmp_path_factory):
    """A running game server with the extension and every test plugin loaded."""
    image = request.config.getoption("--image")
    extension = gameserver.find_extension(request.config.getoption("--package"))

    work = tmp_path_factory.mktemp("server")
    plugins = gameserver.compile_plugins(image, plugin_sources(), INCLUDE, work / "plugins")

    game_files = work / "game"
    for name, content in SERVER_FILES.items():
        path = game_files / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    game = gameserver.GameServer(image)
    game.start(extension, plugins, game_files)
    try:
        # SourceMod loads plugins in no particular order: wait for all of them.
        for plugin in plugins:
            game.wait_until_loaded(plugin.name)
        yield game
    finally:
        log_file = request.config.getoption("--server-log")
        if log_file:
            Path(log_file).write_text(game.log(), errors="replace")
        if not request.config.getoption("--keep-server"):
            game.remove()


@pytest.fixture
def console(server):
    """Runs console commands on the server; every test starts with a fresh view of the server log."""
    assert server.is_running(), "The server is not running anymore; an earlier test stopped it"
    server.mark_log()

    def run(*commands):
        answers = [server.rcon(command) for command in commands]
        return "\n".join(answers)

    return run
