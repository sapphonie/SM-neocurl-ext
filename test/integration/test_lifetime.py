# Copyright 2026 davenonymous
"""Closes curl handles at awkward moments, with test/integration/plugins/curl_lifetime_test.sp.

Each of these cases once crashed the server or went wrong silently. They run last: a crash here must not take the
other tests with it.
"""

import re
import time

import pytest

import services
from helpers import wait_until

PLUGIN = "curl_lifetime_test"
# A closed handle's transfer ends through libcurl's progress callback, which runs about once a second.
ABORT_SECONDS = 10


@pytest.fixture
def lifetime(server, console):
    """The console, and afterwards the checks every case shares: no callback of a closed handle, a living server."""
    yield console

    time.sleep(1)
    assert "UNEXPECTED" not in server.new_log()
    assert server.is_running(), "The server stopped"
    assert "hostname" in server.rcon("status")


def reload_plugin(server):
    server.rcon("sm plugins load " + PLUGIN)
    server.wait_until_loaded(PLUGIN + ".smx")


def test_header_file_together_with_a_write_callback(server, lifetime, http):
    lifetime('lt_header_and_callback "%s/index.html"' % http.url)
    log = server.wait_for_log("[lifetime] header_and_callback:")

    assert "code 0, body 6 bytes" in log
    assert b"HTTP/1.1 200 OK" in server.read_file("addons/sourcemod/data/lifetime_headers.txt")


def test_list_and_file_closed_before_the_transfer(server, lifetime, http):
    lifetime('lt_early_delete "%s/big.txt"' % http.url)
    server.wait_for_log("[lifetime] early_delete: code 0, status 200, file %d bytes" % len(services.BIG_TEXT))

    assert http.requests_to("/big.txt")[-1].headers["x-early"] == "deleted"
    assert server.read_file("addons/sourcemod/data/lifetime_early.txt") == services.BIG_TEXT


def test_value_of_send_and_receive_reaches_every_callback(server, lifetime, sockets):
    lifetime('lt_sendrecv_value "%s"' % sockets.address)
    server.wait_for_log("[lifetime] sendrecv_value: send 222, complete 222")


def test_handle_deleted_in_its_write_callback(server, lifetime, http):
    lifetime('lt_delete_in_write "%s/big.txt" 0' % http.url)
    server.wait_for_log("[lifetime] delete_in_write: deleted in the callback")


def test_handle_deleted_in_the_write_callback_of_a_blocking_transfer(server, lifetime, http):
    lifetime('lt_delete_in_write "%s/big.txt" 1' % http.url)
    log = server.wait_for_log("[lifetime] delete_in_write: blocking transfer returned ")

    # The transfer is ended by whichever notices the closed handle first: the write function, which takes no more
    # data (CURLE_WRITE_ERROR, 23), or the progress function (CURLE_ABORTED_BY_CALLBACK, 42).
    code = int(re.search(r"blocking transfer returned (\d+)", log).group(1))
    assert code in (23, 42)


def test_progress_of_a_blocking_transfer(server, lifetime, http):
    lifetime('lt_progress_blocking "%s/big.txt" 0' % http.url)
    log = server.wait_for_log("[lifetime] progress_blocking:")

    code, calls, downloaded = map(int, re.search(r"code (\d+), (\d+) calls, (\d+) bytes", log).groups())
    assert code == 0
    assert calls >= 1
    assert downloaded == len(services.BIG_TEXT)


def test_progress_callback_stops_a_blocking_transfer(server, lifetime, http):
    lifetime('lt_progress_blocking "%s/big.txt" 1' % http.url)
    # CURLE_ABORTED_BY_CALLBACK (42)
    server.wait_for_log("[lifetime] progress_blocking: code 42,")


def test_handle_deleted_in_its_progress_callback(server, lifetime, http):
    lifetime('lt_delete_in_progress "%s/maps/cp_slow.bsp"' % http.url)
    server.wait_for_log("[lifetime] delete_in_progress: deleted in the callback")


def test_handle_deleted_during_its_transfer(server, lifetime, http):
    before = len(http.slow_requests)
    lifetime('lt_slow_request "%s/slow"' % http.url)
    server.wait_for_log("[lifetime] slow_request: started")
    lifetime("lt_delete_kept")

    wait_until(lambda: len(http.slow_requests) > before, "the transfer to end", ABORT_SECONDS)
    assert http.slow_requests[-1] is not None


def test_plugin_unloaded_during_a_transfer(server, lifetime, http):
    before = len(http.slow_requests)
    lifetime('lt_slow_request "%s/slow"' % http.url)
    server.wait_for_log("[lifetime] slow_request: started")
    lifetime("sm plugins unload " + PLUGIN)

    wait_until(lambda: len(http.slow_requests) > before, "the transfer to end", ABORT_SECONDS)
    assert http.slow_requests[-1] is not None
    reload_plugin(server)


def test_plugin_unloaded_while_send_and_receive_waits(server, lifetime, sockets):
    before = len(sockets.silent_clients)
    lifetime('lt_idle_wait "%s"' % sockets.address)
    server.wait_for_log("[lifetime] idle_wait: waiting")
    lifetime("sm plugins unload " + PLUGIN)

    wait_until(lambda: len(sockets.silent_clients) > before, "the connection to close", ABORT_SECONDS)
    reload_plugin(server)


def test_form_section_with_two_files(server, lifetime, http):
    lifetime('lt_form_two_files "%s/form"' % http.url)
    server.wait_for_log("[lifetime] form_two_files: code 0")

    body = http.requests_to("/form")[-1].body
    assert b"content of the first file" in body
    assert b"content of the second file" in body


def test_read_callback_that_gives_more_than_asked_for(server, lifetime, http):
    lifetime('lt_read_overflow "%s/put/overflow"' % http.url)
    # CURLE_ABORTED_BY_CALLBACK (42)
    log = server.wait_for_log("[lifetime] read_overflow: code 42")

    assert re.search(r"Read callback of curl_lifetime_test\.smx returned \d+ bytes", log)


def unload_extension(server, lifetime):
    """Unloads the extension, which unloads every plugin that uses it."""
    number = re.search(r"\[(\d+)\] NEO cURL Extension", server.rcon("sm exts list")).group(1)
    # SourceMod names the plugins it will unload and wants the command again with a code.
    confirmation = re.search(r"sm exts unload \d+ \d+", lifetime("sm exts unload " + number)).group(0)
    lifetime(confirmation)


def reload_everything(server):
    """Loads the plugins again; they bring the extension back."""
    assert server.is_running(), "The server stopped"
    server.rcon("sm plugins refresh")
    server.wait_until_loaded(PLUGIN + ".smx")
    assert "NEO cURL Extension" in server.rcon("sm exts list")


def test_extension_unloaded_during_a_transfer(server, lifetime, http):
    before = len(http.slow_requests)
    lifetime('lt_slow_request "%s/slow"' % http.url)
    server.wait_for_log("[lifetime] slow_request: started")
    unload_extension(server, lifetime)

    wait_until(lambda: len(http.slow_requests) > before, "the transfer to end", ABORT_SECONDS)
    assert http.slow_requests[-1] is not None
    reload_everything(server)


def test_extension_unloaded_while_send_and_receive_waits(server, lifetime, sockets):
    before = len(sockets.silent_clients)
    lifetime('lt_idle_wait "%s"' % sockets.address)
    server.wait_for_log("[lifetime] idle_wait: waiting")
    unload_extension(server, lifetime)

    wait_until(lambda: len(sockets.silent_clients) > before, "the connection to close", ABORT_SECONDS)
    reload_everything(server)
