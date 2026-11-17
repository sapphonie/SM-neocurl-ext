# Copyright 2026 davenonymous
"""Runs every example plugin of pawn/scripting/examples/ against the stand-in services.

The guides quote these plugins and what they print, so a failure here means that a guide is wrong as well.
"""

import base64
import hashlib
import hmac
import json
import re

import services
from helpers import DEMO_BYTES, UPLOAD_FILE, wait_until


def test_discord_webhook_posts_json(server, console, http):
    console('sm_discord_webhook_url "%s/api/webhooks/1/token"' % http.url, r'sm_discord He said "hi" \ and left')
    wait_until(lambda: http.requests_to("/api/webhooks/1/"), "the webhook request")

    request = http.requests_to("/api/webhooks/1/")[-1]
    assert request.method == "POST"
    assert request.headers["content-type"] == "application/json"
    assert json.loads(request.body) == {"content": 'He said "hi" \\ and left'}


def test_discord_webhook_logs_an_error_status(server, console, http):
    console('sm_discord_webhook_url "%s/api/webhooks-gone"' % http.url, "sm_discord hello")
    server.wait_for_log("Discord webhook: HTTP status 404")


def test_discord_webhook_logs_a_failed_request(server, console):
    console('sm_discord_webhook_url "http://127.0.0.1:1/nobody"', "sm_discord hello")
    server.wait_for_log("Discord webhook: the request failed: ")


def test_map_download_writes_the_map(server, console, http):
    console('sm_downloadmap_url "%s/maps"' % http.url, "sm_downloadmap cp_test")
    server.wait_for_log("Downloaded maps/cp_test.bsp: %d bytes" % len(services.MAP_BYTES))

    assert server.read_file("maps/cp_test.bsp") == services.MAP_BYTES
    assert not server.file_exists("maps/cp_test.bsp.part")


def test_map_download_leaves_nothing_for_a_missing_map(server, console, http):
    console('sm_downloadmap_url "%s/maps"' % http.url, "sm_downloadmap cp_missing")
    server.wait_for_log("Download of cp_missing failed: The requested URL returned error: 404")

    assert not server.file_exists("maps/cp_missing.bsp")
    assert not server.file_exists("maps/cp_missing.bsp.part")


def test_map_download_reports_its_progress(server, console, http):
    console('sm_downloadmap_url "%s/maps"' % http.url, "sm_downloadmap cp_slow")
    log = server.wait_for_log("Downloaded maps/cp_slow.bsp: %d bytes" % len(services.MAP_BYTES), timeout=40)

    total = len(services.MAP_BYTES)
    pattern = r"Downloading cp_slow: (\d+)% \((\d+) of " + str(total) + r" bytes\)"
    reports = [(int(percent), int(done)) for percent, done in re.findall(pattern, log)]
    # About one report a second while the stand-in sends for four seconds, and one at the end.
    assert len(reports) >= 3
    assert reports == sorted(reports)
    assert reports[-1] == (100, total)
    assert 0 < reports[1][1] < total


def test_map_download_stops_a_map_that_is_too_large(server, console, http):
    console('sm_downloadmap_url "%s/maps"' % http.url, "sm_downloadmap_max_size 500000",
            "sm_downloadmap cp_slow_large")
    try:
        log = server.wait_for_log("Download of cp_slow_large failed: ", timeout=40)
    finally:
        console("sm_downloadmap_max_size 536870912")

    assert "cp_slow_large is larger than 500000 bytes; stopping the download" in log
    assert not server.file_exists("maps/cp_slow_large.bsp")
    assert not server.file_exists("maps/cp_slow_large.bsp.part")


def test_demo_upload_reports_a_refused_upload(server, console, http):
    console('sm_demostf_url "%s/upload"' % http.url, "sm_demostf_apikey wrongkey", "sm_uploaddemo " + UPLOAD_FILE)
    server.wait_for_log("demos.tf refused the upload (HTTP status 200): Invalid key")


def test_demo_upload_sends_the_form(server, console, http):
    console('sm_demostf_url "%s/upload"' % http.url, "sm_demostf_apikey " + services.DEMOSTF_API_KEY,
            "sm_uploaddemo " + UPLOAD_FILE)
    log = server.wait_for_log("Demo uploaded: " + services.DEMOSTF_LINK)

    # The last progress report has the whole request body: the demo and the form around it.
    uploaded, total = map(int, re.findall(r"Uploading: (\d+) of (\d+) bytes", log)[-1])
    assert uploaded == total
    assert total > len(DEMO_BYTES)

    fields = http.requests_to("/upload")[-1].fields
    assert set(fields) == {"key", "name", "red", "blu", "demo"}
    assert fields["name"].content.decode() == UPLOAD_FILE
    assert fields["red"].content == b"RED"
    assert fields["demo"].filename == "match.dem"
    assert fields["demo"].content_type == "application/octet-stream"
    assert fields["demo"].content == DEMO_BYTES


def test_etf2l_lookup_finds_a_player(server, console, http):
    console('sm_etf2l_lookup_url "%s"' % http.url, "sm_etf2l_lookup 76561197963283262")
    log = server.wait_for_log("ETF2L name: " + services.ETF2L_PLAYER_NAME)

    assert "bytes of application/json" in log
    assert http.requests_to("/player/")[-1].headers["user-agent"] == "sm-neocurl example"


def test_etf2l_lookup_reports_an_unknown_player(server, console, http):
    console('sm_etf2l_lookup_url "%s"' % http.url, "sm_etf2l_lookup 0")
    server.wait_for_log("ETF2L does not know this player.")


def test_etf2l_lookup_url_encodes_the_id(server, console, http):
    console('sm_etf2l_lookup_url "%s"' % http.url, 'sm_etf2l_lookup "[U:1:3017534]"')
    server.wait_for_log("ETF2L name: ")

    assert http.requests_to("/player/")[-1].path == "/player/%5BU%3A1%3A3017534%5D"


def test_basics_info(server, console):
    console("sm_curl_info")
    log = server.wait_for_log("TLS: yes")

    assert "Version: libcurl/" in log
    assert " https " in log


def test_basics_blocking_head_request(server, console, http):
    console('sm_curl_head "%s/redirect"' % http.url)
    log = server.wait_for_log("redirects, connected to 127.0.0.1")

    assert "Status 200 from %s/index.html" % http.url in log
    assert "1 redirects" in log
    assert "  Location: /index.html" in log
    assert http.requests_to("/redirect")[-1].method == "HEAD"


def test_basics_put_file(server, console, http):
    console('sm_curl_put_file "%s/put/file" %s' % (http.url, UPLOAD_FILE))
    server.wait_for_log("PUT: No error, status 201")

    request = http.requests_to("/put/file")[-1]
    assert request.method == "PUT"
    assert request.headers["content-length"] == str(len(DEMO_BYTES))
    assert request.body == DEMO_BYTES


def test_basics_put_from_a_read_callback(server, console, http):
    console('sm_curl_put_text "%s/put/text" "some generated text"' % http.url)
    server.wait_for_log("PUT: No error, status 201")

    assert http.requests_to("/put/text")[-1].body == b"some generated text"


def test_tcp_client_over_tcp(server, console, sockets):
    console('sm_tcp_send "%s" hello' % sockets.address)
    log = server.wait_for_log("Received 12 bytes: echo: HELLO")

    assert "Sent 6 bytes" in log


def test_tcp_client_over_udp(server, console, sockets):
    console('sm_tcp_send "udp://%s" hello' % sockets.address)
    server.wait_for_log("Received 16 bytes: udp echo: hello")


def test_tcp_client_reports_a_refused_connection(server, console):
    console('sm_tcp_send "127.0.0.1:1" hello')
    server.wait_for_log("Cannot connect: ")


def test_websocket_relay(server, console, websocket):
    console('sm_relay_url "%s/gameserver"' % websocket.url, "sm_relay_token s3cret", "sm_relay_connect")
    server.wait_for_log("Relay: connected")
    assert websocket.connections[-1] == ("/gameserver", "Bearer s3cret")

    console("sm_relay_say hello")
    chat = {"type": "chat", "name": "Console", "text": "hello"}
    wait_until(lambda: chat in [json.loads(text) for text in websocket.text_messages()], "the chat message")
    assert "is open" in console("sm_relay_status")

    # The server drops the connection: the relay connects again by itself.
    server.mark_log()
    console("sm_relay_say !drop")
    log = server.wait_for_log("Relay: connected")
    assert "Relay: connection lost" in log

    # The server closes the connection: the relay is finished.
    console("sm_relay_say !close")
    server.wait_for_log("Relay: closed with code 1000 (bye from the server)")
    assert "The relay is not connected." in console("sm_relay_status")


def test_websocket_frames(server, console, websocket):
    console('sm_ws_frames "%s"' % websocket.url)
    log = server.wait_for_log("Closed with code 1000 (done)")

    assert "Message 1: 4 bytes of binary data" in log
    assert "Message 2: 300000 bytes of binary data" in log
    assert "Pong: are you there?" in log


def test_compression_of_demos(server, console):
    console("sm_demos_compress")
    server.wait_for_log("Compressed demo2.dem: %d to " % len(DEMO_BYTES))
    server.wait_for_log("Compressed demo1.dem: %d to " % len(DEMO_BYTES))
    assert not server.file_exists("demo1.dem")
    assert server.file_exists("demo1.dem.zst")

    console("sm_demos_decompress demo1.dem.zst")
    server.wait_for_log("Unpacked demo1.dem: %d bytes" % len(DEMO_BYTES))
    assert server.read_file("demo1.dem") == DEMO_BYTES

    console("sm_demos_decompress demo1.dem.zst")
    server.wait_for_log("demo1.dem exists already.")

    console("sm_demos_decompress nothere.zst")
    server.wait_for_log("Cannot unpack nothere.zst: CompressError_OpenInput")


def test_compression_of_text(server, console):
    text = "rocket rocket rocket rocket rocket rocket sticky sticky sticky"
    console("sm_compress_text " + text)
    log = server.wait_for_log("and back: " + text)

    assert "gzip: %d bytes became " % len(text) in log


def test_crypt_verify_file(server, console):
    digest = hashlib.sha256(DEMO_BYTES).hexdigest()
    console("sm_verify_file %s %s" % (UPLOAD_FILE, digest.upper()))
    server.wait_for_log("%s is intact." % UPLOAD_FILE)

    console("sm_verify_file %s %s" % (UPLOAD_FILE, "0" * 64))
    server.wait_for_log("%s differs: its SHA-256 is %s" % (UPLOAD_FILE, digest))

    console("sm_verify_file missing.bin " + digest)
    server.wait_for_log("Cannot hash missing.bin: CryptError_OpenInput")


def test_crypt_hash_text(server, console):
    console("sm_hash_text abc")
    log = server.wait_for_log("SHA-256 raw:    32 bytes, the first is 0xba")

    digest = hashlib.sha256(b"abc").digest()
    assert "MD5:            " + hashlib.md5(b"abc").hexdigest() in log
    assert "SHA-1:          " + hashlib.sha1(b"abc").hexdigest() in log
    assert "SHA-256:        " + digest.hex() in log
    assert "SHA3-256:       " + hashlib.sha3_256(b"abc").hexdigest() in log
    assert "CRC-32:         352441c2" in log
    assert "SHA-256 base64: " + base64.b64encode(digest).decode() in log
    assert "SHA-256 b64url: " + base64.urlsafe_b64encode(digest).decode().rstrip("=") in log


def test_crypt_hmac_file(server, console):
    console("sm_hmac_file Jefe " + UPLOAD_FILE)
    expected = base64.b64encode(hmac.new(b"Jefe", DEMO_BYTES, hashlib.sha256).digest()).decode()
    server.wait_for_log("Digest: " + expected)


def test_crypt_hash_buffer(server, console):
    console("sm_hash_buffer abc")
    server.wait_for_log("Digest: " + hashlib.sha512(b"abc").hexdigest())
    server.wait_for_log("Digest: " + hmac.new(b"secret key", b"abc", hashlib.sha256).hexdigest())


def test_crypt_signed_webhook(server, console, http):
    console('sm_signed_url "%s/hook"' % http.url, "sm_signed_secret " + services.SIGNING_SECRET,
            "sm_signed_event match_started")
    server.wait_for_log("Signed event: accepted")

    request = http.requests_to("/hook")[-1]
    signature = hmac.new(services.SIGNING_SECRET.encode(), request.body, hashlib.sha256).hexdigest()
    assert request.headers["x-hub-signature-256"] == "sha256=" + signature
    assert json.loads(request.body)["event"] == "match_started"

    console("sm_signed_secret wrong", "sm_signed_event match_started")
    server.wait_for_log("Signed event: HTTP status 401")


def test_buffer_basics(server, console):
    console("sm_buffer_demo")
    log = server.wait_for_log("The cleared copy has 0 bytes")

    assert 'GetString from 7: "jump" (7 bytes)' in log
    assert "GetBytes from 11: 3 bytes: 0 10 255" in log
    assert 'Find "p" and NUL: 10' in log
    assert "The copy has 28 bytes, the original 14" in log


def test_buffer_whitelist(server, console, http):
    console('sm_whitelist_url "%s/whitelist.txt"' % http.url, "sm_whitelist_check")
    log = server.wait_for_log("%d items are banned" % len(services.BANNED_ITEMS))

    assert "The whitelist has %d bytes" % len(services.whitelist_text()) in log
    assert "  banned: " + services.BANNED_ITEMS[0] in log
