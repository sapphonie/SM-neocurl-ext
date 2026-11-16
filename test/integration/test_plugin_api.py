# Copyright 2026 davenonymous
"""Runs pawn/scripting/curl_ext_test.sp, the plugin that checks the plugin API from inside the server."""

import re


def test_every_check_of_the_test_plugin_passes(server, console, http, websocket):
    console('curl_ext_test_http_url "%s/index.html"' % http.url, 'curl_ext_test_ws_url "%s"' % websocket.url,
            "sm_curl_ext_test")
    log = server.wait_for_log("[curl_ext_test] DONE", timeout=90)

    lines = [line.strip() for line in log.splitlines() if "[curl_ext_test]" in line]
    failed = [line for line in lines if "FAIL" in line]
    skipped = [line for line in lines if "SKIP" in line]
    assert not failed, "\n".join(failed)
    assert not skipped, "\n".join(skipped)

    summary = re.search(r"DONE (\d+) passed, (\d+) failed", log)
    assert summary, "No summary line"
    assert int(summary.group(1)) > 0
    assert int(summary.group(2)) == 0
