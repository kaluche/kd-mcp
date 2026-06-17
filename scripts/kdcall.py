#!/usr/bin/env python3
"""
kdcall.py -- one-shot MCP tool caller for a kd-mcp streamable-http server.

Opens a fresh MCP session, calls one tool, prints the text result. The kd
debug session lives in the server's global state, so it persists across these
short-lived MCP sessions.

Usage:
  ./kdcall.py [HOST:PORT] TOOL ['JSON_ARGS']
Examples:
  ./kdcall.py 172.16.200.137:8001 status
  ./kdcall.py 172.16.200.137:8001 raw '{"cmd":"!process 0 0 lsass.exe","timeout":30}'
"""
import json
import sys
import urllib.request

HOSTPORT = sys.argv[1] if len(sys.argv) > 1 else "172.16.200.137:8001"
TOOL = sys.argv[2] if len(sys.argv) > 2 else "status"
ARGS = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
ENDPOINT = HOSTPORT if HOSTPORT.startswith("http") else f"http://{HOSTPORT}/mcp"
ACCEPT = "application/json, text/event-stream"


def post(sid, body, timeout=240):
    req = urllib.request.Request(ENDPOINT, data=json.dumps(body).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", ACCEPT)
    if sid:
        req.add_header("mcp-session-id", sid)
    resp = urllib.request.urlopen(req, timeout=timeout)
    return resp.headers.get("mcp-session-id"), resp.read().decode("utf-8", "replace")


def parse(raw):
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            line = line[5:].strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if "result" in obj:
            try:
                return json.loads(obj["result"]["content"][0]["text"])
            except Exception:
                return obj["result"]
        if "error" in obj:
            return {"_error": obj["error"]}
    return {"_raw": raw[:300]}


def main():
    sid, _ = post(None, {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                   "clientInfo": {"name": "kdcall", "version": "1.0"}},
    }, timeout=20)
    post(sid, {"jsonrpc": "2.0", "method": "notifications/initialized"}, timeout=10)
    res = parse(post(sid, {
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": TOOL, "arguments": ARGS},
    })[1])
    out = res.get("output") if isinstance(res, dict) and "output" in res else res
    if isinstance(out, str):
        print(out)
    else:
        print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
