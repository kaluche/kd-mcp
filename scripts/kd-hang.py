#!/usr/bin/env python3
"""
kd-hang.py -- reproduce the "server frozen / can't interact" failure mode.

Theory (see fix_todo.md): the MCP SDK runs synchronous tools DIRECTLY on the
asyncio event loop (func_metadata.py:96 -> `return fn(...)`, no
anyio.to_thread offload). So one long-blocking kd command freezes the ENTIRE
server: every other request, from every session, stalls until it returns.

Experiment:
  1. ensure a connected session (reset if needed; target ends up halted).
  2. session A: call `go` with a long timeout. With no breakpoint set, `go`
     resumes the target and sits in expect() for the whole timeout -- holding
     the event loop the entire time.
  3. session B: ~2s later, time a trivial `status` call. If it stalls until A
     returns, one in-flight command froze the whole server == reproduced.

Usage:
  ./kd-hang.py [HOST:PORT] [BLOCK_SECONDS] [CONNECT_STRING]
"""
import json
import sys
import threading
import time
import urllib.request

HOSTPORT = sys.argv[1] if len(sys.argv) > 1 else "172.16.200.137:8001"
BLOCK = int(sys.argv[2]) if len(sys.argv) > 2 else 30
CONNECT_STRING = sys.argv[3] if len(sys.argv) > 3 else "net:port=55001,key=1.2.3.4"
ENDPOINT = HOSTPORT if HOSTPORT.startswith("http") else f"http://{HOSTPORT}/mcp"
ACCEPT = "application/json, text/event-stream"


def post(sid, body, timeout=240):
    data = json.dumps(body).encode()
    req = urllib.request.Request(ENDPOINT, data=data, method="POST")
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
    return {"_raw": raw[:200]}


def new_session(name):
    sid, _ = post(None, {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                   "clientInfo": {"name": name, "version": "1.0"}},
    }, timeout=20)
    post(sid, {"jsonrpc": "2.0", "method": "notifications/initialized"}, timeout=10)
    return sid


def call(sid, _id, tool, args=None):
    _, raw = post(sid, {
        "jsonrpc": "2.0", "id": _id, "method": "tools/call",
        "params": {"name": tool, "arguments": args or {}},
    })
    return parse(raw)


def main():
    print(f"endpoint: {ENDPOINT}  block={BLOCK}s")
    a = new_session("hang-A")
    b = new_session("hang-B")
    print(f"session A: {a}\nsession B (probe): {b}")

    st = call(b, 2, "status")
    print(f"\n### status: {st}")
    if not st.get("connected"):
        print("### not connected -> reset to establish a session")
        print("   ", call(a, 3, "reset", {"connect_string": CONNECT_STRING, "timeout": 90}))

    # baseline latency with nothing in flight
    t = time.monotonic()
    call(b, 4, "status")
    print(f"\n### baseline status latency: {time.monotonic() - t:.2f}s")

    # fire the blocker on A
    a_dur = {}
    def blocker():
        t0 = time.monotonic()
        a_dur["res"] = call(a, 5, "go", {"timeout": BLOCK})
        a_dur["dur"] = time.monotonic() - t0
    th = threading.Thread(target=blocker)
    print(f"\n### session A: go(timeout={BLOCK}) -- holds the event loop")
    th.start()

    time.sleep(2)
    print("### session B: status while A is blocking ...")
    t = time.monotonic()
    call(b, 6, "status")
    probe = time.monotonic() - t
    print(f"### probe latency: {probe:.2f}s")

    th.join()
    print(f"\n### A (go) returned after {a_dur.get('dur', 0):.2f}s: {a_dur.get('res')}")

    print("\n=== verdict ===")
    if probe > 5:
        print(f"REPRODUCED: a trivial status stalled {probe:.1f}s because one "
              f"in-flight `go` froze the entire server (event-loop blocking).")
    else:
        print(f"NOT reproduced this run: probe stayed fast ({probe:.2f}s).")


if __name__ == "__main__":
    main()
