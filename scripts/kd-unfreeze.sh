#!/usr/bin/env bash
#
# kd-unfreeze.sh -- get a stuck target out of a broken-in (frozen) state.
#
# When the kernel is broken into the debugger the whole target machine is
# halted. This clears every breakpoint and resumes execution so the target
# runs again.
#
# Two recovery paths:
#   1. Gentle: break_in (get a prompt) -> remove_bp * -> go.
#   2. Hard reset: if the gentle path is wedged (commands time out with empty
#      output -- usually a stray queued "g" that keeps re-resuming the kernel),
#      detach and re-attach a fresh kd.exe, then clear breakpoints and resume.
#
# The hard reset needs the KDNET connect_string, so pass it (or rely on the
# default) if you want the fallback to work.
#
# Usage:
#   ./kd-unfreeze.sh [HOST:PORT] [CONNECT_STRING]
# Examples:
#   ./kd-unfreeze.sh
#   ./kd-unfreeze.sh 192.168.56.11:8001 "net:port=55001,key=1.2.3.4"

set -uo pipefail

ENDPOINT="http://${1:-192.168.56.11:8001}/mcp"
CONNECT_STRING="${2:-net:port=55001,key=1.2.3.4}"

ACCEPT='application/json, text/event-stream'

# --- open a session (MCP initialize), retry until we get a session id ----------
SID=""
for _ in 1 2 3; do
  SID=$(curl -s -m 15 -D - -o /dev/null -X POST "$ENDPOINT" \
    -H 'Content-Type: application/json' -H "Accept: $ACCEPT" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"kd-unfreeze","version":"1.0"}}}' \
    | grep -i '^mcp-session-id:' | awk '{print $2}' | tr -d '\r')
  [ -n "$SID" ] && break
  sleep 1
done
if [ -z "$SID" ]; then
  echo "ERROR: no MCP session id from $ENDPOINT (is the server up?)" >&2
  exit 1
fi
echo "session: $SID"

# acknowledge initialization
curl -s -m 10 -X POST "$ENDPOINT" \
  -H 'Content-Type: application/json' -H "Accept: $ACCEPT" -H "mcp-session-id: $SID" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null

ID=1
# call <tool> [json-arguments] -- returns the tool's text payload on stdout
call() {
  ID=$((ID + 1))
  local args='{}'
  [ "$#" -ge 2 ] && args="$2"
  local body
  body=$(printf '{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"%s","arguments":%s}}' "$ID" "$1" "$args")
  curl -s -m 140 -N -X POST "$ENDPOINT" \
    -H 'Content-Type: application/json' -H "Accept: $ACCEPT" -H "mcp-session-id: $SID" \
    -d "$body" 2>&1 | sed 's/^data: //' | grep '"jsonrpc"' \
    | python3 -c '
import sys, json
try:
    obj = json.load(sys.stdin)
except Exception:
    print("(no/garbled response)"); sys.exit()
res = obj.get("result")
if res is None:
    print(json.dumps(obj.get("error", obj), indent=2)); sys.exit()
text = res["content"][0]["text"]
try:
    print(json.dumps(json.loads(text), indent=2))
except Exception:
    print(text)
'
}

# wedged? -- true if a tool result looks like a timeout / error with no output
wedged() {
  echo "$1" | grep -qiE '"error"|timeout'
}

echo; echo "### status (connected? pid?)"
call status

echo; echo "### break in (force a prompt; needed to issue commands)"
# Halt the target so kd presents a "kd>" prompt. Harmless if already broken in.
call break_in '{"timeout":20}'

echo; echo "### clear all breakpoints (bc *)"
CLEAR=$(call remove_bp '{"bp_id":"*"}')
echo "$CLEAR"

if wedged "$CLEAR"; then
  echo; echo "!!! session is wedged (command timed out). Hard-resetting kd.exe ..."
  echo; echo "### detach (force-kill kd.exe)"
  call detach
  echo; echo "### kernel_attach (fresh kd.exe, reconnect over KDNET)"
  call kernel_attach "{\"connect_string\":\"$CONNECT_STRING\",\"timeout\":90}"
  echo; echo "### clear all breakpoints (bc *) on the fresh session"
  call remove_bp '{"bp_id":"*"}'
fi

echo; echo "### list breakpoints (should be empty)"
call list_bps

echo; echo "### resume (unfreeze the target)"
# 'g' runs the kernel; with no breakpoint no prompt returns, so a short
# timeout is expected and means "running", not an error.
call raw '{"cmd":"g","timeout":4}'
echo "(target resumed)"
