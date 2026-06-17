#!/usr/bin/env bash
#
# kd-reset.sh -- force-recycle kd.exe on a kd-mcp streamable-http server.
#
# Calls the `reset` tool: hard-kills the current kd.exe and re-attaches over
# KDNET (reusing the supplied connect_string). Use this when the debugger is
# wedged and a graceful detach/break_in won't recover it.
#
# Usage:
#   ./kd-reset.sh [HOST:PORT] [CONNECT_STRING] [TIMEOUT]
# Examples:
#   ./kd-reset.sh
#   ./kd-reset.sh 172.16.200.137:8001 "net:port=55001,key=1.2.3.4"
#   ./kd-reset.sh 172.16.200.137:8001 "net:port=55001,key=1.2.3.4" 120

set -uo pipefail

ENDPOINT="http://${1:-172.16.200.137:8001}/mcp"
CONNECT_STRING="${2:-net:port=55001,key=1.2.3.4}"
TIMEOUT="${3:-90}"

ACCEPT='application/json, text/event-stream'

# --- open a session (MCP initialize), retry until we get a session id ----------
SID=""
for _ in 1 2 3; do
  SID=$(curl -s -m 15 -D - -o /dev/null -X POST "$ENDPOINT" \
    -H 'Content-Type: application/json' -H "Accept: $ACCEPT" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"kd-reset","version":"1.0"}}}' \
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
# call <tool> [json-arguments] -- prints the tool's text payload
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

echo; echo "### status before reset"
call status

echo; echo "### reset (force-kill kd.exe + re-attach over KDNET)"
call reset "{\"connect_string\":\"$CONNECT_STRING\",\"reconnect\":true,\"timeout\":$TIMEOUT}"

echo; echo "### status after reset"
call status
