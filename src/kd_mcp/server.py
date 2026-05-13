"""
kd_mcp.server -- MCP server wrapping kd.exe for Windows kernel debugging.

Spawns kd.exe as a subprocess and exposes its functionality as MCP tools.
Handles KDNET connections, breakpoints, memory reads, and register inspection
without the threading limitations of DbgEng COM wrappers.

Environment variables:
    KD_EXE  Path to kd.exe (default: WDK x64 location)
"""

import os
import re
import signal
import subprocess
import sys
import threading
import time
from typing import Optional

from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KD_EXE = os.environ.get(
    "KD_EXE",
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe",
)

# kd.exe prompt variants: "kd> ", "0: kd> ", "1: kd> "
_PROMPT_RE = re.compile(r"\d*:?\s*kd>\s*$")
_CONNECTED_RE = re.compile(r"Kernel Debugger connection established", re.IGNORECASE)
# Fired when the TCP/KDNET channel is up but the kernel hasn't broken yet.
# Matches: "Connected to target 169.254.x.x on port 50000 on local IP ..."
_TCP_CONNECTED_RE = re.compile(r"Connected to target .+ on port \d+", re.IGNORECASE)
# Wait for either event; which one fired tells us whether we need to break in.
_ANY_CONNECTED_RE = re.compile(
    r"(Kernel Debugger connection established|Connected to target .+ on port \d+)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# KdProcess -- subprocess wrapper with expect-style I/O
# ---------------------------------------------------------------------------

class KdProcess:
    """
    Wraps kd.exe. Reader thread accumulates stdout; expect() scans it for
    a pattern with a deadline, returning everything up to and including the
    match.
    """

    def __init__(self, args: list[str]) -> None:
        self.proc = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=-1,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )
        self._buf = ""
        self._lock = threading.Lock()
        self._ev = threading.Event()
        self._th = threading.Thread(target=self._reader, daemon=True, name="kd-reader")
        self._th.start()

    # -- reader thread -------------------------------------------------------

    def _reader(self) -> None:
        while True:
            try:
                # read1: returns whatever is in the pipe buffer immediately;
                # blocks only until at least 1 byte is available.
                chunk = self.proc.stdout.read1(4096)  # type: ignore[attr-defined]
            except (OSError, ValueError):
                self._ev.set()
                break
            if not chunk:
                if self.proc.poll() is not None:
                    self._ev.set()
                    break
                time.sleep(0.01)
                continue
            with self._lock:
                self._buf += chunk.decode("utf-8", errors="replace")
            self._ev.set()

    # -- public API ----------------------------------------------------------

    def expect(self, pattern: re.Pattern, timeout: float = 30.0) -> str:
        """
        Accumulate stdout until pattern matches anywhere in the buffer.
        Returns all accumulated text (including the match).
        Raises TimeoutError on timeout, RuntimeError if kd.exe exits.
        """
        accumulated = ""
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                accumulated += self._buf
                self._buf = ""
            if pattern.search(accumulated):
                return accumulated
            if self.proc.poll() is not None:
                raise RuntimeError(
                    f"kd.exe exited (code {self.proc.returncode}). "
                    f"Last output:\n{accumulated[-1000:]}"
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"Timeout ({timeout}s) waiting for pattern. "
                    f"Last output:\n{accumulated[-2000:]}"
                )
            self._ev.wait(min(remaining, 0.15))
            self._ev.clear()

    def sendline(self, cmd: str) -> None:
        self.proc.stdin.write((cmd + "\r\n").encode())
        self.proc.stdin.flush()

    def send_break(self) -> None:
        """Send Ctrl+Break to kd.exe -- triggers kernel break-in over KDNET."""
        try:
            os.kill(self.proc.pid, signal.CTRL_BREAK_EVENT)
        except Exception:
            pass

    def is_alive(self) -> bool:
        return self.proc.poll() is None

    def kill(self) -> None:
        for fn in (self.proc.stdin.close, self.proc.terminate, self.proc.kill):
            try:
                fn()
            except Exception:
                pass

    def drain(self) -> None:
        """Discard any buffered output."""
        with self._lock:
            self._buf = ""


# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------

class _State:
    kd: Optional[KdProcess] = None

STATE = _State()
mcp = FastMCP("kd")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _require() -> KdProcess:
    if STATE.kd is None or not STATE.kd.is_alive():
        raise RuntimeError("Not connected -- call kernel_attach first.")
    return STATE.kd


def _cmd(cmd: str, timeout: float = 20.0) -> str:
    """Send a command, wait for the next kd> prompt, return output (prompt stripped)."""
    kd = _require()
    kd.drain()
    kd.sendline(cmd)
    raw = kd.expect(_PROMPT_RE, timeout=timeout)
    # Strip the trailing prompt and leading echo of our command.
    out = _PROMPT_RE.sub("", raw).strip()
    # Remove first line if it looks like the command echo.
    lines = out.splitlines()
    if lines and lines[0].strip() == cmd.strip():
        out = "\n".join(lines[1:]).strip()
    return out


# ---------------------------------------------------------------------------
# MCP tools -- session
# ---------------------------------------------------------------------------

@mcp.tool()
def kernel_attach(
    connect_string: str,
    reset_vm: str = "",
    timeout: int = 90,
) -> dict:
    """
    Launch kd.exe and connect to a kernel over KDNET.

    kd.exe may exit immediately if the target is unreachable; this tool will
    respawn it until the full timeout expires so it catches the KDNET hello
    packet whenever the target becomes ready (e.g. after a VM reboot).

    Args:
        connect_string: KDNET string, e.g. "net:port=50000,key=1.2.3.4.5"
        reset_vm:       Hyper-V VM name to hard-reset 2 seconds after kd.exe
                        starts (so kd catches the boot-time KDNET packet).
        timeout:        Total seconds to keep trying for a connection (default 90).

    Returns: {status, kernel_version, attempts, output} or {status, message}
    """
    # Kill any previous session.
    if STATE.kd and STATE.kd.is_alive():
        try:
            STATE.kd.sendline("q")
            time.sleep(0.4)
        except Exception:
            pass
        STATE.kd.kill()
    STATE.kd = None

    args = [KD_EXE, "-k", connect_string]

    try:
        STATE.kd = KdProcess(args)
    except OSError as exc:
        return {"status": "error", "message": f"Failed to launch kd.exe: {exc}"}

    if reset_vm:
        subprocess.Popen(
            [
                "powershell", "-NoProfile", "-Command",
                f"Start-Sleep -Seconds 2; Restart-VM -Name '{reset_vm}' -Force",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    deadline = time.monotonic() + timeout
    attempt = 0
    last_error = "Timeout waiting for KDNET connection"

    while True:
        attempt += 1
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            # Phase 1: wait for TCP connect OR full KD handshake.
            # On a running system kd.exe fires "Connected to target" first;
            # the kernel won't complete the KD handshake until we break in.
            # On a boot-break system the full handshake arrives on its own.
            out = STATE.kd.expect(_ANY_CONNECTED_RE, timeout=remaining)
            # Phase 2: send break always.  Harmless if the kernel is already
            # halted (boot break); required to trigger the KD handshake on a
            # running system.
            STATE.kd.send_break()
            out += STATE.kd.expect(_PROMPT_RE, timeout=60)
            ver = re.search(r"Windows \S+ \d+ \S+ x64", out)
            return {
                "status": "connected",
                "attempts": attempt,
                "kernel_version": ver.group(0) if ver else "unknown",
                "output": out[-600:].strip(),
            }
        except RuntimeError as exc:
            # kd.exe exited (connection refused, wrong key, etc.) -- respawn and retry
            last_error = str(exc)
            STATE.kd.kill()
            STATE.kd = None
            remaining = deadline - time.monotonic()
            if remaining <= 1:
                break
            time.sleep(1)
            try:
                STATE.kd = KdProcess(args)
            except OSError as oserr:
                STATE.kd = None
                return {"status": "error", "message": f"Failed to launch kd.exe: {oserr}"}
        except TimeoutError as exc:
            # Full timeout elapsed in a single attempt -- no point retrying
            last_error = str(exc)
            STATE.kd.kill()
            STATE.kd = None
            break

    # Ensure STATE is clean so subsequent calls get a clear "not connected" error
    if STATE.kd is not None:
        STATE.kd.kill()
        STATE.kd = None
    return {"status": "error", "attempts": attempt, "message": last_error}


@mcp.tool()
def status() -> dict:
    """Return current debugger connection state."""
    if STATE.kd is None or not STATE.kd.is_alive():
        return {"connected": False}
    return {"connected": True, "pid": STATE.kd.proc.pid}


@mcp.tool()
def detach() -> dict:
    """Quit kd.exe and end the debugging session."""
    if STATE.kd:
        try:
            STATE.kd.sendline("q")
            time.sleep(0.4)
        except Exception:
            pass
        STATE.kd.kill()
    STATE.kd = None
    return {"status": "disconnected"}


# ---------------------------------------------------------------------------
# MCP tools -- execution control
# ---------------------------------------------------------------------------

@mcp.tool()
def go(timeout: int = 120) -> dict:
    """
    Resume kernel execution (g) and wait for the next break event.

    Args:
        timeout: Seconds to wait for the next break (default 120).

    Returns: {status, output}
    """
    kd = _require()
    kd.drain()
    kd.sendline("g")
    try:
        out = kd.expect(_PROMPT_RE, timeout=float(timeout))
        return {"status": "break", "output": out.strip()}
    except TimeoutError as exc:
        return {"status": "timeout", "error": str(exc)}
    except RuntimeError as exc:
        return {"status": "error", "error": str(exc)}


@mcp.tool()
def break_in(timeout: int = 15) -> dict:
    """
    Force a break into the running kernel (Ctrl+Break / NMI over KDNET).

    Args:
        timeout: Seconds to wait for the break event (default 15).

    Returns: {status, output}
    """
    kd = _require()
    kd.drain()
    kd.send_break()
    try:
        out = kd.expect(_PROMPT_RE, timeout=float(timeout))
        return {"status": "break", "output": out.strip()}
    except TimeoutError:
        return {"status": "sent", "message": "Break signal sent; no prompt yet."}


@mcp.tool()
def step_into() -> dict:
    """Single-step into next instruction (t)."""
    try:
        return {"output": _cmd("t", timeout=10)}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def step_over() -> dict:
    """Step over next instruction (p)."""
    try:
        return {"output": _cmd("p", timeout=10)}
    except Exception as exc:
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# MCP tools -- breakpoints
# ---------------------------------------------------------------------------

@mcp.tool()
def bp(address: str, once: bool = False) -> dict:
    """
    Set a breakpoint.

    Args:
        address: Address or symbol -- e.g. "nt!NtCreateFile" or "fffff805`1234abcd"
        once:    One-shot breakpoint (cleared after first hit).

    Returns: {output}
    """
    prefix = "bp /1" if once else "bp"
    try:
        return {"output": _cmd(f"{prefix} {address}") or "(breakpoint set)"}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def hw_bp(address: str, width: int = 4, access: str = "e") -> dict:
    """
    Set a hardware breakpoint (ba command).

    Args:
        address: Target address.
        width:   Access width in bytes: 1, 2, 4, or 8 (default 4).
        access:  Access type -- "e"=execute, "r"=read, "w"=write (default "e").

    Returns: {output}
    """
    try:
        return {"output": _cmd(f"ba {access}{width} {address}") or "(hw bp set)"}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def list_bps() -> dict:
    """List all breakpoints (bl)."""
    try:
        return {"output": _cmd("bl")}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def remove_bp(bp_id: str = "*") -> dict:
    """
    Remove a breakpoint.

    Args:
        bp_id: Breakpoint number, or '*' to clear all (default '*').
    """
    try:
        return {"output": _cmd(f"bc {bp_id}") or "(done)"}
    except Exception as exc:
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# MCP tools -- inspection
# ---------------------------------------------------------------------------

@mcp.tool()
def raw(cmd: str, timeout: int = 20) -> dict:
    """
    Execute any raw kd command and return its output.

    Examples:
        "lm", "!process 0 0", "dt nt!_EPROCESS @$proc",
        "r", "k 20", "!token", "vertarget"

    Args:
        cmd:     kd command string.
        timeout: Seconds to wait for the prompt (default 20).
    """
    try:
        return {"output": _cmd(cmd, timeout=float(timeout))}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def get_regs() -> dict:
    """Read general-purpose registers at the current break context (r)."""
    try:
        return {"output": _cmd("r")}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def read_mem(address: str, count: int = 16, width: int = 1) -> dict:
    """
    Read memory (db/dw/dd/dq).

    Args:
        address: Hex address, e.g. "fffff805`12345678".
        count:   Number of units (default 16).
        width:   Unit bytes -- 1=byte, 2=word, 4=dword, 8=qword (default 1).
    """
    cmd_map = {1: "db", 2: "dw", 4: "dd", 8: "dq"}
    kd_cmd = f"{cmd_map.get(width, 'db')} {address} L{count:x}"
    try:
        return {"output": _cmd(kd_cmd)}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def stack_trace(frames: int = 20) -> dict:
    """
    Show the current call stack (k).

    Args:
        frames: Number of frames (default 20).
    """
    try:
        return {"output": _cmd(f"k {frames}")}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def whereami() -> dict:
    """Show current RIP, its nearest symbol, and the top 5 stack frames."""
    try:
        rip_out = _cmd("r rip")
        m = re.search(r"rip=([0-9a-f`]+)", rip_out, re.IGNORECASE)
        rip = m.group(1) if m else "@rip"
        return {
            "rip": rip_out,
            "symbol": _cmd(f"ln {rip}"),
            "stack": _cmd("k 5"),
        }
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def list_modules(pattern: str = "") -> dict:
    """
    List loaded kernel modules (lm).

    Args:
        pattern: Optional name glob, e.g. "mmc*".
    """
    cmd = f"lm m {pattern}" if pattern else "lm"
    try:
        return {"output": _cmd(cmd, timeout=30)}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def find_symbol(pattern: str) -> dict:
    """
    Resolve symbol pattern to addresses (x command).

    Args:
        pattern: Symbol glob, e.g. "nt!NtCreate*" or "mmc!ScOnOpen*".
    """
    try:
        return {"output": _cmd(f"x {pattern}", timeout=30)}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def addr_to_symbol(address: str) -> dict:
    """
    Resolve an address to its nearest symbol (ln).

    Args:
        address: Hex address, e.g. "fffff805`12345678".
    """
    try:
        return {"output": _cmd(f"ln {address}")}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def set_sympath(path: str = "") -> dict:
    """
    Set or show the symbol search path (.sympath).

    Args:
        path: Symbol path string.  Omit to just query the current path.
              Example: "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols"
    """
    cmd = f".sympath {path}" if path else ".sympath"
    try:
        return {"output": _cmd(cmd, timeout=60)}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def reload_symbols(module: str = "") -> dict:
    """
    Reload symbol information (.reload).

    Args:
        module: Specific module to reload, e.g. "mmc.exe".  Empty = all.
    """
    cmd = f".reload {module}" if module else ".reload"
    try:
        return {"output": _cmd(cmd, timeout=60)}
    except Exception as exc:
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    global KD_EXE
    if not os.path.exists(KD_EXE):
        import shutil
        found = shutil.which("kd.exe") or shutil.which("kd")
        if found:
            KD_EXE = found
        else:
            print(f"ERROR: kd.exe not found at {KD_EXE} and not in PATH.", file=sys.stderr)
            print("Set KD_EXE environment variable to point to kd.exe.", file=sys.stderr)
            sys.exit(1)

    print("kd MCP server starting (stdio)...", file=sys.stderr)
    mcp.run()


if __name__ == "__main__":
    main()
