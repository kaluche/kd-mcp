"""
kd_mcp.server -- MCP server wrapping kd.exe for Windows kernel debugging.

Spawns kd.exe as a subprocess and exposes its functionality as MCP tools.
Handles KDNET connections, breakpoints, memory reads, and register inspection
without the threading limitations of DbgEng COM wrappers.

Environment variables:
    KD_EXE  Path to kd.exe (default: WDK x64 location)
"""

import atexit
import functools
import os
import re
import signal
import subprocess
import sys
import threading
import time
from typing import Optional

import anyio
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
# kd.exe init failures that retrying cannot fix -- bail out immediately instead of
# respawning kd.exe in a tight loop. The most common case is the KDNET port already
# being held by another debugger (windbg.exe/kd.exe), which never clears on its own.
_FATAL_INIT_RE = re.compile(
    r"already in use|Debuggee initialization failed|"
    r"Kernel debugger failed initialization|HRESULT 0x80004005",
    re.IGNORECASE,
)
# KDNET link loss. kd.exe prints these while a command is in flight and the
# transport to the target dies (e.g. a bulk read over slow KDNET saturates the
# link). We surface this as a distinct, actionable status instead of a generic
# pattern-timeout so callers know a reset/resync (or a target reboot) is needed.
_TRANSPORT_LOST_RE = re.compile(
    r"Retry sending the same data packet|"
    r"transport connection between host kernel debugger and target .*? (?:seems|is) lost|"
    r"\[no_debuggee\]",
    re.IGNORECASE,
)
# Printed by kd.exe after a reset/revert when something host-side keeps sending
# to the KDNET UDP port (most often a stale kd.exe still bound to it). Used to
# enrich kernel_attach's failure message.
_BAD_PACKET_RE = re.compile(r"Bad packet sent from", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Windows Job Object -- guarantees kd.exe children die with this server.
#
# kd.exe is spawned as a child process. On Windows, killing or crashing the
# parent (or `taskkill`-ing it) does NOT kill the child, so orphaned kd.exe
# processes keep holding the KDNET UDP port -- after which no new kd.exe can
# bind it ("Failed to initialize IPv4 socket", HRESULT 0x80004005) and the only
# observed recovery was a manual taskkill / VM restart. Assigning every kd.exe
# to a job with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE makes Windows terminate them
# when our last handle to the job closes -- which happens automatically when
# this process exits for ANY reason, including a hard taskkill.
# ---------------------------------------------------------------------------

_JOB = None  # opaque job handle (HANDLE) on Windows; None elsewhere


def _ensure_job():
    """Create (once) a kill-on-close job object. Returns the handle or None."""
    global _JOB
    if _JOB is not None or os.name != "nt":
        return _JOB
    import ctypes
    from ctypes import wintypes

    class _BASIC(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
            ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _IO(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class _EXT(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BASIC),
            ("IoInfo", _IO),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
    JobObjectExtendedLimitInformation = 9

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    hjob = k32.CreateJobObjectW(None, None)
    if not hjob:
        return None
    info = _EXT()
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not k32.SetInformationJobObject(
        hjob, JobObjectExtendedLimitInformation,
        ctypes.byref(info), ctypes.sizeof(info),
    ):
        k32.CloseHandle(hjob)
        return None
    _JOB = hjob
    return _JOB


def _assign_to_job(pid: int) -> None:
    """Best-effort: put a kd.exe pid in the kill-on-close job."""
    if os.name != "nt":
        return
    hjob = _ensure_job()
    if not hjob:
        return
    import ctypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    PROCESS_SET_QUOTA = 0x0100
    PROCESS_TERMINATE = 0x0001
    hproc = k32.OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, False, pid)
    if not hproc:
        return
    try:
        k32.AssignProcessToJobObject(hjob, hproc)
    finally:
        k32.CloseHandle(hproc)


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
        # Tie kd.exe's lifetime to ours so it can't be orphaned holding the
        # KDNET port (see _ensure_job above).
        _assign_to_job(self.proc.pid)
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

    def kill(self, wait: float = 5.0) -> None:
        for fn in (self.proc.stdin.close, self.proc.terminate, self.proc.kill):
            try:
                fn()
            except Exception:
                pass
        # Wait for the OS to actually reap kd.exe. Until it fully exits it keeps
        # the KDNET UDP port bound; relaunching before then makes the new kd.exe
        # race the stale one for the KDNET hello -- the target then logs
        # "Bad packet sent from <host>" and the link never re-establishes
        # (see kernel_attach / issue: reset+revert recovery).
        try:
            self.proc.wait(timeout=wait)
        except Exception:
            pass

    def drain(self) -> None:
        """Discard any buffered output."""
        with self._lock:
            self._buf = ""

    def read_available(self) -> str:
        """Atomically take and clear whatever is currently buffered."""
        with self._lock:
            data = self._buf
            self._buf = ""
        return data


# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------

class _State:
    kd: Optional[KdProcess] = None
    last_connect_string: str = ""
    state: str = "disconnected"
    last_error: str = ""
    last_output_tail: str = ""
    last_pid: Optional[int] = None

STATE = _State()
mcp = FastMCP("kd")

# Serializes access to kd.exe's stdin/stdout. Every tool now runs in a worker
# thread (see _offload), so without this two concurrent commands would
# interleave writes and cannibalize each other's output from the shared buffer.
# Reentrant because reset() calls kernel_attach() on the same thread.
_LOCK = threading.RLock()


def _offload(fn):
    """
    Register a synchronous tool body as an MCP tool that runs in a worker
    thread instead of on the asyncio event loop.

    The MCP SDK calls synchronous tools directly on the event loop, so a single
    blocking kd command (go can wait 120s, kernel_attach 90s, or any command
    that hangs while the target is running) would freeze the ENTIRE server --
    no other request, including break_in, could run until it returned. Running
    the body in a thread keeps the loop free and lets break_in interrupt an
    in-flight go.
    """
    @mcp.tool(name=fn.__name__, description=(fn.__doc__ or "").strip())
    @functools.wraps(fn)
    async def wrapper(**kwargs):
        return await anyio.to_thread.run_sync(functools.partial(fn, **kwargs))

    return wrapper


@atexit.register
def _cleanup() -> None:
    """Make sure kd.exe doesn't outlive us even on a graceful exit."""
    if STATE.kd is not None:
        STATE.kd.kill()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class KdTransportLost(RuntimeError):
    """The KDNET link between the debug host and the target dropped."""


class KdDesyncError(RuntimeError):
    """A command timed out and the kd.exe pipe could not be resynced."""


def _require() -> KdProcess:
    if STATE.kd is None or not STATE.kd.is_alive():
        raise RuntimeError("Not connected -- call kernel_attach first.")
    return STATE.kd


def _transport_lost_msg(out: str) -> str:
    return (
        "KDNET transport to the target was lost (kd.exe is retrying packets / the "
        "target is [no_debuggee]). Bulk reads over KDNET -- whole-module 's'/'uf', "
        "wide wildcard 'x' -- can saturate the slow link. Narrow the range, or do "
        "heavy static work offline (Ghidra/IDA) and use KD only for targeted "
        "bp + reads. If the target is unreachable, call reset; a snapshot revert may "
        "need a full target reboot to re-arm KDNET.\nLast output:\n" + out[-800:]
    )


def _command_risk(cmd: str) -> Optional[str]:
    """Return a refusal reason for commands known to desync KDNET sessions."""
    stripped = cmd.strip()
    lowered = stripped.lower()
    if re.search(r"^s\s+-(?:d|q|b|w)\b", lowered):
        return (
            "whole-range kd memory searches are high risk over KDNET; use read_mem "
            "on a bounded range or run the search offline"
        )
    if re.search(r"^uf\b", lowered):
        return (
            "uf can emit very large disassemblies and desync KDNET; use bounded "
            "u <addr> L<count> chunks instead"
        )
    if re.search(r"^x\s+\S*\*", stripped, re.IGNORECASE):
        return (
            "wildcard symbol expansion can produce very large output; query a "
            "single symbol or a narrower prefix"
        )
    if lowered.startswith(".reload /f"):
        return (
            "forced symbol reloads can stall the KDNET session; prefer a plain "
            ".reload or attach with a longer timeout"
        )
    return None


def _guard_command(cmd: str, allow_dangerous: bool = False) -> None:
    reason = _command_risk(cmd)
    if reason and not allow_dangerous:
        raise ValueError(
            f"Refusing risky kd command {cmd!r}: {reason}. "
            "Pass allow_dangerous=true to run it anyway."
        )


def _err(exc: Exception) -> dict:
    """Map an exception from a kd command into a tool result dict, tagging the
    recoverable KDNET/pipe failures with a distinct, actionable status."""
    STATE.last_error = str(exc)
    if isinstance(exc, KdTransportLost):
        STATE.state = "transport_lost"
        return {"status": "transport_lost", "error": str(exc)}
    if isinstance(exc, KdDesyncError):
        STATE.state = "desynced"
        return {"status": "desynced", "error": str(exc)}
    return {"error": str(exc)}


def _resync_locked(kd: KdProcess, cmd: str, orig_timeout: float) -> None:
    """
    Called with _LOCK held after a prompt timeout. kd.exe is still mid-command
    and still emitting output; if we simply released the lock, that late output
    would contaminate the next command's prompt match and the whole session
    would be desynced. Send a break, wait a short bounded interval, and either
    recover the pipe to a clean prompt or report a real desync. Always raises.
    """
    kd.send_break()
    try:
        recovered = kd.expect(_PROMPT_RE, timeout=10.0)
    except TimeoutError:
        recovered = kd.read_available()
        STATE.last_output_tail = recovered[-800:]
        if _TRANSPORT_LOST_RE.search(recovered):
            STATE.state = "transport_lost"
            raise KdTransportLost(_transport_lost_msg(recovered)) from None
        STATE.state = "desynced"
        raise KdDesyncError(
            f"'{cmd}' did not return within {orig_timeout}s; sent a break but "
            f"kd.exe never returned to a prompt. The session is desynced or the "
            f"KDNET link is down -- call reset.\nLast output:\n{recovered[-800:]}"
        ) from None

    # kd exited mid-resync -> let RuntimeError from expect propagate as-is.
    kd.drain()
    STATE.state = "connected"
    STATE.last_output_tail = recovered[-800:]
    if _TRANSPORT_LOST_RE.search(recovered):
        STATE.state = "transport_lost"
        raise KdTransportLost(_transport_lost_msg(recovered)) from None
    raise TimeoutError(
        f"'{cmd}' exceeded {orig_timeout}s. Interrupted it with a break and "
        f"resynced the session to a clean prompt; re-run with a larger timeout "
        f"or a narrower command."
    )


def _cmd(cmd: str, timeout: float = 20.0, allow_dangerous: bool = False) -> str:
    """Send a command, wait for the next kd> prompt, return output (prompt stripped)."""
    _guard_command(cmd, allow_dangerous=allow_dangerous)
    kd = _require()
    with _LOCK:
        kd.drain()
        kd.sendline(cmd)
        try:
            raw = kd.expect(_PROMPT_RE, timeout=timeout)
        except TimeoutError:
            _resync_locked(kd, cmd, timeout)  # always raises
            raise  # pragma: no cover -- unreachable, keeps type-checkers happy
    STATE.last_output_tail = raw[-800:]
    if _TRANSPORT_LOST_RE.search(raw):
        STATE.state = "transport_lost"
        raise KdTransportLost(_transport_lost_msg(raw))
    STATE.state = "connected"
    STATE.last_error = ""
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

@_offload
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
    with _LOCK:
        if STATE.kd and STATE.kd.is_alive():
            try:
                # qd = quit and detach, leaves the target running.  Clear breakpoints
                # first so we don't strand int3s in guest code.
                STATE.kd.sendline("bc *")
                time.sleep(0.2)
                STATE.kd.sendline("qd")
                time.sleep(0.4)
            except Exception:
                pass
            old_pid = STATE.kd.proc.pid
            STATE.kd.kill()
            STATE.last_pid = old_pid

        args = [KD_EXE, "-k", connect_string]
        try:
            STATE.kd = KdProcess(args)
        except OSError as exc:
            STATE.state = "disconnected"
            STATE.last_error = str(exc)
            return {"status": "error", "message": f"Failed to launch kd.exe: {exc}"}

        STATE.state = "attaching"
        STATE.last_error = ""
        STATE.last_output_tail = ""
        STATE.last_pid = STATE.kd.proc.pid

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
                # Phase 1: wait for TCP connect OR KD handshake. kd.exe fires
                # "Connected to target" first; boot-time KDNET can then take a
                # long time to finish initial symbol / target validation.
                out = STATE.kd.expect(_ANY_CONNECTED_RE, timeout=remaining)
                STATE.last_output_tail = out[-800:]

                # We have a live KDNET association. From this point onward, do not
                # kill kd.exe merely because prompt validation takes too long; doing
                # so can leave the target rejecting later attach attempts until reboot.
                prompt_timeout = min(60.0, max(deadline - time.monotonic(), 1.0))
                try:
                    STATE.kd.send_break()
                    out += STATE.kd.expect(_PROMPT_RE, timeout=prompt_timeout)
                except TimeoutError:
                    out += STATE.kd.read_available()
                    STATE.state = "connected"
                    STATE.last_connect_string = connect_string
                    STATE.last_pid = STATE.kd.proc.pid
                    STATE.last_output_tail = out[-800:]
                    ver = re.search(r"Windows .*? Kernel Version .*", out)
                    return {
                        "status": "connected",
                        "validation": "prompt_timeout",
                        "attempts": attempt,
                        "pid": STATE.kd.proc.pid,
                        "kernel_version": ver.group(0) if ver else "unknown",
                        "message": (
                            "KDNET reported an established debugger connection, but kd.exe "
                            "did not return to a prompt before the validation timeout. The "
                            "existing kd.exe was kept alive; retry with a longer timeout or "
                            "use break_in/status rather than reset/kernel_attach."
                        ),
                        "output": out[-600:].strip(),
                    }

                if _TRANSPORT_LOST_RE.search(out):
                    STATE.state = "transport_lost"
                    STATE.last_error = _transport_lost_msg(out)
                    return {
                        "status": "transport_lost",
                        "attempts": attempt,
                        "pid": STATE.kd.proc.pid,
                        "error": STATE.last_error,
                    }

                ver = re.search(r"Windows .*? Kernel Version .*", out)
                STATE.last_connect_string = connect_string
                STATE.state = "connected"
                STATE.last_error = ""
                STATE.last_pid = STATE.kd.proc.pid
                STATE.last_output_tail = out[-800:]
                return {
                    "status": "connected",
                    "attempts": attempt,
                    "pid": STATE.kd.proc.pid,
                    "kernel_version": ver.group(0) if ver else "unknown",
                    "output": out[-600:].strip(),
                }

            except RuntimeError as exc:
                # kd.exe exited (connection refused, wrong key, etc.) -- respawn and retry.
                last_error = str(exc)
                STATE.last_error = last_error
                if STATE.kd:
                    STATE.kd.kill()
                STATE.kd = None
                STATE.state = "disconnected"
                if _FATAL_INIT_RE.search(last_error):
                    # Permanent failure -- respawning will only spin and can destabilize
                    # the server. Stop now with an actionable message.
                    return {
                        "status": "error",
                        "attempts": attempt,
                        "message": (
                            "kd.exe failed before attaching; this is usually another "
                            "kd.exe/windbg still holding the KDNET UDP port, a bad "
                            "connect string, or a target that needs a full reboot.\n" +
                            last_error[-600:]
                        ),
                    }
            except TimeoutError as exc:
                last_error = str(exc)
                STATE.last_error = last_error
                if STATE.kd:
                    STATE.kd.kill()
                STATE.kd = None
                STATE.state = "disconnected"

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(2.0, max(0.1, remaining / 10)))
            try:
                STATE.kd = KdProcess(args)
                STATE.state = "attaching"
                STATE.last_pid = STATE.kd.proc.pid
            except OSError as exc:
                last_error = str(exc)
                STATE.last_error = last_error
                time.sleep(min(2.0, max(0.1, deadline - time.monotonic())))

        STATE.state = "disconnected"
        STATE.last_error = last_error
        message = last_error
        if _BAD_PACKET_RE.search(last_error):
            message = (
                "Target reports 'Bad packet sent from <host>' on the KDNET port -- "
                "the KDNET hello is being rejected. Most likely a stale kd.exe is "
                "still bound to the KDNET UDP port (kill any leftover kd.exe/windbg "
                "and retry), or the target's dbgsettings (port/key) no longer match "
                "after a revert. If it persists, power-cycle the target (a snapshot "
                "revert alone may not re-arm KDNET).\n" + last_error[-600:]
            )
        return {"status": "error", "attempts": attempt, "message": message}


@mcp.tool()
def status() -> dict:
    """Return current debugger connection state without touching kd.exe stdin/stdout."""
    kd = STATE.kd
    alive = kd is not None and kd.is_alive()
    if not alive:
        if STATE.state not in ("transport_lost", "desynced"):
            STATE.state = "disconnected"
        return {
            "connected": False,
            "state": STATE.state,
            "last_pid": STATE.last_pid,
            "last_error": STATE.last_error,
            "last_output_tail": STATE.last_output_tail,
        }
    return {
        "connected": True,
        "state": STATE.state or "connected",
        "pid": kd.proc.pid,
        "last_connect_string": STATE.last_connect_string,
        "last_error": STATE.last_error,
        "last_output_tail": STATE.last_output_tail,
    }


@_offload
def detach() -> dict:
    """
    End the debugging session, leaving the target RUNNING.

    Uses 'qd' (quit and detach) rather than bare 'q'. A plain 'q' ends the kd
    session but leaves the target halted at its current break -- frozen, with no
    debugger attached -- which then needs a VM reset to recover. 'qd' detaches
    so the kernel keeps running.
    """
    with _LOCK:
        if STATE.kd:
            try:
                # Clear breakpoints first. A software breakpoint is an int 3
                # written into the target's code; if we leave one in a user
                # process (especially a critical one like lsass) and detach,
                # the process hits it with no debugger attached -> unhandled
                # exception -> CRITICAL_PROCESS_DIED bugcheck -> VM needs a reset.
                STATE.kd.sendline("bc *")
                time.sleep(0.2)
                STATE.kd.sendline("qd")
                time.sleep(0.4)
            except Exception:
                pass
            STATE.last_pid = STATE.kd.proc.pid
            STATE.kd.kill()
            STATE.kd = None
            STATE.state = "disconnected"
        return {"status": "disconnected"}


@_offload
def reset(connect_string: str = "", reconnect: bool = True, timeout: int = 90) -> dict:
    """
    Force-kill the current kd.exe and optionally reconnect.

    This deliberately does not take _LOCK before killing: a wedged command may be
    holding it. Dropping STATE.kd and killing the process makes that command's
    expect() see a dead process and release the lock; reconnect then happens
    normally.

    Args:
        connect_string: KDNET string. Empty = reuse last successful connect string.
        reconnect:      Reconnect after killing (default True). Set False to just
                        tear down the current kd.exe.
        timeout:        Seconds to keep trying for the reconnection (default 90).

    Returns: kernel_attach's result when reconnecting, else {status}.
    """
    old = STATE.kd
    old_pid = old.proc.pid if old else None
    STATE.kd = None
    STATE.state = "resetting"
    if old:
        try:
            # Best-effort breakpoint clear so a hard reset doesn't strand an int3
            # in guest code (e.g. lsass -> CRITICAL_PROCESS_DIED). No-ops if kd
            # is truly wedged; we kill regardless.
            old.sendline("bc *")
            time.sleep(0.2)
        except Exception:
            pass
        old.kill()
        STATE.last_pid = old_pid

    if not reconnect:
        STATE.state = "disconnected"
        return {"status": "killed", "killed_pid": old_pid}

    cs = connect_string or STATE.last_connect_string
    if not cs:
        STATE.state = "disconnected"
        return {
            "status": "killed",
            "killed_pid": old_pid,
            "message": "No connect_string to reconnect with; pass one or call kernel_attach.",
        }

    # kernel_attach is the async MCP wrapper; call the sync function underneath.
    result = kernel_attach.__wrapped__(connect_string=cs, timeout=timeout)
    if isinstance(result, dict):
        result.setdefault("killed_pid", old_pid)
        result.setdefault("reconnect", True)
    return result


# ---------------------------------------------------------------------------
# MCP tools -- execution control
# ---------------------------------------------------------------------------

@_offload
def go(timeout: int = 120) -> dict:
    """
    Resume kernel execution (g) and wait for the next break event.

    Args:
        timeout: Seconds to wait for the next break (default 120).

    Returns: {status, output}. status is "break" if the target stopped,
    "running" if it's still going after `timeout` (no breakpoint hit -- not an
    error), or "error".
    """
    kd = _require()
    with _LOCK:
        kd.drain()
        kd.sendline("g")
        try:
            out = kd.expect(_PROMPT_RE, timeout=float(timeout))
            if _TRANSPORT_LOST_RE.search(out):
                return {"status": "transport_lost", "error": _transport_lost_msg(out)}
            return {"status": "break", "output": out.strip()}
        except TimeoutError:
            # No prompt within the window == the target is still running. This
            # is the normal outcome when no breakpoint is set; break_in (which
            # does not need the lock) can interrupt it.
            return {"status": "running",
                    "message": f"Target still running after {timeout}s."}
        except RuntimeError as exc:
            return {"status": "error", "error": str(exc)}


@_offload
def break_in(timeout: int = 15) -> dict:
    """
    Force a break into the running kernel (Ctrl+Break / NMI over KDNET).

    Args:
        timeout: Seconds to wait for the break event (default 15).

    Returns: {status, output}
    """
    kd = _require()
    # Fire the NMI without taking the lock so we can interrupt an in-flight go.
    kd.send_break()
    # If a command (e.g. go) is currently holding the pipe, IT will consume the
    # prompt the break produces and return -- so we just report the signal was
    # sent. If nothing is in flight, grab the lock and collect the prompt here.
    if not _LOCK.acquire(blocking=False):
        return {"status": "sent",
                "message": "Break signal sent; an in-flight command will return it."}
    try:
        out = kd.expect(_PROMPT_RE, timeout=float(timeout))
        if _TRANSPORT_LOST_RE.search(out):
            return {"status": "transport_lost", "error": _transport_lost_msg(out)}
        return {"status": "break", "output": out.strip()}
    except TimeoutError:
        return {"status": "sent", "message": "Break signal sent; no prompt yet."}
    except RuntimeError as exc:
        return {"status": "error", "error": str(exc)}
    finally:
        _LOCK.release()


@_offload
def step_into() -> dict:
    """Single-step into next instruction (t)."""
    try:
        return {"output": _cmd("t", timeout=10)}
    except Exception as exc:
        return _err(exc)


@_offload
def step_over() -> dict:
    """Step over next instruction (p)."""
    try:
        return {"output": _cmd("p", timeout=10)}
    except Exception as exc:
        return _err(exc)


# ---------------------------------------------------------------------------
# MCP tools -- breakpoints
# ---------------------------------------------------------------------------

@_offload
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
        return _err(exc)


@_offload
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
        return _err(exc)


@_offload
def list_bps() -> dict:
    """List all breakpoints (bl)."""
    try:
        return {"output": _cmd("bl")}
    except Exception as exc:
        return _err(exc)


@_offload
def remove_bp(bp_id: str = "*") -> dict:
    """
    Remove a breakpoint.

    Args:
        bp_id: Breakpoint number, or '*' to clear all (default '*').
    """
    try:
        return {"output": _cmd(f"bc {bp_id}") or "(done)"}
    except Exception as exc:
        return _err(exc)


# ---------------------------------------------------------------------------
# MCP tools -- inspection
# ---------------------------------------------------------------------------

@_offload
def raw(cmd: str, timeout: int = 20, allow_dangerous: bool = False) -> dict:
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
        return {"output": _cmd(cmd, timeout=float(timeout), allow_dangerous=allow_dangerous)}
    except Exception as exc:
        return _err(exc)


@_offload
def get_regs() -> dict:
    """Read general-purpose registers at the current break context (r)."""
    try:
        return {"output": _cmd("r")}
    except Exception as exc:
        return _err(exc)


@_offload
def read_mem(address: str, count: int = 16, width: int = 1) -> dict:
    """
    Read memory (db/dw/dd/dq).

    Args:
        address: Hex address, e.g. "fffff805`12345678".
        count:   Number of units (default 16).
        width:   Unit bytes -- 1=byte, 2=word, 4=dword, 8=qword (default 1).
    """
    # Guard against link-saturating bulk reads. A single huge read over the slow
    # KDNET link is many round-trips and has been observed to destabilize/drop
    # the transport (see issue: whole-module reads). Cap it with an actionable
    # error rather than firing a read that can take the target offline.
    _MAX_UNITS = 0x4000
    if count > _MAX_UNITS:
        return {
            "error": (
                f"count={count:#x} units is too large for a single KDNET read "
                f"(cap {_MAX_UNITS:#x}). Bulk reads can saturate and drop the KDNET "
                f"link -- narrow the range, or do bulk extraction offline "
                f"(Ghidra/IDA) and use KD only for targeted reads."
            )
        }
    cmd_map = {1: "db", 2: "dw", 4: "dd", 8: "dq"}
    kd_cmd = f"{cmd_map.get(width, 'db')} {address} L{count:x}"
    try:
        return {"output": _cmd(kd_cmd)}
    except Exception as exc:
        return _err(exc)


@_offload
def stack_trace(frames: int = 20) -> dict:
    """
    Show the current call stack (k).

    Args:
        frames: Number of frames (default 20).
    """
    try:
        return {"output": _cmd(f"k {frames}")}
    except Exception as exc:
        return _err(exc)


@_offload
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
        return _err(exc)


@_offload
def list_modules(pattern: str = "", reload: bool = False) -> dict:
    """
    List loaded kernel modules (lm).

    Args:
        pattern: Optional name glob, e.g. "mmc*" or "tcpip*".
        reload:  Run a kernel '.reload' first (default False). Set this if a
                 driver you expect (e.g. http.sys, tcpip) doesn't show up: after
                 switching into a user-process context (.process /r) and doing
                 '.reload /user', lm enumerates that process's USER modules and
                 the kernel driver list disappears until a kernel '.reload'
                 rebuilds it. (The trailing "Unable to enumerate user-mode
                 unloaded modules" line from lm is a benign warning.)
    """
    try:
        if reload:
            _cmd(".reload", timeout=60)
        cmd = f"lm m {pattern}" if pattern else "lm"
        return {"output": _cmd(cmd, timeout=30)}
    except Exception as exc:
        return _err(exc)


@_offload
def find_symbol(pattern: str, allow_dangerous: bool = False) -> dict:
    """
    Resolve symbol pattern to addresses (x command).

    Args:
        pattern: Symbol glob, e.g. "nt!NtCreate*" or "mmc!ScOnOpen*".
    """
    try:
        return {"output": _cmd(f"x {pattern}", timeout=30, allow_dangerous=allow_dangerous)}
    except Exception as exc:
        return _err(exc)


@_offload
def addr_to_symbol(address: str) -> dict:
    """
    Resolve an address to its nearest symbol (ln).

    Args:
        address: Hex address, e.g. "fffff805`12345678".
    """
    try:
        return {"output": _cmd(f"ln {address}")}
    except Exception as exc:
        return _err(exc)


@_offload
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
        return _err(exc)


@_offload
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
        return _err(exc)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    global KD_EXE
    import argparse

    parser = argparse.ArgumentParser(
        description="MCP server wrapping kd.exe for Windows kernel debugging over KDNET",
    )
    parser.add_argument(
        "--kd-path",
        type=str,
        help="Path to kd.exe (overrides the KD_EXE environment variable)",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http"],
        default="stdio",
        help="Transport protocol to use (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind the HTTP server to (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind the HTTP server to (default: 8000)",
    )
    args = parser.parse_args()

    if args.kd_path:
        KD_EXE = args.kd_path

    if not os.path.exists(KD_EXE):
        import shutil
        found = shutil.which("kd.exe") or shutil.which("kd")
        if found:
            KD_EXE = found
        else:
            print(f"ERROR: kd.exe not found at {KD_EXE} and not in PATH.", file=sys.stderr)
            print("Set the KD_EXE environment variable or pass --kd-path to point to kd.exe.", file=sys.stderr)
            sys.exit(1)

    try:
        from importlib.metadata import version as _pkg_version
        _ver = _pkg_version("kd-mcp")
    except Exception:
        _ver = "unknown"

    if args.transport == "streamable-http":
        from mcp.server.transport_security import TransportSecuritySettings

        mcp.settings.host = args.host
        mcp.settings.port = args.port
        # The HTTP transport is unauthenticated and meant for a trusted network
        # (see README). FastMCP's DNS-rebinding protection otherwise rejects any
        # Host header that is not localhost, which blocks reaching the server by
        # its LAN IP. Disable it so the bind address is actually usable.
        mcp.settings.transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=False
        )
        endpoint = f"http://{args.host}:{args.port}{mcp.settings.streamable_http_path}"
        print(f"kd MCP server v{_ver} starting (streamable-http) on {endpoint}", file=sys.stderr)
        mcp.run(transport="streamable-http")
    else:
        print(f"kd MCP server v{_ver} starting (stdio)...", file=sys.stderr)
        mcp.run()


if __name__ == "__main__":
    main()
