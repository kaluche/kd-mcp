# kd-mcp

An MCP (Model Context Protocol) server wrapping `kd.exe` for Windows kernel debugging.
Spawns kd.exe as a subprocess and exposes its functionality as 22 MCP tools.
Handles KDNET connections, breakpoints, memory reads, register inspection, and symbol
resolution without the threading limitations of DbgEng COM wrappers.

> Designed to pair with [hyperv-mcp](https://github.com/originsec/hyperv-mcp),
> which manages Hyper-V VMs and configures KDNET inside guests via PowerShell
> Direct. Use `hyperv-mcp` to snapshot a VM and set up KDNET, then pass the
> resulting `kernel_attach_string` to `kd-mcp`'s `kernel_attach` to drop into a
> kernel debug session.

---

## Requirements

- Windows 10/11 with [Windows Debugging Tools](https://developer.microsoft.com/windows/downloads/windows-sdk/) installed
- Python 3.10+
- A target kernel connected over KDNET

---

## Installation

Install directly from GitHub:

```powershell
pip install git+https://github.com/originsec/kd-mcp.git
```

This installs the `kd-mcp` console script and pulls in the `mcp` dependency automatically.

To install a specific revision (tag or commit):

```powershell
pip install git+https://github.com/originsec/kd-mcp.git@v0.1.0
```

### kd.exe location

The server defaults to:

```
C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe
```

Override with the `KD_EXE` environment variable if installed elsewhere:

```powershell
$env:KD_EXE = "C:\path\to\kd.exe"
```

---

## Connecting to MCP clients

### Claude Code (CLI)

```powershell
claude mcp add kd -- kd-mcp
```

### .mcp.json

```json
{
  "mcpServers": {
    "kd": {
      "command": "kd-mcp"
    }
  }
}
```

If you need to pin `KD_EXE` per-config:

```json
{
  "mcpServers": {
    "kd": {
      "command": "kd-mcp",
      "env": { "KD_EXE": "C:\\path\\to\\kd.exe" }
    }
  }
}
```

You can also invoke the module directly without the console script:

```powershell
python -m kd_mcp
```

---

## Remote / HTTP transport

By default the server speaks MCP over stdio, which assumes your MCP client runs on the
same Windows machine as `kd.exe`. To drive it from another machine (for example, Claude
Code running on a Linux box), start the server with the streamable-http transport on the
debug host and connect to it over the network:

```powershell
# On the debug host (the machine running kd.exe):
python -m kd_mcp --transport streamable-http --host 0.0.0.0 --port 8001
```

Then register it from the client machine:

```bash
claude mcp add --transport http kd http://<debug-host-ip>:8001/mcp
```

`kd.exe` still runs on the debug host; only the MCP traffic crosses the network. The
KDNET connection (`kernel_attach`) is between the debug host and the target kernel as
usual.

> The HTTP transport has no authentication. Bind it to `0.0.0.0` only on a trusted,
> isolated network such as a lab debug subnet.

---

## Development install

```powershell
git clone https://github.com/originsec/kd-mcp.git
cd kd-mcp
pip install -e .
```

---

## Available Tools (21 total)

### Session

| Tool | Parameters | Returns |
|------|-----------|---------|
| `kernel_attach` | `connect_string`, `reset_vm?`, `timeout` | `{status, kernel_version, attempts, output}` |
| `status` | — | `{connected, pid?}` |
| `detach` | — | `{status}` |

**`kernel_attach`** — Launches kd.exe and connects via KDNET. Auto-respawns kd.exe on
connection failures until `timeout` expires, so it can catch the KDNET hello packet
whenever the target becomes ready (e.g. after a VM reboot). Pass `reset_vm` with a
Hyper-V VM name to hard-reset the VM 2 seconds after kd.exe starts.

`connect_string` format: `"net:port=50000,key=a1b2.c3d4.e5f6.a7b8.c9d0"`

### Execution Control

| Tool | Parameters | Returns |
|------|-----------|---------|
| `go` | `timeout` | `{status, output}` |
| `break_in` | `timeout` | `{status, output}` |
| `step_into` | — | `{output}` |
| `step_over` | — | `{output}` |

`go` resumes execution (`g`) and waits for the next break event.
`break_in` sends Ctrl+Break / NMI over KDNET to halt a running kernel.

### Breakpoints

| Tool | Parameters | Returns |
|------|-----------|---------|
| `bp` | `address`, `once` | `{output}` |
| `hw_bp` | `address`, `width`, `access` | `{output}` |
| `list_bps` | — | `{output}` |
| `remove_bp` | `bp_id` | `{output}` |

`address` accepts symbols or hex addresses: `"nt!NtCreateFile"`, `"fffff805\`1234abcd"`

`hw_bp` access types: `"e"` = execute (default), `"r"` = read, `"w"` = write.
`remove_bp` defaults to `"*"` (clear all breakpoints).

### Inspection

| Tool | Parameters | Returns |
|------|-----------|---------|
| `raw` | `cmd`, `timeout` | `{output}` |
| `get_regs` | — | `{output}` |
| `read_mem` | `address`, `count`, `width` | `{output}` |
| `stack_trace` | `frames` | `{output}` |
| `whereami` | — | `{rip, symbol, stack}` |
| `list_modules` | `pattern?` | `{output}` |
| `find_symbol` | `pattern` | `{output}` |
| `addr_to_symbol` | `address` | `{output}` |
| `set_sympath` | `path?` | `{output}` |
| `reload_symbols` | `module?` | `{output}` |

`raw` executes any kd command directly: `"!process 0 0"`, `"dt nt!_EPROCESS @$proc"`, etc.

`read_mem` `width` values: `1` = byte (db), `2` = word (dw), `4` = dword (dd), `8` = qword (dq).

`whereami` returns current RIP, nearest symbol (`ln`), and top 5 stack frames in one call.

`set_sympath` with no argument queries the current path. Example path:
`"srv*C:\\symbols*https://msdl.microsoft.com/download/symbols"`

## Typical Workflow

```
# 1. Attach kd.exe (connect_string from your KDNET setup)
kernel_attach(connect_string="net:port=50000,key=a1b2.c3d4.e5f6.a7b8.c9d0",
              reset_vm="debug-vm")

# 2. Set a breakpoint and resume
bp(address="nt!NtCreateFile")
go()

# 3. Inspect on break
whereami()
stack_trace(frames=30)
read_mem(address="@rcx", count=32, width=8)

# 4. Continue or detach
go()
detach()
```

---

## Contributing

Issues and PRs welcome. This is a research tool, not a product — expect rough edges and breaking changes between versions.

---

## License

Apache 2.0 — see [LICENSE](./LICENSE) and [NOTICE](./NOTICE)

Built by [Origin](https://originhq.com) for security research and red team operations.
