<p align="center">
  <img src=".github/assets/header.svg" alt="zsync" width="100%"/>
</p>

<p align="center">
  <code>nix run github:andrewgazelka/zsync -- watch ./local user@host:/remote</code>
</p>

A modern alternative to rsync and mutagen for syncing files over SSH.

## Why zsync?

**Your remote server needs nothing installed.** zsync auto-deploys a tiny, statically-linked agent over SSH. No rsync, no dependencies, no setup — just SSH access.

| Feature | rsync | mutagen | zsync |
|---------|-------|---------|-------|
| Remote dependencies | rsync required | Auto-deploy (~50MB Go) | Auto-deploy (~3MB Rust) |
| Respects .gitignore | ❌ Manual exclude | ⚠️ Works but ignores global | ✅ **Automatic** |
| Watch mode | ❌ External tools | ✅ Built-in | ✅ Built-in |
| Intra-file delta sync | ✅ Fixed blocks | ❌ Whole files | ✅ **FastCDC** |

## Features

- **Zero remote dependencies** — Agent auto-deploys via SSH (Linux x86_64/aarch64)
- **Native .gitignore** — Respects your existing ignore files automatically
- **FastCDC delta sync** — Content-defined chunking transfers only changed bytes, not whole files
- **Watch mode** — Continuous sync with debouncing
- **Port forwarding** — Forward local ports to remote services through SSH
- **Static binaries** — Works on any Linux server, no glibc version issues
- **Fast** — BLAKE3 hashing, zstd compression, heed (LMDB) signature caching

## Quick Start

```bash
# One-time sync
zsync sync ./project user@server:/home/user/project

# Watch mode (continuous)
zsync watch ./project user@server:/workspace
```

## Install

```bash
# Nix (recommended)
nix run github:andrewgazelka/zsync

# Cargo
cargo install --git https://github.com/andrewgazelka/zsync
```

## How It Works

```mermaid
sequenceDiagram
    participant Local as Local Machine
    participant SSH as SSH Transport
    participant Remote as Remote Linux Server

    Local->>SSH: Connect via SSH
    SSH->>Remote: Detect platform (uname)
    Remote-->>SSH: Linux x86_64
    SSH->>Remote: Deploy zsync-agent (if needed)

    Note over Local,Remote: Agent is a single static binary — no dependencies

    Local->>Remote: Request snapshot
    Remote-->>Local: File hashes (BLAKE3)
    Local->>Local: Compute diff

    Note over Local,Remote: For modified files — intra-file delta sync

    Local->>Remote: Request chunk signature
    Remote-->>Local: FastCDC chunks (from cache or computed)
    Local->>Local: Match chunks, generate delta
    Local->>Remote: Send delta (only changed bytes, zstd compressed)
    Remote->>Remote: Apply delta atomically
```

**The key insight:** zsync embeds pre-compiled static agents for Linux x86_64 and aarch64. When you connect, it detects the remote platform, uploads the ~3MB agent binary, and runs it. The agent handles all file operations on the remote side.

No `apt install`. No version conflicts. No "rsync: command not found".

## Supported Platforms

**Local (where you run zsync):**
- macOS (Apple Silicon, Intel)
- Linux (x86_64, aarch64)

**Remote (where files sync to):**
- Any Linux server with SSH access (x86_64, aarch64)
- Works on minimal containers, VMs, cloud instances — anywhere with SSH

## Configuration

Create a `.zsync.toml` in your project root for advanced settings:

```toml
# Include files even if they're gitignored
include = [".env", "secrets/config.yaml"]

# Port forwarding (active during watch mode)
[[forward]]
local = 8080    # Listen on localhost:8080
remote = 8080   # Forward to remote:8080

[[forward]]
local = 3000
remote = 3000
remote_host = "api-server"  # Forward to api-server:3000 on the remote
```

### Port Forwarding

In watch mode, zsync can forward local ports to the remote machine through the SSH connection:

```bash
zsync watch ./project user@server:/workspace
# Output: Forwarding localhost:8080 -> localhost:8080
```

Access remote services at `http://localhost:8080` — no separate SSH tunnel needed.

## Status

Early development. Core sync and watch mode work. Bidirectional sync coming soon.

---

MIT OR Apache-2.0
