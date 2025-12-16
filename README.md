<p align="center">
  <img src=".github/assets/header.svg" alt="zsync" width="100%"/>
</p>

<p align="center">
  <code>nix run github:andrewgazelka/zsync -- watch ./local user@host:/remote</code>
</p>

A modern alternative to rsync and mutagen. Syncs files over SSH with automatic `.gitignore` support.

## Features

- **Native .gitignore**: Respects your existing ignore files automatically
- **Delta sync**: Only transfers what changed (rsync algorithm)
- **File watching**: Continuous sync with debouncing
- **Zero remote deps**: Agent binary auto-deploys via SSH
- **Fast**: BLAKE3 hashing, zstd compression, pure Rust

## Usage

```bash
# One-time sync
zsync sync ./project user@server:/home/user/project

# Watch mode (continuous)
zsync watch ./project user@server:/workspace

# Scan local directory
zsync scan ./project
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
flowchart TB
    subgraph Local["Local Machine"]
        CLI[CLI]
        SCAN[Scanner]
        DIFF[Diff Engine]
        FS[(Local Files)]
    end

    subgraph Transport["SSH Transport"]
        SSH[SSH Client]
        DEPLOY[Agent Deployer]
        PROTO[Binary Protocol]
    end

    subgraph Remote["Remote Host"]
        AGENT[zsync-agent]
        REMOTE_SCAN[Scanner]
        REMOTE_FS[(Remote Files)]
    end

    %% Local scanning
    CLI -->|scan| SCAN
    SCAN -->|read| FS
    SCAN -->|BLAKE3 hashes| DIFF

    %% Connection & deployment
    CLI -->|connect| SSH
    SSH -->|detect platform| DEPLOY
    DEPLOY -.->|auto-deploy if needed| AGENT

    %% Snapshot exchange
    CLI -->|request snapshot| PROTO
    PROTO -->|binary messages| AGENT
    AGENT -->|scan| REMOTE_SCAN
    REMOTE_SCAN -->|read| REMOTE_FS
    AGENT -->|snapshot| PROTO
    PROTO -->|hashes| DIFF

    %% Transfer
    DIFF -->|changed files| PROTO
    AGENT -->|write/delete| REMOTE_FS

    %% Styling
    classDef local fill:#e8f5e9,stroke:#1b5e20
    classDef transport fill:#e1f5fe,stroke:#01579b
    classDef remote fill:#f3e5f5,stroke:#4a148c
    classDef storage fill:#fff3e0,stroke:#e65100

    class CLI,SCAN,DIFF local
    class SSH,DEPLOY,PROTO transport
    class AGENT,REMOTE_SCAN remote
    class FS,REMOTE_FS storage
```

**Sync Flow:**
1. **Scan** - CLI scans local directory respecting `.gitignore`, computes BLAKE3 hashes
2. **Connect** - SSH authenticates, detects remote platform, auto-deploys agent if needed
3. **Snapshot** - Agent scans remote directory, returns hashes over binary protocol
4. **Diff** - CLI computes added/modified/removed files
5. **Transfer** - Changed files sent to agent, removed files deleted

## Status

Early development. Core sync works, watch mode works. Bidirectional sync coming soon.

---

MIT OR Apache-2.0
