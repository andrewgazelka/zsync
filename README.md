# zsync

**Fast, modern file synchronization with native `.gitignore` support.**

```bash
zsync watch ./local user@host:/remote
```

## Why zsync?

Every existing sync tool has problems:

| Tool | Issue |
|------|-------|
| **rsync** | No file watching. No `.gitignore`. One-shot only. |
| **mutagen** | Ignores `.gitignore`. Requires manual `--ignore` patterns. Go binary. |
| **lsyncd** | Complex Lua config. No delta sync. |
| **unison** | Dated UI. No `.gitignore`. |

**zsync** fixes all of this:

- **Native `.gitignore` support** — respects your existing ignore files automatically
- **Delta sync** — only transfers what changed (rsync algorithm)
- **File watching** — continuous sync with debouncing
- **Zero remote deps** — agent binary auto-deploys via SSH
- **Fast** — BLAKE3 hashing, zstd compression, pure Rust

## Installation

```bash
# From source
cargo install --git https://github.com/andrewgazelka/zsync

# With Nix
nix run github:andrewgazelka/zsync
```

## Usage

### One-time sync

```bash
zsync sync ./project user@server:/home/user/project
```

### Watch mode (continuous)

```bash
zsync watch ./project user@server:/workspace --debounce 100
```

### Scan local directory

```bash
zsync scan ./project           # Summary
zsync scan ./project --format json  # Full snapshot
```

## How it works

```
┌─────────────┐                      ┌─────────────┐
│   Local     │                      │   Remote    │
│             │                      │             │
│  zsync CLI  │◄────── SSH ────────►│ zsync-agent │
│             │                      │             │
│  • scan     │      delta ops       │  • scan     │
│  • hash     │◄────────────────────►│  • apply    │
│  • watch    │      (zstd)          │  • verify   │
└─────────────┘                      └─────────────┘
```

1. **Scan** — Walk directory tree, respecting `.gitignore`
2. **Hash** — BLAKE3 content hashes for change detection
3. **Delta** — Compute rsync-style block deltas
4. **Compress** — zstd compress the delta
5. **Transfer** — Send via SSH
6. **Apply** — Reconstruct files on remote

## Architecture

```
crates/
├── core/        # Scanning, hashing, delta computation
├── transport/   # SSH transport, agent deployment
├── agent/       # Remote agent binary
└── cli/         # Main CLI with file watching
```

**Key crates:**
- `ignore` — gitignore parsing (same as ripgrep)
- `blake3` — fast cryptographic hashing
- `zstd` — compression
- `notify` — cross-platform file watching

## Comparison

| Feature | zsync | mutagen | rsync |
|---------|-------|---------|-------|
| `.gitignore` support | ✅ Native | ❌ Manual | ❌ No |
| File watching | ✅ | ✅ | ❌ |
| Delta sync | ✅ | ✅ | ✅ |
| Auto agent deploy | ✅ | ✅ | ❌ |
| Written in | Rust | Go | C |
| Bidirectional | 🔜 | ✅ | ❌ |

## License

MIT OR Apache-2.0
