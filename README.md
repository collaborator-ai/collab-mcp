# collab-mcp

**Collaborator MCP Server** — bring your Collaborator's accumulated context and judgment into any MCP-compatible AI tool.

## What is this?

When everything is buildable, the bottleneck becomes knowing the *right* thing to build. Collaborator helps you decide what and why. `/collab` brings that judgment into the tools you're already building with.

This MCP server exposes two tools:

- **`collab-bootstrap`** — Returns a synthesized context payload: persona, user context, active goals, and recent state. Think of it as your Collaborator briefing you on what matters right now.
- **`recall`** — Search the Collaborator's workspace files by keyword. When you need to pull specific context from notes, goals, or memory.

## Quick Start

### Claude Code (SSE transport)
```bash
claude mcp add collab-mcp --transport sse "https://your-server.example.com/mcp/sse?key=YOUR_API_KEY"
```

### Codex (Streamable HTTP)
```bash
codex mcp add collab-mcp --url "https://your-server.example.com/mcp?key=YOUR_API_KEY"
```

### stdio (local)
```bash
COLLAB_WORKSPACE=/path/to/workspace node build/index.js
```

## Setup

```bash
npm install
npm run build
```

### Environment Variables

| Variable | Description | Default |
|---|---|---|
| `COLLAB_WORKSPACE` | Path to the Collaborator workspace | `~/.openclaw/workspace` |
| `COLLAB_AUTH_TOKEN` | API key for SSE/HTTP transports | *(none)* |
| `PORT` | Server port | `3100` |
| `TRANSPORT` | Transport mode: `stdio`, `sse` | `sse` |
| `PUBLIC_URL` | Public URL (for OAuth metadata) | `http://localhost:3100` |
| `SV_SERVER` | Seedvault server URL | `https://seedvault.fly.dev` |
| `SV_TOKEN` | Seedvault contributor token | *(none)* |

### Running

```bash
# SSE mode (Claude Code, remote access)
COLLAB_AUTH_TOKEN=your-secret TRANSPORT=sse npm start

# stdio mode (local piping)
TRANSPORT=stdio npm start
```

## Architecture

This server is the **invocation layer** of a two-part system:

1. **Collaborator process** (continuous) — watches input streams, maintains context, develops perspective
2. **`/collab` MCP server** (this repo) — exposes that accumulated understanding to any MCP-compatible tool

The server reads from the Collaborator's workspace files (SOUL.md, USER.md, GOALS.md, memory/, notes/) and synthesizes them into a coherent briefing. The Collaborator process does the reading and thinking; `/collab` delivers it.

## Transports

- **SSE** — Server-Sent Events, works with Claude Code. Auth via `?key=` query param.
- **Streamable HTTP** — Works with Codex and other HTTP-based MCP clients. Auth via `?key=` query param.
- **stdio** — Standard I/O piping for local use. No auth needed.
- **OAuth 2.1** — For Claude Desktop app (WIP).

## Part of [Collaborator](https://collaborator.bot)

*Thinks for itself. Creates with you.*

---

Built by [Collaborator AI](https://github.com/collaborator-ai)
