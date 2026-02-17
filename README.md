# openclaw-mcp

Pull any [OpenClaw](https://github.com/openclaw/openclaw) agent into MCP-compatible tools — Claude Code, Codex, Cursor, or anything that speaks MCP.

Point it at an OpenClaw workspace and it exposes three tools:

- **agent-bootstrap** — Load the agent's persona, context, memory, and current state. The agent's identity comes from its workspace files (`SOUL.md`, `USER.md`, `MEMORY.md`, etc.).
- **recall** — Search the agent's memory and connected notes (local files + Seedvault if configured).
- **record** — Write observations, decisions, and lessons back into the agent's memory.

## How it works

An OpenClaw agent's workspace is a folder of markdown files with a known schema:

```
workspace/
├── SOUL.md          # Who the agent is
├── USER.md          # Who it's working with
├── IDENTITY.md      # Name, emoji, avatar
├── AGENTS.md        # Operating instructions
├── MEMORY.md        # Long-term memory
├── memory/          # Daily notes (YYYY-MM-DD.md)
├── notes/           # Check-in notes
└── initiative/      # Initiative pipeline output
    └── output/
        └── YYYY-MM-DD/
            └── initiative_brief.md
```

This server reads those files and exposes them via MCP. Any MCP-compatible tool can invoke the agent's persona, search its memory, and write back to it.

## Setup

```bash
# Clone
git clone https://github.com/collaborator-ai/collab-mcp.git
cd collab-mcp
npm install

# Configure
export OPENCLAW_WORKSPACE=/path/to/agent/workspace
export OPENCLAW_AUTH_TOKEN=your-api-key

# Optional: Seedvault integration
export SV_SERVER=https://seedvault.fly.dev
export SV_TOKEN=your-seedvault-token
export SV_CONTRIBUTOR=contributor-name

# Run
npx tsx src/index.ts
```

### Connect to Claude Code (SSE)

```bash
claude mcp add my-agent --transport sse "http://localhost:3100/mcp/sse?key=YOUR_TOKEN"
```

### Connect to Codex (Streamable HTTP)

```bash
codex mcp add my-agent --url "http://localhost:3100/mcp?key=YOUR_TOKEN"
```

### Remote access

For remote access, set up a tunnel (e.g., Cloudflare Tunnel) and configure:

```bash
export PUBLIC_URL=https://your-tunnel-url.example.com
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENCLAW_WORKSPACE` | Yes | Path to the OpenClaw agent's workspace directory |
| `OPENCLAW_AUTH_TOKEN` | Recommended | API key for authenticating MCP connections |
| `PORT` | No | Server port (default: 3100) |
| `TRANSPORT` | No | `sse` or `stdio` (default: `sse`) |
| `PUBLIC_URL` | No | Public URL for OAuth/remote access |
| `SV_SERVER` | No | Seedvault server URL |
| `SV_TOKEN` | No | Seedvault API token |
| `SV_CONTRIBUTOR` | No | Seedvault contributor to search |

## License

MIT
