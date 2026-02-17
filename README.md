# Collab MCP

Pull your [OpenClaw](https://github.com/openclaw/openclaw) agent into any MCP-compatible tool — Claude Code, Codex, Cursor, or anything that speaks MCP.

Your agent already has a persona, memory, and context. Collab MCP makes that available everywhere you work.

## What it does

Collab MCP is a lightweight server that reads your agent's workspace and exposes three tools via [MCP](https://modelcontextprotocol.io):

| Tool | What it does |
|------|-------------|
| **agent-bootstrap** | Loads the agent's identity, memory, stances, and current state into a new session |
| **recall** | Searches the agent's memory and notes for context on a specific topic |
| **record** | Writes observations, decisions, and lessons back into the agent's memory |

When you invoke your agent in Claude Code (or any MCP client), it arrives with everything it knows — your goals, recent decisions, open questions, and its own opinions. It doesn't start from scratch.

## How it works

An OpenClaw agent's workspace is a folder of markdown files:

```
~/.openclaw/workspace/
├── SOUL.md          # Who the agent is
├── USER.md          # Who it's working with
├── IDENTITY.md      # Name, emoji, metadata
├── MEMORY.md        # Long-term memory
├── memory/          # Daily notes (YYYY-MM-DD.md)
├── notes/           # Check-in notes
└── initiative/      # Initiative pipeline output
    └── output/
        └── YYYY-MM-DD/
            └── initiative_brief.md
```

Collab MCP reads these files and serves them over MCP. That's it. No database, no cloud sync, no account required. Your agent's workspace is the source of truth.

If your agent uses [Seedvault](https://seedvault.ai) for note sync, Collab MCP can also search those notes via the `recall` tool.

## Install

### Option A: Let your agent do it

If you're running an OpenClaw agent, give it the setup skill:

```
Read https://raw.githubusercontent.com/collaborator-ai/collab-mcp/main/SKILL.md and follow it.
```

Your agent will clone the repo, install dependencies, configure the server, and connect it to your coding tools. You can review the skill file first — it's short and readable.

### Option B: Do it yourself

```bash
# 1. Clone and build
git clone https://github.com/collaborator-ai/collab-mcp.git
cd collab-mcp
npm install
npm run build

# 2. Set environment variables
export OPENCLAW_WORKSPACE=~/.openclaw/workspace    # Path to your agent's workspace
export OPENCLAW_AUTH_TOKEN=$(openssl rand -hex 16)  # API key for connections
export PORT=3100

# 3. Start the server
node build/index.js

# 4. Connect to Claude Code
claude mcp add collab --transport sse \
  "http://localhost:3100/mcp/sse?key=$OPENCLAW_AUTH_TOKEN"
```

That's it. Open Claude Code and your agent's context is available.

### Codex

```bash
codex mcp add collab --url "http://localhost:3100/mcp?key=$OPENCLAW_AUTH_TOKEN"
```

### Remote access

For access from other machines, put a tunnel in front:

```bash
cloudflared tunnel --url http://localhost:3100
```

Then set `PUBLIC_URL` to the tunnel URL and use that in your `claude mcp add` command.

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENCLAW_WORKSPACE` | Yes | Path to the agent's workspace |
| `OPENCLAW_AUTH_TOKEN` | Recommended | API key for MCP connections. Without it, the server is open. |
| `PORT` | No | Server port (default: 3100) |
| `TRANSPORT` | No | `sse` or `stdio` (default: `sse`) |
| `PUBLIC_URL` | No | Public URL if behind a tunnel |
| `SV_SERVER` | No | Seedvault server URL |
| `SV_TOKEN` | No | Seedvault API token |
| `SV_CONTRIBUTOR` | No | Seedvault contributor to search |

## What your agent sees

When a coding tool calls `agent-bootstrap`, it receives:

- **Persona** — from `SOUL.md` (who the agent is, how it thinks)
- **Operating instructions** — from `AGENTS.md`
- **User profile** — from `USER.md`
- **Current state** — from the latest initiative brief (what's active, what's stuck)
- **Active stances** — opinions and decisions extracted from memory
- **Recent context** — from daily notes and check-ins

The agent doesn't recite this back. It internalizes it, orients in the current repo, and proposes what to do based on everything it knows.

## Security

- The server only reads from your local workspace. Nothing is sent to external services unless you configure Seedvault.
- The auth token is a simple API key passed as a URL parameter. This is fine for local use. For remote access, always use HTTPS (e.g., Cloudflare Tunnel).
- OAuth 2.1 is also supported for clients that need it (e.g., Claude Desktop). The flow auto-approves — no login page.

## License

MIT
