# Collab MCP — Setup Skill

Install and run the Collab MCP server so your agent's persona, memory, and context are available in any MCP-compatible tool (Claude Code, Codex, Cursor, etc.).

## What This Does

Collab MCP exposes your OpenClaw agent's workspace as three MCP tools:

- **agent-bootstrap** — Load the agent's identity, memory, stances, and current state
- **recall** — Search the agent's memory and connected notes
- **record** — Write observations and decisions back into memory

Any tool that speaks MCP can invoke your agent — its personality, context, and judgment travel with you.

## Prerequisites

- An OpenClaw agent with a workspace (you're probably reading this as one)
- Node.js 20+ (check: `node --version`)
- A workspace with at least `SOUL.md` and `MEMORY.md`

## Setup

### 1. Clone and install

```bash
cd ~/.openclaw
git clone https://github.com/collaborator-ai/collab-mcp.git
cd collab-mcp
npm install
npm run build
```

### 2. Configure environment

Create `~/.openclaw/collab-mcp/.env`:

```bash
# Required: path to your agent's workspace
OPENCLAW_WORKSPACE=~/.openclaw/workspace

# Required: API key for MCP connections (generate something random)
OPENCLAW_AUTH_TOKEN=<generate-a-random-token>

# Optional: Seedvault integration (if your agent uses it)
# SV_SERVER=https://seedvault.fly.dev
# SV_TOKEN=<your-seedvault-token>
# SV_CONTRIBUTOR=<contributor-name>

# Server config
PORT=3100
TRANSPORT=sse
```

To generate a token: `node -e "console.log('collab-' + require('crypto').randomBytes(16).toString('hex'))"`

### 3. Start the server

```bash
cd ~/.openclaw/collab-mcp
source .env 2>/dev/null; export $(grep -v '^#' .env | xargs)
nohup node build/index.js > /tmp/collab-mcp.log 2>&1 &
echo $! > /tmp/collab-mcp.pid
```

Verify it's running:

```bash
curl -s http://localhost:3100/health
# Should return: {"status":"ok","server":"openclaw-mcp","version":"0.2.0"}
```

### 4. Connect to your coding tools

**Claude Code (SSE):**
```bash
claude mcp add collab --transport sse "http://localhost:3100/mcp/sse?key=YOUR_TOKEN"
```

**Codex (Streamable HTTP):**
```bash
codex mcp add collab --url "http://localhost:3100/mcp?key=YOUR_TOKEN"
```

Replace `YOUR_TOKEN` with the `OPENCLAW_AUTH_TOKEN` you set in step 2.

### 5. (Optional) Remote access via tunnel

If you want to use Collab MCP from other machines:

```bash
# Using Cloudflare Tunnel
cloudflared tunnel --url http://localhost:3100

# Then add PUBLIC_URL to your .env
PUBLIC_URL=https://your-tunnel-url.trycloudflare.com
```

## Usage

Once connected, use `/collab` in Claude Code or Codex to invoke your agent:

1. Call `agent-bootstrap` first — this loads your agent's full context
2. Use `recall` to search for specific topics when needed
3. Use `record` to write back observations or decisions

See `collab.md` in this repo for the skill file that teaches coding tools how to use these tools.

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `connection refused` | Server not running. Check `cat /tmp/collab-mcp.log` |
| `403 Forbidden` | Wrong token. Check `OPENCLAW_AUTH_TOKEN` matches the URL `?key=` param |
| `agent-bootstrap returns empty` | `OPENCLAW_WORKSPACE` doesn't point to a valid workspace. Need at least `SOUL.md` |
| Server dies on restart | Re-run step 3. Add to your `HEARTBEAT.md` to check `curl localhost:3100/health` |

## Keeping It Running

The server runs as a background process. If your container restarts, you'll need to start it again. Options:

- Add a health check to your `HEARTBEAT.md` so you notice when it's down
- Add a cron job to restart it: `*/5 * * * * pgrep -f "collab-mcp" || (cd ~/.openclaw/collab-mcp && source .env && node build/index.js &)`
- Start it in your agent's session bootstrap
