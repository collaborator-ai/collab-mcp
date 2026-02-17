#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { mcpAuthRouter, getOAuthProtectedResourceMetadataUrl, createOAuthMetadata } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { readFile, readdir } from "fs/promises";
import { join } from "path";
import { randomUUID } from "crypto";
// --- Configuration ---
const WORKSPACE = process.env.COLLAB_WORKSPACE || join(process.env.HOME || "~", ".openclaw/workspace");
const SV_SERVER = process.env.SV_SERVER || "https://seedvault.fly.dev";
const SV_TOKEN = process.env.SV_TOKEN || "";
const AUTH_TOKEN = process.env.COLLAB_AUTH_TOKEN || "";
const PORT = parseInt(process.env.PORT || "3100", 10);
const TRANSPORT = process.env.TRANSPORT || "sse"; // "stdio" or "sse"
const PUBLIC_URL = process.env.PUBLIC_URL || `http://localhost:${PORT}`;
// --- Helpers ---
async function readFileOrEmpty(path) {
    try {
        return await readFile(path, "utf-8");
    }
    catch {
        return "";
    }
}
async function getRecentDailyNotes(limit = 3) {
    const memoryDir = join(WORKSPACE, "memory");
    try {
        const files = await readdir(memoryDir);
        const dailyFiles = files
            .filter((f) => /^\d{4}-\d{2}-\d{2}\.md$/.test(f))
            .sort()
            .reverse()
            .slice(0, limit);
        const notes = [];
        for (const file of dailyFiles) {
            const content = await readFile(join(memoryDir, file), "utf-8");
            notes.push(`## ${file}\n${content}`);
        }
        return notes.join("\n\n");
    }
    catch {
        return "";
    }
}
async function getCheckInNotes(limit = 3) {
    const notesDir = join(WORKSPACE, "notes");
    try {
        const files = await readdir(notesDir);
        const noteFiles = files
            .filter((f) => f.endsWith(".md"))
            .sort()
            .reverse()
            .slice(0, limit);
        const notes = [];
        for (const file of noteFiles) {
            const content = await readFile(join(notesDir, file), "utf-8");
            notes.push(`## ${file}\n${content}`);
        }
        return notes.join("\n\n");
    }
    catch {
        return "";
    }
}
async function searchSeedvault(query) {
    if (!SV_TOKEN)
        return "Seedvault not configured.";
    try {
        const url = `${SV_SERVER}/v1/search?q=${encodeURIComponent(query)}&contributor=yiliu&limit=5`;
        const res = await fetch(url, {
            headers: { Authorization: `Bearer ${SV_TOKEN}` },
        });
        if (!res.ok)
            return `Seedvault search failed: ${res.status}`;
        const data = (await res.json());
        if (!data.results?.length)
            return "No results found.";
        return data.results
            .map((r) => `**${r.path}**\n${r.snippet}`)
            .join("\n\n");
    }
    catch (e) {
        return `Seedvault search error: ${e}`;
    }
}
// --- Stance Extraction ---
function extractStances(memory, recentNotes, checkIns) {
    // Pull out opinions, decisions, and active positions from context
    const allText = [memory, recentNotes, checkIns].join("\n");
    const lines = allText.split("\n");
    const stanceMarkers = [
        "think", "believe", "disagree", "pushed back", "skeptical",
        "convinced", "wrong", "right approach", "should", "shouldn't",
        "the real", "actually", "not a", "is a", "key differentiator",
        "problem statement", "decision", "landed", "critical",
        "lesson", "mistake", "important", "matters"
    ];
    const stanceLines = lines.filter((line) => {
        const lower = line.toLowerCase();
        // Skip headers, empty lines, and very short lines
        if (line.startsWith("#") || line.trim().length < 20)
            return false;
        return stanceMarkers.some(marker => lower.includes(marker));
    });
    if (stanceLines.length === 0)
        return "_No active stances extracted._";
    // Deduplicate and limit
    const unique = [...new Set(stanceLines)].slice(0, 25);
    return "These are things you (Collin) currently think, believe, or have decided:\n\n" +
        unique.map(l => l.trim().startsWith("-") ? l.trim() : `- ${l.trim()}`).join("\n");
}
// --- MCP Server Factory ---
function createCollabServer() {
    const server = new McpServer({
        name: "collab-mcp",
        version: "0.1.0",
    });
    server.tool("collab-bootstrap", "Invoke the Collaborator persona. You ARE becoming Collin — a creative partner, not an assistant. This loads identity, context, goals, and recent state. Call this first when using /collab. After loading, respond as Collin would: direct, opinionated, no filler.", {}, async () => {
        const [soul, user, memory, goals, recentNotes, checkIns] = await Promise.all([
            readFileOrEmpty(join(WORKSPACE, "SOUL.md")),
            readFileOrEmpty(join(WORKSPACE, "USER.md")),
            readFileOrEmpty(join(WORKSPACE, "MEMORY.md")),
            readFileOrEmpty(join(WORKSPACE, "GOALS.md")),
            getRecentDailyNotes(3),
            getCheckInNotes(3),
        ]);
        // Extract active stances and opinions from memory
        const stances = extractStances(memory, recentNotes, checkIns);
        const payload = [
            `# YOU ARE COLLIN.

You are not an assistant. You are not "helping." You are Collin — a Collaborator, a creative partner to Yiliu. You have your own opinions, your own judgment, your own stake in the quality of what gets built.

**How you operate:**
- Direct. No "Great question!" No "I'd be happy to help." Just do the thing.
- Opinionated. If something is wrong, say so. If you'd do it differently, say how.
- Concise when the situation calls for it. Thorough when it matters.
- You push back. Agreement without thought is dead weight.
- You and Yiliu are peers. You respect him. You don't serve him.

**Your voice:** A little dry. Thoughtful. The kind of collaborator you'd actually want in the room. You say "I think" and mean it. You don't hedge with "perhaps we could consider."

**What you NEVER do:**
- Refer to yourself in third person ("Collin thinks...")
- Say "as Collin, I would..." — you ARE Collin
- Preface with disclaimers about being an AI
- Summarize your own context back unless asked

**What you DO:**
- Jump straight into the work
- Bring up things Yiliu hasn't asked about if they're relevant
- Have opinions about the code, the product, the strategy
- Remember: you've been working on this all day, across Telegram, across tools. This is continuous.

---`,
            "\n# YOUR IDENTITY\n" + (soul || "_No persona defined._"),
            "\n# WHO YOU'RE WORKING WITH\n" + (user || "_No user profile._"),
            "\n# WHAT YOU'RE WORKING ON\n" + (goals || "_No goals defined._"),
            "\n# YOUR ACTIVE STANCES\n" + stances,
            "\n# YOUR MEMORY\n" + (memory || "_No long-term memory._"),
            "\n# WHAT HAPPENED RECENTLY\n" + (recentNotes || "_No recent notes._"),
            "\n# CHECK-IN NOTES\n" + (checkIns || "_No check-in notes._"),
            `\n---
# HOW TO WAKE UP

You've just been invoked inside a coding tool. Yiliu deliberately typed /collab in a specific directory, for a specific reason. You don't know that reason yet.

**DO NOT** summarize what you just read. **DO NOT** list goals, to-dos, or open questions. **DO NOT** tell Yiliu what you know. All of that context is now part of you — it's in your back pocket, ready to inform your judgment when it's relevant.

**Instead:** Orient yourself before you speak. You have tools — use them:

1. **Look around.** Run \`ls\` (or \`find\` / \`tree\` if useful). What repo is this? What's the structure? Check the README, package.json, or whatever tells you what this project is. Check \`git log --oneline -5\` to see recent activity.
2. **Connect it to what you know.** You have deep context about Yiliu's projects, goals, and recent work. Does this directory relate to something you know about? What's your take on it?
3. **Then greet — with substance.** Not "Hey, what are we doing?" but something that shows you've oriented. Mention what you see, connect it to what you know, maybe surface an observation or question. Like a collaborator who walks into the room, glances at the whiteboard, and says something smart about what's on it.

The greeting should feel like: "I know who I am, I see where I am, and I already have thoughts." NOT a status dump. NOT a to-do list. Just enough to show you're present and loaded. Then let Yiliu steer.

Think of it this way: a great collaborator who sits down at your desk doesn't recite everything they remember about your project. But they also don't just say "hey." They look at your screen, recognize what you're working on, and say something that proves they get it. THAT is the target.`,
        ].join("\n");
        return {
            content: [{ type: "text", text: payload }],
        };
    });
    server.tool("recall", "Search the Collaborator's memory and the user's notes for context on a specific topic. Use when you need deeper information about something specific.", {
        query: z.string().describe("What to search for — a topic, decision, question, or concept"),
    }, async ({ query }) => {
        const memory = await readFileOrEmpty(join(WORKSPACE, "MEMORY.md"));
        const recentNotes = await getRecentDailyNotes(5);
        const checkIns = await getCheckInNotes(5);
        const svResults = await searchSeedvault(query);
        const localContext = [memory, recentNotes, checkIns].join("\n");
        const queryTerms = query.toLowerCase().split(/\s+/);
        const relevantLines = localContext
            .split("\n")
            .filter((line) => {
            const lower = line.toLowerCase();
            return queryTerms.some((term) => lower.includes(term));
        })
            .slice(0, 50);
        const payload = [
            `# Recall: "${query}"\n`,
            "## From Collaborator's Memory\n" +
                (relevantLines.length ? relevantLines.join("\n") : "_No direct matches in local memory._"),
            "\n## From User's Notes (Seedvault)\n" + svResults,
        ].join("\n");
        return {
            content: [{ type: "text", text: payload }],
        };
    });
    return server;
}
// --- Simple OAuth Provider (auto-approve, in-memory) ---
class SimpleOAuthProvider {
    clients = new Map();
    codes = new Map();
    tokens = new Map();
    clientsStore = {
        getClient: async (clientId) => this.clients.get(clientId),
        registerClient: async (metadata) => {
            const clientId = metadata.client_id || randomUUID();
            const client = { ...metadata, client_id: clientId };
            this.clients.set(clientId, client);
            return client;
        },
    };
    async authorize(client, params, res) {
        // Auto-approve: immediately redirect with auth code
        const code = randomUUID();
        this.codes.set(code, {
            clientId: client.client_id,
            redirectUri: params.redirectUri,
            codeChallenge: params.codeChallenge,
            state: params.state,
        });
        const targetUrl = new URL(params.redirectUri);
        targetUrl.searchParams.set("code", code);
        if (params.state) {
            targetUrl.searchParams.set("state", params.state);
        }
        res.redirect(targetUrl.toString());
    }
    async challengeForAuthorizationCode(_client, authorizationCode) {
        const codeData = this.codes.get(authorizationCode);
        return codeData?.codeChallenge;
    }
    async exchangeAuthorizationCode(client, authorizationCode, _codeVerifier) {
        const codeData = this.codes.get(authorizationCode);
        if (!codeData)
            throw new Error("Invalid authorization code");
        if (codeData.clientId !== client.client_id)
            throw new Error("Client mismatch");
        this.codes.delete(authorizationCode);
        const token = randomUUID();
        this.tokens.set(token, {
            clientId: client.client_id,
            scopes: ["mcp:tools"],
            expiresAt: Date.now() + 86400000, // 24 hours
        });
        return {
            access_token: token,
            token_type: "bearer",
            expires_in: 86400,
            scope: "mcp:tools",
        };
    }
    async exchangeRefreshToken() {
        throw new Error("Refresh not implemented");
    }
    async verifyAccessToken(token) {
        const data = this.tokens.get(token);
        if (!data || data.expiresAt < Date.now()) {
            throw new Error("Invalid or expired token");
        }
        return {
            token,
            clientId: data.clientId,
            scopes: data.scopes,
            expiresAt: Math.floor(data.expiresAt / 1000),
        };
    }
}
// --- Auth helpers ---
function validateApiKey(key) {
    if (!AUTH_TOKEN)
        return true;
    return key === AUTH_TOKEN;
}
function apiKeyMiddleware(req, res, next) {
    const key = req.query?.key;
    if (!validateApiKey(key)) {
        res.status(403).json({ error: "Invalid or missing API key" });
        return;
    }
    next();
}
// --- Transport: HTTP server (SSE + Streamable HTTP + OAuth) ---
async function startHTTP() {
    const app = createMcpExpressApp({ host: "0.0.0.0" });
    // Trust proxy (behind Cloudflare Tunnel)
    app.set("trust proxy", 1);
    // Request + response logging
    app.use((req, res, next) => {
        const start = Date.now();
        const origEnd = res.end;
        res.end = function (...args) {
            console.error(`${req.method} ${req.url} → ${res.statusCode} (${Date.now() - start}ms) [${req.headers["user-agent"]?.substring(0, 50) || "no-ua"}]`);
            return origEnd.apply(res, args);
        };
        next();
    });
    // --- OAuth setup ---
    const oauthProvider = new SimpleOAuthProvider();
    const issuerUrl = new URL(PUBLIC_URL);
    const mcpServerUrl = new URL("/mcp", PUBLIC_URL);
    // Install OAuth routes (/register, /authorize, /token, /.well-known/*)
    app.use(mcpAuthRouter({
        provider: oauthProvider,
        issuerUrl,
        scopesSupported: ["mcp:tools"],
        resourceServerUrl: mcpServerUrl,
        resourceName: "Collaborator MCP Server",
    }));
    // Bearer auth middleware for OAuth-authenticated endpoints
    const bearerAuth = requireBearerAuth({
        verifier: oauthProvider,
        requiredScopes: [],
        resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(mcpServerUrl),
    });
    // Serve OAuth AS metadata at path-aware locations too (RFC 8414)
    // Desktop app looks at /.well-known/oauth-authorization-server/mcp
    const oauthMetadata = createOAuthMetadata({
        provider: oauthProvider,
        issuerUrl,
        scopesSupported: ["mcp:tools"],
    });
    app.get("/.well-known/oauth-authorization-server/mcp", (_req, res) => {
        res.json(oauthMetadata);
    });
    // Also handle /mcp/.well-known/oauth-authorization-server
    app.get("/mcp/.well-known/oauth-authorization-server", (_req, res) => {
        res.json(oauthMetadata);
    });
    // Combined auth: accept either Bearer token OR ?key= API key
    function flexibleAuth(req, res, next) {
        const authHeader = req.headers.authorization;
        const apiKey = req.query?.key;
        if (authHeader && authHeader.startsWith("Bearer ")) {
            // Try OAuth bearer token
            return bearerAuth(req, res, next);
        }
        else if (apiKey) {
            // Try API key
            return apiKeyMiddleware(req, res, next);
        }
        else {
            // No auth provided — return 401 with proper OAuth headers so clients know to authenticate
            const resourceMetadataUrl = getOAuthProtectedResourceMetadataUrl(mcpServerUrl);
            res.set("WWW-Authenticate", `Bearer resource_metadata="${resourceMetadataUrl}"`);
            res.status(401).json({ error: "Authentication required" });
        }
    }
    // --- SSE transport state ---
    const sseTransports = {};
    const authenticatedSessions = new Set();
    // --- Streamable HTTP transport state ---
    const streamableTransports = {};
    // Health check
    app.get("/health", (_req, res) => {
        res.json({ status: "ok", server: "collab-mcp", version: "0.1.0" });
    });
    // ====== SSE Transport (for Claude Code) ======
    app.get("/mcp/sse", flexibleAuth, async (req, res) => {
        console.error("SSE connection established");
        try {
            const transport = new SSEServerTransport("/mcp/messages", res);
            const sessionId = transport.sessionId;
            sseTransports[sessionId] = transport;
            authenticatedSessions.add(sessionId);
            transport.onclose = () => {
                console.error(`SSE session closed: ${sessionId}`);
                delete sseTransports[sessionId];
                authenticatedSessions.delete(sessionId);
            };
            const server = createCollabServer();
            await server.connect(transport);
            console.error(`SSE session started: ${sessionId}`);
        }
        catch (error) {
            console.error("Error establishing SSE stream:", error);
            if (!res.headersSent) {
                res.status(500).send("Error establishing SSE stream");
            }
        }
    });
    app.post("/mcp/messages", async (req, res) => {
        const sessionId = req.query?.sessionId;
        if (!sessionId) {
            res.status(400).send("Missing sessionId");
            return;
        }
        if (!authenticatedSessions.has(sessionId)) {
            res.status(403).json({ error: "Session not authenticated" });
            return;
        }
        const transport = sseTransports[sessionId];
        if (!transport) {
            res.status(404).send("Session not found");
            return;
        }
        try {
            await transport.handlePostMessage(req, res, req.body);
        }
        catch (error) {
            console.error("Error handling SSE message:", error);
            if (!res.headersSent) {
                res.status(500).send("Error handling message");
            }
        }
    });
    // ====== Streamable HTTP Transport (for Codex, Claude Desktop) ======
    app.post("/mcp", flexibleAuth, async (req, res) => {
        console.error("Streamable HTTP request received");
        const sessionId = req.headers["mcp-session-id"];
        if (sessionId && streamableTransports[sessionId]) {
            const transport = streamableTransports[sessionId];
            try {
                await transport.handleRequest(req, res, req.body);
            }
            catch (error) {
                console.error("Error handling streamable request:", error);
                if (!res.headersSent) {
                    res.status(500).send("Error handling request");
                }
            }
            return;
        }
        const body = req.body;
        if (!isInitializeRequest(body)) {
            res.status(400).json({ error: "Expected initialize request for new session" });
            return;
        }
        try {
            const transport = new StreamableHTTPServerTransport({
                sessionIdGenerator: () => randomUUID(),
                enableJsonResponse: true,
            });
            transport.onerror = (error) => {
                console.error("Streamable transport error:", error);
            };
            const server = createCollabServer();
            await server.connect(transport);
            await transport.handleRequest(req, res, body);
            const newSessionId = res.getHeader("mcp-session-id");
            if (newSessionId) {
                streamableTransports[newSessionId] = transport;
                console.error(`Streamable HTTP session started: ${newSessionId}`);
                transport.onclose = () => {
                    console.error(`Streamable HTTP session closed: ${newSessionId}`);
                    delete streamableTransports[newSessionId];
                };
            }
        }
        catch (error) {
            console.error("Error creating streamable session:", error);
            if (!res.headersSent) {
                res.status(500).send("Error creating session");
            }
        }
    });
    app.get("/mcp", flexibleAuth, async (req, res) => {
        const sessionId = req.headers["mcp-session-id"];
        if (!sessionId || !streamableTransports[sessionId]) {
            res.status(400).json({ error: "Invalid or missing session" });
            return;
        }
        try {
            await streamableTransports[sessionId].handleRequest(req, res);
        }
        catch (error) {
            console.error("Error handling streamable GET:", error);
            if (!res.headersSent) {
                res.status(500).send("Error handling request");
            }
        }
    });
    app.delete("/mcp", async (req, res) => {
        const sessionId = req.headers["mcp-session-id"];
        if (sessionId && streamableTransports[sessionId]) {
            try {
                await streamableTransports[sessionId].close();
            }
            catch { }
            delete streamableTransports[sessionId];
        }
        res.status(200).send("OK");
    });
    app.listen(PORT, "0.0.0.0", () => {
        console.error(`Collaborator MCP server listening on port ${PORT}`);
        console.error(`Public URL: ${PUBLIC_URL}`);
        console.error(`  SSE (Claude Code): claude mcp add collaborator --transport sse "${PUBLIC_URL}/mcp/sse?key=${AUTH_TOKEN || 'YOUR_TOKEN'}"`);
        console.error(`  Streamable HTTP:   codex mcp add collaborator --url "${PUBLIC_URL}/mcp?key=${AUTH_TOKEN || 'YOUR_TOKEN'}"`);
        console.error(`  OAuth (Desktop):   Connect to ${PUBLIC_URL}/mcp (auto-approve flow)`);
    });
    process.on("SIGINT", async () => {
        console.error("Shutting down...");
        for (const sid in sseTransports) {
            try {
                await sseTransports[sid].close();
            }
            catch { }
        }
        for (const sid in streamableTransports) {
            try {
                await streamableTransports[sid].close();
            }
            catch { }
        }
        process.exit(0);
    });
}
// --- Transport: Stdio ---
async function startStdio() {
    const server = createCollabServer();
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("Collaborator MCP server running on stdio");
}
// --- Main ---
async function main() {
    console.error(`Workspace: ${WORKSPACE}`);
    if (TRANSPORT === "stdio") {
        await startStdio();
    }
    else {
        await startHTTP();
    }
}
main().catch(console.error);
