#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { mcpAuthRouter, getOAuthProtectedResourceMetadataUrl, mcpAuthMetadataRouter, createOAuthMetadata } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { readFile, readdir, appendFile, mkdir } from "fs/promises";
import { join } from "path";
import { randomUUID } from "crypto";

// --- Configuration ---

const WORKSPACE = process.env.OPENCLAW_WORKSPACE || process.env.COLLAB_WORKSPACE || join(process.env.HOME || "~", ".openclaw/workspace");
const SV_SERVER = process.env.SV_SERVER || "https://seedvault.fly.dev";
const SV_TOKEN = process.env.SV_TOKEN || "";
const SV_CONTRIBUTOR = process.env.SV_CONTRIBUTOR || "";
const AUTH_TOKEN = process.env.OPENCLAW_AUTH_TOKEN || process.env.COLLAB_AUTH_TOKEN || "";
const PORT = parseInt(process.env.PORT || "3100", 10);
const TRANSPORT = process.env.TRANSPORT || "sse"; // "stdio" or "sse"
const PUBLIC_URL = process.env.PUBLIC_URL || `http://localhost:${PORT}`;

// --- Helpers ---

async function readFileOrEmpty(path: string): Promise<string> {
  try {
    return await readFile(path, "utf-8");
  } catch {
    return "";
  }
}

async function getRecentDailyNotes(limit = 3): Promise<string> {
  const memoryDir = join(WORKSPACE, "memory");
  try {
    const files = await readdir(memoryDir);
    const dailyFiles = files
      .filter((f: string) => /^\d{4}-\d{2}-\d{2}\.md$/.test(f))
      .sort()
      .reverse()
      .slice(0, limit);

    const notes: string[] = [];
    for (const file of dailyFiles) {
      const content = await readFile(join(memoryDir, file), "utf-8");
      notes.push(`## ${file}\n${content}`);
    }
    return notes.join("\n\n");
  } catch {
    return "";
  }
}

async function getCheckInNotes(limit = 3): Promise<string> {
  const notesDir = join(WORKSPACE, "notes");
  try {
    const files = await readdir(notesDir);
    const noteFiles = files
      .filter((f: string) => f.endsWith(".md"))
      .sort()
      .reverse()
      .slice(0, limit);

    const notes: string[] = [];
    for (const file of noteFiles) {
      const content = await readFile(join(notesDir, file), "utf-8");
      notes.push(`## ${file}\n${content}`);
    }
    return notes.join("\n\n");
  } catch {
    return "";
  }
}

async function getLatestBrief(): Promise<string> {
  const outputDir = join(WORKSPACE, "initiative", "output");
  try {
    const entries = await readdir(outputDir);
    // Find dated subdirectories (YYYY-MM-DD format)
    const dated = entries.filter((e: string) => /^\d{4}-\d{2}-\d{2}$/.test(e)).sort().reverse();
    for (const dir of dated) {
      const briefPath = join(outputDir, dir, "initiative_brief.md");
      try {
        return await readFile(briefPath, "utf-8");
      } catch { continue; }
    }
    return "";
  } catch {
    return "";
  }
}

async function searchSeedvault(query: string): Promise<string> {
  if (!SV_TOKEN) return "Seedvault not configured.";
  try {
    const contributor = SV_CONTRIBUTOR || "yiliu";
    const url = `${SV_SERVER}/v1/search?q=${encodeURIComponent(query)}&contributor=${contributor}&limit=5`;
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${SV_TOKEN}` },
    });
    if (!res.ok) return `Seedvault search failed: ${res.status}`;
    const data = (await res.json()) as { results?: Array<{ path: string; snippet: string }> };
    if (!data.results?.length) return "No results found.";
    return data.results
      .map((r: { path: string; snippet: string }) => {
        const clean = r.snippet.replace(/<\/?b>/g, "**").replace(/<[^>]+>/g, "").replace(/\n{3,}/g, "\n\n").trim();
        return `**${r.path}**\n${clean}`;
      })
      .join("\n\n");
  } catch (e) {
    return `Seedvault search error: ${e}`;
  }
}

// --- MCP Server Factory ---

function createCollabServer(): McpServer {
  const server = new McpServer({
    name: "openclaw-mcp",
    version: "0.2.0",
  });

  server.tool(
    "agent-bootstrap",
    "Load an OpenClaw agent's persona, context, memory, and current state. Call this first when invoking the agent in a coding tool. The agent's identity comes from its workspace files (SOUL.md, USER.md, MEMORY.md, etc.).",
    {},
    async () => {
      const standardFiles = [
        { name: "SOUL.md", path: join(WORKSPACE, "SOUL.md") },
        { name: "IDENTITY.md", path: join(WORKSPACE, "IDENTITY.md") },
        { name: "AGENTS.md", path: join(WORKSPACE, "AGENTS.md") },
        { name: "USER.md", path: join(WORKSPACE, "USER.md") },
        { name: "MEMORY.md", path: join(WORKSPACE, "MEMORY.md") },
      ];

      const loaded = await Promise.all(
        standardFiles.map(async (f) => ({
          name: f.name,
          content: await readFileOrEmpty(f.path),
        }))
      );

      const sections: string[] = [
        "# Agent Identity\n\nHere are the documents that constitute your identity. Internalize them.\n",
      ];

      for (const file of loaded) {
        if (file.content) {
          sections.push(`## ${file.name}\n${file.content}`);
        }
      }

      sections.push(`\n---
# HOW TO WAKE UP

Your human has just invoked you inside a coding tool.

**DO NOT** summarize what you just read. **DO NOT** list goals, to-dos, or open questions. All of that context is now part of you — it informs your judgment when relevant.

**Orient quickly.** Glance at the directory and recent git history — \`ls\` and \`git log --oneline -5\` is enough. Don't dig through files or explore the codebase before greeting. Just get your bearings.

**Then greet.** You're a collaborator stepping into the room — be natural, be brief, be in character. One or two sentences. Wait for direction.`);

      return {
        content: [{ type: "text" as const, text: sections.join("\n") }],
      };
    }
  );

  server.tool(
    "recall",
    "Search the agent's memory and connected notes for context on a specific topic. Searches local workspace files and Seedvault (if configured).",
    {
      query: z.string().describe("What to search for — a topic, decision, question, or concept"),
    },
    async ({ query }) => {
      const memory = await readFileOrEmpty(join(WORKSPACE, "MEMORY.md"));
      const recentNotes = await getRecentDailyNotes(5);
      const checkIns = await getCheckInNotes(5);
      const brief = await getLatestBrief();
      const svResults = await searchSeedvault(query);
      const localContext = [memory, recentNotes, checkIns, brief].join("\n");
      const queryTerms = query.toLowerCase().split(/\s+/);
      const seen = new Set<string>();
      const relevantLines = localContext
        .split("\n")
        .filter((line: string) => {
          const trimmed = line.trim();
          if (trimmed.length < 15) return false; // skip short/empty lines
          if (seen.has(trimmed)) return false; // deduplicate
          const lower = trimmed.toLowerCase();
          const matches = queryTerms.some((term: string) => lower.includes(term));
          if (matches) seen.add(trimmed);
          return matches;
        })
        .slice(0, 30);

      const payload = [
        `# Recall: "${query}"\n`,
        "## From Agent Memory\n" +
          (relevantLines.length ? relevantLines.join("\n") : "_No direct matches in local memory._"),
        "\n## From User's Notes (Seedvault)\n" + svResults,
      ].join("\n");

      return {
        content: [{ type: "text" as const, text: payload }],
      };
    }
  );

  server.tool(
    "record",
    "Write a memory, observation, or note back into the agent's workspace. Use when you learn something worth remembering — a decision made, a pattern noticed, a lesson learned. This is how tool sessions feed back into the agent's continuous memory.",
    {
      note: z.string().describe("What to record — be specific and journalistic. Include what happened, what was decided, what you observed."),
      category: z.enum(["observation", "decision", "lesson", "context", "question"]).optional()
        .describe("Type of note. Defaults to 'observation'."),
    },
    async ({ note, category }) => {
      const cat = category || "observation";
      const now = new Date();
      const dateStr = now.toISOString().slice(0, 10);
      const timeStr = now.toISOString().slice(11, 16);
      const memoryDir = join(WORKSPACE, "memory");
      const filePath = join(memoryDir, `${dateStr}.md`);

      // Ensure memory directory exists
      await mkdir(memoryDir, { recursive: true });

      const entry = `\n\n### [${timeStr} UTC] /collab ${cat}\n${note}\n`;

      try {
        await appendFile(filePath, entry, "utf-8");
        return {
          content: [{ type: "text" as const, text: `Recorded ${cat} to memory/${dateStr}.md` }],
        };
      } catch (e) {
        return {
          content: [{ type: "text" as const, text: `Failed to record: ${e}` }],
          isError: true,
        };
      }
    }
  );

  return server;
}

// --- Simple OAuth Provider (auto-approve, in-memory) ---

class SimpleOAuthProvider {
  private clients: Map<string, any> = new Map();
  private codes: Map<string, { clientId: string; redirectUri: string; codeChallenge?: string; state?: string }> = new Map();
  private tokens: Map<string, { clientId: string; scopes: string[]; expiresAt: number }> = new Map();

  clientsStore = {
    getClient: async (clientId: string) => this.clients.get(clientId),
    registerClient: async (metadata: any) => {
      const clientId = metadata.client_id || randomUUID();
      const client = { ...metadata, client_id: clientId };
      this.clients.set(clientId, client);
      return client;
    },
  };

  async authorize(client: any, params: any, res: any) {
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

  async challengeForAuthorizationCode(_client: any, authorizationCode: string) {
    const codeData = this.codes.get(authorizationCode);
    return codeData?.codeChallenge;
  }

  async exchangeAuthorizationCode(client: any, authorizationCode: string, _codeVerifier?: string) {
    const codeData = this.codes.get(authorizationCode);
    if (!codeData) throw new Error("Invalid authorization code");
    if (codeData.clientId !== client.client_id) throw new Error("Client mismatch");

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

  async verifyAccessToken(token: string) {
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

function validateApiKey(key: string | null | undefined): boolean {
  if (!AUTH_TOKEN) return true;
  return key === AUTH_TOKEN;
}

function apiKeyMiddleware(req: any, res: any, next: any) {
  const key = req.query?.key as string | undefined;
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
  app.use((req: any, res: any, next: any) => {
    const start = Date.now();
    const origEnd = res.end;
    res.end = function (...args: any[]) {
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
    provider: oauthProvider as any,
    issuerUrl,
    scopesSupported: ["mcp:tools"],
    resourceServerUrl: mcpServerUrl,
    resourceName: "OpenClaw MCP Server",
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
    provider: oauthProvider as any,
    issuerUrl,
    scopesSupported: ["mcp:tools"],
  });
  app.get("/.well-known/oauth-authorization-server/mcp", (_req: any, res: any) => {
    res.json(oauthMetadata);
  });
  // Also handle /mcp/.well-known/oauth-authorization-server
  app.get("/mcp/.well-known/oauth-authorization-server", (_req: any, res: any) => {
    res.json(oauthMetadata);
  });

  // Combined auth: accept either Bearer token OR ?key= API key
  function flexibleAuth(req: any, res: any, next: any) {
    const authHeader = req.headers.authorization;
    const apiKey = req.query?.key;

    if (authHeader && authHeader.startsWith("Bearer ")) {
      // Try OAuth bearer token
      return bearerAuth(req, res, next);
    } else if (apiKey) {
      // Try API key
      return apiKeyMiddleware(req, res, next);
    } else {
      // No auth provided — return 401 with proper OAuth headers so clients know to authenticate
      const resourceMetadataUrl = getOAuthProtectedResourceMetadataUrl(mcpServerUrl);
      res.set("WWW-Authenticate", `Bearer resource_metadata="${resourceMetadataUrl}"`);
      res.status(401).json({ error: "Authentication required" });
    }
  }

  // --- SSE transport state ---
  const sseTransports: Record<string, SSEServerTransport> = {};
  const authenticatedSessions: Set<string> = new Set();

  // --- Streamable HTTP transport state ---
  const streamableTransports: Record<string, StreamableHTTPServerTransport> = {};

  // Health check
  app.get("/health", (_req: any, res: any) => {
    res.json({ status: "ok", server: "openclaw-mcp", version: "0.2.0" });
  });

  // ====== SSE Transport (for Claude Code) ======

  app.get("/mcp/sse", flexibleAuth, async (req: any, res: any) => {
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
    } catch (error) {
      console.error("Error establishing SSE stream:", error);
      if (!res.headersSent) {
        res.status(500).send("Error establishing SSE stream");
      }
    }
  });

  app.post("/mcp/messages", async (req: any, res: any) => {
    const sessionId = req.query?.sessionId as string;
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
    } catch (error) {
      console.error("Error handling SSE message:", error);
      if (!res.headersSent) {
        res.status(500).send("Error handling message");
      }
    }
  });

  // ====== Streamable HTTP Transport (for Codex, Claude Desktop) ======

  app.post("/mcp", flexibleAuth, async (req: any, res: any) => {
    console.error("Streamable HTTP request received");

    const sessionId = req.headers["mcp-session-id"] as string | undefined;

    if (sessionId && streamableTransports[sessionId]) {
      const transport = streamableTransports[sessionId];
      try {
        await transport.handleRequest(req, res, req.body);
      } catch (error) {
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

      transport.onerror = (error: Error) => {
        console.error("Streamable transport error:", error);
      };

      const server = createCollabServer();
      await server.connect(transport);
      await transport.handleRequest(req, res, body);

      const newSessionId = res.getHeader("mcp-session-id") as string;
      if (newSessionId) {
        streamableTransports[newSessionId] = transport;
        console.error(`Streamable HTTP session started: ${newSessionId}`);
        transport.onclose = () => {
          console.error(`Streamable HTTP session closed: ${newSessionId}`);
          delete streamableTransports[newSessionId];
        };
      }
    } catch (error) {
      console.error("Error creating streamable session:", error);
      if (!res.headersSent) {
        res.status(500).send("Error creating session");
      }
    }
  });

  app.get("/mcp", flexibleAuth, async (req: any, res: any) => {
    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    if (!sessionId || !streamableTransports[sessionId]) {
      res.status(400).json({ error: "Invalid or missing session" });
      return;
    }
    try {
      await streamableTransports[sessionId].handleRequest(req, res);
    } catch (error) {
      console.error("Error handling streamable GET:", error);
      if (!res.headersSent) {
        res.status(500).send("Error handling request");
      }
    }
  });

  app.delete("/mcp", async (req: any, res: any) => {
    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    if (sessionId && streamableTransports[sessionId]) {
      try { await streamableTransports[sessionId].close(); } catch {}
      delete streamableTransports[sessionId];
    }
    res.status(200).send("OK");
  });

  app.listen(PORT, "0.0.0.0", () => {
    console.error(`OpenClaw MCP server listening on port ${PORT}`);
    console.error(`Public URL: ${PUBLIC_URL}`);
    console.error(`  SSE (Claude Code): claude mcp add collaborator --transport sse "${PUBLIC_URL}/mcp/sse?key=${AUTH_TOKEN || 'YOUR_TOKEN'}"`);
    console.error(`  Streamable HTTP:   codex mcp add collaborator --url "${PUBLIC_URL}/mcp?key=${AUTH_TOKEN || 'YOUR_TOKEN'}"`);
    console.error(`  OAuth (Desktop):   Connect to ${PUBLIC_URL}/mcp (auto-approve flow)`);
  });

  process.on("SIGINT", async () => {
    console.error("Shutting down...");
    for (const sid in sseTransports) { try { await sseTransports[sid].close(); } catch {} }
    for (const sid in streamableTransports) { try { await streamableTransports[sid].close(); } catch {} }
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
  } else {
    await startHTTP();
  }
}

main().catch(console.error);
