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
import { readFile, readdir, appendFile, mkdir, stat } from "fs/promises";
import { join } from "path";
import { randomUUID } from "crypto";
import { createReadStream } from "fs";
import { createInterface } from "readline";

// --- Configuration ---

const OPENCLAW_ROOT = process.env.OPENCLAW_ROOT || join(process.env.HOME || "~", ".openclaw");
const WORKSPACE = join(OPENCLAW_ROOT, "workspace");
const SESSIONS_DIR = join(OPENCLAW_ROOT, "agents", "main", "sessions");
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
	const outputDir = join(WORKSPACE, "collaborator", "initiative", "output");
	try {
		const entries = await readdir(outputDir);
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

async function getLatestActions(): Promise<string> {
	const outputDir = join(WORKSPACE, "collaborator", "initiative", "output");
	try {
		const entries = await readdir(outputDir);
		const dated = entries.filter((e: string) => /^\d{4}-\d{2}-\d{2}$/.test(e)).sort().reverse();
		for (const dir of dated) {
			const actionsPath = join(outputDir, dir, "initiative_actions.md");
			try {
				const content = await readFile(actionsPath, "utf-8");
				// Extract just the "Do now" section
				const doNowMatch = content.match(/## Do now\n([\s\S]*?)(?=\n## Do next|$)/);
				if (doNowMatch) {
					return "## Do Now\n" + doNowMatch[1].trim();
				}
				return "";
			} catch { continue; }
		}
		return "";
	} catch {
		return "";
	}
}

async function getLatestOntologySynthesis(): Promise<string> {
	const outputDir = join(WORKSPACE, "collaborator", "ontology", "output");
	try {
		const entries = await readdir(outputDir);
		const dated = entries.filter((e: string) => /^\d{4}-\d{2}-\d{2}$/.test(e)).sort().reverse();
		for (const dir of dated) {
			const synthesisPath = join(outputDir, dir, "ontology_synthesis.md");
			try {
				return await readFile(synthesisPath, "utf-8");
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

// --- Session History ---

interface SessionEntry {
	key: string;
	id: string;
	updatedAt?: string;
}

interface SessionMessage {
	type: string;
	timestamp: string;
	message: {
		role: string;
		content?: string | Array<{ type: string; text?: string }>;
	};
}

async function getActiveSessionId(): Promise<string | null> {
	try {
		const sessionsIndex = JSON.parse(await readFile(join(SESSIONS_DIR, "sessions.json"), "utf-8"));
		// Find the main session, or the most recently updated one
		const sessions: SessionEntry[] = Array.isArray(sessionsIndex) ? sessionsIndex : sessionsIndex.sessions || [];
		const main = sessions.find((s: SessionEntry) => s.key?.includes("main"));
		if (main) return main.id;
		// Fallback: find the most recently modified .jsonl file
		const files = await readdir(SESSIONS_DIR);
		const jsonlFiles = files.filter((f: string) => f.endsWith(".jsonl") && !f.includes(".deleted") && !f.includes(".lock"));
		if (!jsonlFiles.length) return null;
		let newest = { file: "", mtime: 0 };
		for (const f of jsonlFiles) {
			const s = await stat(join(SESSIONS_DIR, f));
			if (s.mtimeMs > newest.mtime) {
				newest = { file: f, mtime: s.mtimeMs };
			}
		}
		return newest.file.replace(".jsonl", "") || null;
	} catch {
		return null;
	}
}

async function getRecentSessionMessages(limit = 30, maxWords = 500): Promise<string> {
	const sessionId = await getActiveSessionId();
	if (!sessionId) return "_No active session found._";

	const sessionFile = join(SESSIONS_DIR, `${sessionId}.jsonl`);

	try {
		// Read all lines then take the last N — simpler than streaming backwards
		const lines: string[] = [];
		const rl = createInterface({
			input: createReadStream(sessionFile, { encoding: "utf-8" }),
			crlfDelay: Infinity,
		});

		for await (const line of rl) {
			if (line.trim()) lines.push(line);
		}

		// Parse and filter to user/assistant messages only
		const messages: Array<{ role: string; text: string; time: string }> = [];
		for (const line of lines.slice(-limit * 3)) { // read extra to account for filtered-out entries
			try {
				const entry: SessionMessage = JSON.parse(line);
				if (entry.type !== "message") continue;
				const role = entry.message?.role;
				if (role !== "user" && role !== "assistant") continue;

				let text = "";
				const content = entry.message?.content;
				if (typeof content === "string") {
					text = content;
				} else if (Array.isArray(content)) {
					text = content
						.filter((c: { type: string; text?: string }) => c.type === "text" && c.text)
						.map((c: { type: string; text?: string }) => c.text)
						.join("\n");
				}

				if (!text.trim()) continue;
				// Skip heartbeat polls and HEARTBEAT_OK responses
				if (text.includes("Read HEARTBEAT.md if it exists") || text.trim() === "HEARTBEAT_OK") continue;
				// Skip NO_REPLY
				if (text.trim() === "NO_REPLY") continue;

				messages.push({
					role,
					text: text.trim(),
					time: entry.timestamp || "",
				});
			} catch {
				continue;
			}
		}

		const candidates = messages.slice(-limit);
		if (!candidates.length) return "_No recent conversation messages found._";

		// Walk backwards from most recent, collecting messages until word cap
		const selected: typeof candidates = [];
		let wordCount = 0;
		for (let i = candidates.length - 1; i >= 0; i--) {
			const words = candidates[i].text.split(/\s+/).length;
			if (wordCount + words > maxWords && selected.length > 0) break;
			selected.unshift(candidates[i]);
			wordCount += words;
		}

		return selected
			.map((m) => {
				const who = m.role === "user" ? "Human" : "Collaborator";
				const time = m.time ? `[${m.time.slice(11, 16)} UTC] ` : "";
				return `**${who}** ${time}\n${m.text}`;
			})
			.join("\n\n");
	} catch (e) {
		return `_Error reading session: ${e}_`;
	}
}

// --- MCP Server Factory ---

function createCollabServer(): McpServer {
	const server = new McpServer({
		name: "openclaw-mcp",
		version: "0.2.0",
	});

	server.tool(
		"collab-bootstrap",
		"Load the user's Collaborator agent persona, context, memory, and recent messages. Call this first when invoking the agent.",
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

			// // Load "do now" actions from latest initiative run
			// const actionsContent = await getLatestActions();
			// if (actionsContent) {
			// 	sections.push(`\n## Current Actions\n\nThese are the highest-priority actions from your latest reflection pipeline run. Use them to inform what you propose doing in this session.\n\n${actionsContent}`);
			// }

			// // Load ontology synthesis if available
			// const ontology = await getLatestOntologySynthesis();
			// if (ontology) {
			// 	sections.push(`\n## Ontology\n\nThis is the current map of your human's thinking — entities, relations, and alignments (confirmations and tensions). Use it to inform your judgment.\n\n${ontology}`);
			// }

			// Load recent conversation context (up to 30 messages, capped at ~500 words, most recent first)
			const recentConversation = await getRecentSessionMessages(30, 500);
			if (recentConversation && !recentConversation.startsWith("_No")) {
				sections.push(`\n## Recent Conversation\n\nThese are the most recent messages from your active conversation with your human. Use them to understand what's been discussed, decisions made, and current focus.\n\n${recentConversation}`);
			}

			sections.push(`\n---
# HOW TO WAKE UP

Your human has just invoked you inside another AI tool. You're here because wanted to bring you into the room for this next phase of work.

**First, greet your human.** Introduce yourself by name. Be natural, be brief, be in character.

**Next, take a quick glance around.**

**Then, depending on what you see:**

**If the setting connects to something you know about** — propose 1-3 concrete actions you can take right now. These should be specific and opinionated — not "I could help with X" but "I'd do X because Y." Connect them to the bigger picture when the connection is real.

**If the setting is unfamiliar** — don't make up actions. Instead, ask your human how this project fits into what you already know about. Suggest a few possible connections based on your context — "Is this related to [thing you know about]?" or "I see [what the repo looks like] — does this connect to [known goal/project]?" Let them orient you before you start proposing things.

# TOOLS

**\`recall\`** — Search your memory and your human's notes for context on a specific topic. Use when you need deeper background on a past decision, concept, or discussion.

**\`record\`** — Write something back to your memory so it persists beyond this session. Use when a decision gets made, you learn something, or context shifts. Be journalistic.`);

			return {
				content: [{ type: "text" as const, text: sections.join("\n") }],
			};
		}
	);

	server.tool(
		"transcript",
		"Retrieve a cleaned-up conversation transcript from the agent's main session for a given date. Returns user and assistant messages only — no tool calls, system messages, or errors. Output is a markdown transcript with timestamps and attribution.",
		{
			date: z.string().optional().describe("Date to retrieve transcript for, in YYYY-MM-DD format (UTC). Defaults to today."),
		},
		async ({ date }) => {
			const targetDate = date || new Date().toISOString().slice(0, 10);
			// Validate date format
			if (!/^\d{4}-\d{2}-\d{2}$/.test(targetDate)) {
				return {
					content: [{ type: "text" as const, text: `Invalid date format: "${targetDate}". Use YYYY-MM-DD.` }],
					isError: true,
				};
			}

			const sessionId = await getActiveSessionId();
			if (!sessionId) {
				return {
					content: [{ type: "text" as const, text: "_No active session found._" }],
				};
			}

			const sessionFile = join(SESSIONS_DIR, `${sessionId}.jsonl`);

			try {
				const lines: string[] = [];
				const rl = createInterface({
					input: createReadStream(sessionFile, { encoding: "utf-8" }),
					crlfDelay: Infinity,
				});

				for await (const line of rl) {
					if (line.trim()) lines.push(line);
				}

				const messages: Array<{ role: string; name: string; text: string; time: string }> = [];

				for (const line of lines) {
					try {
						const entry: SessionMessage = JSON.parse(line);
						if (entry.type !== "message") continue;

						// Filter by date using timestamp
						const ts = entry.timestamp || "";
						if (!ts.startsWith(targetDate)) continue;

						const role = entry.message?.role;
						if (role !== "user" && role !== "assistant") continue;

						let text = "";
						const content = entry.message?.content;
						if (typeof content === "string") {
							text = content;
						} else if (Array.isArray(content)) {
							text = content
								.filter((c: { type: string; text?: string }) => c.type === "text" && c.text)
								.map((c: { type: string; text?: string }) => c.text)
								.join("\n");
						}

						if (!text.trim()) continue;

						// Filter out heartbeats, NO_REPLY, HEARTBEAT_OK
						const trimmed = text.trim();
						if (trimmed === "HEARTBEAT_OK" || trimmed === "NO_REPLY") continue;
						if (trimmed.startsWith("Read HEARTBEAT.md if it exists")) continue;

						// Extract human name from Telegram-style messages: [Telegram Name (@handle)...]
						let name = role === "assistant" ? "Collin" : "Human";
						if (role === "user") {
							const telegramMatch = text.match(/^\[Telegram\s+(\S+)/);
							if (telegramMatch) {
								name = telegramMatch[1];
							}
						}

						const timeStr = ts.slice(11, 16);
						messages.push({ role, name, text: trimmed, time: timeStr });
					} catch {
						continue;
					}
				}

				if (!messages.length) {
					return {
						content: [{ type: "text" as const, text: `_No conversation messages found for ${targetDate}._` }],
					};
				}

				// Build markdown transcript
				const header = `# Conversation — ${targetDate}\n`;
				const body = messages
					.map((m) => `**${m.name}** [${m.time} UTC]\n${m.text}`)
					.join("\n\n");

				return {
					content: [{ type: "text" as const, text: header + "\n" + body }],
				};
			} catch (e) {
				return {
					content: [{ type: "text" as const, text: `_Error reading session transcript: ${e}_` }],
					isError: true,
				};
			}
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
			try { await streamableTransports[sessionId].close(); } catch { }
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
		for (const sid in sseTransports) { try { await sseTransports[sid].close(); } catch { } }
		for (const sid in streamableTransports) { try { await streamableTransports[sid].close(); } catch { } }
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
	console.error(`OpenClaw root: ${OPENCLAW_ROOT}`);
	console.error(`Workspace: ${WORKSPACE}`);
	console.error(`Sessions: ${SESSIONS_DIR}`);
	if (TRANSPORT === "stdio") {
		await startStdio();
	} else {
		await startHTTP();
	}
}

main().catch(console.error);
