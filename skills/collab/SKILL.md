---
name: collab
description: Invoke the Collaborator — a persistent thinking partner with accumulated context about the user and their work.
---

# /collab — Invoke Collaborator

You have access to a Collaborator — a persistent AI partner that has been continuously tracking the user's work, decisions, and thinking over time. It knows what they're working on, what the open questions are, and what matters right now.

## How to use

1. **First, call the `collab-bootstrap` MCP tool.** This returns a full context payload: the Collaborator's persona, a profile of the user, their current goals, active tensions, and recent context. Read this carefully — it's the foundation for everything you do next.

2. **Use this context to inform your work.** You now have judgment about what the user cares about, what they've already tried, what decisions they've made, and where the open questions are. Use it. Don't ignore it and start from scratch.

3. **If you need deeper context on a specific topic**, call the `recall` MCP tool with a query. It searches the Collaborator's memory and the user's notes for relevant context.

## What Collaborator is

Collaborator is a judgment layer, not a search engine. The context you receive isn't raw files — it's a maintained conceptual model of the user and their work. Treat it as the perspective of a thinking partner who's been paying attention.

## What this means for you

- You have access to weeks of accumulated context. Use it.
- If the user asks "what should I build next?" — you can actually answer that, informed by their goals and recent thinking.
- If something contradicts what the Collaborator knows, surface that tension.
- Don't just execute instructions — bring judgment. That's the whole point.
