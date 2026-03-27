# JSON Output Mode Investigation

## Context

SFAE's primary consumer is an LLM agent, not a human. Agents parse program output to decide their next action. Plain-text output is ambiguous and brittle to parse. A `--json` flag (or `--output json`) that emits structured JSON for all commands would make SFAE much more reliable as an agent tool.

## Questions to Investigate

1. **Scope** — Should `--json` apply to all subcommands or just `proxy`?
   - `proxy`: most critical (status code, headers, body all need parsing).
   - `credential list` / `service list`: useful for agents that enumerate available credentials.
   - `credential add` / `service add`: confirmation output — lower value but still nice for consistency.

2. **Output schema** — What should the JSON structure look like?
   - For `proxy`: `{ "status": 200, "headers": {...}, "body": "..." }` — should `body` be a string or parsed JSON when the response is JSON?
   - For `list` commands: `{ "credentials": ["name1", "name2"] }` or `{ "services": [{...}] }`?
   - For errors: `{ "error": "message", "code": "CREDENTIAL_NOT_FOUND" }` — should error codes map 1:1 to `SfaeError` variants?

3. **Binary/large responses** — How to handle non-text response bodies?
   - Base64 encode? Omit body and write to file? Truncate with a size field?

4. **Stderr vs stdout** — With `--json`, should all output (including errors) go to stdout as JSON? Or keep errors on stderr?
   - Agent frameworks typically read stdout. Mixing JSON on stdout with plain text on stderr is fine for humans, confusing for agents.

5. **Existing CLI tools for reference** — How do similar tools handle this?
   - `gh` (GitHub CLI): `--json` flag with field selection.
   - `docker`: `--format '{{json .}}'`.
   - `kubectl`: `-o json`.

6. **Global flag vs per-command** — Should `--json` be a global flag or per-subcommand?

## Proposed Next Steps

1. Survey 2-3 agent frameworks (LangChain tool spec, Claude tool use, OpenAI function calling) to understand what output format they expect from CLI tools.
2. Draft JSON schemas for each subcommand's output.
3. Decide on error handling strategy (stdout JSON vs stderr).
4. Implement as a follow-up to the MVP (plan 001), since the MVP is usable without it.
