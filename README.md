[![CI](https://github.com/fundamental-research-labs/sfae/actions/workflows/ci.yml/badge.svg)](https://github.com/fundamental-research-labs/sfae/actions/workflows/ci.yml)

# SFAE — Speak Friend, and Enter

*Pronounced "safe."* &nbsp; [sfae.io](https://sfae.io)

SFAE lets AI coding agents make authenticated API calls and database queries without ever seeing your credentials. Agents use placeholders such as `{ACCESS_TOKEN}` or `{PASSWORD}`. SFAE resolves them from secret storage at execution time, so secrets stay out of chat and out of the context window.

## Features

- **Secret-manager storage** — macOS Keychain, Windows Credential Manager, Linux Secret Service, or an authenticated SFAE backend.
- **Credentials agents can request safely** — API keys, Basic Auth, OAuth 2.0, and more.
- **Communication protocols** — HTTP by default, plus Postgres and Redis with `--protocol`.

## Install

Install the SFAE skill in the current project:

```bash
curl -fsSL https://sfae.io/install-skill.sh | sh
```

By default this installs the skill for supported agent targets. To target one agent, pass a flag such as `--codex`, `--claude`, or `--grok`.

```bash
curl -fsSL https://sfae.io/install-skill.sh | sh -s -- --codex
```

The skill includes a small CLI installer. When an agent needs SFAE and the `sfae` command is not available yet, it can install the CLI through the bundled helper. CLI-only installation and command details live in [docs/cli.md](docs/cli.md).

## Quick Start

You normally do not need to run SFAE commands yourself. Install the skill, then ask your agent to use SFAE for authenticated work:

```text
Use SFAE to call the GitHub API and tell me who I am. If credentials are missing, open the SFAE browser form. Do not ask me to paste secrets into chat.
```

```text
Use SFAE for the API call in this repo. Read the service's official API/auth docs first, collect credentials through SFAE if needed, then make the request with placeholders.
```

The agent checks which credentials exist, opens a web form when something is missing, and makes the authenticated request with placeholders. You provide secrets only in the browser form, not in chat.

## How It Works

1. The agent reads the service's official API/auth docs and checks for stored credentials.
2. SFAE offers you a web form for anything missing.
3. The agent makes HTTP, Postgres, or Redis requests with placeholders, and SFAE resolves them from secret storage.

## Roadmap

| Area | Work |
| --- | --- |
| Authentication | [x.509 certificate authentication](https://github.com/fundamental-research-labs/sfae/issues/27) |
| Protocol | [Support MySQL / MariaDB](https://github.com/fundamental-research-labs/sfae/issues/60) |
| Protocol | [Support MongoDB](https://github.com/fundamental-research-labs/sfae/issues/62) |
| Protocol | [Support Microsoft SQL Server / TDS](https://github.com/fundamental-research-labs/sfae/issues/61) |
| Protocol | [Support ClickHouse](https://github.com/fundamental-research-labs/sfae/issues/31) |
| Product | [Add a credential management UI](https://github.com/fundamental-research-labs/sfae/issues/12) |

## License

MIT
