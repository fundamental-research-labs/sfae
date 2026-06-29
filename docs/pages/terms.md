---
title: Terms of Use
description: Terms for using SFAE software, websites, and hosted OAuth services.
path: /terms/
updated: June 29, 2026
---

# Terms of Use

Effective date: June 29, 2026

These Terms of Use apply to SFAE websites and SFAE-operated services, including `sfae.io` and `oauth.sfae.io`, provided by Fundamental Research Labs Inc. The SFAE source code is licensed under the license included in the repository; these terms do not replace that open-source license.

## Using SFAE

SFAE is a developer tool for storing credentials and letting AI agents make authenticated requests without receiving raw secrets in chat or model context. You are responsible for deciding when to use SFAE, which credentials to store, which scopes to authorize, and which commands an agent may run.

You may use SFAE only for services, accounts, data, and systems that you are authorized to access. You must comply with applicable law and the terms, API rules, and acceptable-use policies of each third-party service you connect through SFAE.

## Accounts and Credentials

Normal CLI use does not require a SFAE user account. You are responsible for protecting your device, operating-system account, configured credential store, SFAE configuration, and any remote, self-hosted, or third-party backend you choose to use.

Do not submit secrets, passwords, access tokens, refresh tokens, private keys, or confidential account data in public GitHub issues, support requests, logs, prompts, or examples.

## Hosted OAuth

SFAE-operated OAuth services help complete provider authorization flows for supported providers. Providers may approve, deny, limit, revoke, or change access independently of SFAE. SFAE does not control Google, Dropbox, GitHub, Discord, or other third-party services.

You are responsible for requesting appropriate OAuth scopes and for ensuring your agent's requests match the access you intended to grant.

## Agent Actions

SFAE can reduce secret exposure, but it does not make every agent action safe. Review agent instructions, generated commands, destination URLs, request bodies, database queries, and scope requests before approving sensitive work.

You are responsible for the effects of requests, writes, deletions, queries, messages, uploads, downloads, and other actions made with credentials you provide to SFAE.

## Availability and Changes

SFAE-operated services may change, suspend, rate-limit, or stop operating at any time. We may update SFAE software, websites, hosted OAuth providers, supported protocols, or these terms as the project evolves.

## No Warranty

SFAE-operated services and SFAE software are provided as available and without warranties to the fullest extent permitted by law. We do not promise that SFAE will be uninterrupted, error-free, secure against every threat, or suitable for every environment.

## Limitation of Liability

To the fullest extent permitted by law, Fundamental Research Labs Inc will not be liable for indirect, incidental, special, consequential, exemplary, or punitive damages, or for lost profits, lost data, lost credentials, service interruptions, or third-party claims arising from your use of SFAE.

## Termination

We may suspend or block access to SFAE-operated services to protect the service, users, providers, or third parties, or if we believe use of the service violates these terms or applicable law.

## Contact

For questions about these terms, open an issue at [github.com/fundamental-research-labs/sfae/issues](https://github.com/fundamental-research-labs/sfae/issues). Do not include secrets in public issues.
