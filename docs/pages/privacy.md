---
title: Privacy Policy
description: How SFAE handles credentials, OAuth tokens, and provider data.
path: /privacy/
updated: June 29, 2026
---

# Privacy Policy

Effective date: June 29, 2026

SFAE ("Speak Friend, and Enter") is a command-line tool and hosted OAuth broker from Fundamental Research Labs Inc. It helps AI agents make authenticated API calls without receiving raw secrets in chat or model context.

This policy covers SFAE software and SFAE-operated services, including `sfae.io` and `oauth.sfae.io`. Self-hosted SFAE servers are controlled by the party that operates them.

## Summary

- SFAE does not create an end-user account for normal CLI use.
- The SFAE CLI defaults to local operating-system secret storage, such as macOS Keychain, Windows Credential Manager, or Linux Secret Service.
- Some users may configure SFAE to use another supported credential storage backend. In that case, the storage location, retention, access controls, and operator depend on that configuration.
- Agents receive credential IDs, domains, labels, field names, and request results. Agents should not receive the secret values that SFAE stores.
- Hosted OAuth uses `oauth.sfae.io` to complete provider authorization and hand token material back to trusted SFAE software for storage in the configured credential store.
- We do not sell credential data, OAuth tokens, Google user data, Dropbox user data, or other provider user data.
- We do not use provider user data for advertising, profiling, credit decisions, or model training.

## Data SFAE Handles

SFAE may handle the following data depending on how you use it:

- Credential details you enter, such as API keys, passwords, OAuth access tokens, OAuth refresh tokens, usernames, hostnames, database names, ports, and related fields.
- Credential metadata, such as credential IDs, domains, labels, field names, provider names, requested OAuth scopes, account display names, account email addresses, provider account IDs, token expiry times, and timestamps.
- OAuth session data, such as provider name, requested scopes, state hashes, local redemption challenges, authorization status, error codes, and return URLs.
- Temporary OAuth handoff data, which can include access tokens and refresh tokens encrypted at rest while trusted SFAE software redeems a completed OAuth session.
- Broker grant records used to refresh or revoke OAuth credentials stored through SFAE. These records contain provider names, provider account IDs, broker secret hashes, refresh token hashes, status, and timestamps.
- Website, download, and service logs, such as IP address, user agent, request path, timestamp, and error details, when you visit SFAE websites or call SFAE-operated services.

SFAE also has a transient verification-code flow for active two-factor or multi-factor authentication challenges. Verification codes submitted through `sfae code` are returned to the local CLI for immediate use and are not stored by SFAE.

## Credential Storage

By default, the SFAE CLI stores credential values in your operating system's secret storage. SFAE may also support other credential storage backends, such as an SFAE backend or another configured credential store, depending on the version and configuration you use.

SFAE keeps non-secret lookup information such as credential IDs, domains, labels, field names, and OAuth metadata so the CLI and agents can select the right credential. Depending on the configured storage backend, that index or metadata may be local, remote, self-hosted, or managed by another service.

When an agent runs `sfae credentials`, `sfae show`, or similar commands, SFAE may reveal metadata and field names so the agent can select the right credential. SFAE does not intentionally reveal stored secret values to the agent.

When an agent runs `sfae request`, the agent provides placeholders such as `{ACCESS_TOKEN}` or `{PASSWORD}`. The trusted SFAE runtime resolves those placeholders at execution time and sends the resulting request to the destination chosen by the command.

## Hosted OAuth

SFAE uses `oauth.sfae.io` to support OAuth providers such as Google, Dropbox, GitHub, and Discord. The hosted broker starts the provider authorization flow, receives the provider callback, exchanges the authorization code with the provider, and fetches provider account identity needed for account linking.

For local CLI OAuth, the broker temporarily stores encrypted token material only long enough for the local CLI to redeem it, or until the short-lived session expires. After redemption, the encrypted handoff payload is cleared. The broker keeps limited grant metadata and hashes so SFAE can refresh or revoke credentials later without storing raw broker secrets in the broker database.

For configured backend or third-party storage deployments, OAuth token material may be stored in that configured credential store. If you configure or use a storage backend operated by someone other than Fundamental Research Labs Inc, that operator controls the backend's privacy and security practices.

## Google User Data

When SFAE requests access to Google APIs, the requested scopes are determined by the credential prompt and are shown on Google's consent screen. SFAE uses Google user data only to provide or improve user-facing SFAE functionality that you request.

Depending on scopes you approve, SFAE may handle Google account identity, email address, OAuth scopes, access tokens, refresh tokens, token expiry metadata, and API responses returned from requests you ask SFAE to make. SFAE uses this data to complete OAuth, store the resulting credential in your configured credential storage, refresh or revoke tokens, and send authenticated API requests selected by you or your agent.

SFAE does not sell Google user data, transfer Google user data for advertising, use Google user data for profiling, or use Google user data to train AI models. SFAE's use and transfer of information received from Google APIs will adhere to the Google API Services User Data Policy, including Limited Use requirements.

## Dropbox User Data

When SFAE requests access to Dropbox, the requested scopes are determined by the credential prompt and are shown on Dropbox's authorization screen. SFAE should request the narrowest Dropbox scopes needed for the task.

Depending on scopes you approve, SFAE may handle Dropbox account identity, email address, OAuth scopes, access tokens, refresh tokens, token expiry metadata, and API responses returned from requests you ask SFAE to make. SFAE uses this data to complete OAuth, store the resulting credential in your configured credential storage, refresh or revoke tokens, and send authenticated API requests selected by you or your agent.

SFAE does not sell Dropbox user data, transfer Dropbox user data for advertising, use Dropbox user data for profiling, or use Dropbox user data to train AI models.

## How We Use Data

We use data handled by SFAE to:

- Store credentials in the location you configure.
- Let agents make authenticated HTTP, Postgres, Redis, and future supported protocol requests without exposing stored secrets to the agent.
- Complete OAuth authorization, account linking, token refresh, and token revocation.
- Prevent abuse, debug failures, maintain reliability, and secure SFAE-operated services.
- Respond to support, security, legal, or operational requests.

## Sharing and Disclosure

SFAE may share data in these limited cases:

- With the API, database, OAuth provider, or destination service selected by the user or agent so the requested authenticated operation can be performed.
- With Google, Dropbox, GitHub, Discord, or another OAuth provider as needed to authorize, refresh, identify, or revoke an OAuth credential.
- With infrastructure providers that host, secure, monitor, or deliver SFAE-operated services.
- When required by law, legal process, security investigation, or to protect the rights and safety of users, SFAE, Fundamental Research Labs Inc, or others.

We do not sell credential data or provider user data.

## Security

SFAE is designed so secret values stay out of chat transcripts and model context. When the default CLI store is used, credential values are stored in OS secret storage. When another backend is configured, that backend's security controls apply in addition to SFAE's credential-handling design. Hosted OAuth sessions use state validation, short session lifetimes, HTTPS, encrypted temporary handoff payloads, one-time redemption, and hashed broker secrets.

No system can guarantee absolute security. You are responsible for reviewing the commands an agent runs, choosing appropriate OAuth scopes, protecting your machine and operating-system account, and using SFAE only with services and accounts you are authorized to access.

## Retention and Deletion

Credentials remain in the configured credential store until you delete them or the store's retention rules remove them. `sfae delete <uuid>` forgets a credential from SFAE's index, and `sfae delete <uuid> --purge` also removes stored secret material where the configured backend supports purging. OAuth credentials can also be revoked from SFAE or from the provider's account settings.

Temporary hosted OAuth handoff material is cleared after local redemption or when the session expires. SFAE may retain OAuth session metadata, grant metadata, logs, and security records for operation, debugging, abuse prevention, and legal compliance.

To request deletion of SFAE-operated service records associated with you, open an issue at [github.com/fundamental-research-labs/sfae/issues](https://github.com/fundamental-research-labs/sfae/issues). Do not include secrets, access tokens, refresh tokens, passwords, or private account data in public issues.

## Children

SFAE is a developer tool and is not directed to children under 13. Do not use SFAE to collect personal information from children.

## Changes

We may update this policy as SFAE changes. If SFAE materially changes how it uses Google, Dropbox, or other provider user data, we will update this policy before using that data in the new way.

## Contact

For privacy or security questions, open an issue at [github.com/fundamental-research-labs/sfae/issues](https://github.com/fundamental-research-labs/sfae/issues). Do not include secrets in public issues.
