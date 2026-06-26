# OAuth Provider Candidates for SFAE

Last checked: 2026-06-26

SFAE currently supports Discord, Google, GitHub, and Dropbox. Google support is pending approval/verification for the requested scopes. Dropbox production approval remains external operational work.

## Recommended Next Batch

Prioritize:

1. Slack
2. Linear
3. Notion
4. Atlassian Jira/Confluence
5. Microsoft Graph

This covers code, chat, issue tracking, docs, enterprise files/email/calendar, and project management with the best balance of user value and implementation practicality.

## Candidate Table

| Candidate | Why it is good for SFAE | Review / approval status |
|---|---|---|
| GitLab | Similar value to GitHub, plus self-managed enterprise installs. | No central review for GitLab.com OAuth apps is apparent in the docs. Self-managed GitLab instances require per-instance app setup and may be subject to local admin policy. Source: [GitLab OAuth provider docs](https://docs.gitlab.com/integration/oauth_provider/). |
| Linear | Excellent for agent-driven issue and project workflows. | No platform review is apparent for OAuth apps. Enterprise workspaces can require admin approval for third-party apps. Sources: [Linear OAuth docs](https://linear.app/developers/oauth-2-0-authentication), [Linear third-party app approvals](https://linear.app/docs/third-party-application-approvals). |
| Slack | High-value workspace data and messaging. Strong fit for agents that need to read or act in team context. | Unlisted distribution can work without Slack Marketplace review, but commercial/Marketplace apps should be submitted and reviewed. Some APIs and rate limits favor Marketplace-approved apps. Sources: [Slack app distribution docs](https://docs.slack.dev/app-management/distribution), [Slack rate limit changes for non-Marketplace apps](https://docs.slack.dev/changelog/2025/05/29/rate-limit-changes-for-non-marketplace-apps). |
| Notion | Docs, databases, project notes, and lightweight CRM-style workflows. Very agent-friendly. | Public connections can be used without Marketplace listing, but Marketplace listing requires Notion security review. Source: [Notion developer overview](https://developers.notion.com/guides/get-started/overview). |
| Atlassian Jira/Confluence | Work tracking and knowledge base access. High enterprise relevance. | OAuth 2.0 apps can run unapproved, but users see an unreviewed warning. Approval goes through Atlassian Marketplace flow. Source: [Atlassian OAuth 2.0 3LO apps](https://developer.atlassian.com/cloud/jira/software/oauth-2-3lo-apps/). |
| Microsoft Graph | Outlook, OneDrive, SharePoint, Teams, calendars, users, and files. Huge payoff for enterprise workflows. | No single app-store review, but publisher verification and tenant admin consent are real friction, especially for higher-risk permissions. Sources: [Microsoft publisher verification](https://learn.microsoft.com/en-us/entra/identity-platform/publisher-verification-overview), [Microsoft permissions and consent](https://learn.microsoft.com/en-us/entra/identity-platform/permissions-consent-overview). |
| Airtable | Structured records and base workflows. Good scoped access model. | Public docs describe OAuth grants and admin management, but no broad platform-review requirement was found. Enterprise admins may still govern integrations. Source: [Airtable third-party OAuth overview](https://support.airtable.com/docs/third-party-integrations-via-oauth-overview). |
| Asana | Task and project automation. Useful for lightweight work management. | OAuth is standard. Publishing/listing app experiences goes through Asana review. Sources: [Asana OAuth docs](https://developers.asana.com/docs/oauth), [Asana publish-your-app docs](https://developers.asana.com/docs/publish-your-app). |
| Figma | Design files, comments, design-to-code workflows, and design metadata. | Public OAuth apps require Figma review before broad user authorization. Source: [Figma OAuth apps docs](https://developers.figma.com/docs/rest-api/oauth-apps/). |
| Box | Enterprise file and document access. Strong fit for regulated company content. | Not usually a public marketplace review issue, but many enterprise apps require explicit Box admin authorization. Source: [Box authorization docs](https://developer.box.com/guides/authorization). |
| HubSpot | CRM, contacts, companies, deals, and marketing/sales workflows. | Unverified apps can show warning UX. Marketplace/certification requires HubSpot review. Sources: [HubSpot public apps overview](https://developers.hubspot.com/docs/apps/legacy-apps/public-apps/overview), [HubSpot certification requirements](https://developers.hubspot.com/docs/apps/developer-platform/list-apps/apply-for-certification/certification-requirements). |
| Salesforce | CRM, sales ops, service workflows, and enterprise automation. | Custom connected/external client apps can be used directly, but AppExchange or partner distribution requires Salesforce security review. Customer admins also control connected app policies. Sources: [Salesforce OAuth and connected apps](https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/intro_oauth_and_connected_apps.htm), [Salesforce security review](https://developer.salesforce.com/docs/atlas.en-us.packagingGuide.meta/packagingGuide/security_review_how_it_works.htm). |
| Zoom | Meetings, users, recordings, and transcript-related workflows where scopes allow. | Public and unlisted Marketplace apps go through Zoom review. Source: [Zoom app review process](https://developers.zoom.us/docs/distribute/app-review-process/). |

## Lower Priority

| Candidate | Reason to defer |
|---|---|
| Trello | Current REST API auth is still API key/token or OAuth 1.0 style. OAuth 2.0 is not the clean path yet, though Atlassian has discussed a future OAuth 2.0 rollout. Sources: [Trello REST API authorization](https://developer.atlassian.com/cloud/trello/guides/rest-api/authorization/), [Trello OAuth 2.0 RFC](https://community.developer.atlassian.com/t/rfc-89-introducing-oauth2-to-trello/90359). |

## Implemented

| Provider | Notes |
|---|---|
| Discord | Existing hosted OAuth provider. |
| Google | Existing hosted OAuth provider for Google API scopes; approval/verification depends on requested Google scopes. |
| GitHub | Hosted OAuth provider for `github.com`. No provider review for a normal OAuth App; organization owners may need to approve access when organization OAuth restrictions are enabled. Marketplace listing and paid plans are separate. Sources: [GitHub OAuth REST API docs](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authenticating-to-the-rest-api-with-an-oauth-app), [GitHub org OAuth approval docs](https://docs.github.com/en/organizations/managing-oauth-access-to-your-organizations-data/approving-oauth-apps-for-your-organization). |
| Dropbox | Hosted OAuth provider for `dropboxapi.com`. Uses offline access with `account_info.read` for account linking; Dropbox production approval is required beyond development/limited usage. Source: [Dropbox developer guide](https://www.dropbox.com/developers/reference/developer-guide). |
