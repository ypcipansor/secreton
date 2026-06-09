# Sentinel's Journal

## Journal Entries

2025-05-22 - [Session Metadata Enhancement]
Vulnerability: Hardcoded "unknown" or "legacy" client metadata (IP/UA) in session storage hindered auditability and forensics.
Learning: Centralizing session creation into a single helper within `AuthenticationService` ensures consistent metadata capture across various authentication entry points (login, refresh, MFA, OAuth).
Prevention: Always extract client metadata at the API boundary (handlers) and propagate it through the service layer to persistence. Avoid using placeholders in security-critical session records.
