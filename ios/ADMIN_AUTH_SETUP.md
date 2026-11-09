# Admin authentication setup

Admin credentials must not be embedded in the iOS app, obfuscated in source, or committed to this repository. A value compiled into a client can be recovered.

Before enabling an admin sign-in screen, configure a server-side authentication endpoint over HTTPS. The server must:
- validate credentials without returning the secret to the app;
- issue short-lived, revocable session tokens;
- store only token hashes server-side where practical;
- enforce rate limits and audit failed sign-in attempts;
- authorize every admin operation on the server, not merely hide UI controls;
- support token rotation and revocation.

The iOS client should store only a short-lived session token in Keychain and should never contain the admin master credential. No admin endpoint is configured in this repository yet, so the app must not pretend that local-only token checking is secure.
