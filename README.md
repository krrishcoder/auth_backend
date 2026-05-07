# Auth Backend

Small OAuth authorization server for local MCP development. It uses Google OAuth
for user login, then issues short-lived bearer tokens for the MCP server.

## Setup

1. Create a Google OAuth client in Google Cloud Console.
2. Add this authorized redirect URI:

   `http://localhost:8080/oauth/google/callback`

3. Copy `.env.example` to `.env` and fill in `GOOGLE_CLIENT_ID`,
   `GOOGLE_CLIENT_SECRET`, and `AUTH_JWT_SECRET`.
4. Install and run:

   ```sh
   npm install
   npm run dev
   ```

## Endpoints

- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/openid-configuration`
- `POST /register`
- `GET /authorize`
- `POST /token`
- `POST /introspect`
- `GET /oauth/google/callback`

## Claude web connector redirects

For Claude.ai custom connectors, dynamic client registration must allow Claude's
hosted OAuth callback:

`https://claude.ai/api/mcp/auth_callback`

The server allows that callback and `https://claude.com/api/mcp/auth_callback`
by default. To override the allowlist, set comma-separated values in
`ALLOWED_REDIRECT_URIS`.

This is intentionally developer-focused. For production, persist client
registrations and authorization codes, enforce HTTPS, restrict dynamic client
registration, and store secrets in a proper secret manager.
