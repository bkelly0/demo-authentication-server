# Postman collection for the OAuth/OIDC server

This folder contains a Postman collection for the OAuth 2.0 / OpenID Connect endpoints exposed by the auth server in this project.

## Files

- `oauth-server.postman_collection.json` - the collection itself
- `local.postman_environment.json` - local environment variables

## Covered endpoints

- `GET /.well-known/openid-configuration`
- `GET /.well-known/oauth-authorization-server`
- `GET /oauth2/jwks`
- `GET /oauth2/authorize`
- `POST /oauth2/token`
- `GET /userinfo`
- `POST /oauth2/introspect`
- `POST /oauth2/revoke`

## Import steps

1. Open Postman.
2. Import `oauth-server.postman_collection.json`.
3. Import `local.postman_environment.json`.
4. Select the `Demo Authentication Server - Local` environment.
5. Update the environment values if your server runs on a different host, port, client ID, or redirect URI.

## Default values used by the collection

These values match the defaults from `src/main/resources/application.yaml`:

- `baseUrl`: `http://localhost:8080`
- `clientId`: `pkce-client`
- `clientSecret`: empty unless you configure one
- `redirectUri`: `http://127.0.0.1:8081/callback`
- `scopes`: `openid profile`
- `username`: `testuser`

## Notes

- The `Authorize with PKCE` request generates a verifier, challenge, state, and nonce before each run.
- If the authorization request returns a redirect, turn off automatic redirects in Postman so you can capture the `code` from the `Location` header.
- The collection includes both public PKCE and confidential-client token exchange requests.
- The `/clients` endpoints from `openapi-client-management.yaml` are not included here because you asked for the OAuth server endpoints.

