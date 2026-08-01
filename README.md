# tsgh

`tsgh` is a tailnet-only GitHub token broker. It uses Tailscale identity to mint
short-lived GitHub App tokens whose repositories and permissions come from grants.

## Tailscale grants

Put repositories and permissions in separate objects within the same app
capability array:

```json
{
  "grants": [
    {
      "src": ["group:developers"],
      "dst": ["tag:tsgh"],
      "ip": ["*"],
      "app": {
        "bog.dev/cap/tsgh": [
          {"target": "acme", "repositories": ["api", "web"]},
          {"target": "acme", "permissions": {"contents": "read", "pull_requests": "write"}}
        ]
      }
    },
    {
      "src": ["alice@example.com"],
      "dst": ["tag:tsgh"],
      "ip": ["*"],
      "app": {
        "bog.dev/cap/tsgh": [
          {"target": "acme", "githubUser": "octocat"}
        ]
      }
    }
  ]
}
```

Omit `githubUser` for an installation token. Any authenticated node, tagged or
untagged, may use either token flow. OAuth credentials are shared by GitHub
login across the broker instance; scoped user tokens are isolated per Tailscale
node.

All matching repository values are unioned. All matching permissions are
unioned using `admin > write > read`, and the resulting permission map applies
to every resulting repository. `"*"` means every repository available to the
GitHub App installation. A value containing more than one of `githubUser`,
`repositories`, or `permissions` is rejected.

## GitHub App and configuration

Create one GitHub App, grant it the maximum permissions that policy may
request, and install it on every target organization or personal account.
Enable expiring user-to-server tokens if user tokens are needed.

Always required:

| Variable | Meaning |
| --- | --- |
| `TSGH_GITHUB_APP_ID` | Numeric GitHub App ID |
| `TSGH_GITHUB_PRIVATE_KEY_FILE` | Mounted GitHub App RSA private-key PEM |
| `TSGH_STATE_DIR` | Directory for broker and tsnet state |

The tsnet node uses the system hostname. `TS_AUTHKEY` is handled directly by
`tsnet` and is only needed to enroll a node that has no persisted state.

User-token support additionally requires all of:

| Variable | Meaning |
| --- | --- |
| `TSGH_GITHUB_CLIENT_ID` | GitHub App client ID |
| `TSGH_GITHUB_CLIENT_SECRET_FILE` | Mounted client-secret file |
| `TSGH_STORE_KEY_FILE` | File containing 32 raw bytes or base64-encoded 32 bytes |

Register `https://<tsnet-cert-domain>/auth/github/callback` as the GitHub App
callback URL. `tsgh` derives this URL from its Tailscale HTTPS certificate
domain. A store key can be generated with:

```sh
mkdir -p secrets
openssl rand -base64 32 > secrets/store.key
chmod 600 secrets/store.key
```

The encrypted broker state contains only OAuth access/refresh credentials and
active scoped-user tokens awaiting their strict one-hour revocation. GitHub
installation IDs and installation tokens are memory-only.

## Use

Link a GitHub identity by opening `/auth/github` from a tailnet browser. Check
the link with `GET /auth/github/status` and remove it with
`DELETE /auth/github`.

Request a token for one GitHub owner:

```sh
GH_TOKEN="$(curl -fsS -X POST http://tsgh/token/acme)" gh repo view acme/api
```

For an unattended workload, grant its tagged Tailscale node an installation
token scope. No GitHub account link or user-token configuration is needed:

```json
{
  "grants": [
    {
      "src": ["tag:ci"],
      "dst": ["tag:tsgh"],
      "ip": ["*"],
      "app": {
        "bog.dev/cap/tsgh": [
          {"target": "acme", "repositories": ["api"]},
          {"target": "acme", "permissions": {"contents": "read"}}
        ]
      }
    }
  ]
}
```

The workload can then fetch a token using only its Tailscale identity:

```sh
GH_TOKEN="$(curl -fsS -X POST http://tsgh/token/acme)" gh api repos/acme/api
```

Run from source:

```sh
go run ./cmd/tsgh
```

For Docker Compose, put the three files referenced by `compose.yaml` in
`./secrets`, export `TSGH_GITHUB_APP_ID` and `TSGH_GITHUB_CLIENT_ID`, then run
`docker compose up -d`. Set `TS_AUTHKEY` for the first startup if the state
volume does not already contain an enrolled node. Remove the client ID,
client-secret, and store-key settings for installation-only mode.

Compose file-backed secrets retain their host ownership and permissions. Make
them readable by the container's GID before starting it:

```sh
sudo chgrp 65532 secrets/*
chmod 640 secrets/*
```

Tailscale HTTPS and MagicDNS must be enabled because startup requires both the
HTTP and HTTPS listeners. The container image runs as UID/GID 65532 and expects
`/var/lib/tsgh` to be writable when it is used as the state volume.

## Audit logs

Security-relevant broker actions are written as `log/slog` text records on
standard output. Successful token requests include both the Tailscale caller
and the SHA-256 token hash used by GitHub organization audit logs:

```text
time=2026-08-01T12:00:00.000Z level=INFO msg=audit action=token.issue outcome=success status=200 node_id=node-id node_name=client.example.ts.net. source_ip=100.64.0.1 tailscale_user_id=100 tailscale_user_login=alice@example.com target=acme token_type=installation scope_key=scope-hash token_hash="base64-sha256"
```

The broker audits authentication failures, token issuance attempts, OAuth
authorization starts, links and unlinks, and scoped-user-token recovery and
revocation. Routine OAuth status reads, unknown routes, and general HTTP access
are not logged. Tagged nodes include `tailscale_tags` instead of a user profile.
`node_id` is the durable identity; `node_key` is logged only when Tailscale does
not supply a stable node ID.

To correlate an auditable GitHub action, search the target organization's audit
log for `hashed_token:"<token_hash>"`. Git events require an audit-log export;
see GitHub's [token audit guidance](https://docs.github.com/en/enterprise-cloud@latest/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/identifying-audit-log-events-performed-by-an-access-token).
GitHub does not provide equivalent organization audit visibility for personal
account targets. Correlation identifies the Tailscale host that received a
bearer token; it cannot prove that the token was not copied before use.

## Tests

```sh
go test -short ./...  # unit and fake-GitHub tests
go test ./...         # also real tsnet nodes with local control, DERP/STUN, HTTP, and HTTPS
```

Both commands are secret-free and isolated from the real tailnet and GitHub.

## License

[MIT](LICENSE)
